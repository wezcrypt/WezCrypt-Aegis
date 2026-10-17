#include "updates/update_verifier.h"

#include <fstream>

#include "common/base64.h"
#include "common/json.h"
#include "common/strings.h"
#include "common/url.h"

extern "C" {
#include "monocypher-ed25519.h"
}

namespace aegis {

std::optional<Version> Version::Parse(std::string_view s) {
  s = TrimAsciiWhitespace(s);
  if (s.empty() || s.size() > 64) return std::nullopt;
  Version v;
  for (std::string_view part : Split(s, '.')) {
    std::uint64_t n;
    if (!ParseUint64(part, &n) || n > 0xFFFFFFFFULL) return std::nullopt;
    v.parts.push_back(static_cast<std::uint32_t>(n));
  }
  if (v.parts.size() > 8) return std::nullopt;
  return v;
}

int Version::Compare(const Version& o) const {
  std::size_t n = std::max(parts.size(), o.parts.size());
  for (std::size_t i = 0; i < n; ++i) {
    std::uint32_t a = i < parts.size() ? parts[i] : 0;
    std::uint32_t b = i < o.parts.size() ? o.parts[i] : 0;
    if (a != b) return a < b ? -1 : 1;
  }
  return 0;
}

std::string Version::ToString() const {
  std::string s;
  for (std::size_t i = 0; i < parts.size(); ++i) {
    if (i) s += '.';
    s += std::to_string(parts[i]);
  }
  return s;
}

std::string_view ManifestStatusText(ManifestStatus s) {
  switch (s) {
    case ManifestStatus::kOk: return "verified";
    case ManifestStatus::kNoTrustedKeys: return "no update signing key configured in this build";
    case ManifestStatus::kBadSignatureEncoding: return "signature is not valid base64 Ed25519";
    case ManifestStatus::kSignatureInvalid: return "signature verification failed";
    case ManifestStatus::kMalformed: return "manifest is malformed";
    case ManifestStatus::kWrongProduct: return "manifest is for a different product";
    case ManifestStatus::kWrongChannel: return "manifest is for a different channel";
    case ManifestStatus::kRollback: return "manifest is older than one already accepted (rollback)";
    case ManifestStatus::kExpired: return "manifest has expired";
    case ManifestStatus::kNotYetValid: return "manifest issue time is in the future";
    case ManifestStatus::kInsecureArtifactUrl: return "manifest lists a non-HTTPS download";
  }
  return "unknown";
}

bool VerifyEd25519(const Ed25519PublicKey& key, std::string_view message,
                   const std::uint8_t signature[64]) {
  return crypto_ed25519_check(signature, key.data(),
                              reinterpret_cast<const std::uint8_t*>(message.data()),
                              message.size()) == 0;
}

std::vector<Ed25519PublicKey> ParsePublicKeys(std::string_view config) {
  std::vector<Ed25519PublicKey> keys;
  for (std::string_view raw : Split(config, ',')) {
    std::string_view k = TrimAsciiWhitespace(raw);
    if (k.empty()) continue;
    std::vector<std::uint8_t> bytes;
    const bool ok = (k.size() == 64 && HexDecode(k, &bytes) && bytes.size() == 32) ||
                    (Base64Decode(k, &bytes) && bytes.size() == 32);
    if (!ok) continue;
    Ed25519PublicKey key;
    std::copy(bytes.begin(), bytes.end(), key.begin());
    keys.push_back(key);
  }
  return keys;
}

VerifiedManifest VerifyManifest(std::string_view manifest_bytes, std::string_view signature_b64,
                                const VerifyOptions& options) {
  VerifiedManifest out;
  if (options.trusted_keys.empty()) {
    out.status = ManifestStatus::kNoTrustedKeys;
    return out;
  }
  std::vector<std::uint8_t> sig;
  if (!Base64Decode(signature_b64, &sig) || sig.size() != 64) {
    out.status = ManifestStatus::kBadSignatureEncoding;
    return out;
  }
  bool valid = false;
  for (const auto& key : options.trusted_keys) {
    if (VerifyEd25519(key, manifest_bytes, sig.data())) {
      valid = true;
      break;
    }
  }
  if (!valid) {
    out.status = ManifestStatus::kSignatureInvalid;
    return out;
  }
  // Only signed bytes are parsed.
  json::ParseLimits limits;
  limits.max_bytes = 1024 * 1024;
  auto doc = json::Parse(manifest_bytes, nullptr, limits);
  if (!doc || !doc->is_object()) {
    out.status = ManifestStatus::kMalformed;
    return out;
  }
  UpdateManifest m;
  m.product = doc->GetString("product");
  m.channel = doc->GetString("channel");
  std::int64_t seq = doc->GetInt("sequence", -1);
  auto ver = Version::Parse(doc->GetString("version"));
  auto chromium = Version::Parse(doc->GetString("chromium_version"));
  auto min_safe = Version::Parse(doc->GetString("minimum_safe_chromium_version"));
  m.issued_unix = doc->GetInt("issued_unix", -1);
  m.expires_unix = doc->GetInt("expires_unix", -1);
  m.security_notes = doc->GetString("security_notes").substr(0, 4096);
  if (seq <= 0 || !ver || !chromium || !min_safe || m.issued_unix <= 0 ||
      m.expires_unix <= m.issued_unix) {
    out.status = ManifestStatus::kMalformed;
    return out;
  }
  m.sequence = static_cast<std::uint64_t>(seq);
  m.version = *ver;
  m.chromium_version = *chromium;
  m.minimum_safe_chromium = *min_safe;
  if (const json::Value* arts = doc->Find("artifacts"); arts && arts->is_array()) {
    for (const json::Value& a : arts->as_array()) {
      ReleaseArtifact ra;
      ra.name = a.GetString("name");
      ra.url = a.GetString("url");
      ra.sha512_hex = ToLowerAscii(a.GetString("sha512"));
      std::int64_t size = a.GetInt("size", -1);
      std::vector<std::uint8_t> digest;
      if (ra.name.empty() || size <= 0 || ra.sha512_hex.size() != 128 ||
          !HexDecode(ra.sha512_hex, &digest)) {
        out.status = ManifestStatus::kMalformed;
        return out;
      }
      auto u = ParseUrl(ra.url);
      if (!u || u->scheme != "https" || u->has_credentials) {
        out.status = ManifestStatus::kInsecureArtifactUrl;
        return out;
      }
      ra.size = static_cast<std::uint64_t>(size);
      m.artifacts.push_back(std::move(ra));
    }
  }
  if (m.product != "wezcrypt-aegis") {
    out.status = ManifestStatus::kWrongProduct;
    return out;
  }
  if (m.channel != options.expected_channel) {
    out.status = ManifestStatus::kWrongChannel;
    return out;
  }
  if (m.sequence <= options.last_accepted_sequence) {
    out.status = ManifestStatus::kRollback;
    out.manifest = m;
    return out;
  }
  if (options.now_unix > 0) {
    if (m.issued_unix > options.now_unix + options.max_clock_skew_seconds) {
      out.status = ManifestStatus::kNotYetValid;
      return out;
    }
    if (m.expires_unix < options.now_unix) {
      out.status = ManifestStatus::kExpired;
      return out;
    }
  }
  out.status = ManifestStatus::kOk;
  out.manifest = std::move(m);
  return out;
}

std::string Sha512Hex(std::string_view data) {
  std::uint8_t h[64];
  crypto_sha512(h, reinterpret_cast<const std::uint8_t*>(data.data()), data.size());
  return HexEncode(h, 64);
}

std::optional<std::string> Sha512FileHex(const std::filesystem::path& file,
                                         std::uint64_t max_bytes) {
  std::ifstream in(file, std::ios::binary);
  if (!in) return std::nullopt;
  crypto_sha512_ctx ctx;
  crypto_sha512_init(&ctx);
  std::vector<char> buf(1 << 16);
  std::uint64_t total = 0;
  while (in) {
    in.read(buf.data(), static_cast<std::streamsize>(buf.size()));
    std::streamsize n = in.gcount();
    if (n <= 0) break;
    total += static_cast<std::uint64_t>(n);
    if (total > max_bytes) return std::nullopt;
    crypto_sha512_update(&ctx, reinterpret_cast<const std::uint8_t*>(buf.data()),
                         static_cast<std::size_t>(n));
  }
  if (in.bad()) return std::nullopt;
  std::uint8_t h[64];
  crypto_sha512_final(&ctx, h);
  return HexEncode(h, 64);
}

bool VerifyArtifactFile(const std::filesystem::path& file, const ReleaseArtifact& artifact) {
  std::error_code ec;
  auto size = std::filesystem::file_size(file, ec);
  if (ec || size != artifact.size) return false;
  auto hex = Sha512FileHex(file, artifact.size);
  if (!hex || hex->size() != artifact.sha512_hex.size()) return false;
  return ConstantTimeEquals(reinterpret_cast<const std::uint8_t*>(hex->data()),
                            reinterpret_cast<const std::uint8_t*>(artifact.sha512_hex.data()),
                            hex->size());
}

std::string_view EngineFreshnessText(EngineFreshness f) {
  switch (f) {
    case EngineFreshness::kCurrent: return "up to date (verified signed manifest)";
    case EngineFreshness::kUpdateAvailable: return "a newer signed release is available";
    case EngineFreshness::kBelowMinimumSafe:
      return "OUTDATED: browser engine is below the minimum safe version - update now";
    case EngineFreshness::kUnknownStale:
      return "possibly outdated: this build is old and no signed update information is available";
    case EngineFreshness::kUnknown: return "not yet checked";
  }
  return "unknown";
}

EngineFreshness EvaluateEngineFreshness(const Version& running_app, const Version& running_engine,
                                        std::int64_t build_unix, std::int64_t now_unix,
                                        const UpdateManifest* manifest,
                                        std::int64_t stale_after_days) {
  if (manifest) {
    if (running_engine.Compare(manifest->minimum_safe_chromium) < 0) {
      return EngineFreshness::kBelowMinimumSafe;
    }
    if (running_app.Compare(manifest->version) < 0 ||
        running_engine.Compare(manifest->chromium_version) < 0) {
      return EngineFreshness::kUpdateAvailable;
    }
    return EngineFreshness::kCurrent;
  }
  if (build_unix > 0 && now_unix > build_unix &&
      (now_unix - build_unix) > stale_after_days * 86400) {
    return EngineFreshness::kUnknownStale;
  }
  return EngineFreshness::kUnknown;
}

}  // namespace aegis

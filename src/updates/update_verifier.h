// WezCrypt Aegis - signed update manifests.
//
// WezCrypt Aegis never downloads and runs code automatically. The update
// subsystem:
//   1. fetches a release manifest and its detached Ed25519 signature,
//   2. verifies the signature against public keys compiled into the binary,
//   3. enforces rollback protection (monotonic sequence numbers) and
//      freshness (issued/expires timestamps),
//   4. reports whether a newer, signed release exists and whether the
//      running engine is below the minimum safe version,
//   5. verifies the SHA-512 of a downloaded installer against the signed
//      manifest before the user is offered to run it.
//
// Signatures use Ed25519 (RFC 8032) as implemented by Monocypher 4.0.2.
#pragma once

#include <array>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace aegis {

// Dotted numeric versions ("154.0.8037.98"). Missing components count as 0.
struct Version {
  std::vector<std::uint32_t> parts;
  static std::optional<Version> Parse(std::string_view s);
  int Compare(const Version& other) const;
  std::string ToString() const;
};

struct ReleaseArtifact {
  std::string name;         // "WezCryptAegis-1.0.0-x64-setup.exe"
  std::string url;          // HTTPS only
  std::string sha512_hex;   // 128 hex chars
  std::uint64_t size = 0;
};

struct UpdateManifest {
  std::string product;              // must be "wezcrypt-aegis"
  std::string channel;              // "stable"
  std::uint64_t sequence = 0;       // strictly increasing per release
  Version version;                  // application version
  Version chromium_version;         // engine version shipped in the release
  Version minimum_safe_chromium;    // engines below this are flagged unsafe
  std::int64_t issued_unix = 0;
  std::int64_t expires_unix = 0;
  std::vector<ReleaseArtifact> artifacts;
  std::string security_notes;
};

enum class ManifestStatus {
  kOk,
  kNoTrustedKeys,
  kBadSignatureEncoding,
  kSignatureInvalid,
  kMalformed,
  kWrongProduct,
  kWrongChannel,
  kRollback,          // sequence <= last accepted
  kExpired,
  kNotYetValid,
  kInsecureArtifactUrl,
};

std::string_view ManifestStatusText(ManifestStatus s);

struct VerifiedManifest {
  ManifestStatus status = ManifestStatus::kMalformed;
  UpdateManifest manifest;
};

using Ed25519PublicKey = std::array<std::uint8_t, 32>;

struct VerifyOptions {
  std::vector<Ed25519PublicKey> trusted_keys;
  std::string expected_channel = "stable";
  std::uint64_t last_accepted_sequence = 0;
  std::int64_t now_unix = 0;
  std::int64_t max_clock_skew_seconds = 24 * 3600;
};

// |manifest_bytes| are the exact bytes that were signed; |signature_b64| is
// the base64-encoded 64-byte detached signature.
VerifiedManifest VerifyManifest(std::string_view manifest_bytes, std::string_view signature_b64,
                                const VerifyOptions& options);

bool VerifyEd25519(const Ed25519PublicKey& key, std::string_view message,
                   const std::uint8_t signature[64]);

// Parses comma-separated base64 or hex public keys (build-time config).
std::vector<Ed25519PublicKey> ParsePublicKeys(std::string_view config);

std::string Sha512Hex(std::string_view data);
std::optional<std::string> Sha512FileHex(const std::filesystem::path& file,
                                         std::uint64_t max_bytes);

// Constant-time check of a file against an artifact entry (size + SHA-512).
bool VerifyArtifactFile(const std::filesystem::path& file, const ReleaseArtifact& artifact);

enum class EngineFreshness {
  kCurrent,
  kUpdateAvailable,       // newer signed release exists
  kBelowMinimumSafe,      // signed manifest says the engine is unsafe
  kUnknownStale,          // no manifest and the build is older than the threshold
  kUnknown,               // no manifest yet, build is recent
};

std::string_view EngineFreshnessText(EngineFreshness f);

EngineFreshness EvaluateEngineFreshness(const Version& running_app, const Version& running_engine,
                                        std::int64_t build_unix, std::int64_t now_unix,
                                        const UpdateManifest* manifest,
                                        std::int64_t stale_after_days = 45);

}  // namespace aegis

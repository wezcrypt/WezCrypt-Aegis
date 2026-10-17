// WezCrypt Aegis - release and diagnostics command-line tool.
//
// Uses the same security core as the browser, so release engineering checks
// exercise exactly the shipped verification code.
//
//   aegis_tool verify-manifest <manifest.json> <manifest.json.sig> <pubkeys> [--last-sequence N]
//   aegis_tool verify-artifact <manifest.json> <manifest.json.sig> <pubkeys> <file>
//   aegis_tool sha512 <file>
//   aegis_tool list-stats <filter-list.txt>...
//   aegis_tool explain <psl.dat> <filter-list.txt> <request-url> <top-level-url> <type>
#include <chrono>
#include <cstdio>
#include <iostream>
#include <string>
#include <vector>

#include "common/strings.h"
#include "common/url.h"
#include "filtering/filter_engine.h"
#include "storage/atomic_file.h"
#include "updates/update_verifier.h"

using namespace aegis;

namespace {

int Usage() {
  std::cerr << "usage:\n"
               "  aegis_tool verify-manifest <manifest> <sig> <pubkeys> [--last-sequence N]\n"
               "  aegis_tool verify-artifact <manifest> <sig> <pubkeys> <file>\n"
               "  aegis_tool sha512 <file>\n"
               "  aegis_tool list-stats <list.txt>...\n"
               "  aegis_tool explain <psl.dat> <list.txt> <url> <top-url> <type>\n";
  return 2;
}

bool ReadAll(const std::string& path, std::size_t max, std::string* out) {
  auto r = storage::ReadFile(path, max);
  if (r.status != storage::ReadStatus::kOk) {
    std::cerr << "cannot read " << path << "\n";
    return false;
  }
  *out = std::move(r.data);
  return true;
}

VerifiedManifest Verify(const std::string& m, const std::string& s, const std::string& k,
                        std::uint64_t last_seq) {
  std::string manifest, sig, keys;
  VerifiedManifest bad;
  bad.status = ManifestStatus::kMalformed;
  if (!ReadAll(m, 1 << 20, &manifest) || !ReadAll(s, 4096, &sig) || !ReadAll(k, 4096, &keys)) return bad;
  VerifyOptions o;
  o.trusted_keys = ParsePublicKeys(TrimAsciiWhitespace(keys));
  o.last_accepted_sequence = last_seq;
  o.now_unix = std::chrono::duration_cast<std::chrono::seconds>(
                   std::chrono::system_clock::now().time_since_epoch()).count();
  return VerifyManifest(manifest, TrimAsciiWhitespace(sig), o);
}

ResourceType ParseType(const std::string& t) {
  static const std::pair<const char*, ResourceType> kTypes[] = {
      {"document", kResourceDocument}, {"subdocument", kResourceSubdocument},
      {"script", kResourceScript},     {"image", kResourceImage},
      {"stylesheet", kResourceStylesheet}, {"xhr", kResourceXhr},
      {"font", kResourceFont},         {"media", kResourceMedia},
      {"ping", kResourcePing},         {"other", kResourceOther}};
  for (auto& [n, v] : kTypes) if (t == n) return v;
  return kResourceOther;
}

}  // namespace

int main(int argc, char** argv) {
  std::vector<std::string> a(argv + 1, argv + argc);
  if (a.empty()) return Usage();
  const std::string cmd = a[0];
  if (cmd == "verify-manifest" && a.size() >= 4) {
    std::uint64_t last = 0;
    if (a.size() == 6 && a[4] == "--last-sequence" && !ParseUint64(a[5], &last)) return Usage();
    VerifiedManifest v = Verify(a[1], a[2], a[3], last);
    std::cout << ManifestStatusText(v.status) << "\n";
    if (v.status != ManifestStatus::kOk) return 1;
    std::cout << "version " << v.manifest.version.ToString() << ", sequence " << v.manifest.sequence
              << ", chromium " << v.manifest.chromium_version.ToString() << ", "
              << v.manifest.artifacts.size() << " artifact(s)\n";
    return 0;
  }
  if (cmd == "verify-artifact" && a.size() == 5) {
    VerifiedManifest v = Verify(a[1], a[2], a[3], 0);
    if (v.status != ManifestStatus::kOk) {
      std::cout << ManifestStatusText(v.status) << "\n";
      return 1;
    }
    std::string name = std::filesystem::path(a[4]).filename().string();
    for (const auto& art : v.manifest.artifacts) {
      if (art.name == name) {
        bool ok = VerifyArtifactFile(a[4], art);
        std::cout << (ok ? "artifact verified" : "ARTIFACT MISMATCH") << "\n";
        return ok ? 0 : 1;
      }
    }
    std::cout << "artifact not listed in manifest\n";
    return 1;
  }
  if (cmd == "sha512" && a.size() == 2) {
    auto h = Sha512FileHex(a[1], 1ULL << 34);
    if (!h) return 1;
    std::cout << *h << "  " << a[1] << "\n";
    return 0;
  }
  if (cmd == "list-stats" && a.size() >= 2) {
    std::vector<FilterListSource> sources;
    for (std::size_t i = 1; i < a.size(); ++i) {
      FilterListSource s;
      s.id = std::filesystem::path(a[i]).stem().string();
      s.name = s.id;
      if (!ReadAll(a[i], 32 << 20, &s.text)) return 1;
      sources.push_back(std::move(s));
    }
    auto psl = std::make_shared<PublicSuffixList>();
    psl->Load("com\n");  // party detection is irrelevant for statistics
    auto built = FilterEngine::Build(sources, psl);
    if (!built.ok) {
      std::cerr << "build failed: " << built.error << "\n";
      return 1;
    }
    for (const auto& st : built.lists) {
      std::printf("%-16s version=%-14s lines=%zu network=%zu exceptions=%zu cosmetic=%zu "
                  "unsupported=%zu invalid=%zu\n",
                  st.id.c_str(), st.version.c_str(), st.lines, st.network_rules, st.exception_rules,
                  st.cosmetic_skipped, st.unsupported, st.invalid);
    }
    return 0;
  }
  if (cmd == "explain" && a.size() == 6) {
    std::string psl_text, list;
    if (!ReadAll(a[1], 8 << 20, &psl_text) || !ReadAll(a[2], 32 << 20, &list)) return 1;
    auto psl = std::make_shared<PublicSuffixList>();
    if (!psl->Load(psl_text)) return 1;
    FilterListSource s;
    s.id = "list";
    s.text = list;
    auto built = FilterEngine::Build({s}, psl);
    if (!built.ok) return 1;
    auto u = ParseUrl(a[3]);
    auto t = ParseUrl(a[4]);
    if (!u || !t) {
      std::cerr << "invalid URL\n";
      return 1;
    }
    RequestInfo r;
    std::string host = NormalizeHostForMatching(u->host), top = NormalizeHostForMatching(t->host);
    r.url = a[3];
    r.request_host = host;
    r.first_party_host = top;
    r.first_party_url = a[4];
    r.type = ParseType(a[5]);
    r.third_party = psl->IsThirdParty(host, top);
    FilterMatch m = built.engine->Match(r);
    const char* d = m.decision == FilterDecision::kBlock ? "BLOCK"
                    : m.decision == FilterDecision::kAllowedByException ? "ALLOW (exception)" : "no match";
    std::cout << d << (r.third_party ? " [third-party]" : " [first-party]");
    if (m.rule) std::cout << "  rule: " << m.rule->text;
    if (m.exception) std::cout << "  exception: " << m.exception->text;
    std::cout << "\n";
    return 0;
  }
  return Usage();
}

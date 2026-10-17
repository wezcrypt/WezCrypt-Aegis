// WezCrypt Aegis - shared helpers for tests.
#pragma once

#include <memory>
#include <string>
#include <vector>

#include "common/url.h"
#include "filtering/filter_engine.h"
#include "filtering/public_suffix_list.h"
#include "storage/atomic_file.h"
#include "test_framework.h"

namespace aegis_test {

// The real Public Suffix List shipped in assets/data, loaded once.
inline std::shared_ptr<const aegis::PublicSuffixList> RealPsl() {
  static std::shared_ptr<const aegis::PublicSuffixList> psl = [] {
    auto p = std::make_shared<aegis::PublicSuffixList>();
    auto r = aegis::storage::ReadFile(SourceDir() / "assets/data/public_suffix_list.dat",
                                      8 * 1024 * 1024);
    if (r.status != aegis::storage::ReadStatus::kOk || !p->Load(r.data)) {
      ReportFailure(__FILE__, __LINE__, "could not load bundled public suffix list");
    }
    return std::shared_ptr<const aegis::PublicSuffixList>(p);
  }();
  return psl;
}

inline std::string ReadAsset(const std::string& rel) {
  auto r = aegis::storage::ReadFile(SourceDir() / rel, 32 * 1024 * 1024);
  return r.status == aegis::storage::ReadStatus::kOk ? r.data : std::string();
}

inline std::shared_ptr<const aegis::FilterEngine> EngineFromRules(
    const std::string& rules, aegis::ListCategory cat = aegis::ListCategory::kAdvertising,
    const std::string& id = "test") {
  aegis::FilterListSource src;
  src.id = id;
  src.name = id;
  src.category = cat;
  src.text = rules;
  auto built = aegis::FilterEngine::Build({src}, RealPsl());
  if (!built.ok) ReportFailure(__FILE__, __LINE__, "engine build failed: " + built.error);
  return built.engine;
}

// Builds a RequestInfo with host and party computed from URLs.
struct Req {
  std::string url;
  std::string host;
  std::string fp_host;
  std::string fp_url;
  aegis::RequestInfo info;
};

inline Req MakeReq(const std::string& url, const std::string& top_url, aegis::ResourceType type) {
  Req r;
  r.url = url;
  r.fp_url = top_url;
  auto u = aegis::ParseUrl(url);
  auto t = aegis::ParseUrl(top_url);
  r.host = u ? aegis::NormalizeHostForMatching(u->host) : "";
  r.fp_host = t ? aegis::NormalizeHostForMatching(t->host) : "";
  r.info.url = r.url;
  r.info.request_host = r.host;
  r.info.first_party_host = r.fp_host;
  r.info.first_party_url = r.fp_url;
  r.info.type = type;
  r.info.third_party = RealPsl()->IsThirdParty(r.host, r.fp_host);
  return r;
}
}  // namespace aegis_test

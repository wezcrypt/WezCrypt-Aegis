// Integration tests: real bundled EasyList + EasyPrivacy + Public Suffix
// List evaluated through the same policy pipeline the CEF request handler
// calls before any network access (required tests 1, 2, 3, 6, 12, 13).
#include <fstream>

#include "filtering/filter_list_manager.h"
#include "security/security_policy.h"
#include "storage/atomic_file.h"
#include "test_support.h"

using namespace aegis;
using aegis_test::RealPsl;
using aegis_test::ReadAsset;

namespace {

std::filesystem::path BundledFiltersDir() { return aegis_test::SourceDir() / "assets/filters"; }

std::shared_ptr<FilterListManager> RealManager(const std::filesystem::path& cache) {
  auto m = std::make_shared<FilterListManager>(BundledFiltersDir(), cache, RealPsl());
  if (!m->Initialize(FilterListManager::DefaultLists(), {})) {
    aegis_test::ReportFailure(__FILE__, __LINE__, "filter manager failed to initialize");
  }
  return m;
}

RequestDecision Eval(const PolicySnapshot& p, const std::string& url, const std::string& top,
                     ResourceType type) {
  RequestContext c;
  c.url = url;
  c.top_level_url = top;
  c.type = type;
  return EvaluateRequest(p, c);
}

}  // namespace

TEST(Pipeline, BundledListsLoadWithRealisticRuleCounts) {
  auto m = RealManager(aegis_test::TempDir());
  auto status = m->Status();
  ASSERT_TRUE(status.size() == 3);
  for (const auto& s : status) {
    EXPECT_EQ(s.source, std::string("bundled"));
    if (s.config.id != "aegis-baseline") {
      EXPECT_TRUE(s.stats.network_rules > 5000);
      EXPECT_FALSE(s.stats.version.empty());
    }
  }
  EXPECT_TRUE(m->engine()->rule_count() > 20000);
}

TEST(Pipeline, ThirdPartyAdsBlockedBeforeFetch) {
  auto m = RealManager(aegis_test::TempDir());
  Settings s;
  s.mode = SecurityMode::kCompatibility;  // weakest mode: only filters apply
  auto p = PolicySnapshot::Create(s, m->engine(), RealPsl());
  struct C { const char* url; ResourceType type; EventCategory cat; };
  const C cases[] = {
      {"https://ib.adnxs.com/ut/v3/prebid", kResourceXhr, EventCategory::kAdvertising},
      {"https://aax.amazon-adsystem.com/e/dtb/bid", kResourceScript, EventCategory::kAdvertising},
      // popads.net is on the built-in baseline list, which is evaluated first.
      {"https://c1.popads.net/pop.js", kResourceScript, EventCategory::kUserRule},
      {"https://www.googletagmanager.com/gtm.js?id=GTM-XXXX", kResourceScript,
       EventCategory::kTracker},
      {"https://www.google-analytics.com/analytics.js", kResourceScript, EventCategory::kTracker},
  };
  for (const auto& c : cases) {
    auto d = Eval(*p, c.url, "https://news.example.org/article", c.type);
    EXPECT_TRUE(d.action == RequestAction::kBlock);
    EXPECT_TRUE(d.category == c.cat);
    if (d.category != c.cat) {
      aegis_test::ReportFailure(__FILE__, __LINE__, std::string("category mismatch for ") + c.url +
                                                         " list=" + d.list + " rule=" + d.rule);
    }
    EXPECT_FALSE(d.rule.empty());
  }
}

TEST(Pipeline, LegitimateRequestsStillLoad) {
  auto m = RealManager(aegis_test::TempDir());
  Settings s;
  s.mode = SecurityMode::kCompatibility;
  auto p = PolicySnapshot::Create(s, m->engine(), RealPsl());
  const char* allowed[] = {
      "https://en.wikipedia.org/static/images/project-logos/enwiki.png",
      "https://upload.wikimedia.org/wikipedia/commons/a/a9/Example.jpg",
      "https://cdnjs.cloudflare.com/ajax/libs/jquery/3.7.1/jquery.min.js",
      "https://fonts.gstatic.com/s/inter/v13/font.woff2",
      "https://news.example.org/assets/app.css",
  };
  for (const char* u : allowed) {
    auto d = Eval(*p, u, "https://news.example.org/article", kResourceImage);
    EXPECT_TRUE(d.action == RequestAction::kAllow);
    if (d.action != RequestAction::kAllow) {
      aegis_test::ReportFailure(__FILE__, __LINE__, std::string("unexpectedly blocked: ") + u +
                                                         " by " + d.rule);
    }
  }
  auto doc = PolicySnapshot::Create(s, m->engine(), RealPsl());
  RequestContext nav;
  nav.url = "https://en.wikipedia.org/wiki/Web_browser";
  nav.type = kResourceDocument;
  nav.is_main_frame = true;
  EXPECT_TRUE(EvaluateRequest(*doc, nav).action == RequestAction::kAllow);
}

TEST(Pipeline, RedirectTargetsAreReevaluated) {
  // A first-party click-tracking URL redirects to an ad server. The request
  // handler evaluates every redirect target with the same context, so the
  // ad server is never contacted.
  auto m = RealManager(aegis_test::TempDir());
  Settings s;
  s.mode = SecurityMode::kCompatibility;
  auto p = PolicySnapshot::Create(s, m->engine(), RealPsl());
  const std::string top = "https://news.example.org/";
  auto hop1 = Eval(*p, "https://news.example.org/out?id=42", top, kResourceScript);
  EXPECT_TRUE(hop1.action == RequestAction::kAllow);
  auto hop2 = Eval(*p, "https://ib.adnxs.com/getuid?redirect", top, kResourceScript);
  EXPECT_TRUE(hop2.action == RequestAction::kBlock);
}

TEST(Pipeline, UserRulesAndExceptions) {
  auto m = RealManager(aegis_test::TempDir());
  ASSERT_TRUE(m->SetUserRules({"||annoying-widget.test^", "@@||ib.adnxs.com/allowed-for-test^"}));
  Settings s;
  s.mode = SecurityMode::kCompatibility;
  auto p = PolicySnapshot::Create(s, m->engine(), RealPsl());
  auto d = Eval(*p, "https://annoying-widget.test/w.js", "https://site.example/", kResourceScript);
  EXPECT_TRUE(d.action == RequestAction::kBlock);
  EXPECT_TRUE(d.category == EventCategory::kUserRule);
  EXPECT_TRUE(Eval(*p, "https://ib.adnxs.com/allowed-for-test", "https://site.example/", kResourceXhr)
                  .action == RequestAction::kAllow);
}

TEST(Pipeline, FilterUpdateFailuresNeverWeakenRules) {
  auto cache = aegis_test::TempDir();
  auto m = RealManager(cache);
  auto before = m->engine();
  const std::size_t rules_before = before->rule_count();

  std::string tiny = "[Adblock Plus 2.0]\n! Title: EasyList\n||only-one.example^\n";
  std::string html = "<!DOCTYPE html><html><body>Captive portal login</body></html>";
  std::string binary("\x7f" "ELF\x00\x01\x02", 7);
  std::string mostly_invalid = "[Adblock Plus 2.0]\n! Title: EasyList\n";
  for (int i = 0; i < 6000; ++i) mostly_invalid += "||bad" + std::to_string(i) + ".example^$script,~script\n";
  for (int i = 0; i < 6000; ++i) mostly_invalid += "||ok" + std::to_string(i) + ".example^\n";
  std::string huge(FilterListManager::kMaxListBytes + 1, 'a');

  EXPECT_TRUE(m->ApplyUpdate("easylist", tiny) == UpdateOutcome::kRejectedTooFewRules);
  EXPECT_TRUE(m->ApplyUpdate("easylist", html) == UpdateOutcome::kRejectedNotAFilterList);
  EXPECT_TRUE(m->ApplyUpdate("easylist", binary) == UpdateOutcome::kRejectedNotAFilterList);
  EXPECT_TRUE(m->ApplyUpdate("easylist", huge) == UpdateOutcome::kRejectedTooLarge);
  EXPECT_TRUE(m->ApplyUpdate("easylist", mostly_invalid) == UpdateOutcome::kRejectedShrankTooMuch ||
              m->ApplyUpdate("easylist", mostly_invalid) == UpdateOutcome::kRejectedTooManyInvalid);
  EXPECT_TRUE(m->ApplyUpdate("unknown-list", tiny) == UpdateOutcome::kRejectedUnknownList);

  // The active engine is unchanged and still blocks.
  EXPECT_TRUE(m->engine() == before);
  EXPECT_EQ(m->engine()->rule_count(), rules_before);
  Settings s;
  s.mode = SecurityMode::kCompatibility;
  auto p = PolicySnapshot::Create(s, m->engine(), RealPsl());
  EXPECT_TRUE(Eval(*p, "https://ib.adnxs.com/ut/v3", "https://site.example/", kResourceXhr).action ==
              RequestAction::kBlock);
  // No cache file was written for rejected updates.
  EXPECT_FALSE(std::filesystem::exists(cache / "easylist.txt"));
  for (const auto& st : m->Status()) {
    if (st.config.id == "easylist") EXPECT_FALSE(st.last_error.empty());
  }
}

TEST(Pipeline, ValidUpdateIsAppliedPersistedAndSurvivesRestart) {
  auto cache = aegis_test::TempDir();
  std::string updated = ReadAsset("assets/filters/easylist.txt");
  ASSERT_TRUE(!updated.empty());
  updated += "\n||freshly-added-adserver.example^\n";
  {
    auto m = RealManager(cache);
    EXPECT_TRUE(m->ApplyUpdate("easylist", updated) == UpdateOutcome::kApplied);
    EXPECT_TRUE(m->ApplyUpdate("easylist", updated) == UpdateOutcome::kUnchanged);
  }
  EXPECT_TRUE(std::filesystem::exists(cache / "easylist.txt"));
  auto restarted = RealManager(cache);
  Settings s;
  auto p = PolicySnapshot::Create(s, restarted->engine(), RealPsl());
  EXPECT_TRUE(Eval(*p, "https://freshly-added-adserver.example/a.js", "https://site.example/",
                   kResourceScript).category == EventCategory::kAdvertising);
  for (const auto& st : restarted->Status()) {
    if (st.config.id == "easylist") EXPECT_EQ(st.source, std::string("cache"));
  }
}

TEST(Pipeline, CorruptCacheFallsBackToBundledLists) {
  auto cache = aegis_test::TempDir();
  { std::ofstream(cache / "easylist.txt", std::ios::binary) << "<html>not a list</html>"; }
  auto m = RealManager(cache);
  for (const auto& st : m->Status()) {
    if (st.config.id == "easylist") EXPECT_EQ(st.source, std::string("bundled"));
  }
  EXPECT_TRUE(m->engine()->rule_count() > 20000);
}

TEST(Pipeline, PerSiteExceptionsUseRegistrableDomains) {
  auto m = RealManager(aegis_test::TempDir());
  auto psl = RealPsl();
  Settings s;
  s.mode = SecurityMode::kMaximumIsolation;
  std::string key = MakeSiteExceptionKey(*psl, "https://shop.example.co.uk/cart", false);
  EXPECT_EQ(key, std::string("example.co.uk"));
  s.site_exceptions[key].allow_third_party = true;
  auto p = PolicySnapshot::Create(s, m->engine(), psl);
  EXPECT_TRUE(Eval(*p, "https://cdn.payments.test/pay.css", "https://www.example.co.uk/",
                   kResourceStylesheet).action == RequestAction::kAllow);
  // Same registrable label under another suffix is a different site.
  EXPECT_TRUE(Eval(*p, "https://cdn.payments.test/pay.css", "https://www.example.co.jp/",
                   kResourceStylesheet).action == RequestAction::kBlock);
  // github.io tenants are separate sites.
  Settings g;
  g.mode = SecurityMode::kMaximumIsolation;
  g.site_exceptions[MakeSiteExceptionKey(*psl, "alice.github.io", false)].allow_third_party = true;
  auto pg = PolicySnapshot::Create(g, m->engine(), psl);
  EXPECT_TRUE(Eval(*pg, "https://cdn.other.test/x.png", "https://alice.github.io/", kResourceImage)
                  .action == RequestAction::kAllow);
  EXPECT_TRUE(Eval(*pg, "https://cdn.other.test/x.png", "https://mallory.github.io/", kResourceImage)
                  .action == RequestAction::kBlock);
}

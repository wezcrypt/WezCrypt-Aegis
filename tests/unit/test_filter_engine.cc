#include "filtering/filter_engine.h"
#include "test_support.h"

using namespace aegis;
using aegis_test::EngineFromRules;
using aegis_test::MakeReq;

namespace {
FilterDecision Decide(const FilterEngine& e, const std::string& url, const std::string& top,
                      ResourceType type) {
  auto r = MakeReq(url, top, type);
  return e.Match(r.info).decision;
}
}  // namespace

TEST(FilterPattern, WildcardsAndSeparators) {
  auto m = [](const char* pat, const char* url, bool l = false, bool r = false) {
    return MatchFilterPattern(pat, url, l, r, 0, 0, false);
  };
  EXPECT_TRUE(m("/ads/", "https://x.example/ads/banner.png"));
  EXPECT_FALSE(m("/ads/", "https://x.example/adsx/banner.png"));
  EXPECT_TRUE(m("banner*.gif", "https://x.example/img/banner_300x250.gif"));
  EXPECT_TRUE(m("ad^", "https://x.example/ad?x=1"));
  EXPECT_TRUE(m("ad^", "https://x.example/ad"));  // ^ matches end of URL
  EXPECT_FALSE(m("ad^", "https://x.example/adx"));
  EXPECT_TRUE(m("https://x", "https://x.example/", true));
  EXPECT_FALSE(m("x.example/", "https://x.example/", true));
  EXPECT_TRUE(m(".gif", "https://x.example/a.gif", false, true));
  EXPECT_FALSE(m(".gif", "https://x.example/a.gif?x", false, true));
  EXPECT_TRUE(m("a*b*c", "https://x/aXXbYYc", false, true));
  EXPECT_FALSE(m("a*b*c", "https://x/aXXbYYcd", false, true));
}

TEST(FilterEngine, DomainAnchorMatchesHostAndSubdomainsOnly) {
  auto e = EngineFromRules("||ads.example^\n");
  const std::string top = "https://news.site.test/";
  EXPECT_EQ(Decide(*e, "https://ads.example/x.js", top, kResourceScript), FilterDecision::kBlock);
  EXPECT_EQ(Decide(*e, "https://cdn.ads.example/x.js", top, kResourceScript), FilterDecision::kBlock);
  EXPECT_EQ(Decide(*e, "https://badads.example/x.js", top, kResourceScript), FilterDecision::kNoMatch);
  EXPECT_EQ(Decide(*e, "https://ads.example.org/x.js", top, kResourceScript), FilterDecision::kNoMatch);
  EXPECT_EQ(Decide(*e, "https://site.test/?ref=ads.example", top, kResourceImage),
            FilterDecision::kNoMatch);
}

TEST(FilterEngine, NonTerminatedDomainAnchorIsPrefixMatch) {
  // ABP semantics: "||example.com" without ^ also matches example.community.
  auto e = EngineFromRules("||adtrack\n");
  const std::string top = "https://site.test/";
  EXPECT_EQ(Decide(*e, "https://adtracker.example/p", top, kResourceImage), FilterDecision::kBlock);
  EXPECT_EQ(Decide(*e, "https://x.adtrack.example/p", top, kResourceImage), FilterDecision::kBlock);
}

TEST(FilterEngine, ThirdPartyOption) {
  auto e = EngineFromRules("||widgets.example^$third-party\n");
  EXPECT_EQ(Decide(*e, "https://widgets.example/w.js", "https://blog.test/", kResourceScript),
            FilterDecision::kBlock);
  EXPECT_EQ(Decide(*e, "https://widgets.example/w.js", "https://www.widgets.example/",
                   kResourceScript),
            FilterDecision::kNoMatch);
}

TEST(FilterEngine, ResourceTypeOptions) {
  auto e = EngineFromRules("||media.example^$image\n/track.js$script\n");
  const std::string top = "https://site.test/";
  EXPECT_EQ(Decide(*e, "https://media.example/a.png", top, kResourceImage), FilterDecision::kBlock);
  EXPECT_EQ(Decide(*e, "https://media.example/a.css", top, kResourceStylesheet),
            FilterDecision::kNoMatch);
  EXPECT_EQ(Decide(*e, "https://x.test/track.js", top, kResourceScript), FilterDecision::kBlock);
  EXPECT_EQ(Decide(*e, "https://x.test/track.js", top, kResourceXhr), FilterDecision::kNoMatch);
}

TEST(FilterEngine, DocumentsNeedStrictHostRules) {
  auto e = EngineFromRules("||malvert.example^\n/popunder/*\n");
  EXPECT_EQ(Decide(*e, "https://malvert.example/landing", "https://malvert.example/landing",
                   kResourceDocument),
            FilterDecision::kBlock);
  // Generic path rules never block top-level documents.
  EXPECT_EQ(Decide(*e, "https://site.test/popunder/x", "https://site.test/popunder/x",
                   kResourceDocument),
            FilterDecision::kNoMatch);
}

TEST(FilterEngine, DomainOptionScopesRules) {
  auto e = EngineFromRules("/sponsor/*$domain=news.test|~sports.news.test\n");
  EXPECT_EQ(Decide(*e, "https://cdn.test/sponsor/a.png", "https://www.news.test/", kResourceImage),
            FilterDecision::kBlock);
  EXPECT_EQ(Decide(*e, "https://cdn.test/sponsor/a.png", "https://sports.news.test/", kResourceImage),
            FilterDecision::kNoMatch);
  EXPECT_EQ(Decide(*e, "https://cdn.test/sponsor/a.png", "https://other.test/", kResourceImage),
            FilterDecision::kNoMatch);
  auto entity = EngineFromRules("/promo/*$domain=shop.*\n");
  EXPECT_EQ(Decide(*entity, "https://x.test/promo/1", "https://www.shop.co.uk/", kResourceImage),
            FilterDecision::kBlock);
  EXPECT_EQ(Decide(*entity, "https://x.test/promo/1", "https://shop.example.com/", kResourceImage),
            FilterDecision::kNoMatch);
}

TEST(FilterEngine, ExceptionsAndImportant) {
  auto e = EngineFromRules(
      "||ads.example^\n@@||ads.example/allowed/\n||must.example^$important\n@@||must.example^\n");
  const std::string top = "https://site.test/";
  EXPECT_EQ(Decide(*e, "https://ads.example/banner", top, kResourceImage), FilterDecision::kBlock);
  EXPECT_EQ(Decide(*e, "https://ads.example/allowed/x", top, kResourceImage),
            FilterDecision::kAllowedByException);
  EXPECT_EQ(Decide(*e, "https://must.example/x", top, kResourceImage), FilterDecision::kBlock);
}

TEST(FilterEngine, DocumentExceptionAllowlistsPage) {
  auto e = EngineFromRules("||ads.example^\n@@||trusted.test^$document\n");
  EXPECT_EQ(Decide(*e, "https://ads.example/a", "https://trusted.test/page", kResourceScript),
            FilterDecision::kAllowedByException);
  EXPECT_EQ(Decide(*e, "https://ads.example/a", "https://other.test/page", kResourceScript),
            FilterDecision::kBlock);
}

TEST(FilterEngine, BadFilterDisablesRule) {
  auto e = EngineFromRules("||ads.example^$script\n||ads.example^$script,badfilter\n");
  EXPECT_EQ(Decide(*e, "https://ads.example/a.js", "https://site.test/", kResourceScript),
            FilterDecision::kNoMatch);
}

TEST(FilterEngine, MatchCase) {
  auto e = EngineFromRules("/AdBanner/*$match-case\n");
  const std::string top = "https://site.test/";
  EXPECT_EQ(Decide(*e, "https://x.test/AdBanner/1", top, kResourceImage), FilterDecision::kBlock);
  EXPECT_EQ(Decide(*e, "https://x.test/adbanner/1", top, kResourceImage), FilterDecision::kNoMatch);
}

TEST(FilterEngine, ReportsMatchedRuleForExplanations) {
  auto e = EngineFromRules("||ads.example^$third-party\n", ListCategory::kAdvertising, "easylist");
  auto r = MakeReq("https://ads.example/a.js", "https://site.test/", kResourceScript);
  FilterMatch m = e->Match(r.info);
  ASSERT_TRUE(m.rule != nullptr);
  EXPECT_EQ(m.rule->text, std::string("||ads.example^$third-party"));
  EXPECT_EQ(m.list_id, std::string("easylist"));
  EXPECT_TRUE(m.category == ListCategory::kAdvertising);
}

TEST(FilterEngine, EnforcesBuildLimits) {
  FilterListSource src;
  src.id = "big";
  src.text = std::string(100, 'x');
  EngineLimits limits;
  limits.max_list_bytes = 10;
  auto built = FilterEngine::Build({src}, aegis_test::RealPsl(), limits);
  EXPECT_FALSE(built.ok);
  EngineLimits few;
  few.max_total_rules = 2;
  src.text = "||a.example^\n||b.example^\n||c.example^\n";
  EXPECT_FALSE(FilterEngine::Build({src}, aegis_test::RealPsl(), few).ok);
  EXPECT_FALSE(FilterEngine::Build({src}, nullptr).ok);
}

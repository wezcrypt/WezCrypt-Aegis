#include "security/security_policy.h"
#include "test_support.h"

using namespace aegis;
using aegis_test::EngineFromRules;
using aegis_test::RealPsl;

namespace {

std::shared_ptr<const PolicySnapshot> Policy(SecurityMode mode, Settings s = Settings(),
                                             const std::string& rules = "||ads.example^\n") {
  s.mode = mode;
  return PolicySnapshot::Create(s, EngineFromRules(rules), RealPsl());
}

RequestDecision Eval(const PolicySnapshot& p, const std::string& url, const std::string& top,
                     ResourceType type, bool main_frame = false) {
  RequestContext c;
  c.url = url;
  c.top_level_url = top;
  c.type = type;
  c.is_main_frame = main_frame;
  return EvaluateRequest(p, c);
}

}  // namespace

TEST(Policy, FilterListBlocksAdsInEveryMode) {
  for (SecurityMode m : {SecurityMode::kMaximumIsolation, SecurityMode::kStrictProtection,
                         SecurityMode::kCompatibility}) {
    auto p = Policy(m);
    auto d = Eval(*p, "https://ads.example/banner.png", "https://news.test/", kResourceImage);
    EXPECT_TRUE(d.action == RequestAction::kBlock);
    EXPECT_TRUE(d.category == EventCategory::kAdvertising);
    EXPECT_EQ(d.rule, std::string("||ads.example^"));
    EXPECT_EQ(d.site, std::string("news.test"));
  }
}

TEST(Policy, AllowedFirstPartyRequestsProceed) {
  auto p = Policy(SecurityMode::kMaximumIsolation);
  auto d = Eval(*p, "https://static.news.test/style.css", "https://www.news.test/", kResourceStylesheet);
  EXPECT_TRUE(d.action == RequestAction::kAllow);
  EXPECT_FALSE(d.third_party);
  auto img = Eval(*p, "https://www.news.test/logo.png", "https://www.news.test/", kResourceImage);
  EXPECT_TRUE(img.action == RequestAction::kAllow);
}

TEST(Policy, MaximumIsolationBlocksScriptsAndThirdParty) {
  auto p = Policy(SecurityMode::kMaximumIsolation);
  auto s = Eval(*p, "https://www.news.test/app.js", "https://www.news.test/", kResourceScript);
  EXPECT_TRUE(s.action == RequestAction::kBlock);
  EXPECT_TRUE(s.category == EventCategory::kScript);
  auto f = Eval(*p, "https://embed.video.test/player", "https://www.news.test/", kResourceSubdocument);
  EXPECT_TRUE(f.action == RequestAction::kBlock);
  EXPECT_TRUE(f.category == EventCategory::kThirdPartyFrame);
  auto i = Eval(*p, "https://cdn.other.test/img.png", "https://www.news.test/", kResourceImage);
  EXPECT_TRUE(i.action == RequestAction::kBlock);
  EXPECT_TRUE(i.category == EventCategory::kThirdPartyRequest);
}

TEST(Policy, StrictBlocksThirdPartyFramesOnly) {
  auto p = Policy(SecurityMode::kStrictProtection);
  EXPECT_TRUE(Eval(*p, "https://embed.video.test/player", "https://www.news.test/",
                   kResourceSubdocument).action == RequestAction::kBlock);
  EXPECT_TRUE(Eval(*p, "https://cdn.other.test/lib.js", "https://www.news.test/",
                   kResourceScript).action == RequestAction::kAllow);
  EXPECT_TRUE(Eval(*p, "https://www.news.test/app.js", "https://www.news.test/",
                   kResourceScript).action == RequestAction::kAllow);
}

TEST(Policy, CompatibilityAllowsFramesButKeepsFilters) {
  auto p = Policy(SecurityMode::kCompatibility);
  EXPECT_TRUE(Eval(*p, "https://embed.video.test/player", "https://www.news.test/",
                   kResourceSubdocument).action == RequestAction::kAllow);
  EXPECT_TRUE(Eval(*p, "https://ads.example/frame", "https://www.news.test/",
                   kResourceSubdocument).action == RequestAction::kBlock);
}

TEST(Policy, SiteExceptionsApplyOnlyToIntendedSite) {
  Settings s;
  s.site_exceptions["news.test"].allow_third_party = true;
  s.site_exceptions["news.test"].allow_javascript = true;
  auto p = Policy(SecurityMode::kMaximumIsolation, s);
  // Intended site and its subdomains.
  EXPECT_TRUE(Eval(*p, "https://cdn.other.test/a.png", "https://www.news.test/", kResourceImage)
                  .action == RequestAction::kAllow);
  EXPECT_TRUE(Eval(*p, "https://www.news.test/app.js", "https://news.test/", kResourceScript)
                  .action == RequestAction::kAllow);
  // Look-alike and unrelated sites keep full protection.
  for (const char* top : {"https://news.test.evil.example/", "https://notnews.test/",
                          "https://other.test/", "https://news.tes/"}) {
    EXPECT_TRUE(Eval(*p, "https://cdn.other2.test/a.png", top, kResourceImage).action ==
                RequestAction::kBlock);
  }
  // Exceptions relax mode policy, not the ad filter.
  EXPECT_TRUE(Eval(*p, "https://ads.example/a.png", "https://www.news.test/", kResourceImage)
                  .action == RequestAction::kBlock);
}

TEST(Policy, ExactHostExceptionDoesNotCoverSiblings) {
  Settings s;
  s.site_exceptions["=app.news.test"].allow_javascript = true;
  auto p = Policy(SecurityMode::kMaximumIsolation, s);
  EXPECT_TRUE(IsJavaScriptAllowed(*p, "https://app.news.test/"));
  EXPECT_FALSE(IsJavaScriptAllowed(*p, "https://www.news.test/"));
  EXPECT_FALSE(IsJavaScriptAllowed(*p, "https://news.test/"));
}

TEST(Policy, DisableFilteringExceptionScopedToSite) {
  Settings s;
  s.site_exceptions["trusted.test"].disable_filtering = true;
  auto p = Policy(SecurityMode::kCompatibility, s);
  EXPECT_TRUE(Eval(*p, "https://ads.example/a.js", "https://trusted.test/", kResourceScript).action ==
              RequestAction::kAllow);
  EXPECT_TRUE(Eval(*p, "https://ads.example/a.js", "https://untrusted.test/", kResourceScript).action ==
              RequestAction::kBlock);
}

TEST(Policy, ExceptionKeysRefusePublicSuffixes) {
  auto psl = RealPsl();
  EXPECT_EQ(MakeSiteExceptionKey(*psl, "https://www.example.co.uk/page", false),
            std::string("example.co.uk"));
  EXPECT_EQ(MakeSiteExceptionKey(*psl, "github.io", false), std::string(""));
  EXPECT_EQ(MakeSiteExceptionKey(*psl, "co.uk", false), std::string(""));
  EXPECT_EQ(MakeSiteExceptionKey(*psl, "alice.github.io", false), std::string("alice.github.io"));
  EXPECT_EQ(MakeSiteExceptionKey(*psl, "https://App.Example.com/", true),
            std::string("=app.example.com"));
  EXPECT_EQ(MakeSiteExceptionKey(*psl, "bad host!", false), std::string(""));
}

TEST(Policy, JavaScriptPolicyPerMode) {
  Settings s;
  s.javascript_blocked_sites.insert("blocked.test");
  auto a = Policy(SecurityMode::kMaximumIsolation, s);
  auto b = Policy(SecurityMode::kStrictProtection, s);
  auto c = Policy(SecurityMode::kCompatibility, s);
  EXPECT_FALSE(IsJavaScriptAllowed(*a, "https://site.test/"));
  EXPECT_TRUE(IsJavaScriptAllowed(*b, "https://site.test/"));
  EXPECT_FALSE(IsJavaScriptAllowed(*b, "https://www.blocked.test/"));
  EXPECT_TRUE(IsJavaScriptAllowed(*c, "https://www.blocked.test/"));
  EXPECT_FALSE(IsJavaScriptAllowed(*c, "aegis://security/"));
  EXPECT_FALSE(IsJavaScriptOptimizerAllowed(*a, "https://site.test/"));
  EXPECT_FALSE(IsJavaScriptOptimizerAllowed(*b, "https://site.test/"));
  EXPECT_TRUE(IsJavaScriptOptimizerAllowed(*c, "https://site.test/"));
  // Strict mode also blocks script *requests* for JS-blocked sites.
  EXPECT_TRUE(Eval(*b, "https://www.blocked.test/a.js", "https://www.blocked.test/", kResourceScript)
                  .action == RequestAction::kBlock);
}

TEST(Policy, HttpsFirstUpgradesTopLevelNavigation) {
  auto p = Policy(SecurityMode::kStrictProtection);
  auto d = Eval(*p, "http://www.news.test/a?b=1", "", kResourceDocument, true);
  EXPECT_TRUE(d.action == RequestAction::kUpgradeToHttps);
  EXPECT_EQ(d.upgraded_url, std::string("https://www.news.test/a?b=1"));
  // Local hosts and user-approved hosts stay on HTTP.
  EXPECT_TRUE(Eval(*p, "http://localhost:3000/", "", kResourceDocument, true).action ==
              RequestAction::kAllow);
  Settings s;
  s.http_allowed_hosts.insert("legacy.test");
  auto q = Policy(SecurityMode::kStrictProtection, s);
  EXPECT_TRUE(Eval(*q, "http://legacy.test/", "", kResourceDocument, true).action ==
              RequestAction::kAllow);
}

TEST(Policy, TopLevelNavigationToAdHostIsInterstitialed) {
  auto p = Policy(SecurityMode::kCompatibility);
  auto d = Eval(*p, "https://ads.example/landing", "", kResourceDocument, true);
  EXPECT_TRUE(d.action == RequestAction::kBlockWithInterstitial);
  EXPECT_TRUE(d.category == EventCategory::kNavigation);
}

TEST(Policy, PrivateNetworkFromPublicPageBlocked) {
  auto p = Policy(SecurityMode::kCompatibility);
  auto d = Eval(*p, "http://192.168.1.1/cgi-bin/reboot", "https://evil.test/", kResourceImage);
  EXPECT_TRUE(d.action == RequestAction::kBlock);
  EXPECT_TRUE(d.category == EventCategory::kPrivateNetwork);
  auto local_top = Eval(*p, "http://127.0.0.1:8080/api", "http://localhost:3000/", kResourceXhr);
  EXPECT_TRUE(local_top.action == RequestAction::kAllow);
}

TEST(Policy, UnsafeSchemesForSubresources) {
  auto p = Policy(SecurityMode::kCompatibility);
  EXPECT_TRUE(Eval(*p, "file:///C:/Windows/win.ini", "https://evil.test/", kResourceImage).action ==
              RequestAction::kBlock);
  EXPECT_TRUE(Eval(*p, "aegis://security/", "https://evil.test/", kResourceSubdocument).action ==
              RequestAction::kBlock);
  EXPECT_TRUE(Eval(*p, "chrome://settings/", "https://evil.test/", kResourceSubdocument).action ==
              RequestAction::kBlock);
  EXPECT_TRUE(Eval(*p, "data:image/png;base64,AAAA", "https://site.test/", kResourceImage).action ==
              RequestAction::kAllow);
  EXPECT_TRUE(Eval(*p, "::not a url::", "https://site.test/", kResourceImage).action ==
              RequestAction::kBlock);
}

TEST(Policy, ServiceWorkerScriptsAreBlockedInEveryMode) {
  for (SecurityMode m : {SecurityMode::kMaximumIsolation, SecurityMode::kStrictProtection,
                         SecurityMode::kCompatibility}) {
    auto p = Policy(m);
    RequestContext c;
    c.url = "https://app.test/sw.js";
    c.top_level_url = "https://app.test/";
    c.type = kResourceScript;
    c.is_service_worker_script = true;
    auto d = EvaluateRequest(*p, c);
    EXPECT_TRUE(d.action == RequestAction::kBlock);
    EXPECT_TRUE(d.category == EventCategory::kScript);
  }
}

TEST(Policy, PopupsRequireGestureAndPassFilters) {
  auto p = Policy(SecurityMode::kStrictProtection, Settings(), "||popads.example^$popup\n");
  PopupContext c;
  c.opener_url = "https://site.test/";
  c.target_url = "https://other.test/";
  c.user_gesture = false;
  EXPECT_TRUE(EvaluatePopup(*p, c).action == PopupAction::kBlock);
  c.user_gesture = true;
  EXPECT_TRUE(EvaluatePopup(*p, c).action == PopupAction::kOpenAsTab);
  c.target_url = "https://popads.example/x";
  EXPECT_TRUE(EvaluatePopup(*p, c).action == PopupAction::kBlock);
  c.target_url = "javascript:alert(1)";
  EXPECT_TRUE(EvaluatePopup(*p, c).action == PopupAction::kBlock);
  auto a = Policy(SecurityMode::kMaximumIsolation);
  PopupContext win;
  win.opener_url = "https://site.test/";
  win.target_url = "https://other.test/";
  win.user_gesture = true;
  win.is_new_foreground_tab_disposition = false;  // window.open with features
  EXPECT_TRUE(EvaluatePopup(*a, win).action == PopupAction::kBlock);
  win.is_new_foreground_tab_disposition = true;
  EXPECT_TRUE(EvaluatePopup(*a, win).action == PopupAction::kOpenAsTab);
}

TEST(Policy, NavigationSchemePolicy) {
  auto p = Policy(SecurityMode::kCompatibility);
  NavigationContext n;
  n.target_url = "file:///C:/Users/me/secret.txt";
  n.current_url = "https://evil.test/";
  EXPECT_TRUE(EvaluateNavigation(*p, n).action == NavigationAction::kBlock);
  n.typed_by_user = true;
  n.current_url = "";
  EXPECT_TRUE(EvaluateNavigation(*p, n).action == NavigationAction::kAllow);
  NavigationContext internal;
  internal.target_url = "aegis://security/";
  internal.current_url = "https://evil.test/";
  EXPECT_TRUE(EvaluateNavigation(*p, internal).action == NavigationAction::kBlock);
  internal.current_url = "aegis://newtab/";
  EXPECT_TRUE(EvaluateNavigation(*p, internal).action == NavigationAction::kAllow);
  NavigationContext data;
  data.target_url = "data:text/html,<h1>phish</h1>";
  data.current_url = "https://evil.test/";
  EXPECT_TRUE(EvaluateNavigation(*p, data).action == NavigationAction::kBlock);
  NavigationContext js;
  js.target_url = "javascript:alert(1)";
  EXPECT_TRUE(EvaluateNavigation(*p, js).action == NavigationAction::kBlock);
  NavigationContext web;
  web.target_url = "https://example.com/";
  web.current_url = "https://site.test/";
  EXPECT_TRUE(EvaluateNavigation(*p, web).action == NavigationAction::kAllow);
}

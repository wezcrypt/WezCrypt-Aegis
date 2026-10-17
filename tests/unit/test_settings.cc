#include "storage/settings.h"
#include "storage/settings_store.h"
#include "test_framework.h"

using namespace aegis;

TEST(Settings, DefaultsAreSecure) {
  Settings s;
  EXPECT_TRUE(s.mode == SecurityMode::kMaximumIsolation);
  EXPECT_TRUE(s.https_first);
  EXPECT_TRUE(s.block_third_party_cookies);
  EXPECT_FALSE(s.restore_tabs);
  EXPECT_TRUE(s.webrtc_ip_policy == WebRtcIpPolicy::kDisableNonProxiedUdp);
  EXPECT_TRUE(s.permission_grants.empty());
  EXPECT_TRUE(s.site_exceptions.empty());
}

TEST(Settings, JsonRoundTrip) {
  Settings s;
  s.mode = SecurityMode::kStrictProtection;
  s.home_page = "https://start.example/";
  s.site_exceptions["example.com"].allow_javascript = true;
  s.site_exceptions["=app.example.org"].allow_popups = true;
  s.javascript_blocked_sites.insert("blocked.test");
  s.user_rules = {"||tracker.test^", "@@||ok.test^"};
  s.filter_lists_enabled["easyprivacy"] = false;
  s.permission_grants["https://meet.example"] = 4 | 4096;
  s.external_protocols_allowed.insert("mailto");
  s.update_manifest_sequence = 42;
  s.restore_tabs = true;
  s.session_tabs = {"https://a.example/", "aegis://security/"};
  std::vector<std::string> warnings;
  Settings back = SettingsFromJson(SettingsToJson(s), &warnings);
  EXPECT_TRUE(back == s);
  EXPECT_TRUE(warnings.empty());
}

TEST(Settings, InvalidValuesFallBackToSecureDefaults) {
  auto v = json::Parse(R"JSON({
    "schema_version": 1,
    "mode": "turbo-insecure",
    "home_page": "javascript:alert(1)",
    "https_first": "yes",
    "block_third_party_cookies": 0,
    "site_exceptions": {"bad host!": {"allow_javascript": true}, "ok.test": {"allow_javascript": true}},
    "permission_grants": {"http://insecure.test": 4, "https://ok.test": 4, "https://x.test/path": 4},
    "session_tabs": ["file:///etc/passwd", "https://fine.test/"],
    "user_rules": ["||a.test^", "multi\nline"],
    "update_manifest_sequence": -5
  })JSON");
  ASSERT_TRUE(v.has_value());
  std::vector<std::string> warnings;
  Settings s = SettingsFromJson(*v, &warnings);
  EXPECT_TRUE(s.mode == SecurityMode::kMaximumIsolation);
  EXPECT_EQ(s.home_page, std::string("aegis://newtab/"));
  EXPECT_TRUE(s.https_first);
  EXPECT_TRUE(s.block_third_party_cookies);
  EXPECT_EQ(s.site_exceptions.size(), 1u);
  EXPECT_TRUE(s.site_exceptions.count("ok.test") == 1);
  EXPECT_EQ(s.permission_grants.size(), 1u);
  EXPECT_EQ(s.session_tabs.size(), 1u);
  EXPECT_EQ(s.user_rules.size(), 1u);
  EXPECT_EQ(s.update_manifest_sequence, 0u);
  EXPECT_FALSE(warnings.empty());
}

TEST(Settings, ProtectionReductionDetection) {
  EXPECT_TRUE(IsProtectionReduction(SecurityMode::kMaximumIsolation, SecurityMode::kCompatibility));
  EXPECT_TRUE(IsProtectionReduction(SecurityMode::kStrictProtection, SecurityMode::kCompatibility));
  EXPECT_FALSE(IsProtectionReduction(SecurityMode::kCompatibility, SecurityMode::kMaximumIsolation));
  EXPECT_FALSE(IsProtectionReduction(SecurityMode::kStrictProtection, SecurityMode::kStrictProtection));
  for (SecurityMode m : {SecurityMode::kMaximumIsolation, SecurityMode::kStrictProtection,
                         SecurityMode::kCompatibility}) {
    EXPECT_TRUE(SecurityModeFromId(SecurityModeId(m)) == m);
  }
}

TEST(Settings, NormalizeSiteKey) {
  EXPECT_EQ(NormalizeSiteKey("https://WWW.Example.com/path", false), std::string("www.example.com"));
  EXPECT_EQ(NormalizeSiteKey("example.com.", false), std::string("example.com"));
  EXPECT_EQ(NormalizeSiteKey("b\xc3\xbc" "cher.example", true), std::string("=xn--bcher-kva.example"));
  EXPECT_EQ(NormalizeSiteKey("<script>", false), std::string(""));
}

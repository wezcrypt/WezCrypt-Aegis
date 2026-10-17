#include "security/engine_switches.h"
#include "test_framework.h"

using namespace aegis;

TEST(EngineSwitches, DetectsSandboxAndTlsWeakeningSwitches) {
  auto found = FindForbiddenSwitches({"WezCryptAegis.exe", "--no-sandbox", "--IGNORE-CERTIFICATE-ERRORS",
                                      "/disable-web-security", "-single-process",
                                      "--remote-debugging-port=9222", "--profile=Work",
                                      "https://example.com/"});
  EXPECT_EQ(found.size(), 5u);
  EXPECT_EQ(found[0], std::string("no-sandbox"));
  EXPECT_EQ(found[1], std::string("ignore-certificate-errors"));
}

TEST(EngineSwitches, ArgumentsAfterDoubleDashArePositional) {
  EXPECT_TRUE(FindForbiddenSwitches({"app", "--", "--no-sandbox"}).empty());
  EXPECT_TRUE(FindForbiddenSwitches({"app", "no-sandbox", "https://x.example/--no-sandbox"}).empty());
}

TEST(EngineSwitches, HardeningNeverWeakens) {
  for (SecurityMode m : {SecurityMode::kMaximumIsolation, SecurityMode::kStrictProtection,
                         SecurityMode::kCompatibility}) {
    for (const auto& [name, value] : HardeningSwitches(m)) {
      if (name == "js-flags") continue;  // added by WezCrypt Aegis itself, value checked below
      EXPECT_FALSE(IsForbiddenSwitch(name));
    }
  }
  bool wasm_off = false;
  for (const auto& [name, value] : HardeningSwitches(SecurityMode::kMaximumIsolation)) {
    if (name == "js-flags" && value == "--noexpose_wasm") wasm_off = true;
  }
  EXPECT_TRUE(wasm_off);
}

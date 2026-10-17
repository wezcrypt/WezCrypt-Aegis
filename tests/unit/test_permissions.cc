#include "permissions/permission_policy.h"
#include "test_framework.h"

using namespace aegis;

TEST(Permissions, DeniedByDefaultInMaximumIsolation) {
  std::map<std::string, std::uint32_t> grants;
  grants["https://meet.example"] = perm::kCameraStream;
  auto d = EvaluatePermission(SecurityMode::kMaximumIsolation, "https://meet.example",
                              perm::kCameraStream, grants, false);
  EXPECT_TRUE(d.action == PermissionAction::kDeny);
}

TEST(Permissions, PromptRequiredWithoutGrant) {
  std::map<std::string, std::uint32_t> grants;
  for (SecurityMode m : {SecurityMode::kStrictProtection, SecurityMode::kCompatibility}) {
    auto d = EvaluatePermission(m, "https://maps.example", perm::kGeolocation, grants, false);
    EXPECT_TRUE(d.action == PermissionAction::kAsk);
    EXPECT_EQ(d.ask_mask, perm::kGeolocation);
  }
}

TEST(Permissions, GrantsAreScopedToExactOriginAndNotUsedInPrivate) {
  std::map<std::string, std::uint32_t> grants;
  grants["https://meet.example"] = perm::kCameraStream | perm::kMicStream;
  auto ok = EvaluatePermission(SecurityMode::kStrictProtection, "https://meet.example",
                               perm::kCameraStream | perm::kMicStream, grants, false);
  EXPECT_TRUE(ok.action == PermissionAction::kAllow);
  auto other = EvaluatePermission(SecurityMode::kStrictProtection, "https://evil.meet.example",
                                  perm::kCameraStream, grants, false);
  EXPECT_TRUE(other.action == PermissionAction::kAsk);
  auto partial = EvaluatePermission(SecurityMode::kStrictProtection, "https://meet.example",
                                    perm::kCameraStream | perm::kGeolocation, grants, false);
  EXPECT_TRUE(partial.action == PermissionAction::kAsk);
  auto priv = EvaluatePermission(SecurityMode::kStrictProtection, "https://meet.example",
                                 perm::kCameraStream, grants, true);
  EXPECT_TRUE(priv.action == PermissionAction::kAsk);
}

TEST(Permissions, DangerousPermissionsNeverGranted) {
  std::map<std::string, std::uint32_t> grants;
  grants["https://x.example"] = 0xFFFFFFFFu;
  for (std::uint32_t p : {perm::kMidiSysex, perm::kWindowManagement, perm::kLocalFonts,
                          perm::kRegisterProtocolHandler, perm::kFileSystemAccess,
                          perm::kLocalNetworkAccess, perm::kIdleDetection, perm::kKeyboardLock}) {
    auto d = EvaluatePermission(SecurityMode::kCompatibility, "https://x.example", p, grants, false);
    EXPECT_TRUE(d.action == PermissionAction::kDeny);
  }
}

TEST(Permissions, InsecureOriginsDenied) {
  std::map<std::string, std::uint32_t> grants;
  auto d = EvaluatePermission(SecurityMode::kCompatibility, "http://maps.example",
                              perm::kGeolocation, grants, false);
  EXPECT_TRUE(d.action == PermissionAction::kDeny);
  EXPECT_TRUE(EvaluatePermission(SecurityMode::kCompatibility, "garbage", perm::kGeolocation, grants,
                                 false).action == PermissionAction::kDeny);
  EXPECT_EQ(PermissionNames(perm::kCameraStream | perm::kMicStream).size(), 2u);
}

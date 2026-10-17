// WezCrypt Aegis - web permission policy (deny by default).
//
// Bit values mirror cef_permission_request_types_t (CEF 152+) so the CEF
// layer can pass masks through unchanged; a static_assert in the browser
// layer verifies the correspondence at compile time.
#pragma once

#include <cstdint>
#include <map>
#include <string>
#include <string_view>
#include <vector>

#include "security/security_mode.h"

namespace aegis {

namespace perm {
inline constexpr std::uint32_t kArSession = 1u << 0;
inline constexpr std::uint32_t kCameraPanTiltZoom = 1u << 1;
inline constexpr std::uint32_t kCameraStream = 1u << 2;
inline constexpr std::uint32_t kCapturedSurfaceControl = 1u << 3;
inline constexpr std::uint32_t kClipboard = 1u << 4;
inline constexpr std::uint32_t kTopLevelStorageAccess = 1u << 5;
inline constexpr std::uint32_t kDiskQuota = 1u << 6;
inline constexpr std::uint32_t kLocalFonts = 1u << 7;
inline constexpr std::uint32_t kGeolocation = 1u << 8;
inline constexpr std::uint32_t kHandTracking = 1u << 9;
inline constexpr std::uint32_t kIdentityProvider = 1u << 10;
inline constexpr std::uint32_t kIdleDetection = 1u << 11;
inline constexpr std::uint32_t kMicStream = 1u << 12;
inline constexpr std::uint32_t kMidiSysex = 1u << 13;
inline constexpr std::uint32_t kMultipleDownloads = 1u << 14;
inline constexpr std::uint32_t kNotifications = 1u << 15;
inline constexpr std::uint32_t kKeyboardLock = 1u << 16;
inline constexpr std::uint32_t kPointerLock = 1u << 17;
inline constexpr std::uint32_t kProtectedMediaIdentifier = 1u << 18;
inline constexpr std::uint32_t kRegisterProtocolHandler = 1u << 19;
inline constexpr std::uint32_t kStorageAccess = 1u << 20;
inline constexpr std::uint32_t kVrSession = 1u << 21;
inline constexpr std::uint32_t kWebAppInstallation = 1u << 22;
inline constexpr std::uint32_t kWindowManagement = 1u << 23;
inline constexpr std::uint32_t kFileSystemAccess = 1u << 24;
inline constexpr std::uint32_t kLocalNetworkAccess = 1u << 25;
inline constexpr std::uint32_t kLocalNetwork = 1u << 26;
inline constexpr std::uint32_t kLoopbackNetwork = 1u << 27;
inline constexpr std::uint32_t kSensors = 1u << 28;

// Permissions a user may grant after an explicit prompt.
inline constexpr std::uint32_t kPromptable =
    kCameraStream | kMicStream | kGeolocation | kNotifications | kClipboard |
    kPointerLock | kDiskQuota | kStorageAccess | kTopLevelStorageAccess |
    kMultipleDownloads;

// Permissions that are never granted to web content.
inline constexpr std::uint32_t kAlwaysDenied =
    ~kPromptable;
}  // namespace perm

std::vector<std::string> PermissionNames(std::uint32_t mask);

enum class PermissionAction { kDeny, kAllow, kAsk };

struct PermissionDecision {
  PermissionAction action = PermissionAction::kDeny;
  std::uint32_t allowed_mask = 0;   // for kAllow
  std::uint32_t ask_mask = 0;       // for kAsk: what the prompt covers
  std::string reason;
};

// |origin| must be the requesting origin ("https://example.com").
PermissionDecision EvaluatePermission(SecurityMode mode, std::string_view origin,
                                      std::uint32_t requested,
                                      const std::map<std::string, std::uint32_t>& grants,
                                      bool is_private_window);

}  // namespace aegis

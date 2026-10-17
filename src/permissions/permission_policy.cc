#include "permissions/permission_policy.h"

#include "common/url.h"

namespace aegis {

std::vector<std::string> PermissionNames(std::uint32_t mask) {
  static constexpr std::pair<std::uint32_t, const char*> kNames[] = {
      {perm::kArSession, "AR session"},
      {perm::kCameraPanTiltZoom, "camera pan/tilt/zoom"},
      {perm::kCameraStream, "camera"},
      {perm::kCapturedSurfaceControl, "captured surface control"},
      {perm::kClipboard, "clipboard"},
      {perm::kTopLevelStorageAccess, "top-level storage access"},
      {perm::kDiskQuota, "persistent storage"},
      {perm::kLocalFonts, "local fonts"},
      {perm::kGeolocation, "location"},
      {perm::kHandTracking, "hand tracking"},
      {perm::kIdentityProvider, "identity provider"},
      {perm::kIdleDetection, "idle detection"},
      {perm::kMicStream, "microphone"},
      {perm::kMidiSysex, "MIDI system exclusive"},
      {perm::kMultipleDownloads, "multiple downloads"},
      {perm::kNotifications, "notifications"},
      {perm::kKeyboardLock, "keyboard lock"},
      {perm::kPointerLock, "pointer lock"},
      {perm::kProtectedMediaIdentifier, "protected media identifier"},
      {perm::kRegisterProtocolHandler, "protocol handler registration"},
      {perm::kStorageAccess, "storage access"},
      {perm::kVrSession, "VR session"},
      {perm::kWebAppInstallation, "web app installation"},
      {perm::kWindowManagement, "window management"},
      {perm::kFileSystemAccess, "file system access"},
      {perm::kLocalNetworkAccess, "local network access"},
      {perm::kLocalNetwork, "local network"},
      {perm::kLoopbackNetwork, "loopback network"},
      {perm::kSensors, "motion sensors"},
  };
  std::vector<std::string> out;
  for (const auto& [bit, name] : kNames) {
    if (mask & bit) out.emplace_back(name);
  }
  if (out.empty() && mask) out.emplace_back("unknown permission");
  return out;
}

PermissionDecision EvaluatePermission(SecurityMode mode, std::string_view origin,
                                      std::uint32_t requested,
                                      const std::map<std::string, std::uint32_t>& grants,
                                      bool is_private_window) {
  PermissionDecision d;
  if (requested == 0) {
    d.reason = "empty request";
    return d;
  }
  auto u = ParseUrl(origin);
  if (!u || u->scheme != "https" || u->host.empty()) {
    d.reason = "permissions are only considered for HTTPS origins";
    return d;
  }
  if (requested & perm::kAlwaysDenied) {
    d.reason = "request includes a permission WezCrypt Aegis never grants";
    return d;
  }
  if (mode == SecurityMode::kMaximumIsolation) {
    d.reason = "all permission requests are denied in Maximum Isolation mode";
    return d;
  }
  const std::string key = u->Origin();
  auto it = grants.find(key);
  std::uint32_t granted = (it != grants.end() && !is_private_window) ? it->second : 0;
  if ((requested & granted) == requested) {
    d.action = PermissionAction::kAllow;
    d.allowed_mask = requested;
    d.reason = "previously granted by user";
    return d;
  }
  d.action = PermissionAction::kAsk;
  d.ask_mask = requested;
  d.reason = "requires explicit user approval";
  return d;
}

}  // namespace aegis

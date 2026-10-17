#include "networking/network_policy.h"

#include "common/strings.h"

namespace aegis {

std::optional<std::string> HttpsFirstUpgrade(const Url& url,
                                             const std::set<std::string>& http_allowed_hosts) {
  if (url.scheme != "http") return std::nullopt;
  if (url.host.empty() || url.host_type != HostType::kDomain) return std::nullopt;
  if (IsLocalOrPrivateHost(url)) return std::nullopt;
  // Single-label names (intranet) cannot have publicly trusted certificates.
  if (url.host.find('.') == std::string::npos) return std::nullopt;
  if (url.port >= 0 && url.port != 80) return std::nullopt;
  std::string host = NormalizeHostForMatching(url.host);
  if (http_allowed_hosts.count(host)) return std::nullopt;
  Url up = url;
  up.scheme = "https";
  up.port = -1;
  return up.Spec();
}

bool IsHttpsUpgradeFallbackError(int e) {
  // Chromium net error codes (net/base/net_error_list.h).
  switch (e) {
    case -2:    // ERR_FAILED
    case -7:    // ERR_TIMED_OUT
    case -15:   // ERR_SOCKET_NOT_CONNECTED
    case -21:   // ERR_NETWORK_CHANGED
    case -100:  // ERR_CONNECTION_CLOSED
    case -101:  // ERR_CONNECTION_RESET
    case -102:  // ERR_CONNECTION_REFUSED
    case -104:  // ERR_CONNECTION_FAILED
    case -105:  // ERR_NAME_NOT_RESOLVED
    case -106:  // ERR_INTERNET_DISCONNECTED
    case -107:  // ERR_SSL_PROTOCOL_ERROR
    case -109:  // ERR_ADDRESS_UNREACHABLE
    case -118:  // ERR_CONNECTION_TIMED_OUT
    case -324:  // ERR_EMPTY_RESPONSE
      return true;
    default:
      return false;
  }
}

bool IsDangerousExternalScheme(std::string_view scheme_in) {
  std::string scheme = ToLowerAscii(scheme_in);
  static constexpr std::string_view kDangerous[] = {
      "ms-msdt", "search-ms", "search", "ms-officecmd", "ms-word", "ms-excel",
      "ms-powerpoint", "ms-access", "ms-visio", "ms-project", "ms-publisher",
      "ms-infopath", "ms-spd", "ms-xcel", "ms-cxh", "ms-cxh-full",
      "ms-appinstaller", "ms-settings", "ms-help", "its", "mk", "hcp",
      "ms-its", "file", "javascript", "vbscript", "jar", "res", "shell",
      "ldap", "ldaps", "smb", "nfs", "telnet", "ssh", "rlogin", "ftp",
      "vnc", "rdp", "ms-rd", "steam", "microsoft-edge", "ms-gamingoverlay",
      "ms-screenclip", "ms-windows-store", "windowsdefender", "ms-msdt-launch",
      "ms-word-nft", "callto", "zoommtg", "teams", "msteams"};
  for (auto d : kDangerous) {
    if (scheme == d) return true;
  }
  // Any "ms-" prefixed handler is treated as dangerous by default.
  return StartsWith(scheme, "ms-");
}

ExternalProtocolVerdict EvaluateExternalProtocol(std::string_view url_text, SecurityMode mode,
                                                 bool user_gesture,
                                                 const std::set<std::string>& allowed_schemes) {
  ExternalProtocolVerdict v;
  std::size_t colon = url_text.find(':');
  if (colon == std::string_view::npos || colon == 0 || colon > 32) {
    v.reason = "malformed external URL";
    return v;
  }
  std::string scheme = ToLowerAscii(url_text.substr(0, colon));
  for (char c : scheme) {
    if (!(IsAsciiAlnum(c) || c == '+' || c == '-' || c == '.')) {
      v.reason = "malformed scheme";
      return v;
    }
  }
  if (IsDangerousExternalScheme(scheme)) {
    v.reason = "scheme '" + scheme + "' is on the dangerous protocol list";
    return v;
  }
  if (mode == SecurityMode::kMaximumIsolation) {
    v.reason = "external applications cannot be launched in Maximum Isolation";
    return v;
  }
  if (!user_gesture) {
    v.reason = "external application launch without a user gesture";
    return v;
  }
  if (allowed_schemes.count(scheme)) {
    v.decision = ExternalProtocolDecision::kAllow;
    v.reason = "scheme previously allowed by user";
    return v;
  }
  v.decision = ExternalProtocolDecision::kAskUser;
  v.reason = "requires confirmation";
  return v;
}

bool IsPrivateNetworkRequestFromPublicPage(const Url& request, const Url* top_level) {
  if (!top_level || !top_level->has_authority || top_level->host.empty()) return false;
  if (!(top_level->IsHttpLike())) return false;
  if (IsLocalOrPrivateHost(*top_level)) return false;
  return IsLocalOrPrivateHost(request);
}

}  // namespace aegis

// WezCrypt Aegis - network-level navigation policies.
#pragma once

#include <optional>
#include <set>
#include <string>
#include <string_view>

#include "common/url.h"
#include "security/security_mode.h"

namespace aegis {

// HTTPS-first: returns the https:// URL a top-level http:// navigation must
// be upgraded to, or nullopt when no upgrade applies (already secure,
// local/private host, IP literal, non-default port, or user-approved host).
std::optional<std::string> HttpsFirstUpgrade(const Url& url,
                                             const std::set<std::string>& http_allowed_hosts);

// Network errors after which an upgraded navigation may offer a plain HTTP
// fallback (connection failures, not certificate errors: a certificate
// failure on the HTTPS version never offers HTTP).
bool IsHttpsUpgradeFallbackError(int chromium_net_error);

enum class ExternalProtocolDecision {
  kBlock,     // never launched
  kAskUser,   // launch only after explicit confirmation
  kAllow,     // user previously allowed this scheme (still requires gesture)
};

struct ExternalProtocolVerdict {
  ExternalProtocolDecision decision = ExternalProtocolDecision::kBlock;
  std::string reason;
};

// Policy for URLs whose scheme Chromium cannot handle (OS protocol handlers).
ExternalProtocolVerdict EvaluateExternalProtocol(std::string_view url, SecurityMode mode,
                                                 bool user_gesture,
                                                 const std::set<std::string>& allowed_schemes);

// Schemes that have been abused for code execution or credential theft via
// OS protocol handlers and are never launched.
bool IsDangerousExternalScheme(std::string_view scheme);

// True when a public top-level page tries to reach a loopback / private
// network address (router CSRF, local service attacks).
bool IsPrivateNetworkRequestFromPublicPage(const Url& request, const Url* top_level);

}  // namespace aegis

#include "security/security_mode.h"

namespace aegis {

std::string_view SecurityModeId(SecurityMode m) {
  switch (m) {
    case SecurityMode::kMaximumIsolation: return "maximum-isolation";
    case SecurityMode::kStrictProtection: return "strict-protection";
    case SecurityMode::kCompatibility: return "compatibility";
  }
  return "maximum-isolation";
}

std::string_view SecurityModeDisplayName(SecurityMode m) {
  switch (m) {
    case SecurityMode::kMaximumIsolation: return "Maximum Isolation";
    case SecurityMode::kStrictProtection: return "Strict Protection";
    case SecurityMode::kCompatibility: return "Compatibility";
  }
  return "Maximum Isolation";
}

std::string_view SecurityModeShortLabel(SecurityMode m) {
  switch (m) {
    case SecurityMode::kMaximumIsolation: return "MAX ISOLATION";
    case SecurityMode::kStrictProtection: return "STRICT";
    case SecurityMode::kCompatibility: return "COMPATIBILITY";
  }
  return "MAX ISOLATION";
}

std::string_view SecurityModeDescription(SecurityMode m) {
  switch (m) {
    case SecurityMode::kMaximumIsolation:
      return "JavaScript is disabled by engine policy, all third-party requests and "
             "frames are blocked, WebAssembly is not exposed, popups are blocked and "
             "permission requests are denied. Per-site exceptions can be granted.";
    case SecurityMode::kStrictProtection:
      return "JavaScript runs according to site policy with the higher-tier V8 "
             "optimizers disabled, advertising and tracking filters are active, "
             "third-party frames are blocked and permissions require approval.";
    case SecurityMode::kCompatibility:
      return "Advertising and tracking filters stay active and the sandbox and site "
             "isolation remain enabled, but third-party frames and JavaScript "
             "optimizers are allowed for better site compatibility.";
  }
  return "";
}

std::optional<SecurityMode> SecurityModeFromId(std::string_view id) {
  if (id == "maximum-isolation") return SecurityMode::kMaximumIsolation;
  if (id == "strict-protection") return SecurityMode::kStrictProtection;
  if (id == "compatibility") return SecurityMode::kCompatibility;
  return std::nullopt;
}

}  // namespace aegis

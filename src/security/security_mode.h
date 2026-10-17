// WezCrypt Aegis - security modes.
#pragma once

#include <optional>
#include <string_view>

namespace aegis {

// Ordered from strongest to weakest. Numeric order is used to detect
// protection reductions (a higher value is weaker).
enum class SecurityMode : int {
  kMaximumIsolation = 0,  // Mode A
  kStrictProtection = 1,  // Mode B
  kCompatibility = 2,     // Mode C
};

inline constexpr SecurityMode kDefaultSecurityMode = SecurityMode::kMaximumIsolation;

std::string_view SecurityModeId(SecurityMode m);           // "maximum-isolation"
std::string_view SecurityModeDisplayName(SecurityMode m);  // "Maximum Isolation"
std::string_view SecurityModeShortLabel(SecurityMode m);   // "MAX ISOLATION"
std::string_view SecurityModeDescription(SecurityMode m);
std::optional<SecurityMode> SecurityModeFromId(std::string_view id);

// True when switching from |from| to |to| lowers protection. Such changes
// always require explicit user confirmation.
constexpr bool IsProtectionReduction(SecurityMode from, SecurityMode to) {
  return static_cast<int>(to) > static_cast<int>(from);
}

}  // namespace aegis

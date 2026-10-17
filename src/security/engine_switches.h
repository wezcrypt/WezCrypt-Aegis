// WezCrypt Aegis - Chromium command-line hardening.
//
// Chromium accepts many switches that silently disable security features.
// WezCrypt Aegis refuses to start (fails closed) if any of them is present
// on its command line, and never adds them itself.
#pragma once

#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "security/security_mode.h"

namespace aegis {

// Returns the security-weakening switches found in |args| (without the
// leading dashes). Matching is case-insensitive and accepts "--x", "-x",
// "--x=value" and "/x" forms.
std::vector<std::string> FindForbiddenSwitches(const std::vector<std::string>& args);

bool IsForbiddenSwitch(std::string_view name);

// Switches WezCrypt Aegis adds to the browser process command line for the
// given startup mode. Values are applied via CefCommandLine.
std::vector<std::pair<std::string, std::string>> HardeningSwitches(SecurityMode startup_mode);

}  // namespace aegis

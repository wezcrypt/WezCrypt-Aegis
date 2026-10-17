// WezCrypt Aegis - persistent user settings.
//
// Every field has a secure default. Values that fail validation on load are
// replaced by their secure default, never by a weaker value.
#pragma once

#include <cstdint>
#include <filesystem>
#include <map>
#include <set>
#include <string>
#include <vector>

#include "common/json.h"
#include "security/security_mode.h"

namespace aegis {

struct SiteException {
  bool allow_javascript = false;
  bool allow_third_party = false;
  bool disable_filtering = false;
  bool allow_popups = false;
  bool operator==(const SiteException&) const = default;
  bool empty() const {
    return !allow_javascript && !allow_third_party && !disable_filtering && !allow_popups;
  }
};

enum class WebRtcIpPolicy {
  kDisableNonProxiedUdp,  // default: no local IP exposure
  kDefaultPublicInterfaceOnly,
  kDefault,
};

std::string_view WebRtcIpPolicyId(WebRtcIpPolicy p);  // Chromium pref value

struct Settings {
  static constexpr int kSchemaVersion = 1;

  SecurityMode mode = kDefaultSecurityMode;
  std::string home_page = "aegis://newtab/";
  bool https_first = true;
  // Hosts for which the user explicitly accepted plain HTTP after an
  // HTTPS-upgrade failure.
  std::set<std::string> http_allowed_hosts;
  // Key: registrable domain ("example.com") or "=host" for an exact host.
  std::map<std::string, SiteException> site_exceptions;
  // Strict Protection only: sites where JavaScript is blocked.
  std::set<std::string> javascript_blocked_sites;
  std::vector<std::string> user_rules;
  std::map<std::string, bool> filter_lists_enabled;
  bool block_third_party_cookies = true;
  WebRtcIpPolicy webrtc_ip_policy = WebRtcIpPolicy::kDisableNonProxiedUdp;
  bool restore_tabs = false;
  bool save_history = true;
  bool clear_cookies_on_exit = false;
  bool clear_cache_on_exit = false;
  bool clear_history_on_exit = false;
  // Origin -> bitmask of CEF permission types the user granted.
  std::map<std::string, std::uint32_t> permission_grants;
  // Schemes the user allowed to launch external applications.
  std::set<std::string> external_protocols_allowed;
  // Highest update-manifest sequence accepted (rollback protection).
  std::uint64_t update_manifest_sequence = 0;
  std::vector<std::string> session_tabs;  // only used when restore_tabs

  bool operator==(const Settings&) const = default;
};

struct SettingsLimits {
  std::size_t max_sites = 10'000;
  std::size_t max_user_rules = 50'000;
  std::size_t max_string_bytes = 8192;
  std::size_t max_session_tabs = 200;
};

json::Value SettingsToJson(const Settings& s);

// Converts JSON to settings. Unknown fields are ignored; invalid values are
// replaced by secure defaults and reported through |warnings|.
Settings SettingsFromJson(const json::Value& v, std::vector<std::string>* warnings,
                          const SettingsLimits& limits = SettingsLimits());

// Normalizes a user-entered site exception key (host or URL) to the stored
// key form. Returns empty on invalid input.
std::string NormalizeSiteKey(std::string_view input, bool exact_host);

}  // namespace aegis

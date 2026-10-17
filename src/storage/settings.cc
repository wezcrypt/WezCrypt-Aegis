#include "storage/settings.h"

#include "common/idna.h"
#include "common/strings.h"
#include "common/url.h"
#include "common/utf8.h"

namespace aegis {

std::string_view WebRtcIpPolicyId(WebRtcIpPolicy p) {
  switch (p) {
    case WebRtcIpPolicy::kDisableNonProxiedUdp: return "disable_non_proxied_udp";
    case WebRtcIpPolicy::kDefaultPublicInterfaceOnly: return "default_public_interface_only";
    case WebRtcIpPolicy::kDefault: return "default";
  }
  return "disable_non_proxied_udp";
}

namespace {

bool IsValidHostKey(std::string_view h) {
  if (h.empty() || h.size() > 253) return false;
  for (char c : h) {
    if (!(IsAsciiAlnum(c) || c == '-' || c == '.' || c == '_' || c == ':')) return false;
  }
  return h.front() != '.' && h.back() != '.';
}

json::Value StringSetToJson(const std::set<std::string>& s) {
  json::Array a;
  for (const auto& v : s) a.emplace_back(v);
  return json::Value(std::move(a));
}

std::set<std::string> StringSetFromJson(const json::Value* v, std::size_t max_items,
                                        std::size_t max_bytes, bool hosts,
                                        std::vector<std::string>* warnings,
                                        std::string_view field) {
  std::set<std::string> out;
  if (!v) return out;
  if (!v->is_array()) {
    warnings->push_back(std::string(field) + ": expected array");
    return out;
  }
  for (const json::Value& item : v->as_array()) {
    if (out.size() >= max_items) {
      warnings->push_back(std::string(field) + ": too many entries, truncated");
      break;
    }
    if (!item.is_string() || item.as_string().size() > max_bytes) continue;
    if (hosts && !IsValidHostKey(item.as_string())) {
      warnings->push_back(std::string(field) + ": dropped invalid host");
      continue;
    }
    out.insert(item.as_string());
  }
  return out;
}

}  // namespace

json::Value SettingsToJson(const Settings& s) {
  json::Object o;
  o["schema_version"] = Settings::kSchemaVersion;
  o["mode"] = std::string(SecurityModeId(s.mode));
  o["home_page"] = s.home_page;
  o["https_first"] = s.https_first;
  o["http_allowed_hosts"] = StringSetToJson(s.http_allowed_hosts);
  json::Object ex;
  for (const auto& [site, e] : s.site_exceptions) {
    if (e.empty()) continue;
    json::Object eo;
    eo["allow_javascript"] = e.allow_javascript;
    eo["allow_third_party"] = e.allow_third_party;
    eo["disable_filtering"] = e.disable_filtering;
    eo["allow_popups"] = e.allow_popups;
    ex[site] = json::Value(std::move(eo));
  }
  o["site_exceptions"] = json::Value(std::move(ex));
  o["javascript_blocked_sites"] = StringSetToJson(s.javascript_blocked_sites);
  json::Array rules;
  for (const auto& r : s.user_rules) rules.emplace_back(r);
  o["user_rules"] = json::Value(std::move(rules));
  json::Object lists;
  for (const auto& [id, en] : s.filter_lists_enabled) lists[id] = en;
  o["filter_lists_enabled"] = json::Value(std::move(lists));
  o["block_third_party_cookies"] = s.block_third_party_cookies;
  o["webrtc_ip_policy"] = std::string(WebRtcIpPolicyId(s.webrtc_ip_policy));
  o["restore_tabs"] = s.restore_tabs;
  o["save_history"] = s.save_history;
  o["clear_cookies_on_exit"] = s.clear_cookies_on_exit;
  o["clear_cache_on_exit"] = s.clear_cache_on_exit;
  o["clear_history_on_exit"] = s.clear_history_on_exit;
  json::Object grants;
  for (const auto& [origin, mask] : s.permission_grants) {
    grants[origin] = static_cast<std::int64_t>(mask);
  }
  o["permission_grants"] = json::Value(std::move(grants));
  o["external_protocols_allowed"] = StringSetToJson(s.external_protocols_allowed);
  o["update_manifest_sequence"] = static_cast<std::int64_t>(s.update_manifest_sequence);
  json::Array tabs;
  for (const auto& t : s.session_tabs) tabs.emplace_back(t);
  o["session_tabs"] = json::Value(std::move(tabs));
  return json::Value(std::move(o));
}

Settings SettingsFromJson(const json::Value& v, std::vector<std::string>* warnings,
                          const SettingsLimits& limits) {
  std::vector<std::string> local;
  if (!warnings) warnings = &local;
  Settings s;  // secure defaults
  if (!v.is_object()) {
    warnings->push_back("settings root is not an object; using secure defaults");
    return s;
  }
  std::int64_t schema = v.GetInt("schema_version", -1);
  if (schema != Settings::kSchemaVersion) {
    warnings->push_back("unknown schema version; reading compatible fields only");
  }

  if (const json::Value* m = v.Find("mode")) {
    auto mode = m->is_string() ? SecurityModeFromId(m->as_string()) : std::nullopt;
    if (mode) {
      s.mode = *mode;
    } else {
      warnings->push_back("invalid mode; using Maximum Isolation");
    }
  }
  std::string home = v.GetString("home_page", s.home_page);
  auto home_url = ParseUrl(home);
  if (home_url && (home_url->scheme == "https" || home_url->scheme == "aegis" ||
                   home_url->scheme == "http") && home.size() <= limits.max_string_bytes) {
    s.home_page = home;
  } else {
    warnings->push_back("invalid home page; using default");
  }
  s.https_first = v.GetBool("https_first", true);
  s.http_allowed_hosts = StringSetFromJson(v.Find("http_allowed_hosts"), limits.max_sites,
                                           limits.max_string_bytes, true, warnings,
                                           "http_allowed_hosts");
  if (const json::Value* ex = v.Find("site_exceptions"); ex && ex->is_object()) {
    for (const auto& [key, val] : ex->as_object()) {
      if (s.site_exceptions.size() >= limits.max_sites) {
        warnings->push_back("site_exceptions truncated");
        break;
      }
      std::string_view host = key;
      if (!host.empty() && host[0] == '=') host.remove_prefix(1);
      if (!IsValidHostKey(host) || !val.is_object()) {
        warnings->push_back("dropped invalid site exception");
        continue;
      }
      SiteException e;
      e.allow_javascript = val.GetBool("allow_javascript", false);
      e.allow_third_party = val.GetBool("allow_third_party", false);
      e.disable_filtering = val.GetBool("disable_filtering", false);
      e.allow_popups = val.GetBool("allow_popups", false);
      if (!e.empty()) s.site_exceptions[key] = e;
    }
  }
  s.javascript_blocked_sites = StringSetFromJson(v.Find("javascript_blocked_sites"),
                                                 limits.max_sites, limits.max_string_bytes,
                                                 true, warnings, "javascript_blocked_sites");
  if (const json::Value* r = v.Find("user_rules"); r && r->is_array()) {
    for (const json::Value& item : r->as_array()) {
      if (s.user_rules.size() >= limits.max_user_rules) {
        warnings->push_back("user_rules truncated");
        break;
      }
      if (item.is_string() && item.as_string().size() <= 4096 &&
          item.as_string().find_first_of("\r\n") == std::string::npos) {
        s.user_rules.push_back(item.as_string());
      }
    }
  }
  if (const json::Value* l = v.Find("filter_lists_enabled"); l && l->is_object()) {
    for (const auto& [id, en] : l->as_object()) {
      if (id.size() <= 64 && en.is_bool()) s.filter_lists_enabled[id] = en.as_bool();
    }
  }
  s.block_third_party_cookies = v.GetBool("block_third_party_cookies", true);
  std::string webrtc = v.GetString("webrtc_ip_policy", "disable_non_proxied_udp");
  if (webrtc == "default") s.webrtc_ip_policy = WebRtcIpPolicy::kDefault;
  else if (webrtc == "default_public_interface_only")
    s.webrtc_ip_policy = WebRtcIpPolicy::kDefaultPublicInterfaceOnly;
  else s.webrtc_ip_policy = WebRtcIpPolicy::kDisableNonProxiedUdp;
  s.restore_tabs = v.GetBool("restore_tabs", false);
  s.save_history = v.GetBool("save_history", true);
  s.clear_cookies_on_exit = v.GetBool("clear_cookies_on_exit", false);
  s.clear_cache_on_exit = v.GetBool("clear_cache_on_exit", false);
  s.clear_history_on_exit = v.GetBool("clear_history_on_exit", false);
  if (const json::Value* g = v.Find("permission_grants"); g && g->is_object()) {
    for (const auto& [origin, mask] : g->as_object()) {
      auto u = ParseUrl(origin);
      std::int64_t m = mask.as_int(-1);
      if (!u || u->Origin() != origin || u->scheme != "https" || m < 0 || m > 0xFFFFFFFFLL) {
        warnings->push_back("dropped invalid permission grant");
        continue;
      }
      if (s.permission_grants.size() >= limits.max_sites) break;
      s.permission_grants[origin] = static_cast<std::uint32_t>(m);
    }
  }
  s.external_protocols_allowed = StringSetFromJson(
      v.Find("external_protocols_allowed"), 64, 32, false, warnings,
      "external_protocols_allowed");
  std::int64_t seq = v.GetInt("update_manifest_sequence", 0);
  s.update_manifest_sequence = seq > 0 ? static_cast<std::uint64_t>(seq) : 0;
  if (const json::Value* t = v.Find("session_tabs"); t && t->is_array()) {
    for (const json::Value& item : t->as_array()) {
      if (s.session_tabs.size() >= limits.max_session_tabs) break;
      if (!item.is_string() || item.as_string().size() > limits.max_string_bytes) continue;
      auto u = ParseUrl(item.as_string());
      if (u && (u->IsHttpLike() || u->scheme == "aegis")) s.session_tabs.push_back(item.as_string());
    }
  }
  return s;
}

std::string NormalizeSiteKey(std::string_view input, bool exact_host) {
  std::string_view in = TrimAsciiWhitespace(input);
  std::string host;
  if (in.find("://") != std::string_view::npos) {
    auto u = ParseUrl(in);
    if (!u || u->host.empty()) return {};
    host = u->host;
  } else {
    auto ascii = idna::ToAscii(in);
    if (!ascii) return {};
    host = *ascii;
  }
  host = NormalizeHostForMatching(host);
  if (!IsValidHostKey(host)) return {};
  return exact_host ? "=" + host : host;
}

}  // namespace aegis

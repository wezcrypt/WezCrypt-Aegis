// WezCrypt Aegis - request, navigation, popup and JavaScript policy.
//
// All decisions are pure functions of an immutable PolicySnapshot and the
// request. The CEF integration layer translates engine callbacks into
// RequestContext values and enforces the returned decision; this module is
// fully testable without the browser engine.
#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <string_view>

#include "common/url.h"
#include "filtering/filter_engine.h"
#include "filtering/public_suffix_list.h"
#include "security/security_events.h"
#include "security/security_mode.h"
#include "storage/settings.h"

namespace aegis {

struct PolicySnapshot {
  SecurityMode mode = kDefaultSecurityMode;
  bool https_first = true;
  bool block_third_party_cookies = true;
  std::set<std::string> http_allowed_hosts;
  std::map<std::string, SiteException> site_exceptions;
  std::set<std::string> javascript_blocked_sites;
  std::set<std::string> external_protocols_allowed;
  std::shared_ptr<const FilterEngine> filters;  // may be null (no lists loaded)
  std::shared_ptr<const PublicSuffixList> psl;  // required

  static std::shared_ptr<const PolicySnapshot> Create(
      const Settings& settings, std::shared_ptr<const FilterEngine> filters,
      std::shared_ptr<const PublicSuffixList> psl);

  // Site exception effective for a top-level host (exact-host entries take
  // precedence over registrable-domain entries).
  SiteException ExceptionFor(std::string_view top_level_host) const;
  std::string SiteFor(std::string_view host) const;
};

enum class RequestAction : std::uint8_t {
  kAllow,
  kBlock,                // cancel before any network access
  kUpgradeToHttps,       // rewrite to |upgraded_url| before network access
  kBlockWithInterstitial // top-level navigation: show the blocked page
};

struct RequestContext {
  std::string_view url;
  ResourceType type = kResourceOther;
  bool is_main_frame = false;            // true for top-level documents
  std::string_view top_level_url;        // empty when unknown
  bool from_internal_page = false;       // initiated by an aegis:// page
};

struct RequestDecision {
  RequestAction action = RequestAction::kAllow;
  std::optional<EventCategory> category;  // set for blocks and upgrades
  std::string reason;
  std::string rule;
  std::string list;
  std::string upgraded_url;
  std::string site;  // top-level site, for accounting
  bool third_party = false;
};

RequestDecision EvaluateRequest(const PolicySnapshot& policy, const RequestContext& req);

// JavaScript permission for documents of |site_url|. Enforced through the
// engine's content-settings system (scripts never start executing).
bool IsJavaScriptAllowed(const PolicySnapshot& policy, std::string_view site_url);

// Whether the V8 optimizing tiers (JIT) are permitted for |site_url|.
bool IsJavaScriptOptimizerAllowed(const PolicySnapshot& policy, std::string_view site_url);

enum class PopupAction : std::uint8_t { kOpenAsTab, kBlock };

struct PopupContext {
  std::string_view target_url;
  std::string_view opener_url;
  bool user_gesture = false;
  bool is_new_foreground_tab_disposition = false;  // target=_blank / middle click
};

struct PopupDecision {
  PopupAction action = PopupAction::kBlock;
  std::string reason;
};

PopupDecision EvaluatePopup(const PolicySnapshot& policy, const PopupContext& ctx);

enum class NavigationAction : std::uint8_t { kAllow, kBlock };

struct NavigationContext {
  std::string_view target_url;
  std::string_view current_url;   // URL of the frame being navigated
  bool is_main_frame = true;
  bool user_gesture = false;
  bool typed_by_user = false;     // entered in the address bar / bookmark
  bool is_redirect = false;
};

struct NavigationDecision {
  NavigationAction action = NavigationAction::kAllow;
  std::optional<EventCategory> category;
  std::string reason;
};

// Scheme-level navigation policy (file://, internal pages, data: URLs).
NavigationDecision EvaluateNavigation(const PolicySnapshot& policy, const NavigationContext& ctx);

// Builds the stored key for a site exception from a URL/host. Returns an
// empty string when the host is a public suffix (an exception for
// "github.io" would apply to every github.io site and is refused).
std::string MakeSiteExceptionKey(const PublicSuffixList& psl, std::string_view url_or_host,
                                 bool exact_host);

}  // namespace aegis

#include "security/security_policy.h"

#include "common/strings.h"
#include "networking/network_policy.h"

namespace aegis {
namespace {

EventCategory CategoryForList(ListCategory c) {
  switch (c) {
    case ListCategory::kAdvertising: return EventCategory::kAdvertising;
    case ListCategory::kTracking: return EventCategory::kTracker;
    case ListCategory::kMalware:
    case ListCategory::kUser:
    case ListCategory::kBuiltin: return EventCategory::kUserRule;
  }
  return EventCategory::kUserRule;
}

RequestDecision Block(EventCategory c, std::string reason) {
  RequestDecision d;
  d.action = RequestAction::kBlock;
  d.category = c;
  d.reason = std::move(reason);
  return d;
}

bool IsInternalScheme(std::string_view s) { return s == "aegis"; }

}  // namespace

std::shared_ptr<const PolicySnapshot> PolicySnapshot::Create(
    const Settings& settings, std::shared_ptr<const FilterEngine> filters,
    std::shared_ptr<const PublicSuffixList> psl) {
  auto p = std::make_shared<PolicySnapshot>();
  p->mode = settings.mode;
  p->https_first = settings.https_first;
  p->block_third_party_cookies = settings.block_third_party_cookies;
  p->http_allowed_hosts = settings.http_allowed_hosts;
  p->site_exceptions = settings.site_exceptions;
  p->javascript_blocked_sites = settings.javascript_blocked_sites;
  p->external_protocols_allowed = settings.external_protocols_allowed;
  p->filters = std::move(filters);
  p->psl = std::move(psl);
  return p;
}

std::string PolicySnapshot::SiteFor(std::string_view host) const {
  return psl ? psl->SiteForHost(host) : NormalizeHostForMatching(host);
}

SiteException PolicySnapshot::ExceptionFor(std::string_view top_level_host) const {
  if (top_level_host.empty() || site_exceptions.empty()) return {};
  std::string host = NormalizeHostForMatching(top_level_host);
  auto exact = site_exceptions.find("=" + host);
  if (exact != site_exceptions.end()) return exact->second;
  auto site = site_exceptions.find(SiteFor(host));
  if (site != site_exceptions.end()) return site->second;
  return {};
}

std::string MakeSiteExceptionKey(const PublicSuffixList& psl, std::string_view url_or_host,
                                 bool exact_host) {
  std::string key = NormalizeSiteKey(url_or_host, exact_host);
  if (key.empty()) return {};
  if (exact_host) return key;
  std::string reg = psl.RegistrableDomain(key);
  if (reg.empty()) {
    // IP literals and single-label hosts use the full host as the site.
    if (ParseIPv4(key) || key.find('.') == std::string::npos) return key;
    return {};  // public suffix: refused
  }
  return reg;
}

RequestDecision EvaluateRequest(const PolicySnapshot& policy, const RequestContext& req) {
  auto url = ParseUrl(req.url);
  std::optional<Url> top;
  if (!req.top_level_url.empty()) top = ParseUrl(req.top_level_url);
  const std::string top_host = top ? NormalizeHostForMatching(top->host) : std::string();

  RequestDecision d;
  d.site = top ? policy.SiteFor(top_host) : std::string();

  if (!url) {
    RequestDecision b = Block(EventCategory::kUnsafeScheme, "malformed URL");
    b.site = d.site;
    return b;
  }
  const std::string& scheme = url->scheme;

  // 1. Scheme policy.
  if (scheme == "data" || scheme == "about") return d;
  if (scheme == "blob") {
    // blob: URLs are same-origin object URLs created by the page itself.
    return d;
  }
  if (IsInternalScheme(scheme)) {
    // Internal pages are display-isolated; only top-level loads and loads
    // from other internal pages are permitted.
    if (req.is_main_frame || req.from_internal_page ||
        (top && IsInternalScheme(top->scheme))) {
      return d;
    }
    auto b = Block(EventCategory::kUnsafeScheme, "web content may not load internal pages");
    b.site = d.site;
    return b;
  }
  if (scheme == "file") {
    if (req.is_main_frame) return d;  // navigation policy decides top-level file loads
    if (top && top->scheme == "file") return d;
    auto b = Block(EventCategory::kUnsafeScheme, "web content may not read local files");
    b.site = d.site;
    return b;
  }
  if (!(url->IsHttpLike() || url->IsWebSocket())) {
    auto b = Block(EventCategory::kUnsafeScheme, "scheme '" + scheme + "' is not permitted");
    b.site = d.site;
    return b;
  }

  const std::string req_host = NormalizeHostForMatching(url->host);

  // 2. Top-level documents.
  if (req.is_main_frame) {
    d.site = policy.SiteFor(req_host);
    if (policy.https_first) {
      if (auto up = HttpsFirstUpgrade(*url, policy.http_allowed_hosts)) {
        d.action = RequestAction::kUpgradeToHttps;
        d.category = EventCategory::kHttpsUpgrade;
        d.upgraded_url = *up;
        d.reason = "HTTPS-first: navigation upgraded to HTTPS";
        return d;
      }
    }
    SiteException ex = policy.ExceptionFor(req_host);
    if (policy.filters && !ex.disable_filtering) {
      RequestInfo info;
      info.url = req.url;
      info.request_host = req_host;
      info.first_party_host = req_host;
      info.first_party_url = req.url;
      info.type = kResourceDocument;
      info.third_party = false;
      FilterMatch m = policy.filters->Match(info);
      if (m.decision == FilterDecision::kBlock && m.rule) {
        d.action = RequestAction::kBlockWithInterstitial;
        d.category = EventCategory::kNavigation;
        d.reason = "page address is on the " + m.list_id + " filter list";
        d.rule = m.rule->text;
        d.list = m.list_id;
      }
    }
    return d;
  }

  // 3. Service workers: their own fetches bypass pre-network filtering.
  if (req.is_service_worker_script) {
    auto b = Block(EventCategory::kScript,
                   "service workers are disabled because their network requests cannot be "
                   "filtered before they are sent");
    b.site = d.site;
    return b;
  }

  // 4. Subresources and subframes.
  const bool third_party =
      !top || top_host.empty() || (policy.psl ? policy.psl->IsThirdParty(req_host, top_host)
                                              : req_host != top_host);
  d.third_party = third_party;
  const SiteException ex = policy.ExceptionFor(top_host);

  if (top && IsPrivateNetworkRequestFromPublicPage(*url, &*top) && !ex.allow_third_party) {
    auto b = Block(EventCategory::kPrivateNetwork,
                   "public page attempted to reach a local or private network address");
    b.site = d.site;
    b.third_party = third_party;
    return b;
  }

  if (policy.filters && !ex.disable_filtering) {
    RequestInfo info;
    info.url = req.url;
    info.request_host = req_host;
    info.first_party_host = top_host;
    info.first_party_url = req.top_level_url;
    info.type = req.type;
    info.third_party = third_party;
    FilterMatch m = policy.filters->Match(info);
    if (m.decision == FilterDecision::kBlock && m.rule) {
      RequestDecision b = Block(CategoryForList(m.category),
                                "matched " + m.list_id + " rule");
      b.rule = m.rule->text;
      b.list = m.list_id;
      b.site = d.site;
      b.third_party = third_party;
      return b;
    }
  }

  switch (policy.mode) {
    case SecurityMode::kMaximumIsolation:
      if (req.type == kResourceScript && !ex.allow_javascript) {
        auto b = Block(EventCategory::kScript,
                       "scripts are blocked in Maximum Isolation mode");
        b.site = d.site;
        b.third_party = third_party;
        return b;
      }
      if (third_party && !ex.allow_third_party) {
        auto b = Block(req.type == kResourceSubdocument ? EventCategory::kThirdPartyFrame
                                                        : EventCategory::kThirdPartyRequest,
                       "third-party content is blocked in Maximum Isolation mode");
        b.site = d.site;
        b.third_party = true;
        return b;
      }
      break;
    case SecurityMode::kStrictProtection:
      if (third_party && req.type == kResourceSubdocument && !ex.allow_third_party) {
        auto b = Block(EventCategory::kThirdPartyFrame,
                       "third-party frames are blocked in Strict Protection mode");
        b.site = d.site;
        b.third_party = true;
        return b;
      }
      if (req.type == kResourceScript && !d.site.empty() &&
          policy.javascript_blocked_sites.count(d.site) && !ex.allow_javascript) {
        auto b = Block(EventCategory::kScript, "JavaScript is blocked for this site");
        b.site = d.site;
        b.third_party = third_party;
        return b;
      }
      break;
    case SecurityMode::kCompatibility:
      break;
  }
  return d;
}

bool IsJavaScriptAllowed(const PolicySnapshot& policy, std::string_view site_url) {
  auto u = ParseUrl(site_url);
  if (!u) return false;
  if (IsInternalScheme(u->scheme)) return false;  // internal pages never run script
  const std::string host = NormalizeHostForMatching(u->host);
  SiteException ex = policy.ExceptionFor(host);
  switch (policy.mode) {
    case SecurityMode::kMaximumIsolation:
      return ex.allow_javascript;
    case SecurityMode::kStrictProtection:
      if (ex.allow_javascript) return true;
      return !policy.javascript_blocked_sites.count(policy.SiteFor(host));
    case SecurityMode::kCompatibility:
      return true;
  }
  return false;
}

bool IsJavaScriptOptimizerAllowed(const PolicySnapshot& policy, std::string_view site_url) {
  // Disabling the optimizing compilers removes a large share of the V8
  // attack surface historically used by renderer exploits, at a
  // performance cost. Only Compatibility mode enables them.
  (void)site_url;
  return policy.mode == SecurityMode::kCompatibility;
}

PopupDecision EvaluatePopup(const PolicySnapshot& policy, const PopupContext& ctx) {
  PopupDecision d;
  auto target = ParseUrl(ctx.target_url);
  auto opener = ParseUrl(ctx.opener_url);
  std::string opener_host = opener ? NormalizeHostForMatching(opener->host) : std::string();
  SiteException ex = policy.ExceptionFor(opener_host);

  if (!target) {
    d.reason = "popup with an invalid target";
    return d;
  }
  if (!(target->IsHttpLike() || target->scheme == "about")) {
    d.reason = "popup to scheme '" + target->scheme + "' blocked";
    return d;
  }
  if (policy.filters && target->IsHttpLike()) {
    RequestInfo info;
    std::string host = NormalizeHostForMatching(target->host);
    info.url = ctx.target_url;
    info.request_host = host;
    info.first_party_host = opener_host;
    info.first_party_url = ctx.opener_url;
    info.type = kResourcePopup;
    info.third_party = policy.psl ? policy.psl->IsThirdParty(host, opener_host) : true;
    FilterMatch m = policy.filters->Match(info);
    if (m.decision != FilterDecision::kBlock) {
      info.type = kResourceDocument;
      m = policy.filters->Match(info);
    }
    if (m.decision == FilterDecision::kBlock && !ex.disable_filtering) {
      d.reason = "popup target is on the " + m.list_id + " filter list";
      return d;
    }
  }
  if (!ctx.user_gesture && !ex.allow_popups) {
    d.reason = "popup opened without a user gesture";
    return d;
  }
  if (policy.mode == SecurityMode::kMaximumIsolation && !ctx.is_new_foreground_tab_disposition &&
      !ex.allow_popups) {
    d.reason = "script-sized popup windows are blocked in Maximum Isolation mode";
    return d;
  }
  d.action = PopupAction::kOpenAsTab;
  d.reason = "user-initiated new tab";
  return d;
}

NavigationDecision EvaluateNavigation(const PolicySnapshot& policy, const NavigationContext& ctx) {
  (void)policy;
  NavigationDecision d;
  auto target = ParseUrl(ctx.target_url);
  auto current = ParseUrl(ctx.current_url);
  if (!target) {
    d.action = NavigationAction::kBlock;
    d.category = EventCategory::kUnsafeScheme;
    d.reason = "malformed navigation target";
    return d;
  }
  const std::string& s = target->scheme;
  const bool from_internal = current && IsInternalScheme(current->scheme);
  if (s == "javascript" || s == "vbscript") {
    d.action = NavigationAction::kBlock;
    d.category = EventCategory::kUnsafeScheme;
    d.reason = "script URLs are not navigable";
    return d;
  }
  if (IsInternalScheme(s)) {
    if (ctx.typed_by_user || from_internal || (!current && ctx.is_main_frame)) return d;
    d.action = NavigationAction::kBlock;
    d.category = EventCategory::kUnsafeScheme;
    d.reason = "web pages may not open internal pages";
    return d;
  }
  if (s == "file") {
    if (ctx.typed_by_user && ctx.is_main_frame) return d;
    if (current && current->scheme == "file" && ctx.user_gesture && ctx.is_main_frame) return d;
    d.action = NavigationAction::kBlock;
    d.category = EventCategory::kUnsafeScheme;
    d.reason = "local file access requires explicit user navigation";
    return d;
  }
  if (s == "data" && ctx.is_main_frame && !ctx.typed_by_user) {
    d.action = NavigationAction::kBlock;
    d.category = EventCategory::kUnsafeScheme;
    d.reason = "top-level data: URL navigation blocked (phishing vector)";
    return d;
  }
  if (s == "chrome" || s == "chrome-untrusted" || s == "devtools" || s == "view-source" ||
      s == "chrome-extension") {
    if (ctx.typed_by_user && ctx.is_main_frame && (s == "view-source")) return d;
    d.action = NavigationAction::kBlock;
    d.category = EventCategory::kUnsafeScheme;
    d.reason = "engine-internal pages are not exposed";
    return d;
  }
  return d;
}

}  // namespace aegis

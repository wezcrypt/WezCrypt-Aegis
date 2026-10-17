#include "browser/request_handlers.h"

#include <map>
#include <mutex>
#include <set>

#include <shellapi.h>
#include <windows.h>

#include "browser/aegis_context.h"
#include "browser/scheme_handler.h"
#include "common/strings.h"
#include "common/utf8.h"
#include "include/base/cef_callback.h"
#include "include/cef_task.h"
#include "include/wrapper/cef_closure_task.h"
#include "include/wrapper/cef_helpers.h"
#include "networking/network_policy.h"

namespace aegis {
namespace {

std::mutex g_nav_mutex;
std::map<int, std::multiset<std::string>> g_expected_navs;
std::map<int, std::map<std::string, std::string>> g_https_upgrades;
std::map<int, std::string> g_gesture_navs;

class ThirdPartyCookieFilter : public CefCookieAccessFilter {
 public:
  bool CanSendCookie(CefRefPtr<CefBrowser>, CefRefPtr<CefFrame>, CefRefPtr<CefRequest>,
                     const CefCookie&) override {
    return false;
  }
  bool CanSaveCookie(CefRefPtr<CefBrowser>, CefRefPtr<CefFrame>, CefRefPtr<CefRequest>,
                     CefRefPtr<CefResponse>, const CefCookie&) override {
    return false;
  }

 private:
  IMPLEMENT_REFCOUNTING(ThirdPartyCookieFilter);
};

RequestContext BuildContext(CefRefPtr<CefBrowser> browser, CefRefPtr<CefFrame> frame,
                            CefRefPtr<CefRequest> request, const std::string& url,
                            std::string* top_storage) {
  RequestContext ctx;
  ctx.type = MapResourceType(request->GetResourceType());
  ctx.is_main_frame = ctx.type == kResourceDocument;
  *top_storage = ctx.is_main_frame ? url : FirstPartyUrlFor(browser, frame, request);
  ctx.top_level_url = *top_storage;
  auto top = ParseUrl(*top_storage);
  ctx.from_internal_page = top && top->scheme == "aegis";
  return ctx;
}

std::string ExternalSchemeOf(const std::string& url) {
  std::size_t c = url.find(':');
  return c == std::string::npos ? std::string() : ToLowerAscii(url.substr(0, c));
}

void ConfirmExternalLaunch(int browser_id, std::string url) {
  CEF_REQUIRE_UI_THREAD();
  auto* ctx = AegisContext::Get();
  if (!ctx) return;
  // Re-evaluate on the UI thread with the current settings.
  auto verdict = EvaluateExternalProtocol(url, ctx->settings().mode, true,
                                          ctx->settings().external_protocols_allowed);
  if (verdict.decision == ExternalProtocolDecision::kBlock) return;
  std::string scheme = ExternalSchemeOf(url);
  if (verdict.decision == ExternalProtocolDecision::kAskUser) {
    std::wstring msg = L"A page wants to open an external application to handle this link:\n\n" +
                       Utf8ToWide(SanitizeForLog(url, 300)) +
                       L"\n\nOnly continue if you trust both the site and the application.\n\n"
                       L"Yes = open once and remember this protocol (" + Utf8ToWide(scheme) +
                       L"),  No = open once,  Cancel = do not open";
    int r = ::MessageBoxW(nullptr, msg.c_str(), L"WezCrypt Aegis - Open external application?",
                          MB_YESNOCANCEL | MB_ICONWARNING | MB_DEFBUTTON3 | MB_TASKMODAL);
    if (r == IDCANCEL) {
      ctx->Record(EventCategory::kUnsafeScheme, "", url, kResourceOther,
                  "external protocol launch declined by user", {}, {}, browser_id);
      return;
    }
    if (r == IDYES) {
      ctx->UpdateSettings([&](Settings& s) { s.external_protocols_allowed.insert(scheme); });
    }
  }
  ::ShellExecuteW(nullptr, L"open", Utf8ToWide(url).c_str(), nullptr, nullptr, SW_SHOWNORMAL);
}

}  // namespace

ResourceType MapResourceType(cef_resource_type_t t) {
  switch (t) {
    case RT_MAIN_FRAME:
    case RT_NAVIGATION_PRELOAD_MAIN_FRAME:
      return kResourceDocument;
    case RT_SUB_FRAME:
      return kResourceSubdocument;
    case RT_STYLESHEET:
      return kResourceStylesheet;
    case RT_SCRIPT:
    case RT_WORKER:
    case RT_SHARED_WORKER:
    case RT_SERVICE_WORKER:
      return kResourceScript;
    case RT_IMAGE:
    case RT_FAVICON:
      return kResourceImage;
    case RT_FONT_RESOURCE:
      return kResourceFont;
    case RT_OBJECT:
    case RT_PLUGIN_RESOURCE:
      return kResourceObject;
    case RT_MEDIA:
      return kResourceMedia;
    case RT_XHR:
      return kResourceXhr;
    case RT_PING:
      return kResourcePing;
    default:
      // RT_NAVIGATION_PRELOAD_SUB_FRAME (20) is a subframe navigation.
      if (static_cast<int>(t) == 20) return kResourceSubdocument;
      return kResourceOther;
  }
}

std::string FirstPartyUrlFor(CefRefPtr<CefBrowser> browser, CefRefPtr<CefFrame> frame,
                             CefRefPtr<CefRequest> request) {
  if (browser) {
    if (auto main = browser->GetMainFrame()) {
      std::string u = main->GetURL().ToString();
      if (!u.empty() && u != "about:blank") return u;
    }
  }
  (void)frame;
  return request->GetFirstPartyForCookies().ToString();
}

CefRefPtr<CefCookieAccessFilter> AegisResourceRequestHandler::GetCookieAccessFilter(
    CefRefPtr<CefBrowser> browser, CefRefPtr<CefFrame> frame, CefRefPtr<CefRequest> request) {
  auto* ctx = AegisContext::Get();
  if (!ctx) return new ThirdPartyCookieFilter();  // fail closed
  auto policy = ctx->policy();
  if (!policy->block_third_party_cookies) return nullptr;
  std::string url = request->GetURL().ToString();
  if (MapResourceType(request->GetResourceType()) == kResourceDocument) return nullptr;
  auto req = ParseUrl(url);
  auto top = ParseUrl(FirstPartyUrlFor(browser, frame, request));
  if (!req || !top) return new ThirdPartyCookieFilter();
  if (policy->psl->IsThirdParty(NormalizeHostForMatching(req->host),
                                NormalizeHostForMatching(top->host))) {
    return new ThirdPartyCookieFilter();
  }
  return nullptr;
}

CefResourceRequestHandler::ReturnValue AegisResourceRequestHandler::OnBeforeResourceLoad(
    CefRefPtr<CefBrowser> browser, CefRefPtr<CefFrame> frame, CefRefPtr<CefRequest> request,
    CefRefPtr<CefCallback> callback) {
  (void)callback;
  auto* ctx = AegisContext::Get();
  if (!ctx) return RV_CANCEL;  // shutting down or not initialized: fail closed
  const std::string url = request->GetURL().ToString();
  std::string top;
  RequestContext rc = BuildContext(browser, frame, request, url, &top);
  rc.url = url;
  RequestDecision d = EvaluateRequest(*ctx->policy(), rc);
  const int browser_id = browser ? browser->GetIdentifier() : -1;

  switch (d.action) {
    case RequestAction::kAllow:
      return RV_CONTINUE;
    case RequestAction::kUpgradeToHttps:
      ctx->Record(EventCategory::kHttpsUpgrade, d.site, url, rc.type, d.reason, {}, {}, browser_id);
      RememberHttpsUpgrade(browser_id, d.upgraded_url, url);
      request->SetURL(d.upgraded_url);  // treated by CEF as a redirect before any fetch
      return RV_CONTINUE;
    case RequestAction::kBlock:
      ctx->Record(*d.category, d.site, url, rc.type, d.reason, d.rule, d.list, browser_id);
      return RV_CANCEL;
    case RequestAction::kBlockWithInterstitial: {
      ctx->Record(*d.category, d.site, url, rc.type, d.reason, d.rule, d.list, browser_id);
      if (browser) {
        std::string token = ctx->IssueActionToken(
            json::Serialize(json::Value(json::Object{{"url", url}, {"reason", d.reason},
                                                     {"rule", d.rule}, {"list", d.list}}),
                            -1));
        NavigateToInternalPage(browser, "aegis://blocked/?t=" + token);
      }
      return RV_CANCEL;
    }
  }
  return RV_CANCEL;
}

void AegisResourceRequestHandler::OnResourceRedirect(CefRefPtr<CefBrowser> browser,
                                                     CefRefPtr<CefFrame> frame,
                                                     CefRefPtr<CefRequest> request,
                                                     CefRefPtr<CefResponse> response,
                                                     CefString& new_url) {
  (void)response;
  auto* ctx = AegisContext::Get();
  if (!ctx) {
    new_url = kBlockedResourceUrl;
    return;
  }
  const std::string target = new_url.ToString();
  std::string top;
  RequestContext rc = BuildContext(browser, frame, request, target, &top);
  rc.url = target;
  RequestDecision d = EvaluateRequest(*ctx->policy(), rc);
  const int browser_id = browser ? browser->GetIdentifier() : -1;
  switch (d.action) {
    case RequestAction::kAllow:
      return;
    case RequestAction::kUpgradeToHttps:
      ctx->Record(EventCategory::kHttpsUpgrade, d.site, target, rc.type, d.reason, {}, {}, browser_id);
      RememberHttpsUpgrade(browser_id, d.upgraded_url, target);
      new_url = d.upgraded_url;
      return;
    case RequestAction::kBlock:
    case RequestAction::kBlockWithInterstitial:
      ctx->Record(*d.category, d.site, target, rc.type, "redirect target: " + d.reason, d.rule,
                  d.list, browser_id);
      // The redirect is pointed at a non-network internal URL. Chromium
      // refuses redirects from web content to the display-isolated aegis
      // scheme, so the load fails without contacting the blocked host.
      new_url = kBlockedResourceUrl;
      if (rc.is_main_frame && browser) {
        std::string token = ctx->IssueActionToken(json::Serialize(
            json::Value(json::Object{{"url", target}, {"reason", "redirect target: " + d.reason},
                                     {"rule", d.rule}, {"list", d.list}}),
            -1));
        NavigateToInternalPage(browser, "aegis://blocked/?t=" + token);
      }
      return;
  }
}

void AegisResourceRequestHandler::OnProtocolExecution(CefRefPtr<CefBrowser> browser,
                                                      CefRefPtr<CefFrame> frame,
                                                      CefRefPtr<CefRequest> request,
                                                      bool& allow_os_execution) {
  (void)frame;
  // The engine never launches OS handlers directly. Permitted launches are
  // confirmed and performed by WezCrypt Aegis on the UI thread.
  allow_os_execution = false;
  auto* ctx = AegisContext::Get();
  if (!ctx) return;
  const std::string url = request->GetURL().ToString();
  const int browser_id = browser ? browser->GetIdentifier() : -1;
  const bool gesture = browser && WasGestureNavigation(browser_id, url);
  auto policy = ctx->policy();
  auto verdict = EvaluateExternalProtocol(url, policy->mode, gesture, policy->external_protocols_allowed);
  if (verdict.decision == ExternalProtocolDecision::kBlock) {
    std::string site;
    if (browser) {
      auto top = ParseUrl(browser->GetMainFrame()->GetURL().ToString());
      if (top) site = policy->SiteFor(top->host);
    }
    ctx->Record(EventCategory::kUnsafeScheme, site, url, kResourceOther,
                "external protocol blocked: " + verdict.reason, {}, {}, browser_id);
    return;
  }
  CefPostTask(TID_UI, base::BindOnce(&ConfirmExternalLaunch, browser_id, url));
}

AegisRequestContextHandler::AegisRequestContextHandler()
    : handler_(new AegisResourceRequestHandler()) {}

void AegisRequestContextHandler::OnRequestContextInitialized(
    CefRefPtr<CefRequestContext> request_context) {
  CEF_REQUIRE_UI_THREAD();
  RegisterInternalSchemeHandler(request_context);
  if (auto* ctx = AegisContext::Get()) ctx->ApplyEnginePolicy(request_context);
}

CefRefPtr<CefResourceRequestHandler> AegisRequestContextHandler::GetResourceRequestHandler(
    CefRefPtr<CefBrowser>, CefRefPtr<CefFrame>, CefRefPtr<CefRequest>, bool, bool,
    const CefString&, bool& disable_default_handling) {
  disable_default_handling = false;
  return handler_;
}

void NavigateToInternalPage(CefRefPtr<CefBrowser> browser, const std::string& url) {
  if (!browser) return;
  ExpectBrowserNavigation(browser->GetIdentifier(), url);
  if (!CefCurrentlyOn(TID_UI)) {
    CefPostTask(TID_UI, base::BindOnce(&NavigateToInternalPage, browser, url));
    return;
  }
  browser->GetMainFrame()->LoadURL(url);
}

void ExpectBrowserNavigation(int browser_id, const std::string& url) {
  std::lock_guard<std::mutex> lock(g_nav_mutex);
  auto& set = g_expected_navs[browser_id];
  if (set.size() > 64) set.clear();
  set.insert(url);
}

bool ConsumeExpectedNavigation(int browser_id, const std::string& url) {
  std::lock_guard<std::mutex> lock(g_nav_mutex);
  auto it = g_expected_navs.find(browser_id);
  if (it == g_expected_navs.end()) return false;
  auto e = it->second.find(url);
  if (e == it->second.end()) {
    // Chromium canonicalizes URLs ("aegis://x" -> "aegis://x/"); compare canonical forms.
    auto want = ParseUrl(url);
    for (auto i = it->second.begin(); i != it->second.end(); ++i) {
      auto have = ParseUrl(*i);
      if (want && have && want->Spec() == have->Spec()) {
        it->second.erase(i);
        return true;
      }
    }
    return false;
  }
  it->second.erase(e);
  return true;
}

void RememberHttpsUpgrade(int browser_id, const std::string& https_url, const std::string& http_url) {
  if (browser_id < 0) return;
  std::lock_guard<std::mutex> lock(g_nav_mutex);
  auto& m = g_https_upgrades[browser_id];
  if (m.size() > 64) m.clear();
  m[https_url] = http_url;
}

bool TakeHttpsUpgrade(int browser_id, const std::string& https_url, std::string* http_url) {
  std::lock_guard<std::mutex> lock(g_nav_mutex);
  auto it = g_https_upgrades.find(browser_id);
  if (it == g_https_upgrades.end()) return false;
  auto e = it->second.find(https_url);
  if (e == it->second.end()) return false;
  *http_url = e->second;
  it->second.erase(e);
  return true;
}

void RememberGestureNavigation(int browser_id, const std::string& url) {
  std::lock_guard<std::mutex> lock(g_nav_mutex);
  g_gesture_navs[browser_id] = url;
}

bool WasGestureNavigation(int browser_id, const std::string& url) {
  std::lock_guard<std::mutex> lock(g_nav_mutex);
  auto it = g_gesture_navs.find(browser_id);
  return it != g_gesture_navs.end() && it->second == url;
}

}  // namespace aegis

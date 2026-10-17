#include "browser/client_handler.h"

#include <windows.h>

#include <cstring>

#include "browser/aegis_context.h"
#include "browser/request_handlers.h"
#include "browser/sandbox_check.h"
#include "browser/update_service.h"
#include "common/strings.h"
#include "common/utf8.h"
#include "downloads/download_safety.h"
#include "include/base/cef_callback.h"
#include "include/cef_parser.h"
#include "include/wrapper/cef_closure_task.h"
#include "include/wrapper/cef_helpers.h"
#include "networking/network_policy.h"
#include "permissions/permission_policy.h"
#include "ui/omnibox.h"

namespace aegis {
namespace {

// CEF permission bit values must match the core's mirror (CEF 154).
static_assert(perm::kCameraStream == CEF_PERMISSION_TYPE_CAMERA_STREAM);
static_assert(perm::kGeolocation == CEF_PERMISSION_TYPE_GEOLOCATION);
static_assert(perm::kMicStream == CEF_PERMISSION_TYPE_MIC_STREAM);
static_assert(perm::kNotifications == CEF_PERMISSION_TYPE_NOTIFICATIONS);
static_assert(perm::kSensors == CEF_PERMISSION_TYPE_SENSORS);
static_assert(perm::kLoopbackNetwork == CEF_PERMISSION_TYPE_LOOPBACK_NETWORK);

constexpr int kMenuOpenLinkNewTab = MENU_ID_USER_FIRST + 1;
constexpr int kMenuCopyLink = MENU_ID_USER_FIRST + 2;

std::string SiteOfUrl(const std::string& url) {
  auto* ctx = AegisContext::Get();
  auto u = ParseUrl(url);
  if (!ctx || !u) return {};
  return ctx->policy()->SiteFor(u->host);
}

std::string TokenFor(AegisContext* ctx, json::Object o) {
  return ctx->IssueActionToken(json::Serialize(json::Value(std::move(o)), -1));
}

bool IsCertError(int code) { return code <= -200 && code >= -299; }

void CopyToClipboard(HWND owner, const std::string& text) {
  std::wstring w = Utf8ToWide(text);
  if (!::OpenClipboard(owner)) return;
  ::EmptyClipboard();
  HGLOBAL mem = ::GlobalAlloc(GMEM_MOVEABLE, (w.size() + 1) * sizeof(wchar_t));
  if (mem) {
    void* p = ::GlobalLock(mem);
    std::memcpy(p, w.c_str(), (w.size() + 1) * sizeof(wchar_t));
    ::GlobalUnlock(mem);
    if (!::SetClipboardData(CF_UNICODETEXT, mem)) ::GlobalFree(mem);
  }
  ::CloseClipboard();
}

}  // namespace

ClientHandler::ClientHandler(TabHost* host) : host_(host) {}

void ClientHandler::DetachHost() {
  CEF_REQUIRE_UI_THREAD();
  host_ = nullptr;
}

bool ClientHandler::IsPrivate(CefRefPtr<CefBrowser> browser) const {
  auto* ctx = AegisContext::Get();
  return ctx && browser && ctx->IsPrivateContext(browser->GetHost()->GetRequestContext());
}

void* ClientHandler::OwnerWindow() { return host_ ? host_->NativeWindowHandle() : nullptr; }

bool ClientHandler::OnProcessMessageReceived(CefRefPtr<CefBrowser> browser, CefRefPtr<CefFrame>,
                                             CefProcessId source_process,
                                             CefRefPtr<CefProcessMessage> message) {
  // WezCrypt Aegis installs no renderer-side bindings (its only renderer code
  // removes Web APIs), so no renderer has a legitimate reason to message the
  // browser process. Messages are dropped
  // and logged: a compromised renderer gains no privileged entry point.
  LOG(WARNING) << "dropped unexpected process message '" << message->GetName().ToString()
               << "' from process " << source_process << " (browser "
               << (browser ? browser->GetIdentifier() : -1) << ")";
  return true;
}

void ClientHandler::OnBeforeContextMenu(CefRefPtr<CefBrowser>, CefRefPtr<CefFrame>,
                                        CefRefPtr<CefContextMenuParams> params,
                                        CefRefPtr<CefMenuModel> model) {
  model->Remove(MENU_ID_VIEW_SOURCE);
  if (!params->GetLinkUrl().empty()) {
    if (model->GetCount() > 0) model->AddSeparator();
    model->AddItem(kMenuOpenLinkNewTab, "Open link in new tab");
    model->AddItem(kMenuCopyLink, "Copy link address");
  }
}

bool ClientHandler::OnContextMenuCommand(CefRefPtr<CefBrowser> browser, CefRefPtr<CefFrame>,
                                         CefRefPtr<CefContextMenuParams> params, int command_id,
                                         EventFlags) {
  if (command_id == kMenuOpenLinkNewTab) {
    auto* ctx = AegisContext::Get();
    std::string link = params->GetLinkUrl().ToString();
    if (!ctx || !host_) return true;
    PopupContext pc;
    std::string opener = browser->GetMainFrame()->GetURL().ToString();
    pc.target_url = link;
    pc.opener_url = opener;
    pc.user_gesture = true;
    pc.is_new_foreground_tab_disposition = true;
    if (EvaluatePopup(*ctx->policy(), pc).action == PopupAction::kOpenAsTab) {
      host_->OpenInNewTab(link, true);
    }
    return true;
  }
  if (command_id == kMenuCopyLink) {
    CopyToClipboard(static_cast<HWND>(OwnerWindow()), params->GetLinkUrl().ToString());
    return true;
  }
  return false;
}

void ClientHandler::OnAddressChange(CefRefPtr<CefBrowser> browser, CefRefPtr<CefFrame> frame,
                                    const CefString& url) {
  CEF_REQUIRE_UI_THREAD();
  if (frame->IsMain() && host_) host_->OnTabAddressChanged(browser->GetIdentifier(), url.ToString());
}

void ClientHandler::OnTitleChange(CefRefPtr<CefBrowser> browser, const CefString& title) {
  CEF_REQUIRE_UI_THREAD();
  if (host_) host_->OnTabTitleChanged(browser->GetIdentifier(), title.ToString());
  auto* ctx = AegisContext::Get();
  if (ctx && !IsPrivate(browser) && ctx->settings().save_history) {
    ctx->history().UpdateTitle(browser->GetMainFrame()->GetURL().ToString(), title.ToString());
  }
}

void ClientHandler::OnStatusMessage(CefRefPtr<CefBrowser> browser, const CefString& value) {
  CEF_REQUIRE_UI_THREAD();
  if (host_) host_->OnTabStatusMessage(browser->GetIdentifier(), value.ToString());
}

bool ClientHandler::OnConsoleMessage(CefRefPtr<CefBrowser>, cef_log_severity_t, const CefString&,
                                     const CefString&, int) {
  return true;  // page console output is not written to WezCrypt logs
}

bool ClientHandler::CanDownload(CefRefPtr<CefBrowser>, const CefString& url, const CefString&) {
  auto u = ParseUrl(url.ToString());
  // Downloads are only accepted over HTTP(S), data: and blob: URLs.
  return u && (u->IsHttpLike() || u->scheme == "blob" || u->scheme == "data");
}

bool ClientHandler::OnBeforeDownload(CefRefPtr<CefBrowser> browser, CefRefPtr<CefDownloadItem> item,
                                     const CefString& suggested_name,
                                     CefRefPtr<CefBeforeDownloadCallback> callback) {
  CEF_REQUIRE_UI_THREAD();
  auto* ctx = AegisContext::Get();
  if (!ctx) return false;  // Alloy style: returning false cancels
  const std::string name = SanitizeDownloadFilename(suggested_name.ToString());
  const FileRisk risk = ClassifyDownloadRisk(name);
  const std::string url = item->GetURL().ToString();
  const std::string site = SiteOfUrl(browser->GetMainFrame()->GetURL().ToString());
  DownloadRecord& rec = ctx->UpsertDownload(item->GetId());
  rec.filename = name;
  rec.url = SanitizeForLog(url, 500);
  rec.referrer = browser->GetMainFrame()->GetURL().ToString();
  rec.risk = risk;

  std::wstring msg = L"Do you want to download this file?\n\nFile: " + Utf8ToWide(name) +
                     L"\nFrom: " + Utf8ToWide(SanitizeForLog(url, 200)) + L"\nRisk: " +
                     Utf8ToWide(std::string(FileRiskLabel(risk)));
  UINT icon = MB_ICONQUESTION;
  if (risk == FileRisk::kDangerous) {
    msg += L"\n\nWARNING: this type of file can run code on your computer. "
           L"WezCrypt Aegis will never open it automatically. Only keep it if you trust the source.";
    icon = MB_ICONWARNING;
  }
  if (HasDeceptiveDoubleExtension(name)) {
    msg += L"\n\nThe file name uses a double extension often used to disguise programs.";
  }
  int r = ::MessageBoxW(static_cast<HWND>(OwnerWindow()), msg.c_str(),
                        L"WezCrypt Aegis - Confirm download",
                        MB_YESNO | icon | MB_DEFBUTTON2);
  if (r != IDYES) {
    rec.state = "declined";
    ctx->Record(EventCategory::kDownload, site, url, kResourceOther, "download declined by user", {}, {},
                browser->GetIdentifier());
    return false;
  }
  std::filesystem::path dir = ctx->DefaultDownloadDirectory();
  auto target = ResolveDownloadPath(dir, name);
  if (!target) {
    rec.state = "failed: unsafe download path";
    return false;
  }
  rec.state = "in progress";
  // show_dialog=true: the user confirms the final location in the Save dialog.
  callback->Continue(WideToUtf8(target->wstring()), true);
  return true;
}

void ClientHandler::OnDownloadUpdated(CefRefPtr<CefBrowser> browser, CefRefPtr<CefDownloadItem> item,
                                      CefRefPtr<CefDownloadItemCallback>) {
  CEF_REQUIRE_UI_THREAD();
  auto* ctx = AegisContext::Get();
  if (!ctx) return;
  DownloadRecord& rec = ctx->UpsertDownload(item->GetId());
  rec.percent = item->GetPercentComplete();
  std::string path = item->GetFullPath().ToString();
  if (!path.empty()) rec.path = path;
  if (item->IsInProgress()) rec.state = "in progress";
  if (item->IsCanceled()) rec.state = "cancelled";
  if (item->IsInterrupted()) rec.state = "interrupted";
  if (item->IsComplete() && rec.state != "complete") {
    rec.state = "complete";
    std::filesystem::path p(Utf8ToWide(path));
    rec.motw_applied = ApplyMarkOfTheWeb(p, rec.referrer, item->GetURL().ToString());
    if (!rec.motw_applied) LOG(WARNING) << "could not write Mark-of-the-Web for " << path;
    bool matches = false;
    if (UpdateService::VerifyDownloadedArtifact(path, WideToUtf8(p.filename().wstring()), &matches)) {
      if (matches) {
        rec.state = "complete - signature-verified WezCrypt Aegis release";
      } else {
        // A file claiming to be a release that fails verification is removed.
        std::error_code ec;
        std::filesystem::remove(p, ec);
        rec.state = "DELETED - failed release integrity verification";
        ::MessageBoxW(static_cast<HWND>(OwnerWindow()),
                      L"The downloaded file does not match the signed WezCrypt Aegis release "
                      L"manifest and has been deleted.",
                      L"WezCrypt Aegis - Integrity check failed", MB_OK | MB_ICONERROR);
      }
    }
  }
  (void)browser;
}

void ClientHandler::OnFindResult(CefRefPtr<CefBrowser> browser, int, int count, const CefRect&,
                                 int active_match_ordinal, bool final_update) {
  CEF_REQUIRE_UI_THREAD();
  if (host_) host_->OnTabFindResult(browser->GetIdentifier(), count, active_match_ordinal, final_update);
}

bool ClientHandler::OnJSDialog(CefRefPtr<CefBrowser> browser, const CefString& origin_url,
                               JSDialogType, const CefString&, const CefString&,
                               CefRefPtr<CefJSDialogCallback>, bool& suppress_message) {
  // Cross-origin subframes and Maximum Isolation pages may not open modal
  // dialogs (a common scareware / tech-support-scam technique).
  auto* ctx = AegisContext::Get();
  std::string top = browser->GetMainFrame()->GetURL().ToString();
  auto o = ParseUrl(origin_url.ToString());
  auto t = ParseUrl(top);
  bool cross_origin = !o || !t || o->Origin() != t->Origin();
  if (!ctx || ctx->settings().mode == SecurityMode::kMaximumIsolation || cross_origin) {
    suppress_message = true;
    return false;
  }
  suppress_message = false;
  return false;  // default dialog
}

bool ClientHandler::OnBeforePopup(CefRefPtr<CefBrowser> browser, CefRefPtr<CefFrame> frame, int,
                                  const CefString& target_url, const CefString&,
                                  cef_window_open_disposition_t target_disposition, bool user_gesture,
                                  const CefPopupFeatures&, CefWindowInfo&, CefRefPtr<CefClient>&,
                                  CefBrowserSettings&, CefRefPtr<CefDictionaryValue>&,
                                  bool* no_javascript_access) {
  // Popups never get a scripting relationship with their opener: allowed
  // popups are opened as independent tabs (no window.opener), all others
  // are blocked. Returning true cancels the engine-created popup.
  *no_javascript_access = true;
  auto* ctx = AegisContext::Get();
  if (!ctx) return true;
  const std::string target = target_url.ToString();
  const std::string opener = frame ? frame->GetURL().ToString() : browser->GetMainFrame()->GetURL().ToString();
  PopupContext pc;
  pc.target_url = target;
  pc.opener_url = opener;
  pc.user_gesture = user_gesture;
  pc.is_new_foreground_tab_disposition = target_disposition == CEF_WOD_NEW_FOREGROUND_TAB ||
                                         target_disposition == CEF_WOD_NEW_BACKGROUND_TAB;
  PopupDecision d = EvaluatePopup(*ctx->policy(), pc);
  if (d.action == PopupAction::kBlock) {
    ctx->Record(EventCategory::kPopup, SiteOfUrl(browser->GetMainFrame()->GetURL().ToString()), target,
                kResourcePopup, d.reason, {}, {}, browser->GetIdentifier());
    if (host_) host_->OnTabSecurityEvent(browser->GetIdentifier());
    return true;
  }
  if (host_) host_->OpenInNewTab(target, target_disposition != CEF_WOD_NEW_BACKGROUND_TAB);
  return true;
}

void ClientHandler::OnAfterCreated(CefRefPtr<CefBrowser> browser) {
  CEF_REQUIRE_UI_THREAD();
  if (host_) host_->OnTabCreated(browser);
  ScheduleSandboxCheck(3000);
}

void ClientHandler::OnBeforeClose(CefRefPtr<CefBrowser> browser) {
  CEF_REQUIRE_UI_THREAD();
  if (auto* ctx = AegisContext::Get()) ctx->events().ResetTab(browser->GetIdentifier());
  if (host_) host_->OnTabClosed(browser->GetIdentifier());
}

void ClientHandler::OnLoadingStateChange(CefRefPtr<CefBrowser> browser, bool is_loading,
                                         bool can_go_back, bool can_go_forward) {
  CEF_REQUIRE_UI_THREAD();
  if (host_) host_->OnTabLoadingState(browser->GetIdentifier(), is_loading, can_go_back, can_go_forward);
}

void ClientHandler::OnLoadStart(CefRefPtr<CefBrowser> browser, CefRefPtr<CefFrame> frame,
                                TransitionType) {
  CEF_REQUIRE_UI_THREAD();
  if (frame->IsMain()) {
    if (auto* ctx = AegisContext::Get()) ctx->events().ResetTab(browser->GetIdentifier());
    if (host_) host_->OnTabSecurityEvent(browser->GetIdentifier());
  }
}

void ClientHandler::OnLoadEnd(CefRefPtr<CefBrowser> browser, CefRefPtr<CefFrame> frame, int) {
  CEF_REQUIRE_UI_THREAD();
  if (!frame->IsMain()) return;
  auto* ctx = AegisContext::Get();
  if (ctx && !IsPrivate(browser) && ctx->settings().save_history) {
    ctx->history().AddVisit(frame->GetURL().ToString(), "", NowUnixMs());
  }
  if (host_) host_->OnTabSecurityEvent(browser->GetIdentifier());
  ScheduleSandboxCheck(1000);
}

void ClientHandler::OnLoadError(CefRefPtr<CefBrowser> browser, CefRefPtr<CefFrame> frame,
                                ErrorCode error_code, const CefString& error_text,
                                const CefString& failed_url) {
  CEF_REQUIRE_UI_THREAD();
  if (!frame->IsMain()) return;
  // ERR_ABORTED (-3) and ERR_BLOCKED_BY_CLIENT (-20, our own cancellation,
  // which shows its own interstitial) need no error page.
  // ERR_UNSAFE_REDIRECT is the expected result of a neutralized redirect
  // (the blocked page is shown instead) and ERR_UNKNOWN_URL_SCHEME is
  // handled by the external-protocol policy.
  if (error_code == ERR_ABORTED || error_code == ERR_BLOCKED_BY_CLIENT ||
      error_code == ERR_UNSAFE_REDIRECT || error_code == ERR_UNKNOWN_URL_SCHEME) {
    return;
  }
  auto* ctx = AegisContext::Get();
  if (!ctx) return;
  const std::string url = failed_url.ToString();
  const int code = static_cast<int>(error_code);
  std::string http_url;
  if (IsCertError(code)) {
    // The engine already refused the connection (OnCertificateError
    // returned false). WezCrypt Aegis offers no bypass.
    ctx->Record(EventCategory::kCertificate, SiteOfUrl(url), url, kResourceDocument,
                "certificate error " + error_text.ToString(), {}, {}, browser->GetIdentifier());
    NavigateToInternalPage(browser, "aegis://cert-error/?t=" +
                                        TokenFor(ctx, {{"url", url}, {"error", error_text.ToString()},
                                                       {"code", code}}));
    return;
  }
  if (TakeHttpsUpgrade(browser->GetIdentifier(), url, &http_url) && IsHttpsUpgradeFallbackError(code)) {
    NavigateToInternalPage(browser, "aegis://https-fallback/?t=" +
                                        TokenFor(ctx, {{"https_url", url}, {"http_url", http_url},
                                                       {"error", error_text.ToString()}}));
    return;
  }
  auto u = ParseUrl(url);
  if (u && u->scheme == "aegis") return;  // never loop on internal pages
  NavigateToInternalPage(browser, "aegis://load-error/?t=" +
                                      TokenFor(ctx, {{"url", url}, {"error", error_text.ToString()},
                                                     {"code", code}}));
}

bool ClientHandler::OnRequestMediaAccessPermission(CefRefPtr<CefBrowser> browser, CefRefPtr<CefFrame>,
                                                   const CefString& requesting_origin,
                                                   uint32_t requested_permissions,
                                                   CefRefPtr<CefMediaAccessCallback> callback) {
  CEF_REQUIRE_UI_THREAD();
  auto* ctx = AegisContext::Get();
  std::uint32_t mask = 0;
  if (requested_permissions & CEF_MEDIA_PERMISSION_DEVICE_AUDIO_CAPTURE) mask |= perm::kMicStream;
  if (requested_permissions & CEF_MEDIA_PERMISSION_DEVICE_VIDEO_CAPTURE) mask |= perm::kCameraStream;
  const bool desktop = (requested_permissions & (CEF_MEDIA_PERMISSION_DESKTOP_AUDIO_CAPTURE |
                                                 CEF_MEDIA_PERMISSION_DESKTOP_VIDEO_CAPTURE)) != 0;
  const std::string origin = requesting_origin.ToString();
  if (!ctx || desktop || mask == 0) {
    if (ctx) {
      ctx->Record(EventCategory::kPermission, SiteOfUrl(origin), origin, kResourceOther,
                  desktop ? "screen capture is never granted" : "unsupported media request", {}, {},
                  browser->GetIdentifier());
    }
    callback->Cancel();
    return true;
  }
  PermissionDecision d = EvaluatePermission(ctx->settings().mode, origin, mask,
                                            ctx->settings().permission_grants, IsPrivate(browser));
  if (d.action == PermissionAction::kAllow) {
    callback->Continue(requested_permissions);
    return true;
  }
  if (d.action == PermissionAction::kAsk) {
    std::wstring msg = Utf8ToWide(origin) + L" wants to use your " +
                       Utf8ToWide(Join(PermissionNames(mask), " and ")) +
                       L".\n\nAllow? (Yes = allow and remember for this site, No = deny)";
    int r = ::MessageBoxW(static_cast<HWND>(OwnerWindow()), msg.c_str(),
                          L"WezCrypt Aegis - Permission request", MB_YESNO | MB_ICONQUESTION | MB_DEFBUTTON2);
    if (r == IDYES) {
      if (!IsPrivate(browser)) {
        auto u = ParseUrl(origin);
        std::string key = u ? u->Origin() : origin;
        ctx->UpdateSettings([&](Settings& s) { s.permission_grants[key] |= mask; });
      }
      callback->Continue(requested_permissions);
      return true;
    }
    d.reason = "denied by user";
  }
  ctx->Record(EventCategory::kPermission, SiteOfUrl(origin), origin, kResourceOther, d.reason, {}, {},
              browser->GetIdentifier());
  callback->Cancel();
  return true;
}

bool ClientHandler::OnShowPermissionPrompt(CefRefPtr<CefBrowser> browser, uint64_t,
                                           const CefString& requesting_origin,
                                           uint32_t requested_permissions,
                                           CefRefPtr<CefPermissionPromptCallback> callback) {
  CEF_REQUIRE_UI_THREAD();
  auto* ctx = AegisContext::Get();
  const std::string origin = requesting_origin.ToString();
  if (!ctx) {
    callback->Continue(CEF_PERMISSION_RESULT_DENY);
    return true;
  }
  PermissionDecision d = EvaluatePermission(ctx->settings().mode, origin, requested_permissions,
                                            ctx->settings().permission_grants, IsPrivate(browser));
  if (d.action == PermissionAction::kAllow) {
    callback->Continue(CEF_PERMISSION_RESULT_ACCEPT);
    return true;
  }
  if (d.action == PermissionAction::kAsk) {
    std::wstring msg = Utf8ToWide(origin) + L" requests permission for: " +
                       Utf8ToWide(Join(PermissionNames(requested_permissions), ", ")) +
                       L".\n\nAllow? (Yes = allow and remember for this site, No = deny)";
    int r = ::MessageBoxW(static_cast<HWND>(OwnerWindow()), msg.c_str(),
                          L"WezCrypt Aegis - Permission request", MB_YESNO | MB_ICONQUESTION | MB_DEFBUTTON2);
    if (r == IDYES) {
      if (!IsPrivate(browser)) {
        auto u = ParseUrl(origin);
        std::string key = u ? u->Origin() : origin;
        ctx->UpdateSettings([&](Settings& s) { s.permission_grants[key] |= requested_permissions; });
      }
      callback->Continue(CEF_PERMISSION_RESULT_ACCEPT);
      return true;
    }
    d.reason = "denied by user";
  }
  ctx->Record(EventCategory::kPermission, SiteOfUrl(origin), origin, kResourceOther,
              d.reason + " (" + Join(PermissionNames(requested_permissions), ", ") + ")", {}, {},
              browser->GetIdentifier());
  if (host_) host_->OnTabSecurityEvent(browser->GetIdentifier());
  callback->Continue(CEF_PERMISSION_RESULT_DENY);
  return true;
}

bool ClientHandler::OnBeforeBrowse(CefRefPtr<CefBrowser> browser, CefRefPtr<CefFrame> frame,
                                   CefRefPtr<CefRequest> request, bool user_gesture, bool is_redirect) {
  CEF_REQUIRE_UI_THREAD();
  auto* ctx = AegisContext::Get();
  if (!ctx) return true;
  const std::string url = request->GetURL().ToString();
  const int id = browser->GetIdentifier();
  const bool main = frame->IsMain();
  const bool expected = main && ConsumeExpectedNavigation(id, url);
  if (user_gesture) RememberGestureNavigation(id, url);

  NavigationContext nc;
  nc.target_url = url;
  std::string current = frame->GetURL().ToString();
  nc.current_url = current;
  nc.is_main_frame = main;
  nc.user_gesture = user_gesture;
  nc.typed_by_user = expected;
  nc.is_redirect = is_redirect;
  NavigationDecision d = EvaluateNavigation(*ctx->policy(), nc);
  if (d.action == NavigationAction::kBlock) {
    ctx->Record(d.category.value_or(EventCategory::kUnsafeScheme),
                SiteOfUrl(browser->GetMainFrame()->GetURL().ToString()), url,
                main ? kResourceDocument : kResourceSubdocument, d.reason, {}, {}, id);
    if (host_) host_->OnTabSecurityEvent(id);
    return true;
  }

  // HTTPS-first consent link on the fallback page (one-time token).
  auto u = ParseUrl(url);
  if (u && u->scheme == "aegis" && u->host == "https-fallback" && u->path == "/continue") {
    std::string payload;
    auto from = ParseUrl(current);
    if (main && user_gesture && from && from->scheme == "aegis" &&
        ctx->ConsumeActionToken(QueryParam(u->query, "t"), &payload)) {
      auto v = json::Parse(payload);
      std::string http_url = v ? v->GetString("http_url") : std::string();
      auto hu = ParseUrl(http_url);
      if (v && v->GetString("action") == "http-continue" && hu && hu->scheme == "http") {
        std::string host = NormalizeHostForMatching(hu->host);
        if (!IsPrivate(browser)) {
          ctx->UpdateSettings([&](Settings& s) { s.http_allowed_hosts.insert(host); });
        }
        ExpectBrowserNavigation(id, http_url);
        CefPostTask(TID_UI, base::BindOnce(
                                [](CefRefPtr<CefBrowser> b, std::string target) {
                                  b->GetMainFrame()->LoadURL(target);
                                },
                                browser, http_url));
      }
    }
    return true;
  }

  // Engine-level JavaScript policy for this frame, set before it loads.
  const std::string top = main ? url : browser->GetMainFrame()->GetURL().ToString();
  ctx->ApplyFramePolicy(browser->GetHost()->GetRequestContext(), url, top);
  return false;
}

bool ClientHandler::OnOpenURLFromTab(CefRefPtr<CefBrowser> browser, CefRefPtr<CefFrame> frame,
                                     const CefString& target_url,
                                     cef_window_open_disposition_t target_disposition, bool user_gesture) {
  CEF_REQUIRE_UI_THREAD();
  auto* ctx = AegisContext::Get();
  if (!ctx || !host_) return true;
  PopupContext pc;
  const std::string target = target_url.ToString();
  const std::string opener = frame ? frame->GetURL().ToString() : std::string();
  pc.target_url = target;
  pc.opener_url = opener;
  pc.user_gesture = user_gesture;
  pc.is_new_foreground_tab_disposition = true;
  if (EvaluatePopup(*ctx->policy(), pc).action == PopupAction::kOpenAsTab) {
    host_->OpenInNewTab(target, target_disposition != CEF_WOD_NEW_BACKGROUND_TAB);
  } else {
    ctx->Record(EventCategory::kPopup, SiteOfUrl(browser->GetMainFrame()->GetURL().ToString()), target,
                kResourcePopup, "new-tab navigation blocked by popup policy", {}, {},
                browser->GetIdentifier());
  }
  return true;
}

CefRefPtr<CefResourceRequestHandler> ClientHandler::GetResourceRequestHandler(
    CefRefPtr<CefBrowser>, CefRefPtr<CefFrame>, CefRefPtr<CefRequest>, bool, bool, const CefString&,
    bool& disable_default_handling) {
  static CefRefPtr<AegisResourceRequestHandler> handler = new AegisResourceRequestHandler();
  disable_default_handling = false;
  return handler;
}

bool ClientHandler::GetAuthCredentials(CefRefPtr<CefBrowser>, const CefString&, bool, const CefString&,
                                       int, const CefString&, const CefString&,
                                       CefRefPtr<CefAuthCallback>) {
  return false;  // HTTP authentication dialogs are not offered (request cancelled)
}

bool ClientHandler::OnCertificateError(CefRefPtr<CefBrowser>, cef_errorcode_t, const CefString&,
                                       CefRefPtr<CefSSLInfo>, CefRefPtr<CefCallback>) {
  // Returning false cancels the request immediately. Invalid certificates
  // are never accepted; the error page is shown from OnLoadError.
  return false;
}

bool ClientHandler::OnSelectClientCertificate(CefRefPtr<CefBrowser>, bool, const CefString& host, int,
                                              const X509CertificateList&,
                                              CefRefPtr<CefSelectClientCertificateCallback> callback) {
  // Never present a client certificate automatically (identity leak).
  LOG(INFO) << "client certificate requested by " << host.ToString() << "; none presented";
  callback->Select(nullptr);
  return true;
}

void ClientHandler::OnRenderProcessTerminated(CefRefPtr<CefBrowser> browser, TerminationStatus status,
                                              int error_code, const CefString& error_string) {
  CEF_REQUIRE_UI_THREAD();
  LOG(WARNING) << "renderer terminated: status " << status << " code " << error_code;
  auto* ctx = AegisContext::Get();
  if (!ctx) return;
  std::string url = browser->GetMainFrame()->GetURL().ToString();
  NavigateToInternalPage(browser, "aegis://load-error/?t=" +
                                      TokenFor(ctx, {{"url", url},
                                                     {"error", "The page's isolated renderer process "
                                                               "stopped (" + error_string.ToString() + ")"},
                                                     {"code", error_code}}));
  ScheduleSandboxCheck(2000);
}

}  // namespace aegis

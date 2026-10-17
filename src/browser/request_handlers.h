// WezCrypt Aegis - network interception.
//
// Every resource request issued by a browser, frame or dedicated worker
// reaches AegisResourceRequestHandler::OnBeforeResourceLoad on the network
// (IO) thread *before* a connection is made. Blocked requests are cancelled
// there (RV_CANCEL), so no DNS lookup, TCP/TLS connection or HTTP request is
// made for them by the network stack.
//
// Requests that CEF 152 cannot attribute to a browser (service workers and
// shared workers in processes without a CEF frame) never reach this handler;
// they are caught by the http/https gate in browser/worker_gate.h, which
// denies them before any network access.
//
// Known interception gaps are documented in docs/SECURITY_ARCHITECTURE.md:
// WebSocket handshakes, WebRTC, <link rel=preconnect>/DNS prefetch hints
// and Chromium-internal requests (component updater) do not pass through
// CEF resource handlers.
#pragma once

#include "filtering/resource_type.h"
#include "include/cef_request_context_handler.h"
#include "include/cef_resource_request_handler.h"

namespace aegis {

ResourceType MapResourceType(cef_resource_type_t t);

// Top-level URL used as the first party for a request: the main frame's
// committed URL when available, otherwise the request's site-for-cookies.
std::string FirstPartyUrlFor(CefRefPtr<CefBrowser> browser, CefRefPtr<CefFrame> frame,
                             CefRefPtr<CefRequest> request);

class AegisResourceRequestHandler : public CefResourceRequestHandler {
 public:
  AegisResourceRequestHandler() = default;

  CefRefPtr<CefCookieAccessFilter> GetCookieAccessFilter(CefRefPtr<CefBrowser> browser,
                                                         CefRefPtr<CefFrame> frame,
                                                         CefRefPtr<CefRequest> request) override;
  ReturnValue OnBeforeResourceLoad(CefRefPtr<CefBrowser> browser, CefRefPtr<CefFrame> frame,
                                   CefRefPtr<CefRequest> request,
                                   CefRefPtr<CefCallback> callback) override;
  void OnResourceRedirect(CefRefPtr<CefBrowser> browser, CefRefPtr<CefFrame> frame,
                          CefRefPtr<CefRequest> request, CefRefPtr<CefResponse> response,
                          CefString& new_url) override;
  void OnProtocolExecution(CefRefPtr<CefBrowser> browser, CefRefPtr<CefFrame> frame,
                           CefRefPtr<CefRequest> request, bool& allow_os_execution) override;

 private:
  IMPLEMENT_REFCOUNTING(AegisResourceRequestHandler);
};

// Handles requests without a browser whose process hosts a CEF frame
// and initializes per-context engine policy.
class AegisRequestContextHandler : public CefRequestContextHandler {
 public:
  AegisRequestContextHandler();

  void OnRequestContextInitialized(CefRefPtr<CefRequestContext> request_context) override;
  CefRefPtr<CefResourceRequestHandler> GetResourceRequestHandler(
      CefRefPtr<CefBrowser> browser, CefRefPtr<CefFrame> frame, CefRefPtr<CefRequest> request,
      bool is_navigation, bool is_download, const CefString& request_initiator,
      bool& disable_default_handling) override;

  CefRefPtr<AegisResourceRequestHandler> resource_handler() const { return handler_; }

 private:
  CefRefPtr<AegisResourceRequestHandler> handler_;
  IMPLEMENT_REFCOUNTING(AegisRequestContextHandler);
};

// Posts a browser-initiated navigation to an internal page (UI thread).
void NavigateToInternalPage(CefRefPtr<CefBrowser> browser, const std::string& url);

// Browser-initiated navigations are registered so OnBeforeBrowse can tell
// them apart from page-initiated ones (thread-safe).
void ExpectBrowserNavigation(int browser_id, const std::string& url);
bool ConsumeExpectedNavigation(int browser_id, const std::string& url);

// HTTPS-first bookkeeping: URLs WezCrypt upgraded, so a connection failure
// on them can offer the HTTP fallback page.
void RememberHttpsUpgrade(int browser_id, const std::string& https_url, const std::string& http_url);
bool TakeHttpsUpgrade(int browser_id, const std::string& https_url, std::string* http_url);

// Last navigation URL started with a user gesture (for external protocols).
void RememberGestureNavigation(int browser_id, const std::string& url);
bool WasGestureNavigation(int browser_id, const std::string& url);

}  // namespace aegis

// WezCrypt Aegis - per-window CefClient: navigation, popup, permission,
// download, certificate and display handling for every tab of a window.
#pragma once

#include <string>

#include "include/cef_client.h"

namespace aegis {

// Implemented by the window that owns the tabs (UI thread callbacks).
class TabHost {
 public:
  virtual ~TabHost() = default;
  virtual void OnTabCreated(CefRefPtr<CefBrowser> browser) = 0;
  virtual void OnTabClosed(int browser_id) = 0;
  virtual void OnTabAddressChanged(int browser_id, const std::string& url) = 0;
  virtual void OnTabTitleChanged(int browser_id, const std::string& title) = 0;
  virtual void OnTabLoadingState(int browser_id, bool loading, bool can_back, bool can_forward) = 0;
  virtual void OnTabStatusMessage(int browser_id, const std::string& text) = 0;
  virtual void OnTabFindResult(int browser_id, int count, int active, bool final_update) = 0;
  virtual void OnTabSecurityEvent(int browser_id) = 0;
  virtual void OpenInNewTab(const std::string& url, bool foreground) = 0;
  virtual bool IsPrivateWindow() const = 0;
  virtual void* NativeWindowHandle() = 0;
};

class ClientHandler : public CefClient,
                      public CefContextMenuHandler,
                      public CefDisplayHandler,
                      public CefDownloadHandler,
                      public CefFindHandler,
                      public CefJSDialogHandler,
                      public CefLifeSpanHandler,
                      public CefLoadHandler,
                      public CefPermissionHandler,
                      public CefRequestHandler {
 public:
  explicit ClientHandler(TabHost* host);
  void DetachHost();  // called when the window is destroyed

  // CefClient
  CefRefPtr<CefContextMenuHandler> GetContextMenuHandler() override { return this; }
  CefRefPtr<CefDisplayHandler> GetDisplayHandler() override { return this; }
  CefRefPtr<CefDownloadHandler> GetDownloadHandler() override { return this; }
  CefRefPtr<CefFindHandler> GetFindHandler() override { return this; }
  CefRefPtr<CefJSDialogHandler> GetJSDialogHandler() override { return this; }
  CefRefPtr<CefLifeSpanHandler> GetLifeSpanHandler() override { return this; }
  CefRefPtr<CefLoadHandler> GetLoadHandler() override { return this; }
  CefRefPtr<CefPermissionHandler> GetPermissionHandler() override { return this; }
  CefRefPtr<CefRequestHandler> GetRequestHandler() override { return this; }
  bool OnProcessMessageReceived(CefRefPtr<CefBrowser> browser, CefRefPtr<CefFrame> frame,
                                CefProcessId source_process,
                                CefRefPtr<CefProcessMessage> message) override;

  // CefContextMenuHandler
  void OnBeforeContextMenu(CefRefPtr<CefBrowser> browser, CefRefPtr<CefFrame> frame,
                           CefRefPtr<CefContextMenuParams> params,
                           CefRefPtr<CefMenuModel> model) override;
  bool OnContextMenuCommand(CefRefPtr<CefBrowser> browser, CefRefPtr<CefFrame> frame,
                            CefRefPtr<CefContextMenuParams> params, int command_id,
                            EventFlags event_flags) override;

  // CefDisplayHandler
  void OnAddressChange(CefRefPtr<CefBrowser> browser, CefRefPtr<CefFrame> frame,
                       const CefString& url) override;
  void OnTitleChange(CefRefPtr<CefBrowser> browser, const CefString& title) override;
  void OnStatusMessage(CefRefPtr<CefBrowser> browser, const CefString& value) override;
  bool OnConsoleMessage(CefRefPtr<CefBrowser> browser, cef_log_severity_t level,
                        const CefString& message, const CefString& source, int line) override;

  // CefDownloadHandler
  bool CanDownload(CefRefPtr<CefBrowser> browser, const CefString& url,
                   const CefString& request_method) override;
  bool OnBeforeDownload(CefRefPtr<CefBrowser> browser, CefRefPtr<CefDownloadItem> item,
                        const CefString& suggested_name,
                        CefRefPtr<CefBeforeDownloadCallback> callback) override;
  void OnDownloadUpdated(CefRefPtr<CefBrowser> browser, CefRefPtr<CefDownloadItem> item,
                         CefRefPtr<CefDownloadItemCallback> callback) override;

  // CefFindHandler
  void OnFindResult(CefRefPtr<CefBrowser> browser, int identifier, int count,
                    const CefRect& selection_rect, int active_match_ordinal,
                    bool final_update) override;

  // CefJSDialogHandler
  bool OnJSDialog(CefRefPtr<CefBrowser> browser, const CefString& origin_url,
                  JSDialogType dialog_type, const CefString& message_text,
                  const CefString& default_prompt_text, CefRefPtr<CefJSDialogCallback> callback,
                  bool& suppress_message) override;

  // CefLifeSpanHandler
  bool OnBeforePopup(CefRefPtr<CefBrowser> browser, CefRefPtr<CefFrame> frame, int popup_id,
                     const CefString& target_url, const CefString& target_frame_name,
                     cef_window_open_disposition_t target_disposition, bool user_gesture,
                     const CefPopupFeatures& popup_features, CefWindowInfo& window_info,
                     CefRefPtr<CefClient>& client, CefBrowserSettings& settings,
                     CefRefPtr<CefDictionaryValue>& extra_info, bool* no_javascript_access) override;
  void OnAfterCreated(CefRefPtr<CefBrowser> browser) override;
  void OnBeforeClose(CefRefPtr<CefBrowser> browser) override;

  // CefLoadHandler
  void OnLoadingStateChange(CefRefPtr<CefBrowser> browser, bool is_loading, bool can_go_back,
                            bool can_go_forward) override;
  void OnLoadStart(CefRefPtr<CefBrowser> browser, CefRefPtr<CefFrame> frame,
                   TransitionType transition_type) override;
  void OnLoadEnd(CefRefPtr<CefBrowser> browser, CefRefPtr<CefFrame> frame,
                 int http_status_code) override;
  void OnLoadError(CefRefPtr<CefBrowser> browser, CefRefPtr<CefFrame> frame, ErrorCode error_code,
                   const CefString& error_text, const CefString& failed_url) override;

  // CefPermissionHandler
  bool OnRequestMediaAccessPermission(CefRefPtr<CefBrowser> browser, CefRefPtr<CefFrame> frame,
                                      const CefString& requesting_origin,
                                      uint32_t requested_permissions,
                                      CefRefPtr<CefMediaAccessCallback> callback) override;
  bool OnShowPermissionPrompt(CefRefPtr<CefBrowser> browser, uint64_t prompt_id,
                              const CefString& requesting_origin, uint32_t requested_permissions,
                              CefRefPtr<CefPermissionPromptCallback> callback) override;

  // CefRequestHandler
  bool OnBeforeBrowse(CefRefPtr<CefBrowser> browser, CefRefPtr<CefFrame> frame,
                      CefRefPtr<CefRequest> request, bool user_gesture, bool is_redirect) override;
  bool OnOpenURLFromTab(CefRefPtr<CefBrowser> browser, CefRefPtr<CefFrame> frame,
                        const CefString& target_url, cef_window_open_disposition_t target_disposition,
                        bool user_gesture) override;
  CefRefPtr<CefResourceRequestHandler> GetResourceRequestHandler(
      CefRefPtr<CefBrowser> browser, CefRefPtr<CefFrame> frame, CefRefPtr<CefRequest> request,
      bool is_navigation, bool is_download, const CefString& request_initiator,
      bool& disable_default_handling) override;
  bool GetAuthCredentials(CefRefPtr<CefBrowser> browser, const CefString& origin_url,
                          bool is_proxy, const CefString& host, int port, const CefString& realm,
                          const CefString& scheme, CefRefPtr<CefAuthCallback> callback) override;
  bool OnCertificateError(CefRefPtr<CefBrowser> browser, cef_errorcode_t cert_error,
                          const CefString& request_url, CefRefPtr<CefSSLInfo> ssl_info,
                          CefRefPtr<CefCallback> callback) override;
  bool OnSelectClientCertificate(CefRefPtr<CefBrowser> browser, bool is_proxy,
                                 const CefString& host, int port,
                                 const X509CertificateList& certificates,
                                 CefRefPtr<CefSelectClientCertificateCallback> callback) override;
  void OnRenderProcessTerminated(CefRefPtr<CefBrowser> browser, TerminationStatus status,
                                 int error_code, const CefString& error_string) override;

 private:
  bool IsPrivate(CefRefPtr<CefBrowser> browser) const;
  void* OwnerWindow();

  TabHost* host_;  // UI thread only; cleared by DetachHost()
  IMPLEMENT_REFCOUNTING(ClientHandler);
};

}  // namespace aegis

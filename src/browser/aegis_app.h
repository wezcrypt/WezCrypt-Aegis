// WezCrypt Aegis - CefApp for all processes.
#pragma once

#include <filesystem>
#include <string>
#include <vector>

#include "browser/request_handlers.h"
#include "include/cef_app.h"
#include "privacy/profile.h"
#include "security/security_mode.h"

namespace aegis {

class AegisApp : public CefApp, public CefBrowserProcessHandler {
 public:
  // Sub-process instance: only registers the internal scheme.
  AegisApp();
  // Browser-process instance.
  AegisApp(ProfilePaths paths, std::filesystem::path assets_dir, SecurityMode startup_mode,
           std::vector<std::string> startup_urls, bool start_private);

  // CefApp
  void OnBeforeCommandLineProcessing(const CefString& process_type,
                                     CefRefPtr<CefCommandLine> command_line) override;
  void OnRegisterCustomSchemes(CefRawPtr<CefSchemeRegistrar> registrar) override;
  CefRefPtr<CefBrowserProcessHandler> GetBrowserProcessHandler() override { return this; }
  CefRefPtr<CefRenderProcessHandler> GetRenderProcessHandler() override;

  // CefBrowserProcessHandler
  void OnContextInitialized() override;
  bool OnAlreadyRunningAppRelaunch(CefRefPtr<CefCommandLine> command_line,
                                   const CefString& current_directory) override;
  CefRefPtr<CefRequestContextHandler> GetDefaultRequestContextHandler() override;

 private:
  const bool browser_process_;
  ProfilePaths paths_;
  std::filesystem::path assets_dir_;
  SecurityMode startup_mode_ = kDefaultSecurityMode;
  std::vector<std::string> startup_urls_;
  bool start_private_ = false;
  CefRefPtr<AegisRequestContextHandler> context_handler_;
  CefRefPtr<CefRenderProcessHandler> render_handler_;
  IMPLEMENT_REFCOUNTING(AegisApp);
};

}  // namespace aegis

#include "browser/aegis_app.h"

#include <windows.h>

#include "browser/aegis_context.h"
#include "browser/request_handlers.h"
#include "browser/sandbox_check.h"
#include "browser/scheme_handler.h"
#include "browser/test_hooks.h"
#include "browser/update_service.h"
#include "browser/worker_gate.h"
#include "common/utf8.h"
#include "include/base/cef_callback.h"
#include "include/cef_request_context.h"
#include "include/wrapper/cef_closure_task.h"
#include "include/wrapper/cef_helpers.h"
#include "security/engine_switches.h"
#include "ui/browser_window.h"
#include "ui/omnibox.h"

namespace aegis {

AegisApp::AegisApp() : browser_process_(false) {}

AegisApp::AegisApp(ProfilePaths paths, std::filesystem::path assets_dir, SecurityMode startup_mode,
                   std::vector<std::string> startup_urls, bool start_private)
    : browser_process_(true),
      paths_(std::move(paths)),
      assets_dir_(std::move(assets_dir)),
      startup_mode_(startup_mode),
      startup_urls_(std::move(startup_urls)),
      start_private_(start_private),
      context_handler_(new AegisRequestContextHandler()) {}

void AegisApp::OnBeforeCommandLineProcessing(const CefString& process_type,
                                             CefRefPtr<CefCommandLine> command_line) {
  if (!process_type.empty()) return;  // sub-processes inherit from the browser
  for (const auto& [name, value] : HardeningSwitches(startup_mode_)) {
    if (name == "js-flags") continue;  // applied through CefSettings.javascript_flags
    if (value.empty()) command_line->AppendSwitch(name);
    else command_line->AppendSwitchWithValue(name, value);
  }
}

void AegisApp::OnRegisterCustomSchemes(CefRawPtr<CefSchemeRegistrar> registrar) {
  // Must be identical in every process.
  registrar->AddCustomScheme(kInternalScheme, InternalSchemeOptions());
}

CefRefPtr<CefRequestContextHandler> AegisApp::GetDefaultRequestContextHandler() {
  return context_handler_;
}

void AegisApp::OnContextInitialized() {
  CEF_REQUIRE_UI_THREAD();
  std::string error;
  AegisContext* ctx = AegisContext::Create(paths_, assets_dir_, &error);
  if (!ctx) {
    std::wstring msg = L"WezCrypt Aegis cannot start safely:\n\n" + Utf8ToWide(error) +
                       L"\n\nReinstall WezCrypt Aegis to restore the missing files.";
    ::MessageBoxW(nullptr, msg.c_str(), L"WezCrypt Aegis", MB_OK | MB_ICONERROR);
    CefQuitMessageLoop();
    return;
  }
  ctx->SetRequestContextHandler(context_handler_);
  auto global = CefRequestContext::GetGlobalContext();
  ctx->SetNormalRequestContext(global);
  RegisterInternalSchemeHandler(nullptr);
  // Requests without a browser (service workers in CEF 152) bypass resource
  // request handlers; without the gate they would reach the network
  // unfiltered, so startup does not continue if it cannot be installed.
  if (!RegisterUnattributedRequestGate(nullptr)) {
    ::MessageBoxW(nullptr,
                  L"WezCrypt Aegis cannot start safely: the network request gate could not be "
                  L"installed.\n\nReinstall WezCrypt Aegis.",
                  L"WezCrypt Aegis", MB_OK | MB_ICONERROR);
    CefQuitMessageLoop();
    return;
  }
  ctx->ApplyEnginePolicy(global);

  SetFailClosedHandler([](const std::string& reason) {
    // Runtime evidence shows web content running outside the sandbox. All
    // browsers are closed immediately and the application exits.
    BrowserWindow::CloseAll(true);
    std::wstring msg = L"WezCrypt Aegis detected that web content is running without the "
                       L"Chromium sandbox and has closed all windows to protect this computer.\n\n"
                       L"Details: " + Utf8ToWide(reason) +
                       L"\n\nPlease reinstall WezCrypt Aegis from the official source.";
    ::MessageBoxW(nullptr, msg.c_str(), L"WezCrypt Aegis - Sandbox failure", MB_OK | MB_ICONERROR);
    CefQuitMessageLoop();
  });

  std::vector<std::string> urls = startup_urls_;
  if (start_private_) {
    BrowserWindow::Open(true, urls);
  } else {
    if (urls.empty() && ctx->settings().restore_tabs) urls = ctx->settings().session_tabs;
    BrowserWindow::Open(false, urls);
  }
  StartTestHooks();

  // First update checks run shortly after startup, off the critical path.
  CefPostDelayedTask(TID_UI, base::BindOnce(&UpdateService::ScheduleBackgroundChecks), 15000);
}

bool AegisApp::OnAlreadyRunningAppRelaunch(CefRefPtr<CefCommandLine> command_line,
                                           const CefString& current_directory) {
  CEF_REQUIRE_UI_THREAD();
  (void)current_directory;
  if (!AegisContext::Get()) return false;
  // A second launch opens a new window in the running instance. Switches
  // on the relaunch command line are ignored; only URLs are honoured.
  std::vector<std::string> urls;
  CefCommandLine::ArgumentList args;
  command_line->GetArguments(args);
  for (const auto& a : args) {
    OmniboxResult r = ResolveOmniboxInput(a.ToString());
    if (!r.is_search && !r.typed_file_url) urls.push_back(r.url);
  }
  BrowserWindow::Open(command_line->HasSwitch("private"), urls);
  return true;
}

}  // namespace aegis

// WezCrypt Aegis - Windows entry point.
//
// Sandbox architecture (CEF M138+): the cef_sandbox static library can no
// longer be linked into applications built outside the Chromium toolchain.
// WezCrypt Aegis is therefore built as WezCryptAegis.dll and launched by
// CEF's prebuilt bootstrap.exe, renamed to WezCryptAegis.exe. The bootstrap
// creates the sandbox information object and calls RunWinMain() below for
// the browser process and for every sub-process.
//
// Fail-closed rules enforced here:
//  * sandbox_info must be non-null in every process, otherwise exit;
//  * security-weakening Chromium switches on the command line abort startup;
//  * CefSettings.no_sandbox is never set and user command-line switches are
//    not forwarded to Chromium (command_line_args_disabled).

#include <windows.h>
#include <shlobj.h>

#include <cstdint>
#include <cwchar>
#include <cwctype>
#include <filesystem>
#include <string>
#include <vector>

#include "browser/aegis_app.h"
#include "browser/aegis_context.h"
#include "browser/sandbox_check.h"
#include "browser/test_hooks.h"
#include "common/strings.h"
#include "common/utf8.h"
#include "include/cef_app.h"
#include "include/cef_command_line.h"
#include "include/cef_sandbox_win.h"
#include "privacy/profile.h"
#include "security/engine_switches.h"
#include "storage/atomic_file.h"
#include "storage/settings_store.h"
#include "ui/omnibox.h"

namespace {

std::filesystem::path ExecutableDir() {
  std::wstring buf(MAX_PATH, L'\0');
  for (;;) {
    DWORD n = ::GetModuleFileNameW(nullptr, buf.data(), static_cast<DWORD>(buf.size()));
    if (n == 0) return {};
    if (n < buf.size()) {
      buf.resize(n);
      break;
    }
    buf.resize(buf.size() * 2);
  }
  return std::filesystem::path(buf).parent_path();
}

std::filesystem::path DataRoot(const std::filesystem::path& exe_dir) {
  // Portable builds keep all data next to the executable.
  std::error_code ec;
  if (std::filesystem::exists(exe_dir / "portable.flag", ec)) return exe_dir / "Data";
  PWSTR raw = nullptr;
  std::filesystem::path root;
  if (SUCCEEDED(::SHGetKnownFolderPath(FOLDERID_LocalAppData, KF_FLAG_CREATE, nullptr, &raw)) && raw) {
    root = std::filesystem::path(raw) / L"WezCrypt" / L"Aegis";
  }
  if (raw) ::CoTaskMemFree(raw);
  return root;
}

int FailClosed(const std::wstring& message) {
  ::MessageBoxW(nullptr, message.c_str(), L"WezCrypt Aegis", MB_OK | MB_ICONERROR);
  return 1;
}

// Named after the profile directory so that only the first engine instance
// for a profile performs destructive startup maintenance. Later launches are
// forwarded to that instance by CEF's process singleton.
HANDLE AcquireProfileLock(const std::filesystem::path& profile_dir, bool* first_instance) {
  std::wstring key = profile_dir.wstring();
  for (auto& c : key) c = static_cast<wchar_t>(::towlower(c));
  std::uint64_t h = 1469598103934665603ull;  // FNV-1a
  for (wchar_t c : key) {
    h ^= static_cast<std::uint64_t>(c);
    h *= 1099511628211ull;
  }
  wchar_t name[64];
  std::swprintf(name, 64, L"Local\\WezCryptAegis-profile-%016llx", static_cast<unsigned long long>(h));
  HANDLE m = ::CreateMutexW(nullptr, FALSE, name);
  *first_instance = m && ::GetLastError() != ERROR_ALREADY_EXISTS;
  return m;
}

int RunBrowser(HINSTANCE instance, void* sandbox_info) {
  CefMainArgs main_args(instance);

  CefRefPtr<CefCommandLine> command_line = CefCommandLine::CreateCommandLine();
  command_line->InitFromString(::GetCommandLineW());

  // Sub-processes (renderer, GPU, utility...) run here and return.
  if (command_line->HasSwitch("type")) {
    CefRefPtr<CefApp> sub_app = new aegis::AegisApp();
    return CefExecuteProcess(main_args, sub_app, sandbox_info);
  }

  std::vector<CefString> argv;
  command_line->GetArgv(argv);
  std::vector<std::string> args;
  for (const auto& a : argv) args.push_back(a.ToString());
  auto forbidden = aegis::FindForbiddenSwitches(args);
  if (!forbidden.empty()) {
    return FailClosed(L"WezCrypt Aegis refuses to start with security-weakening options:\n\n--" +
                      aegis::Utf8ToWide(aegis::Join(forbidden, "\n--")) +
                      L"\n\nRemove these options from the shortcut or command line.");
  }

  const std::filesystem::path exe_dir = ExecutableDir();
  const std::filesystem::path root = DataRoot(exe_dir);
  const std::string profile = command_line->GetSwitchValue("profile").ToString();
  auto paths = aegis::MakeProfilePaths(root, profile);
  if (root.empty() || !paths) {
    return FailClosed(L"Invalid profile name or data directory. Profile names may contain letters, "
                      L"digits, '-' and '_' (up to 32 characters).");
  }
  aegis::storage::EnsureDirectory(paths->profile_dir);
  aegis::storage::EnsureDirectory(paths->logs_dir);

  bool first_instance = false;
  HANDLE profile_lock = AcquireProfileLock(paths->profile_dir, &first_instance);
  if (!profile_lock) {
    return FailClosed(L"WezCrypt Aegis could not lock its profile and will not start.");
  }
  int sw_dirs_removed = -1;
  if (first_instance) {
    // "Clear all site data on next start" deletes the engine profile before
    // Chromium opens it.
    std::error_code ec;
    if (std::filesystem::exists(paths->profile_dir / "clear-site-data.pending", ec)) {
      std::filesystem::remove_all(paths->engine_cache, ec);
      std::filesystem::remove(paths->profile_dir / "clear-site-data.pending", ec);
    }
    // Service workers are disabled (their requests cannot be filtered before
    // they are sent). Persistent registrations, script caches and
    // CacheStorage are deleted before the engine starts so that nothing
    // registered earlier can run; startup stops if that is not possible.
    aegis::ServiceWorkerPurgeResult purge = aegis::PurgeServiceWorkerStorage(*paths);
    if (!purge.ok) {
      ::CloseHandle(profile_lock);
      return FailClosed(L"WezCrypt Aegis could not remove stored service workers from its profile "
                        L"and will not start:\n\n" + aegis::Utf8ToWide(purge.error) +
                        L"\n\nClose other programs that may be using the profile folder and try again.");
    }
    sw_dirs_removed = purge.removed;
  }

  // The startup security mode determines process-wide engine flags.
  aegis::SettingsStore store(paths->settings_file);
  const aegis::SecurityMode startup_mode = store.Load().settings.mode;

  std::vector<std::string> urls;
  CefCommandLine::ArgumentList positional;
  command_line->GetArguments(positional);
  for (const auto& p : positional) {
    aegis::OmniboxResult r = aegis::ResolveOmniboxInput(p.ToString());
    // Command-line arguments are untrusted input: local files and searches
    // are not opened from them.
    if (!r.is_search && !r.typed_file_url) urls.push_back(r.url);
  }

  // End-to-end test hooks (see browser/test_hooks.h).
  wchar_t e2e[8] = {};
  if (::GetEnvironmentVariableW(L"AEGIS_E2E", e2e, 8) == 1 && e2e[0] == L'1') {
    aegis::TestHooks& hooks = aegis::GetTestHooks();
    std::uint64_t secs = 0;
    if (aegis::ParseUint64(command_line->GetSwitchValue("aegis-test-exit-after").ToString(), &secs) &&
        secs > 0 && secs < 3600) {
      hooks.enabled = true;
      hooks.exit_after_seconds = static_cast<int>(secs);
      hooks.report_path = command_line->GetSwitchValue("aegis-test-report").ToWString();
      hooks.service_worker_dirs_removed = sw_dirs_removed;
    }
  }

  CefRefPtr<aegis::AegisApp> app =
      new aegis::AegisApp(*paths, exe_dir / "assets", startup_mode, urls, command_line->HasSwitch("private"));

  CefSettings settings;
  settings.no_sandbox = false;
  settings.command_line_args_disabled = true;
  settings.persist_session_cookies = false;
  settings.log_severity = LOGSEVERITY_WARNING;
  settings.background_color = 0xFF121417;
  CefString(&settings.root_cache_path) = paths->profile_dir.wstring();
  CefString(&settings.cache_path) = paths->engine_cache.wstring();
  CefString(&settings.log_file) = (paths->logs_dir / L"aegis.log").wstring();
  for (const auto& [name, value] : aegis::HardeningSwitches(startup_mode)) {
    if (name == "js-flags") CefString(&settings.javascript_flags) = value;
  }

  if (!CefInitialize(main_args, settings, app.get(), sandbox_info)) {
    // Includes the process-singleton case where an existing instance was
    // asked to open a new window.
    ::CloseHandle(profile_lock);
    return CefGetExitCode();
  }
  aegis::SetSandboxRequested(true);
  CefRunMessageLoop();
  aegis::WriteTestReport();
  CefShutdown();
  aegis::AegisContext::Destroy();
  ::CloseHandle(profile_lock);
  return 0;
}

}  // namespace

// Entry point called by the CEF bootstrap executable (WezCryptAegis.exe).
CEF_BOOTSTRAP_EXPORT int RunWinMain(HINSTANCE hInstance, LPWSTR lpCmdLine, int nCmdShow,
                                    void* sandbox_info, cef_version_info_t* version_info) {
  (void)lpCmdLine;
  (void)nCmdShow;
  (void)version_info;
  if (!sandbox_info) {
    // Without the bootstrap's sandbox object no process may run web content.
    return FailClosed(L"WezCrypt Aegis must be started through WezCryptAegis.exe so that the "
                      L"Chromium sandbox is active. Starting without the sandbox is not permitted.");
  }
  return RunBrowser(hInstance, sandbox_info);
}

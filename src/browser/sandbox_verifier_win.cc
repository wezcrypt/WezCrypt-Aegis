#include "browser/sandbox_verifier_win.h"

#include <windows.h>
#include <tlhelp32.h>
#include <winternl.h>

#include <memory>

#include "common/utf8.h"

namespace aegis {
namespace {

// ProcessCommandLineInformation (Windows 8.1+), documented in winternl.h
// as a PROCESSINFOCLASS value.
constexpr int kProcessCommandLineInformation = 60;

using NtQueryInformationProcessFn = LONG(NTAPI*)(HANDLE, int, PVOID, ULONG, PULONG);

NtQueryInformationProcessFn GetNtQuery() {
  static NtQueryInformationProcessFn fn = [] {
    HMODULE ntdll = ::GetModuleHandleW(L"ntdll.dll");
    return ntdll ? reinterpret_cast<NtQueryInformationProcessFn>(
                       reinterpret_cast<void*>(::GetProcAddress(ntdll, "NtQueryInformationProcess")))
                 : nullptr;
  }();
  return fn;
}

std::wstring QueryCommandLine(HANDLE process) {
  auto fn = GetNtQuery();
  if (!fn) return {};
  ULONG len = 0;
  fn(process, kProcessCommandLineInformation, nullptr, 0, &len);
  if (len == 0 || len > 64 * 1024) return {};
  std::unique_ptr<std::uint8_t[]> buf(new std::uint8_t[len]);
  if (fn(process, kProcessCommandLineInformation, buf.get(), len, &len) < 0) return {};
  auto* us = reinterpret_cast<UNICODE_STRING*>(buf.get());
  if (!us->Buffer || us->Length == 0) return {};
  return std::wstring(us->Buffer, us->Length / sizeof(wchar_t));
}

std::string ProcessType(const std::wstring& cmd) {
  const std::wstring key = L"--type=";
  std::size_t p = cmd.find(key);
  if (p == std::wstring::npos) return "browser";
  std::size_t e = cmd.find_first_of(L" \"", p + key.size());
  return WideToUtf8(cmd.substr(p + key.size(), e == std::wstring::npos ? std::wstring::npos
                                                                      : e - p - key.size()));
}

void QueryToken(HANDLE process, ChildProcessInfo* info) {
  HANDLE token = nullptr;
  if (!::OpenProcessToken(process, TOKEN_QUERY, &token)) return;
  std::uint8_t buf[256];
  DWORD len = 0;
  if (::GetTokenInformation(token, TokenIntegrityLevel, buf, sizeof(buf), &len)) {
    auto* label = reinterpret_cast<TOKEN_MANDATORY_LABEL*>(buf);
    PSID sid = label->Label.Sid;
    if (::IsValidSid(sid)) {
      DWORD count = *::GetSidSubAuthorityCount(sid);
      if (count > 0) {
        info->integrity_rid = *::GetSidSubAuthority(sid, count - 1);
        info->token_queried = true;
      }
    }
  }
  DWORD is_app_container = 0;
  if (::GetTokenInformation(token, TokenIsAppContainer, &is_app_container, sizeof(is_app_container), &len)) {
    info->app_container = is_app_container != 0;
  }
  info->restricted_token = ::IsTokenRestricted(token) != FALSE;
  ::CloseHandle(token);
}

}  // namespace

std::string IntegrityName(std::uint32_t rid) {
  if (rid == 0xFFFFFFFF) return "unknown";
  if (rid < SECURITY_MANDATORY_LOW_RID) return "Untrusted";
  if (rid < SECURITY_MANDATORY_MEDIUM_RID) return "Low";
  if (rid < SECURITY_MANDATORY_HIGH_RID) return "Medium";
  if (rid < SECURITY_MANDATORY_SYSTEM_RID) return "High";
  return "System";
}

SandboxReport InspectChildProcesses() {
  SandboxReport report;
  const DWORD self = ::GetCurrentProcessId();
  HANDLE snap = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (snap == INVALID_HANDLE_VALUE) {
    report.summary = "process enumeration failed";
    return report;
  }
  PROCESSENTRY32W pe{};
  pe.dwSize = sizeof(pe);
  for (BOOL ok = ::Process32FirstW(snap, &pe); ok; ok = ::Process32NextW(snap, &pe)) {
    if (pe.th32ParentProcessID != self || pe.th32ProcessID == self) continue;
    ChildProcessInfo info;
    info.pid = pe.th32ProcessID;
    HANDLE h = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
    if (h) {
      info.type = ProcessType(QueryCommandLine(h));
      QueryToken(h, &info);
      ::CloseHandle(h);
    } else {
      info.type = "unknown";
    }
    report.children.push_back(info);
  }
  ::CloseHandle(snap);

  for (const auto& c : report.children) {
    if (c.type != "renderer") continue;
    ++report.renderers;
    if (!c.token_queried) {
      ++report.renderers_unknown;
    } else if (c.integrity_rid >= SECURITY_MANDATORY_MEDIUM_RID) {
      ++report.renderers_unsandboxed;
    } else {
      ++report.renderers_sandboxed;
    }
  }
  std::string detail;
  for (const auto& c : report.children) {
    detail += c.type + " (pid " + std::to_string(c.pid) + "): integrity " + IntegrityName(c.integrity_rid) +
              (c.app_container ? ", AppContainer" : "") + (c.restricted_token ? ", restricted token" : "") +
              "; ";
  }
  report.detail = detail;
  if (report.renderers_unsandboxed > 0) {
    report.summary = std::to_string(report.renderers_unsandboxed) +
                     " renderer process(es) running WITHOUT the sandbox";
  } else if (report.renderers_sandboxed > 0) {
    report.summary = std::to_string(report.renderers_sandboxed) + " of " +
                     std::to_string(report.renderers) +
                     " renderer process(es) verified at Low/Untrusted integrity";
  } else if (report.renderers == 0) {
    report.summary = "no renderer process running yet";
  } else {
    report.summary = "renderer tokens could not be inspected";
  }
  return report;
}

}  // namespace aegis

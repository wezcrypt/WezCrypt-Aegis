#include "browser/sandbox_check.h"

#include <atomic>

#include "browser/aegis_context.h"
#include "browser/sandbox_verifier_win.h"
#include "include/base/cef_callback.h"
#include "include/wrapper/cef_closure_task.h"
#include "include/wrapper/cef_helpers.h"

namespace aegis {
namespace {

std::atomic<bool> g_requested{false};
bool g_check_pending = false;
bool g_failed = false;
std::function<void(const std::string&)> g_fail_closed;

void RunCheck() {
  CEF_REQUIRE_UI_THREAD();
  g_check_pending = false;
  auto* ctx = AegisContext::Get();
  if (!ctx || g_failed) return;
  SandboxReport report = InspectChildProcesses();
  SandboxStatus st = ctx->sandbox_status();
  st.detail = report.detail;
  st.renderers_checked = report.renderers;
  if (!g_requested.load()) {
    st.state = SandboxStatus::State::kFailed;
    st.summary = "sandbox was not requested at startup";
  } else if (report.renderers_unsandboxed > 0) {
    st.state = SandboxStatus::State::kFailed;
    st.summary = report.summary;
  } else if (report.renderers_sandboxed > 0) {
    // Verified once means the sandbox policy is active for this process
    // tree; later checks keep confirming every new renderer.
    st.state = SandboxStatus::State::kVerified;
    st.summary = report.summary;
  } else if (st.state != SandboxStatus::State::kVerified) {
    st.state = SandboxStatus::State::kPending;
    st.summary = report.summary;
  }
  ctx->SetSandboxStatus(st);
  if (st.state == SandboxStatus::State::kFailed) {
    g_failed = true;
    LOG(ERROR) << "SANDBOX FAILURE: " << st.summary << " :: " << st.detail;
    if (g_fail_closed) g_fail_closed(st.summary);
  }
}

}  // namespace

void SetSandboxRequested(bool requested) { g_requested = requested; }
bool SandboxRequested() { return g_requested.load(); }

void SetFailClosedHandler(std::function<void(const std::string& reason)> handler) {
  g_fail_closed = std::move(handler);
}

void ScheduleSandboxCheck(int delay_ms) {
  if (!CefCurrentlyOn(TID_UI)) {
    CefPostTask(TID_UI, base::BindOnce(&ScheduleSandboxCheck, delay_ms));
    return;
  }
  if (g_check_pending) return;
  g_check_pending = true;
  CefPostDelayedTask(TID_UI, base::BindOnce(&RunCheck), delay_ms);
}

}  // namespace aegis

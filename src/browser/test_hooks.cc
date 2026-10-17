#include "browser/test_hooks.h"

#include "browser/aegis_context.h"
#include "browser/sandbox_check.h"
#include "browser/sandbox_verifier_win.h"
#include "include/base/cef_callback.h"
#include "include/cef_version.h"
#include "include/wrapper/cef_closure_task.h"
#include "include/wrapper/cef_helpers.h"
#include "storage/atomic_file.h"
#include "ui/browser_window.h"

namespace aegis {

TestHooks& GetTestHooks() {
  static TestHooks hooks;
  return hooks;
}

void StartTestHooks() {
  CEF_REQUIRE_UI_THREAD();
  const TestHooks& h = GetTestHooks();
  if (!h.enabled || h.exit_after_seconds <= 0) return;
  // A final sandbox inspection shortly before exit so the report reflects
  // the renderers that served the test pages.
  CefPostDelayedTask(TID_UI, base::BindOnce([]() { ScheduleSandboxCheck(0); }),
                     static_cast<int64_t>(h.exit_after_seconds) * 1000 - 1500);
  CefPostDelayedTask(TID_UI, base::BindOnce([]() { BrowserWindow::CloseAll(false); }),
                     static_cast<int64_t>(h.exit_after_seconds) * 1000);
}

void WriteTestReport() {
  const TestHooks& h = GetTestHooks();
  auto* ctx = AegisContext::Get();
  if (!h.enabled || h.report_path.empty() || !ctx) return;
  json::Object root;
  root["mode"] = std::string(SecurityModeId(ctx->settings().mode));
  root["startup_mode"] = std::string(SecurityModeId(ctx->startup_mode()));
  root["cef_version"] = CEF_VERSION;
  root["sandbox_requested"] = SandboxRequested();
  SandboxStatus sb = ctx->sandbox_status();
  json::Object sandbox;
  sandbox["state"] = sb.state == SandboxStatus::State::kVerified ? "verified"
                     : sb.state == SandboxStatus::State::kFailed ? "failed" : "pending";
  sandbox["summary"] = sb.summary;
  sandbox["detail"] = sb.detail;
  sandbox["renderers_checked"] = sb.renderers_checked;
  root["sandbox"] = json::Value(std::move(sandbox));
  json::Object counts;
  for (int i = 0; i < static_cast<int>(EventCategory::kCount); ++i) {
    auto c = static_cast<EventCategory>(i);
    counts[std::string(EventCategoryId(c))] = static_cast<std::int64_t>(ctx->events().SessionCount(c));
  }
  root["service_worker_dirs_removed"] = static_cast<std::int64_t>(h.service_worker_dirs_removed);
  root["session_counts"] = json::Value(std::move(counts));
  json::Array events;
  for (const auto& e : ctx->events().Recent(500)) {
    json::Object o;
    o["category"] = std::string(EventCategoryId(e.category));
    o["url"] = e.url;
    o["resource"] = e.resource;
    o["reason"] = e.reason;
    o["rule"] = e.rule;
    events.emplace_back(std::move(o));
  }
  root["events"] = json::Value(std::move(events));
  json::Array lists;
  for (const auto& st : ctx->filters().Status()) {
    json::Object o;
    o["id"] = st.config.id;
    o["source"] = st.source;
    o["version"] = st.stats.version;
    o["rules"] = static_cast<std::int64_t>(st.stats.network_rules + st.stats.exception_rules);
    o["enabled"] = st.config.enabled;
    lists.emplace_back(std::move(o));
  }
  root["filter_lists"] = json::Value(std::move(lists));
  std::string error;
  if (!storage::WriteFileAtomically(h.report_path, json::Serialize(json::Value(std::move(root))), false,
                                    &error)) {
    LOG(ERROR) << "could not write test report: " << error;
  }
}

}  // namespace aegis

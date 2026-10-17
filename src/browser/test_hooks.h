// WezCrypt Aegis - end-to-end test hooks.
//
// Active only when the environment variable AEGIS_E2E=1 is set *and* the
// switches below are present. They let the automated Windows test harness
// close the browser after a fixed time and collect a JSON report of real
// enforcement evidence (sandbox inspection, blocking counters). They grant
// no capability beyond what the person starting the process already has.
//
//   --aegis-test-exit-after=<seconds>
//   --aegis-test-report=<path to JSON file>
#pragma once

#include <filesystem>

namespace aegis {

struct TestHooks {
  bool enabled = false;
  int exit_after_seconds = 0;
  std::filesystem::path report_path;
};

TestHooks& GetTestHooks();

// Schedules the exit timer (UI thread, after context initialization).
void StartTestHooks();

// Writes the evidence report (called after the message loop ends, before
// CefShutdown, while AegisContext is still alive).
void WriteTestReport();

}  // namespace aegis

// WezCrypt Aegis - sandbox status tracking and fail-closed enforcement.
#pragma once

#include <functional>
#include <string>

namespace aegis {

// Records whether CEF was initialized with a sandbox_info pointer from the
// bootstrap executable. Without it the browser never starts.
void SetSandboxRequested(bool requested);
bool SandboxRequested();

// Schedules a runtime inspection of child processes (UI thread, debounced).
void ScheduleSandboxCheck(int delay_ms);

// Called when runtime evidence shows an unsandboxed renderer. Installed by
// the window layer; it closes every browser and exits.
void SetFailClosedHandler(std::function<void(const std::string& reason)> handler);

}  // namespace aegis

// WezCrypt Aegis - renderer-side API reduction.
//
// WezCrypt Aegis exposes no native functions to web pages. The only
// renderer-side code removes Web APIs whose network traffic bypasses CEF's
// pre-network request interception (verified by the Windows E2E suite):
//   * navigator.serviceWorker - service-worker script and fetch() traffic is
//     not delivered to CefResourceRequestHandler, so ad/tracker filtering
//     could be evaded from a service worker.
// The removal runs in OnContextCreated, before any page script executes.
#pragma once

#include "include/cef_render_process_handler.h"

namespace aegis {

// Script evaluated in every new V8 context. Exposed for tests.
const char* RenderHardeningScript();

class RenderHardening : public CefRenderProcessHandler {
 public:
  void OnContextCreated(CefRefPtr<CefBrowser> browser, CefRefPtr<CefFrame> frame,
                        CefRefPtr<CefV8Context> context) override;

 private:
  IMPLEMENT_REFCOUNTING(RenderHardening);
};

}  // namespace aegis

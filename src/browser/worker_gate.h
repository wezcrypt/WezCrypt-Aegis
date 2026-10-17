// WezCrypt Aegis - engine-level gate for requests without a browser.
//
// Registers a CefSchemeHandlerFactory for http and https on a request
// context. CEF consults it for every request routed through its loader
// proxy that no CefResourceRequestHandler took over, including the requests
// of service workers that run outside any CEF browser frame (which CEF 152
// never delivers to resource request handlers). See
// networking/unattributed_request_gate.h for the decision rules.
#pragma once

#include "include/cef_request_context.h"

namespace aegis {

// Registers the gate on |ctx| (nullptr = global context). Returns false if
// CEF refused the registration.
bool RegisterUnattributedRequestGate(CefRefPtr<CefRequestContext> ctx);

}  // namespace aegis

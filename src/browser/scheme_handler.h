// WezCrypt Aegis - aegis:// internal pages.
#pragma once

#include "include/cef_request_context.h"
#include "include/cef_scheme.h"

namespace aegis {

inline constexpr char kInternalScheme[] = "aegis";
// Target used to neutralize blocked redirects; served as an empty 403.
inline constexpr char kBlockedResourceUrl[] = "aegis://blocked-resource/";

// Scheme options: standard, secure, display-isolated (web pages cannot
// link, frame or fetch it), no CORS, not CSP-bypassing.
int InternalSchemeOptions();

// Registers the aegis:// handler factory for |ctx| (nullptr = global).
void RegisterInternalSchemeHandler(CefRefPtr<CefRequestContext> ctx);

}  // namespace aegis

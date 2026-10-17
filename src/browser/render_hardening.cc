#include "browser/render_hardening.h"

#include "include/cef_v8.h"

namespace aegis {

const char* RenderHardeningScript() {
  return "(function(){"
         "try{delete Navigator.prototype.serviceWorker;}catch(e){}"
         "try{Object.defineProperty(Navigator.prototype,'serviceWorker',"
         "{get:function(){return undefined;},configurable:false});}catch(e){}"
         "})();";
}

void RenderHardening::OnContextCreated(CefRefPtr<CefBrowser>, CefRefPtr<CefFrame>,
                                       CefRefPtr<CefV8Context> context) {
  CefRefPtr<CefV8Value> retval;
  CefRefPtr<CefV8Exception> exception;
  // Failures (e.g. script disabled) leave nothing to remove.
  context->Eval(RenderHardeningScript(), CefString(), 0, retval, exception);
}

}  // namespace aegis

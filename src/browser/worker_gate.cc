#include "browser/worker_gate.h"

#include <string>

#include "browser/aegis_context.h"
#include "include/base/cef_logging.h"
#include "include/cef_resource_handler.h"
#include "include/cef_scheme.h"
#include "networking/unattributed_request_gate.h"

namespace aegis {
namespace {

// Serves an empty 403 response from inside the browser process: the request
// is answered without any DNS lookup, connection or bytes sent to the host.
class DeniedRequestHandler : public CefResourceHandler {
 public:
  bool Open(CefRefPtr<CefRequest>, bool& handle_request, CefRefPtr<CefCallback>) override {
    handle_request = true;
    return true;
  }

  void GetResponseHeaders(CefRefPtr<CefResponse> response, int64_t& response_length,
                          CefString& redirect_url) override {
    (void)redirect_url;
    response->SetStatus(403);
    response->SetStatusText("Forbidden");
    response->SetMimeType("text/plain");
    CefResponse::HeaderMap headers;
    headers.emplace("Cache-Control", "no-store");
    headers.emplace("X-Content-Type-Options", "nosniff");
    response->SetHeaderMap(headers);
    response_length = 0;
  }

  bool Read(void*, int, int& bytes_read, CefRefPtr<CefResourceReadCallback>) override {
    bytes_read = 0;
    return false;
  }

  void Cancel() override {}

 private:
  IMPLEMENT_REFCOUNTING(DeniedRequestHandler);
};

class UnattributedRequestGateFactory : public CefSchemeHandlerFactory {
 public:
  CefRefPtr<CefResourceHandler> Create(CefRefPtr<CefBrowser> browser, CefRefPtr<CefFrame> frame,
                                       const CefString& scheme_name,
                                       CefRefPtr<CefRequest> request) override {
    (void)frame;
    (void)scheme_name;
    if (!request) return new DeniedRequestHandler();
    const std::string url = request->GetURL().ToString();
    UnattributedRequest req;
    req.url = url;
    req.has_browser = browser != nullptr;
    req.is_service_worker_script = request->GetResourceType() == RT_SERVICE_WORKER ||
                                   request->GetHeaderByName("Service-Worker").ToString() == "script";
    GateVerdict v = EvaluateUnattributedRequest(req, GetInternalFetchRegistry());
    switch (v.decision) {
      case GateDecision::kNotHandled:
      case GateDecision::kAllowInternal:
        return nullptr;  // default network handling
      case GateDecision::kDeny:
        break;
    }
    if (auto* ctx = AegisContext::Get()) {
      ctx->Record(EventCategory::kScript, {}, url,
                  req.is_service_worker_script ? kResourceScript : MapGateResourceType(request),
                  v.reason, {}, {}, browser ? browser->GetIdentifier() : -1);
    }
    return new DeniedRequestHandler();
  }

 private:
  static ResourceType MapGateResourceType(CefRefPtr<CefRequest> request) {
    switch (request->GetResourceType()) {
      case RT_SCRIPT:
      case RT_WORKER:
      case RT_SHARED_WORKER:
        return kResourceScript;
      case RT_IMAGE:
      case RT_FAVICON:
        return kResourceImage;
      case RT_XHR:
        return kResourceXhr;
      case RT_PING:
        return kResourcePing;
      default:
        return kResourceOther;
    }
  }

  IMPLEMENT_REFCOUNTING(UnattributedRequestGateFactory);
};

}  // namespace

bool RegisterUnattributedRequestGate(CefRefPtr<CefRequestContext> ctx) {
  CefRefPtr<CefSchemeHandlerFactory> factory = new UnattributedRequestGateFactory();
  bool all = true;
  for (const char* scheme : {"http", "https"}) {
    bool ok = ctx ? ctx->RegisterSchemeHandlerFactory(scheme, CefString(), factory)
                  : CefRegisterSchemeHandlerFactory(scheme, CefString(), factory);
    if (!ok) {
      LOG(ERROR) << "could not register the request gate for " << scheme;
      all = false;
    }
  }
  return all;
}

}  // namespace aegis

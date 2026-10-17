// WezCrypt Aegis - gate for network requests that cannot be attributed to a
// browser tab.
//
// In CEF 152 (Chromium branch 7977) requests issued by a service worker that
// runs in a renderer process without a CEF browser frame never reach
// CefResourceRequestHandler: the per-request handler lookup is keyed on the
// render process of a CEF browser and CEF 152 has no worker fallback (it was
// added upstream as CefBrowserContext::UpdateWorkerRequestContextHandler in
// later branches). Such requests would therefore bypass every filter list
// and security-mode rule.
//
// CEF still consults scheme handler factories for those requests. WezCrypt
// Aegis registers one for http/https and passes every request without an
// associated browser through this gate. The gate denies by default:
//  * service-worker script fetches are always denied, so no service worker
//    can be registered, updated or started from the network;
//  * every other unattributed request is denied unless WezCrypt Aegis itself
//    issued it (filter-list and update downloads), which is proven by an
//    exact-URL reservation made immediately before the fetch.
#pragma once

#include <cstddef>
#include <mutex>
#include <set>
#include <string>
#include <string_view>

namespace aegis {

// Thread-safe registry of in-flight fetches issued by WezCrypt Aegis itself.
// A reservation admits exactly one unattributed request for exactly that
// URL; redirects are not admitted (a redirect target is a different URL).
class InternalFetchRegistry {
 public:
  static constexpr std::size_t kMaxReservations = 64;

  // Returns false when the URL is not a valid https URL without credentials,
  // is already reserved, or the registry is full.
  bool Reserve(const std::string& url);
  // Consumes the reservation for |url|. Returns true when one existed.
  bool Consume(std::string_view url);
  // Drops an unconsumed reservation when its fetch completes (no-op when the
  // gate already consumed it).
  void Release(const std::string& url);
  std::size_t Size() const;

 private:
  mutable std::mutex mutex_;
  std::set<std::string, std::less<>> reservations_;
};

InternalFetchRegistry& GetInternalFetchRegistry();

struct UnattributedRequest {
  std::string_view url;
  bool is_service_worker_script = false;  // RT_SERVICE_WORKER or "Service-Worker: script"
  bool has_browser = false;               // request is associated with a CEF browser
};

enum class GateDecision : unsigned char {
  kNotHandled,  // request belongs to a browser; normal policy already ran
  kAllowInternal,
  kDeny,
};

struct GateVerdict {
  GateDecision decision = GateDecision::kDeny;
  std::string reason;
};

// Decides the fate of a request that reached the http/https scheme handler
// factory. |registry| is consulted (and a reservation consumed) only for
// requests without a browser that are not service-worker scripts.
GateVerdict EvaluateUnattributedRequest(const UnattributedRequest& req, InternalFetchRegistry& registry);

}  // namespace aegis

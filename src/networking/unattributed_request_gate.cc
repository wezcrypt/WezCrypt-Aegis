#include "networking/unattributed_request_gate.h"

#include "common/url.h"

namespace aegis {

bool InternalFetchRegistry::Reserve(const std::string& url) {
  auto u = ParseUrl(url);
  if (!u || u->scheme != "https" || u->has_credentials) return false;
  std::lock_guard<std::mutex> lock(mutex_);
  if (reservations_.size() >= kMaxReservations) return false;
  return reservations_.insert(url).second;
}

bool InternalFetchRegistry::Consume(std::string_view url) {
  std::lock_guard<std::mutex> lock(mutex_);
  auto it = reservations_.find(url);
  if (it == reservations_.end()) return false;
  reservations_.erase(it);
  return true;
}

void InternalFetchRegistry::Release(const std::string& url) { (void)Consume(url); }

std::size_t InternalFetchRegistry::Size() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return reservations_.size();
}

InternalFetchRegistry& GetInternalFetchRegistry() {
  static InternalFetchRegistry registry;
  return registry;
}

GateVerdict EvaluateUnattributedRequest(const UnattributedRequest& req, InternalFetchRegistry& registry) {
  GateVerdict v;
  if (req.is_service_worker_script) {
    // Checked first so that a browser-associated registration attempt is
    // denied here as well, independently of the request handler.
    v.decision = GateDecision::kDeny;
    v.reason = "service worker script blocked: service workers are disabled because their "
               "network requests cannot be filtered before they are sent";
    return v;
  }
  if (req.has_browser) {
    v.decision = GateDecision::kNotHandled;
    return v;
  }
  if (registry.Consume(req.url)) {
    v.decision = GateDecision::kAllowInternal;
    v.reason = "fetch issued by WezCrypt Aegis";
    return v;
  }
  v.decision = GateDecision::kDeny;
  v.reason = "unattributed worker request blocked: the request has no browser tab, so it "
             "cannot be checked against filter lists before it is sent";
  return v;
}

}  // namespace aegis

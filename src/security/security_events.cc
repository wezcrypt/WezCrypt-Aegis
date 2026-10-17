#include "security/security_events.h"

#include <algorithm>

#include "common/strings.h"

namespace aegis {

std::string_view EventCategoryId(EventCategory c) {
  switch (c) {
    case EventCategory::kAdvertising: return "advertising";
    case EventCategory::kTracker: return "tracker";
    case EventCategory::kScript: return "script";
    case EventCategory::kThirdPartyFrame: return "third_party_frame";
    case EventCategory::kThirdPartyRequest: return "third_party_request";
    case EventCategory::kUserRule: return "user_rule";
    case EventCategory::kPopup: return "popup";
    case EventCategory::kPermission: return "permission";
    case EventCategory::kCertificate: return "certificate";
    case EventCategory::kPrivateNetwork: return "private_network";
    case EventCategory::kUnsafeScheme: return "unsafe_scheme";
    case EventCategory::kHttpsUpgrade: return "https_upgrade";
    case EventCategory::kDownload: return "download";
    case EventCategory::kNavigation: return "navigation";
    case EventCategory::kCount: break;
  }
  return "unknown";
}

std::string_view EventCategoryLabel(EventCategory c) {
  switch (c) {
    case EventCategory::kAdvertising: return "Advertising requests blocked";
    case EventCategory::kTracker: return "Tracker requests blocked";
    case EventCategory::kScript: return "Script requests blocked";
    case EventCategory::kThirdPartyFrame: return "Third-party frames blocked";
    case EventCategory::kThirdPartyRequest: return "Other third-party requests blocked";
    case EventCategory::kUserRule: return "Blocked by user / built-in rules";
    case EventCategory::kPopup: return "Popup attempts blocked";
    case EventCategory::kPermission: return "Permission requests denied";
    case EventCategory::kCertificate: return "Certificate errors stopped";
    case EventCategory::kPrivateNetwork: return "Private-network requests blocked";
    case EventCategory::kUnsafeScheme: return "Unsafe scheme / protocol launches blocked";
    case EventCategory::kHttpsUpgrade: return "Navigations upgraded to HTTPS";
    case EventCategory::kDownload: return "Downloads cancelled or declined";
    case EventCategory::kNavigation: return "Top-level navigations stopped";
    case EventCategory::kCount: break;
  }
  return "Unknown";
}

std::int64_t NowUnixMs() {
  return std::chrono::duration_cast<std::chrono::milliseconds>(
             std::chrono::system_clock::now().time_since_epoch())
      .count();
}

std::uint64_t SiteCounters::total() const {
  std::uint64_t t = 0;
  for (int i = 0; i < static_cast<int>(EventCategory::kCount); ++i) {
    if (i == static_cast<int>(EventCategory::kHttpsUpgrade)) continue;
    t += counts[static_cast<std::size_t>(i)];
  }
  return t;
}

SecurityEventLog::SecurityEventLog(std::size_t capacity) : capacity_(capacity) {}

void SecurityEventLog::Record(SecurityEvent event) {
  const auto idx = static_cast<std::size_t>(event.category);
  if (idx >= session_.size()) return;
  session_[idx].fetch_add(1, std::memory_order_relaxed);
  lifetime_[idx].fetch_add(1, std::memory_order_relaxed);
  if (event.unix_ms == 0) event.unix_ms = NowUnixMs();
  event.url = SanitizeForLog(event.url, 300);
  event.reason = SanitizeForLog(event.reason, 300);
  event.rule = SanitizeForLog(event.rule, 300);
  event.site = SanitizeForLog(event.site, 253);
  std::lock_guard<std::mutex> lock(mutex_);
  if (!event.site.empty()) {
    if (per_site_.size() < 20000 || per_site_.count(event.site)) {
      per_site_[event.site].counts[idx]++;
    }
  }
  recent_.push_back(std::move(event));
  while (recent_.size() > capacity_) recent_.pop_front();
}

std::uint64_t SecurityEventLog::SessionCount(EventCategory c) const {
  return session_[static_cast<std::size_t>(c)].load(std::memory_order_relaxed);
}

std::uint64_t SecurityEventLog::LifetimeCount(EventCategory c) const {
  return lifetime_[static_cast<std::size_t>(c)].load(std::memory_order_relaxed);
}

SiteCounters SecurityEventLog::ForSite(const std::string& site) const {
  std::lock_guard<std::mutex> lock(mutex_);
  auto it = per_site_.find(site);
  return it == per_site_.end() ? SiteCounters{} : it->second;
}

std::vector<SecurityEvent> SecurityEventLog::Recent(std::size_t max,
                                                    const std::string& site_filter) const {
  std::lock_guard<std::mutex> lock(mutex_);
  std::vector<SecurityEvent> out;
  for (auto it = recent_.rbegin(); it != recent_.rend() && out.size() < max; ++it) {
    if (!site_filter.empty() && it->site != site_filter) continue;
    out.push_back(*it);
  }
  return out;
}

std::vector<std::pair<std::string, std::uint64_t>> SecurityEventLog::TopSites(
    std::size_t max) const {
  std::lock_guard<std::mutex> lock(mutex_);
  std::vector<std::pair<std::string, std::uint64_t>> v;
  for (const auto& [site, c] : per_site_) v.emplace_back(site, c.total());
  std::sort(v.begin(), v.end(), [](const auto& a, const auto& b) {
    return a.second != b.second ? a.second > b.second : a.first < b.first;
  });
  if (v.size() > max) v.resize(max);
  return v;
}

void SecurityEventLog::RecordForTab(int browser_id, EventCategory c) {
  if (c == EventCategory::kHttpsUpgrade) return;
  std::lock_guard<std::mutex> lock(mutex_);
  per_tab_[browser_id]++;
}

std::uint64_t SecurityEventLog::TabBlockedCount(int browser_id) const {
  std::lock_guard<std::mutex> lock(mutex_);
  auto it = per_tab_.find(browser_id);
  return it == per_tab_.end() ? 0 : it->second;
}

void SecurityEventLog::ResetTab(int browser_id) {
  std::lock_guard<std::mutex> lock(mutex_);
  per_tab_.erase(browser_id);
}

json::Value SecurityEventLog::LifetimeToJson() const {
  json::Object o;
  for (int i = 0; i < static_cast<int>(EventCategory::kCount); ++i) {
    o[std::string(EventCategoryId(static_cast<EventCategory>(i)))] =
        static_cast<std::int64_t>(lifetime_[static_cast<std::size_t>(i)].load());
  }
  return json::Value(std::move(o));
}

void SecurityEventLog::LoadLifetime(const json::Value& v) {
  for (int i = 0; i < static_cast<int>(EventCategory::kCount); ++i) {
    std::int64_t n = v.GetInt(EventCategoryId(static_cast<EventCategory>(i)), 0);
    if (n > 0) lifetime_[static_cast<std::size_t>(i)].store(static_cast<std::uint64_t>(n));
  }
}

}  // namespace aegis

// WezCrypt Aegis - security event accounting.
//
// Every counter shown in the Security Control Center is incremented here,
// and only from real enforcement decisions made by the request, navigation,
// popup, permission, certificate and download handlers. Nothing is
// estimated or synthesized. Counters describe what was *blocked or denied*;
// they do not claim that a blocked item was malicious.
#pragma once

#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <deque>
#include <map>
#include <mutex>
#include <string>
#include <vector>

#include "common/json.h"

namespace aegis {

enum class EventCategory : int {
  kAdvertising = 0,     // blocked by an advertising filter list
  kTracker,             // blocked by a tracking-protection list
  kScript,              // script blocked by security-mode policy
  kThirdPartyFrame,     // third-party iframe blocked by mode policy
  kThirdPartyRequest,   // other third-party request blocked by mode policy
  kUserRule,            // blocked by a user-defined or built-in rule
  kPopup,               // popup / new window blocked
  kPermission,          // permission request denied
  kCertificate,         // navigation stopped on certificate error
  kPrivateNetwork,      // public page -> private network request blocked
  kUnsafeScheme,        // file://, dangerous scheme or external protocol
  kHttpsUpgrade,        // navigation upgraded to HTTPS (not a block)
  kDownload,            // download cancelled or warned
  kNavigation,          // top-level navigation stopped by filter or policy
  kCount
};

std::string_view EventCategoryId(EventCategory c);
std::string_view EventCategoryLabel(EventCategory c);

struct SecurityEvent {
  std::int64_t unix_ms = 0;
  EventCategory category = EventCategory::kAdvertising;
  std::string site;        // top-level site (registrable domain)
  std::string url;         // sanitized, truncated request URL
  std::string resource;    // resource type name
  std::string reason;      // human-readable explanation
  std::string rule;        // matching filter rule text, if any
  std::string list;        // list id, if any
};

struct SiteCounters {
  std::array<std::uint64_t, static_cast<int>(EventCategory::kCount)> counts{};
  std::uint64_t total() const;
};

class SecurityEventLog {
 public:
  explicit SecurityEventLog(std::size_t capacity = 2000);

  // Thread-safe. Called from the network (IO) and UI threads.
  void Record(SecurityEvent event);

  std::uint64_t SessionCount(EventCategory c) const;
  std::uint64_t LifetimeCount(EventCategory c) const;
  SiteCounters ForSite(const std::string& site) const;
  std::vector<SecurityEvent> Recent(std::size_t max, const std::string& site_filter = {}) const;
  std::vector<std::pair<std::string, std::uint64_t>> TopSites(std::size_t max) const;

  // Per-tab counters keyed by an opaque browser id.
  void RecordForTab(int browser_id, EventCategory c);
  std::uint64_t TabBlockedCount(int browser_id) const;
  void ResetTab(int browser_id);

  // Lifetime totals persist across restarts (counts only, no URLs).
  json::Value LifetimeToJson() const;
  void LoadLifetime(const json::Value& v);

 private:
  const std::size_t capacity_;
  std::array<std::atomic<std::uint64_t>, static_cast<int>(EventCategory::kCount)> session_{};
  std::array<std::atomic<std::uint64_t>, static_cast<int>(EventCategory::kCount)> lifetime_{};
  mutable std::mutex mutex_;
  std::deque<SecurityEvent> recent_;
  std::map<std::string, SiteCounters> per_site_;
  std::map<int, std::uint64_t> per_tab_;
};

std::int64_t NowUnixMs();

}  // namespace aegis

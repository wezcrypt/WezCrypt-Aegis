// WezCrypt Aegis - internal pages (aegis://...).
//
// Internal pages are rendered as static HTML in the browser process from
// real engine state. They contain no JavaScript, are served with a strict
// Content-Security-Policy, and the aegis scheme is registered as
// display-isolated so ordinary web pages cannot frame, fetch or link to
// them. They expose no privileged bridge to page content.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "security/security_events.h"
#include "security/security_mode.h"
#include "storage/browsing_data.h"

namespace aegis::pages {

// Content-Security-Policy applied to every internal page.
std::string_view InternalPageCsp();

struct FilterListRow {
  std::string name;
  std::string version;
  std::string source;
  std::string updated;
  std::string status;
  std::string license;
  std::size_t rules = 0;
  std::size_t cosmetic_skipped = 0;
  std::size_t unsupported = 0;
  bool enabled = true;
};

struct PermissionRow {
  std::string origin;
  std::string permissions;
};

struct ExceptionRow {
  std::string site;
  std::string details;
};

struct DashboardData {
  SecurityMode mode = kDefaultSecurityMode;
  std::string app_version;
  std::string cef_version;
  std::string chromium_version;
  std::string sandbox_status;       // e.g. "Verified: 3 renderer processes at Untrusted integrity"
  bool sandbox_ok = false;
  std::string sandbox_detail;
  std::string update_status;
  bool update_warning = false;
  std::string site_isolation;
  std::string wasm_status;
  std::string javascript_status;
  std::vector<std::pair<std::string, std::uint64_t>> session_counts;   // label, count
  std::vector<std::pair<std::string, std::uint64_t>> lifetime_counts;  // label, count
  std::vector<FilterListRow> lists;
  std::vector<PermissionRow> permissions;
  std::vector<ExceptionRow> exceptions;
  std::vector<std::pair<std::string, std::uint64_t>> top_sites;
  std::vector<std::string> notices;  // e.g. settings recovered from backup
  bool private_window = false;
};

struct SiteReportData {
  std::string site;
  std::string display_host;
  bool idn_spoof_risk = false;
  std::string url;
  bool secure_connection = false;
  std::string certificate_summary;
  SecurityMode mode = kDefaultSecurityMode;
  bool javascript_allowed = false;
  bool js_optimizer_allowed = false;
  std::string exception_summary;
  std::string permissions;
  std::vector<std::pair<std::string, std::uint64_t>> counts;
  std::vector<SecurityEvent> events;
};

struct DownloadRow {
  std::string filename;
  std::string url;
  std::string state;
  std::string risk;
  std::string path;
  int percent = -1;
};

std::string NewTabPage(SecurityMode mode, std::uint64_t session_blocked, bool private_window);
std::string DashboardPage(const DashboardData& d);
std::string SiteReportPage(const SiteReportData& d);
std::string NetworkActivityPage(const std::vector<SecurityEvent>& events, std::size_t total_shown);
std::string HistoryPage(const std::vector<HistoryEntry>& entries, const std::string& query,
                        bool history_enabled);
std::string BookmarksPage(const std::vector<Bookmark>& bookmarks);
std::string DownloadsPage(const std::vector<DownloadRow>& rows, const std::string& directory);
std::string BlockedNavigationPage(const std::string& url, const std::string& reason,
                                  const std::string& rule, const std::string& list);
std::string CertificateErrorPage(const std::string& url, const std::string& error_name,
                                 int error_code);
std::string HttpsFallbackPage(const std::string& https_url, const std::string& http_url,
                              const std::string& continue_link, const std::string& error_name);
std::string LoadErrorPage(const std::string& url, const std::string& error_name, int error_code);
std::string AboutPage(const std::string& app_version, const std::string& cef_version,
                      const std::string& chromium_version,
                      const std::vector<std::pair<std::string, std::string>>& licenses);
std::string NotFoundPage(const std::string& url);

}  // namespace aegis::pages

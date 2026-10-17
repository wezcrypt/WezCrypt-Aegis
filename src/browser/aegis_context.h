// WezCrypt Aegis - browser-process state shared by all windows.
//
// Threading:
//  * Settings are owned by the UI thread. Every mutation goes through
//    UpdateSettings(), which persists the change and publishes a new
//    immutable PolicySnapshot.
//  * The network (IO) thread only ever reads the current PolicySnapshot
//    through policy(), which is a lock-protected shared_ptr copy.
#pragma once

#include <atomic>
#include <filesystem>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

#include "downloads/download_safety.h"
#include "filtering/filter_list_manager.h"
#include "include/cef_request_context.h"
#include "include/cef_request_context_handler.h"
#include "privacy/profile.h"
#include "security/security_events.h"
#include "security/security_policy.h"
#include "storage/browsing_data.h"
#include "storage/settings_store.h"
#include "ui/internal_pages.h"
#include "updates/update_verifier.h"

namespace aegis {

struct SandboxStatus {
  enum class State { kPending, kVerified, kFailed };
  State state = State::kPending;
  std::string summary;
  std::string detail;
  int renderers_checked = 0;
};

struct UpdateStatus {
  std::string text = "not yet checked";
  bool warning = false;
  std::int64_t checked_unix_ms = 0;
  std::optional<UpdateManifest> manifest;
};

struct DownloadRecord {
  std::uint32_t id = 0;
  std::string filename;
  std::string url;
  std::string referrer;
  std::string path;
  std::string state = "awaiting confirmation";
  FileRisk risk = FileRisk::kElevated;
  int percent = -1;
  bool motw_applied = false;
};

class AegisContext {
 public:
  // Creates the singleton. Returns nullptr (and fills |error|) if a required
  // asset such as the Public Suffix List cannot be loaded; the browser then
  // refuses to start rather than running without site-boundary logic.
  static AegisContext* Create(const ProfilePaths& paths,
                              const std::filesystem::path& assets_dir, std::string* error);
  static AegisContext* Get();
  static void Destroy();

  // Thread-safe.
  std::shared_ptr<const PolicySnapshot> policy() const;
  SecurityEventLog& events() { return events_; }
  FilterListManager& filters() { return *filters_; }
  const PublicSuffixList& psl() const { return *psl_; }
  std::shared_ptr<const PublicSuffixList> psl_ptr() const { return psl_; }

  // UI thread only.
  const Settings& settings() const { return settings_; }
  SecurityMode startup_mode() const { return startup_mode_; }
  void UpdateSettings(const std::function<void(Settings&)>& mutate);
  void RebuildPolicy();  // after filter changes
  const std::vector<std::string>& load_notices() const { return load_notices_; }

  // Records an enforcement event (any thread).
  void Record(EventCategory category, const std::string& site, const std::string& url,
              ResourceType type, const std::string& reason, const std::string& rule = {},
              const std::string& list = {}, int browser_id = -1);

  HistoryStore& history() { return history_; }
  BookmarkStore& bookmarks() { return bookmarks_; }
  const ProfilePaths& paths() const { return paths_; }
  const std::filesystem::path& assets_dir() const { return assets_dir_; }

  // Request contexts. The normal context persists to the profile directory;
  // private contexts are in-memory and discarded on close.
  void SetNormalRequestContext(CefRefPtr<CefRequestContext> ctx) { normal_context_ = ctx; }
  void SetRequestContextHandler(CefRefPtr<CefRequestContextHandler> h) { context_handler_ = h; }
  CefRefPtr<CefRequestContext> normal_request_context() const { return normal_context_; }
  CefRefPtr<CefRequestContext> CreatePrivateRequestContext();
  void ReleasePrivateRequestContext(CefRefPtr<CefRequestContext> ctx);
  bool IsPrivateContext(CefRefPtr<CefRequestContext> ctx) const;
  // Applies engine-level preferences and default content settings for the
  // active mode to every live request context.
  void ApplyEnginePolicyToAllContexts();
  void ApplyEnginePolicy(CefRefPtr<CefRequestContext> ctx);
  // Sets the per-origin JavaScript content settings before a frame loads.
  void ApplyFramePolicy(CefRefPtr<CefRequestContext> ctx, const std::string& frame_url,
                        const std::string& top_level_url);

  // Sandbox verification state (UI thread writes, any thread reads).
  SandboxStatus sandbox_status() const;
  void SetSandboxStatus(const SandboxStatus& s);

  UpdateStatus update_status() const;
  void SetUpdateStatus(const UpdateStatus& s);

  // Downloads (UI thread).
  DownloadRecord& UpsertDownload(std::uint32_t id);
  std::vector<DownloadRecord> Downloads() const;
  std::filesystem::path DefaultDownloadDirectory() const;

  // One-time tokens for internal-page actions (HTTPS fallback consent).
  std::string IssueActionToken(const std::string& payload);
  bool ConsumeActionToken(const std::string& token, std::string* payload);

  void SaveStatistics();
  // Persists stores and applies clear-on-exit settings, then runs |done|
  // on the UI thread once asynchronous deletions have completed.
  void Shutdown(std::function<void()> done);

  pages::DashboardData BuildDashboard(bool private_window) const;
  pages::SiteReportData BuildSiteReport(const std::string& url, bool private_window) const;

 private:
  AegisContext(const ProfilePaths& paths, std::filesystem::path assets_dir);
  bool Init(std::string* error);
  void PublishPolicy();

  ProfilePaths paths_;
  std::filesystem::path assets_dir_;
  SettingsStore store_;
  Settings settings_;
  SecurityMode startup_mode_ = kDefaultSecurityMode;
  std::vector<std::string> load_notices_;
  std::shared_ptr<const PublicSuffixList> psl_;
  std::unique_ptr<FilterListManager> filters_;
  SecurityEventLog events_;
  HistoryStore history_;
  BookmarkStore bookmarks_;

  mutable std::mutex policy_mutex_;
  std::shared_ptr<const PolicySnapshot> policy_;

  mutable std::mutex status_mutex_;
  SandboxStatus sandbox_;
  UpdateStatus update_;

  CefRefPtr<CefRequestContext> normal_context_;
  CefRefPtr<CefRequestContextHandler> context_handler_;
  // Read from the IO thread (internal page factory), modified on the UI thread.
  mutable std::mutex contexts_mutex_;
  std::vector<CefRefPtr<CefRequestContext>> private_contexts_;
  std::map<std::uint32_t, DownloadRecord> downloads_;

  std::mutex token_mutex_;
  std::map<std::string, std::string> action_tokens_;
};

}  // namespace aegis

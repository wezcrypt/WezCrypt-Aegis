#include "browser/aegis_context.h"

#include <random>

#include <shlobj.h>
#include <windows.h>

#include "aegis_build_info.h"
#include "common/base64.h"
#include "common/idna.h"
#include "common/strings.h"
#include "common/utf8.h"
#include "include/base/cef_callback.h"
#include "include/cef_cookie.h"
#include "include/cef_values.h"
#include "include/wrapper/cef_closure_task.h"
#include "include/cef_version.h"
#include "include/wrapper/cef_helpers.h"
#include "permissions/permission_policy.h"
#include "storage/atomic_file.h"

namespace aegis {
namespace {

AegisContext* g_context = nullptr;

std::string Iso(std::int64_t unix_ms) {
  if (unix_ms <= 0) return "-";
  std::time_t t = static_cast<std::time_t>(unix_ms / 1000);
  std::tm tm{};
  gmtime_s(&tm, &t);
  char buf[32];
  std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M UTC", &tm);
  return buf;
}

void SetPref(CefRefPtr<CefRequestContext> ctx, const char* name, CefRefPtr<CefValue> value) {
  if (!ctx->HasPreference(name) || !ctx->CanSetPreference(name)) {
    LOG(WARNING) << "preference unavailable: " << name;
    return;
  }
  CefString error;
  if (!ctx->SetPreference(name, value, error)) {
    LOG(WARNING) << "preference " << name << " rejected: " << error.ToString();
  }
}

CefRefPtr<CefValue> IntValue(int v) {
  auto value = CefValue::Create();
  value->SetInt(v);
  return value;
}
CefRefPtr<CefValue> BoolValue(bool v) {
  auto value = CefValue::Create();
  value->SetBool(v);
  return value;
}
CefRefPtr<CefValue> StringValue(std::string_view v) {
  auto value = CefValue::Create();
  value->SetString(std::string(v));
  return value;
}

std::string ChromiumVersion() {
  return std::to_string(CHROME_VERSION_MAJOR) + "." + std::to_string(CHROME_VERSION_MINOR) + "." +
         std::to_string(CHROME_VERSION_BUILD) + "." + std::to_string(CHROME_VERSION_PATCH);
}

}  // namespace

AegisContext* AegisContext::Create(const ProfilePaths& paths,
                                   const std::filesystem::path& assets_dir, std::string* error) {
  if (g_context) return g_context;
  auto* ctx = new AegisContext(paths, assets_dir);
  if (!ctx->Init(error)) {
    delete ctx;
    return nullptr;
  }
  g_context = ctx;
  return g_context;
}

AegisContext* AegisContext::Get() { return g_context; }

void AegisContext::Destroy() {
  delete g_context;
  g_context = nullptr;
}

AegisContext::AegisContext(const ProfilePaths& paths, std::filesystem::path assets_dir)
    : paths_(paths),
      assets_dir_(std::move(assets_dir)),
      store_(paths.settings_file),
      history_(paths.history_file),
      bookmarks_(paths.bookmarks_file) {}

bool AegisContext::Init(std::string* error) {
  storage::EnsureDirectory(paths_.profile_dir);
  storage::EnsureDirectory(paths_.filter_cache_dir);

  SettingsLoadResult loaded = store_.Load();
  settings_ = loaded.settings;
  startup_mode_ = settings_.mode;
  if (loaded.source == SettingsSource::kBackup) {
    load_notices_.push_back("Settings were restored from the backup copy because the main "
                            "settings file was damaged.");
  } else if (loaded.source == SettingsSource::kDefaults && loaded.primary_was_corrupt) {
    load_notices_.push_back("Settings could not be read and secure defaults (Maximum Isolation) "
                            "were applied.");
  }
  for (const auto& w : loaded.warnings) LOG(WARNING) << "settings: " << w;
  if (loaded.source != SettingsSource::kPrimary) store_.Save(settings_);

  auto psl_file = storage::ReadFile(assets_dir_ / "data" / "public_suffix_list.dat", 8 << 20);
  auto psl = std::make_shared<PublicSuffixList>();
  if (psl_file.status != storage::ReadStatus::kOk || !psl->Load(psl_file.data)) {
    if (error) *error = "The Public Suffix List (assets\\data\\public_suffix_list.dat) is missing or invalid.";
    return false;
  }
  psl_ = psl;

  filters_ = std::make_unique<FilterListManager>(assets_dir_ / "filters", paths_.filter_cache_dir, psl_);
  auto lists = FilterListManager::DefaultLists();
  for (auto& l : lists) {
    auto it = settings_.filter_lists_enabled.find(l.id);
    if (it != settings_.filter_lists_enabled.end()) l.enabled = it->second;
  }
  if (!filters_->Initialize(lists, settings_.user_rules)) {
    if (error) *error = "No filter list could be loaded from assets\\filters.";
    return false;
  }

  if (auto stats = storage::ReadFile(paths_.stats_file, 1 << 20);
      stats.status == storage::ReadStatus::kOk) {
    if (auto v = json::Parse(stats.data)) events_.LoadLifetime(*v);
  }
  history_.Load();
  bookmarks_.Load();
  PublishPolicy();
  return true;
}

void AegisContext::PublishPolicy() {
  auto snapshot = PolicySnapshot::Create(settings_, filters_->engine(), psl_);
  std::lock_guard<std::mutex> lock(policy_mutex_);
  policy_ = std::move(snapshot);
}

std::shared_ptr<const PolicySnapshot> AegisContext::policy() const {
  std::lock_guard<std::mutex> lock(policy_mutex_);
  return policy_;
}

void AegisContext::UpdateSettings(const std::function<void(Settings&)>& mutate) {
  CEF_REQUIRE_UI_THREAD();
  Settings next = settings_;
  mutate(next);
  if (next == settings_) return;
  const bool rules_changed = next.user_rules != settings_.user_rules;
  const bool lists_changed = next.filter_lists_enabled != settings_.filter_lists_enabled;
  settings_ = std::move(next);
  std::string err;
  if (!store_.Save(settings_, &err)) LOG(ERROR) << "settings save failed: " << err;
  if (rules_changed) filters_->SetUserRules(settings_.user_rules);
  if (lists_changed) {
    for (const auto& [id, en] : settings_.filter_lists_enabled) filters_->SetListEnabled(id, en);
  }
  PublishPolicy();
  ApplyEnginePolicyToAllContexts();
}

void AegisContext::RebuildPolicy() { PublishPolicy(); }

void AegisContext::Record(EventCategory category, const std::string& site, const std::string& url,
                          ResourceType type, const std::string& reason, const std::string& rule,
                          const std::string& list, int browser_id) {
  SecurityEvent e;
  e.category = category;
  e.site = site;
  e.url = url;
  e.resource = std::string(ResourceTypeName(type));
  e.reason = reason;
  e.rule = rule;
  e.list = list;
  events_.Record(std::move(e));
  if (browser_id >= 0) events_.RecordForTab(browser_id, category);
}

CefRefPtr<CefRequestContext> AegisContext::CreatePrivateRequestContext() {
  CEF_REQUIRE_UI_THREAD();
  CefRequestContextSettings s;
  // An empty cache_path creates an in-memory ("incognito") context: cookies,
  // storage and cache never touch the disk and vanish with the context.
  s.persist_session_cookies = false;
  auto ctx = CefRequestContext::CreateContext(s, context_handler_);
  std::lock_guard<std::mutex> lock(contexts_mutex_);
  private_contexts_.push_back(ctx);
  return ctx;
}

void AegisContext::ReleasePrivateRequestContext(CefRefPtr<CefRequestContext> ctx) {
  CEF_REQUIRE_UI_THREAD();
  std::lock_guard<std::mutex> lock(contexts_mutex_);
  for (auto it = private_contexts_.begin(); it != private_contexts_.end(); ++it) {
    if ((*it)->IsSame(ctx)) {
      (*it)->ClearHttpCache(nullptr);
      if (auto cm = (*it)->GetCookieManager(nullptr)) cm->DeleteCookies("", "", nullptr);
      private_contexts_.erase(it);
      return;
    }
  }
}

bool AegisContext::IsPrivateContext(CefRefPtr<CefRequestContext> ctx) const {
  if (!ctx) return false;
  std::lock_guard<std::mutex> lock(contexts_mutex_);
  for (const auto& p : private_contexts_) {
    if (p->IsSame(ctx)) return true;
  }
  return false;
}

void AegisContext::ApplyEnginePolicyToAllContexts() {
  CEF_REQUIRE_UI_THREAD();
  if (normal_context_) ApplyEnginePolicy(normal_context_);
  std::vector<CefRefPtr<CefRequestContext>> privates;
  {
    std::lock_guard<std::mutex> lock(contexts_mutex_);
    privates = private_contexts_;
  }
  for (auto& p : privates) ApplyEnginePolicy(p);
}

void AegisContext::ApplyEnginePolicy(CefRefPtr<CefRequestContext> ctx) {
  CEF_REQUIRE_UI_THREAD();
  const SecurityMode mode = settings_.mode;
  const bool max_iso = mode == SecurityMode::kMaximumIsolation;
  // Default content settings. Defaults cannot be changed for in-memory
  // contexts; there the per-origin values set in ApplyFramePolicy() apply.
  auto set_default = [&](cef_content_setting_types_t type, cef_content_setting_values_t value) {
    ctx->SetContentSetting(CefString(), CefString(), type, value);
  };
  set_default(CEF_CONTENT_SETTING_TYPE_JAVASCRIPT,
              max_iso ? CEF_CONTENT_SETTING_VALUE_BLOCK : CEF_CONTENT_SETTING_VALUE_ALLOW);
  set_default(CEF_CONTENT_SETTING_TYPE_JAVASCRIPT_OPTIMIZER,
              mode == SecurityMode::kCompatibility ? CEF_CONTENT_SETTING_VALUE_ALLOW
                                                   : CEF_CONTENT_SETTING_VALUE_BLOCK);
  set_default(CEF_CONTENT_SETTING_TYPE_POPUPS, CEF_CONTENT_SETTING_VALUE_BLOCK);
  set_default(CEF_CONTENT_SETTING_TYPE_AUTOMATIC_DOWNLOADS, CEF_CONTENT_SETTING_VALUE_BLOCK);
  set_default(CEF_CONTENT_SETTING_TYPE_MIXEDSCRIPT, CEF_CONTENT_SETTING_VALUE_BLOCK);
  set_default(CEF_CONTENT_SETTING_TYPE_PROTOCOL_HANDLERS, CEF_CONTENT_SETTING_VALUE_BLOCK);
  set_default(CEF_CONTENT_SETTING_TYPE_SENSORS, CEF_CONTENT_SETTING_VALUE_BLOCK);
  const auto prompt = max_iso ? CEF_CONTENT_SETTING_VALUE_BLOCK : CEF_CONTENT_SETTING_VALUE_ASK;
  set_default(CEF_CONTENT_SETTING_TYPE_GEOLOCATION, prompt);
  set_default(CEF_CONTENT_SETTING_TYPE_NOTIFICATIONS, prompt);
  set_default(CEF_CONTENT_SETTING_TYPE_CLIPBOARD_READ_WRITE, prompt);

  // Engine preferences (Chromium pref names). Unavailable preferences are
  // logged; WezCrypt-level enforcement covers the same ground.
  if (settings_.block_third_party_cookies) {
    SetPref(ctx, "profile.cookie_controls_mode", IntValue(1));  // kBlockThirdParty
  }
  SetPref(ctx, "webrtc.ip_handling_policy", StringValue(WebRtcIpPolicyId(settings_.webrtc_ip_policy)));
  SetPref(ctx, "net.network_prediction_options", IntValue(2));  // never prefetch/preconnect
  SetPref(ctx, "credentials_enable_service", BoolValue(false));
  SetPref(ctx, "autofill.profile_enabled", BoolValue(false));
  SetPref(ctx, "autofill.credit_card_enabled", BoolValue(false));
  SetPref(ctx, "search.suggest_enabled", BoolValue(false));
  SetPref(ctx, "translate.enabled", BoolValue(false));
  SetPref(ctx, "alternate_error_pages.enabled", BoolValue(false));
  SetPref(ctx, "download.prompt_for_download", BoolValue(true));
}

void AegisContext::ApplyFramePolicy(CefRefPtr<CefRequestContext> ctx, const std::string& frame_url,
                                    const std::string& top_level_url) {
  CEF_REQUIRE_UI_THREAD();
  auto frame = ParseUrl(frame_url);
  if (!frame || !(frame->IsHttpLike() || frame->scheme == "file" || frame->scheme == "aegis")) return;
  auto p = policy();
  const std::string& top = top_level_url.empty() ? frame_url : top_level_url;
  const bool js = IsJavaScriptAllowed(*p, frame_url) && IsJavaScriptAllowed(*p, top);
  const bool jit = IsJavaScriptOptimizerAllowed(*p, frame_url);
  ctx->SetContentSetting(frame_url, top, CEF_CONTENT_SETTING_TYPE_JAVASCRIPT,
                         js ? CEF_CONTENT_SETTING_VALUE_ALLOW : CEF_CONTENT_SETTING_VALUE_BLOCK);
  ctx->SetContentSetting(frame_url, top, CEF_CONTENT_SETTING_TYPE_JAVASCRIPT_OPTIMIZER,
                         jit ? CEF_CONTENT_SETTING_VALUE_ALLOW : CEF_CONTENT_SETTING_VALUE_BLOCK);
}

SandboxStatus AegisContext::sandbox_status() const {
  std::lock_guard<std::mutex> lock(status_mutex_);
  return sandbox_;
}

void AegisContext::SetSandboxStatus(const SandboxStatus& s) {
  std::lock_guard<std::mutex> lock(status_mutex_);
  sandbox_ = s;
}

UpdateStatus AegisContext::update_status() const {
  std::lock_guard<std::mutex> lock(status_mutex_);
  return update_;
}

void AegisContext::SetUpdateStatus(const UpdateStatus& s) {
  std::lock_guard<std::mutex> lock(status_mutex_);
  update_ = s;
}

DownloadRecord& AegisContext::UpsertDownload(std::uint32_t id) {
  CEF_REQUIRE_UI_THREAD();
  DownloadRecord& r = downloads_[id];
  r.id = id;
  return r;
}

std::vector<DownloadRecord> AegisContext::Downloads() const {
  std::vector<DownloadRecord> out;
  for (const auto& [id, r] : downloads_) out.push_back(r);
  return out;
}

std::filesystem::path AegisContext::DefaultDownloadDirectory() const {
  PWSTR raw = nullptr;
  std::filesystem::path dir;
  if (SUCCEEDED(::SHGetKnownFolderPath(FOLDERID_Downloads, KF_FLAG_DEFAULT, nullptr, &raw)) && raw) {
    dir = std::filesystem::path(raw);
  }
  if (raw) ::CoTaskMemFree(raw);
  if (dir.empty()) dir = paths_.root / "Downloads";
  return dir;
}

std::string AegisContext::IssueActionToken(const std::string& payload) {
  std::random_device rd;
  std::uint8_t bytes[24];
  for (auto& b : bytes) b = static_cast<std::uint8_t>(rd());
  std::string token = HexEncode(bytes, sizeof(bytes));
  std::lock_guard<std::mutex> lock(token_mutex_);
  if (action_tokens_.size() > 256) action_tokens_.clear();
  action_tokens_[token] = payload;
  return token;
}

bool AegisContext::ConsumeActionToken(const std::string& token, std::string* payload) {
  std::lock_guard<std::mutex> lock(token_mutex_);
  auto it = action_tokens_.find(token);
  if (it == action_tokens_.end()) return false;
  *payload = it->second;
  action_tokens_.erase(it);
  return true;
}

void AegisContext::SaveStatistics() {
  storage::WriteFileAtomically(paths_.stats_file, json::Serialize(events_.LifetimeToJson()), false);
}

namespace {

class FlushThenDone : public CefCompletionCallback {
 public:
  explicit FlushThenDone(std::function<void()> done) : done_(std::move(done)) {}
  void OnComplete() override {
    if (done_) {
      auto d = std::move(done_);
      done_ = nullptr;
      d();
    }
  }

 private:
  std::function<void()> done_;
  IMPLEMENT_REFCOUNTING(FlushThenDone);
};

class DeleteThenFlush : public CefDeleteCookiesCallback {
 public:
  DeleteThenFlush(CefRefPtr<CefCookieManager> cm, std::function<void()> done)
      : cm_(cm), done_(std::move(done)) {}
  void OnComplete(int num_deleted) override {
    LOG(INFO) << "clear-on-exit removed " << num_deleted << " cookies";
    cm_->FlushStore(new FlushThenDone(std::move(done_)));
  }

 private:
  CefRefPtr<CefCookieManager> cm_;
  std::function<void()> done_;
  IMPLEMENT_REFCOUNTING(DeleteThenFlush);
};

}  // namespace

void AegisContext::Shutdown(std::function<void()> done) {
  CEF_REQUIRE_UI_THREAD();
  SaveStatistics();
  if (settings_.clear_history_on_exit) {
    history_.Clear();
  } else if (settings_.save_history) {
    history_.Save();
  }
  bookmarks_.Save();
  store_.Save(settings_);
  // The completion callbacks run on the UI thread; |done| is posted there.
  auto finish = [done]() { CefPostTask(TID_UI, base::BindOnce([](std::function<void()> d) { d(); }, done)); };
  if (normal_context_ && settings_.clear_cache_on_exit) normal_context_->ClearHttpCache(nullptr);
  if (normal_context_ && settings_.clear_cookies_on_exit) {
    if (auto cm = normal_context_->GetCookieManager(nullptr)) {
      if (cm->DeleteCookies("", "", new DeleteThenFlush(cm, finish))) return;
    }
  }
  finish();
}

pages::DashboardData AegisContext::BuildDashboard(bool private_window) const {
  pages::DashboardData d;
  d.mode = settings_.mode;
  d.private_window = private_window;
  d.app_version = std::string(AEGIS_VERSION_STRING) + " (" + AEGIS_GIT_REVISION + ")";
  d.cef_version = CEF_VERSION;
  d.chromium_version = ChromiumVersion();
  SandboxStatus sb = sandbox_status();
  d.sandbox_ok = sb.state == SandboxStatus::State::kVerified;
  d.sandbox_status = sb.summary.empty() ? "verification pending" : sb.summary;
  d.sandbox_detail = sb.detail.empty() ? d.sandbox_status : sb.detail;
  UpdateStatus up = update_status();
  d.update_status = up.text;
  d.update_warning = up.warning;
  d.site_isolation = "Strict site isolation (one renderer process per site, --site-per-process)";
  const bool wasm_off = startup_mode_ == SecurityMode::kMaximumIsolation;
  d.wasm_status = wasm_off ? "Not exposed to pages (V8 --noexpose_wasm, set at startup)"
                           : "Available (Maximum Isolation disables it after a restart)";
  if (startup_mode_ != settings_.mode) d.wasm_status += " - restart pending for mode change";
  switch (settings_.mode) {
    case SecurityMode::kMaximumIsolation:
      d.javascript_status = "Blocked by engine content settings and script requests cancelled; "
                            "per-site exceptions only";
      break;
    case SecurityMode::kStrictProtection:
      d.javascript_status = "Allowed per site, V8 optimizing compilers (JIT tiers) disabled";
      break;
    case SecurityMode::kCompatibility:
      d.javascript_status = "Allowed with all V8 tiers";
      break;
  }
  for (int i = 0; i < static_cast<int>(EventCategory::kCount); ++i) {
    auto c = static_cast<EventCategory>(i);
    d.session_counts.emplace_back(std::string(EventCategoryLabel(c)), events_.SessionCount(c));
    d.lifetime_counts.emplace_back(std::string(EventCategoryLabel(c)), events_.LifetimeCount(c));
  }
  for (const auto& st : filters_->Status()) {
    pages::FilterListRow row;
    row.name = st.config.name;
    row.version = st.stats.version.empty() ? "-" : st.stats.version;
    row.source = st.source;
    row.updated = Iso(st.updated_unix_ms);
    row.status = st.last_error.empty() ? "OK" : st.last_error;
    row.license = st.config.license;
    row.rules = st.stats.network_rules + st.stats.exception_rules;
    row.cosmetic_skipped = st.stats.cosmetic_skipped;
    row.unsupported = st.stats.unsupported;
    row.enabled = st.config.enabled;
    d.lists.push_back(row);
  }
  for (const auto& [origin, mask] : settings_.permission_grants) {
    d.permissions.push_back({origin, Join(PermissionNames(mask), ", ")});
  }
  for (const auto& [site, ex] : settings_.site_exceptions) {
    std::vector<std::string> parts;
    if (ex.allow_javascript) parts.push_back("JavaScript allowed");
    if (ex.allow_third_party) parts.push_back("third-party content allowed");
    if (ex.disable_filtering) parts.push_back("filtering disabled");
    if (ex.allow_popups) parts.push_back("popups allowed");
    d.exceptions.push_back({site, Join(parts, ", ")});
  }
  d.top_sites = events_.TopSites(10);
  d.notices = load_notices_;
  return d;
}

pages::SiteReportData AegisContext::BuildSiteReport(const std::string& url, bool private_window) const {
  pages::SiteReportData r;
  auto p = policy();
  r.url = url;
  r.mode = settings_.mode;
  auto u = ParseUrl(url);
  std::string host = u ? NormalizeHostForMatching(u->host) : url;
  r.site = p->SiteFor(host);
  auto disp = idna::ForDisplay(host);
  r.display_host = disp.text;
  r.idn_spoof_risk = disp.spoof_risk;
  r.secure_connection = u && u->scheme == "https";
  r.javascript_allowed = IsJavaScriptAllowed(*p, url);
  r.js_optimizer_allowed = IsJavaScriptOptimizerAllowed(*p, url);
  SiteException ex = p->ExceptionFor(host);
  std::vector<std::string> parts;
  if (ex.allow_javascript) parts.push_back("JavaScript allowed");
  if (ex.allow_third_party) parts.push_back("third-party content allowed");
  if (ex.disable_filtering) parts.push_back("filtering disabled");
  if (ex.allow_popups) parts.push_back("popups allowed");
  r.exception_summary = Join(parts, ", ");
  if (u && !private_window) {
    auto it = settings_.permission_grants.find(u->Origin());
    if (it != settings_.permission_grants.end()) r.permissions = Join(PermissionNames(it->second), ", ");
  }
  SiteCounters c = events_.ForSite(r.site);
  for (int i = 0; i < static_cast<int>(EventCategory::kCount); ++i) {
    if (c.counts[static_cast<std::size_t>(i)] == 0) continue;
    r.counts.emplace_back(std::string(EventCategoryLabel(static_cast<EventCategory>(i))),
                          c.counts[static_cast<std::size_t>(i)]);
  }
  r.events = events_.Recent(200, r.site);
  return r;
}

}  // namespace aegis

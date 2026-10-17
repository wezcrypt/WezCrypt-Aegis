#include "browser/update_service.h"

#include <chrono>

#include "aegis_build_info.h"
#include "browser/aegis_context.h"
#include "common/strings.h"
#include "common/utf8.h"
#include "include/base/cef_callback.h"
#include "include/cef_request_context.h"
#include "include/cef_urlrequest.h"
#include "include/cef_version.h"
#include "include/wrapper/cef_closure_task.h"
#include "include/wrapper/cef_helpers.h"

namespace aegis {
namespace {

class CappedFetchClient : public CefURLRequestClient {
 public:
  CappedFetchClient(std::size_t max_bytes, FetchCallback done)
      : max_bytes_(max_bytes), done_(std::move(done)) {}

  void OnRequestComplete(CefRefPtr<CefURLRequest> request) override {
    CEF_REQUIRE_UI_THREAD();
    if (!done_) return;
    auto status = request->GetRequestStatus();
    auto response = request->GetResponse();
    int http = response ? response->GetStatus() : 0;
    bool ok = !overflow_ && status == UR_SUCCESS && http == 200;
    std::string error;
    if (overflow_) error = "response exceeded size limit";
    else if (status != UR_SUCCESS) error = "network error " + std::to_string(request->GetRequestError());
    else if (http != 200) error = "HTTP status " + std::to_string(http);
    auto done = std::move(done_);
    done_ = nullptr;
    done(ok, http, ok ? std::move(body_) : std::string(), error);
  }

  void OnUploadProgress(CefRefPtr<CefURLRequest>, int64_t, int64_t) override {}
  void OnDownloadProgress(CefRefPtr<CefURLRequest>, int64_t, int64_t) override {}

  void OnDownloadData(CefRefPtr<CefURLRequest> request, const void* data, size_t len) override {
    if (overflow_) return;
    if (body_.size() + len > max_bytes_) {
      overflow_ = true;
      body_.clear();
      request->Cancel();
      return;
    }
    body_.append(static_cast<const char*>(data), len);
  }

  bool GetAuthCredentials(bool, const CefString&, int, const CefString&, const CefString&,
                          CefRefPtr<CefAuthCallback>) override {
    return false;  // never authenticate
  }

 private:
  const std::size_t max_bytes_;
  FetchCallback done_;
  std::string body_;
  bool overflow_ = false;
  IMPLEMENT_REFCOUNTING(CappedFetchClient);
};

std::int64_t NowUnix() {
  return std::chrono::duration_cast<std::chrono::seconds>(
             std::chrono::system_clock::now().time_since_epoch())
      .count();
}

Version RunningChromium() {
  Version v;
  v.parts = {CHROME_VERSION_MAJOR, CHROME_VERSION_MINOR, CHROME_VERSION_BUILD, CHROME_VERSION_PATCH};
  return v;
}

Version RunningApp() {
  Version v;
  v.parts = {AEGIS_VERSION_MAJOR, AEGIS_VERSION_MINOR, AEGIS_VERSION_PATCH};
  return v;
}

void ApplyListUpdateOffThread(std::string id, std::string body) {
  auto* ctx = AegisContext::Get();
  if (!ctx) return;
  UpdateOutcome o = ctx->filters().ApplyUpdate(id, std::move(body));
  LOG(INFO) << "filter list " << id << ": " << UpdateOutcomeText(o);
  CefPostTask(TID_UI, base::BindOnce([]() {
                if (auto* c = AegisContext::Get()) c->RebuildPolicy();
              }));
}

}  // namespace

void FetchHttps(const std::string& url, std::size_t max_bytes, FetchCallback done) {
  CEF_REQUIRE_UI_THREAD();
  auto u = ParseUrl(url);
  if (!u || u->scheme != "https" || u->has_credentials) {
    done(false, 0, {}, "refusing non-HTTPS update URL");
    return;
  }
  CefRefPtr<CefRequest> request = CefRequest::Create();
  request->SetURL(url);
  request->SetMethod("GET");
  request->SetFlags(UR_FLAG_SKIP_CACHE);
  CefURLRequest::Create(request, new CappedFetchClient(max_bytes, std::move(done)),
                        CefRequestContext::GetGlobalContext());
}

std::int64_t ParseExpiresSeconds(const std::string& value) {
  std::string v = ToLowerAscii(TrimAsciiWhitespace(value));
  std::size_t sp = v.find(' ');
  std::uint64_t n = 0;
  if (!ParseUint64(v.substr(0, sp), &n) || n == 0 || n > 365) return 4 * 86400;
  std::string unit = sp == std::string::npos ? "days" : v.substr(sp + 1);
  if (StartsWith(unit, "hour")) return static_cast<std::int64_t>(n) * 3600;
  return static_cast<std::int64_t>(n) * 86400;
}

void UpdateService::RefreshFilterLists(bool force) {
  CEF_REQUIRE_UI_THREAD();
  auto* ctx = AegisContext::Get();
  if (!ctx) return;
  const std::int64_t now_ms = NowUnix() * 1000;
  for (const auto& st : ctx->filters().Status()) {
    if (st.config.update_url.empty() || !st.config.enabled) continue;
    const std::int64_t expires_ms = ParseExpiresSeconds(st.stats.expires) * 1000;
    const bool stale = st.source == "bundled" || st.updated_unix_ms == 0 ||
                       now_ms - st.updated_unix_ms > expires_ms;
    // Do not retry more than hourly after a failure.
    const bool recently_tried = st.last_attempt_unix_ms > 0 && now_ms - st.last_attempt_unix_ms < 3600 * 1000;
    if (!force && (!stale || recently_tried)) continue;
    std::string id = st.config.id;
    FetchHttps(st.config.update_url, FilterListManager::kMaxListBytes,
               [id](bool ok, int, std::string body, std::string error) {
                 if (!ok) {
                   LOG(WARNING) << "filter list " << id << " download failed: " << error;
                   if (auto* c = AegisContext::Get()) c->filters().RecordUpdateFailure(id, error);
                   return;
                 }
                 // Parsing and engine compilation are done off the UI thread.
                 CefPostTask(TID_FILE_BACKGROUND,
                             base::BindOnce(&ApplyListUpdateOffThread, id, std::move(body)));
               });
  }
}

void UpdateService::CheckForBrowserUpdate() {
  CEF_REQUIRE_UI_THREAD();
  auto* ctx = AegisContext::Get();
  if (!ctx) return;
  const std::string manifest_url = AEGIS_UPDATE_MANIFEST_URL;
  const auto keys = ParsePublicKeys(AEGIS_UPDATE_PUBLIC_KEYS);
  if (manifest_url.empty() || keys.empty()) {
    UpdateStatus s;
    EngineFreshness f = EvaluateEngineFreshness(RunningApp(), RunningChromium(), AEGIS_BUILD_UNIX,
                                                NowUnix(), nullptr);
    s.warning = f == EngineFreshness::kUnknownStale;
    s.text = std::string(EngineFreshnessText(f)) +
             ". Signed online update checks are not configured in this build "
             "(see docs/RELEASE_PROCESS.md).";
    s.checked_unix_ms = NowUnix() * 1000;
    ctx->SetUpdateStatus(s);
    return;
  }
  FetchHttps(manifest_url, 1 << 20, [manifest_url, keys](bool ok, int, std::string manifest, std::string err) {
    if (!ok) {
      UpdateStatus s;
      s.text = "Update check failed: " + err;
      s.warning = EvaluateEngineFreshness(RunningApp(), RunningChromium(), AEGIS_BUILD_UNIX, NowUnix(),
                                          nullptr) == EngineFreshness::kUnknownStale;
      s.checked_unix_ms = NowUnix() * 1000;
      if (auto* c = AegisContext::Get()) c->SetUpdateStatus(s);
      return;
    }
    FetchHttps(manifest_url + ".sig", 4096, [manifest, keys](bool sig_ok, int, std::string sig, std::string serr) {
      auto* c = AegisContext::Get();
      if (!c) return;
      UpdateStatus s;
      s.checked_unix_ms = NowUnix() * 1000;
      if (!sig_ok) {
        s.text = "Update check failed: signature unavailable (" + serr + ")";
        c->SetUpdateStatus(s);
        return;
      }
      VerifyOptions opts;
      opts.trusted_keys = keys;
      opts.expected_channel = AEGIS_UPDATE_CHANNEL;
      opts.last_accepted_sequence = c->settings().update_manifest_sequence;
      opts.now_unix = NowUnix();
      VerifiedManifest vm = VerifyManifest(manifest, TrimAsciiWhitespace(sig), opts);
      if (vm.status == ManifestStatus::kRollback && vm.manifest.sequence == opts.last_accepted_sequence) {
        // Same manifest as last time: still authoritative for freshness.
        vm.status = ManifestStatus::kOk;
      }
      if (vm.status != ManifestStatus::kOk) {
        s.text = std::string("Update manifest rejected: ") + std::string(ManifestStatusText(vm.status));
        s.warning = true;
        c->SetUpdateStatus(s);
        return;
      }
      const std::uint64_t seq = vm.manifest.sequence;
      c->UpdateSettings([seq](Settings& st) {
        if (seq > st.update_manifest_sequence) st.update_manifest_sequence = seq;
      });
      EngineFreshness f = EvaluateEngineFreshness(RunningApp(), RunningChromium(), AEGIS_BUILD_UNIX,
                                                  NowUnix(), &vm.manifest);
      s.text = std::string(EngineFreshnessText(f)) + " (latest " + vm.manifest.version.ToString() +
               ", Chromium " + vm.manifest.chromium_version.ToString() + ")";
      s.warning = f == EngineFreshness::kBelowMinimumSafe || f == EngineFreshness::kUpdateAvailable;
      s.manifest = vm.manifest;
      c->SetUpdateStatus(s);
    });
  });
}

bool UpdateService::VerifyDownloadedArtifact(const std::string& file_path, const std::string& file_name,
                                             bool* matches) {
  auto* ctx = AegisContext::Get();
  if (!ctx) return false;
  UpdateStatus s = ctx->update_status();
  if (!s.manifest) return false;
  for (const auto& a : s.manifest->artifacts) {
    if (a.name == file_name) {
      *matches = VerifyArtifactFile(std::filesystem::path(Utf8ToWide(file_path)), a);
      return true;
    }
  }
  return false;
}

void UpdateService::ScheduleBackgroundChecks() {
  CEF_REQUIRE_UI_THREAD();
  RefreshFilterLists(false);
  CheckForBrowserUpdate();
  // Re-check every 6 hours while running.
  CefPostDelayedTask(TID_UI, base::BindOnce(&UpdateService::ScheduleBackgroundChecks),
                     6LL * 3600 * 1000);
}

}  // namespace aegis

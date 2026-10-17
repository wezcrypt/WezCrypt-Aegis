#include "filtering/filter_list_manager.h"

#include "common/strings.h"
#include "common/utf8.h"
#include "security/security_events.h"
#include "storage/atomic_file.h"

namespace aegis {

std::string_view UpdateOutcomeText(UpdateOutcome o) {
  switch (o) {
    case UpdateOutcome::kApplied: return "applied";
    case UpdateOutcome::kUnchanged: return "unchanged";
    case UpdateOutcome::kRejectedTooLarge: return "rejected: list exceeds size limit";
    case UpdateOutcome::kRejectedNotAFilterList: return "rejected: not a filter list";
    case UpdateOutcome::kRejectedTooFewRules: return "rejected: too few valid rules";
    case UpdateOutcome::kRejectedShrankTooMuch:
      return "rejected: rule count dropped by more than half";
    case UpdateOutcome::kRejectedTooManyInvalid: return "rejected: too many invalid lines";
    case UpdateOutcome::kRejectedBuildFailed: return "rejected: engine build failed";
    case UpdateOutcome::kRejectedUnknownList: return "rejected: unknown list";
    case UpdateOutcome::kRejectedCacheWriteFailed: return "rejected: could not persist list";
  }
  return "unknown";
}

namespace {

bool LooksLikeFilterList(std::string_view text) {
  if (!IsValidUtf8(text)) return false;
  std::string_view head = text.substr(0, 4096);
  if (head.find('\0') != std::string_view::npos) return false;
  // Reject obvious HTML error pages / captive portals.
  std::string lower = ToLowerAscii(head.substr(0, 512));
  if (lower.find("<html") != std::string::npos || lower.find("<!doctype") != std::string::npos)
    return false;
  return StartsWith(TrimAsciiWhitespace(head), "[Adblock Plus") ||
         head.find("! Title:") != std::string_view::npos ||
         head.find("! Version:") != std::string_view::npos;
}

FilterListSource SourceFor(const FilterListConfig& c, const std::string& text) {
  FilterListSource s;
  s.id = c.id;
  s.name = c.name;
  s.category = c.category;
  s.text = text;
  return s;
}

}  // namespace

FilterListManager::FilterListManager(std::filesystem::path bundled_dir,
                                     std::filesystem::path cache_dir,
                                     std::shared_ptr<const PublicSuffixList> psl)
    : bundled_dir_(std::move(bundled_dir)), cache_dir_(std::move(cache_dir)), psl_(std::move(psl)) {}

std::vector<FilterListConfig> FilterListManager::DefaultLists() {
  std::vector<FilterListConfig> v;
  FilterListConfig baseline;
  baseline.id = "aegis-baseline";
  baseline.name = "WezCrypt Aegis Baseline";
  baseline.category = ListCategory::kBuiltin;
  baseline.license = "MIT (WezCrypt)";
  baseline.min_rules = 1;
  v.push_back(baseline);

  FilterListConfig easylist;
  easylist.id = "easylist";
  easylist.name = "EasyList";
  easylist.update_url = "https://easylist.to/easylist/easylist.txt";
  easylist.category = ListCategory::kAdvertising;
  easylist.license = "GPLv3 / CC BY-SA 3.0 (The EasyList authors)";
  easylist.min_rules = 5000;
  v.push_back(easylist);

  FilterListConfig easyprivacy;
  easyprivacy.id = "easyprivacy";
  easyprivacy.name = "EasyPrivacy";
  easyprivacy.update_url = "https://easylist.to/easylist/easyprivacy.txt";
  easyprivacy.category = ListCategory::kTracking;
  easyprivacy.license = "GPLv3 / CC BY-SA 3.0 (The EasyList authors)";
  easyprivacy.min_rules = 5000;
  v.push_back(easyprivacy);
  return v;
}

std::string FilterListManager::ReadBundled(const std::string& id) const {
  auto r = storage::ReadFile(bundled_dir_ / (id + ".txt"), kMaxListBytes);
  return r.status == storage::ReadStatus::kOk ? r.data : std::string();
}

bool FilterListManager::Initialize(std::vector<FilterListConfig> lists,
                                   const std::vector<std::string>& user_rules) {
  std::lock_guard<std::mutex> lock(mutex_);
  configs_ = std::move(lists);
  user_rules_ = user_rules;
  texts_.assign(configs_.size(), std::string());
  status_.assign(configs_.size(), ListStatus());
  for (std::size_t i = 0; i < configs_.size(); ++i) {
    status_[i].config = configs_[i];
    auto cached = storage::ReadFile(cache_dir_ / (configs_[i].id + ".txt"), kMaxListBytes);
    if (cached.status == storage::ReadStatus::kOk && LooksLikeFilterList(cached.data)) {
      texts_[i] = std::move(cached.data);
      status_[i].source = "cache";
      std::error_code ec;
      auto t = std::filesystem::last_write_time(cache_dir_ / (configs_[i].id + ".txt"), ec);
      if (!ec) {
        auto sys = std::chrono::clock_cast<std::chrono::system_clock>(t);
        status_[i].updated_unix_ms =
            std::chrono::duration_cast<std::chrono::milliseconds>(sys.time_since_epoch()).count();
      }
      continue;
    }
    texts_[i] = ReadBundled(configs_[i].id);
    status_[i].source = texts_[i].empty() ? "missing" : "bundled";
    if (texts_[i].empty()) status_[i].last_error = "no bundled or cached copy";
  }
  std::string error;
  if (RebuildLocked(&error)) return true;
  // A corrupt cache must not disable filtering: fall back to bundled copies.
  for (std::size_t i = 0; i < configs_.size(); ++i) {
    if (status_[i].source == "cache") {
      texts_[i] = ReadBundled(configs_[i].id);
      status_[i].source = "bundled";
      status_[i].last_error = "cached copy unusable: " + error;
    }
  }
  return RebuildLocked(&error);
}

bool FilterListManager::RebuildLocked(std::string* error) {
  std::vector<FilterListSource> sources;
  std::vector<std::size_t> idx;
  for (std::size_t i = 0; i < configs_.size(); ++i) {
    if (!configs_[i].enabled || texts_[i].empty()) continue;
    sources.push_back(SourceFor(configs_[i], texts_[i]));
    idx.push_back(i);
  }
  FilterListSource user;
  user.id = "user";
  user.name = "My rules";
  user.category = ListCategory::kUser;
  user.text = Join(user_rules_, "\n");
  sources.push_back(std::move(user));

  auto built = FilterEngine::Build(sources, psl_);
  if (!built.ok) {
    if (error) *error = built.error;
    return false;
  }
  for (std::size_t k = 0; k < idx.size(); ++k) status_[idx[k]].stats = built.lists[k];
  std::lock_guard<std::mutex> engine_lock(engine_mutex_);
  engine_ = built.engine;
  return true;
}

std::shared_ptr<const FilterEngine> FilterListManager::engine() const {
  std::lock_guard<std::mutex> engine_lock(engine_mutex_);
  return engine_;
}

UpdateOutcome FilterListManager::ApplyUpdate(const std::string& list_id, std::string text) {
  std::lock_guard<std::mutex> lock(mutex_);
  std::size_t i = 0;
  for (; i < configs_.size(); ++i) {
    if (configs_[i].id == list_id) break;
  }
  if (i == configs_.size()) return UpdateOutcome::kRejectedUnknownList;
  ListStatus& st = status_[i];
  st.last_attempt_unix_ms = NowUnixMs();
  auto reject = [&](UpdateOutcome o) {
    st.last_error = std::string(UpdateOutcomeText(o));
    return o;
  };
  if (text.size() > kMaxListBytes) return reject(UpdateOutcome::kRejectedTooLarge);
  if (!LooksLikeFilterList(text)) return reject(UpdateOutcome::kRejectedNotAFilterList);
  if (text == texts_[i]) {
    st.last_error.clear();
    return UpdateOutcome::kUnchanged;
  }

  // Parse the candidate on its own to evaluate plausibility.
  auto probe = FilterEngine::Build({SourceFor(configs_[i], text)}, psl_);
  if (!probe.ok) return reject(UpdateOutcome::kRejectedBuildFailed);
  const ListStats& ps = probe.lists.front();
  const std::size_t rules = ps.network_rules + ps.exception_rules;
  if (rules < configs_[i].min_rules) return reject(UpdateOutcome::kRejectedTooFewRules);
  const std::size_t previous = st.stats.network_rules + st.stats.exception_rules;
  if (previous > 0 && rules * 2 < previous) return reject(UpdateOutcome::kRejectedShrankTooMuch);
  const std::size_t considered = ps.network_rules + ps.exception_rules + ps.invalid;
  if (considered > 0 && ps.invalid * 4 > considered)
    return reject(UpdateOutcome::kRejectedTooManyInvalid);

  // Build the full candidate engine before touching any state.
  std::string old_text = std::move(texts_[i]);
  ListStats old_stats = st.stats;
  texts_[i] = text;
  std::string error;
  if (!RebuildLocked(&error)) {
    texts_[i] = std::move(old_text);
    st.stats = old_stats;
    return reject(UpdateOutcome::kRejectedBuildFailed);
  }
  // Persist only after the engine is known-good. If persisting fails the
  // in-memory update stays active (it is valid) and the old cache remains.
  std::string werr;
  storage::EnsureDirectory(cache_dir_);
  if (!storage::WriteFileAtomically(cache_dir_ / (list_id + ".txt"), text, false, &werr)) {
    st.last_error = "update applied but not persisted: " + werr;
  } else {
    st.last_error.clear();
  }
  st.source = "update";
  st.updated_unix_ms = NowUnixMs();
  return UpdateOutcome::kApplied;
}

bool FilterListManager::SetUserRules(const std::vector<std::string>& rules) {
  std::lock_guard<std::mutex> lock(mutex_);
  auto old = user_rules_;
  user_rules_ = rules;
  std::string error;
  if (!RebuildLocked(&error)) {
    user_rules_ = std::move(old);
    return false;
  }
  return true;
}

bool FilterListManager::SetListEnabled(const std::string& list_id, bool enabled) {
  std::lock_guard<std::mutex> lock(mutex_);
  for (std::size_t i = 0; i < configs_.size(); ++i) {
    if (configs_[i].id != list_id) continue;
    bool old = configs_[i].enabled;
    configs_[i].enabled = enabled;
    status_[i].config.enabled = enabled;
    std::string error;
    if (!RebuildLocked(&error)) {
      configs_[i].enabled = old;
      status_[i].config.enabled = old;
      return false;
    }
    return true;
  }
  return false;
}

std::vector<ListStatus> FilterListManager::Status() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return status_;
}

std::vector<FilterListConfig> FilterListManager::Configs() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return configs_;
}

}  // namespace aegis

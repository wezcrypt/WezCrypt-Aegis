// WezCrypt Aegis - filter list lifecycle: bundled lists, cached updates,
// validation and atomic replacement of the active engine.
//
// Security properties:
//  * An update is applied only if the candidate list parses within limits,
//    passes sanity checks, and the complete engine builds successfully.
//  * A failed or suspicious update never replaces the active rules and
//    never deletes the cached last-known-good copy.
//  * Updates are plain data (filter text). No executable content is ever
//    downloaded or loaded by the filter subsystem.
#pragma once

#include <filesystem>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "filtering/filter_engine.h"
#include "filtering/public_suffix_list.h"

namespace aegis {

struct FilterListConfig {
  std::string id;          // "easylist"
  std::string name;        // "EasyList"
  std::string update_url;  // HTTPS only; empty = never updated online
  ListCategory category = ListCategory::kAdvertising;
  std::string license;     // shown on the dashboard
  bool enabled = true;
  // Minimum rule count for an update to be considered plausible.
  std::size_t min_rules = 100;
};

enum class UpdateOutcome {
  kApplied,
  kUnchanged,
  kRejectedTooLarge,
  kRejectedNotAFilterList,
  kRejectedTooFewRules,
  kRejectedShrankTooMuch,
  kRejectedTooManyInvalid,
  kRejectedBuildFailed,
  kRejectedUnknownList,
  kRejectedCacheWriteFailed,
};

std::string_view UpdateOutcomeText(UpdateOutcome o);

struct ListStatus {
  FilterListConfig config;
  ListStats stats;
  std::string source;          // "bundled", "cache", "update"
  std::int64_t updated_unix_ms = 0;
  std::string last_error;
  std::int64_t last_attempt_unix_ms = 0;
};

class FilterListManager {
 public:
  FilterListManager(std::filesystem::path bundled_dir, std::filesystem::path cache_dir,
                    std::shared_ptr<const PublicSuffixList> psl);

  static std::vector<FilterListConfig> DefaultLists();

  // Loads every configured list from cache (preferred, if valid) or bundled
  // copy and builds the initial engine. Returns false only if no engine
  // could be built at all.
  bool Initialize(std::vector<FilterListConfig> lists,
                  const std::vector<std::string>& user_rules);

  // Thread-safe snapshot of the active engine.
  std::shared_ptr<const FilterEngine> engine() const;

  // Validates and applies downloaded list text for |list_id|.
  UpdateOutcome ApplyUpdate(const std::string& list_id, std::string text);

  // Replaces user rules and rebuilds. Invalid user rules are skipped and
  // reported in the list stats; the rebuild itself must succeed.
  bool SetUserRules(const std::vector<std::string>& rules);

  bool SetListEnabled(const std::string& list_id, bool enabled);

  std::vector<ListStatus> Status() const;
  std::vector<FilterListConfig> Configs() const;

  static constexpr std::size_t kMaxListBytes = 16 * 1024 * 1024;

 private:
  bool RebuildLocked(std::string* error);
  std::string ReadBundled(const std::string& id) const;

  const std::filesystem::path bundled_dir_;
  const std::filesystem::path cache_dir_;
  std::shared_ptr<const PublicSuffixList> psl_;

  mutable std::mutex mutex_;
  std::vector<FilterListConfig> configs_;
  std::vector<std::string> texts_;     // parallel to configs_
  std::vector<ListStatus> status_;     // parallel to configs_
  std::vector<std::string> user_rules_;
  // Guards only |engine_| so request evaluation never waits for a rebuild.
  mutable std::mutex engine_mutex_;
  std::shared_ptr<const FilterEngine> engine_;
};

}  // namespace aegis

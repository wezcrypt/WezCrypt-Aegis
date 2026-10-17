// WezCrypt Aegis - compiled network filter engine.
//
// The engine is immutable after Build(): it is shared between threads via
// std::shared_ptr<const FilterEngine> and replaced atomically on update, so
// request evaluation on the network (IO) thread never takes a lock.
#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "filtering/filter_rule.h"
#include "filtering/public_suffix_list.h"

namespace aegis {

enum class ListCategory : std::uint8_t {
  kAdvertising,
  kTracking,
  kMalware,
  kUser,
  kBuiltin,
};

std::string_view ListCategoryName(ListCategory c);

struct FilterListSource {
  std::string name;           // e.g. "EasyList"
  std::string id;             // e.g. "easylist"
  ListCategory category = ListCategory::kAdvertising;
  std::string text;           // full list contents
};

struct ListStats {
  std::string id;
  std::string name;
  std::string version;        // "! Version:" header if present
  std::string title;
  std::string expires;        // "! Expires:" header if present
  std::size_t lines = 0;
  std::size_t network_rules = 0;
  std::size_t exception_rules = 0;
  std::size_t cosmetic_skipped = 0;
  std::size_t unsupported = 0;
  std::size_t invalid = 0;
  std::size_t badfilters = 0;
};

struct EngineLimits {
  std::size_t max_list_bytes = 16 * 1024 * 1024;
  std::size_t max_total_rules = 600'000;
  ParseLimits line_limits;
};

struct RequestInfo {
  std::string_view url;               // full canonical URL
  std::string_view request_host;      // normalized host of |url|
  std::string_view first_party_host;  // top-level document host (may be empty)
  std::string_view first_party_url;   // top-level document URL (may be empty)
  ResourceType type = kResourceOther;
  bool third_party = true;
};

enum class FilterDecision : std::uint8_t {
  kNoMatch,
  kBlock,
  kAllowedByException,
};

struct FilterMatch {
  FilterDecision decision = FilterDecision::kNoMatch;
  const FilterRule* rule = nullptr;       // blocking rule, if any
  const FilterRule* exception = nullptr;  // exception that overrode it
  ListCategory category = ListCategory::kBuiltin;
  std::string list_id;
};

class FilterEngine {
 public:
  struct BuildResult {
    std::shared_ptr<const FilterEngine> engine;
    std::vector<ListStats> lists;
    bool ok = false;
    std::string error;
  };

  static BuildResult Build(const std::vector<FilterListSource>& sources,
                           std::shared_ptr<const PublicSuffixList> psl,
                           const EngineLimits& limits = EngineLimits());

  FilterMatch Match(const RequestInfo& req) const;

  // True when an "@@...$document" exception allowlists the whole page.
  bool IsDocumentAllowlisted(std::string_view first_party_url,
                             std::string_view first_party_host) const;

  std::size_t rule_count() const { return rules_.size(); }
  const std::vector<ListStats>& list_stats() const { return list_stats_; }

 private:
  struct Index {
    std::unordered_map<std::string, std::vector<std::uint32_t>> by_host;
    std::unordered_map<std::uint64_t, std::vector<std::uint32_t>> by_token;
    std::vector<std::uint32_t> generic;
  };

  FilterEngine() = default;

  void AddToIndex(Index* index, std::uint32_t id);
  const FilterRule* FindIn(const Index& index, const RequestInfo& req,
                           std::string_view url_lower,
                           const std::vector<std::uint64_t>& tokens) const;
  bool RuleMatches(const FilterRule& rule, const RequestInfo& req,
                   std::string_view url_lower) const;
  bool DomainsMatch(const FilterRule& rule, std::string_view fp_host) const;

  std::vector<FilterRule> rules_;
  std::vector<ListCategory> rule_categories_;
  std::vector<std::string> list_ids_;  // index = list_id
  std::vector<ListCategory> list_categories_;
  Index important_;
  Index block_;
  Index exceptions_;
  Index document_exceptions_;
  std::vector<ListStats> list_stats_;
  std::shared_ptr<const PublicSuffixList> psl_;
};

// Exposed for tests: ABP pattern matching with '*' and '^'.
bool MatchFilterPattern(std::string_view pattern, std::string_view url,
                        bool left_anchor, bool right_anchor,
                        std::size_t host_begin, std::size_t host_end,
                        bool domain_anchor);

}  // namespace aegis

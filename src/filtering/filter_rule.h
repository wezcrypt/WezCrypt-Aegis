// WezCrypt Aegis - parsed Adblock-Plus-compatible network filter rule.
#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "filtering/resource_type.h"

namespace aegis {

enum class PartyRequirement : std::uint8_t { kAny, kFirstParty, kThirdParty };

struct DomainConstraint {
  std::string domain;     // lower-case ASCII host or "entity.*"
  bool negated = false;
  bool entity = false;    // "google.*" form
};

struct FilterRule {
  std::string text;       // original rule text (for explanations)
  std::uint16_t list_id = 0;
  bool exception = false;      // "@@"
  bool important = false;      // "$important"
  bool match_case = false;
  bool left_anchor = false;    // "|"
  bool right_anchor = false;   // trailing "|"
  bool domain_anchor = false;  // "||"
  bool pure_host = false;      // "||host^" with nothing after
  // Pure host rules without type options also apply to top-level documents
  // (navigations are stopped at an interstitial, like other strict blockers).
  bool strict_document = false;
  std::string pattern;         // without anchors; lower-case unless match_case
  std::string host;            // host part for domain-anchored rules
  std::uint32_t types = kDefaultRuleTypes;
  PartyRequirement party = PartyRequirement::kAny;
  std::vector<DomainConstraint> domains;
};

enum class ParseOutcome {
  kRule,
  kComment,      // "!" comments and "[Adblock Plus x.y]" headers
  kEmpty,
  kCosmetic,     // element hiding / scriptlets: not supported (counted)
  kUnsupported,  // valid syntax WezCrypt Aegis deliberately does not apply
  kInvalid,      // malformed or exceeds limits
  kBadFilter,    // "$badfilter" rule; disables a matching rule
};

struct ParseLimits {
  std::size_t max_line_bytes = 4096;
  std::size_t max_options = 64;
  std::size_t max_domains = 1024;
};

struct ParsedLine {
  ParseOutcome outcome = ParseOutcome::kInvalid;
  FilterRule rule;
  std::string reason;  // for kUnsupported / kInvalid
};

// Parses one line of an ABP / uBlock-compatible filter list, or a hosts-file
// line ("0.0.0.0 ads.example").
ParsedLine ParseFilterLine(std::string_view line, std::uint16_t list_id,
                           const ParseLimits& limits = ParseLimits());

// Canonical text used to pair "$badfilter" rules with their targets.
std::string BadFilterKey(std::string_view rule_text_without_badfilter);

}  // namespace aegis

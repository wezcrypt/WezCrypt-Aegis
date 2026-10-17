#include "filtering/filter_engine.h"

#include <algorithm>

#include "common/strings.h"

namespace aegis {

std::string_view ListCategoryName(ListCategory c) {
  switch (c) {
    case ListCategory::kAdvertising: return "advertising";
    case ListCategory::kTracking: return "tracking";
    case ListCategory::kMalware: return "malware";
    case ListCategory::kUser: return "user";
    case ListCategory::kBuiltin: return "builtin";
  }
  return "builtin";
}

namespace {

constexpr bool IsTokenChar(char c) { return IsAsciiAlnum(c) || c == '%'; }

constexpr bool IsSeparatorChar(char c) {
  // ABP '^': anything but a letter, digit, or one of _ - . %
  return !(IsAsciiAlnum(c) || c == '_' || c == '-' || c == '.' || c == '%');
}

bool IsCommonToken(std::string_view t) {
  static constexpr std::string_view kCommon[] = {
      "http", "https", "www", "com", "net", "org", "js", "html", "php",
      "png", "gif", "jpg", "css", "static", "cdn", "assets", "img",
      "images", "api", "v1", "v2"};
  for (auto c : kCommon) {
    if (t == c) return true;
  }
  return false;
}

// Matches |seg| (no '*') at |pos|; '^' matches a separator or end of text.
bool SegmentMatchAt(std::string_view seg, std::string_view text, std::size_t pos,
                    std::size_t* end) {
  for (char c : seg) {
    if (c == '^') {
      if (pos < text.size()) {
        if (!IsSeparatorChar(text[pos])) return false;
        ++pos;
      }
      // At end of text '^' matches the empty string.
    } else {
      if (pos >= text.size() || text[pos] != c) return false;
      ++pos;
    }
  }
  *end = pos;
  return true;
}

// Finds the leftmost match of |seg| at or after |from|.
bool SegmentFind(std::string_view seg, std::string_view text, std::size_t from,
                 std::size_t* match_begin, std::size_t* match_end) {
  if (seg.empty()) {
    *match_begin = *match_end = from;
    return true;
  }
  for (std::size_t p = from; p <= text.size(); ++p) {
    std::size_t e;
    if (SegmentMatchAt(seg, text, p, &e)) {
      *match_begin = p;
      *match_end = e;
      return true;
    }
  }
  return false;
}

// Glob match with '*' starting exactly at |start|.
bool GlobMatchAnchored(std::string_view pattern, std::string_view text,
                       std::size_t start, bool right_anchor) {
  std::vector<std::string_view> segs = Split(pattern, '*');
  std::size_t pos = start;
  std::size_t e;
  // First segment is anchored.
  if (!SegmentMatchAt(segs[0], text, pos, &e)) return false;
  pos = e;
  if (segs.size() == 1) return !right_anchor || pos == text.size();
  for (std::size_t i = 1; i + 1 < segs.size(); ++i) {
    std::size_t b;
    if (!SegmentFind(segs[i], text, pos, &b, &e)) return false;
    pos = e;
  }
  std::string_view last = segs.back();
  if (!right_anchor) {
    std::size_t b;
    return SegmentFind(last, text, pos, &b, &e);
  }
  // Right-anchored: the last segment must end exactly at the end of text.
  for (std::size_t p = text.size() + 1; p-- > pos;) {
    if (SegmentMatchAt(last, text, p, &e) && e == text.size()) return true;
  }
  return false;
}

bool GlobSearch(std::string_view pattern, std::string_view text, bool right_anchor) {
  // Unanchored: try the first segment at each leftmost occurrence. Because
  // later segments are searched greedily-leftmost, trying the leftmost
  // occurrence of the first segment is sufficient unless right-anchored.
  std::vector<std::string_view> segs = Split(pattern, '*');
  std::size_t from = 0;
  while (from <= text.size()) {
    std::size_t b, e;
    if (!SegmentFind(segs[0], text, from, &b, &e)) return false;
    if (GlobMatchAnchored(pattern, text, b, right_anchor)) return true;
    if (!right_anchor) return false;
    from = b + 1;
  }
  return false;
}

void HostBounds(std::string_view url, std::size_t* begin, std::size_t* end) {
  std::size_t p = url.find("://");
  if (p == std::string_view::npos) {
    *begin = *end = 0;
    return;
  }
  std::size_t b = p + 3;
  std::size_t stop = url.find_first_of("/?#", b);
  if (stop == std::string_view::npos) stop = url.size();
  std::size_t at = url.rfind('@', stop);
  if (at != std::string_view::npos && at >= b) b = at + 1;
  std::size_t e = b;
  if (e < url.size() && url[e] == '[') {
    std::size_t close = url.find(']', e);
    e = close == std::string_view::npos ? stop : close + 1;
  } else {
    while (e < stop && url[e] != ':') ++e;
  }
  *begin = b;
  *end = e;
}

void TokenizeUrl(std::string_view url_lower, std::vector<std::uint64_t>* out) {
  out->clear();
  std::size_t i = 0;
  while (i < url_lower.size()) {
    while (i < url_lower.size() && !IsTokenChar(url_lower[i])) ++i;
    std::size_t s = i;
    while (i < url_lower.size() && IsTokenChar(url_lower[i])) ++i;
    if (i > s) out->push_back(Fnv1a64(url_lower.substr(s, i - s)));
  }
  std::sort(out->begin(), out->end());
  out->erase(std::unique(out->begin(), out->end()), out->end());
}

bool HostMatchesDomain(std::string_view host, std::string_view domain) {
  if (host.size() == domain.size()) return host == domain;
  return host.size() > domain.size() && EndsWith(host, domain) &&
         host[host.size() - domain.size() - 1] == '.';
}

void ParseHeader(std::string_view line, ListStats* st) {
  auto value_after = [&](std::string_view key) -> std::string {
    std::string_view rest = TrimAsciiWhitespace(line.substr(1));
    if (StartsWithIgnoreCaseAscii(rest, key)) {
      return std::string(TrimAsciiWhitespace(rest.substr(key.size())));
    }
    return {};
  };
  if (st->version.empty()) st->version = value_after("Version:");
  if (st->title.empty()) st->title = value_after("Title:");
  if (st->expires.empty()) st->expires = value_after("Expires:");
}

}  // namespace

bool MatchFilterPattern(std::string_view pattern, std::string_view url,
                        bool left_anchor, bool right_anchor,
                        std::size_t host_begin, std::size_t host_end,
                        bool domain_anchor) {
  if (domain_anchor) {
    if (host_end <= host_begin) return false;
    if (GlobMatchAnchored(pattern, url, host_begin, right_anchor)) return true;
    for (std::size_t i = host_begin; i < host_end; ++i) {
      if (url[i] == '.' && GlobMatchAnchored(pattern, url, i + 1, right_anchor))
        return true;
    }
    return false;
  }
  if (left_anchor) return GlobMatchAnchored(pattern, url, 0, right_anchor);
  return GlobSearch(pattern, url, right_anchor);
}

FilterEngine::BuildResult FilterEngine::Build(
    const std::vector<FilterListSource>& sources,
    std::shared_ptr<const PublicSuffixList> psl, const EngineLimits& limits) {
  BuildResult result;
  if (!psl || psl->empty()) {
    result.error = "public suffix list unavailable";
    return result;
  }
  std::shared_ptr<FilterEngine> engine(new FilterEngine());
  engine->psl_ = psl;

  std::vector<FilterRule> parsed;
  std::unordered_set<std::string> bad_keys;
  std::unordered_set<std::string> seen_text;
  for (std::size_t li = 0; li < sources.size(); ++li) {
    const FilterListSource& src = sources[li];
    ListStats st;
    st.id = src.id;
    st.name = src.name;
    if (src.text.size() > limits.max_list_bytes) {
      result.error = "filter list '" + src.id + "' exceeds size limit";
      return result;
    }
    if (li > 0xFFFF) {
      result.error = "too many filter lists";
      return result;
    }
    engine->list_ids_.push_back(src.id);
    engine->list_categories_.push_back(src.category);
    for (std::string_view line : SplitLines(src.text)) {
      ++st.lines;
      ParsedLine p = ParseFilterLine(line, static_cast<std::uint16_t>(li), limits.line_limits);
      switch (p.outcome) {
        case ParseOutcome::kEmpty: break;
        case ParseOutcome::kComment:
          if (!line.empty() && line[0] == '!') ParseHeader(line, &st);
          break;
        case ParseOutcome::kCosmetic: ++st.cosmetic_skipped; break;
        case ParseOutcome::kUnsupported: ++st.unsupported; break;
        case ParseOutcome::kInvalid: ++st.invalid; break;
        case ParseOutcome::kBadFilter:
          ++st.badfilters;
          bad_keys.insert(BadFilterKey(p.rule.text));
          break;
        case ParseOutcome::kRule:
          if (!seen_text.insert(p.rule.text).second) break;
          if (p.rule.exception) ++st.exception_rules;
          else ++st.network_rules;
          parsed.push_back(std::move(p.rule));
          if (parsed.size() > limits.max_total_rules) {
            result.error = "filter rules exceed limit";
            return result;
          }
          break;
      }
    }
    result.lists.push_back(st);
  }

  engine->rules_.reserve(parsed.size());
  for (FilterRule& r : parsed) {
    if (!bad_keys.empty() && bad_keys.count(BadFilterKey(r.text))) continue;
    engine->rules_.push_back(std::move(r));
  }
  for (std::uint32_t id = 0; id < engine->rules_.size(); ++id) {
    const FilterRule& r = engine->rules_[id];
    if (r.exception) {
      if (r.types & kResourceDocument) engine->AddToIndex(&engine->document_exceptions_, id);
      if (r.types & ~kResourceDocument) engine->AddToIndex(&engine->exceptions_, id);
    } else if (r.important) {
      engine->AddToIndex(&engine->important_, id);
    } else {
      engine->AddToIndex(&engine->block_, id);
    }
  }
  engine->list_stats_ = result.lists;
  result.engine = engine;
  result.ok = true;
  return result;
}

void FilterEngine::AddToIndex(Index* index, std::uint32_t id) {
  const FilterRule& r = rules_[id];
  const std::string& p = r.pattern;
  if (r.domain_anchor && !r.host.empty()) {
    std::size_t hl = r.host.size();
    bool terminated = (hl < p.size() && (p[hl] == '^' || p[hl] == '/' || p[hl] == ':')) ||
                      (hl == p.size() && r.right_anchor);
    if (terminated) {
      index->by_host[r.host].push_back(id);
      return;
    }
  }
  // Pick the best complete token from the pattern.
  std::string lower = ToLowerAscii(p);
  std::string_view best;
  bool best_common = true;
  std::size_t i = 0;
  while (i < lower.size()) {
    while (i < lower.size() && !IsTokenChar(lower[i])) ++i;
    std::size_t s = i;
    while (i < lower.size() && IsTokenChar(lower[i])) ++i;
    if (i == s) break;
    if (s > 0 && lower[s - 1] == '*') continue;
    if (i < lower.size() && lower[i] == '*') continue;
    if (s == 0 && !r.left_anchor && !r.domain_anchor) continue;
    if (i == lower.size() && !r.right_anchor) continue;
    std::string_view tok = std::string_view(lower).substr(s, i - s);
    if (tok.size() < 2) continue;
    bool common = IsCommonToken(tok);
    if (best.empty() || (best_common && !common) ||
        (common == best_common && tok.size() > best.size())) {
      best = tok;
      best_common = common;
    }
  }
  if (best.empty()) {
    index->generic.push_back(id);
  } else {
    index->by_token[Fnv1a64(best)].push_back(id);
  }
}

bool FilterEngine::DomainsMatch(const FilterRule& rule, std::string_view fp_host) const {
  if (rule.domains.empty()) return true;
  std::size_t include_len = 0;
  std::size_t exclude_len = 0;
  bool has_include = false;
  std::string entity_base;
  bool entity_computed = false;
  for (const DomainConstraint& d : rule.domains) {
    if (!d.negated) has_include = true;
    if (fp_host.empty()) continue;
    bool match;
    if (d.entity) {
      if (!entity_computed) {
        std::string suffix = psl_->PublicSuffix(fp_host);
        std::string host(fp_host);
        if (!suffix.empty() && host.size() > suffix.size() + 1 && EndsWith(host, suffix)) {
          entity_base = host.substr(0, host.size() - suffix.size() - 1);
        }
        entity_computed = true;
      }
      match = !entity_base.empty() && HostMatchesDomain(entity_base, d.domain);
    } else {
      match = HostMatchesDomain(fp_host, d.domain);
    }
    if (!match) continue;
    std::size_t len = d.domain.size() + (d.entity ? 2 : 0);
    if (d.negated) exclude_len = std::max(exclude_len, len);
    else include_len = std::max(include_len, len);
  }
  if (has_include) return include_len > exclude_len;
  return exclude_len == 0;
}

bool FilterEngine::RuleMatches(const FilterRule& rule, const RequestInfo& req,
                               std::string_view url_lower) const {
  std::uint32_t types = rule.types | (rule.strict_document ? kResourceDocument : 0u);
  if (!(types & req.type)) return false;
  if (rule.party == PartyRequirement::kThirdParty && !req.third_party) return false;
  if (rule.party == PartyRequirement::kFirstParty && req.third_party) return false;
  if (!DomainsMatch(rule, req.first_party_host)) return false;
  if (rule.pure_host) {
    return HostMatchesDomain(req.request_host, rule.host);
  }
  std::string_view text = rule.match_case ? req.url : url_lower;
  std::size_t hb, he;
  HostBounds(text, &hb, &he);
  return MatchFilterPattern(rule.pattern, text, rule.left_anchor, rule.right_anchor,
                            hb, he, rule.domain_anchor);
}

const FilterRule* FilterEngine::FindIn(const Index& index, const RequestInfo& req,
                                       std::string_view url_lower,
                                       const std::vector<std::uint64_t>& tokens) const {
  if (!index.by_host.empty() && !req.request_host.empty()) {
    std::string_view h = req.request_host;
    while (true) {
      auto it = index.by_host.find(std::string(h));
      if (it != index.by_host.end()) {
        for (std::uint32_t id : it->second) {
          if (RuleMatches(rules_[id], req, url_lower)) return &rules_[id];
        }
      }
      std::size_t dot = h.find('.');
      if (dot == std::string_view::npos) break;
      h.remove_prefix(dot + 1);
    }
  }
  if (!index.by_token.empty()) {
    for (std::uint64_t t : tokens) {
      auto it = index.by_token.find(t);
      if (it == index.by_token.end()) continue;
      for (std::uint32_t id : it->second) {
        if (RuleMatches(rules_[id], req, url_lower)) return &rules_[id];
      }
    }
  }
  for (std::uint32_t id : index.generic) {
    if (RuleMatches(rules_[id], req, url_lower)) return &rules_[id];
  }
  return nullptr;
}

bool FilterEngine::IsDocumentAllowlisted(std::string_view first_party_url,
                                         std::string_view first_party_host) const {
  if (first_party_url.empty() ||
      (document_exceptions_.by_host.empty() && document_exceptions_.by_token.empty() &&
       document_exceptions_.generic.empty())) {
    return false;
  }
  RequestInfo doc;
  doc.url = first_party_url;
  doc.request_host = first_party_host;
  doc.first_party_host = first_party_host;
  doc.first_party_url = first_party_url;
  doc.type = kResourceDocument;
  doc.third_party = false;
  std::string lower = ToLowerAscii(first_party_url);
  std::vector<std::uint64_t> tokens;
  TokenizeUrl(lower, &tokens);
  return FindIn(document_exceptions_, doc, lower, tokens) != nullptr;
}

FilterMatch FilterEngine::Match(const RequestInfo& req) const {
  FilterMatch m;
  std::string lower = ToLowerAscii(req.url);
  std::vector<std::uint64_t> tokens;
  TokenizeUrl(lower, &tokens);

  auto fill = [&](const FilterRule* r) {
    m.rule = r;
    m.list_id = list_ids_[r->list_id];
    m.category = list_categories_[r->list_id];
  };

  if (const FilterRule* r = FindIn(important_, req, lower, tokens)) {
    m.decision = FilterDecision::kBlock;
    fill(r);
    return m;
  }
  const FilterRule* block = FindIn(block_, req, lower, tokens);
  if (!block) return m;
  fill(block);
  if (const FilterRule* ex = FindIn(exceptions_, req, lower, tokens)) {
    m.decision = FilterDecision::kAllowedByException;
    m.exception = ex;
    return m;
  }
  if (IsDocumentAllowlisted(req.first_party_url, req.first_party_host)) {
    m.decision = FilterDecision::kAllowedByException;
    return m;
  }
  m.decision = FilterDecision::kBlock;
  return m;
}

}  // namespace aegis

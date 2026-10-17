#include <algorithm>

#include "common/idna.h"
#include "common/strings.h"
#include "filtering/filter_rule.h"

namespace aegis {

std::string_view ResourceTypeName(ResourceType t) {
  switch (t) {
    case kResourceDocument: return "document";
    case kResourceSubdocument: return "subdocument";
    case kResourceStylesheet: return "stylesheet";
    case kResourceScript: return "script";
    case kResourceImage: return "image";
    case kResourceFont: return "font";
    case kResourceObject: return "object";
    case kResourceXhr: return "xmlhttprequest";
    case kResourcePing: return "ping";
    case kResourceMedia: return "media";
    case kResourceWebSocket: return "websocket";
    case kResourceOther: return "other";
    case kResourcePopup: return "popup";
    default: return "none";
  }
}

namespace {

struct TypeName {
  std::string_view name;
  std::uint32_t mask;
};

constexpr TypeName kTypeNames[] = {
    {"script", kResourceScript},
    {"image", kResourceImage},
    {"stylesheet", kResourceStylesheet},
    {"css", kResourceStylesheet},
    {"object", kResourceObject},
    {"object-subrequest", kResourceObject},
    {"xmlhttprequest", kResourceXhr},
    {"xhr", kResourceXhr},
    {"subdocument", kResourceSubdocument},
    {"frame", kResourceSubdocument},
    {"ping", kResourcePing},
    {"beacon", kResourcePing},
    {"media", kResourceMedia},
    {"font", kResourceFont},
    {"websocket", kResourceWebSocket},
    {"other", kResourceOther},
    {"document", kResourceDocument},
    {"doc", kResourceDocument},
    {"popup", kResourcePopup},
    {"all", kAllResourceTypes},
};

bool LookupType(std::string_view name, std::uint32_t* mask) {
  for (const auto& t : kTypeNames) {
    if (t.name == name) {
      *mask = t.mask;
      return true;
    }
  }
  return false;
}

// Options that only affect cosmetic filtering. Exception rules consisting
// solely of these have no network effect.
bool IsCosmeticOnlyOption(std::string_view o) {
  return o == "elemhide" || o == "ehide" || o == "generichide" ||
         o == "ghide" || o == "specifichide" || o == "shide" ||
         o == "genericblock" || o == "content";
}

// Options that change request/response semantics in ways WezCrypt Aegis
// does not implement. Applying such rules as plain blocks could break or
// mis-describe behaviour, so they are skipped and counted.
bool IsUnsupportedOption(std::string_view o) {
  static constexpr std::string_view kNames[] = {
      "csp", "removeparam", "queryprune", "redirect-rule", "header",
      "replace", "permissions", "urltransform", "uritransform", "to",
      "denyallow", "method", "sitekey", "strict1p", "strict3p",
      "inline-script", "inline-font", "webrtc", "cname", "rewrite",
      "urlskip", "requestheader", "responseheader", "ipaddress"};
  std::string_view key = o.substr(0, o.find('='));
  for (auto n : kNames) {
    if (key == n) return true;
  }
  return false;
}

bool IsCosmeticLine(std::string_view line) {
  static constexpr std::string_view kMarkers[] = {
      "##", "#@#", "#?#", "#@?#", "#$#", "#@$#", "#%#", "#@%#", "$$", "$@$"};
  for (auto m : kMarkers) {
    if (line.find(m) != std::string_view::npos) return true;
  }
  return false;
}

bool LooksLikeOptions(std::string_view s) {
  if (s.empty()) return false;
  for (char c : s) {
    if (!(IsAsciiAlnum(c) || c == '~' || c == ',' || c == '=' || c == '|' ||
          c == '.' || c == '*' || c == '_' || c == '-' || c == ':' || c == '[' ||
          c == ']' || static_cast<unsigned char>(c) >= 0x80)) {
      return false;
    }
  }
  return true;
}

bool IsHostChar(char c) {
  return IsAsciiAlnum(c) || c == '-' || c == '.' || c == '_';
}

// "0.0.0.0 ads.example.com" style lines.
bool ParseHostsLine(std::string_view line, std::string* host) {
  static constexpr std::string_view kPrefixes[] = {"0.0.0.0", "127.0.0.1", "::1", "::"};
  for (auto p : kPrefixes) {
    if (StartsWith(line, p) && line.size() > p.size() &&
        (line[p.size()] == ' ' || line[p.size()] == '\t')) {
      std::string_view rest = TrimAsciiWhitespace(line.substr(p.size()));
      std::size_t end = rest.find_first_of(" \t#");
      std::string_view h = rest.substr(0, end);
      if (h.empty() || h == "localhost" || h == "0.0.0.0" ||
          h == "localhost.localdomain" || h == "broadcasthost")
        return false;
      for (char c : h) {
        if (!IsHostChar(c)) return false;
      }
      *host = ToLowerAscii(h);
      return true;
    }
  }
  return false;
}

ParsedLine Invalid(std::string reason) {
  ParsedLine p;
  p.outcome = ParseOutcome::kInvalid;
  p.reason = std::move(reason);
  return p;
}

ParsedLine Unsupported(std::string reason) {
  ParsedLine p;
  p.outcome = ParseOutcome::kUnsupported;
  p.reason = std::move(reason);
  return p;
}

std::string NormalizeWildcards(std::string_view in) {
  std::string out;
  out.reserve(in.size());
  for (char c : in) {
    if (c == '*' && !out.empty() && out.back() == '*') continue;
    out.push_back(c);
  }
  return out;
}

}  // namespace

ParsedLine ParseFilterLine(std::string_view raw, std::uint16_t list_id,
                           const ParseLimits& limits) {
  std::string_view line = TrimAsciiWhitespace(raw);
  ParsedLine result;
  if (line.empty()) {
    result.outcome = ParseOutcome::kEmpty;
    return result;
  }
  if (line.size() > limits.max_line_bytes) return Invalid("line too long");
  if (line[0] == '!' || line[0] == '[' || line[0] == '#') {
    // '#' lines are hosts-file comments (cosmetic rules always contain a
    // selector before or after "##" and are detected below when they do not
    // start with '#'; "##.ad" with an empty domain list starts with '#').
    if (StartsWith(line, "##") || StartsWith(line, "#@#") || StartsWith(line, "#?#")) {
      result.outcome = ParseOutcome::kCosmetic;
      return result;
    }
    result.outcome = ParseOutcome::kComment;
    return result;
  }

  std::string hosts_host;
  if (ParseHostsLine(line, &hosts_host)) {
    FilterRule& r = result.rule;
    r.text = std::string(line);
    r.list_id = list_id;
    r.domain_anchor = true;
    r.host = hosts_host;
    r.pattern = hosts_host + "^";
    r.pure_host = true;
    r.strict_document = true;
    result.outcome = ParseOutcome::kRule;
    return result;
  }

  if (IsCosmeticLine(line)) {
    result.outcome = ParseOutcome::kCosmetic;
    return result;
  }

  FilterRule r;
  r.text = std::string(line);
  r.list_id = list_id;
  std::string_view body = line;
  if (StartsWith(body, "@@")) {
    r.exception = true;
    body.remove_prefix(2);
  }

  // Regular-expression rules are not supported: arbitrary regexes over
  // attacker-controlled URLs are a denial-of-service risk on the network
  // thread, and the major lists provide equivalent plain rules.
  if (body.size() > 2 && body.front() == '/') {
    std::size_t dollar = body.rfind('$');
    std::string_view pat = body;
    if (dollar != std::string_view::npos && dollar > 0 && body[dollar - 1] == '/') {
      pat = body.substr(0, dollar);
    }
    if (pat.size() > 2 && pat.back() == '/') return Unsupported("regular-expression rule");
  }

  std::string_view options;
  std::size_t dollar = body.rfind('$');
  if (dollar != std::string_view::npos && LooksLikeOptions(body.substr(dollar + 1))) {
    options = body.substr(dollar + 1);
    body = body.substr(0, dollar);
  }

  bool explicit_types = false;
  std::uint32_t include_types = 0;
  std::uint32_t exclude_types = 0;
  bool bad_filter = false;
  bool cosmetic_only = !options.empty();
  bool any_network_option = false;

  if (!options.empty()) {
    auto opts = Split(options, ',');
    if (opts.size() > limits.max_options) return Invalid("too many options");
    for (std::string_view raw_opt : opts) {
      std::string opt_lower = ToLowerAscii(TrimAsciiWhitespace(raw_opt));
      std::string_view opt = opt_lower;
      if (opt.empty()) return Invalid("empty option");
      if (IsCosmeticOnlyOption(opt)) continue;
      cosmetic_only = false;
      bool negated = false;
      if (opt[0] == '~') {
        negated = true;
        opt.remove_prefix(1);
      }
      std::uint32_t mask;
      if (LookupType(opt, &mask)) {
        explicit_types = true;
        any_network_option = true;
        if (negated) exclude_types |= mask;
        else include_types |= mask;
        continue;
      }
      if (opt == "third-party" || opt == "3p") {
        r.party = negated ? PartyRequirement::kFirstParty : PartyRequirement::kThirdParty;
        continue;
      }
      if (opt == "first-party" || opt == "1p") {
        r.party = negated ? PartyRequirement::kThirdParty : PartyRequirement::kFirstParty;
        continue;
      }
      if (negated) return Unsupported("negated option " + std::string(opt));
      if (opt == "match-case") {
        r.match_case = true;
        continue;
      }
      if (opt == "important") {
        r.important = true;
        continue;
      }
      if (opt == "badfilter") {
        bad_filter = true;
        continue;
      }
      if (StartsWith(opt, "domain=") || StartsWith(opt, "from=")) {
        std::string_view value = opt.substr(opt.find('=') + 1);
        auto entries = Split(value, '|');
        if (entries.size() > limits.max_domains) return Invalid("too many domains");
        for (std::string_view e : entries) {
          DomainConstraint dc;
          if (!e.empty() && e[0] == '~') {
            dc.negated = true;
            e.remove_prefix(1);
          }
          if (e.empty()) return Invalid("empty domain");
          if (EndsWith(e, ".*")) {
            dc.entity = true;
            e.remove_suffix(2);
          }
          if (e.find('*') != std::string_view::npos || e.find('/') != std::string_view::npos)
            return Unsupported("wildcard or regex domain constraint");
          auto ascii = idna::ToAscii(e);
          if (!ascii || ascii->empty()) return Invalid("bad domain");
          dc.domain = *ascii;
          r.domains.push_back(std::move(dc));
        }
        continue;
      }
      if (StartsWith(opt, "redirect=") || opt == "empty" || opt == "mp4" ||
          StartsWith(opt, "rewrite=abp-resource:")) {
        // Redirect-to-neutral-resource rules block the original request; the
        // request is cancelled instead of being replaced.
        continue;
      }
      if (IsUnsupportedOption(opt)) return Unsupported("option " + std::string(opt));
      return Unsupported("unknown option " + std::string(opt));
    }
  }
  (void)any_network_option;

  if (cosmetic_only) {
    result.outcome = ParseOutcome::kCosmetic;
    return result;
  }

  if (StartsWith(body, "||")) {
    r.domain_anchor = true;
    body.remove_prefix(2);
  } else if (StartsWith(body, "|")) {
    r.left_anchor = true;
    body.remove_prefix(1);
  }
  if (EndsWith(body, "|") && !body.empty()) {
    r.right_anchor = true;
    body.remove_suffix(1);
  }
  std::string pattern = NormalizeWildcards(body);
  if (!r.domain_anchor && !r.left_anchor) {
    while (!pattern.empty() && pattern.front() == '*') pattern.erase(pattern.begin());
  }
  if (r.domain_anchor && !pattern.empty() && pattern.front() == '*') {
    r.domain_anchor = false;
    while (!pattern.empty() && pattern.front() == '*') pattern.erase(pattern.begin());
  }
  if (!r.right_anchor) {
    while (!pattern.empty() && pattern.back() == '*') pattern.pop_back();
  }
  // A '|' inside the pattern is a literal character in ABP syntax.
  for (char c : pattern) {
    if (static_cast<unsigned char>(c) < 0x21) return Invalid("whitespace in pattern");
  }

  if (explicit_types) {
    std::uint32_t base = include_types ? include_types : (kDefaultRuleTypes);
    r.types = base & ~exclude_types;
    if (r.types == 0) return Invalid("rule matches no resource types");
  }

  bool has_positive_domain = std::any_of(r.domains.begin(), r.domains.end(),
                                         [](const DomainConstraint& d) { return !d.negated; });
  // Match-all rules ("*$...") must be narrowed by a site restriction or by
  // explicit resource types plus a party restriction ("*$ping,third-party").
  // "$script" or "*$third-party" alone would affect every request: refused.
  const bool narrowed = has_positive_domain ||
                        (explicit_types && r.party != PartyRequirement::kAny &&
                         !(r.types & kResourceDocument));
  if (pattern.empty() && !narrowed) {
    return Unsupported("match-all rule without domain or type restriction");
  }

  if (!r.match_case) pattern = ToLowerAscii(pattern);

  if (r.domain_anchor) {
    std::size_t end = 0;
    while (end < pattern.size() && IsHostChar(pattern[end])) ++end;
    bool host_ok = end > 0 && (end == pattern.size() || pattern[end] != '*');
    if (host_ok) {
      r.host = ToLowerAscii(pattern.substr(0, end));
      if (end == pattern.size() && r.right_anchor) {
        // "||host|" : exact-URL-end match, keep as pattern rule.
      } else if (pattern.size() == end + 1 && pattern[end] == '^') {
        r.pure_host = true;
      }
    }
  }
  r.pattern = std::move(pattern);
  r.strict_document = r.pure_host && !explicit_types && !r.exception &&
                      r.party == PartyRequirement::kAny && r.domains.empty();

  result.rule = std::move(r);
  result.outcome = bad_filter ? ParseOutcome::kBadFilter : ParseOutcome::kRule;
  return result;
}

std::string BadFilterKey(std::string_view text) {
  std::string_view t = TrimAsciiWhitespace(text);
  std::size_t dollar = t.rfind('$');
  std::string base(t);
  std::vector<std::string> opts;
  if (dollar != std::string_view::npos && LooksLikeOptions(t.substr(dollar + 1))) {
    base = std::string(t.substr(0, dollar));
    for (auto o : Split(t.substr(dollar + 1), ',')) {
      std::string lo = ToLowerAscii(TrimAsciiWhitespace(o));
      if (lo != "badfilter" && !lo.empty()) opts.push_back(lo);
    }
  }
  std::sort(opts.begin(), opts.end());
  std::string key = base;
  if (!opts.empty()) key += "$" + Join(opts, ",");
  return key;
}

}  // namespace aegis

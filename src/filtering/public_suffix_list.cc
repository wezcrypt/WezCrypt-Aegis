#include "filtering/public_suffix_list.h"

#include <vector>

#include "common/idna.h"
#include "common/strings.h"
#include "common/url.h"

namespace aegis {
namespace {

bool IsIpLiteral(std::string_view host) {
  if (host.find(':') != std::string_view::npos) return true;  // IPv6
  return ParseIPv4(host).has_value() &&
         !host.empty() && IsAsciiDigit(host.back());
}

// Returns positions of the start of each label, last label last.
std::vector<std::size_t> LabelStarts(std::string_view host) {
  std::vector<std::size_t> starts;
  starts.push_back(0);
  for (std::size_t i = 0; i < host.size(); ++i) {
    if (host[i] == '.') starts.push_back(i + 1);
  }
  return starts;
}

}  // namespace

bool PublicSuffixList::Load(std::string_view text, PslLoadStats* stats,
                            const PslLimits& limits) {
  if (text.size() > limits.max_bytes) return false;
  std::unordered_set<std::string> rules, wildcards, exceptions;
  PslLoadStats st;
  for (std::string_view raw : SplitLines(text)) {
    std::string_view line = TrimAsciiWhitespace(raw);
    if (line.empty() || StartsWith(line, "//")) continue;
    // Rules end at the first whitespace.
    std::size_t ws = line.find_first_of(" \t");
    if (ws != std::string_view::npos) line = line.substr(0, ws);
    if (line.size() > limits.max_line_bytes) {
      ++st.rejected_lines;
      continue;
    }
    bool exception = false;
    bool wildcard = false;
    if (line[0] == '!') {
      exception = true;
      line.remove_prefix(1);
    } else if (StartsWith(line, "*.")) {
      wildcard = true;
      line.remove_prefix(2);
    }
    if (line.empty() || line.find('*') != std::string_view::npos) {
      ++st.rejected_lines;
      continue;
    }
    auto ascii = idna::ToAscii(line);
    if (!ascii || ascii->empty() || ascii->front() == '.' || ascii->back() == '.') {
      ++st.rejected_lines;
      continue;
    }
    if (exception) {
      exceptions.insert(*ascii);
      ++st.exception_rules;
    } else if (wildcard) {
      wildcards.insert(*ascii);
      ++st.wildcard_rules;
    } else {
      rules.insert(*ascii);
    }
    if (++st.rules > limits.max_rules) return false;
  }
  if (st.rules == 0) return false;
  rules_ = std::move(rules);
  wildcards_ = std::move(wildcards);
  exceptions_ = std::move(exceptions);
  if (stats) *stats = st;
  return true;
}

std::size_t PublicSuffixList::SuffixLabelCount(std::string_view host) const {
  const std::vector<std::size_t> starts = LabelStarts(host);
  const std::size_t n = starts.size();
  // Exception rules take priority: the public suffix is the exception rule
  // with its leftmost label removed.
  for (std::size_t i = 0; i < n; ++i) {
    std::string candidate(host.substr(starts[i]));
    if (exceptions_.count(candidate)) return n - i - 1;
  }
  // Otherwise the longest matching normal or wildcard rule wins.
  for (std::size_t i = 0; i < n; ++i) {
    std::string_view candidate = host.substr(starts[i]);
    if (rules_.count(std::string(candidate))) return n - i;
    if (i + 1 < n) {
      std::string parent(host.substr(starts[i + 1]));
      if (wildcards_.count(parent)) return n - i;
    }
  }
  return 1;  // implicit "*" rule
}

std::string PublicSuffixList::PublicSuffix(std::string_view host_in) const {
  std::string host = NormalizeHostForMatching(host_in);
  if (host.empty() || IsIpLiteral(host)) return {};
  const std::vector<std::size_t> starts = LabelStarts(host);
  std::size_t count = SuffixLabelCount(host);
  if (count == 0 || count > starts.size()) return host;
  return host.substr(starts[starts.size() - count]);
}

std::string PublicSuffixList::RegistrableDomain(std::string_view host_in) const {
  std::string host = NormalizeHostForMatching(host_in);
  if (host.empty() || IsIpLiteral(host)) return {};
  for (std::string_view label : Split(host, '.')) {
    if (label.empty()) return {};  // malformed ("a..b")
  }
  const std::vector<std::size_t> starts = LabelStarts(host);
  std::size_t count = SuffixLabelCount(host);
  if (count >= starts.size()) return {};
  return host.substr(starts[starts.size() - count - 1]);
}

std::string PublicSuffixList::SiteForHost(std::string_view host) const {
  std::string reg = RegistrableDomain(host);
  return reg.empty() ? NormalizeHostForMatching(host) : reg;
}

bool PublicSuffixList::IsThirdParty(std::string_view request_host,
                                    std::string_view top_level_host) const {
  if (top_level_host.empty()) return true;
  return SiteForHost(request_host) != SiteForHost(top_level_host);
}

}  // namespace aegis

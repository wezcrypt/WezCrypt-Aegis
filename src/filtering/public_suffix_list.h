// WezCrypt Aegis - Public Suffix List (https://publicsuffix.org/).
//
// Used to compute registrable domains ("eTLD+1") so that first-party /
// third-party relationships are decided the same way browsers decide
// cookie and site boundaries. Both ICANN and PRIVATE sections are honoured,
// which means e.g. "alice.github.io" and "bob.github.io" are different sites.
#pragma once

#include <cstddef>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_set>

namespace aegis {

struct PslLoadStats {
  std::size_t rules = 0;
  std::size_t wildcard_rules = 0;
  std::size_t exception_rules = 0;
  std::size_t rejected_lines = 0;
};

struct PslLimits {
  std::size_t max_bytes = 4 * 1024 * 1024;
  std::size_t max_rules = 200'000;
  std::size_t max_line_bytes = 512;
};

class PublicSuffixList {
 public:
  PublicSuffixList() = default;

  // Parses PSL text (UTF-8). Returns false if the input exceeds limits or
  // yields no rules; on failure the object is left unchanged.
  bool Load(std::string_view text, PslLoadStats* stats = nullptr,
            const PslLimits& limits = PslLimits());

  bool empty() const { return rules_.empty() && wildcards_.empty(); }

  // Returns the public suffix of |host| (lower-case ASCII). For hosts not
  // covered by any rule the implicit "*" rule applies (the last label).
  std::string PublicSuffix(std::string_view host) const;

  // Returns the registrable domain (eTLD+1), or an empty string when the host
  // is itself a public suffix, an IP literal or empty.
  std::string RegistrableDomain(std::string_view host) const;

  // "Site" used for first/third-party decisions: the registrable domain,
  // or the full host when there is none (IP literals, bare suffixes,
  // single-label intranet names).
  std::string SiteForHost(std::string_view host) const;

  bool IsThirdParty(std::string_view request_host,
                    std::string_view top_level_host) const;

 private:
  // Returns the number of labels in the public suffix of |labels_host|.
  std::size_t SuffixLabelCount(std::string_view host) const;

  std::unordered_set<std::string> rules_;       // "co.uk"
  std::unordered_set<std::string> wildcards_;   // "ck" for "*.ck"
  std::unordered_set<std::string> exceptions_;  // "www.ck" for "!www.ck"
};

}  // namespace aegis

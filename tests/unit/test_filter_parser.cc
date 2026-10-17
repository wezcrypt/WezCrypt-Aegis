#include "filtering/filter_rule.h"
#include "test_framework.h"

using namespace aegis;

TEST(FilterParser, ClassifiesLineKinds) {
  EXPECT_EQ(ParseFilterLine("! comment", 0).outcome, ParseOutcome::kComment);
  EXPECT_EQ(ParseFilterLine("[Adblock Plus 2.0]", 0).outcome, ParseOutcome::kComment);
  EXPECT_EQ(ParseFilterLine("   ", 0).outcome, ParseOutcome::kEmpty);
  EXPECT_EQ(ParseFilterLine("example.com##.ad-banner", 0).outcome, ParseOutcome::kCosmetic);
  EXPECT_EQ(ParseFilterLine("##.ad", 0).outcome, ParseOutcome::kCosmetic);
  EXPECT_EQ(ParseFilterLine("example.com#@#.ad", 0).outcome, ParseOutcome::kCosmetic);
  EXPECT_EQ(ParseFilterLine("example.com##+js(aopr, x)", 0).outcome, ParseOutcome::kCosmetic);
  EXPECT_EQ(ParseFilterLine("@@||example.com^$elemhide", 0).outcome, ParseOutcome::kCosmetic);
  EXPECT_EQ(ParseFilterLine("/banner[0-9]+/", 0).outcome, ParseOutcome::kUnsupported);
  EXPECT_NE(ParseFilterLine("||example.com^$csp=script-src 'none'", 0).outcome,
            ParseOutcome::kRule);
  EXPECT_EQ(ParseFilterLine("||example.com^$csp=default-src", 0).outcome, ParseOutcome::kUnsupported);
  // ABP: a pattern enclosed in slashes is a regular expression.
  EXPECT_EQ(ParseFilterLine("/sponsor/$image", 0).outcome, ParseOutcome::kUnsupported);
  EXPECT_EQ(ParseFilterLine("/sponsor/*$image", 0).outcome, ParseOutcome::kRule);
  EXPECT_EQ(ParseFilterLine("||example.com^$removeparam=utm_source", 0).outcome,
            ParseOutcome::kUnsupported);
  EXPECT_EQ(ParseFilterLine("||example.com^$frobnicate", 0).outcome, ParseOutcome::kUnsupported);
  EXPECT_EQ(ParseFilterLine("||ads.example^$badfilter", 0).outcome, ParseOutcome::kBadFilter);
}

TEST(FilterParser, ParsesDomainAnchoredHostRule) {
  ParsedLine p = ParseFilterLine("||ads.example.com^", 3);
  ASSERT_TRUE(p.outcome == ParseOutcome::kRule);
  EXPECT_TRUE(p.rule.domain_anchor);
  EXPECT_TRUE(p.rule.pure_host);
  EXPECT_TRUE(p.rule.strict_document);
  EXPECT_EQ(p.rule.host, std::string("ads.example.com"));
  EXPECT_EQ(p.rule.list_id, 3);
  EXPECT_EQ(p.rule.types, kDefaultRuleTypes);
}

TEST(FilterParser, ParsesOptions) {
  ParsedLine p = ParseFilterLine(
      "||tracker.example^$script,image,third-party,domain=a.com|~b.a.com|shop.*,important", 0);
  ASSERT_TRUE(p.outcome == ParseOutcome::kRule);
  EXPECT_EQ(p.rule.types, static_cast<std::uint32_t>(kResourceScript | kResourceImage));
  EXPECT_TRUE(p.rule.party == PartyRequirement::kThirdParty);
  EXPECT_TRUE(p.rule.important);
  EXPECT_FALSE(p.rule.strict_document);
  ASSERT_TRUE(p.rule.domains.size() == 3);
  EXPECT_EQ(p.rule.domains[0].domain, std::string("a.com"));
  EXPECT_TRUE(p.rule.domains[1].negated);
  EXPECT_TRUE(p.rule.domains[2].entity);

  ParsedLine neg = ParseFilterLine("/ads/*$~script,~image", 0);
  ASSERT_TRUE(neg.outcome == ParseOutcome::kRule);
  EXPECT_EQ(neg.rule.types & (kResourceScript | kResourceImage), 0u);
  EXPECT_TRUE((neg.rule.types & kResourceStylesheet) != 0);

  ParsedLine fp = ParseFilterLine("||x.example^$~third-party", 0);
  EXPECT_TRUE(fp.rule.party == PartyRequirement::kFirstParty);
  ParsedLine popup = ParseFilterLine("||pop.example^$popup", 0);
  EXPECT_EQ(popup.rule.types, static_cast<std::uint32_t>(kResourcePopup));
  ParsedLine ex = ParseFilterLine("@@||good.example^$document", 0);
  EXPECT_TRUE(ex.rule.exception);
  EXPECT_EQ(ex.rule.types, static_cast<std::uint32_t>(kResourceDocument));
  ParsedLine redirect = ParseFilterLine("||ads.example/a.js$script,redirect=noop.js", 0);
  EXPECT_EQ(redirect.outcome, ParseOutcome::kRule);
}

TEST(FilterParser, RefusesOverBroadAndMalformedRules) {
  EXPECT_EQ(ParseFilterLine("$script", 0).outcome, ParseOutcome::kUnsupported);
  EXPECT_EQ(ParseFilterLine("*$third-party", 0).outcome, ParseOutcome::kUnsupported);
  EXPECT_EQ(ParseFilterLine("*$ping,third-party", 0).outcome, ParseOutcome::kRule);
  EXPECT_EQ(ParseFilterLine("*$script,domain=example.com", 0).outcome, ParseOutcome::kRule);
  EXPECT_EQ(ParseFilterLine("||a.example^$script,~script", 0).outcome, ParseOutcome::kInvalid);
  EXPECT_EQ(ParseFilterLine("||a.example^$domain=", 0).outcome, ParseOutcome::kInvalid);
  EXPECT_EQ(ParseFilterLine(std::string(70000, 'a'), 0).outcome, ParseOutcome::kInvalid);
  // '|' inside a pattern is literal.
  EXPECT_EQ(ParseFilterLine("/adiframe|*|adtech;", 0).outcome, ParseOutcome::kRule);
  // IPv6 literals in domain options.
  ParsedLine v6 = ParseFilterLine("||0.0.0.0^$third-party,domain=~127.0.0.1|~[::1]", 0);
  EXPECT_EQ(v6.outcome, ParseOutcome::kRule);
}

TEST(FilterParser, HostsFileLines) {
  ParsedLine p = ParseFilterLine("0.0.0.0 ads.tracker.example  # comment", 0);
  ASSERT_TRUE(p.outcome == ParseOutcome::kRule);
  EXPECT_TRUE(p.rule.pure_host);
  EXPECT_EQ(p.rule.host, std::string("ads.tracker.example"));
  EXPECT_NE(ParseFilterLine("127.0.0.1 localhost", 0).outcome, ParseOutcome::kRule);
}

TEST(FilterParser, BadFilterKeyIsOrderInsensitive) {
  EXPECT_EQ(BadFilterKey("||a.example^$script,third-party,badfilter"),
            BadFilterKey("||a.example^$third-party,script"));
}

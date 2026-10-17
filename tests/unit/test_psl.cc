#include "filtering/public_suffix_list.h"
#include "test_support.h"

using namespace aegis;
using aegis_test::RealPsl;

TEST(PublicSuffixList, SyntheticRules) {
  PublicSuffixList psl;
  ASSERT_TRUE(psl.Load("// comment\ncom\nuk\nco.uk\n*.ck\n!www.ck\n\xe4\xb8\xad\xe5\x9b\xbd\n"));
  EXPECT_EQ(psl.RegistrableDomain("www.example.com"), std::string("example.com"));
  EXPECT_EQ(psl.RegistrableDomain("a.b.example.co.uk"), std::string("example.co.uk"));
  EXPECT_EQ(psl.RegistrableDomain("co.uk"), std::string(""));
  EXPECT_EQ(psl.RegistrableDomain("foo.bar.ck"), std::string("foo.bar.ck"));
  EXPECT_EQ(psl.PublicSuffix("foo.bar.ck"), std::string("bar.ck"));
  EXPECT_EQ(psl.RegistrableDomain("www.ck"), std::string("www.ck"));
  EXPECT_EQ(psl.RegistrableDomain("a.www.ck"), std::string("www.ck"));
  // Unicode rule stored as punycode.
  EXPECT_EQ(psl.RegistrableDomain("shop.xn--fiqs8s"), std::string("shop.xn--fiqs8s"));
  // Unknown TLD: implicit "*" rule.
  EXPECT_EQ(psl.RegistrableDomain("a.b.unknowntld"), std::string("b.unknowntld"));
  EXPECT_EQ(psl.RegistrableDomain("example.com."), std::string("example.com"));
  EXPECT_EQ(psl.RegistrableDomain("127.0.0.1"), std::string(""));
  EXPECT_EQ(psl.RegistrableDomain("a..example.com"), std::string(""));
}

TEST(PublicSuffixList, RejectsOversizedInput) {
  PublicSuffixList psl;
  PslLimits limits;
  limits.max_bytes = 16;
  EXPECT_FALSE(psl.Load("com\nnet\norg\nexample\nfoo\n", nullptr, limits));
  EXPECT_FALSE(psl.Load("// only comments\n"));
  EXPECT_TRUE(psl.empty());
}

TEST(PublicSuffixList, RealListOfficialTestVectors) {
  // Subset of https://raw.githubusercontent.com/publicsuffix/list/main/tests/test_psl.txt
  auto psl = RealPsl();
  ASSERT_TRUE(psl && !psl->empty());
  struct V { const char* host; const char* reg; };
  const V vectors[] = {
      {"com", ""},
      {"example.com", "example.com"},
      {"www.example.com", "example.com"},
      {"uk.com", ""},
      {"example.uk.com", "example.uk.com"},
      {"b.example.uk.com", "example.uk.com"},
      {"ac", ""},
      {"mm", ""},
      {"c.mm", ""},
      {"b.c.mm", "b.c.mm"},
      {"a.b.c.mm", "b.c.mm"},
      {"jp", ""},
      {"test.jp", "test.jp"},
      {"www.test.jp", "test.jp"},
      {"ac.jp", ""},
      {"test.ac.jp", "test.ac.jp"},
      {"kyoto.jp", ""},
      {"test.kyoto.jp", "test.kyoto.jp"},
      {"ide.kyoto.jp", ""},
      {"b.ide.kyoto.jp", "b.ide.kyoto.jp"},
      {"c.kobe.jp", ""},
      {"b.c.kobe.jp", "b.c.kobe.jp"},
      {"city.kobe.jp", "city.kobe.jp"},
      {"www.city.kobe.jp", "city.kobe.jp"},
      {"ck", ""},
      {"test.ck", ""},
      {"b.test.ck", "b.test.ck"},
      {"www.ck", "www.ck"},
      {"www.www.ck", "www.ck"},
      {"us", ""},
      {"test.us", "test.us"},
      {"ak.us", ""},
      {"test.ak.us", "test.ak.us"},
      {"k12.ak.us", ""},
      {"test.k12.ak.us", "test.k12.ak.us"},
      {"xn--85x722f.com.cn", "xn--85x722f.com.cn"},
      {"xn--55qx5d.cn", ""},
      {"xn--85x722f.xn--55qx5d.cn", "xn--85x722f.xn--55qx5d.cn"},
      {"shishi.xn--fiqs8s", "shishi.xn--fiqs8s"},
      {"xn--fiqs8s", ""},
  };
  for (const auto& v : vectors) {
    EXPECT_EQ(psl->RegistrableDomain(v.host), std::string(v.reg));
  }
}

TEST(PublicSuffixList, ThirdPartyDecisions) {
  auto psl = RealPsl();
  EXPECT_FALSE(psl->IsThirdParty("cdn.example.com", "www.example.com"));
  EXPECT_TRUE(psl->IsThirdParty("ads.adnetwork.example", "news.example.com"));
  // Private-section suffixes make tenants separate sites.
  EXPECT_TRUE(psl->IsThirdParty("alice.github.io", "bob.github.io"));
  EXPECT_FALSE(psl->IsThirdParty("x.alice.github.io", "alice.github.io"));
  EXPECT_TRUE(psl->IsThirdParty("example.com.evil.net", "example.com"));
  EXPECT_TRUE(psl->IsThirdParty("anything.example", ""));
  EXPECT_FALSE(psl->IsThirdParty("EXAMPLE.com.", "www.example.COM"));
}

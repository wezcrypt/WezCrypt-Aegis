#include "common/idna.h"
#include "common/url.h"
#include "common/utf8.h"
#include "test_framework.h"

using namespace aegis;

TEST(Url, ParsesHierarchicalUrls) {
  auto u = ParseUrl("HTTPS://User:Pw@Example.COM:8443/a/b?q=1#frag");
  ASSERT_TRUE(u.has_value());
  EXPECT_EQ(u->scheme, std::string("https"));
  EXPECT_EQ(u->host, std::string("example.com"));
  EXPECT_TRUE(u->has_credentials);
  EXPECT_EQ(u->port, 8443);
  EXPECT_EQ(u->path, std::string("/a/b"));
  EXPECT_EQ(u->query, std::string("q=1"));
  EXPECT_EQ(u->fragment, std::string("frag"));
  EXPECT_EQ(u->Origin(), std::string("https://example.com:8443"));
  EXPECT_EQ(u->Spec(), std::string("https://example.com:8443/a/b?q=1#frag"));  // no credentials
}

TEST(Url, DefaultPortIsDropped) {
  auto u = ParseUrl("http://example.com:80");
  ASSERT_TRUE(u.has_value());
  EXPECT_EQ(u->port, -1);
  EXPECT_EQ(u->path, std::string("/"));
  EXPECT_EQ(u->EffectivePort(), 80);
}

TEST(Url, CredentialsDoNotConfuseHost) {
  // The real host is evil.example, not good.example.
  auto u = ParseUrl("https://good.example@evil.example/login");
  ASSERT_TRUE(u.has_value());
  EXPECT_EQ(u->host, std::string("evil.example"));
  auto v = ParseUrl("https://good.example:443@evil.example/");
  ASSERT_TRUE(v.has_value());
  EXPECT_EQ(v->host, std::string("evil.example"));
}

TEST(Url, BackslashesInSpecialSchemes) {
  auto u = ParseUrl("https:\\\\evil.example\\path");
  ASSERT_TRUE(u.has_value());
  EXPECT_EQ(u->host, std::string("evil.example"));
  EXPECT_EQ(u->path, std::string("/path"));
}

TEST(Url, Ipv4NumericFormsCanonicalize) {
  auto a = ParseUrl("http://0x7f.1/");
  ASSERT_TRUE(a.has_value());
  EXPECT_EQ(a->host, std::string("127.0.0.1"));
  EXPECT_EQ(a->host_type, HostType::kIPv4);
  auto b = ParseUrl("http://2130706433/");
  ASSERT_TRUE(b.has_value());
  EXPECT_EQ(b->host, std::string("127.0.0.1"));
  auto c = ParseUrl("http://0177.0.0.1/");
  ASSERT_TRUE(c.has_value());
  EXPECT_EQ(c->host, std::string("127.0.0.1"));
  EXPECT_FALSE(ParseUrl("http://256.1.1.1/").has_value());
  EXPECT_FALSE(ParseUrl("http://1.2.3.4.5/").has_value());
}

TEST(Url, Ipv6Literals) {
  auto u = ParseUrl("http://[::1]:8080/x");
  ASSERT_TRUE(u.has_value());
  EXPECT_EQ(u->host, std::string("::1"));
  EXPECT_EQ(u->host_type, HostType::kIPv6);
  EXPECT_EQ(u->Origin(), std::string("http://[::1]:8080"));
  EXPECT_FALSE(ParseUrl("http://[::1/").has_value());
  EXPECT_FALSE(ParseUrl("http://[1:2:3:4:5:6:7:8:9]/").has_value());
  EXPECT_TRUE(IsValidIPv6Literal("2001:db8::ff00:42:8329"));
  EXPECT_TRUE(IsValidIPv6Literal("::ffff:192.0.2.1"));
  EXPECT_FALSE(IsValidIPv6Literal("1::2::3"));
}

TEST(Url, RejectsAmbiguousInput) {
  EXPECT_FALSE(ParseUrl("http:example.com").has_value());
  EXPECT_FALSE(ParseUrl("https://exa mple.com/").has_value());
  EXPECT_FALSE(ParseUrl("https://exa%41mple.com/").has_value());
  EXPECT_FALSE(ParseUrl("https://example.com\n/").has_value());
  EXPECT_FALSE(ParseUrl("https://:443/").has_value());
  EXPECT_FALSE(ParseUrl("https://example.com:99999/").has_value());
  EXPECT_FALSE(ParseUrl("1http://x").has_value());
  EXPECT_FALSE(ParseUrl("").has_value());
}

TEST(Url, NonHierarchicalSchemes) {
  auto d = ParseUrl("data:text/html,<b>x</b>");
  ASSERT_TRUE(d.has_value());
  EXPECT_EQ(d->scheme, std::string("data"));
  EXPECT_FALSE(d->has_authority);
  auto b = ParseUrl("blob:https://site.example/uuid-1");
  ASSERT_TRUE(b.has_value());
  auto inner = InnerUrlOfBlob(*b);
  ASSERT_TRUE(inner.has_value());
  EXPECT_EQ(inner->host, std::string("site.example"));
}

TEST(Url, LocalAndPrivateHosts) {
  for (const char* s : {"http://localhost/", "http://app.localhost/", "http://127.0.0.1/",
                        "http://10.1.2.3/", "http://192.168.1.1/", "http://172.20.0.1/",
                        "http://169.254.1.1/", "http://[::1]/", "http://[fd00::1]/",
                        "http://[fe80::1]/", "http://100.64.0.1/", "http://0x7f.1/"}) {
    auto u = ParseUrl(s);
    ASSERT_TRUE(u.has_value());
    EXPECT_TRUE(IsLocalOrPrivateHost(*u));
  }
  for (const char* s : {"http://8.8.8.8/", "https://example.com/", "http://172.32.0.1/",
                        "http://[2001:db8::1]/"}) {
    auto u = ParseUrl(s);
    ASSERT_TRUE(u.has_value());
    EXPECT_FALSE(IsLocalOrPrivateHost(*u));
  }
}

TEST(Idna, PunycodeRfc3492Vectors) {
  // "bücher" -> "bcher-kva"
  std::vector<char32_t> buecher = {'b', 0xFC, 'c', 'h', 'e', 'r'};
  auto enc = idna::PunycodeEncode(buecher);
  ASSERT_TRUE(enc.has_value());
  EXPECT_EQ(*enc, std::string("bcher-kva"));
  auto dec = idna::PunycodeDecode("bcher-kva");
  ASSERT_TRUE(dec.has_value());
  EXPECT_TRUE(*dec == buecher);
  // RFC 3492 7.1 (L) Japanese example: 3<nen>B<gumi><kinpachi><sensei>
  auto jp = idna::PunycodeDecode("3B-ww4c5e180e575a65lsy2b");
  ASSERT_TRUE(jp.has_value());
  EXPECT_EQ(EncodeUtf8(*jp), std::string("3\xe5\xb9\xb4" "B\xe7\xb5\x84\xe9\x87\x91\xe5\x85\xab"
                                         "\xe5\x85\x88\xe7\x94\x9f"));
  EXPECT_FALSE(idna::PunycodeDecode("99999999999999999999").has_value());
}

TEST(Idna, ToAsciiConvertsUnicodeHosts) {
  auto a = idna::ToAscii("B\xc3\xbc" "cher.Example");
  ASSERT_TRUE(a.has_value());
  EXPECT_EQ(*a, std::string("xn--bcher-kva.example"));
  auto u = ParseUrl("https://b\xc3\xbc" "cher.example/");
  ASSERT_TRUE(u.has_value());
  EXPECT_EQ(u->host, std::string("xn--bcher-kva.example"));
  // Zero-width joiner in a host is rejected outright.
  EXPECT_FALSE(idna::ToAscii("pay\xe2\x80\x8dpal.com").has_value());
}

TEST(Idna, DisplayPolicyBlocksHomographs) {
  // "аррӏе.com" (Cyrillic look-alike of apple.com) must not render as Unicode.
  auto spoof = idna::ToAscii("\xd0\xb0\xd1\x80\xd1\x80\xd3\x8f\xd0\xb5.com");
  ASSERT_TRUE(spoof.has_value());
  auto d1 = idna::ForDisplay(*spoof);
  EXPECT_TRUE(d1.is_idn);
  EXPECT_TRUE(d1.spoof_risk);
  EXPECT_EQ(d1.text, *spoof);
  // Mixed Latin + Cyrillic ("pаypal" with Cyrillic 'а').
  auto mixed = idna::ToAscii("p\xd0\xb0ypal.com");
  ASSERT_TRUE(mixed.has_value());
  EXPECT_TRUE(idna::ForDisplay(*mixed).spoof_risk);
  // A legitimate single-script German IDN is shown in Unicode.
  auto d2 = idna::ForDisplay("xn--bcher-kva.example");
  EXPECT_FALSE(d2.spoof_risk);
  EXPECT_EQ(d2.text, std::string("b\xc3\xbc" "cher.example"));
  // Plain ASCII hosts are untouched.
  EXPECT_FALSE(idna::ForDisplay("example.com").is_idn);
}

// Parser robustness: deterministic pseudo-random and adversarial inputs for
// every parser that handles untrusted data. Tests assert absence of crashes,
// bounded work and invariant preservation; run them under ASan/UBSan with
// -DAEGIS_ENABLE_SANITIZERS=ON.
#include <chrono>
#include <random>

#include "common/base64.h"
#include "common/idna.h"
#include "common/json.h"
#include "common/url.h"
#include "common/utf8.h"
#include "downloads/download_safety.h"
#include "filtering/filter_rule.h"
#include "security/security_policy.h"
#include "storage/settings.h"
#include "test_support.h"
#include "ui/omnibox.h"
#include "updates/update_verifier.h"

using namespace aegis;

namespace {

std::string RandomBytes(std::mt19937_64& rng, std::size_t max_len, bool printable) {
  std::uniform_int_distribution<std::size_t> len_dist(0, max_len);
  std::size_t n = len_dist(rng);
  std::string s(n, '\0');
  static const char kAlphabet[] =
      "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
      ":/?#[]@!$&'()*+,;=.-_~%^|\\\"{}<> \t\n\r\x01\x7f\xc3\xa9\xe2\x80\xae\xf0\x9f\x98\x80";
  for (auto& c : s) {
    if (printable) {
      c = kAlphabet[rng() % (sizeof(kAlphabet) - 1)];
    } else {
      c = static_cast<char>(rng() & 0xFF);
    }
  }
  return s;
}

std::string Mutate(std::mt19937_64& rng, std::string s) {
  int ops = 1 + static_cast<int>(rng() % 4);
  for (int i = 0; i < ops && !s.empty(); ++i) {
    std::size_t pos = rng() % s.size();
    switch (rng() % 4) {
      case 0: s[pos] = static_cast<char>(rng() & 0xFF); break;
      case 1: s.erase(pos, 1); break;
      case 2: s.insert(pos, 1, "*^|$~,=@#:/."[rng() % 12]); break;
      case 3: s.insert(pos, s.substr(0, std::min<std::size_t>(s.size(), 16))); break;
    }
  }
  return s;
}

}  // namespace

TEST(Robustness, UrlParserNeverCrashesAndRoundTrips) {
  std::mt19937_64 rng(0xAE615);
  const char* seeds[] = {"https://user:pw@host.example:8080/p/a/t/h?query=1#frag",
                         "http://[::ffff:127.0.0.1]/", "http://0x7f.0.0.1/", "blob:https://a/b",
                         "file:///C:/x", "data:,x", "https://xn--bcher-kva.example/"};
  for (int i = 0; i < 20000; ++i) {
    std::string in = (i % 2) ? RandomBytes(rng, 200, true) : Mutate(rng, seeds[i % 7]);
    auto u = ParseUrl(in);
    if (u && u->has_authority && (u->IsHttpLike())) {
      // Re-parsing the serialization must yield the same host and scheme.
      auto again = ParseUrl(u->Spec());
      ASSERT_TRUE(again.has_value());
      EXPECT_EQ(again->host, u->host);
      EXPECT_EQ(again->scheme, u->scheme);
    }
  }
}

TEST(Robustness, JsonParserRejectsGarbageSafely) {
  std::mt19937_64 rng(42);
  const std::string seed = R"({"a":[1,2,{"b":"c\u0041"}],"d":true,"e":null,"f":-1.5e3})";
  for (int i = 0; i < 20000; ++i) {
    std::string in = (i % 3) ? Mutate(rng, seed) : RandomBytes(rng, 128, false);
    auto v = json::Parse(in);
    if (v) {
      auto again = json::Parse(json::Serialize(*v));
      ASSERT_TRUE(again.has_value());
      EXPECT_EQ(json::Serialize(*again), json::Serialize(*v));
    }
  }
  // Pathological nesting is bounded.
  std::string bomb;
  for (int i = 0; i < 100000; ++i) bomb += "{\"a\":";
  EXPECT_FALSE(json::Parse(bomb).has_value());
}

TEST(Robustness, FilterParserHandlesHostileLines) {
  std::mt19937_64 rng(7);
  const char* seeds[] = {"||ads.example^$script,third-party,domain=a.com|~b.com",
                         "@@||x.example/path*$document", "/regex[0-9]+/$image",
                         "example.com##.ad", "|https://x.example/*^|", "0.0.0.0 host.example"};
  std::string list = "[Adblock Plus 2.0]\n";
  for (int i = 0; i < 20000; ++i) {
    std::string line = (i % 2) ? Mutate(rng, seeds[i % 6]) : RandomBytes(rng, 120, true);
    ParsedLine p = ParseFilterLine(line, 0);
    if (p.outcome == ParseOutcome::kRule) {
      EXPECT_TRUE(p.rule.types != 0);
      EXPECT_TRUE(p.rule.pattern.size() <= line.size() + 1);
    }
    if (i < 3000) list += line + "\n";
  }
  // Building an engine from the fuzzed list and matching must not crash.
  FilterListSource src;
  src.id = "fuzz";
  src.text = list;
  auto built = FilterEngine::Build({src}, aegis_test::RealPsl());
  ASSERT_TRUE(built.ok);
  for (int i = 0; i < 2000; ++i) {
    auto r = aegis_test::MakeReq("https://" + std::to_string(i) + ".example/" + RandomBytes(rng, 60, true),
                                 "https://top.example/", kResourceScript);
    built.engine->Match(r.info);
  }
}

TEST(Robustness, PatternMatchingIsNotExponential) {
  // A classic catastrophic-backtracking shape for naive matchers.
  std::string rule = "a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*b";
  auto engine = aegis_test::EngineFromRules(rule + "\n");
  std::string url = "https://x.example/" + std::string(4000, 'a');
  auto t0 = std::chrono::steady_clock::now();
  for (int i = 0; i < 20; ++i) {
    auto r = aegis_test::MakeReq(url, "https://top.example/", kResourceImage);
    EXPECT_TRUE(engine->Match(r.info).decision == FilterDecision::kNoMatch);
  }
  double ms = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t0).count();
  EXPECT_TRUE(ms < 5000.0);
}

TEST(Robustness, IdnaAndPunycodeHostileInput) {
  std::mt19937_64 rng(99);
  for (int i = 0; i < 20000; ++i) {
    std::string in = RandomBytes(rng, 80, i % 2 == 0);
    auto dec = idna::PunycodeDecode(in);
    if (dec) {
      auto enc = idna::PunycodeEncode(*dec);
      // Decoding is not injective for invalid case variants, but encoding
      // a decoded label must not crash and must decode back identically.
      if (enc) {
        auto dec2 = idna::PunycodeDecode(*enc);
        ASSERT_TRUE(dec2.has_value());
        EXPECT_TRUE(*dec2 == *dec);
      }
    }
    idna::ToAscii(in);
    idna::ForDisplay("xn--" + in);
  }
}

TEST(Robustness, MiscParsersHostileInput) {
  std::mt19937_64 rng(1234);
  for (int i = 0; i < 10000; ++i) {
    std::string in = RandomBytes(rng, 300, i % 2 == 0);
    std::vector<std::uint8_t> out;
    Base64Decode(in, &out);
    std::string name = SanitizeDownloadFilename(in);
    EXPECT_FALSE(name.empty());
    EXPECT_TRUE(name.find('/') == std::string::npos);
    EXPECT_TRUE(name.find('\\') == std::string::npos);
    EXPECT_TRUE(name.find("..") == std::string::npos);
    EXPECT_TRUE(IsValidUtf8(name));
    EXPECT_TRUE(name.size() <= 180);
    ResolveOmniboxInput(in);
    Version::Parse(in);
    ParsePublicKeys(in);
    NormalizeSiteKey(in, i % 2 == 0);
    std::string mark = BuildMarkOfTheWeb(in, in);
    EXPECT_EQ(mark.find("ZoneId=", 20), std::string::npos);  // exactly one zone line
  }
}

TEST(Robustness, PolicyEvaluationOnRandomRequests) {
  std::mt19937_64 rng(555);
  Settings s;
  auto p = PolicySnapshot::Create(s, aegis_test::EngineFromRules("||ads.example^\n"), aegis_test::RealPsl());
  for (int i = 0; i < 10000; ++i) {
    RequestContext c;
    std::string url = (i % 2) ? "https://" + RandomBytes(rng, 40, true) : RandomBytes(rng, 60, true);
    std::string top = RandomBytes(rng, 40, true);
    c.url = url;
    c.top_level_url = top;
    c.type = static_cast<ResourceType>(1u << (rng() % 13));
    c.is_main_frame = (rng() % 5) == 0;
    RequestDecision d = EvaluateRequest(*p, c);
    // An unparseable URL is never allowed.
    if (!ParseUrl(url)) EXPECT_TRUE(d.action == RequestAction::kBlock);
  }
}

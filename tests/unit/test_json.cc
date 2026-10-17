#include "common/base64.h"
#include "common/json.h"
#include "common/strings.h"
#include "common/utf8.h"
#include "test_framework.h"

using namespace aegis;

TEST(Json, ParsesNestedDocument) {
  auto v = json::Parse(R"({"a":[1,2.5,true,null,"x\u00e9\ud83d\ude00"],"b":{"c":-3e2}})");
  ASSERT_TRUE(v.has_value());
  EXPECT_EQ(v->Find("a")->as_array().size(), 5u);
  EXPECT_EQ(v->Find("a")->as_array()[1].as_number(), 2.5);
  EXPECT_EQ(v->Find("a")->as_array()[4].as_string(), std::string("x\xc3\xa9\xf0\x9f\x98\x80"));
  EXPECT_EQ(v->Find("b")->GetInt("c", 0), -300);
}

TEST(Json, RejectsMalformedInput) {
  const char* bad[] = {"", "{", "[1,]", "{\"a\":}", "{\"a\" 1}", "01", "1.", "-", "\"\\x\"",
                       "\"\\ud800\"", "\"\\udc00\"", "{\"a\":1}x", "[\"\x01\"]", "nul",
                       "{\"a\":1,\"a\":2}", "\"\xff\"", "1e", "NaN", "Infinity"};
  for (const char* b : bad) {
    EXPECT_FALSE(json::Parse(b).has_value());
  }
}

TEST(Json, EnforcesDepthAndSizeLimits) {
  std::string deep(200, '[');
  deep += std::string(200, ']');
  EXPECT_FALSE(json::Parse(deep).has_value());
  json::ParseLimits small;
  small.max_bytes = 10;
  EXPECT_FALSE(json::Parse("[1,2,3,4,5,6]", nullptr, small).has_value());
  json::ParseLimits few;
  few.max_elements = 3;
  EXPECT_FALSE(json::Parse("[1,2,3,4]", nullptr, few).has_value());
}

TEST(Json, SerializeRoundTripIsDeterministic) {
  json::Object o;
  o["z"] = 1;
  o["a"] = "line\nbreak \"quoted\" \x01";
  o["m"] = json::Array{json::Value(true), json::Value(nullptr), json::Value(1.25)};
  std::string s1 = json::Serialize(json::Value(o));
  auto back = json::Parse(s1);
  ASSERT_TRUE(back.has_value());
  EXPECT_EQ(json::Serialize(*back), s1);
  EXPECT_TRUE(s1.find("\"a\"") < s1.find("\"z\""));
}

TEST(Base64, RoundTripAndStrictness) {
  for (std::string s : {"", "f", "fo", "foo", "foob", "fooba", "foobar"}) {
    std::vector<std::uint8_t> out;
    ASSERT_TRUE(Base64Decode(Base64Encode(s), &out));
    EXPECT_EQ(std::string(out.begin(), out.end()), s);
  }
  std::vector<std::uint8_t> out;
  EXPECT_FALSE(Base64Decode("Zm9v=", &out));
  EXPECT_FALSE(Base64Decode("Zm=v", &out));
  EXPECT_FALSE(Base64Decode("Zm9!", &out));
  EXPECT_FALSE(Base64Decode("Zh==", &out));  // non-canonical trailing bits
  EXPECT_TRUE(Base64Decode("Zg==", &out));
}

TEST(Utf8, ValidationRejectsOverlongsAndSurrogates) {
  EXPECT_TRUE(IsValidUtf8("plain ascii"));
  EXPECT_TRUE(IsValidUtf8("\xe2\x82\xac"));
  EXPECT_FALSE(IsValidUtf8("\xc0\xaf"));          // overlong '/'
  EXPECT_FALSE(IsValidUtf8("\xed\xa0\x80"));      // surrogate
  EXPECT_FALSE(IsValidUtf8("\xf4\x90\x80\x80"));  // > U+10FFFF
  EXPECT_FALSE(IsValidUtf8("\xe2\x82"));          // truncated
  EXPECT_EQ(ReplaceInvalidUtf8("a\xffz"), std::string("a\xef\xbf\xbdz"));
  EXPECT_EQ(TruncateUtf8Boundary("\xe2\x82\xac\xe2\x82\xac", 4), 3u);
}

TEST(Strings, HtmlEscapeNeutralizesMarkup) {
  EXPECT_EQ(HtmlEscape("<script>alert('x')</script>&\"`"),
            std::string("&lt;script&gt;alert(&#39;x&#39;)&lt;/script&gt;&amp;&quot;&#96;"));
  EXPECT_EQ(SanitizeForLog("a\nb\x7f"), std::string("a?b?"));
  std::uint64_t v = 0;
  EXPECT_TRUE(ParseUint64("18446744073709551615", &v));
  EXPECT_FALSE(ParseUint64("18446744073709551616", &v));
  EXPECT_FALSE(ParseUint64("12a", &v));
  EXPECT_FALSE(ParseUint64("", &v));
}

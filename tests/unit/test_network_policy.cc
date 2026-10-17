#include "networking/network_policy.h"
#include "test_framework.h"

using namespace aegis;

TEST(NetworkPolicy, HttpsFirstUpgradeRules) {
  std::set<std::string> allowed;
  auto up = HttpsFirstUpgrade(*ParseUrl("http://example.com/a"), allowed);
  ASSERT_TRUE(up.has_value());
  EXPECT_EQ(*up, std::string("https://example.com/a"));
  EXPECT_EQ(*HttpsFirstUpgrade(*ParseUrl("http://example.com:80/"), allowed),
            std::string("https://example.com/"));
  EXPECT_FALSE(HttpsFirstUpgrade(*ParseUrl("https://example.com/"), allowed).has_value());
  EXPECT_FALSE(HttpsFirstUpgrade(*ParseUrl("http://localhost/"), allowed).has_value());
  EXPECT_FALSE(HttpsFirstUpgrade(*ParseUrl("http://192.168.0.1/"), allowed).has_value());
  EXPECT_FALSE(HttpsFirstUpgrade(*ParseUrl("http://8.8.8.8/"), allowed).has_value());
  EXPECT_FALSE(HttpsFirstUpgrade(*ParseUrl("http://intranet/"), allowed).has_value());
  EXPECT_FALSE(HttpsFirstUpgrade(*ParseUrl("http://example.com:8080/"), allowed).has_value());
  allowed.insert("example.com");
  EXPECT_FALSE(HttpsFirstUpgrade(*ParseUrl("http://example.com/"), allowed).has_value());
  EXPECT_TRUE(HttpsFirstUpgrade(*ParseUrl("http://www.example.com/"), allowed).has_value());
}

TEST(NetworkPolicy, FallbackNeverOnCertificateErrors) {
  EXPECT_TRUE(IsHttpsUpgradeFallbackError(-102));  // connection refused
  EXPECT_TRUE(IsHttpsUpgradeFallbackError(-105));
  EXPECT_FALSE(IsHttpsUpgradeFallbackError(-200));  // ERR_CERT_COMMON_NAME_INVALID
  EXPECT_FALSE(IsHttpsUpgradeFallbackError(-201));  // ERR_CERT_DATE_INVALID
  EXPECT_FALSE(IsHttpsUpgradeFallbackError(-202));  // ERR_CERT_AUTHORITY_INVALID
  EXPECT_FALSE(IsHttpsUpgradeFallbackError(0));
}

TEST(NetworkPolicy, ExternalProtocols) {
  std::set<std::string> allowed{"mailto"};
  EXPECT_TRUE(EvaluateExternalProtocol("ms-msdt:/id PCWDiagnostic", SecurityMode::kCompatibility, true,
                                       allowed).decision == ExternalProtocolDecision::kBlock);
  EXPECT_TRUE(EvaluateExternalProtocol("search-ms:query=x", SecurityMode::kCompatibility, true, allowed)
                  .decision == ExternalProtocolDecision::kBlock);
  EXPECT_TRUE(EvaluateExternalProtocol("ms-anything:x", SecurityMode::kCompatibility, true, allowed)
                  .decision == ExternalProtocolDecision::kBlock);
  EXPECT_TRUE(EvaluateExternalProtocol("mailto:a@b.example", SecurityMode::kMaximumIsolation, true, allowed)
                  .decision == ExternalProtocolDecision::kBlock);
  EXPECT_TRUE(EvaluateExternalProtocol("mailto:a@b.example", SecurityMode::kStrictProtection, false,
                                       allowed).decision == ExternalProtocolDecision::kBlock);
  EXPECT_TRUE(EvaluateExternalProtocol("mailto:a@b.example", SecurityMode::kStrictProtection, true,
                                       allowed).decision == ExternalProtocolDecision::kAllow);
  EXPECT_TRUE(EvaluateExternalProtocol("spotify:track:1", SecurityMode::kStrictProtection, true, allowed)
                  .decision == ExternalProtocolDecision::kAskUser);
  EXPECT_TRUE(EvaluateExternalProtocol("no-colon", SecurityMode::kCompatibility, true, allowed).decision ==
              ExternalProtocolDecision::kBlock);
}

TEST(NetworkPolicy, PrivateNetworkFromPublic) {
  auto pub = *ParseUrl("https://public.example/");
  auto local_top = *ParseUrl("http://localhost:8000/");
  EXPECT_TRUE(IsPrivateNetworkRequestFromPublicPage(*ParseUrl("http://10.0.0.1/"), &pub));
  EXPECT_TRUE(IsPrivateNetworkRequestFromPublicPage(*ParseUrl("http://0x7f000001/"), &pub));
  EXPECT_FALSE(IsPrivateNetworkRequestFromPublicPage(*ParseUrl("https://cdn.example/"), &pub));
  EXPECT_FALSE(IsPrivateNetworkRequestFromPublicPage(*ParseUrl("http://127.0.0.1/"), &local_top));
  EXPECT_FALSE(IsPrivateNetworkRequestFromPublicPage(*ParseUrl("http://127.0.0.1/"), nullptr));
}

#include <fstream>

#include "common/base64.h"
#include "common/strings.h"
#include "test_framework.h"
#include "updates/update_verifier.h"

extern "C" {
#include "monocypher-ed25519.h"
}

using namespace aegis;

namespace {

struct KeyPair {
  std::uint8_t secret[64];
  Ed25519PublicKey pub;
};

KeyPair MakeKey(std::uint8_t seed_byte) {
  KeyPair k;
  std::uint8_t seed[32];
  for (auto& b : seed) b = seed_byte;
  crypto_ed25519_key_pair(k.secret, k.pub.data(), seed);
  return k;
}

std::string Sign(const KeyPair& k, const std::string& msg) {
  std::uint8_t sig[64];
  crypto_ed25519_sign(sig, k.secret, reinterpret_cast<const std::uint8_t*>(msg.data()), msg.size());
  return Base64Encode(sig, 64);
}

std::string Manifest(std::uint64_t seq, const std::string& extra_artifact_url = "",
                     std::int64_t issued = 1'790'000'000, std::int64_t expires = 1'800'000'000) {
  std::string url = extra_artifact_url.empty()
                        ? "https://downloads.wezcrypt.example/WezCryptAegis-1.1.0-setup.exe"
                        : extra_artifact_url;
  return "{\"product\":\"wezcrypt-aegis\",\"channel\":\"stable\",\"sequence\":" + std::to_string(seq) +
         ",\"version\":\"1.1.0\",\"chromium_version\":\"154.0.8037.120\","
         "\"minimum_safe_chromium_version\":\"154.0.8037.98\",\"issued_unix\":" +
         std::to_string(issued) + ",\"expires_unix\":" + std::to_string(expires) +
         ",\"artifacts\":[{\"name\":\"setup.exe\",\"url\":\"" + url +
         "\",\"sha512\":\"" + std::string(128, 'a') + "\",\"size\":1234}]}";
}

VerifyOptions Opts(const KeyPair& k, std::uint64_t last_seq = 0) {
  VerifyOptions o;
  o.trusted_keys = {k.pub};
  o.last_accepted_sequence = last_seq;
  o.now_unix = 1'795'000'000;
  return o;
}

}  // namespace

TEST(Updates, Rfc8032Ed25519TestVector1) {
  std::vector<std::uint8_t> pub, sig;
  ASSERT_TRUE(HexDecode("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", &pub));
  ASSERT_TRUE(HexDecode(
      "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bac"
      "c61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
      &sig));
  Ed25519PublicKey key;
  std::copy(pub.begin(), pub.end(), key.begin());
  EXPECT_TRUE(VerifyEd25519(key, "", sig.data()));
  sig[0] ^= 1;
  EXPECT_FALSE(VerifyEd25519(key, "", sig.data()));
}

TEST(Updates, Sha512KnownAnswer) {
  EXPECT_EQ(Sha512Hex("abc"),
            std::string("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
                        "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"));
}

TEST(Updates, ValidSignedManifestIsAccepted) {
  KeyPair k = MakeKey(7);
  std::string m = Manifest(5);
  VerifiedManifest v = VerifyManifest(m, Sign(k, m), Opts(k));
  EXPECT_TRUE(v.status == ManifestStatus::kOk);
  EXPECT_EQ(v.manifest.sequence, 5u);
  EXPECT_EQ(v.manifest.version.ToString(), std::string("1.1.0"));
  EXPECT_EQ(v.manifest.artifacts.size(), 1u);
}

TEST(Updates, TamperedOrForeignSignaturesRejected) {
  KeyPair k = MakeKey(7);
  KeyPair attacker = MakeKey(9);
  std::string m = Manifest(5);
  std::string sig = Sign(k, m);
  std::string tampered = m;
  tampered.replace(tampered.find("1.1.0"), 5, "9.9.9");
  EXPECT_TRUE(VerifyManifest(tampered, sig, Opts(k)).status == ManifestStatus::kSignatureInvalid);
  EXPECT_TRUE(VerifyManifest(m, Sign(attacker, m), Opts(k)).status == ManifestStatus::kSignatureInvalid);
  EXPECT_TRUE(VerifyManifest(m, "not base64!", Opts(k)).status == ManifestStatus::kBadSignatureEncoding);
  VerifyOptions none = Opts(k);
  none.trusted_keys.clear();
  EXPECT_TRUE(VerifyManifest(m, sig, none).status == ManifestStatus::kNoTrustedKeys);
}

TEST(Updates, RollbackAndFreshnessProtection) {
  KeyPair k = MakeKey(7);
  std::string old = Manifest(4);
  EXPECT_TRUE(VerifyManifest(old, Sign(k, old), Opts(k, 4)).status == ManifestStatus::kRollback);
  EXPECT_TRUE(VerifyManifest(old, Sign(k, old), Opts(k, 10)).status == ManifestStatus::kRollback);
  std::string expired = Manifest(11, "", 1'700'000'000, 1'710'000'000);
  EXPECT_TRUE(VerifyManifest(expired, Sign(k, expired), Opts(k, 10)).status == ManifestStatus::kExpired);
  std::string future = Manifest(12, "", 1'900'000'000, 1'910'000'000);
  EXPECT_TRUE(VerifyManifest(future, Sign(k, future), Opts(k, 10)).status == ManifestStatus::kNotYetValid);
}

TEST(Updates, InsecureArtifactUrlRejected) {
  KeyPair k = MakeKey(7);
  std::string m = Manifest(5, "http://downloads.example/setup.exe");
  EXPECT_TRUE(VerifyManifest(m, Sign(k, m), Opts(k)).status == ManifestStatus::kInsecureArtifactUrl);
}

TEST(Updates, ArtifactFileVerification) {
  auto dir = aegis_test::TempDir();
  std::string payload = "installer bytes";
  { std::ofstream(dir / "setup.exe", std::ios::binary) << payload; }
  ReleaseArtifact a;
  a.name = "setup.exe";
  a.size = payload.size();
  a.sha512_hex = Sha512Hex(payload);
  EXPECT_TRUE(VerifyArtifactFile(dir / "setup.exe", a));
  a.sha512_hex[0] = a.sha512_hex[0] == 'a' ? 'b' : 'a';
  EXPECT_FALSE(VerifyArtifactFile(dir / "setup.exe", a));
  a.sha512_hex = Sha512Hex(payload);
  a.size += 1;
  EXPECT_FALSE(VerifyArtifactFile(dir / "setup.exe", a));
}

TEST(Updates, VersionsAndEngineFreshness) {
  auto v = Version::Parse("154.0.8037.98");
  ASSERT_TRUE(v.has_value());
  EXPECT_EQ(v->Compare(*Version::Parse("154.0.8037.98")), 0);
  EXPECT_EQ(v->Compare(*Version::Parse("154.0.8037.120")), -1);
  EXPECT_EQ(v->Compare(*Version::Parse("153.9")), 1);
  EXPECT_FALSE(Version::Parse("1.x").has_value());
  EXPECT_FALSE(Version::Parse("").has_value());

  UpdateManifest m;
  m.version = *Version::Parse("1.1.0");
  m.chromium_version = *Version::Parse("154.0.8037.120");
  m.minimum_safe_chromium = *Version::Parse("154.0.8037.110");
  auto app = *Version::Parse("1.0.0");
  EXPECT_TRUE(EvaluateEngineFreshness(app, *v, 0, 0, &m) == EngineFreshness::kBelowMinimumSafe);
  m.minimum_safe_chromium = *Version::Parse("154.0.8037.98");
  EXPECT_TRUE(EvaluateEngineFreshness(app, *v, 0, 0, &m) == EngineFreshness::kUpdateAvailable);
  EXPECT_TRUE(EvaluateEngineFreshness(*Version::Parse("1.1.0"), *Version::Parse("154.0.8037.120"), 0, 0,
                                      &m) == EngineFreshness::kCurrent);
  const std::int64_t build = 1'790'000'000;
  EXPECT_TRUE(EvaluateEngineFreshness(app, *v, build, build + 10 * 86400, nullptr) ==
              EngineFreshness::kUnknown);
  EXPECT_TRUE(EvaluateEngineFreshness(app, *v, build, build + 60 * 86400, nullptr) ==
              EngineFreshness::kUnknownStale);
}

TEST(Updates, PublicKeyConfigParsing) {
  KeyPair k = MakeKey(3);
  std::string b64 = Base64Encode(k.pub.data(), 32);
  std::string hex = HexEncode(k.pub.data(), 32);
  auto keys = ParsePublicKeys(b64 + ", " + hex + ",garbage,");
  EXPECT_EQ(keys.size(), 2u);
  EXPECT_TRUE(keys[0] == k.pub);
  EXPECT_TRUE(keys[1] == k.pub);
}

// Persistence across restarts and crashes (required tests 5, 14, 16).
#include <fstream>

#include "storage/atomic_file.h"
#include "storage/settings_store.h"
#include "test_framework.h"

using namespace aegis;

namespace {
void WriteRaw(const std::filesystem::path& p, const std::string& data) {
  std::ofstream out(p, std::ios::binary | std::ios::trunc);
  out << data;
}
}  // namespace

TEST(Persistence, StrictSettingsPersistAcrossRestart) {
  auto dir = aegis_test::TempDir();
  Settings s;
  s.mode = SecurityMode::kStrictProtection;
  s.javascript_blocked_sites.insert("blocked.test");
  s.https_first = true;
  {
    SettingsStore store(dir / "settings.json");
    ASSERT_TRUE(store.Save(s));
  }
  // "Restart": a brand-new store instance reads the file.
  SettingsStore reopened(dir / "settings.json");
  SettingsLoadResult r = reopened.Load();
  EXPECT_TRUE(r.source == SettingsSource::kPrimary);
  EXPECT_TRUE(r.settings == s);
}

TEST(Persistence, MissingSettingsYieldMaximumIsolation) {
  auto dir = aegis_test::TempDir();
  SettingsStore store(dir / "settings.json");
  SettingsLoadResult r = store.Load();
  EXPECT_TRUE(r.source == SettingsSource::kDefaults);
  EXPECT_TRUE(r.settings.mode == SecurityMode::kMaximumIsolation);
  EXPECT_TRUE(r.warnings.empty());
}

TEST(Persistence, TornWriteRecoversFromBackup) {
  auto dir = aegis_test::TempDir();
  SettingsStore store(dir / "settings.json");
  Settings first;
  first.mode = SecurityMode::kStrictProtection;
  first.site_exceptions["intended.test"].allow_javascript = true;
  ASSERT_TRUE(store.Save(first));
  Settings second = first;
  second.home_page = "https://second.example/";
  ASSERT_TRUE(store.Save(second));  // first is now the .bak
  // Simulate a crash that left the primary file truncated mid-write.
  auto r0 = storage::ReadFile(dir / "settings.json", 1 << 20);
  ASSERT_TRUE(r0.status == storage::ReadStatus::kOk);
  WriteRaw(dir / "settings.json", r0.data.substr(0, r0.data.size() / 2));
  SettingsLoadResult r = store.Load();
  EXPECT_TRUE(r.source == SettingsSource::kBackup);
  EXPECT_TRUE(r.primary_was_corrupt);
  EXPECT_TRUE(r.settings == first);
}

TEST(Persistence, CorruptPrimaryAndBackupFailClosed) {
  auto dir = aegis_test::TempDir();
  WriteRaw(dir / "settings.json", "{\"mode\":\"compatibility\",");  // truncated
  WriteRaw(dir / "settings.json.bak", std::string("\x00\x01garbage", 9));
  SettingsStore store(dir / "settings.json");
  SettingsLoadResult r = store.Load();
  EXPECT_TRUE(r.source == SettingsSource::kDefaults);
  // Weaker mode from the torn file must not be applied.
  EXPECT_TRUE(r.settings.mode == SecurityMode::kMaximumIsolation);
  EXPECT_FALSE(r.warnings.empty());
}

TEST(Persistence, AtomicWriteLeavesNoTemporaryFiles) {
  auto dir = aegis_test::TempDir();
  for (int i = 0; i < 20; ++i) {
    ASSERT_TRUE(storage::WriteFileAtomically(dir / "f.json", "{\"i\":" + std::to_string(i) + "}", true));
  }
  int files = 0;
  for (const auto& e : std::filesystem::directory_iterator(dir)) {
    (void)e;
    ++files;
  }
  EXPECT_EQ(files, 2);  // f.json and f.json.bak
  auto r = storage::ReadFile(dir / "f.json", 1024);
  EXPECT_EQ(r.data, std::string("{\"i\":19}"));
  auto b = storage::ReadFile(dir / "f.json.bak", 1024);
  EXPECT_EQ(b.data, std::string("{\"i\":18}"));
}

TEST(Persistence, ReadFileHonoursSizeLimit) {
  auto dir = aegis_test::TempDir();
  WriteRaw(dir / "big", std::string(4096, 'x'));
  EXPECT_TRUE(storage::ReadFile(dir / "big", 100).status == storage::ReadStatus::kTooLarge);
  EXPECT_TRUE(storage::ReadFile(dir / "missing", 100).status == storage::ReadStatus::kNotFound);
}

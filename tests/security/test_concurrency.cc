// Thread-safety: request evaluation on many "IO threads" while the UI
// thread swaps filter engines and records events.
#include <atomic>
#include <thread>

#include "filtering/filter_list_manager.h"
#include "security/security_events.h"
#include "security/security_policy.h"
#include "test_support.h"

using namespace aegis;

TEST(Concurrency, EngineSwapWhileMatching) {
  auto cache = aegis_test::TempDir();
  auto bundled = aegis_test::TempDir();
  {
    std::string list = "[Adblock Plus 2.0]\n! Title: T\n";
    for (int i = 0; i < 500; ++i) list += "||ad" + std::to_string(i) + ".example^\n";
    storage::WriteFileAtomically(bundled / "base.txt", list, false);
  }
  FilterListConfig cfg;
  cfg.id = "base";
  cfg.name = "Base";
  cfg.min_rules = 10;
  FilterListManager m(bundled, cache, aegis_test::RealPsl());
  ASSERT_TRUE(m.Initialize({cfg}, {}));

  std::atomic<bool> stop{false};
  std::atomic<std::uint64_t> blocked{0};
  std::atomic<std::uint64_t> wrong{0};
  std::vector<std::thread> workers;
  for (int t = 0; t < 4; ++t) {
    workers.emplace_back([&, t] {
      std::uint64_t n = 0;
      while (!stop.load()) {
        auto engine = m.engine();
        auto r = aegis_test::MakeReq("https://ad" + std::to_string((n + t) % 500) + ".example/x",
                                     "https://site.example/", kResourceImage);
        if (engine->Match(r.info).decision == FilterDecision::kBlock) blocked++;
        else wrong++;
        ++n;
      }
    });
  }
  for (int round = 0; round < 30; ++round) {
    std::string list = "[Adblock Plus 2.0]\n! Title: T\n";
    for (int i = 0; i < 501 + round; ++i) list += "||ad" + std::to_string(i) + ".example^\n";
    EXPECT_TRUE(m.ApplyUpdate("base", list) == UpdateOutcome::kApplied);
    m.SetUserRules({"||user" + std::to_string(round) + ".example^"});
  }
  stop = true;
  for (auto& w : workers) w.join();
  EXPECT_TRUE(blocked.load() > 0);
  EXPECT_EQ(wrong.load(), 0u);  // every engine version blocks every ad host
}

TEST(Concurrency, EventLogCountsAreExact) {
  SecurityEventLog log(100);
  std::vector<std::thread> threads;
  for (int t = 0; t < 8; ++t) {
    threads.emplace_back([&log, t] {
      for (int i = 0; i < 5000; ++i) {
        SecurityEvent e;
        e.category = (i % 2) ? EventCategory::kAdvertising : EventCategory::kTracker;
        e.site = "site" + std::to_string(t) + ".example";
        e.url = "https://x.example/" + std::to_string(i);
        log.Record(std::move(e));
        log.RecordForTab(t, EventCategory::kAdvertising);
      }
    });
  }
  for (auto& th : threads) th.join();
  EXPECT_EQ(log.SessionCount(EventCategory::kAdvertising), 20000u);
  EXPECT_EQ(log.SessionCount(EventCategory::kTracker), 20000u);
  EXPECT_EQ(log.ForSite("site3.example").total(), 5000u);
  EXPECT_EQ(log.TabBlockedCount(5), 5000u);
  EXPECT_EQ(log.Recent(1000).size(), 100u);  // ring buffer bounded
  // Lifetime totals persist through JSON.
  SecurityEventLog restored;
  restored.LoadLifetime(log.LifetimeToJson());
  EXPECT_EQ(restored.LifetimeCount(EventCategory::kAdvertising), 20000u);
  EXPECT_EQ(restored.SessionCount(EventCategory::kAdvertising), 0u);
}

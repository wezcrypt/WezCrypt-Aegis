#include <atomic>
#include <fstream>
#include <thread>
#include <vector>

#include "networking/unattributed_request_gate.h"
#include "privacy/profile.h"
#include "test_framework.h"

using namespace aegis;

TEST(RequestGate, ServiceWorkerScriptsAreDeniedEvenWithABrowser) {
  InternalFetchRegistry reg;
  ASSERT_TRUE(reg.Reserve("https://page.example/sw.js"));
  for (bool has_browser : {false, true}) {
    UnattributedRequest r;
    r.url = "https://page.example/sw.js";
    r.is_service_worker_script = true;
    r.has_browser = has_browser;
    // A reservation for the same URL does not admit a service-worker script.
    EXPECT_TRUE(EvaluateUnattributedRequest(r, reg).decision == GateDecision::kDeny);
  }
  EXPECT_EQ(reg.Size(), 1u);
}

TEST(RequestGate, BrowserRequestsAreLeftToTheRequestHandler) {
  InternalFetchRegistry reg;
  UnattributedRequest r;
  r.url = "https://ads.example/banner.png";
  r.has_browser = true;
  EXPECT_TRUE(EvaluateUnattributedRequest(r, reg).decision == GateDecision::kNotHandled);
}

TEST(RequestGate, UnattributedRequestsAreDeniedByDefault) {
  InternalFetchRegistry reg;
  for (const char* url : {"https://ads.example/sw-ad", "http://tracker.example/p", "https://easylist.to/easylist/easylist.txt"}) {
    UnattributedRequest r;
    r.url = url;
    GateVerdict v = EvaluateUnattributedRequest(r, reg);
    EXPECT_TRUE(v.decision == GateDecision::kDeny);
    EXPECT_FALSE(v.reason.empty());
  }
}

TEST(RequestGate, ReservationAdmitsExactlyOneRequestForExactlyThatUrl) {
  InternalFetchRegistry reg;
  const std::string url = "https://easylist.to/easylist/easylist.txt";
  ASSERT_TRUE(reg.Reserve(url));
  EXPECT_FALSE(reg.Reserve(url));  // no duplicate in-flight reservation
  UnattributedRequest other;
  other.url = "https://easylist.to/easylist/easylist.txt?x=1";
  EXPECT_TRUE(EvaluateUnattributedRequest(other, reg).decision == GateDecision::kDeny);
  UnattributedRequest r;
  r.url = url;
  EXPECT_TRUE(EvaluateUnattributedRequest(r, reg).decision == GateDecision::kAllowInternal);
  // Consumed: a second request for the same URL (e.g. a worker replaying
  // it) is denied.
  EXPECT_TRUE(EvaluateUnattributedRequest(r, reg).decision == GateDecision::kDeny);
  reg.Release(url);  // completion after consumption is a no-op
  EXPECT_EQ(reg.Size(), 0u);
}

TEST(RequestGate, ReservationsRequireHttpsAndAreBounded) {
  InternalFetchRegistry reg;
  EXPECT_FALSE(reg.Reserve("http://easylist.to/easylist/easylist.txt"));
  EXPECT_FALSE(reg.Reserve("https://user:pw@easylist.to/list.txt"));
  EXPECT_FALSE(reg.Reserve("not a url"));
  for (std::size_t i = 0; i < InternalFetchRegistry::kMaxReservations; ++i) {
    ASSERT_TRUE(reg.Reserve("https://u.example/" + std::to_string(i)));
  }
  EXPECT_FALSE(reg.Reserve("https://u.example/overflow"));
  reg.Release("https://u.example/0");
  EXPECT_TRUE(reg.Reserve("https://u.example/overflow"));
}

TEST(RequestGate, ConcurrentConsumersAdmitASingleRequest) {
  InternalFetchRegistry reg;
  const std::string url = "https://easyprivacy.example/list.txt";
  for (int round = 0; round < 50; ++round) {
    ASSERT_TRUE(reg.Reserve(url));
    std::atomic<int> allowed{0};
    std::vector<std::thread> threads;
    for (int t = 0; t < 8; ++t) {
      threads.emplace_back([&] {
        UnattributedRequest r;
        r.url = url;
        if (EvaluateUnattributedRequest(r, reg).decision == GateDecision::kAllowInternal) ++allowed;
      });
    }
    for (auto& t : threads) t.join();
    EXPECT_EQ(allowed.load(), 1);
  }
}

TEST(ServiceWorkerStorage, PurgeRemovesRegistrationsAndCacheStorage) {
  auto dir = aegis_test::TempDir();
  auto paths = MakeProfilePaths(dir, "Default");
  ASSERT_TRUE(paths.has_value());
  int created = 0;
  for (const auto& d : ServiceWorkerStorageDirs(*paths)) {
    std::filesystem::create_directories(d / "Database");
    std::filesystem::create_directories(d / "CacheStorage" / "abc");
    std::ofstream(d / "Database" / "CURRENT") << "MANIFEST-000001\n";
    std::ofstream(d / "ScriptCache") << "cached";
    ++created;
  }
  // Unrelated engine data survives.
  std::filesystem::create_directories(paths->engine_cache / "Local Storage");
  ServiceWorkerPurgeResult r = PurgeServiceWorkerStorage(*paths);
  EXPECT_TRUE(r.ok);
  EXPECT_EQ(r.removed, created);
  for (const auto& d : ServiceWorkerStorageDirs(*paths)) EXPECT_FALSE(std::filesystem::exists(d));
  EXPECT_TRUE(std::filesystem::exists(paths->engine_cache / "Local Storage"));
  // Idempotent on a clean profile.
  ServiceWorkerPurgeResult again = PurgeServiceWorkerStorage(*paths);
  EXPECT_TRUE(again.ok);
  EXPECT_EQ(again.removed, 0);
}

TEST(ServiceWorkerStorage, PurgeRemovesSymlinkWithoutFollowingIt) {
  auto dir = aegis_test::TempDir();
  auto paths = MakeProfilePaths(dir / "root", "Default");
  ASSERT_TRUE(paths.has_value());
  auto outside = dir / "outside";
  std::filesystem::create_directories(outside);
  std::ofstream(outside / "keep.txt") << "must survive";
  std::filesystem::create_directories(paths->engine_cache);
  std::error_code ec;
  std::filesystem::create_directory_symlink(outside, paths->engine_cache / "Service Worker", ec);
  if (ec) return;  // symlinks unavailable (e.g. unprivileged Windows)
  ServiceWorkerPurgeResult r = PurgeServiceWorkerStorage(*paths);
  EXPECT_TRUE(r.ok);
  EXPECT_FALSE(std::filesystem::exists(std::filesystem::symlink_status(paths->engine_cache / "Service Worker")));
  EXPECT_TRUE(std::filesystem::exists(outside / "keep.txt"));
}

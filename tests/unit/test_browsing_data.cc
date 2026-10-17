#include "privacy/profile.h"
#include "storage/browsing_data.h"
#include "test_framework.h"

using namespace aegis;

TEST(History, StoresOnlyWebUrlsWithoutCredentials) {
  auto dir = aegis_test::TempDir();
  HistoryStore h(dir / "history.json", 3);
  h.AddVisit("https://user:pw@site.example/a#frag", "Title\nwith newline", 1);
  h.AddVisit("aegis://security/", "internal", 2);
  h.AddVisit("file:///C:/secret.txt", "file", 3);
  h.AddVisit("data:text/html,x", "data", 4);
  auto r = h.Recent(10);
  ASSERT_TRUE(r.size() == 1);
  EXPECT_EQ(r[0].url, std::string("https://site.example/a"));
  EXPECT_EQ(r[0].title, std::string("Title with newline"));
}

TEST(History, CapsEntriesAndPersists) {
  auto dir = aegis_test::TempDir();
  {
    HistoryStore h(dir / "history.json", 3);
    for (int i = 0; i < 5; ++i) h.AddVisit("https://s" + std::to_string(i) + ".example/", "", i);
    h.AddVisit("https://s4.example/", "again", 10);
    ASSERT_TRUE(h.Save());
  }
  HistoryStore again(dir / "history.json", 3);
  again.Load();
  auto r = again.Recent(10);
  ASSERT_TRUE(r.size() == 3);
  EXPECT_EQ(r[0].url, std::string("https://s4.example/"));
  EXPECT_EQ(r[0].visit_count, 2u);
  EXPECT_EQ(again.Search("s3", 10).size(), 1u);
  again.Clear();
  HistoryStore cleared(dir / "history.json", 3);
  cleared.Load();
  EXPECT_EQ(cleared.size(), 0u);
}

TEST(Bookmarks, AddRemovePersist) {
  auto dir = aegis_test::TempDir();
  BookmarkStore b(dir / "bookmarks.json");
  EXPECT_TRUE(b.Add("https://a.example/", "A", 1));
  EXPECT_FALSE(b.Add("https://a.example/", "dup", 2));
  EXPECT_FALSE(b.Add("javascript:alert(1)", "bookmarklet", 3));
  EXPECT_TRUE(b.Add("https://b.example/x#f", "", 4));
  ASSERT_TRUE(b.Save());
  BookmarkStore re(dir / "bookmarks.json");
  re.Load();
  EXPECT_EQ(re.All().size(), 2u);
  EXPECT_TRUE(re.Contains("https://b.example/x"));
  EXPECT_TRUE(re.Remove("https://a.example/"));
  EXPECT_EQ(re.All().size(), 1u);
}

TEST(Profiles, NamesAndPathsAreIsolated) {
  EXPECT_EQ(*ValidateProfileName(""), std::string("Default"));
  EXPECT_TRUE(ValidateProfileName("Work_1").has_value());
  EXPECT_FALSE(ValidateProfileName("../evil").has_value());
  EXPECT_FALSE(ValidateProfileName("a b").has_value());
  EXPECT_FALSE(ValidateProfileName("CON").has_value());
  EXPECT_FALSE(ValidateProfileName("com1").has_value());
  EXPECT_FALSE(ValidateProfileName(std::string(33, 'a')).has_value());
  auto a = MakeProfilePaths("/root", "Work");
  auto b = MakeProfilePaths("/root", "Home");
  ASSERT_TRUE(a && b);
  EXPECT_TRUE(a->engine_cache != b->engine_cache);
  EXPECT_TRUE(a->settings_file != b->settings_file);
  EXPECT_TRUE(a->filter_cache_dir == b->filter_cache_dir);
}

TEST(Profiles, ClearDataPlanParsing) {
  auto all = ParseClearDataPlan("all");
  ASSERT_TRUE(all.has_value());
  EXPECT_TRUE(all->cookies_and_site_data && all->cache && all->history && all->site_permissions);
  auto some = ParseClearDataPlan("cookies, cache");
  ASSERT_TRUE(some.has_value());
  EXPECT_TRUE(some->cookies_and_site_data && some->cache && !some->history);
  EXPECT_FALSE(ParseClearDataPlan("cookies,passwords").has_value());
  EXPECT_FALSE(ParseClearDataPlan("")->any());
}

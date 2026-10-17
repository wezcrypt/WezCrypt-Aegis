// WezCrypt Aegis - local history and bookmarks.
//
// Stored only on the local machine under the profile directory. WezCrypt
// does not collect or transmit browsing history. Private windows never
// write to these stores.
#pragma once

#include <cstdint>
#include <filesystem>
#include <mutex>
#include <string>
#include <vector>

#include "common/json.h"

namespace aegis {

struct HistoryEntry {
  std::string url;
  std::string title;
  std::int64_t last_visit_ms = 0;
  std::uint32_t visit_count = 0;
};

struct Bookmark {
  std::string url;
  std::string title;
  std::int64_t added_ms = 0;
};

class HistoryStore {
 public:
  explicit HistoryStore(std::filesystem::path file, std::size_t max_entries = 5000);
  void Load();
  bool Save();
  // Records a visit. Only http(s) URLs are stored; credentials are removed.
  void AddVisit(const std::string& url, const std::string& title, std::int64_t now_ms);
  void UpdateTitle(const std::string& url, const std::string& title);
  std::vector<HistoryEntry> Recent(std::size_t max) const;
  std::vector<HistoryEntry> Search(const std::string& query, std::size_t max) const;
  void Clear();
  std::size_t size() const;

 private:
  std::filesystem::path file_;
  const std::size_t max_entries_;
  mutable std::mutex mutex_;
  std::vector<HistoryEntry> entries_;  // most recent last
  bool dirty_ = false;
};

class BookmarkStore {
 public:
  explicit BookmarkStore(std::filesystem::path file, std::size_t max_entries = 10000);
  void Load();
  bool Save();
  bool Add(const std::string& url, const std::string& title, std::int64_t now_ms);
  bool Remove(const std::string& url);
  bool Contains(const std::string& url) const;
  std::vector<Bookmark> All() const;

 private:
  std::filesystem::path file_;
  const std::size_t max_entries_;
  mutable std::mutex mutex_;
  std::vector<Bookmark> items_;
};

// Returns |url| without credentials or fragment if it is a storable
// http(s) URL, otherwise empty.
std::string StorableUrl(const std::string& url);

}  // namespace aegis

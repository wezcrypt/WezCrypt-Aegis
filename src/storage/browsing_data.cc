#include "storage/browsing_data.h"

#include <algorithm>

#include "common/strings.h"
#include "common/url.h"
#include "common/utf8.h"
#include "storage/atomic_file.h"

namespace aegis {
namespace {
constexpr std::size_t kMaxStoreBytes = 32 * 1024 * 1024;
constexpr std::size_t kMaxTitleBytes = 512;
constexpr std::size_t kMaxUrlStoreBytes = 4096;

std::string CleanTitle(const std::string& t) {
  std::string s = ReplaceInvalidUtf8(t);
  for (char& c : s) {
    if (static_cast<unsigned char>(c) < 0x20) c = ' ';
  }
  s.resize(TruncateUtf8Boundary(s, kMaxTitleBytes));
  return s;
}
}  // namespace

std::string StorableUrl(const std::string& url) {
  auto u = ParseUrl(url);
  if (!u || !u->IsHttpLike()) return {};
  std::string spec = u->Spec(/*include_fragment=*/false);
  if (spec.size() > kMaxUrlStoreBytes) return {};
  return spec;
}

HistoryStore::HistoryStore(std::filesystem::path file, std::size_t max_entries)
    : file_(std::move(file)), max_entries_(max_entries) {}

void HistoryStore::Load() {
  std::lock_guard<std::mutex> lock(mutex_);
  entries_.clear();
  auto r = storage::ReadFile(file_, kMaxStoreBytes);
  if (r.status != storage::ReadStatus::kOk) return;
  auto v = json::Parse(r.data);
  if (!v || v->GetString("format") != "aegis-history-1") return;
  const json::Value* list = v->Find("entries");
  if (!list) return;
  for (const json::Value& e : list->as_array()) {
    HistoryEntry h;
    h.url = StorableUrl(e.GetString("url"));
    if (h.url.empty()) continue;
    h.title = CleanTitle(e.GetString("title"));
    h.last_visit_ms = e.GetInt("last_visit_ms", 0);
    std::int64_t vc = e.GetInt("visit_count", 1);
    h.visit_count = static_cast<std::uint32_t>(std::clamp<std::int64_t>(vc, 1, 1'000'000));
    entries_.push_back(std::move(h));
    if (entries_.size() >= max_entries_) break;
  }
  std::sort(entries_.begin(), entries_.end(),
            [](const HistoryEntry& a, const HistoryEntry& b) { return a.last_visit_ms < b.last_visit_ms; });
}

bool HistoryStore::Save() {
  std::lock_guard<std::mutex> lock(mutex_);
  json::Array arr;
  for (const auto& e : entries_) {
    json::Object o;
    o["url"] = e.url;
    o["title"] = e.title;
    o["last_visit_ms"] = e.last_visit_ms;
    o["visit_count"] = static_cast<std::int64_t>(e.visit_count);
    arr.emplace_back(std::move(o));
  }
  json::Object root;
  root["format"] = "aegis-history-1";
  root["entries"] = json::Value(std::move(arr));
  dirty_ = false;
  return storage::WriteFileAtomically(file_, json::Serialize(json::Value(std::move(root)), -1), true);
}

void HistoryStore::AddVisit(const std::string& url, const std::string& title, std::int64_t now_ms) {
  std::string clean = StorableUrl(url);
  if (clean.empty()) return;
  std::lock_guard<std::mutex> lock(mutex_);
  auto it = std::find_if(entries_.begin(), entries_.end(),
                         [&](const HistoryEntry& e) { return e.url == clean; });
  HistoryEntry e;
  if (it != entries_.end()) {
    e = *it;
    entries_.erase(it);
  } else {
    e.url = clean;
  }
  if (!title.empty()) e.title = CleanTitle(title);
  e.last_visit_ms = now_ms;
  e.visit_count = std::min<std::uint32_t>(e.visit_count + 1, 1'000'000);
  entries_.push_back(std::move(e));
  if (entries_.size() > max_entries_) entries_.erase(entries_.begin());
  dirty_ = true;
}

void HistoryStore::UpdateTitle(const std::string& url, const std::string& title) {
  std::string clean = StorableUrl(url);
  if (clean.empty() || title.empty()) return;
  std::lock_guard<std::mutex> lock(mutex_);
  for (auto it = entries_.rbegin(); it != entries_.rend(); ++it) {
    if (it->url == clean) {
      it->title = CleanTitle(title);
      dirty_ = true;
      return;
    }
  }
}

std::vector<HistoryEntry> HistoryStore::Recent(std::size_t max) const {
  std::lock_guard<std::mutex> lock(mutex_);
  std::vector<HistoryEntry> out;
  for (auto it = entries_.rbegin(); it != entries_.rend() && out.size() < max; ++it) out.push_back(*it);
  return out;
}

std::vector<HistoryEntry> HistoryStore::Search(const std::string& query, std::size_t max) const {
  std::string q = ToLowerAscii(query);
  std::lock_guard<std::mutex> lock(mutex_);
  std::vector<HistoryEntry> out;
  for (auto it = entries_.rbegin(); it != entries_.rend() && out.size() < max; ++it) {
    if (q.empty() || ToLowerAscii(it->url).find(q) != std::string::npos ||
        ToLowerAscii(it->title).find(q) != std::string::npos) {
      out.push_back(*it);
    }
  }
  return out;
}

void HistoryStore::Clear() {
  {
    std::lock_guard<std::mutex> lock(mutex_);
    entries_.clear();
  }
  Save();
  storage::RemoveFileIfExists(storage::BackupPathFor(file_));
}

std::size_t HistoryStore::size() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return entries_.size();
}

BookmarkStore::BookmarkStore(std::filesystem::path file, std::size_t max_entries)
    : file_(std::move(file)), max_entries_(max_entries) {}

void BookmarkStore::Load() {
  std::lock_guard<std::mutex> lock(mutex_);
  items_.clear();
  auto r = storage::ReadFile(file_, kMaxStoreBytes);
  if (r.status != storage::ReadStatus::kOk) {
    r = storage::ReadFile(storage::BackupPathFor(file_), kMaxStoreBytes);
    if (r.status != storage::ReadStatus::kOk) return;
  }
  auto v = json::Parse(r.data);
  if (!v || v->GetString("format") != "aegis-bookmarks-1") return;
  const json::Value* arr = v->Find("bookmarks");
  if (!arr) return;
  for (const json::Value& e : arr->as_array()) {
    Bookmark b;
    b.url = StorableUrl(e.GetString("url"));
    if (b.url.empty()) continue;
    b.title = CleanTitle(e.GetString("title"));
    b.added_ms = e.GetInt("added_ms", 0);
    items_.push_back(std::move(b));
    if (items_.size() >= max_entries_) break;
  }
}

bool BookmarkStore::Save() {
  std::lock_guard<std::mutex> lock(mutex_);
  json::Array arr;
  for (const auto& b : items_) {
    json::Object o;
    o["url"] = b.url;
    o["title"] = b.title;
    o["added_ms"] = b.added_ms;
    arr.emplace_back(std::move(o));
  }
  json::Object root;
  root["format"] = "aegis-bookmarks-1";
  root["bookmarks"] = json::Value(std::move(arr));
  return storage::WriteFileAtomically(file_, json::Serialize(json::Value(std::move(root))), true);
}

bool BookmarkStore::Add(const std::string& url, const std::string& title, std::int64_t now_ms) {
  std::string clean = StorableUrl(url);
  if (clean.empty()) return false;
  std::lock_guard<std::mutex> lock(mutex_);
  for (const auto& b : items_) {
    if (b.url == clean) return false;
  }
  if (items_.size() >= max_entries_) return false;
  items_.push_back({clean, CleanTitle(title.empty() ? clean : title), now_ms});
  return true;
}

bool BookmarkStore::Remove(const std::string& url) {
  std::string clean = StorableUrl(url);
  std::lock_guard<std::mutex> lock(mutex_);
  auto it = std::remove_if(items_.begin(), items_.end(),
                           [&](const Bookmark& b) { return b.url == clean; });
  bool removed = it != items_.end();
  items_.erase(it, items_.end());
  return removed;
}

bool BookmarkStore::Contains(const std::string& url) const {
  std::string clean = StorableUrl(url);
  std::lock_guard<std::mutex> lock(mutex_);
  return std::any_of(items_.begin(), items_.end(), [&](const Bookmark& b) { return b.url == clean; });
}

std::vector<Bookmark> BookmarkStore::All() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return items_;
}

}  // namespace aegis

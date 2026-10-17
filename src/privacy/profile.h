// WezCrypt Aegis - profile isolation and browsing-data clearing.
//
// Each named profile has its own Chromium cache directory (cookies, local
// storage, HTTP cache, service workers) and its own WezCrypt stores, so
// sessions in different profiles do not share state. Private windows use an
// in-memory Chromium request context with no cache path at all.
#pragma once

#include <filesystem>
#include <optional>
#include <string>
#include <string_view>

namespace aegis {

struct ProfilePaths {
  std::string name;
  std::filesystem::path root;            // %LOCALAPPDATA%\WezCrypt\Aegis
  std::filesystem::path profile_dir;     // root\Profiles\<name>
  std::filesystem::path engine_cache;    // profile_dir\Engine (CEF cache_path)
  std::filesystem::path settings_file;
  std::filesystem::path history_file;
  std::filesystem::path bookmarks_file;
  std::filesystem::path stats_file;
  std::filesystem::path filter_cache_dir;  // shared across profiles (public data)
  std::filesystem::path logs_dir;
};

// Profile names are restricted to [A-Za-z0-9_-]{1,32}. "Default" is used
// when |name| is empty.
std::optional<std::string> ValidateProfileName(std::string_view name);

std::optional<ProfilePaths> MakeProfilePaths(const std::filesystem::path& root,
                                             std::string_view name);

struct ClearDataPlan {
  bool cookies_and_site_data = false;  // cookies, local storage, IndexedDB, service workers
  bool cache = false;                  // HTTP cache
  bool history = false;
  bool site_permissions = false;
  bool download_list = false;
  bool any() const {
    return cookies_and_site_data || cache || history || site_permissions || download_list;
  }
};

// Parses a comma-separated list: "cookies,cache,history,permissions,downloads"
// ("all" selects everything). Unknown tokens make the result empty.
std::optional<ClearDataPlan> ParseClearDataPlan(std::string_view spec);

}  // namespace aegis

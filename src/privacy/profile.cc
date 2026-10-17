#include "privacy/profile.h"

#include "common/strings.h"

namespace aegis {

std::optional<std::string> ValidateProfileName(std::string_view name) {
  if (name.empty()) return std::string("Default");
  if (name.size() > 32) return std::nullopt;
  for (char c : name) {
    if (!(IsAsciiAlnum(c) || c == '_' || c == '-')) return std::nullopt;
  }
  // Windows device names are not valid directory names.
  std::string lower = ToLowerAscii(name);
  static constexpr std::string_view kReserved[] = {"con", "prn", "aux", "nul"};
  for (auto r : kReserved) {
    if (lower == r) return std::nullopt;
  }
  if ((StartsWith(lower, "com") || StartsWith(lower, "lpt")) && lower.size() == 4 &&
      IsAsciiDigit(lower[3])) {
    return std::nullopt;
  }
  return std::string(name);
}

std::optional<ProfilePaths> MakeProfilePaths(const std::filesystem::path& root,
                                             std::string_view name) {
  auto valid = ValidateProfileName(name);
  if (!valid || root.empty()) return std::nullopt;
  ProfilePaths p;
  p.name = *valid;
  p.root = root;
  p.profile_dir = root / "Profiles" / p.name;
  p.engine_cache = p.profile_dir / "Engine";
  p.settings_file = p.profile_dir / "settings.json";
  p.history_file = p.profile_dir / "history.json";
  p.bookmarks_file = p.profile_dir / "bookmarks.json";
  p.stats_file = p.profile_dir / "statistics.json";
  p.filter_cache_dir = root / "FilterLists";
  p.logs_dir = root / "Logs";
  return p;
}

std::optional<ClearDataPlan> ParseClearDataPlan(std::string_view spec) {
  ClearDataPlan plan;
  for (std::string_view raw : Split(spec, ',')) {
    std::string t = ToLowerAscii(TrimAsciiWhitespace(raw));
    if (t.empty()) continue;
    if (t == "all") {
      plan = {true, true, true, true, true};
    } else if (t == "cookies") {
      plan.cookies_and_site_data = true;
    } else if (t == "cache") {
      plan.cache = true;
    } else if (t == "history") {
      plan.history = true;
    } else if (t == "permissions") {
      plan.site_permissions = true;
    } else if (t == "downloads") {
      plan.download_list = true;
    } else {
      return std::nullopt;
    }
  }
  return plan;
}

}  // namespace aegis

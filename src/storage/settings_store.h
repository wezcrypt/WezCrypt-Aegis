// WezCrypt Aegis - load/save settings with crash recovery.
#pragma once

#include <filesystem>
#include <mutex>
#include <string>
#include <vector>

#include "storage/settings.h"

namespace aegis {

enum class SettingsSource { kPrimary, kBackup, kDefaults };

struct SettingsLoadResult {
  Settings settings;
  SettingsSource source = SettingsSource::kDefaults;
  std::vector<std::string> warnings;
  bool primary_was_corrupt = false;
};

class SettingsStore {
 public:
  explicit SettingsStore(std::filesystem::path path);

  // Loads settings. If the primary file is missing or corrupt, the backup
  // is used; if both are unusable, secure defaults are returned (Maximum
  // Isolation). A corrupt primary is never silently overwritten with
  // weaker values: the recovered settings are re-saved explicitly.
  SettingsLoadResult Load() const;

  bool Save(const Settings& s, std::string* error = nullptr);

  const std::filesystem::path& path() const { return path_; }

 private:
  std::filesystem::path path_;
  std::mutex save_mutex_;
};

}  // namespace aegis

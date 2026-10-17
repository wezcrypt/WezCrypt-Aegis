#include "storage/settings_store.h"

#include "storage/atomic_file.h"

namespace aegis {
namespace {
constexpr std::size_t kMaxSettingsBytes = 16 * 1024 * 1024;

bool TryLoad(const std::filesystem::path& p, Settings* out,
             std::vector<std::string>* warnings, bool* existed) {
  storage::ReadResult r = storage::ReadFile(p, kMaxSettingsBytes);
  *existed = r.status != storage::ReadStatus::kNotFound;
  if (r.status != storage::ReadStatus::kOk) return false;
  json::ParseError err;
  auto v = json::Parse(r.data, &err);
  if (!v || !v->is_object()) {
    warnings->push_back(p.filename().string() + ": unreadable (" + err.message + ")");
    return false;
  }
  *out = SettingsFromJson(*v, warnings);
  return true;
}
}  // namespace

SettingsStore::SettingsStore(std::filesystem::path path) : path_(std::move(path)) {}

SettingsLoadResult SettingsStore::Load() const {
  SettingsLoadResult result;
  bool existed = false;
  if (TryLoad(path_, &result.settings, &result.warnings, &existed)) {
    result.source = SettingsSource::kPrimary;
    return result;
  }
  result.primary_was_corrupt = existed;
  bool bak_existed = false;
  Settings from_backup;
  if (TryLoad(storage::BackupPathFor(path_), &from_backup, &result.warnings, &bak_existed)) {
    result.settings = from_backup;
    result.source = SettingsSource::kBackup;
    result.warnings.push_back("settings restored from backup");
    return result;
  }
  result.settings = Settings();
  result.source = SettingsSource::kDefaults;
  if (existed || bak_existed) {
    result.warnings.push_back("settings unreadable; secure defaults applied");
  }
  return result;
}

bool SettingsStore::Save(const Settings& s, std::string* error) {
  std::lock_guard<std::mutex> lock(save_mutex_);
  std::string text = json::Serialize(SettingsToJson(s));
  return storage::WriteFileAtomically(path_, text, /*keep_backup=*/true, error);
}

}  // namespace aegis

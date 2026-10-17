// WezCrypt Aegis - crash-safe file persistence.
//
// Writes go to a temporary file in the same directory, are flushed to disk,
// and then atomically replace the target. The previous version is kept as
// "<name>.bak" so that a torn or corrupted primary file can be recovered.
#pragma once

#include <cstddef>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>

namespace aegis::storage {

enum class ReadStatus { kOk, kNotFound, kTooLarge, kIoError };

struct ReadResult {
  ReadStatus status = ReadStatus::kIoError;
  std::string data;
};

ReadResult ReadFile(const std::filesystem::path& path, std::size_t max_bytes);

// Atomically replaces |path| with |data|. When |keep_backup| is true the
// existing file (if any) is preserved as "<path>.bak" before replacement.
bool WriteFileAtomically(const std::filesystem::path& path, std::string_view data,
                         bool keep_backup, std::string* error = nullptr);

std::filesystem::path BackupPathFor(const std::filesystem::path& path);

// Creates |dir| (and parents). On Windows the directory inherits the
// per-user ACL of %LOCALAPPDATA%.
bool EnsureDirectory(const std::filesystem::path& dir, std::string* error = nullptr);

// Best-effort secure delete of a file (overwrite-free; relies on OS).
bool RemoveFileIfExists(const std::filesystem::path& path);

}  // namespace aegis::storage

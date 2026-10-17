#include "storage/atomic_file.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <fstream>
#include <random>
#include <system_error>

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <fcntl.h>
#include <unistd.h>
#endif

namespace aegis::storage {
namespace fs = std::filesystem;

namespace {

std::string UniqueSuffix() {
  static std::atomic<unsigned> counter{0};
  auto now = std::chrono::steady_clock::now().time_since_epoch().count();
  std::random_device rd;
  char buf[64];
  std::snprintf(buf, sizeof(buf), ".tmp-%llx-%x-%u",
                static_cast<unsigned long long>(now), rd(), counter.fetch_add(1));
  return buf;
}

void SetError(std::string* error, std::string msg) {
  if (error) *error = std::move(msg);
}

#if defined(_WIN32)
bool WriteAndFlush(const fs::path& path, std::string_view data, std::string* error) {
  HANDLE h = ::CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
  if (h == INVALID_HANDLE_VALUE) {
    SetError(error, "CreateFileW failed: " + std::to_string(::GetLastError()));
    return false;
  }
  std::size_t written = 0;
  while (written < data.size()) {
    DWORD chunk = static_cast<DWORD>(std::min<std::size_t>(data.size() - written, 1 << 20));
    DWORD n = 0;
    if (!::WriteFile(h, data.data() + written, chunk, &n, nullptr) || n == 0) {
      SetError(error, "WriteFile failed: " + std::to_string(::GetLastError()));
      ::CloseHandle(h);
      return false;
    }
    written += n;
  }
  if (!::FlushFileBuffers(h)) {
    SetError(error, "FlushFileBuffers failed: " + std::to_string(::GetLastError()));
    ::CloseHandle(h);
    return false;
  }
  ::CloseHandle(h);
  return true;
}

bool ReplaceAtomically(const fs::path& from, const fs::path& to, std::string* error) {
  if (!::MoveFileExW(from.c_str(), to.c_str(),
                     MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
    SetError(error, "MoveFileExW failed: " + std::to_string(::GetLastError()));
    return false;
  }
  return true;
}
#else
bool WriteAndFlush(const fs::path& path, std::string_view data, std::string* error) {
  int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
  if (fd < 0) {
    SetError(error, "open failed");
    return false;
  }
  std::size_t written = 0;
  while (written < data.size()) {
    ssize_t n = ::write(fd, data.data() + written, data.size() - written);
    if (n <= 0) {
      SetError(error, "write failed");
      ::close(fd);
      return false;
    }
    written += static_cast<std::size_t>(n);
  }
  if (::fsync(fd) != 0) {
    SetError(error, "fsync failed");
    ::close(fd);
    return false;
  }
  ::close(fd);
  return true;
}

bool ReplaceAtomically(const fs::path& from, const fs::path& to, std::string* error) {
  if (::rename(from.c_str(), to.c_str()) != 0) {
    SetError(error, "rename failed");
    return false;
  }
  int dfd = ::open(to.parent_path().empty() ? "." : to.parent_path().c_str(),
                   O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (dfd >= 0) {
    ::fsync(dfd);
    ::close(dfd);
  }
  return true;
}
#endif

}  // namespace

fs::path BackupPathFor(const fs::path& path) {
  fs::path b = path;
  b += ".bak";
  return b;
}

ReadResult ReadFile(const fs::path& path, std::size_t max_bytes) {
  ReadResult r;
  std::error_code ec;
  if (!fs::exists(path, ec)) {
    r.status = ReadStatus::kNotFound;
    return r;
  }
  auto size = fs::file_size(path, ec);
  if (ec) {
    r.status = ReadStatus::kIoError;
    return r;
  }
  if (size > max_bytes) {
    r.status = ReadStatus::kTooLarge;
    return r;
  }
  std::ifstream in(path, std::ios::binary);
  if (!in) {
    r.status = ReadStatus::kIoError;
    return r;
  }
  r.data.resize(static_cast<std::size_t>(size));
  if (size > 0) in.read(r.data.data(), static_cast<std::streamsize>(size));
  if (!in && !in.eof()) {
    r.status = ReadStatus::kIoError;
    r.data.clear();
    return r;
  }
  r.data.resize(static_cast<std::size_t>(in.gcount() >= 0 ? in.gcount() : 0));
  r.status = ReadStatus::kOk;
  return r;
}

bool WriteFileAtomically(const fs::path& path, std::string_view data,
                         bool keep_backup, std::string* error) {
  std::error_code ec;
  if (!path.parent_path().empty()) fs::create_directories(path.parent_path(), ec);
  fs::path tmp = path;
  tmp += UniqueSuffix();
  if (!WriteAndFlush(tmp, data, error)) {
    fs::remove(tmp, ec);
    return false;
  }
  if (keep_backup && fs::exists(path, ec)) {
    // Copy (not move) so the primary stays valid if we crash before the
    // final rename.
    fs::path bak = BackupPathFor(path);
    fs::path bak_tmp = bak;
    bak_tmp += UniqueSuffix();
    ReadResult current = ReadFile(path, 64 * 1024 * 1024);
    if (current.status == ReadStatus::kOk &&
        WriteAndFlush(bak_tmp, current.data, nullptr)) {
      std::string ignored;
      if (!ReplaceAtomically(bak_tmp, bak, &ignored)) fs::remove(bak_tmp, ec);
    } else {
      fs::remove(bak_tmp, ec);
    }
  }
  if (!ReplaceAtomically(tmp, path, error)) {
    fs::remove(tmp, ec);
    return false;
  }
  return true;
}

bool EnsureDirectory(const fs::path& dir, std::string* error) {
  std::error_code ec;
  if (fs::is_directory(dir, ec)) return true;
  fs::create_directories(dir, ec);
  if (ec) {
    SetError(error, ec.message());
    return false;
  }
  return true;
}

bool RemoveFileIfExists(const fs::path& path) {
  std::error_code ec;
  fs::remove(path, ec);
  return !ec;
}

}  // namespace aegis::storage

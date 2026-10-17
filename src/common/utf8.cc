#include "common/utf8.h"

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

namespace aegis {
namespace {

// Decodes one code point starting at |i|. On success advances |i| and
// returns the code point; on failure returns -1 and advances |i| by one.
long DecodeOne(std::string_view s, std::size_t& i) noexcept {
  const auto b0 = static_cast<unsigned char>(s[i]);
  if (b0 < 0x80) {
    ++i;
    return b0;
  }
  std::size_t len;
  char32_t cp;
  char32_t min;
  if ((b0 & 0xE0) == 0xC0) {
    len = 2; cp = b0 & 0x1F; min = 0x80;
  } else if ((b0 & 0xF0) == 0xE0) {
    len = 3; cp = b0 & 0x0F; min = 0x800;
  } else if ((b0 & 0xF8) == 0xF0) {
    len = 4; cp = b0 & 0x07; min = 0x10000;
  } else {
    ++i;
    return -1;
  }
  if (i + len > s.size()) {
    ++i;
    return -1;
  }
  for (std::size_t k = 1; k < len; ++k) {
    const auto b = static_cast<unsigned char>(s[i + k]);
    if ((b & 0xC0) != 0x80) {
      ++i;
      return -1;
    }
    cp = (cp << 6) | (b & 0x3F);
  }
  if (cp < min || cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF)) {
    ++i;
    return -1;
  }
  i += len;
  return static_cast<long>(cp);
}

}  // namespace

bool IsValidUtf8(std::string_view s) noexcept {
  std::size_t i = 0;
  while (i < s.size()) {
    if (DecodeOne(s, i) < 0) return false;
  }
  return true;
}

bool DecodeUtf8(std::string_view s, std::vector<char32_t>* out) {
  out->clear();
  out->reserve(s.size());
  std::size_t i = 0;
  while (i < s.size()) {
    long cp = DecodeOne(s, i);
    if (cp < 0) return false;
    out->push_back(static_cast<char32_t>(cp));
  }
  return true;
}

void AppendUtf8(char32_t cp, std::string* out) {
  if (cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF)) cp = 0xFFFD;
  if (cp < 0x80) {
    out->push_back(static_cast<char>(cp));
  } else if (cp < 0x800) {
    out->push_back(static_cast<char>(0xC0 | (cp >> 6)));
    out->push_back(static_cast<char>(0x80 | (cp & 0x3F)));
  } else if (cp < 0x10000) {
    out->push_back(static_cast<char>(0xE0 | (cp >> 12)));
    out->push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
    out->push_back(static_cast<char>(0x80 | (cp & 0x3F)));
  } else {
    out->push_back(static_cast<char>(0xF0 | (cp >> 18)));
    out->push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
    out->push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
    out->push_back(static_cast<char>(0x80 | (cp & 0x3F)));
  }
}

std::string EncodeUtf8(const std::vector<char32_t>& cps) {
  std::string out;
  out.reserve(cps.size());
  for (char32_t cp : cps) AppendUtf8(cp, &out);
  return out;
}

std::string ReplaceInvalidUtf8(std::string_view s) {
  std::string out;
  out.reserve(s.size());
  std::size_t i = 0;
  while (i < s.size()) {
    std::size_t start = i;
    long cp = DecodeOne(s, i);
    if (cp < 0) {
      AppendUtf8(0xFFFD, &out);
    } else {
      out.append(s.substr(start, i - start));
    }
  }
  return out;
}

std::size_t TruncateUtf8Boundary(std::string_view s,
                                 std::size_t max_bytes) noexcept {
  if (s.size() <= max_bytes) return s.size();
  std::size_t cut = max_bytes;
  while (cut > 0 && (static_cast<unsigned char>(s[cut]) & 0xC0) == 0x80) --cut;
  return cut;
}

#if defined(_WIN32)
std::wstring Utf8ToWide(std::string_view s) {
  if (s.empty()) return {};
  int n = ::MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()),
                                nullptr, 0);
  if (n <= 0) return {};
  std::wstring out(static_cast<std::size_t>(n), L'\0');
  ::MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()),
                        out.data(), n);
  return out;
}

std::string WideToUtf8(std::wstring_view s) {
  if (s.empty()) return {};
  int n = ::WideCharToMultiByte(CP_UTF8, 0, s.data(), static_cast<int>(s.size()),
                                nullptr, 0, nullptr, nullptr);
  if (n <= 0) return {};
  std::string out(static_cast<std::size_t>(n), '\0');
  ::WideCharToMultiByte(CP_UTF8, 0, s.data(), static_cast<int>(s.size()),
                        out.data(), n, nullptr, nullptr);
  return out;
}
#endif

}  // namespace aegis

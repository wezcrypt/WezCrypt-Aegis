// WezCrypt Aegis - string helpers shared by all security components.
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace aegis {

// ASCII-only case folding. Network identifiers (schemes, hosts after IDNA,
// filter tokens) are ASCII, so locale-dependent conversions are never used.
constexpr char AsciiToLower(char c) noexcept {
  return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c;
}

constexpr bool IsAsciiAlpha(char c) noexcept {
  return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

constexpr bool IsAsciiDigit(char c) noexcept { return c >= '0' && c <= '9'; }

constexpr bool IsAsciiAlnum(char c) noexcept {
  return IsAsciiAlpha(c) || IsAsciiDigit(c);
}

std::string ToLowerAscii(std::string_view s);
bool EqualsIgnoreCaseAscii(std::string_view a, std::string_view b) noexcept;
bool StartsWith(std::string_view s, std::string_view prefix) noexcept;
bool EndsWith(std::string_view s, std::string_view suffix) noexcept;
bool StartsWithIgnoreCaseAscii(std::string_view s,
                               std::string_view prefix) noexcept;
bool EndsWithIgnoreCaseAscii(std::string_view s,
                             std::string_view suffix) noexcept;

std::string_view TrimAsciiWhitespace(std::string_view s) noexcept;

// Splits on a single delimiter. Empty fields are kept.
std::vector<std::string_view> Split(std::string_view s, char delim);

// Splits text into lines, accepting \n, \r\n and \r terminators.
std::vector<std::string_view> SplitLines(std::string_view s);

std::string Join(const std::vector<std::string>& parts, std::string_view sep);

// Escapes text for safe inclusion in HTML element content and quoted
// attribute values.
std::string HtmlEscape(std::string_view s);

// Replaces ASCII control characters (and DEL) with '?', and truncates to
// |max_bytes| on a UTF-8 boundary. Used before logging untrusted input.
std::string SanitizeForLog(std::string_view s, std::size_t max_bytes = 512);

// Parses a non-negative decimal integer without overflow. Returns false on
// any non-digit, empty input or overflow.
bool ParseUint64(std::string_view s, std::uint64_t* out) noexcept;

// Constant-time comparison for fixed-length secrets and digests.
bool ConstantTimeEquals(const std::uint8_t* a, const std::uint8_t* b,
                        std::size_t n) noexcept;

std::string HexEncode(const std::uint8_t* data, std::size_t n);
bool HexDecode(std::string_view hex, std::vector<std::uint8_t>* out);

// FNV-1a 64-bit; used only for hash-table bucketing, never for security.
constexpr std::uint64_t Fnv1a64(std::string_view s) noexcept {
  std::uint64_t h = 1469598103934665603ULL;
  for (char c : s) {
    h ^= static_cast<std::uint8_t>(c);
    h *= 1099511628211ULL;
  }
  return h;
}

}  // namespace aegis

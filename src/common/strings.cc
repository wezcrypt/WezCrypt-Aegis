#include "common/strings.h"

#include "common/utf8.h"

namespace aegis {

std::string ToLowerAscii(std::string_view s) {
  std::string out(s);
  for (char& c : out) c = AsciiToLower(c);
  return out;
}

bool EqualsIgnoreCaseAscii(std::string_view a, std::string_view b) noexcept {
  if (a.size() != b.size()) return false;
  for (std::size_t i = 0; i < a.size(); ++i) {
    if (AsciiToLower(a[i]) != AsciiToLower(b[i])) return false;
  }
  return true;
}

bool StartsWith(std::string_view s, std::string_view prefix) noexcept {
  return s.size() >= prefix.size() && s.substr(0, prefix.size()) == prefix;
}

bool EndsWith(std::string_view s, std::string_view suffix) noexcept {
  return s.size() >= suffix.size() &&
         s.substr(s.size() - suffix.size()) == suffix;
}

bool StartsWithIgnoreCaseAscii(std::string_view s,
                               std::string_view prefix) noexcept {
  return s.size() >= prefix.size() &&
         EqualsIgnoreCaseAscii(s.substr(0, prefix.size()), prefix);
}

bool EndsWithIgnoreCaseAscii(std::string_view s,
                             std::string_view suffix) noexcept {
  return s.size() >= suffix.size() &&
         EqualsIgnoreCaseAscii(s.substr(s.size() - suffix.size()), suffix);
}

std::string_view TrimAsciiWhitespace(std::string_view s) noexcept {
  auto is_ws = [](char c) {
    return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\f' ||
           c == '\v';
  };
  std::size_t b = 0;
  std::size_t e = s.size();
  while (b < e && is_ws(s[b])) ++b;
  while (e > b && is_ws(s[e - 1])) --e;
  return s.substr(b, e - b);
}

std::vector<std::string_view> Split(std::string_view s, char delim) {
  std::vector<std::string_view> out;
  std::size_t start = 0;
  for (std::size_t i = 0; i <= s.size(); ++i) {
    if (i == s.size() || s[i] == delim) {
      out.push_back(s.substr(start, i - start));
      start = i + 1;
    }
  }
  return out;
}

std::vector<std::string_view> SplitLines(std::string_view s) {
  std::vector<std::string_view> out;
  std::size_t start = 0;
  std::size_t i = 0;
  while (i < s.size()) {
    if (s[i] == '\n' || s[i] == '\r') {
      out.push_back(s.substr(start, i - start));
      if (s[i] == '\r' && i + 1 < s.size() && s[i + 1] == '\n') ++i;
      ++i;
      start = i;
    } else {
      ++i;
    }
  }
  if (start < s.size()) out.push_back(s.substr(start));
  return out;
}

std::string Join(const std::vector<std::string>& parts, std::string_view sep) {
  std::string out;
  for (std::size_t i = 0; i < parts.size(); ++i) {
    if (i) out.append(sep);
    out.append(parts[i]);
  }
  return out;
}

std::string HtmlEscape(std::string_view s) {
  std::string out;
  out.reserve(s.size() + s.size() / 8);
  for (char c : s) {
    switch (c) {
      case '&': out += "&amp;"; break;
      case '<': out += "&lt;"; break;
      case '>': out += "&gt;"; break;
      case '"': out += "&quot;"; break;
      case '\'': out += "&#39;"; break;
      case '`': out += "&#96;"; break;
      default:
        if (static_cast<unsigned char>(c) < 0x20 && c != '\n' && c != '\t') {
          out += ' ';
        } else {
          out += c;
        }
    }
  }
  return out;
}

std::string SanitizeForLog(std::string_view s, std::size_t max_bytes) {
  std::string valid = ReplaceInvalidUtf8(s);
  std::string out;
  out.reserve(valid.size() < max_bytes ? valid.size() : max_bytes);
  for (char c : valid) {
    unsigned char u = static_cast<unsigned char>(c);
    out += (u < 0x20 || u == 0x7f) ? '?' : c;
  }
  if (out.size() > max_bytes) {
    std::size_t cut = TruncateUtf8Boundary(out, max_bytes);
    out.resize(cut);
    out += "...";
  }
  return out;
}

bool ParseUint64(std::string_view s, std::uint64_t* out) noexcept {
  if (s.empty() || s.size() > 20) return false;
  std::uint64_t v = 0;
  for (char c : s) {
    if (!IsAsciiDigit(c)) return false;
    std::uint64_t d = static_cast<std::uint64_t>(c - '0');
    if (v > (UINT64_MAX - d) / 10) return false;
    v = v * 10 + d;
  }
  *out = v;
  return true;
}

bool ConstantTimeEquals(const std::uint8_t* a, const std::uint8_t* b,
                        std::size_t n) noexcept {
  std::uint8_t diff = 0;
  for (std::size_t i = 0; i < n; ++i) diff |= static_cast<std::uint8_t>(a[i] ^ b[i]);
  return diff == 0;
}

std::string HexEncode(const std::uint8_t* data, std::size_t n) {
  static constexpr char kHex[] = "0123456789abcdef";
  std::string out;
  out.resize(n * 2);
  for (std::size_t i = 0; i < n; ++i) {
    out[2 * i] = kHex[data[i] >> 4];
    out[2 * i + 1] = kHex[data[i] & 0x0f];
  }
  return out;
}

bool HexDecode(std::string_view hex, std::vector<std::uint8_t>* out) {
  if (hex.size() % 2 != 0) return false;
  auto nibble = [](char c) -> int {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
  };
  std::vector<std::uint8_t> bytes;
  bytes.reserve(hex.size() / 2);
  for (std::size_t i = 0; i < hex.size(); i += 2) {
    int hi = nibble(hex[i]);
    int lo = nibble(hex[i + 1]);
    if (hi < 0 || lo < 0) return false;
    bytes.push_back(static_cast<std::uint8_t>((hi << 4) | lo));
  }
  *out = std::move(bytes);
  return true;
}

}  // namespace aegis

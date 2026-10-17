#include "common/base64.h"

namespace aegis {
namespace {
constexpr char kAlphabet[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

int DecodeChar(char c) {
  if (c >= 'A' && c <= 'Z') return c - 'A';
  if (c >= 'a' && c <= 'z') return c - 'a' + 26;
  if (c >= '0' && c <= '9') return c - '0' + 52;
  if (c == '+') return 62;
  if (c == '/') return 63;
  return -1;
}
}  // namespace

std::string Base64Encode(const std::uint8_t* data, std::size_t n) {
  std::string out;
  out.reserve((n + 2) / 3 * 4);
  std::size_t i = 0;
  for (; i + 2 < n; i += 3) {
    std::uint32_t v = (static_cast<std::uint32_t>(data[i]) << 16) |
                      (static_cast<std::uint32_t>(data[i + 1]) << 8) | data[i + 2];
    out += kAlphabet[(v >> 18) & 63];
    out += kAlphabet[(v >> 12) & 63];
    out += kAlphabet[(v >> 6) & 63];
    out += kAlphabet[v & 63];
  }
  if (i + 1 == n) {
    std::uint32_t v = static_cast<std::uint32_t>(data[i]) << 16;
    out += kAlphabet[(v >> 18) & 63];
    out += kAlphabet[(v >> 12) & 63];
    out += "==";
  } else if (i + 2 == n) {
    std::uint32_t v = (static_cast<std::uint32_t>(data[i]) << 16) |
                      (static_cast<std::uint32_t>(data[i + 1]) << 8);
    out += kAlphabet[(v >> 18) & 63];
    out += kAlphabet[(v >> 12) & 63];
    out += kAlphabet[(v >> 6) & 63];
    out += '=';
  }
  return out;
}

std::string Base64Encode(std::string_view data) {
  return Base64Encode(reinterpret_cast<const std::uint8_t*>(data.data()),
                      data.size());
}

bool Base64Decode(std::string_view in, std::vector<std::uint8_t>* out) {
  std::string clean;
  clean.reserve(in.size());
  for (char c : in) {
    if (c == ' ' || c == '\n' || c == '\r' || c == '\t') continue;
    clean += c;
  }
  if (clean.size() % 4 != 0) return false;
  std::vector<std::uint8_t> bytes;
  bytes.reserve(clean.size() / 4 * 3);
  for (std::size_t i = 0; i < clean.size(); i += 4) {
    const bool last = i + 4 == clean.size();
    int pad = 0;
    int v[4];
    for (int k = 0; k < 4; ++k) {
      char c = clean[i + k];
      if (c == '=') {
        if (!last || k < 2) return false;
        v[k] = 0;
        ++pad;
      } else {
        if (pad) return false;  // data after padding
        v[k] = DecodeChar(c);
        if (v[k] < 0) return false;
      }
    }
    std::uint32_t w = (static_cast<std::uint32_t>(v[0]) << 18) |
                      (static_cast<std::uint32_t>(v[1]) << 12) |
                      (static_cast<std::uint32_t>(v[2]) << 6) |
                      static_cast<std::uint32_t>(v[3]);
    // Reject non-canonical encodings (non-zero discarded bits).
    if (pad == 1 && (w & 0xFF) != 0) return false;
    if (pad == 2 && (w & 0xFFFF) != 0) return false;
    bytes.push_back(static_cast<std::uint8_t>(w >> 16));
    if (pad < 2) bytes.push_back(static_cast<std::uint8_t>(w >> 8));
    if (pad < 1) bytes.push_back(static_cast<std::uint8_t>(w));
  }
  *out = std::move(bytes);
  return true;
}

}  // namespace aegis

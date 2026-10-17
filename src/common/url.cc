#include "common/url.h"

#include <array>
#include <cstdio>

#include "common/idna.h"
#include "common/strings.h"
#include "common/utf8.h"

namespace aegis {
namespace {

bool IsSpecialScheme(std::string_view s) {
  // "aegis" is registered with Chromium as a standard scheme, so it is
  // canonicalized the same way as the WHATWG special schemes.
  return s == "http" || s == "https" || s == "ws" || s == "wss" ||
         s == "ftp" || s == "file" || s == "aegis";
}

int DefaultPort(std::string_view s) {
  if (s == "http" || s == "ws") return 80;
  if (s == "https" || s == "wss") return 443;
  if (s == "ftp") return 21;
  return -1;
}

bool IsForbiddenHostChar(char c) {
  // WHATWG forbidden host code points plus '%' (hosts reaching us are
  // canonical and must not contain percent escapes).
  switch (c) {
    case '\0': case '\t': case '\n': case '\r': case ' ': case '#': case '/':
    case ':': case '<': case '>': case '?': case '@': case '[': case '\\':
    case ']': case '^': case '|': case '%': case '"': case '{': case '}':
    case '`':
      return true;
    default:
      return static_cast<unsigned char>(c) < 0x20 || c == 0x7f;
  }
}

bool ParseIPv4Number(std::string_view part, std::uint64_t* out) {
  if (part.empty()) return false;
  int base = 10;
  if (part.size() >= 2 && part[0] == '0' && (part[1] == 'x' || part[1] == 'X')) {
    base = 16;
    part.remove_prefix(2);
    if (part.empty()) {
      *out = 0;
      return true;
    }
  } else if (part.size() >= 2 && part[0] == '0') {
    base = 8;
    part.remove_prefix(1);
  }
  if (part.size() > 32) return false;
  std::uint64_t v = 0;
  for (char c : part) {
    int d;
    if (c >= '0' && c <= '9') d = c - '0';
    else if (base == 16 && c >= 'a' && c <= 'f') d = c - 'a' + 10;
    else if (base == 16 && c >= 'A' && c <= 'F') d = c - 'A' + 10;
    else return false;
    if (d >= base) return false;
    v = v * static_cast<std::uint64_t>(base) + static_cast<std::uint64_t>(d);
    if (v > 0xFFFFFFFFULL) return false;
  }
  *out = v;
  return true;
}

bool AllDigits(std::string_view s) {
  if (s.empty()) return false;
  for (char c : s) {
    if (c < '0' || c > '9') return false;
  }
  return true;
}

bool EndsInNumber(std::string_view host) {
  auto parts = Split(host, '.');
  if (!parts.empty() && parts.back().empty()) parts.pop_back();
  if (parts.empty()) return false;
  std::string_view last = parts.back();
  if (AllDigits(last)) return true;
  std::uint64_t v;
  return ParseIPv4Number(last, &v);
}

}  // namespace

std::optional<std::string> ParseIPv4(std::string_view host) {
  auto parts = Split(host, '.');
  if (!parts.empty() && parts.back().empty() && parts.size() > 1) parts.pop_back();
  if (parts.empty() || parts.size() > 4) return std::nullopt;
  std::array<std::uint64_t, 4> nums{};
  for (std::size_t i = 0; i < parts.size(); ++i) {
    if (!ParseIPv4Number(parts[i], &nums[i])) return std::nullopt;
  }
  for (std::size_t i = 0; i + 1 < parts.size(); ++i) {
    if (nums[i] > 255) return std::nullopt;
  }
  std::uint64_t last = nums[parts.size() - 1];
  std::size_t remaining = 5 - parts.size();
  std::uint64_t limit = 1ULL << (8 * remaining);
  if (last >= limit) return std::nullopt;
  std::uint64_t v = last;
  for (std::size_t i = 0; i + 1 < parts.size(); ++i) {
    v += nums[i] << (8 * (3 - i));
  }
  char buf[20];
  std::snprintf(buf, sizeof(buf), "%u.%u.%u.%u",
                static_cast<unsigned>((v >> 24) & 255),
                static_cast<unsigned>((v >> 16) & 255),
                static_cast<unsigned>((v >> 8) & 255),
                static_cast<unsigned>(v & 255));
  return std::string(buf);
}

bool IsValidIPv6Literal(std::string_view host) {
  if (host.empty() || host.size() > 45) return false;
  int groups = 0;
  bool double_colon = false;
  std::size_t i = 0;
  if (StartsWith(host, "::")) {
    double_colon = true;
    i = 2;
    if (i == host.size()) return true;
  } else if (host[0] == ':') {
    return false;
  }
  while (i < host.size()) {
    std::size_t start = i;
    while (i < host.size() && host[i] != ':' && host[i] != '.') {
      char c = host[i];
      bool hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
      if (!hex) return false;
      ++i;
    }
    if (i < host.size() && host[i] == '.') {
      // Embedded IPv4 in the last 32 bits.
      std::string_view v4 = host.substr(start);
      auto parts = Split(v4, '.');
      if (parts.size() != 4) return false;
      for (auto p : parts) {
        std::uint64_t octet = 0;
        if (p.empty() || p.size() > 3 || !ParseUint64(p, &octet) || octet > 255) return false;
      }
      groups += 2;
      i = host.size();
      break;
    }
    std::size_t len = i - start;
    if (len == 0 || len > 4) return false;
    ++groups;
    if (i == host.size()) break;
    ++i;  // ':'
    if (i < host.size() && host[i] == ':') {
      if (double_colon) return false;
      double_colon = true;
      ++i;
      if (i == host.size()) break;
    } else if (i == host.size()) {
      return false;  // trailing single colon
    }
  }
  return double_colon ? groups < 8 : groups == 8;
}

int Url::EffectivePort() const {
  return port >= 0 ? port : DefaultPort(scheme);
}

std::string Url::HostForAuthority() const {
  return host_type == HostType::kIPv6 ? "[" + host + "]" : host;
}

std::string Url::Origin() const {
  if (!has_authority || host.empty()) return {};
  std::string o = scheme + "://" + HostForAuthority();
  if (port >= 0 && port != DefaultPort(scheme)) o += ":" + std::to_string(port);
  return o;
}

std::string Url::Spec(bool include_fragment) const {
  std::string s = scheme + ":";
  if (has_authority) {
    s += "//" + HostForAuthority();
    if (port >= 0 && port != DefaultPort(scheme)) s += ":" + std::to_string(port);
  }
  s += path;
  if (has_query) s += "?" + query;
  if (include_fragment && has_fragment) s += "#" + fragment;
  return s;
}

std::string NormalizeHostForMatching(std::string_view host) {
  std::string h = ToLowerAscii(host);
  if (!h.empty() && h.back() == '.') h.pop_back();
  return h;
}

std::optional<Url> ParseUrl(std::string_view input) {
  if (input.size() > kMaxUrlBytes) return std::nullopt;
  std::string_view s = TrimAsciiWhitespace(input);
  if (s.empty() || !IsValidUtf8(s)) return std::nullopt;
  for (char c : s) {
    // Embedded tabs/newlines are stripped by WHATWG parsers; treating them
    // as invalid avoids any disagreement with the engine.
    if (c == '\t' || c == '\n' || c == '\r' || c == '\0') return std::nullopt;
  }

  Url url;
  std::size_t colon = s.find(':');
  if (colon == std::string_view::npos || colon == 0) return std::nullopt;
  std::string_view scheme = s.substr(0, colon);
  if (!IsAsciiAlpha(scheme[0])) return std::nullopt;
  for (char c : scheme) {
    if (!IsAsciiAlnum(c) && c != '+' && c != '-' && c != '.') return std::nullopt;
  }
  if (scheme.size() > 32) return std::nullopt;
  url.scheme = ToLowerAscii(scheme);
  std::string_view rest = s.substr(colon + 1);

  const bool special = IsSpecialScheme(url.scheme);
  auto is_slash = [&](char c) { return c == '/' || (special && c == '\\'); };

  // Split off fragment and query first (they never affect the authority).
  std::size_t hash = rest.find('#');
  if (hash != std::string_view::npos) {
    url.has_fragment = true;
    url.fragment = std::string(rest.substr(hash + 1));
    rest = rest.substr(0, hash);
  }

  bool hierarchical = rest.size() >= 2 && is_slash(rest[0]) && is_slash(rest[1]);
  if (special && url.scheme != "file" && !hierarchical) {
    // "http:example.com" and similar forms are rejected rather than guessed.
    return std::nullopt;
  }

  if (hierarchical) {
    url.has_authority = true;
    rest.remove_prefix(2);
    std::size_t end = 0;
    while (end < rest.size() && !is_slash(rest[end]) && rest[end] != '?') ++end;
    std::string_view authority = rest.substr(0, end);
    rest = rest.substr(end);

    std::size_t at = authority.rfind('@');
    if (at != std::string_view::npos) {
      url.has_credentials = true;
      authority = authority.substr(at + 1);
    }
    std::string_view host_port = authority;
    std::string_view port_str;
    if (!host_port.empty() && host_port[0] == '[') {
      std::size_t close = host_port.find(']');
      if (close == std::string_view::npos) return std::nullopt;
      std::string_view v6 = host_port.substr(1, close - 1);
      if (!IsValidIPv6Literal(v6)) return std::nullopt;
      url.host = ToLowerAscii(v6);
      url.host_type = HostType::kIPv6;
      std::string_view after = host_port.substr(close + 1);
      if (!after.empty()) {
        if (after[0] != ':') return std::nullopt;
        port_str = after.substr(1);
      }
    } else {
      std::size_t pc = host_port.rfind(':');
      std::string_view host = host_port;
      if (pc != std::string_view::npos) {
        host = host_port.substr(0, pc);
        port_str = host_port.substr(pc + 1);
      }
      if (host.empty()) {
        if (url.scheme != "file") return std::nullopt;
      } else {
        bool ascii = true;
        for (char c : host) {
          if (static_cast<unsigned char>(c) >= 0x80) ascii = false;
        }
        std::string ascii_host;
        if (ascii) {
          ascii_host = ToLowerAscii(host);
        } else {
          auto converted = idna::ToAscii(host);
          if (!converted) return std::nullopt;
          ascii_host = *converted;
        }
        for (char c : ascii_host) {
          if (IsForbiddenHostChar(c)) return std::nullopt;
        }
        if (ascii_host.size() > 253 + 1) return std::nullopt;
        if (special && EndsInNumber(ascii_host)) {
          auto v4 = ParseIPv4(ascii_host);
          if (!v4) return std::nullopt;
          url.host = *v4;
          url.host_type = HostType::kIPv4;
        } else {
          for (std::string_view label : Split(ascii_host, '.')) {
            if (label.size() > 63) return std::nullopt;
          }
          url.host = ascii_host;
          url.host_type = HostType::kDomain;
        }
      }
    }
    if (!port_str.empty()) {
      std::uint64_t p;
      if (!ParseUint64(port_str, &p) || p > 65535) return std::nullopt;
      url.port = static_cast<int>(p);
      if (url.port == DefaultPort(url.scheme)) url.port = -1;
    }
  }

  std::size_t q = rest.find('?');
  std::string_view path = rest;
  if (q != std::string_view::npos) {
    url.has_query = true;
    url.query = std::string(rest.substr(q + 1));
    path = rest.substr(0, q);
  }
  url.path = std::string(path);
  if (special) {
    for (char& c : url.path) {
      if (c == '\\') c = '/';
    }
    if (url.has_authority && url.path.empty()) url.path = "/";
  }
  return url;
}

bool IsLocalOrPrivateHost(const Url& url) {
  const std::string h = NormalizeHostForMatching(url.host);
  if (h == "localhost" || EndsWith(h, ".localhost")) return true;
  if (url.host_type == HostType::kIPv4) {
    auto parts = Split(h, '.');
    if (parts.size() != 4) return false;
    std::uint64_t oct[4];
    for (std::size_t i = 0; i < 4; ++i) {
      if (!ParseUint64(parts[i], &oct[i]) || oct[i] > 255) return false;
    }
    const std::uint64_t a = oct[0], b = oct[1];
    if (a == 127 || a == 10 || a == 0) return true;
    if (a == 172 && b >= 16 && b <= 31) return true;
    if (a == 192 && b == 168) return true;
    if (a == 169 && b == 254) return true;
    if (a == 100 && b >= 64 && b <= 127) return true;
    return false;
  }
  if (url.host_type == HostType::kIPv6) {
    if (h == "::1" || h == "::") return true;
    if (StartsWith(h, "fe8") || StartsWith(h, "fe9") || StartsWith(h, "fea") ||
        StartsWith(h, "feb"))
      return true;  // fe80::/10
    if (StartsWith(h, "fc") || StartsWith(h, "fd")) return true;  // fc00::/7
    if (StartsWith(h, "::ffff:")) {
      Url inner;
      inner.host = h.substr(7);
      inner.host_type = HostType::kIPv4;
      return IsLocalOrPrivateHost(inner);
    }
  }
  return false;
}

std::optional<Url> InnerUrlOfBlob(const Url& url) {
  if (url.scheme != "blob") return std::nullopt;
  std::string inner = url.path;
  if (url.has_query) inner += "?" + url.query;
  return ParseUrl(inner);
}

}  // namespace aegis

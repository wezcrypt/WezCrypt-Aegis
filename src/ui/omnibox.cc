#include "ui/omnibox.h"

#include "common/strings.h"
#include "common/url.h"

namespace aegis {

std::string UrlEncodeComponent(std::string_view s) {
  static constexpr char kHex[] = "0123456789ABCDEF";
  std::string out;
  out.reserve(s.size() * 3);
  for (unsigned char c : s) {
    if (IsAsciiAlnum(static_cast<char>(c)) || c == '-' || c == '_' || c == '.' || c == '~') {
      out.push_back(static_cast<char>(c));
    } else if (c == ' ') {
      out.push_back('+');
    } else {
      out.push_back('%');
      out.push_back(kHex[c >> 4]);
      out.push_back(kHex[c & 15]);
    }
  }
  return out;
}

std::string UrlDecodeComponent(std::string_view s) {
  auto hex = [](char c) -> int {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
  };
  std::string out;
  out.reserve(s.size());
  for (std::size_t i = 0; i < s.size(); ++i) {
    if (s[i] == '+') {
      out.push_back(' ');
    } else if (s[i] == '%' && i + 2 < s.size() && hex(s[i + 1]) >= 0 && hex(s[i + 2]) >= 0) {
      out.push_back(static_cast<char>(hex(s[i + 1]) * 16 + hex(s[i + 2])));
      i += 2;
    } else {
      out.push_back(s[i]);
    }
  }
  return out;
}

std::string QueryParam(std::string_view query, std::string_view key) {
  for (std::string_view pair : Split(query, '&')) {
    std::size_t eq = pair.find('=');
    std::string_view k = pair.substr(0, eq);
    if (UrlDecodeComponent(k) == key) {
      return eq == std::string_view::npos ? std::string() : UrlDecodeComponent(pair.substr(eq + 1));
    }
  }
  return {};
}

namespace {

bool LooksLikeHost(std::string_view text) {
  if (text.empty() || text.find(' ') != std::string_view::npos) return false;
  std::string_view host = text.substr(0, text.find_first_of("/?#"));
  // Strip port.
  if (!host.empty() && host[0] != '[') {
    std::size_t colon = host.rfind(':');
    if (colon != std::string_view::npos) {
      std::uint64_t port;
      if (!ParseUint64(host.substr(colon + 1), &port) || port > 65535) return false;
      host = host.substr(0, colon);
    }
  }
  if (host.empty()) return false;
  if (host == "localhost") return true;
  if (host.front() == '[') return true;
  if (host.find('.') == std::string_view::npos) return false;
  if (host.front() == '.' || host.back() == '.') return false;
  for (char c : host) {
    unsigned char u = static_cast<unsigned char>(c);
    if (!(IsAsciiAlnum(c) || c == '-' || c == '.' || c == '_' || u >= 0x80)) return false;
  }
  // The last label must look like a TLD or the host must be an IPv4 address.
  std::string_view tld = host.substr(host.rfind('.') + 1);
  if (ParseIPv4(host)) return true;
  if (tld.size() < 2) return false;
  for (char c : tld) {
    if (IsAsciiDigit(c)) return false;
  }
  return true;
}

}  // namespace

OmniboxResult ResolveOmniboxInput(std::string_view raw) {
  OmniboxResult r;
  std::string_view text = TrimAsciiWhitespace(raw);
  if (text.empty()) {
    r.url = "aegis://newtab/";
    return r;
  }
  std::size_t colon = text.find(':');
  if (colon != std::string_view::npos) {
    std::string scheme = ToLowerAscii(text.substr(0, colon));
    if (scheme == "http" || scheme == "https" || scheme == "aegis") {
      if (auto u = ParseUrl(text)) {
        r.url = u->Spec();
        return r;
      }
    } else if (scheme == "file") {
      if (auto u = ParseUrl(text)) {
        r.url = u->Spec();
        r.typed_file_url = true;
        return r;
      }
    } else if (scheme == "about" && ToLowerAscii(text) == "about:blank") {
      r.url = "about:blank";
      return r;
    }
  }
  if (LooksLikeHost(text)) {
    std::string candidate = "https://" + std::string(text);
    if (auto u = ParseUrl(candidate)) {
      // Local development hosts rarely have certificates; they are not
      // reachable from the Internet, so plain HTTP is used for them.
      if (IsLocalOrPrivateHost(*u)) u->scheme = "http";
      r.url = u->Spec();
      return r;
    }
  }
  r.is_search = true;
  r.url = "https://duckduckgo.com/html/?q=" + UrlEncodeComponent(text);
  return r;
}

}  // namespace aegis

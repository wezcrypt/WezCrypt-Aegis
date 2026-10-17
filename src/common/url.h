// WezCrypt Aegis - URL parsing for security decisions.
//
// URLs reaching the security engine come from Chromium and are already
// canonical. This parser is nevertheless strict and defensive: it is also
// used for user input, settings, filter-list URLs and update manifests, and
// it must never disagree with the engine in a way that weakens a decision.
// Where input is ambiguous the parser rejects it.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace aegis {

enum class HostType { kNone, kDomain, kIPv4, kIPv6 };

struct Url {
  std::string scheme;    // lower-case, without ':'
  bool has_authority = false;
  bool has_credentials = false;
  std::string host;      // lower-case ASCII; IPv6 without brackets
  HostType host_type = HostType::kNone;
  int port = -1;         // explicit port, -1 if absent
  std::string path;      // for non-hierarchical schemes: everything after ':'
  std::string query;     // without '?'
  bool has_query = false;
  std::string fragment;  // without '#'
  bool has_fragment = false;

  bool IsHttpLike() const { return scheme == "http" || scheme == "https"; }
  bool IsWebSocket() const { return scheme == "ws" || scheme == "wss"; }
  bool IsSecureScheme() const { return scheme == "https" || scheme == "wss"; }
  int EffectivePort() const;
  // "scheme://host[:port]" for hierarchical URLs, empty otherwise.
  std::string Origin() const;
  // Host with brackets for IPv6, as used in a URL authority.
  std::string HostForAuthority() const;
  // Serialized URL without credentials.
  std::string Spec(bool include_fragment = true) const;
};

// Maximum URL size accepted (matches Chromium's 2 MiB limit).
inline constexpr std::size_t kMaxUrlBytes = 2 * 1024 * 1024;

std::optional<Url> ParseUrl(std::string_view input);

// Returns the host lower-cased with a single trailing dot removed.
std::string NormalizeHostForMatching(std::string_view host);

// IPv4 parsing per the WHATWG URL standard (accepts hex/octal/short forms,
// so that "0x7f.1" is understood as 127.0.0.1). Returns dotted-quad form.
std::optional<std::string> ParseIPv4(std::string_view host);
bool IsValidIPv6Literal(std::string_view host);

// True for loopback, private (RFC 1918), link-local, CGNAT and unique-local
// addresses, and for the "localhost" name family.
bool IsLocalOrPrivateHost(const Url& url);

// For "blob:https://a.example/uuid" returns the parsed inner URL.
std::optional<Url> InnerUrlOfBlob(const Url& url);

}  // namespace aegis

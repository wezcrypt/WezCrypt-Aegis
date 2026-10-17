// WezCrypt Aegis - address bar input interpretation.
#pragma once

#include <string>
#include <string_view>

namespace aegis {

struct OmniboxResult {
  std::string url;
  bool is_search = false;
  bool typed_file_url = false;  // explicit file:// navigation by the user
};

// Interprets text typed into the address bar:
//  * "https://..." / "http://..." / "aegis://..." / "file:///..." are used as-is
//  * host-like input ("example.com", "example.com/path", "localhost:8080")
//    becomes https:// (HTTPS by default; HTTPS-first handles fallback)
//  * script and data URLs are never executed from the address bar; they
//    are treated as search text
//  * anything else is a search sent to DuckDuckGo's HTML endpoint
OmniboxResult ResolveOmniboxInput(std::string_view text);

std::string UrlEncodeComponent(std::string_view s);
std::string UrlDecodeComponent(std::string_view s);

// Parses "a=1&b=2" style queries; returns the first value for |key|.
std::string QueryParam(std::string_view query, std::string_view key);

}  // namespace aegis

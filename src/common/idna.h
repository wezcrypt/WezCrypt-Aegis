// WezCrypt Aegis - IDNA helpers: RFC 3492 punycode and a conservative
// homograph (spoofing) check for address-bar display.
//
// Scope: this is not a full UTS #46 implementation. Chromium canonicalizes
// every URL it hands to WezCrypt Aegis, so hosts arriving from the engine are
// already ASCII (A-labels). These helpers are used to (1) convert Unicode
// Public Suffix List rules and user-entered site exceptions to A-labels and
// (2) decide whether an A-label may be shown to the user in Unicode form.
#pragma once

#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace aegis::idna {

// RFC 3492 encode of a single label's code points (without "xn--").
std::optional<std::string> PunycodeEncode(const std::vector<char32_t>& input);
// RFC 3492 decode of a single label (without "xn--").
std::optional<std::vector<char32_t>> PunycodeDecode(std::string_view input);

// Converts a UTF-8 host to ASCII. ASCII letters are lower-cased; non-ASCII
// labels are punycode-encoded. Ideographic full stops are treated as dots.
// Returns nullopt for malformed UTF-8 or labels that cannot be encoded.
std::optional<std::string> ToAscii(std::string_view host_utf8);

// Decodes all xn-- labels. Returns nullopt if any label fails to decode.
std::optional<std::string> ToUnicode(std::string_view ascii_host);

struct DisplayHost {
  std::string text;      // what to render in the UI
  bool is_idn = false;   // host contains at least one xn-- label
  bool spoof_risk = false;  // Unicode form was rejected by the spoof check
};

// Chooses the form of |ascii_host| to show users. The Unicode form is used
// only when every label passes the spoof check; otherwise the A-label form
// is shown so that look-alike domains are visible.
DisplayHost ForDisplay(std::string_view ascii_host);

// Returns true when a decoded label is considered safe to display.
bool IsLabelSafeForDisplay(const std::vector<char32_t>& label);

}  // namespace aegis::idna

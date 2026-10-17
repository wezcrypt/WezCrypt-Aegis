// WezCrypt Aegis - strict UTF-8 helpers.
#pragma once

#include <cstddef>
#include <string>
#include <string_view>
#include <vector>

namespace aegis {

// Returns true when |s| is well-formed UTF-8 (no overlongs, no surrogates,
// no code points above U+10FFFF).
bool IsValidUtf8(std::string_view s) noexcept;

// Decodes |s| into code points. Returns false on malformed input.
bool DecodeUtf8(std::string_view s, std::vector<char32_t>* out);

// Encodes a code point. Invalid code points are encoded as U+FFFD.
void AppendUtf8(char32_t cp, std::string* out);

std::string EncodeUtf8(const std::vector<char32_t>& cps);

// Replaces malformed sequences with U+FFFD.
std::string ReplaceInvalidUtf8(std::string_view s);

// Largest prefix length <= max_bytes that does not split a UTF-8 sequence.
std::size_t TruncateUtf8Boundary(std::string_view s,
                                 std::size_t max_bytes) noexcept;

#if defined(_WIN32)
std::wstring Utf8ToWide(std::string_view s);
std::string WideToUtf8(std::wstring_view s);
#endif

}  // namespace aegis

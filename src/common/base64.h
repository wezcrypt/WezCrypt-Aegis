// WezCrypt Aegis - RFC 4648 base64 (standard alphabet, strict padding).
#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace aegis {

std::string Base64Encode(const std::uint8_t* data, std::size_t n);
std::string Base64Encode(std::string_view data);

// Strict decoder: rejects non-alphabet characters, bad padding and
// non-canonical trailing bits. ASCII whitespace is ignored.
bool Base64Decode(std::string_view in, std::vector<std::uint8_t>* out);

}  // namespace aegis

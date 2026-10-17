#include "common/idna.h"

#include <algorithm>

#include "common/strings.h"
#include "common/utf8.h"

namespace aegis::idna {
namespace {

constexpr std::uint32_t kBase = 36;
constexpr std::uint32_t kTMin = 1;
constexpr std::uint32_t kTMax = 26;
constexpr std::uint32_t kSkew = 38;
constexpr std::uint32_t kDamp = 700;
constexpr std::uint32_t kInitialBias = 72;
constexpr std::uint32_t kInitialN = 128;
constexpr std::size_t kMaxLabelInput = 256;

char EncodeDigit(std::uint32_t d) {
  return static_cast<char>(d < 26 ? 'a' + d : '0' + (d - 26));
}

int DecodeDigit(char c) {
  if (c >= '0' && c <= '9') return c - '0' + 26;
  if (c >= 'a' && c <= 'z') return c - 'a';
  if (c >= 'A' && c <= 'Z') return c - 'A';
  return -1;
}

std::uint32_t Adapt(std::uint32_t delta, std::uint32_t numpoints, bool first) {
  delta = first ? delta / kDamp : delta / 2;
  delta += delta / numpoints;
  std::uint32_t k = 0;
  while (delta > ((kBase - kTMin) * kTMax) / 2) {
    delta /= kBase - kTMin;
    k += kBase;
  }
  return k + (kBase - kTMin + 1) * delta / (delta + kSkew);
}

enum class Script { kCommon, kLatin, kCyrillic, kGreek, kCjk, kArabic, kHebrew, kOther };

Script ScriptOf(char32_t c) {
  if ((c >= '0' && c <= '9') || c == '-') return Script::kCommon;
  if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) return Script::kLatin;
  if ((c >= 0x00C0 && c <= 0x024F && c != 0x00D7 && c != 0x00F7) ||
      (c >= 0x1E00 && c <= 0x1EFF))
    return Script::kLatin;
  if (c >= 0x0400 && c <= 0x052F) return Script::kCyrillic;
  if ((c >= 0x0370 && c <= 0x03FF) || (c >= 0x1F00 && c <= 0x1FFF)) return Script::kGreek;
  if ((c >= 0x3040 && c <= 0x30FF) || (c >= 0x3400 && c <= 0x4DBF) ||
      (c >= 0x4E00 && c <= 0x9FFF) || (c >= 0xAC00 && c <= 0xD7AF) ||
      (c >= 0x1100 && c <= 0x11FF))
    return Script::kCjk;
  if (c >= 0x0600 && c <= 0x06FF) return Script::kArabic;
  if (c >= 0x0590 && c <= 0x05FF) return Script::kHebrew;
  return Script::kOther;
}

bool IsInvisibleOrControl(char32_t c) {
  return c < 0x20 || (c >= 0x7F && c <= 0x9F) || c == 0x00AD ||
         (c >= 0x200B && c <= 0x200F) || (c >= 0x202A && c <= 0x202E) ||
         (c >= 0x2060 && c <= 0x2064) || (c >= 0x2066 && c <= 0x2069) ||
         c == 0xFEFF || c == 0x034F || (c >= 0xFE00 && c <= 0xFE0F) ||
         (c >= 0x0300 && c <= 0x036F);  // combining diacritics
}

// Cyrillic letters that render like Latin letters in common fonts.
bool IsLatinLookalikeCyrillic(char32_t c) {
  static constexpr char32_t kSet[] = {
      0x0430, 0x0435, 0x043E, 0x0440, 0x0441, 0x0443, 0x0445, 0x0456,
      0x0458, 0x0455, 0x0501, 0x051B, 0x051D, 0x04CF, 0x04BB, 0x043A,
      0x0432, 0x043C, 0x043D, 0x0442, 0x0410, 0x0412, 0x0415, 0x041A,
      0x041C, 0x041D, 0x041E, 0x0420, 0x0421, 0x0422, 0x0425, 0x0406};
  return std::find(std::begin(kSet), std::end(kSet), c) != std::end(kSet);
}

}  // namespace

std::optional<std::string> PunycodeEncode(const std::vector<char32_t>& input) {
  if (input.size() > kMaxLabelInput) return std::nullopt;
  std::string out;
  for (char32_t c : input) {
    if (c < 0x80) out.push_back(static_cast<char>(c));
  }
  const std::uint32_t b = static_cast<std::uint32_t>(out.size());
  std::uint32_t h = b;
  if (b > 0) out.push_back('-');
  std::uint32_t n = kInitialN;
  std::uint32_t delta = 0;
  std::uint32_t bias = kInitialBias;
  const std::uint32_t total = static_cast<std::uint32_t>(input.size());
  while (h < total) {
    std::uint32_t m = UINT32_MAX;
    for (char32_t c : input) {
      if (c >= n && c < m) m = c;
    }
    if ((m - n) > (UINT32_MAX - delta) / (h + 1)) return std::nullopt;
    delta += (m - n) * (h + 1);
    n = m;
    for (char32_t c : input) {
      if (c < n) {
        if (++delta == 0) return std::nullopt;
      }
      if (c == n) {
        std::uint32_t q = delta;
        for (std::uint32_t k = kBase;; k += kBase) {
          std::uint32_t t = k <= bias ? kTMin : (k >= bias + kTMax ? kTMax : k - bias);
          if (q < t) break;
          out.push_back(EncodeDigit(t + (q - t) % (kBase - t)));
          q = (q - t) / (kBase - t);
        }
        out.push_back(EncodeDigit(q));
        bias = Adapt(delta, h + 1, h == b);
        delta = 0;
        ++h;
      }
    }
    ++delta;
    ++n;
  }
  return out;
}

std::optional<std::vector<char32_t>> PunycodeDecode(std::string_view input) {
  if (input.size() > kMaxLabelInput) return std::nullopt;
  std::vector<char32_t> out;
  std::size_t basic_end = input.rfind('-');
  std::size_t pos = 0;
  if (basic_end != std::string_view::npos) {
    for (std::size_t i = 0; i < basic_end; ++i) {
      if (static_cast<unsigned char>(input[i]) >= 0x80) return std::nullopt;
      out.push_back(static_cast<char32_t>(input[i]));
    }
    pos = basic_end + 1;
  }
  std::uint32_t n = kInitialN;
  std::uint32_t i = 0;
  std::uint32_t bias = kInitialBias;
  while (pos < input.size()) {
    std::uint32_t oldi = i;
    std::uint32_t w = 1;
    for (std::uint32_t k = kBase;; k += kBase) {
      if (pos >= input.size()) return std::nullopt;
      int digit = DecodeDigit(input[pos++]);
      if (digit < 0) return std::nullopt;
      std::uint32_t d = static_cast<std::uint32_t>(digit);
      if (d > (UINT32_MAX - i) / w) return std::nullopt;
      i += d * w;
      std::uint32_t t = k <= bias ? kTMin : (k >= bias + kTMax ? kTMax : k - bias);
      if (d < t) break;
      if (w > UINT32_MAX / (kBase - t)) return std::nullopt;
      w *= kBase - t;
    }
    std::uint32_t len = static_cast<std::uint32_t>(out.size()) + 1;
    bias = Adapt(i - oldi, len, oldi == 0);
    if (i / len > UINT32_MAX - n) return std::nullopt;
    n += i / len;
    i %= len;
    if (n > 0x10FFFF || (n >= 0xD800 && n <= 0xDFFF)) return std::nullopt;
    out.insert(out.begin() + i, static_cast<char32_t>(n));
    ++i;
    if (out.size() > kMaxLabelInput) return std::nullopt;
  }
  return out;
}

std::optional<std::string> ToAscii(std::string_view host_utf8) {
  std::vector<char32_t> cps;
  if (!DecodeUtf8(host_utf8, &cps)) return std::nullopt;
  // Map ideographic and fullwidth full stops to '.'.
  for (char32_t& c : cps) {
    if (c == 0x3002 || c == 0xFF0E || c == 0xFF61) c = '.';
  }
  std::string out;
  std::vector<char32_t> label;
  auto flush = [&]() -> bool {
    bool ascii = std::all_of(label.begin(), label.end(),
                             [](char32_t c) { return c < 0x80; });
    if (ascii) {
      for (char32_t c : label) out.push_back(AsciiToLower(static_cast<char>(c)));
    } else {
      for (char32_t c : label) {
        if (IsInvisibleOrControl(c) && c >= 0x200B) return false;
      }
      std::vector<char32_t> lowered = label;
      for (char32_t& c : lowered) {
        if (c >= 'A' && c <= 'Z') c = c - 'A' + 'a';
      }
      auto enc = PunycodeEncode(lowered);
      if (!enc) return false;
      out += "xn--";
      out += *enc;
    }
    label.clear();
    return true;
  };
  for (char32_t c : cps) {
    if (c == '.') {
      if (!flush()) return std::nullopt;
      out.push_back('.');
    } else {
      label.push_back(c);
    }
  }
  if (!flush()) return std::nullopt;
  return out;
}

std::optional<std::string> ToUnicode(std::string_view ascii_host) {
  std::string out;
  for (std::string_view label : Split(ascii_host, '.')) {
    if (StartsWithIgnoreCaseAscii(label, "xn--")) {
      auto dec = PunycodeDecode(label.substr(4));
      if (!dec) return std::nullopt;
      out += EncodeUtf8(*dec);
    } else {
      out.append(label);
    }
    out.push_back('.');
  }
  if (!out.empty()) out.pop_back();
  return out;
}

bool IsLabelSafeForDisplay(const std::vector<char32_t>& label) {
  if (label.empty()) return true;
  bool has_latin = false, has_cyrillic = false, has_greek = false;
  bool has_other = false, has_cjk = false;
  bool all_cyrillic_lookalike = true;
  bool any_cyrillic = false;
  for (char32_t c : label) {
    if (IsInvisibleOrControl(c)) return false;
    switch (ScriptOf(c)) {
      case Script::kCommon: break;
      case Script::kLatin: has_latin = true; break;
      case Script::kCyrillic:
        has_cyrillic = true;
        any_cyrillic = true;
        if (!IsLatinLookalikeCyrillic(c)) all_cyrillic_lookalike = false;
        break;
      case Script::kGreek: has_greek = true; break;
      case Script::kCjk: has_cjk = true; break;
      case Script::kArabic:
      case Script::kHebrew:
      case Script::kOther: has_other = true; break;
    }
  }
  // Mixed confusable scripts are never displayed in Unicode.
  int confusable_scripts = (has_latin ? 1 : 0) + (has_cyrillic ? 1 : 0) + (has_greek ? 1 : 0);
  if (confusable_scripts > 1) return false;
  // Whole-script confusables: a pure Cyrillic label made only of letters
  // that look Latin (e.g. "аррӏе").
  if (any_cyrillic && all_cyrillic_lookalike) return false;
  // Unclassified scripts are shown as punycode: we only render what the
  // spoof check understands.
  if (has_other) return false;
  if (has_cjk && (has_cyrillic || has_greek)) return false;
  return true;
}

DisplayHost ForDisplay(std::string_view ascii_host) {
  DisplayHost d;
  d.text = std::string(ascii_host);
  bool any_idn = false;
  for (std::string_view label : Split(ascii_host, '.')) {
    if (StartsWithIgnoreCaseAscii(label, "xn--")) any_idn = true;
  }
  d.is_idn = any_idn;
  if (!any_idn) return d;
  std::string out;
  for (std::string_view label : Split(ascii_host, '.')) {
    if (StartsWithIgnoreCaseAscii(label, "xn--")) {
      auto dec = PunycodeDecode(label.substr(4));
      if (!dec || !IsLabelSafeForDisplay(*dec)) {
        d.spoof_risk = true;
        return d;
      }
      out += EncodeUtf8(*dec);
    } else {
      out.append(label);
    }
    out.push_back('.');
  }
  if (!out.empty()) out.pop_back();
  d.text = out;
  return d;
}

}  // namespace aegis::idna

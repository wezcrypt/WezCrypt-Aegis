// WezCrypt Aegis - visual identity: dark graphite with electric cyan accents.
#pragma once

#include "include/internal/cef_types.h"

namespace aegis::theme {

inline constexpr cef_color_t kWindowBackground = 0xFF121417;
inline constexpr cef_color_t kTabStripBackground = 0xFF0E1013;
inline constexpr cef_color_t kToolbarBackground = 0xFF1A1D22;
inline constexpr cef_color_t kFieldBackground = 0xFF23272E;
inline constexpr cef_color_t kTabActiveBackground = 0xFF1A1D22;
inline constexpr cef_color_t kTabInactiveBackground = 0xFF0E1013;
inline constexpr cef_color_t kTextPrimary = 0xFFE6E9EE;
inline constexpr cef_color_t kTextMuted = 0xFF9AA3AE;
inline constexpr cef_color_t kAccentCyan = 0xFF22D3EE;
inline constexpr cef_color_t kAccentBlue = 0xFF3B82F6;
inline constexpr cef_color_t kPrivateAccent = 0xFF8B9CF7;
inline constexpr cef_color_t kWarning = 0xFFFBBF24;
inline constexpr cef_color_t kDanger = 0xFFF87171;
inline constexpr cef_color_t kOk = 0xFF34D399;
inline constexpr cef_color_t kSelection = 0xFF155E75;

// Segoe Fluent Icons ships with Windows 11; Segoe MDL2 Assets provides the
// same code points on Windows 10.
inline constexpr char kIconFont[] = "Segoe Fluent Icons, Segoe MDL2 Assets, 14px";
inline constexpr char kUiFont[] = "Segoe UI Variable Text, Segoe UI, 13px";
inline constexpr char kUiFontBold[] = "Segoe UI Variable Text, Segoe UI, Bold 12px";
inline constexpr char kAddressFont[] = "Segoe UI Variable Text, Segoe UI, 14px";

// Icon glyphs (Segoe MDL2 / Fluent code points).
inline constexpr char kGlyphBack[] = "\xee\x9c\xab";       // U+E72B
inline constexpr char kGlyphForward[] = "\xee\x9c\xaa";    // U+E72A
inline constexpr char kGlyphRefresh[] = "\xee\x9c\xac";    // U+E72C
inline constexpr char kGlyphStop[] = "\xee\x9c\x91";       // U+E711
inline constexpr char kGlyphHome[] = "\xee\xa0\x8f";       // U+E80F
inline constexpr char kGlyphAdd[] = "\xee\x9c\x90";        // U+E710
inline constexpr char kGlyphMore[] = "\xee\x9c\x92";       // U+E712
inline constexpr char kGlyphStar[] = "\xee\x9c\xb4";       // U+E734
inline constexpr char kGlyphStarFilled[] = "\xee\x9c\xb5"; // U+E735
inline constexpr char kGlyphShield[] = "\xee\xa8\x98";     // U+EA18
inline constexpr char kGlyphLock[] = "\xee\x9c\xae";       // U+E72E
inline constexpr char kGlyphWarning[] = "\xee\x9e\xba";    // U+E7BA
inline constexpr char kGlyphClose[] = "\xee\xa2\xbb";      // U+E8BB
inline constexpr char kGlyphUp[] = "\xee\x9c\x8e";         // U+E70E
inline constexpr char kGlyphDown[] = "\xee\x9c\x8d";       // U+E70D

}  // namespace aegis::theme

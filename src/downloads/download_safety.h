// WezCrypt Aegis - download safety: filename sanitization, path
// containment, file-type risk classification and Mark-of-the-Web.
//
// Downloads are never opened or executed by WezCrypt Aegis. Every download
// requires explicit confirmation through the native Save dialog.
#pragma once

#include <filesystem>
#include <optional>
#include <string>
#include <string_view>

namespace aegis {

// Produces a filename that is safe on Windows (and POSIX):
//  * strips any directory components ("..\\..\\evil.exe" -> "evil.exe")
//  * removes control, bidi-override and zero-width characters (extension
//    spoofing such as "invoice<U+202E>fdp.exe")
//  * replaces characters invalid on Windows (<>:"/\\|?*)
//  * strips trailing dots and spaces, leading spaces
//  * renames reserved device names (CON, NUL, COM1, LPT1, ...)
//  * limits length while preserving the extension
// Never returns an empty string.
std::string SanitizeDownloadFilename(std::string_view suggested,
                                     std::string_view fallback = "download");

// Joins |filename| (already sanitized) to |directory| and verifies the result
// stays inside |directory|. Picks "name (1).ext" style names if the file
// exists. Returns nullopt if containment cannot be guaranteed.
std::optional<std::filesystem::path> ResolveDownloadPath(const std::filesystem::path& directory,
                                                         std::string_view filename);

enum class FileRisk {
  kLow,        // documents/media without active content
  kElevated,   // archives, macro-capable documents, disk images
  kDangerous,  // directly executable or script content
};

FileRisk ClassifyDownloadRisk(std::string_view filename);
std::string_view FileRiskLabel(FileRisk r);

// Returns true when the name hides a dangerous extension behind a benign
// one shown first ("photo.jpg.exe", "report.pdf      .scr").
bool HasDeceptiveDoubleExtension(std::string_view filename);

// Builds the Zone.Identifier alternate-data-stream content marking a file
// as originating from the Internet (zone 3). URLs are stripped of
// credentials and fragments, and newline characters are removed.
std::string BuildMarkOfTheWeb(std::string_view referrer_url, std::string_view host_url);

// Writes the Mark-of-the-Web stream on Windows. On other platforms returns
// false (no equivalent mechanism) without touching the file.
bool ApplyMarkOfTheWeb(const std::filesystem::path& file, std::string_view referrer_url,
                       std::string_view host_url);

}  // namespace aegis

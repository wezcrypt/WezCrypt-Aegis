#include "downloads/download_safety.h"

#include <system_error>

#include "common/strings.h"
#include "common/url.h"
#include "common/utf8.h"

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

namespace aegis {
namespace {

constexpr std::size_t kMaxFilenameBytes = 180;

bool IsStrippedCodePoint(char32_t c) {
  return c < 0x20 || c == 0x7F || (c >= 0x80 && c <= 0x9F) || c == 0x00AD ||
         (c >= 0x200B && c <= 0x200F) || (c >= 0x202A && c <= 0x202E) ||
         (c >= 0x2060 && c <= 0x2069) || c == 0xFEFF || c == 0xFFFE ||
         (c >= 0xE000 && c <= 0xF8FF) ||  // private use
         c == 0x061C || c == 0x180E;
}

bool IsInvalidWindowsChar(char32_t c) {
  return c == '<' || c == '>' || c == ':' || c == '"' || c == '/' || c == '\\' ||
         c == '|' || c == '?' || c == '*';
}

bool IsReservedDeviceName(std::string_view stem) {
  std::string s = ToLowerAscii(TrimAsciiWhitespace(stem));
  static constexpr std::string_view kNames[] = {"con", "prn", "aux", "nul", "conin$",
                                                "conout$", "clock$"};
  for (auto n : kNames) {
    if (s == n) return true;
  }
  if (s.size() >= 4 && (StartsWith(s, "com") || StartsWith(s, "lpt"))) {
    std::string_view rest = std::string_view(s).substr(3);
    if (rest.size() == 1 && rest[0] >= '0' && rest[0] <= '9') return true;
    // Superscript digits ¹ ² ³ are also reserved by Windows.
    if (rest == "\xc2\xb9" || rest == "\xc2\xb2" || rest == "\xc2\xb3") return true;
  }
  return false;
}

std::string ExtensionOf(std::string_view name) {
  std::size_t dot = name.rfind('.');
  if (dot == std::string_view::npos || dot == 0) return {};
  return ToLowerAscii(name.substr(dot + 1));
}

constexpr std::string_view kDangerousExt[] = {
    "exe", "com", "scr", "pif", "bat", "cmd", "msi", "msp", "mst", "msix",
    "msixbundle", "appx", "appxbundle", "appinstaller", "ps1", "psm1", "psd1",
    "ps1xml", "psc1", "vbs", "vbe", "js", "jse", "wsf", "wsh", "wsc", "hta",
    "cpl", "msc", "jar", "jnlp", "lnk", "url", "scf", "reg", "inf", "dll",
    "sys", "drv", "ocx", "chm", "hlp", "application", "gadget", "settingcontent-ms",
    "library-ms", "search-ms", "searchconnector-ms", "xll", "xla", "xlam", "ppam",
    "website", "diagcab", "diagcfg", "diagpkg", "msh", "msh1", "msh2", "mshxml",
    "msh1xml", "msh2xml", "shb", "shs", "vb", "vsmacros", "ws", "mcf", "theme",
    "themepack", "cab", "py", "pyw", "pyc", "rb", "pl", "sh", "bash", "command",
    "app", "action", "workflow", "apk", "xbap", "crx", "oxt", "vsix", "mof",
    "sct", "cer", "crt", "der", "iqy", "slk", "mht", "mhtml", "htm", "html",
    "svg", "xht", "xhtml", "local", "manifest", "grp", "ins", "isp", "its",
    "mau", "mda", "mdb", "mde", "mdt", "mdw", "mdz", "ops", "pcd", "plg",
    "prf", "prg", "pst", "tmp", "udl", "xnk", "rdp", "ade", "adp", "accda",
    "accdb", "accde", "accdr", "bas", "fxp", "ksh", "csh", "lib", "elf"};

constexpr std::string_view kElevatedExt[] = {
    "zip", "7z", "rar", "tar", "gz", "tgz", "bz2", "xz", "zst", "lzh", "lha",
    "ace", "arj", "iso", "img", "vhd", "vhdx", "dmg", "docm", "dotm", "xlsm",
    "xltm", "xlsb", "pptm", "potm", "ppsm", "sldm", "doc", "xls", "ppt", "rtf",
    "pdf", "one", "onepkg", "odt", "ods", "odp", "xml", "xsl", "wim", "ics",
    "torrent", "deb", "rpm", "pkg", "mpkg"};

}  // namespace

std::string SanitizeDownloadFilename(std::string_view suggested, std::string_view fallback) {
  std::string valid = ReplaceInvalidUtf8(suggested);
  // Keep only the final path component (either separator).
  std::size_t sep = valid.find_last_of("/\\");
  if (sep != std::string::npos) valid = valid.substr(sep + 1);

  std::vector<char32_t> cps;
  DecodeUtf8(valid, &cps);
  std::vector<char32_t> clean;
  clean.reserve(cps.size());
  for (char32_t c : cps) {
    if (IsStrippedCodePoint(c)) continue;
    if (IsInvalidWindowsChar(c)) {
      clean.push_back('_');
      continue;
    }
    clean.push_back(c);
  }
  std::string name = EncodeUtf8(clean);
  // Leading spaces/dots ("..." or " .exe") and trailing dots/spaces.
  while (!name.empty() && (name.front() == ' ' || name.front() == '.')) name.erase(name.begin());
  while (!name.empty() && (name.back() == ' ' || name.back() == '.')) name.pop_back();
  // Collapse runs of spaces that are used to push a real extension off-screen.
  std::string collapsed;
  for (char c : name) {
    if (c == ' ' && !collapsed.empty() && collapsed.back() == ' ') continue;
    collapsed.push_back(c);
  }
  name = collapsed;
  // A space right before the extension separator ("a.pdf .exe") is removed.
  for (std::size_t p = name.find(" ."); p != std::string::npos; p = name.find(" .")) {
    name.erase(p, 1);
  }
  // ".." anywhere is collapsed: no component may be a traversal token.
  for (std::size_t p = name.find(".."); p != std::string::npos; p = name.find("..")) {
    name.erase(p, 1);
  }

  if (name.empty()) name = std::string(fallback);

  std::string ext = ExtensionOf(name);
  std::string stem = ext.empty() ? name : name.substr(0, name.size() - ext.size() - 1);
  std::size_t first_dot = stem.find('.');
  std::string base_stem = first_dot == std::string::npos ? stem : stem.substr(0, first_dot);
  if (IsReservedDeviceName(base_stem) || IsReservedDeviceName(stem)) {
    stem = "_" + stem;
  }

  // Enforce the length limit while keeping the extension intact.
  std::string ext_part = ext.empty() ? std::string() : "." + name.substr(name.size() - ext.size());
  if (ext_part.size() > 32) ext_part = ext_part.substr(0, TruncateUtf8Boundary(ext_part, 32));
  std::size_t stem_budget = kMaxFilenameBytes > ext_part.size() ? kMaxFilenameBytes - ext_part.size() : 1;
  if (stem.size() > stem_budget) stem.resize(TruncateUtf8Boundary(stem, stem_budget));
  while (!stem.empty() && (stem.back() == ' ' || stem.back() == '.')) stem.pop_back();
  if (stem.empty()) stem = std::string(fallback);
  return stem + ext_part;
}

std::optional<std::filesystem::path> ResolveDownloadPath(const std::filesystem::path& directory,
                                                         std::string_view filename) {
  namespace fs = std::filesystem;
  std::error_code ec;
  if (directory.empty()) return std::nullopt;
  fs::path dir = fs::weakly_canonical(directory, ec);
  if (ec) return std::nullopt;
  std::string safe = SanitizeDownloadFilename(filename);
#if defined(_WIN32)
  fs::path leaf(Utf8ToWide(safe));
#else
  fs::path leaf(safe);
#endif
  if (leaf.has_parent_path() || leaf.is_absolute() || leaf.filename() != leaf) return std::nullopt;
  std::string ext = ExtensionOf(safe);
  std::string stem = ext.empty() ? safe : safe.substr(0, safe.size() - ext.size() - 1);
  for (int i = 0; i < 10000; ++i) {
    std::string candidate =
        i == 0 ? safe : stem + " (" + std::to_string(i) + ")" + (ext.empty() ? "" : "." + ext);
#if defined(_WIN32)
    fs::path p = dir / fs::path(Utf8ToWide(candidate));
#else
    fs::path p = dir / candidate;
#endif
    fs::path canon = fs::weakly_canonical(p, ec);
    if (ec) return std::nullopt;
    // Containment check: the parent must be exactly the download directory.
    if (canon.parent_path() != dir) return std::nullopt;
    if (!fs::exists(canon, ec)) return canon;
  }
  return std::nullopt;
}

FileRisk ClassifyDownloadRisk(std::string_view filename) {
  std::string ext = ExtensionOf(filename);
  if (ext.empty()) return FileRisk::kElevated;  // unknown type
  for (auto e : kDangerousExt) {
    if (ext == e) return FileRisk::kDangerous;
  }
  if (HasDeceptiveDoubleExtension(filename)) return FileRisk::kDangerous;
  for (auto e : kElevatedExt) {
    if (ext == e) return FileRisk::kElevated;
  }
  return FileRisk::kLow;
}

std::string_view FileRiskLabel(FileRisk r) {
  switch (r) {
    case FileRisk::kLow: return "low";
    case FileRisk::kElevated: return "elevated";
    case FileRisk::kDangerous: return "dangerous";
  }
  return "dangerous";
}

bool HasDeceptiveDoubleExtension(std::string_view filename) {
  std::string lower = ToLowerAscii(filename);
  std::string ext = ExtensionOf(lower);
  bool last_dangerous = false;
  for (auto e : kDangerousExt) {
    if (ext == e) last_dangerous = true;
  }
  if (!last_dangerous) return false;
  std::string stem = lower.substr(0, lower.size() - ext.size() - 1);
  std::string inner = ExtensionOf(stem);
  static constexpr std::string_view kBenign[] = {"pdf", "jpg", "jpeg", "png", "gif", "doc",
                                                 "docx", "txt", "mp3", "mp4", "xls", "xlsx",
                                                 "zip", "csv", "mov", "avi", "webp", "rtf"};
  for (auto b : kBenign) {
    if (inner == b) return true;
  }
  return false;
}

std::string BuildMarkOfTheWeb(std::string_view referrer_url, std::string_view host_url) {
  auto clean = [](std::string_view in) -> std::string {
    auto u = ParseUrl(in);
    if (!u || !(u->IsHttpLike())) return {};
    std::string s = u->Spec(/*include_fragment=*/false);  // Spec() omits credentials
    std::string out;
    for (char c : s) {
      if (c != '\r' && c != '\n' && c != '\0') out.push_back(c);
    }
    return out.substr(0, 2048);
  };
  std::string mark = "[ZoneTransfer]\r\nZoneId=3\r\n";
  std::string ref = clean(referrer_url);
  std::string host = clean(host_url);
  if (!ref.empty()) mark += "ReferrerUrl=" + ref + "\r\n";
  if (!host.empty()) mark += "HostUrl=" + host + "\r\n";
  return mark;
}

bool ApplyMarkOfTheWeb(const std::filesystem::path& file, std::string_view referrer_url,
                       std::string_view host_url) {
#if defined(_WIN32)
  std::wstring stream = file.wstring() + L":Zone.Identifier";
  HANDLE h = ::CreateFileW(stream.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
  if (h == INVALID_HANDLE_VALUE) return false;
  std::string mark = BuildMarkOfTheWeb(referrer_url, host_url);
  DWORD written = 0;
  BOOL ok = ::WriteFile(h, mark.data(), static_cast<DWORD>(mark.size()), &written, nullptr);
  ::CloseHandle(h);
  return ok && written == mark.size();
#else
  (void)file;
  (void)referrer_url;
  (void)host_url;
  return false;
#endif
}

}  // namespace aegis

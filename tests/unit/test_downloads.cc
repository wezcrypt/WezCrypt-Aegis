#include <fstream>

#include "downloads/download_safety.h"
#include "test_framework.h"

using namespace aegis;

TEST(Downloads, SanitizeStripsTraversalAndInvalidCharacters) {
  EXPECT_EQ(SanitizeDownloadFilename("../../Windows/System32/evil.dll"), std::string("evil.dll"));
  EXPECT_EQ(SanitizeDownloadFilename("..\\..\\startup\\run.bat"), std::string("run.bat"));
  EXPECT_EQ(SanitizeDownloadFilename("C:\\Users\\x\\a.txt"), std::string("a.txt"));
  EXPECT_EQ(SanitizeDownloadFilename("re<po>rt:\"v1\"|?*.pdf"), std::string("re_po_rt__v1____.pdf"));
  EXPECT_EQ(SanitizeDownloadFilename("name.   "), std::string("name"));
  EXPECT_EQ(SanitizeDownloadFilename("...."), std::string("download"));
  EXPECT_EQ(SanitizeDownloadFilename(""), std::string("download"));
  EXPECT_EQ(SanitizeDownloadFilename("a..b.txt"), std::string("a.b.txt"));
  EXPECT_EQ(SanitizeDownloadFilename("tab\there\n.txt"), std::string("tabhere.txt"));
}

TEST(Downloads, SanitizeDefeatsExtensionSpoofing) {
  // U+202E RIGHT-TO-LEFT OVERRIDE makes "invoice<U+202E>fdp.exe" render as "invoiceexe.pdf".
  std::string rlo = "invoice\xe2\x80\xae" "fdp.exe";
  EXPECT_EQ(SanitizeDownloadFilename(rlo), std::string("invoicefdp.exe"));
  // Zero-width characters are removed.
  EXPECT_EQ(SanitizeDownloadFilename("set\xe2\x80\x8bup.exe"), std::string("setup.exe"));
  // Padding spaces that push the real extension out of view are collapsed.
  EXPECT_EQ(SanitizeDownloadFilename("report.pdf                    .exe"),
            std::string("report.pdf.exe"));
}

TEST(Downloads, SanitizeRenamesReservedDeviceNames) {
  EXPECT_EQ(SanitizeDownloadFilename("CON"), std::string("_CON"));
  EXPECT_EQ(SanitizeDownloadFilename("nul.txt"), std::string("_nul.txt"));
  EXPECT_EQ(SanitizeDownloadFilename("com1.tar.gz"), std::string("_com1.tar.gz"));
  EXPECT_EQ(SanitizeDownloadFilename("LPT9"), std::string("_LPT9"));
  EXPECT_EQ(SanitizeDownloadFilename("console.txt"), std::string("console.txt"));
}

TEST(Downloads, SanitizeLimitsLengthPreservingExtension) {
  std::string longname(500, 'a');
  std::string out = SanitizeDownloadFilename(longname + ".docx");
  EXPECT_TRUE(out.size() <= 180);
  EXPECT_TRUE(out.size() > 5 && out.substr(out.size() - 5) == ".docx");
  // Multi-byte names are not cut inside a code point.
  std::string cjk;
  for (int i = 0; i < 200; ++i) cjk += "\xe6\x96\x87";
  std::string c = SanitizeDownloadFilename(cjk + ".txt");
  EXPECT_TRUE(c.size() <= 180);
  EXPECT_TRUE((c.size() - 4) % 3 == 0);
}

TEST(Downloads, ResolvePathStaysInsideDirectory) {
  auto dir = aegis_test::TempDir();
  auto p = ResolveDownloadPath(dir, "../../escape.exe");
  ASSERT_TRUE(p.has_value());
  EXPECT_TRUE(p->parent_path() == std::filesystem::weakly_canonical(dir));
  EXPECT_EQ(p->filename().string(), std::string("escape.exe"));
  { std::ofstream(*p) << "x"; }
  auto q = ResolveDownloadPath(dir, "escape.exe");
  ASSERT_TRUE(q.has_value());
  EXPECT_EQ(q->filename().string(), std::string("escape (1).exe"));
  EXPECT_FALSE(ResolveDownloadPath("", "a.txt").has_value());
}

TEST(Downloads, RiskClassification) {
  EXPECT_TRUE(ClassifyDownloadRisk("setup.EXE") == FileRisk::kDangerous);
  EXPECT_TRUE(ClassifyDownloadRisk("script.ps1") == FileRisk::kDangerous);
  EXPECT_TRUE(ClassifyDownloadRisk("shortcut.lnk") == FileRisk::kDangerous);
  EXPECT_TRUE(ClassifyDownloadRisk("page.hta") == FileRisk::kDangerous);
  EXPECT_TRUE(ClassifyDownloadRisk("macro.docm") == FileRisk::kElevated);
  EXPECT_TRUE(ClassifyDownloadRisk("archive.zip") == FileRisk::kElevated);
  EXPECT_TRUE(ClassifyDownloadRisk("disk.iso") == FileRisk::kElevated);
  EXPECT_TRUE(ClassifyDownloadRisk("noextension") == FileRisk::kElevated);
  EXPECT_TRUE(ClassifyDownloadRisk("photo.jpg") == FileRisk::kLow);
  EXPECT_TRUE(HasDeceptiveDoubleExtension("photo.jpg.exe"));
  EXPECT_FALSE(HasDeceptiveDoubleExtension("installer.exe"));
}

TEST(Downloads, MarkOfTheWebContent) {
  std::string m = BuildMarkOfTheWeb("https://user:pw@site.example/page#frag",
                                    "https://cdn.example/file.exe\r\nZoneId=0");
  EXPECT_TRUE(m.find("[ZoneTransfer]\r\nZoneId=3\r\n") == 0);
  EXPECT_TRUE(m.find("ReferrerUrl=https://site.example/page\r\n") != std::string::npos);
  EXPECT_TRUE(m.find("user:pw") == std::string::npos);
  EXPECT_TRUE(m.find("#frag") == std::string::npos);
  // Header injection via a URL with CR/LF is impossible: such URLs are rejected.
  EXPECT_TRUE(m.find("ZoneId=0") == std::string::npos);
  EXPECT_TRUE(m.find("HostUrl=") == std::string::npos);
}

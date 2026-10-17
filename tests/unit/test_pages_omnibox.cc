#include "test_framework.h"
#include "ui/internal_pages.h"
#include "ui/omnibox.h"

using namespace aegis;

TEST(Omnibox, ResolvesUrlsHostsAndSearches) {
  EXPECT_EQ(ResolveOmniboxInput("example.com").url, std::string("https://example.com/"));
  EXPECT_EQ(ResolveOmniboxInput("  example.com/path?q=1 ").url,
            std::string("https://example.com/path?q=1"));
  EXPECT_EQ(ResolveOmniboxInput("http://legacy.example/").url, std::string("http://legacy.example/"));
  EXPECT_EQ(ResolveOmniboxInput("localhost:8080").url, std::string("http://localhost:8080/"));
  EXPECT_EQ(ResolveOmniboxInput("192.168.1.1").url, std::string("http://192.168.1.1/"));
  EXPECT_EQ(ResolveOmniboxInput("aegis://security").url, std::string("aegis://security/"));
  auto s = ResolveOmniboxInput("how to secure a browser");
  EXPECT_TRUE(s.is_search);
  EXPECT_EQ(s.url, std::string("https://duckduckgo.com/html/?q=how+to+secure+a+browser"));
  EXPECT_TRUE(ResolveOmniboxInput("v1.2").is_search);  // numeric "TLD" is not a host
  EXPECT_EQ(ResolveOmniboxInput("").url, std::string("aegis://newtab/"));
  auto f = ResolveOmniboxInput("file:///C:/Users/me/doc.pdf");
  EXPECT_TRUE(f.typed_file_url);
}

TEST(Omnibox, ScriptUrlsAreNeverExecuted) {
  auto js = ResolveOmniboxInput("javascript:alert(document.cookie)");
  EXPECT_TRUE(js.is_search);
  EXPECT_TRUE(js.url.rfind("https://duckduckgo.com/html/?q=", 0) == 0);
  EXPECT_TRUE(ResolveOmniboxInput("data:text/html,<script>x</script>").is_search);
  EXPECT_TRUE(ResolveOmniboxInput("vbscript:msgbox(1)").is_search);
}

TEST(Omnibox, QueryParsing) {
  EXPECT_EQ(QueryParam("a=1&site=news.test&b=x%20y", "site"), std::string("news.test"));
  EXPECT_EQ(QueryParam("a=1&b=x%20y", "b"), std::string("x y"));
  EXPECT_EQ(QueryParam("a=1", "missing"), std::string(""));
  EXPECT_EQ(UrlEncodeComponent("a b&c/\xc3\xa9"), std::string("a+b%26c%2F%C3%A9"));
}

TEST(InternalPages, UntrustedDataIsEscaped) {
  SecurityEvent ev;
  ev.category = EventCategory::kAdvertising;
  ev.url = "https://ads.example/<script>alert(1)</script>";
  ev.reason = "\"><img src=x onerror=alert(1)>";
  ev.rule = "||ads.example^";
  ev.list = "easylist";
  std::string html = pages::NetworkActivityPage({ev}, 1);
  EXPECT_TRUE(html.find("<script>alert(1)") == std::string::npos);
  EXPECT_TRUE(html.find("<img src=x") == std::string::npos);
  EXPECT_TRUE(html.find("&lt;script&gt;") != std::string::npos);

  HistoryEntry h;
  h.url = "https://x.example/'onmouseover='alert(1)";
  h.title = "</a><script>bad()</script>";
  std::string hist = pages::HistoryPage({h}, "<b>q</b>", true);
  EXPECT_TRUE(hist.find("<script>bad()") == std::string::npos);
  EXPECT_TRUE(hist.find("'onmouseover='") == std::string::npos);
  EXPECT_TRUE(hist.find("<b>q</b>") == std::string::npos);
}

TEST(InternalPages, NoScriptAndStrictCsp) {
  pages::DashboardData d;
  d.sandbox_ok = true;
  d.session_counts = {{"Advertising requests blocked", 12}};
  for (const std::string& html :
       {pages::DashboardPage(d), pages::NewTabPage(SecurityMode::kStrictProtection, 5, true),
        pages::CertificateErrorPage("https://bad.example/", "ERR_CERT_AUTHORITY_INVALID", -202),
        pages::BlockedNavigationPage("https://ads.example/", "listed", "||ads.example^", "easylist"),
        pages::AboutPage("1.0.0", "154", "154.0", {{"Monocypher", "BSD-2-Clause"}})}) {
    EXPECT_TRUE(html.find("<script") == std::string::npos);
    EXPECT_TRUE(html.find("onerror=") == std::string::npos);
    EXPECT_TRUE(html.find("onload=") == std::string::npos);
    EXPECT_TRUE(html.find("javascript:") == std::string::npos);
  }
  std::string csp(pages::InternalPageCsp());
  EXPECT_TRUE(csp.find("script-src 'none'") != std::string::npos);
  EXPECT_TRUE(csp.find("frame-ancestors 'none'") != std::string::npos);
  EXPECT_TRUE(pages::DashboardPage(d).find("12") != std::string::npos);
}

TEST(InternalPages, DashboardShowsUnverifiedSandboxProminently) {
  pages::DashboardData d;
  d.sandbox_ok = false;
  d.sandbox_detail = "no renderer processes inspected yet";
  std::string html = pages::DashboardPage(d);
  EXPECT_TRUE(html.find("Sandbox not verified") != std::string::npos);
  EXPECT_TRUE(html.find("no renderer processes inspected yet") != std::string::npos);
}

#include "ui/internal_pages.h"

#include <ctime>

#include "common/idna.h"
#include "common/strings.h"

namespace aegis::pages {
namespace {

std::string E(std::string_view s) { return HtmlEscape(s); }

std::string FormatTime(std::int64_t unix_ms) {
  if (unix_ms <= 0) return "-";
  std::time_t t = static_cast<std::time_t>(unix_ms / 1000);
  std::tm tm{};
#if defined(_WIN32)
  localtime_s(&tm, &t);
#else
  localtime_r(&t, &tm);
#endif
  char buf[32];
  std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm);
  return buf;
}

std::string FormatCount(std::uint64_t n) {
  std::string s = std::to_string(n);
  std::string out;
  int c = 0;
  for (auto it = s.rbegin(); it != s.rend(); ++it) {
    if (c && c % 3 == 0) out.insert(out.begin(), ',');
    out.insert(out.begin(), *it);
    ++c;
  }
  return out;
}

// The shield mark, drawn with plain geometric paths (original artwork).
constexpr std::string_view kLogoSvg =
    "<svg class='logo' viewBox='0 0 64 64' width='40' height='40' aria-hidden='true'>"
    "<defs><linearGradient id='g' x1='0' y1='0' x2='1' y2='1'>"
    "<stop offset='0' stop-color='#22e3ff'/><stop offset='1' stop-color='#2f6bff'/>"
    "</linearGradient></defs>"
    "<path d='M32 4 L56 13 V30 C56 45 46 55 32 60 C18 55 8 45 8 30 V13 Z' fill='none' "
    "stroke='url(#g)' stroke-width='4' stroke-linejoin='round'/>"
    "<path d='M20 22 L26 42 L32 28 L38 42 L44 22' fill='none' stroke='#e9f6ff' "
    "stroke-width='4' stroke-linecap='round' stroke-linejoin='round'/></svg>";

constexpr std::string_view kCss = R"CSS(
:root{--bg:#121417;--panel:#1a1d22;--panel2:#20242b;--line:#2b3038;--text:#e6e9ee;
--muted:#9aa3ae;--cyan:#22d3ee;--blue:#3b82f6;--ok:#34d399;--warn:#fbbf24;--bad:#f87171}
*{box-sizing:border-box}html,body{margin:0;background:var(--bg);color:var(--text);
font:14px/1.5 "Segoe UI Variable Text","Segoe UI",system-ui,sans-serif}
a{color:var(--cyan);text-decoration:none}a:hover{text-decoration:underline}
main{max-width:1080px;margin:0 auto;padding:28px 24px 56px}
header.top{display:flex;align-items:center;gap:14px;margin-bottom:22px}
header.top h1{font-size:22px;font-weight:600;margin:0;letter-spacing:.2px}
header.top .sub{color:var(--muted);font-size:13px}
.badge{display:inline-block;padding:2px 10px;border-radius:999px;font-size:12px;font-weight:600;
letter-spacing:.6px;border:1px solid var(--cyan);color:var(--cyan)}
.badge.warn{border-color:var(--warn);color:var(--warn)}.badge.bad{border-color:var(--bad);color:var(--bad)}
.badge.ok{border-color:var(--ok);color:var(--ok)}.badge.priv{border-color:#a78bfa;color:#c4b5fd}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(230px,1fr));gap:12px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:16px}
.card h2{font-size:13px;color:var(--muted);font-weight:600;margin:0 0 8px;text-transform:uppercase;
letter-spacing:.8px}
.stat{font-size:28px;font-weight:600;color:var(--text)}.stat small{font-size:12px;color:var(--muted);
font-weight:400;display:block}
section{margin-top:26px}section>h2{font-size:15px;margin:0 0 10px;font-weight:600}
table{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--line);
border-radius:12px;overflow:hidden}
th,td{padding:8px 12px;text-align:left;border-bottom:1px solid var(--line);vertical-align:top;
font-size:13px}th{color:var(--muted);font-weight:600;background:var(--panel2)}
tr:last-child td{border-bottom:none}
td.mono,.mono{font-family:"Cascadia Mono",Consolas,monospace;font-size:12px;word-break:break-all}
.muted{color:var(--muted)}.ok{color:var(--ok)}.warn{color:var(--warn)}.bad{color:var(--bad)}
.notice{background:#2a2312;border:1px solid #5c4a17;color:#f6dfa0;border-radius:10px;padding:10px 14px;
margin-bottom:10px}
.danger{background:#2a1416;border:1px solid #6b2328;color:#ffc9c9;border-radius:12px;padding:18px}
.hero{display:flex;flex-direction:column;align-items:center;justify-content:center;min-height:62vh;
text-align:center;gap:10px}.hero .logo{width:84px;height:84px}
.hero h1{font-size:30px;margin:6px 0 0;font-weight:600}.hero p{color:var(--muted);margin:0}
.btn{display:inline-block;padding:8px 16px;border-radius:8px;border:1px solid var(--line);
background:var(--panel2);color:var(--text)}.btn.primary{border-color:var(--cyan);color:var(--cyan)}
nav.links{display:flex;gap:16px;flex-wrap:wrap;margin-top:14px;font-size:13px}
ul.plain{margin:0;padding-left:18px}
)CSS";

std::string Page(std::string_view title, std::string_view body) {
  std::string html;
  html.reserve(body.size() + 4096);
  html += "<!doctype html><html lang='en'><head><meta charset='utf-8'>";
  html += "<meta name='color-scheme' content='dark'>";
  html += "<meta name='referrer' content='no-referrer'>";
  html += "<title>";
  html += E(title);
  html += "</title><style>";
  html += kCss;
  html += "</style></head><body>";
  html += body;
  html += "</body></html>";
  return html;
}

std::string Header(std::string_view title, std::string_view subtitle, std::string_view badge,
                   std::string_view badge_class = "") {
  std::string h = "<header class='top'>";
  h += kLogoSvg;
  h += "<div><h1>" + E(title) + "</h1><div class='sub'>" + E(subtitle) + "</div></div>";
  if (!badge.empty()) {
    h += "<span class='badge ";
    h += badge_class;
    h += "' style='margin-left:auto'>" + E(badge) + "</span>";
  }
  h += "</header>";
  return h;
}

std::string NavLinks() {
  return "<nav class='links'><a href='aegis://security/'>Security Control Center</a>"
         "<a href='aegis://network/'>Network activity</a>"
         "<a href='aegis://history/'>History</a><a href='aegis://bookmarks/'>Bookmarks</a>"
         "<a href='aegis://downloads/'>Downloads</a><a href='aegis://about/'>About</a></nav>";
}

std::string ModeBadgeClass(SecurityMode m) {
  switch (m) {
    case SecurityMode::kMaximumIsolation: return "ok";
    case SecurityMode::kStrictProtection: return "";
    case SecurityMode::kCompatibility: return "warn";
  }
  return "";
}

std::string EventsTable(const std::vector<SecurityEvent>& events) {
  if (events.empty()) return "<p class='muted'>No blocking events recorded.</p>";
  std::string t = "<table><tr><th>Time</th><th>Category</th><th>Resource</th>"
                  "<th>Address</th><th>Reason / rule</th></tr>";
  for (const auto& ev : events) {
    t += "<tr><td class='muted'>" + E(FormatTime(ev.unix_ms)) + "</td><td>" +
         E(EventCategoryId(ev.category)) + "</td><td>" + E(ev.resource) +
         "</td><td class='mono'>" + E(ev.url) + "</td><td>" + E(ev.reason);
    if (!ev.rule.empty()) {
      t += "<div class='mono muted'>" + E(ev.list) + ": " + E(ev.rule) + "</div>";
    }
    t += "</td></tr>";
  }
  t += "</table>";
  return t;
}

}  // namespace

std::string_view InternalPageCsp() {
  return "default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; "
         "form-action 'none'; frame-ancestors 'none'; script-src 'none'";
}

std::string NewTabPage(SecurityMode mode, std::uint64_t session_blocked, bool private_window) {
  std::string b = "<main><div class='hero'>";
  b += kLogoSvg;
  b += "<h1>WezCrypt Aegis</h1><p>Browse Beyond Threats.</p>";
  b += "<p><span class='badge " + ModeBadgeClass(mode) + "'>" +
       E(SecurityModeShortLabel(mode)) + "</span>";
  if (private_window) b += " <span class='badge priv'>PRIVATE WINDOW</span>";
  b += "</p><p>" + FormatCount(session_blocked) +
       " requests blocked this session before reaching the network.</p>";
  if (private_window) {
    b += "<p class='muted' style='max-width:560px'>Private windows keep cookies, cache and "
         "history in memory only and discard them when the window closes. They do not hide "
         "your activity from websites you sign in to, your network operator, or software "
         "running on this computer.</p>";
  }
  b += "<p class='muted'>Type an address or a search in the address bar. Searches are sent to "
       "DuckDuckGo only when you press Enter.</p>";
  b += NavLinks();
  b += "</div></main>";
  return Page("New Tab", b);
}

std::string DashboardPage(const DashboardData& d) {
  std::string b = "<main>";
  b += Header("Security Control Center",
              "Live state of the WezCrypt Aegis protection layers. All figures come from "
              "enforcement events in this browser.",
              SecurityModeShortLabel(d.mode), ModeBadgeClass(d.mode));
  for (const auto& n : d.notices) b += "<div class='notice'>" + E(n) + "</div>";
  if (!d.sandbox_ok) {
    b += "<div class='danger'><b>Sandbox not verified.</b> " + E(d.sandbox_detail) + "</div>";
  }
  if (d.update_warning) {
    b += "<div class='danger' style='margin-top:10px'><b>Update status:</b> " +
         E(d.update_status) + "</div>";
  }
  b += "<section><div class='grid'>";
  b += "<div class='card'><h2>Security mode</h2><div class='stat'>" +
       E(SecurityModeDisplayName(d.mode)) + "<small>" + E(SecurityModeDescription(d.mode)) +
       "</small></div></div>";
  b += "<div class='card'><h2>Renderer sandbox</h2><div class='stat " +
       std::string(d.sandbox_ok ? "ok" : "bad") + "'>" + E(d.sandbox_ok ? "Verified" : "Unverified") +
       "<small>" + E(d.sandbox_status) + "</small></div></div>";
  b += "<div class='card'><h2>Browser engine</h2><div class='stat' style='font-size:18px'>Chromium " +
       E(d.chromium_version) + "<small>CEF " + E(d.cef_version) + "<br>WezCrypt Aegis " +
       E(d.app_version) + "</small></div></div>";
  b += "<div class='card'><h2>Security updates</h2><div class='stat " +
       std::string(d.update_warning ? "warn" : "") + "' style='font-size:16px'>" +
       E(d.update_status) + "</div></div>";
  b += "</div></section>";

  b += "<section><h2>Engine protections</h2><table>";
  b += "<tr><th>Protection</th><th>State</th></tr>";
  b += "<tr><td>JavaScript</td><td>" + E(d.javascript_status) + "</td></tr>";
  b += "<tr><td>WebAssembly</td><td>" + E(d.wasm_status) + "</td></tr>";
  b += "<tr><td>Site isolation</td><td>" + E(d.site_isolation) + "</td></tr>";
  b += "<tr><td>Certificate validation</td><td>Enforced by Chromium; certificate errors are "
       "never bypassed by WezCrypt Aegis.</td></tr>";
  b += "</table></section>";

  b += "<section><h2>Blocked this session</h2><div class='grid'>";
  for (const auto& [label, n] : d.session_counts) {
    b += "<div class='card'><h2>" + E(label) + "</h2><div class='stat'>" + FormatCount(n) +
         "</div></div>";
  }
  b += "</div></section>";

  b += "<section><h2>Since installation</h2><table><tr><th>Category</th><th>Count</th></tr>";
  for (const auto& [label, n] : d.lifetime_counts) {
    b += "<tr><td>" + E(label) + "</td><td>" + FormatCount(n) + "</td></tr>";
  }
  b += "</table></section>";

  b += "<section><h2>Filter lists</h2><table><tr><th>List</th><th>Version</th><th>Source</th>"
       "<th>Updated</th><th>Network rules</th><th>Skipped</th><th>Status</th></tr>";
  for (const auto& l : d.lists) {
    b += "<tr><td>" + E(l.name) + (l.enabled ? "" : " <span class='muted'>(disabled)</span>") +
         "<div class='muted'>" + E(l.license) + "</div></td><td class='mono'>" + E(l.version) +
         "</td><td>" + E(l.source) + "</td><td>" + E(l.updated) + "</td><td>" +
         FormatCount(l.rules) + "</td><td class='muted'>" + FormatCount(l.cosmetic_skipped) +
         " cosmetic<br>" + FormatCount(l.unsupported) + " unsupported</td><td>" + E(l.status) +
         "</td></tr>";
  }
  b += "</table><p class='muted'>Cosmetic (element-hiding) rules and rules using unsupported "
       "options are counted but not applied. Only network blocking is performed.</p></section>";

  b += "<section><h2>Site permissions</h2>";
  if (d.permissions.empty()) {
    b += "<p class='muted'>No site has been granted any permission.</p>";
  } else {
    b += "<table><tr><th>Origin</th><th>Granted</th></tr>";
    for (const auto& p : d.permissions) {
      b += "<tr><td class='mono'>" + E(p.origin) + "</td><td>" + E(p.permissions) + "</td></tr>";
    }
    b += "</table>";
  }
  b += "</section><section><h2>Site exceptions</h2>";
  if (d.exceptions.empty()) {
    b += "<p class='muted'>No site exceptions. Every site receives the active mode's protections.</p>";
  } else {
    b += "<table><tr><th>Site</th><th>Relaxed protections</th></tr>";
    for (const auto& x : d.exceptions) {
      b += "<tr><td class='mono'>" + E(x.site) + "</td><td>" + E(x.details) + "</td></tr>";
    }
    b += "</table>";
  }
  b += "</section>";
  if (!d.top_sites.empty()) {
    b += "<section><h2>Sites with the most blocked requests</h2><table><tr><th>Site</th>"
         "<th>Blocked</th><th></th></tr>";
    for (const auto& [site, n] : d.top_sites) {
      b += "<tr><td class='mono'>" + E(site) + "</td><td>" + FormatCount(n) +
           "</td><td><a href='aegis://site-report/?site=" + E(site) + "'>Report</a></td></tr>";
    }
    b += "</table></section>";
  }
  b += "<section><h2>What these numbers mean</h2><ul class='plain muted'>"
       "<li>A blocked request was cancelled before any network connection was made for it.</li>"
       "<li>Counts show what policy prevented; they do not claim each item was an attack.</li>"
       "<li>WezCrypt Aegis reduces exposure but cannot guarantee protection against every "
       "exploit, including unknown (zero-day) vulnerabilities.</li></ul></section>";
  b += NavLinks();
  b += "</main>";
  return Page("Security Control Center", b);
}

std::string SiteReportPage(const SiteReportData& d) {
  std::string b = "<main>";
  b += Header("Site security report", d.display_host.empty() ? d.site : d.display_host,
              SecurityModeShortLabel(d.mode), ModeBadgeClass(d.mode));
  if (d.idn_spoof_risk) {
    b += "<div class='danger'>This address uses international characters that resemble other "
         "letters. It is shown in its encoded form. Make sure it is the site you expect.</div>";
  }
  b += "<section><table><tr><th>Property</th><th>Value</th></tr>";
  b += "<tr><td>Address</td><td class='mono'>" + E(d.url) + "</td></tr>";
  b += "<tr><td>Site (registrable domain)</td><td class='mono'>" + E(d.site) + "</td></tr>";
  b += "<tr><td>Connection</td><td class='" + std::string(d.secure_connection ? "ok" : "warn") +
       "'>" + E(d.secure_connection ? "Encrypted (HTTPS)" : "Not encrypted") + "</td></tr>";
  if (!d.certificate_summary.empty())
    b += "<tr><td>Certificate</td><td>" + E(d.certificate_summary) + "</td></tr>";
  b += "<tr><td>JavaScript</td><td>" + E(d.javascript_allowed ? "Allowed" : "Blocked by engine policy") +
       "</td></tr>";
  b += "<tr><td>JavaScript optimizers (JIT)</td><td>" +
       E(d.js_optimizer_allowed ? "Enabled" : "Disabled (reduced attack surface)") + "</td></tr>";
  b += "<tr><td>Site exceptions</td><td>" + E(d.exception_summary.empty() ? "None" : d.exception_summary) +
       "</td></tr>";
  b += "<tr><td>Permissions granted</td><td>" + E(d.permissions.empty() ? "None" : d.permissions) +
       "</td></tr>";
  b += "</table></section>";
  b += "<section><h2>Blocked for this site (this session)</h2><div class='grid'>";
  for (const auto& [label, n] : d.counts) {
    b += "<div class='card'><h2>" + E(label) + "</h2><div class='stat'>" + FormatCount(n) +
         "</div></div>";
  }
  b += "</div></section><section><h2>Recent events</h2>" + EventsTable(d.events) + "</section>";
  b += NavLinks() + "</main>";
  return Page("Site security report", b);
}

std::string NetworkActivityPage(const std::vector<SecurityEvent>& events, std::size_t total_shown) {
  std::string b = "<main>";
  b += Header("Network activity",
              "Most recent " + std::to_string(total_shown) +
                  " enforcement events (blocks, upgrades, denials). Reload to refresh.",
              "");
  b += EventsTable(events);
  b += NavLinks() + "</main>";
  return Page("Network activity", b);
}

std::string HistoryPage(const std::vector<HistoryEntry>& entries, const std::string& query,
                        bool history_enabled) {
  std::string b = "<main>";
  b += Header("History", query.empty() ? "Stored only on this computer." : "Results for: " + query, "");
  if (!history_enabled) b += "<div class='notice'>History recording is turned off.</div>";
  if (entries.empty()) {
    b += "<p class='muted'>No history.</p>";
  } else {
    b += "<table><tr><th>Last visit</th><th>Page</th><th>Visits</th></tr>";
    for (const auto& e : entries) {
      b += "<tr><td class='muted'>" + E(FormatTime(e.last_visit_ms)) + "</td><td><a href='" +
           E(e.url) + "'>" + E(e.title.empty() ? e.url : e.title) +
           "</a><div class='mono muted'>" + E(e.url) + "</div></td><td>" +
           std::to_string(e.visit_count) + "</td></tr>";
    }
    b += "</table>";
  }
  b += NavLinks() + "</main>";
  return Page("History", b);
}

std::string BookmarksPage(const std::vector<Bookmark>& bookmarks) {
  std::string b = "<main>";
  b += Header("Bookmarks", "Press Ctrl+D to bookmark the current page.", "");
  if (bookmarks.empty()) {
    b += "<p class='muted'>No bookmarks yet.</p>";
  } else {
    b += "<table><tr><th>Bookmark</th><th>Added</th></tr>";
    for (const auto& bm : bookmarks) {
      b += "<tr><td><a href='" + E(bm.url) + "'>" + E(bm.title) + "</a><div class='mono muted'>" +
           E(bm.url) + "</div></td><td class='muted'>" + E(FormatTime(bm.added_ms)) + "</td></tr>";
    }
    b += "</table>";
  }
  b += NavLinks() + "</main>";
  return Page("Bookmarks", b);
}

std::string DownloadsPage(const std::vector<DownloadRow>& rows, const std::string& directory) {
  std::string b = "<main>";
  b += Header("Downloads",
              "Downloads always ask where to save, are never opened automatically, and are "
              "marked as coming from the Internet.",
              "");
  if (!directory.empty()) b += "<p class='muted'>Default folder: <span class='mono'>" + E(directory) + "</span></p>";
  if (rows.empty()) {
    b += "<p class='muted'>No downloads in this session.</p>";
  } else {
    b += "<table><tr><th>File</th><th>State</th><th>Risk</th><th>Saved to</th></tr>";
    for (const auto& r : rows) {
      std::string risk_class = r.risk == "dangerous" ? "bad" : (r.risk == "elevated" ? "warn" : "ok");
      std::string state = r.state;
      if (r.percent >= 0 && r.state == "in progress") state += " (" + std::to_string(r.percent) + "%)";
      b += "<tr><td>" + E(r.filename) + "<div class='mono muted'>" + E(r.url) + "</div></td><td>" +
           E(state) + "</td><td class='" + risk_class + "'>" + E(r.risk) + "</td><td class='mono'>" +
           E(r.path) + "</td></tr>";
    }
    b += "</table>";
  }
  b += NavLinks() + "</main>";
  return Page("Downloads", b);
}

std::string BlockedNavigationPage(const std::string& url, const std::string& reason,
                                  const std::string& rule, const std::string& list) {
  std::string b = "<main>";
  b += Header("Page blocked", "WezCrypt Aegis stopped this navigation before connecting.", "BLOCKED", "bad");
  b += "<div class='danger'><p><b>Address:</b> <span class='mono'>" + E(url) + "</span></p><p><b>Reason:</b> " +
       E(reason) + "</p>";
  if (!rule.empty()) b += "<p><b>Rule:</b> <span class='mono'>" + E(list) + ": " + E(rule) + "</span></p>";
  b += "</div><p class='muted'>Advertising and tracking domains are frequently used in "
       "redirect chains that lead to scams and malicious downloads. If you trust this "
       "address, you can disable filtering for its site from the Site Security menu, then "
       "reload.</p>";
  b += NavLinks() + "</main>";
  return Page("Page blocked", b);
}

std::string CertificateErrorPage(const std::string& url, const std::string& error_name,
                                 int error_code) {
  std::string b = "<main>";
  b += Header("Connection not secure", "The site's certificate could not be verified.", "STOPPED", "bad");
  b += "<div class='danger'><p><b>Address:</b> <span class='mono'>" + E(url) + "</span></p><p><b>Error:</b> " +
       E(error_name) + " (" + std::to_string(error_code) + ")</p></div>";
  b += "<p>An attacker could be impersonating this site or intercepting the connection. "
       "WezCrypt Aegis does not allow bypassing certificate errors.</p>";
  b += NavLinks() + "</main>";
  return Page("Connection not secure", b);
}

std::string HttpsFallbackPage(const std::string& https_url, const std::string& http_url,
                              const std::string& continue_link, const std::string& error_name) {
  std::string b = "<main>";
  b += Header("Secure connection unavailable",
              "This site did not respond over HTTPS.", "HTTPS-FIRST", "warn");
  b += "<div class='notice'><p>WezCrypt Aegis tried <span class='mono'>" + E(https_url) +
       "</span> and received: " + E(error_name) + ".</p><p>The insecure version "
       "<span class='mono'>" + E(http_url) + "</span> can be read and modified by anyone on the "
       "network path.</p></div>";
  b += "<p><a class='btn' href='" + E(continue_link) + "'>Continue to the insecure site</a> "
       "<span class='muted'>(remembered for this host)</span></p>";
  b += NavLinks() + "</main>";
  return Page("Secure connection unavailable", b);
}

std::string LoadErrorPage(const std::string& url, const std::string& error_name, int error_code) {
  std::string b = "<main>";
  b += Header("Page could not be loaded", url, "");
  b += "<div class='card'><p><b>" + E(error_name) + "</b> (" + std::to_string(error_code) +
       ")</p></div>";
  b += NavLinks() + "</main>";
  return Page("Page could not be loaded", b);
}

std::string AboutPage(const std::string& app_version, const std::string& cef_version,
                      const std::string& chromium_version,
                      const std::vector<std::pair<std::string, std::string>>& licenses) {
  std::string b = "<main>";
  b += Header("About WezCrypt Aegis", "Browse Beyond Threats.  Published by WezCrypt.", "");
  b += "<table><tr><th>Component</th><th>Version</th></tr>";
  b += "<tr><td>WezCrypt Aegis</td><td class='mono'>" + E(app_version) + "</td></tr>";
  b += "<tr><td>Chromium Embedded Framework</td><td class='mono'>" + E(cef_version) + "</td></tr>";
  b += "<tr><td>Chromium</td><td class='mono'>" + E(chromium_version) + "</td></tr></table>";
  b += "<section><h2>Third-party components</h2><table><tr><th>Component</th><th>License</th></tr>";
  for (const auto& [name, lic] : licenses) {
    b += "<tr><td>" + E(name) + "</td><td>" + E(lic) + "</td></tr>";
  }
  b += "</table></section><section><h2>Privacy</h2><ul class='plain muted'>"
       "<li>No telemetry, analytics or advertising SDKs. No account is required.</li>"
       "<li>History and bookmarks stay on this computer.</li>"
       "<li>Network requests made by WezCrypt Aegis itself: filter-list updates from "
       "easylist.to and, if configured in this build, the signed release manifest.</li>"
       "</ul></section>";
  b += NavLinks() + "</main>";
  return Page("About WezCrypt Aegis", b);
}

std::string NotFoundPage(const std::string& url) {
  std::string b = "<main>";
  b += Header("Unknown internal page", url, "");
  b += NavLinks() + "</main>";
  return Page("Not found", b);
}

}  // namespace aegis::pages

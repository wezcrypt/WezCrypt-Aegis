#include "security/engine_switches.h"

#include "common/strings.h"

namespace aegis {
namespace {

constexpr std::string_view kForbidden[] = {
    "no-sandbox",
    "disable-gpu-sandbox",
    "disable-renderer-sandbox",  // historical spellings
    "disable-seccomp-filter-sandbox",
    "disable-setuid-sandbox",
    "no-zygote-sandbox",
    "disable-web-security",
    "disable-site-isolation-trials",
    "disable-site-isolation-for-policy",
    "site-isolation-trial-opt-out",
    "ignore-certificate-errors",
    "ignore-certificate-errors-spki-list",
    "ignore-ssl-errors",
    "allow-insecure-localhost",
    "allow-running-insecure-content",
    "unsafely-treat-insecure-origin-as-secure",
    "remote-debugging-port",
    "remote-debugging-pipe",
    "remote-debugging-address",
    "remote-allow-origins",
    "single-process",
    "in-process-gpu",
    "renderer-cmd-prefix",
    "gpu-launcher",
    "utility-cmd-prefix",
    "browser-subprocess-path",
    "disable-features",  // could disable security features wholesale
    "enable-features",   // could enable unsafe test features
    "disable-blink-features",
    "js-flags",           // set only by WezCrypt Aegis itself
    "allow-file-access-from-files",
    "allow-file-access",
    "disable-popup-blocking",
    "disable-client-side-phishing-detection",
    "load-extension",
    "disable-extensions-except",
    "user-data-dir",
    "enable-automation",
    "test-type",
    "proxy-server",  // network routing must not be injected via shortcuts
    "proxy-pac-url",
    "host-resolver-rules",
    "host-rules",
};

std::string NormalizeSwitch(std::string_view arg) {
  std::string_view a = arg;
  if (StartsWith(a, "--")) a.remove_prefix(2);
  else if (StartsWith(a, "-") || StartsWith(a, "/")) a.remove_prefix(1);
  else return {};
  std::size_t eq = a.find('=');
  if (eq != std::string_view::npos) a = a.substr(0, eq);
  return ToLowerAscii(a);
}

}  // namespace

bool IsForbiddenSwitch(std::string_view name) {
  std::string n = ToLowerAscii(name);
  for (auto f : kForbidden) {
    if (n == f) return true;
  }
  return false;
}

std::vector<std::string> FindForbiddenSwitches(const std::vector<std::string>& args) {
  std::vector<std::string> found;
  for (const auto& a : args) {
    if (a == "--") break;  // everything after "--" is positional
    std::string n = NormalizeSwitch(a);
    if (!n.empty() && IsForbiddenSwitch(n)) found.push_back(n);
  }
  return found;
}

std::vector<std::pair<std::string, std::string>> HardeningSwitches(SecurityMode startup_mode) {
  std::vector<std::pair<std::string, std::string>> s;
  // Site-per-process is the Chromium desktop default; stating it explicitly
  // guards against field-trial or policy changes.
  s.emplace_back("site-per-process", "");
  // The component updater is deliberately left enabled: it delivers
  // Chromium's CRLSet (certificate revocation) updates. Crash uploads and
  // reliability beacons are disabled because they send data off-device.
  s.emplace_back("disable-breakpad", "");
  s.emplace_back("disable-domain-reliability", "");
  s.emplace_back("no-pings", "");
  s.emplace_back("no-default-browser-check", "");
  if (startup_mode == SecurityMode::kMaximumIsolation) {
    // WebAssembly is not exposed to pages. This is a process-wide V8 flag
    // and therefore follows the mode active at startup.
    s.emplace_back("js-flags", "--noexpose_wasm");
  }
  return s;
}

}  // namespace aegis

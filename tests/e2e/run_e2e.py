#!/usr/bin/env python3
"""WezCrypt Aegis end-to-end security tests (Windows).

Starts local, non-malicious test servers, launches the real browser
(WezCryptAegis.exe) against synthetic pages and verifies, from the server
side, which requests actually reached the network. A request that the
browser blocked before network access never appears in the server log.

Hosts use the *.localhost names, which Chromium resolves to the loopback
interface without DNS:
  page.localhost    first-party test site
  other.localhost   unrelated site (exception scoping, third-party frames)
  ads.localhost     synthetic "advertising" host, blocked by a user rule
  tracker.localhost third-party host not on any list

Usage:
  python tests/e2e/run_e2e.py --browser-dir build/src/app/Release --out e2e-results
"""
import argparse
import datetime
import http.server
import json
import logging
import os
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
from pathlib import Path
from xml.sax.saxutils import escape

LOG = logging.getLogger("e2e")
PNG_1X1 = bytes.fromhex(
    "89504e470d0a1a0a0000000d4948445200000001000000010806000000"
    "1f15c4890000000d49444154789c6360000002000100e221bc330000000049454e44ae426082")


class RequestLog:
    def __init__(self):
        self._lock = threading.Lock()
        self.entries = []

    def add(self, server, host, path, headers):
        with self._lock:
            self.entries.append({"server": server, "host": host, "path": path,
                                 "upgrade": headers.get("Upgrade", ""), "time": time.time()})

    def clear(self):
        with self._lock:
            self.entries = []

    def snapshot(self):
        with self._lock:
            return list(self.entries)


def make_handler(log: RequestLog, name: str, port_ref: dict):
    class Handler(http.server.BaseHTTPRequestHandler):
        server_version = "AegisE2E/1.0"

        def log_message(self, fmt, *args):  # quiet
            LOG.debug("%s %s", name, fmt % args)

        def _send(self, code, body=b"", ctype="text/html; charset=utf-8", headers=None):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            for k, v in (headers or {}).items():
                self.send_header(k, v)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def do_GET(self):
            host = (self.headers.get("Host") or "").split(":")[0].lower()
            parsed = urllib.parse.urlsplit(self.path)
            log.add(name, host, self.path, self.headers)
            port = port_ref["http"]
            path = parsed.path
            page = PAGES.get(path)
            if page is not None:
                return self._send(200, page.replace("{PORT}", str(port)).encode())
            if path.endswith(".png"):
                return self._send(200, PNG_1X1, "image/png")
            if path.endswith(".css"):
                return self._send(200, b"body{}", "text/css")
            if path in ("/worker.js", "/sw.js"):
                return self._send(200, SCRIPTS[path].replace("{PORT}", str(port)).encode(),
                                  "text/javascript", {"Service-Worker-Allowed": "/"})
            if path.endswith(".js"):
                return self._send(200, b"/* synthetic */", "text/javascript")
            if path == "/redirect":
                target = urllib.parse.parse_qs(parsed.query).get("to", ["/"])[0]
                return self._send(302, b"", headers={"Location": target})
            if path == "/ws":
                return self._send(400, b"no websocket")
            return self._send(204)

        do_HEAD = do_GET

        def do_POST(self):
            length = int(self.headers.get("Content-Length") or 0)
            self.rfile.read(min(length, 1 << 20))
            self.do_GET()

    return Handler


PAGES = {
    "/test-a.html": """<!doctype html><meta charset=utf-8><title>Aegis E2E A</title>
<h1>Maximum Isolation test page</h1>
<img src="http://page.localhost:{PORT}/ok.png?a">
<img src="http://ads.localhost:{PORT}/ad.png?a">
<script src="http://ads.localhost:{PORT}/ad.js?a"></script>
<script src="http://page.localhost:{PORT}/first-party.js?a"></script>
<iframe src="http://ads.localhost:{PORT}/frame.html?a"></iframe>
<img src="http://page.localhost:{PORT}/redirect?to=http%3A%2F%2Fads.localhost%3A{PORT}%2Fredirected.png">
<link rel=stylesheet href="http://tracker.localhost:{PORT}/t.css?a">
<script>new Image().src='/js-executed?inline-a';</script>
<noscript><img src="/noscript-rendered.png"></noscript>
""",
    "/test-c.html": """<!doctype html><meta charset=utf-8><title>Aegis E2E C</title>
<h1>Compatibility test page</h1>
<img src="/ok.png?c">
<img src="http://ads.localhost:{PORT}/ad.png?c">
<iframe src="http://other.localhost:{PORT}/frame.html?c"></iframe>
<iframe src="http://ads.localhost:{PORT}/frame.html?c"></iframe>
<script>
new Image().src = '/js-executed?inline-c';
fetch('http://ads.localhost:{PORT}/fetch?c').catch(function(){});
try { new Worker('/worker.js'); } catch (e) {}
if (navigator.serviceWorker) navigator.serviceWorker.register('/sw.js').catch(function(){});
window.open('/popup-opened?c');
try { new WebSocket('ws://ads.localhost:{PORT}/ws'); } catch (e) {}
setTimeout(function(){ new Image().src = '/js-executed?late'; }, 500);
</script>
""",
    "/test-exc.html": """<!doctype html><meta charset=utf-8><title>Aegis E2E Exception</title>
<script>
new Image().src = '/js-executed?exc';
try {
  navigator.geolocation.getCurrentPosition(
    function(){ new Image().src = '/geo-granted'; },
    function(){ new Image().src = '/geo-denied'; });
} catch (e) { new Image().src = '/geo-denied?exception'; }
window.open('/popup-opened?exc');
</script>
""",
    "/test-other.html": """<!doctype html><meta charset=utf-8><title>Aegis E2E Other</title>
<script>new Image().src = '/js-executed?other';</script>
<noscript><img src="/noscript-other.png"></noscript>
""",
    "/frame.html": """<!doctype html><meta charset=utf-8><p>frame</p>""",
    "/": """<!doctype html><meta charset=utf-8><p>tls test</p>""",
}

SCRIPTS = {
    "/worker.js": """fetch('/worker-ok').then(function(){ return fetch('http://ads.localhost:{PORT}/worker-ad'); })
  .catch(function(){});""",
    "/sw.js": """self.addEventListener('install', function(e) {
  e.waitUntil(fetch('/sw-ok').then(function(){ return fetch('http://ads.localhost:{PORT}/sw-ad'); })
    .catch(function(){}));
});""",
}


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def self_signed_context(tmp: Path):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "page.localhost")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=2))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("page.localhost")]), critical=False)
            .sign(key, hashes.SHA256()))
    cert_path, key_path = tmp / "cert.pem", tmp / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert_path, key_path)
    return ctx


class Case:
    def __init__(self, name):
        self.name = name
        self.checks = []  # (description, passed, detail, informational)

    def check(self, desc, passed, detail="", informational=False):
        self.checks.append((desc, bool(passed), detail, informational))
        level = logging.INFO if passed or informational else logging.ERROR
        LOG.log(level, "  [%s] %s %s", "PASS" if passed else ("INFO" if informational else "FAIL"), desc, detail)

    @property
    def passed(self):
        return all(p or info for _, p, _, info in self.checks)


def write_settings(data_dir: Path, settings: dict):
    profile = data_dir / "Profiles" / "Default"
    profile.mkdir(parents=True, exist_ok=True)
    base = {"schema_version": 1, "https_first": True, "user_rules": ["||ads.localhost^"],
            "save_history": False}
    base.update(settings)
    (profile / "settings.json").write_text(json.dumps(base, indent=2), encoding="utf-8")
    return profile / "settings.json"


def run_browser(exe: Path, urls, report: Path, seconds: int, timeout: int):
    env = dict(os.environ, AEGIS_E2E="1")
    args = [str(exe), f"--aegis-test-exit-after={seconds}", f"--aegis-test-report={report}"] + list(urls)
    LOG.info("launch: %s", " ".join(args))
    proc = subprocess.Popen(args, env=env)
    try:
        code = proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        subprocess.run(["taskkill", "/F", "/T", "/IM", exe.name], capture_output=True)
        return None
    time.sleep(1.0)
    return code


def load_report(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def received(log_entries, host=None, path_prefix=None, server=None):
    for e in log_entries:
        if host and e["host"] != host:
            continue
        if path_prefix and not e["path"].startswith(path_prefix):
            continue
        if server and e["server"] != server:
            continue
        return True
    return False


def common_checks(case: Case, code, report, mode_id):
    case.check("browser exited cleanly after the test period", code == 0, f"exit code {code}")
    case.check("evidence report written", report is not None)
    if not report:
        return
    case.check("sandbox requested at startup", report.get("sandbox_requested") is True)
    sb = report.get("sandbox", {})
    case.check("renderer sandbox verified at runtime (Low/Untrusted integrity)", sb.get("state") == "verified",
               f"{sb.get('summary')} | {sb.get('detail')}")
    case.check(f"security mode is {mode_id}", report.get("mode") == mode_id, report.get("mode", ""))
    lists = {l["id"]: l for l in report.get("filter_lists", [])}
    case.check("EasyList and EasyPrivacy loaded", lists.get("easylist", {}).get("rules", 0) > 5000 and
               lists.get("easyprivacy", {}).get("rules", 0) > 5000)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--browser-dir", type=Path, required=True, help="directory containing WezCryptAegis.exe")
    ap.add_argument("--out", type=Path, default=Path("e2e-results"))
    ap.add_argument("--seconds", type=int, default=14, help="time each browser run stays open")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO, format="%(levelname)s %(message)s")

    exe = args.browser_dir / "WezCryptAegis.exe"
    if not exe.exists():
        LOG.error("browser not found: %s", exe)
        return 2
    args.out.mkdir(parents=True, exist_ok=True)
    data_dir = args.browser_dir / "Data"
    flag = args.browser_dir / "portable.flag"
    flag.write_text("e2e\n")

    log = RequestLog()
    ports = {"http": free_port(), "https": free_port()}
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", ports["http"]), make_handler(log, "http", ports))
    tls_tmp = Path(tempfile.mkdtemp())
    httpsd = http.server.ThreadingHTTPServer(("127.0.0.1", ports["https"]), make_handler(log, "https", ports))
    httpsd.socket = self_signed_context(tls_tmp).wrap_socket(httpsd.socket, server_side=True)
    for srv in (httpd, httpsd):
        threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://page.localhost:{ports['http']}"
    other = f"http://other.localhost:{ports['http']}"
    timeout = args.seconds + 90
    cases = []

    try:
        # --- Case 1: Maximum Isolation -----------------------------------
        case = Case("maximum_isolation_blocking")
        shutil.rmtree(data_dir, ignore_errors=True)
        settings_file = write_settings(data_dir, {"mode": "maximum-isolation"})
        log.clear()
        report_path = args.out / "report-max.json"
        code = run_browser(exe, [f"{base}/test-a.html"], report_path, args.seconds, timeout)
        report = load_report(report_path)
        entries = log.snapshot()
        common_checks(case, code, report, "maximum-isolation")
        case.check("first-party page loaded", received(entries, "page.localhost", "/test-a.html"))
        case.check("allowed first-party image fetched", received(entries, "page.localhost", "/ok.png"))
        case.check("ad host never contacted (img/script/iframe/redirect)", not received(entries, "ads.localhost"),
                   json.dumps([e["path"] for e in entries if e["host"] == "ads.localhost"]))
        case.check("redirect source was fetched", received(entries, "page.localhost", "/redirect"))
        case.check("unlisted third-party host blocked by mode policy", not received(entries, "tracker.localhost"))
        case.check("first-party external script not fetched (scripts blocked)",
                   not received(entries, "page.localhost", "/first-party.js"))
        case.check("inline JavaScript did not execute", not received(entries, path_prefix="/js-executed"))
        case.check("<noscript> content rendered (JavaScript disabled at engine level)",
                   received(entries, "page.localhost", "/noscript-rendered.png"))
        if report:
            counts = report.get("session_counts", {})
            case.check("blocking events recorded by the engine",
                       counts.get("user_rule", 0) + counts.get("third_party_request", 0) +
                       counts.get("script", 0) + counts.get("third_party_frame", 0) > 0, json.dumps(counts))
        persisted = json.loads(settings_file.read_text(encoding="utf-8"))
        case.check("strict settings persisted after exit", persisted.get("mode") == "maximum-isolation")
        cases.append(case)

        # --- Case 2: restart keeps protection, exceptions are scoped ------
        case = Case("restart_and_site_exception_scope")
        write_settings(data_dir, {"mode": "maximum-isolation",
                                  "site_exceptions": {"page.localhost": {"allow_javascript": True}}})
        log.clear()
        report_path = args.out / "report-exception.json"
        code = run_browser(exe, [f"{base}/test-exc.html", f"{other}/test-other.html"], report_path,
                           args.seconds, timeout)
        report = load_report(report_path)
        entries = log.snapshot()
        common_checks(case, code, report, "maximum-isolation")
        case.check("JavaScript runs on the excepted site", received(entries, "page.localhost", "/js-executed?exc"))
        case.check("exception does not apply to another site",
                   not received(entries, "other.localhost", "/js-executed"))
        case.check("other site rendered <noscript> content", received(entries, "other.localhost", "/noscript-other"))
        case.check("geolocation was not granted", not received(entries, path_prefix="/geo-granted"))
        case.check("script-initiated popup did not open", not received(entries, path_prefix="/popup-opened"))
        if report:
            counts = report.get("session_counts", {})
            case.check("popup block recorded", counts.get("popup", 0) >= 1, json.dumps(counts))
        cases.append(case)

        # --- Case 3: Compatibility mode, workers, service workers --------
        case = Case("compatibility_workers_and_redirects")
        shutil.rmtree(data_dir, ignore_errors=True)
        write_settings(data_dir, {"mode": "compatibility"})
        log.clear()
        report_path = args.out / "report-compat.json"
        code = run_browser(exe, [f"{base}/test-c.html"], report_path, args.seconds, timeout)
        report = load_report(report_path)
        entries = log.snapshot()
        common_checks(case, code, report, "compatibility")
        case.check("JavaScript executes in Compatibility mode (harness positive control)",
                   received(entries, "page.localhost", "/js-executed?inline-c"))
        ads_paths = [e["path"] for e in entries if e["host"] == "ads.localhost" and e["path"] != "/ws"]
        case.check("ad host never contacted by page, fetch(), iframe, worker or service worker",
                   not ads_paths, json.dumps(ads_paths))
        case.check("third-party frame allowed in Compatibility mode", received(entries, "other.localhost", "/frame.html"))
        case.check("dedicated worker ran (first-party request seen)", received(entries, "page.localhost", "/worker-ok"),
                   informational=True)
        case.check("service worker ran (first-party request seen)", received(entries, "page.localhost", "/sw-ok"),
                   informational=True)
        case.check("script-initiated popup without gesture blocked", not received(entries, path_prefix="/popup-opened"))
        ws = received(entries, "ads.localhost", "/ws")
        case.check("WebSocket handshake to filtered host (documented interception gap)", not ws,
                   "handshake reached server" if ws else "not observed", informational=True)
        cases.append(case)

        # --- Case 4: invalid TLS certificate ------------------------------
        case = Case("invalid_tls_certificate_rejected")
        log.clear()
        report_path = args.out / "report-tls.json"
        code = run_browser(exe, [f"https://page.localhost:{ports['https']}/"], report_path, args.seconds, timeout)
        report = load_report(report_path)
        entries = log.snapshot()
        common_checks(case, code, report, "compatibility")
        case.check("no HTTP request completed over the untrusted TLS connection",
                   not received(entries, server="https"), json.dumps(entries))
        if report:
            case.check("certificate error recorded", report.get("session_counts", {}).get("certificate", 0) >= 1,
                       json.dumps(report.get("session_counts", {})))
        cases.append(case)
    finally:
        httpd.shutdown()
        httpsd.shutdown()
        shutil.rmtree(tls_tmp, ignore_errors=True)
        flag.unlink(missing_ok=True)

    # Reports.
    total = sum(len(c.checks) for c in cases)
    failures = sum(1 for c in cases for _, p, _, info in c.checks if not p and not info)
    junit = ['<?xml version="1.0" encoding="UTF-8"?>',
             f'<testsuite name="aegis-e2e" tests="{total}" failures="{failures}">']
    md = ["# WezCrypt Aegis end-to-end results", ""]
    for c in cases:
        md.append(f"## {c.name}: {'PASS' if c.passed else 'FAIL'}")
        for desc, p, detail, info in c.checks:
            status = "PASS" if p else ("INFO" if info else "FAIL")
            md.append(f"- **{status}** {desc}" + (f" — `{detail[:300]}`" if detail else ""))
            junit.append(f'  <testcase classname="{escape(c.name)}" name="{escape(desc, {chr(34): "&quot;"})}">'
                         + ("" if p or info else f'<failure message="{escape(detail[:500], {chr(34): "&quot;"})}"/>')
                         + "</testcase>")
        md.append("")
    junit.append("</testsuite>")
    (args.out / "e2e-junit.xml").write_text("\n".join(junit), encoding="utf-8")
    (args.out / "E2E_RESULTS.md").write_text("\n".join(md), encoding="utf-8")
    LOG.info("%d checks, %d failures", total, failures)
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main())

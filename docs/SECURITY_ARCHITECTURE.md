# WezCrypt Aegis — Security Architecture

## Engine choice
* **Chromium Embedded Framework 152.0.14** (stable channel) (Chromium 152.0.7977.167), pinned in
  `third_party/cef.json`, downloaded from the official CEF build index with SHA-1 (index) and
  optional pinned SHA-256 verification (`scripts/fetch_cef.py`). The script warns when a newer
  stable CEF exists.
* CEF API version: `CEF_API_VERSION_LAST` (15200), selected automatically by CEF's CMake for
  sandboxed Windows builds.
* Browsers use the **Alloy runtime style** inside a CEF Views window so that every UI surface
  (tabs, prompts, downloads, popups) is WezCrypt's own code and every engine callback is handled
  explicitly.

## Sandbox (CEF M138+ bootstrap model)
Since M138 the `cef_sandbox` static library can only be linked into binaries built with
Chromium's own toolchain. WezCrypt Aegis follows the official replacement:

```
WezCryptAegis.exe  = CEF's prebuilt bootstrap.exe (renamed, unmodified code)
WezCryptAegis.dll  = WezCrypt Aegis, exports RunWinMain(hInstance, cmd, show, sandbox_info, version_info)
```
The bootstrap creates the sandbox information object and calls `RunWinMain` in **every**
process (browser, renderer, GPU, utility). `src/app/main_win.cc`:
1. Exits with an error if `sandbox_info == nullptr` (DLL loaded any other way) — in every process.
2. Refuses to start when the command line contains security-weakening switches
   (`--no-sandbox`, `--disable-web-security`, `--ignore-certificate-errors`,
   `--remote-debugging-port`, `--single-process`, `--disable-site-isolation-trials`, …;
   full list in `src/security/engine_switches.cc`).
3. Initializes CEF with `no_sandbox = false` and `command_line_args_disabled = true`
   (Chromium never sees user-supplied switches).
4. The build grants the LPAC SID read/execute on the install folder (`SET_LPAC_ACLS`, installer
   `icacls` step, `Setup-Portable.cmd`).

**Runtime evidence.** `src/browser/sandbox_verifier_win.cc` enumerates the browser's child
processes, reads each process's `--type=` and the mandatory integrity level / AppContainer /
restricted-token state of its primary token. The Security Control Center shows the result
("N of M renderer processes verified at Low/Untrusted integrity"). If any renderer is found at
Medium integrity or higher, every window is closed and the browser exits (**fail closed**).

## Request pipeline (pre-network)
```
renderer/worker/service worker request
  └─► CefResourceRequestHandler::OnBeforeResourceLoad   (network/IO thread, before DNS/TCP/TLS)
        └─► EvaluateRequest(PolicySnapshot, RequestContext)          src/security/security_policy.cc
              1 scheme policy (aegis/file/chrome/… for subresources)
              2 top-level: HTTPS-first upgrade, strict host filter → interstitial
              3 private-network protection (public page → 10.x/192.168.x/localhost …)
              4 site exception (disable_filtering)
              5 filter engine (important > block > exceptions > $document allowlist)
              6 mode rules (Maximum: scripts + all third-party; Strict: third-party frames,
                per-site JS blocks; Compatibility: none)
        RV_CANCEL | SetURL(https) | RV_CONTINUE
  └─► OnResourceRedirect: every redirect target is re-evaluated; blocked targets are rewritten to
      a non-network internal URL (Chromium refuses web→display-isolated redirects).
```
* Dedicated workers' requests reach the same handler (verified by the E2E suite). Requests without
  a browser reach it through `CefRequestContextHandler::GetResourceRequestHandler`; their first
  party comes from `site_for_cookies`. Service workers are not allowed to start (see gaps).
* First/third-party relationships use the **Public Suffix List** (ICANN + private sections).
* The filter engine is immutable after build and swapped atomically; the IO thread never waits
  for a rebuild.

### Filter engine
* ABP/uBO network syntax: `||host^`, anchors `|`, `*`, `^`, `@@`, `$third-party`/`1p`/`3p`,
  resource types, `domain=`/`from=` with negation and `entity.*`, `match-case`, `important`,
  `badfilter`, `$document` exceptions, `$popup`, hosts-file lines; `redirect=`/`rewrite=abp-resource`
  rules block the request.
* Indexed by host (suffix lookup) and by the rarest complete token; glob matching is
  segment-based and linear-time (no regular expressions, no catastrophic backtracking).
* **Not applied (counted and shown on the dashboard):** cosmetic/element-hiding/scriptlet rules,
  regular-expression rules, `csp=`, `removeparam=`, `redirect-rule=`, `header=`, `method=`,
  `denyallow=`, `to=` and other response-modifying options. Applying them as plain blocks could
  misbehave, so they are skipped. Current bundled lists: ~113k network rules applied,
  ~25k cosmetic rules skipped, 39 unsupported, 11 malformed.
* Limits: 16 MiB per list, 64 KiB per line, 1024 domains per rule, 600k rules total.

### Updates of filter lists
`UpdateService::RefreshFilterLists` downloads `https://easylist.to/...` through `CefURLRequest`
(Chromium certificate validation, no cookies/credentials, streamed size cap). A downloaded list is
applied only if: it is valid UTF-8 and looks like a filter list (not HTML), it builds, it has at
least the configured minimum rules, it did not shrink by more than half, and fewer than 25 % of
lines are invalid. Otherwise the active engine and cached copy remain unchanged.

## JavaScript policy
| Mode | JavaScript | V8 optimizers | WebAssembly | WebGL | Web fonts |
|---|---|---|---|---|---|
| Maximum Isolation | blocked (content setting + browser setting + script requests cancelled), per-site exceptions | off | not exposed (`--noexpose_wasm`) | off | off |
| Strict Protection | allowed, per-site block list | off (`JAVASCRIPT_OPTIMIZER` block) | exposed* | off | on |
| Compatibility | allowed | on | exposed* | on | on |

\* WebAssembly exposure is a process-wide V8 flag fixed at startup; after switching *to* or *from*
Maximum Isolation the change applies after a restart, which the browser states explicitly.
All other mode changes apply immediately; tabs are recreated so browser-level settings follow.
Content settings are written per frame in `OnBeforeBrowse` — before the document is fetched — for
the exact frame URL / top-level URL pair.

## Network protections
* HTTPS-first for top-level navigations (not for localhost/private/IP/intranet/non-default ports);
  connection failures on an upgraded URL show a consent page; certificate errors never offer HTTP.
* Certificate errors: `OnCertificateError` returns `false` (request cancelled); no bypass exists.
  Client certificates are never sent automatically.
* External protocols: the engine never launches OS handlers. `ms-*`, `search-ms`, `ms-msdt`, `file`,
  `javascript`, `vbscript`, `ldap`, `smb`, … are always blocked; others require a user gesture,
  are blocked in Maximum Isolation, and need confirmation.
* Private-network protection: public pages cannot reach loopback/RFC 1918/link-local/CGNAT/ULA.
* WebRTC: `webrtc.ip_handling_policy = disable_non_proxied_udp`.
* Network prediction (prefetch/preconnect) disabled via preference.
* Third-party cookies: Chromium preference `profile.cookie_controls_mode = 1` **and** a
  `CefCookieAccessFilter` that refuses cookies on third-party requests.

## Known interception gaps (documented, not hidden)
| Path | Status | Mitigation |
|---|---|---|
| Requests made by a running **service worker** | Verified on Windows (CEF 152): not delivered to CEF resource handlers | Service-worker registration is blocked in every mode (the script fetch *is* interceptable), so no service worker can run |
| WebSocket handshakes (`ws://`, `wss://`) | Verified on Windows (CEF 152): handshake reaches the server unfiltered | JS disabled in Maximum Isolation; E2E reports the observed behavior on every run |
| WebRTC / DataChannels | Not intercepted | IP-handling policy; JS disabled in Maximum Isolation |
| `<link rel=preconnect/dns-prefetch>` | Socket/DNS may be opened without a request | Network-prediction preference disabled; no HTTP request is sent |
| Chromium-internal traffic (component updater: CRLSets etc.) | Not routed through handlers | Intentionally left enabled for certificate revocation updates |
| Cosmetic filtering | Not implemented | Network blocking only; counted on the dashboard |

## Privacy
* Private windows: in-memory `CefRequestContext` (no cache path), never write history, grants not
  reused; cookies/cache cleared when the window closes. Not anonymity.
* Profiles: `--profile=<name>` gives separate engine data and stores.
* No telemetry, analytics or advertising SDKs; no account. Background traffic generated by
  WezCrypt itself: filter-list updates and (if configured) the signed release manifest.
* Clear history/cookies/cache now or on exit; "clear all site data" wipes the engine profile on
  next start (before Chromium opens it).
* WezCrypt stores no passwords or other secrets. Chromium encrypts its cookie store with DPAPI.

## Downloads
Every download asks for confirmation (with a stronger warning for executable/script types and
deceptive double extensions), then the native Save dialog. Names are sanitized (path components,
bidi/zero-width characters, Windows-invalid characters, reserved device names, length), the target
is verified to stay inside the download directory, Mark-of-the-Web (`Zone.Identifier`, ZoneId=3)
is written on completion, and nothing is ever opened automatically. A downloaded file whose name
matches a signed release artifact is verified against the manifest's SHA-512 and deleted on mismatch.

## Updates of the browser
Release manifests (`scripts/sign_manifest.py`) are JSON signed with Ed25519 (Monocypher in the
browser, `cryptography` in tooling). The browser checks: trusted key, product, channel, monotonic
sequence (rollback protection, persisted), issue/expiry time, HTTPS artifact URLs, then compares
versions and the `minimum_safe_chromium_version`. It shows a warning when the engine is below the
minimum safe version or — without a manifest — when the build is older than 45 days.
There is **no silent auto-installer**: users download the installer through the confirmed
download flow; it is verified, never executed by the browser.

## IPC boundary
WezCrypt Aegis has no `CefRenderProcessHandler`, no `CefV8Handler`, no message router and no
JavaScript bindings. Web pages cannot reach any WezCrypt C++ interface. Renderer-originated
process messages are dropped and logged.

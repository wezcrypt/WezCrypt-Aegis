# WezCrypt Aegis — Threat Model

## Assets
1. The user's Windows account and operating system (files, credentials, other processes).
2. The user's identity and browsing data (cookies, history, permissions).
3. Integrity of the browser itself (settings, filter rules, update decisions).

## Adversaries
| Adversary | Capability |
|---|---|
| Malicious advertiser / compromised ad network | Serves arbitrary HTML/JS/images/frames inside third-party slots; controls redirect chains |
| Malicious or compromised website | Full control of first-party content, can attempt popups, downloads, protocol launches, permission requests |
| Exploit kit | Delivers payloads targeting renderer/V8/WebAssembly/font/GPU bugs, including unknown (0-day) bugs |
| Tracker | Third-party requests, cookies, beacons, fingerprinting scripts |
| Network attacker | Observes/modifies unencrypted traffic; presents invalid certificates |
| Local attacker with user rights | Can modify the browser's files and command line — **out of scope** (equivalent to owning the account) |

## Hostile inputs considered
Malicious advertisements and ad scripts, compromised ad networks, malicious iframes, drive-by
downloads, redirect chains, popups/popunders, exploit landing pages, WebAssembly payloads, Web
Workers, Service Worker abuse, WebSockets, OS protocol handlers (`ms-msdt:`, `search-ms:` …),
`file://` access, credential phishing (look-alike IDN domains, `data:` URL phishing), cross-site
data exposure (third-party cookies, private-network requests), and vulnerable browser components.

## Five distinct security objectives

WezCrypt Aegis keeps these separate; each has different mechanisms and different limits.

| # | Objective | Mechanism in WezCrypt Aegis | What it does **not** do |
|---|---|---|---|
| 1 | **Prevent a resource from loading** | `OnBeforeResourceLoad` → `RV_CANCEL` before any connection, filter lists (EasyList, EasyPrivacy, baseline, user rules), mode rules (third-party, scripts), redirect re-evaluation, private-network blocking, HTTPS-first | Cannot see WebSocket handshakes, WebRTC, `<link rel=preconnect>`/DNS prefetch or Chromium-internal traffic (see gaps) |
| 2 | **Prevent JavaScript execution** | Chromium content settings (`JAVASCRIPT` block per origin, set before each frame navigation), browser-level `javascript` setting in Maximum Isolation, script requests cancelled, WebAssembly not exposed (`--noexpose_wasm`), V8 optimizing tiers disabled in Maximum/Strict (`JAVASCRIPT_OPTIMIZER`) | JS that the user allows via a site exception runs normally |
| 3 | **Isolate a compromised renderer** | Chromium multiprocess architecture, strict site isolation (`--site-per-process`), no renderer-side bindings, browser ignores all renderer IPC messages | Same-site content shares a renderer process |
| 4 | **Prevent sandbox escape** | The Chromium Windows sandbox (restricted token, Untrusted integrity, job objects, win32k lockdown, AppContainer/LPAC for some processes) via CEF's bootstrap; startup refuses to run without it; runtime verification of renderer integrity; fail-closed on evidence of an unsandboxed renderer | Does not fix Chromium/Windows kernel vulnerabilities; timely engine updates are the defense |
| 5 | **Prevent operating-system compromise** | Layers 1–4 plus: downloads never auto-open, sanitized filenames, Mark-of-the-Web, dangerous protocol handlers never launched, `file://` only by explicit user navigation, no Node.js/native APIs in pages | A user who explicitly runs a downloaded program is outside the browser's control |

## Trust boundaries
* **Renderer ↔ browser process**: CEF/Chromium IPC. WezCrypt adds no renderer-side code and
  drops every `CefProcessMessage` (`ClientHandler::OnProcessMessageReceived`).
* **Web content ↔ internal pages**: `aegis://` is a *display-isolated*, secure, standard scheme;
  pages are static HTML without JavaScript, served with `script-src 'none'` CSP; internal pages
  hold no privileged bridge. The one state-changing internal link (HTTPS fallback consent) uses
  a one-time, unguessable token and is accepted only from an `aegis://` page with a user gesture.
* **Network ↔ update subsystem**: filter lists are data, validated before use; release manifests
  must carry an Ed25519 signature from a key compiled into the binary. Nothing downloaded is executed.
* **Command line**: switches that weaken Chromium security abort startup; Chromium never sees
  user-supplied switches (`command_line_args_disabled`).

## Explicit non-goals
* Anonymity against websites, networks or local monitoring (private windows only avoid local persistence).
* Protection when the attacker already controls the user's Windows account.
* Guaranteed immunity to unknown vulnerabilities. WezCrypt Aegis **reduces exposure**; it does not
  and cannot claim complete zero-day protection.

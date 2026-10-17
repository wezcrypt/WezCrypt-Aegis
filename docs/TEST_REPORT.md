# WezCrypt Aegis — Test Report

All results below come from executed runs. CI: `.github/workflows/ci.yml`
(job `core-linux` on Ubuntu 24.04/GCC 13; job `windows` on Windows Server 2022/MSVC 19.44 with
CEF 152.0.14 / Chromium 152.0.7977.167). Results of the latest CI run are attached to each run as
the `test-results-linux`/`test-results-windows` artifacts (JUnit XML, `E2E_RESULTS.md`,
`build-verification.json`, per-run evidence reports).

## 1. Security-core suite (`aegis_tests`, 127 tests)
| Environment | Result |
|---|---|
| Linux GCC 13, Release, `-Werror` | 127/127 pass |
| Linux GCC 13, AddressSanitizer + UBSan | 127/127 pass, no sanitizer reports |
| Linux GCC 13, ThreadSanitizer (`Concurrency.*`) | pass, no data races |
| Windows MSVC 19.44, Release `/MT` | pass (126/126 at the time of the first Windows run; suite since grew to 127) |

Suites: URL/IDNA (12), Public Suffix List incl. official vectors (4), filter parser (6) and
engine (13), policy/modes/exceptions/popups/navigation (17), settings and crash-safe persistence
(11), downloads (7), permissions (5), network policy (4), signed updates incl. RFC 8032 and
SHA-512 known answers (9), internal pages/omnibox (6), switches (3), browsing data/profiles (5),
real-list request pipeline (9), robustness/fuzz (7), concurrency (2).

## 2. Release signing round trip (`tests/release/signing_roundtrip.py`)
Python (`cryptography`) Ed25519 signer → C++ verifier (`aegis_tool`): valid manifest accepted,
artifact verified; wrong key, rollback (sequence replay), tampered manifest and substituted
artifact all rejected. **Pass** (Linux CI and local).

## 3. Windows binary verification (`scripts/verify_build.py`)
`WezCryptAegis.exe` is byte-identical to CEF's `bootstrap.exe`; `WezCryptAegis.dll` exports
`RunWinMain`; both have ASLR, high-entropy VA, DEP, Control Flow Guard and CET-compatible flags.
**Pass.**

## 4. End-to-end browser tests (`tests/e2e/run_e2e.py`, real WezCryptAegis.exe)
Local servers on `*.localhost`; every check is decided by what the *server* received.

| Required test | E2E evidence | Result |
|---|---|---|
| 1 Third-party ad requests blocked before fetch | `ads.localhost` never contacted (img, script, iframe, fetch, worker) | Pass |
| 2 Allowed requests still work | first-party page/image fetched | Pass |
| 3 Redirect-based ad requests filtered | `/redirect` fetched, target on ad host never contacted | Pass |
| 4 Script blocking before execution | inline-script beacon absent; `<noscript>` rendered; external script not fetched | Pass |
| 5 Strict settings persist | settings file still `maximum-isolation` after exit | Pass |
| 6 Per-site exceptions only for intended site | JS runs on `page.localhost`, not on `other.localhost` | Pass |
| 7 Blocked popups cannot open | `window.open` target never requested | Pass |
| 8 Invalid TLS certificates rejected | no HTTP request over the self-signed TLS server | Pass |
| 9 Permissions denied by default | geolocation never granted | Pass |
| 10 Downloads never execute automatically | Not automated end-to-end (download flow requires a modal confirmation); covered by code review and unit tests of naming/MotW | **Not E2E-tested** |
| 11 Private sessions don't persist data | Not automated end-to-end | **Not E2E-tested** (in-memory context by construction) |
| 12 Filter update failures don't weaken rules | unit/integration (`Pipeline.FilterUpdateFailuresNeverWeakenRules`) | Pass |
| 13 Site origins parsed correctly | URL/PSL/IDNA suites | Pass |
| 14 Crashes don't corrupt security settings | torn-write and corrupt-file tests | Pass |
| 15 Sandbox verified with runtime evidence | evidence report `sandbox.state` (renderer token integrity) | see latest CI artifact |
| 16 Protection remains after restart | persistence tests + second launch reads persisted mode | Pass |
| Workers | dedicated worker requests filtered | Pass |
| Service workers | **Gap found**: SW fetches bypass CEF interception → SW registration now blocked; E2E checks it cannot start | see latest CI artifact |
| WebSockets | handshake to filtered host reaches the server (documented gap) | Informational |

## 5. Not tested / limitations of testing
* No manual exploratory UI testing on physical Windows 10 hardware was possible from this
  environment; UI behavior was exercised only through the automated E2E runs.
* Download confirmation, permission prompts with user approval, external-protocol prompts, and
  private-window data deletion are not automated (they involve modal dialogs).
* No exploit testing: no weaponized exploits or live malicious payloads were used (by design).
* HTTPS-first fallback page and update-manifest fetching over the network were not exercised
  end-to-end (no signing infrastructure configured).

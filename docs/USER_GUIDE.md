# WezCrypt Aegis — User Guide

## Security modes (toolbar button, right of the address bar)
| Mode | For | What changes |
|---|---|---|
| **Maximum Isolation** (default) | Unknown or risky sites, reading | JavaScript off, all third-party content blocked, no WebAssembly/WebGL/web fonts, popups and permissions denied |
| **Strict Protection** | Everyday browsing | JavaScript on (block it per site), JIT compilers off, third-party frames blocked, permissions ask |
| **Compatibility** | Sites that break otherwise | Filters, sandbox, site isolation, HTTPS-first and third-party-cookie blocking stay on |

Lowering protection always asks for confirmation. The current mode is shown in the toolbar and the status bar.

## Site security (lock / warning icon left of the address)
Per-site exceptions apply only to the site you are on (its registrable domain, e.g. `example.co.uk`):
allow JavaScript, allow third-party content, allow popups, disable filtering, block JavaScript
(Strict mode), reset permissions. Exceptions for whole public suffixes (e.g. `github.io`) are refused.

## Shield counter
Number of requests blocked on the current page before they reached the network. Click it for the
site report (what was blocked and which rule matched).

## Internal pages
`aegis://security` Security Control Center · `aegis://network` network activity · `aegis://history` ·
`aegis://bookmarks` · `aegis://downloads` · `aegis://about`

## Keyboard shortcuts
| Keys | Action |
|---|---|
| Ctrl+T / Ctrl+W / Ctrl+Shift+T | New tab / close tab / reopen closed tab |
| Ctrl+N / Ctrl+Shift+N | New window / new private window |
| Ctrl+Tab / Ctrl+Shift+Tab | Next / previous tab |
| Ctrl+L, F6 | Focus address bar |
| Ctrl+R, F5 / Ctrl+F5 | Reload / reload ignoring cache |
| Esc | Stop loading / close find bar |
| Alt+Left / Alt+Right / Alt+Home | Back / forward / home |
| Ctrl+F, F3, Shift+F3 | Find, next, previous |
| Ctrl+D | Bookmark page |
| Ctrl+Shift+B / Ctrl+H / Ctrl+J | Bookmarks / history / downloads |
| Ctrl+Shift+S / Ctrl+Shift+A | Security Control Center / network activity |
| Ctrl+Plus / Ctrl+Minus / Ctrl+0 | Zoom |

## Private windows
Cookies, cache and storage live in memory only and are discarded when the window closes; history
is not recorded. Private windows do **not** make you anonymous to websites you sign in to, your
network provider or software on your computer.

## Downloads
Every download asks first and then shows the Save dialog. Programs and scripts get an extra warning.
Files are never opened automatically and are marked as downloaded from the Internet.

## Profiles and portable use
`WezCryptAegis.exe --profile=Work` keeps a separate profile. The portable ZIP stores data next to
the program (`Data\`); run `Setup-Portable.cmd` once after extracting.

## Command line
`WezCryptAegis.exe [--private] [--profile=NAME] [URL ...]`. Switches that weaken Chromium security
(such as `--no-sandbox`) make the browser refuse to start.

# Third-party components in WezCrypt Aegis

| Component | Version | License | Where | License text |
|---|---|---|---|---|
| Chromium Embedded Framework (CEF) | see `third_party/cef.json` | BSD-3-Clause | runtime DLLs and resources | `CEF-LICENSE.txt` |
| Chromium (via CEF) | see `third_party/cef.json` | BSD-3-Clause and many third-party licenses | `libcef.dll` | `CHROMIUM-CREDITS.html` (copied from the CEF distribution at packaging time) |
| Monocypher | 4.0.2 | BSD-2-Clause OR CC0-1.0 | `third_party/monocypher` (Ed25519, SHA-512) | `Monocypher-LICENCE.md` |
| Public Suffix List | snapshot in `assets/data` | MPL-2.0 | `assets/data/public_suffix_list.dat` | `MPL-2.0.txt` |
| EasyList | snapshot in `assets/filters` (see `! Version:` header) | GPL-3.0-or-later OR CC-BY-SA-3.0 | `assets/filters/easylist.txt` | `GPL-3.0-or-later.txt`, `CC-BY-SA-3.0.txt` |
| EasyPrivacy | snapshot in `assets/filters` | GPL-3.0-or-later OR CC-BY-SA-3.0 | `assets/filters/easyprivacy.txt` | `GPL-3.0-or-later.txt`, `CC-BY-SA-3.0.txt` |

## Attribution

* EasyList and EasyPrivacy are maintained by The EasyList authors
  (https://easylist.to/). WezCrypt Aegis redistributes the lists unmodified
  under CC BY-SA 3.0 and updates them from easylist.to at runtime.
* The Public Suffix List is maintained by the Mozilla Foundation and
  contributors (https://publicsuffix.org/). It is redistributed unmodified
  under MPL-2.0; its source is https://github.com/publicsuffix/list.
* Monocypher is written by Loup Vaillant and contributors
  (https://monocypher.org/). The vendored files are unmodified copies of
  release 4.0.2.

Filter lists and the Public Suffix List are data files used by WezCrypt Aegis;
they are separate works aggregated with the WezCrypt Aegis program.

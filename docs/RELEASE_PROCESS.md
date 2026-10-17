# Release Process and Remaining Release Requirements

## Status of release infrastructure
| Item | State |
|---|---|
| Reproducible build from source (CI) | Implemented (`.github/workflows/ci.yml`) |
| Engine pinning and verified download | Implemented (`third_party/cef.json`, `scripts/fetch_cef.py`) |
| SHA-256 release hashes | Implemented (`SHA256SUMS.txt`) |
| SBOM | Implemented (CycloneDX 1.5) |
| Signed release manifests, rollback protection, artifact verification | Implemented (code + tooling); **requires a WezCrypt signing key and hosting** |
| Authenticode code signing | **Not available in this environment** — artifacts from CI are unsigned |
| Automatic installation of updates | Deliberately not implemented (no unsigned or silent installs) |

## 1. Security patch cadence
Chromium ships security fixes roughly every 1–2 weeks. For each new CEF stable release:
1. `python scripts/fetch_cef.py --list`; update `third_party/cef.json` (version, and the
   SHA-256 printed by the first verified download).
2. Run CI (core tests, Windows build, PE verification, E2E). Review CEF release notes for
   API changes, especially anything touching the sandbox bootstrap or `CefRequestHandler`.
3. Update `minimum_safe_chromium_version` in the next manifest to the newest version that fixes
   known exploited vulnerabilities; older engines will then show the red warning.

## 2. Signing keys (one time)
```
python scripts/sign_manifest.py keygen --private release-key.pem --public-out release-key.pub
```
Keep `release-key.pem` offline or in an HSM-backed signing service. Build with
`-DAEGIS_UPDATE_PUBLIC_KEYS=$(cat release-key.pub)` and
`-DAEGIS_UPDATE_MANIFEST_URL=https://<your-domain>/aegis/stable/manifest.json`.
Two keys may be listed for rotation.

## 3. Publishing a release
```
python scripts/sign_manifest.py create --version 1.0.1 --sequence <previous+1> \
   --chromium 154.0.8037.98 --min-chromium 154.0.8037.98 \
   --artifact WezCryptAegis-1.0.1-win-x64-setup.exe=https://<host>/WezCryptAegis-1.0.1-win-x64-setup.exe=dist/WezCryptAegis-1.0.1-win-x64-setup.exe \
   --out manifest.json
python scripts/sign_manifest.py sign --private release-key.pem --manifest manifest.json
build/aegis_tool verify-manifest manifest.json manifest.json.sig release-key.pub
```
Upload `manifest.json` and `manifest.json.sig` next to each other over HTTPS. Sequence numbers
must strictly increase; clients reject any manifest with a sequence ≤ the last one they accepted.

## 4. Authenticode signing
WezCrypt must obtain an EV or OV code-signing certificate (hardware token or cloud signing).
Set `AEGIS_SIGN_THUMBPRINT` and `AEGIS_SIGN_TIMESTAMP_URL` before running
`scripts/package_windows.py`; it signs `WezCryptAegis.exe`, `WezCryptAegis.dll` and the installer
with SHA-256 and RFC 3161 timestamps. Note that `WezCryptAegis.exe` is CEF's bootstrap with
WezCrypt resources (rcedit) — sign after modification, as CEF's documentation requires.
CEF's own DLLs (`libcef.dll`, etc.) should also be signed by the publisher if not already signed.

## 5. Release checklist
- [ ] CI green on Windows and Linux, E2E report reviewed (sandbox verified in every run)
- [ ] `verify_build.py` report: ASLR, high-entropy VA, DEP, CFG on exe and dll
- [ ] Binaries Authenticode-signed and timestamped
- [ ] Manifest signed, sequence incremented, verified with `aegis_tool`
- [ ] SBOM and SHA256SUMS published with the release
- [ ] Filter list snapshots refreshed

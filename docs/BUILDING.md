# Building WezCrypt Aegis

## Requirements (Windows x64 browser)
* Windows 10/11 x64, Visual Studio 2022 (MSVC v143, "Desktop development with C++"), CMake ≥ 3.21
* Python 3.10+ with `cryptography` and `pefile` (`pip install cryptography pefile`)
* Optional: Inno Setup 6 (installer), `rcedit` (exe icon/version), `signtool` + certificate (signing)

## 1. Fetch the pinned CEF distribution
```
python scripts/fetch_cef.py --out third_party/cef
```
Downloads `cef_binary_154.0.34+g14c5a08+chromium-154.0.8037.98_windows64_minimal` from the
official CEF build server, verifies the SHA-1 from the build index (and the SHA-256 when pinned in
`third_party/cef.json`), rejects archives containing links or path traversal, and confirms that
`bootstrap.exe` (CEF M138+ sandbox host) is present. `--list` shows current stable versions.

## 2. Configure and build
```
cmake -S . -B build -G "Visual Studio 17 2022" -A x64 ^
      -DAEGIS_BUILD_BROWSER=ON -DCEF_ROOT=third_party/cef/cef_binary_154.0.34+g14c5a08+chromium-154.0.8037.98_windows64_minimal
cmake --build build --config Release --parallel
```
Output: `build\src\app\Release\` containing `WezCryptAegis.exe` (CEF bootstrap),
`WezCryptAegis.dll`, `libcef.dll` and runtime files, `locales\`, `assets\`.
`USE_SANDBOX` is forced ON; there is no unsandboxed build configuration.

Optional build options:
| Option | Meaning |
|---|---|
| `-DAEGIS_UPDATE_PUBLIC_KEYS=<base64>[,<base64>]` | Ed25519 keys trusted for release manifests |
| `-DAEGIS_UPDATE_MANIFEST_URL=https://…/manifest.json` | enables online release checks (`.sig` is fetched next to it) |
| `-DAEGIS_UPDATE_CHANNEL=stable` | expected manifest channel |
| `SOURCE_DATE_EPOCH` env var | reproducible build timestamp |

## 3. Test
```
build\tests\Release\aegis_tests.exe --junit=aegis-tests.xml
python scripts\verify_build.py --browser-dir build\src\app\Release --cef-root <CEF_ROOT>
python tests\e2e\run_e2e.py --browser-dir build\src\app\Release --out e2e-results
```
The E2E harness launches the real browser several times against local test servers (it needs an
interactive desktop session, as on GitHub's Windows runners).

## 4. Package
```
python scripts\package_windows.py --browser-dir build\src\app\Release --cef-root <CEF_ROOT> ^
       --version 1.0.0 --out dist --rcedit rcedit-x64.exe --iscc "C:\Program Files (x86)\Inno Setup 6\ISCC.exe"
```
Produces the portable ZIP, installer, CycloneDX SBOM and `SHA256SUMS.txt`. The package is
**not standalone as a single EXE**: `WezCryptAegis.exe` requires `WezCryptAegis.dll`, `libcef.dll`,
the `.pak`/`.dat`/`.bin` resources, `locales\` and `assets\` in the same folder.

## Security core only (any OS)
The portable security core and its 126 tests build with GCC/Clang/MSVC without CEF:
```
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build && ./build/tests/aegis_tests
cmake -S . -B build-asan -DAEGIS_ENABLE_SANITIZERS=ON -DCMAKE_BUILD_TYPE=Debug && cmake --build build-asan && ./build-asan/tests/aegis_tests
python3 tests/release/signing_roundtrip.py build/aegis_tool
```

## Regenerating bundled data
* Branding: `python scripts/generate_branding.py`
* Filter lists / PSL snapshots: replace `assets/filters/*.txt` and `assets/data/public_suffix_list.dat`
  with current upstream copies; the browser also updates filter lists at runtime.

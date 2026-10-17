#!/usr/bin/env python3
"""Package WezCrypt Aegis for Windows x64.

Produces in --out:
  WezCryptAegis-<version>-win-x64/            staged application directory
  WezCryptAegis-<version>-win-x64-portable.zip
  WezCryptAegis-<version>-win-x64-setup.exe   (when Inno Setup's ISCC is available)
  WezCryptAegis-<version>.cdx.json            CycloneDX SBOM
  SHA256SUMS.txt

Optional steps run only when their tools/configuration are present:
  * rcedit      - sets the icon and version resources of WezCryptAegis.exe
  * signtool    - Authenticode signing (env AEGIS_SIGN_THUMBPRINT and
                  AEGIS_SIGN_TIMESTAMP_URL); without it the output is UNSIGNED
  * ISCC        - builds the installer from packaging/windows/installer.iss
"""
import argparse
import hashlib
import json
import logging
import os
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

LOG = logging.getLogger("package")
ROOT = Path(__file__).resolve().parent.parent

REQUIRED = [
    "WezCryptAegis.exe", "WezCryptAegis.dll", "libcef.dll", "chrome_elf.dll", "icudtl.dat",
    "resources.pak", "chrome_100_percent.pak", "chrome_200_percent.pak", "v8_context_snapshot.bin",
    "locales/en-US.pak", "assets/data/public_suffix_list.dat", "assets/filters/easylist.txt",
    "assets/filters/easyprivacy.txt", "assets/filters/aegis-baseline.txt", "assets/branding/aegis-32.png",
]
EXCLUDE_SUFFIXES = {".pdb", ".lib", ".exp", ".ilk", ".log", ".iobj", ".ipdb"}
EXCLUDE_NAMES = {"bootstrap.exe", "bootstrapc.exe", "portable.flag", "debug.log"}
EXCLUDE_DIRS = {"Data"}


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def stage(browser_dir: Path, dest: Path):
    if dest.exists():
        shutil.rmtree(dest)
    for src in browser_dir.rglob("*"):
        rel = src.relative_to(browser_dir)
        if rel.parts and rel.parts[0] in EXCLUDE_DIRS:
            continue
        if src.is_dir() or src.suffix.lower() in EXCLUDE_SUFFIXES or src.name in EXCLUDE_NAMES:
            continue
        out = dest / rel
        out.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, out)
    for extra in ("README.md",):
        shutil.copy2(ROOT / extra, dest / extra)
    shutil.copytree(ROOT / "LICENSES", dest / "LICENSES")
    shutil.copy2(ROOT / "packaging" / "windows" / "Setup-Portable.cmd", dest / "Setup-Portable.cmd")
    missing = [r for r in REQUIRED if not (dest / r).exists()]
    if missing:
        raise SystemExit(f"package is incomplete, missing: {missing}")


def run_optional(cmd, what):
    LOG.info("%s: %s", what, " ".join(str(c) for c in cmd))
    subprocess.run([str(c) for c in cmd], check=True)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--browser-dir", type=Path, required=True)
    ap.add_argument("--version", required=True)
    ap.add_argument("--out", type=Path, default=ROOT / "dist")
    ap.add_argument("--cef-root", type=Path, help="CEF distribution (for its LICENSE/CREDITS files)")
    ap.add_argument("--rcedit", type=Path)
    ap.add_argument("--iscc", type=Path)
    ap.add_argument("-v", "--verbose", action="store_true")
    a = ap.parse_args(argv)
    # ISCC resolves relative paths against the .iss file's directory, so
    # every path handed to external tools is made absolute.
    a.out = a.out.resolve()
    a.browser_dir = a.browser_dir.resolve()
    if a.cef_root:
        a.cef_root = a.cef_root.resolve()
    logging.basicConfig(level=logging.DEBUG if a.verbose else logging.INFO, format="%(levelname)s %(message)s")

    a.out.mkdir(parents=True, exist_ok=True)
    name = f"WezCryptAegis-{a.version}-win-x64"
    staged = a.out / name
    stage(a.browser_dir, staged)
    if a.cef_root:
        for src, dst in (("LICENSE.txt", "CEF-LICENSE.txt"), ("CREDITS.html", "CHROMIUM-CREDITS.html")):
            if (a.cef_root / src).exists():
                shutil.copy2(a.cef_root / src, staged / "LICENSES" / dst)
            else:
                LOG.warning("%s not found in CEF distribution", src)
    exe = staged / "WezCryptAegis.exe"

    if a.rcedit and a.rcedit.exists():
        run_optional([a.rcedit, exe, "--set-icon", ROOT / "assets/branding/aegis.ico",
                      "--set-version-string", "ProductName", "WezCrypt Aegis",
                      "--set-version-string", "FileDescription", "WezCrypt Aegis",
                      "--set-version-string", "CompanyName", "WezCrypt",
                      "--set-version-string", "OriginalFilename", "WezCryptAegis.exe",
                      "--set-file-version", a.version, "--set-product-version", a.version], "rcedit")
    else:
        LOG.warning("rcedit not available: WezCryptAegis.exe keeps the CEF bootstrap icon/version resources")

    thumb = os.environ.get("AEGIS_SIGN_THUMBPRINT")
    ts = os.environ.get("AEGIS_SIGN_TIMESTAMP_URL")
    signed = False
    if thumb and ts and shutil.which("signtool"):
        run_optional(["signtool", "sign", "/sha1", thumb, "/fd", "sha256", "/tr", ts, "/td", "sha256",
                      exe, staged / "WezCryptAegis.dll"], "signtool")
        signed = True
    else:
        LOG.warning("Code signing not configured: binaries are UNSIGNED (see docs/RELEASE_PROCESS.md)")

    artifacts = []
    zip_path = a.out / f"{name}-portable.zip"
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        for f in sorted(staged.rglob("*")):
            if f.is_file():
                z.write(f, Path(name) / f.relative_to(staged))
        z.writestr(f"{name}/portable.flag", "portable\n")
    artifacts.append(zip_path)

    iscc = a.iscc if a.iscc and a.iscc.exists() else (Path(shutil.which("iscc")) if shutil.which("iscc") else None)
    if iscc:
        run_optional([iscc, f"/DSourceDir={staged}", f"/DAppVersion={a.version}", f"/O{a.out}",
                      f"/F{name}-setup", ROOT / "packaging/windows/installer.iss"], "iscc")
        setup = a.out / f"{name}-setup.exe"
        if thumb and ts and shutil.which("signtool"):
            run_optional(["signtool", "sign", "/sha1", thumb, "/fd", "sha256", "/tr", ts, "/td", "sha256", setup],
                         "signtool")
        artifacts.append(setup)
    else:
        LOG.warning("Inno Setup (ISCC) not found: installer not built")

    sbom = a.out / f"WezCryptAegis-{a.version}.cdx.json"
    subprocess.run([sys.executable, str(ROOT / "scripts/generate_sbom.py"), "--stage", str(staged),
                    "--version", a.version, "--out", str(sbom)], check=True)
    artifacts.append(sbom)

    sums = a.out / "SHA256SUMS.txt"
    lines = [f"{sha256(p)}  {p.name}" for p in artifacts]
    lines += [f"{sha256(staged / f)}  {name}/{f}" for f in ("WezCryptAegis.exe", "WezCryptAegis.dll", "libcef.dll")]
    sums.write_text("\n".join(lines) + "\n", encoding="utf-8")
    (a.out / "package-info.json").write_text(json.dumps(
        {"version": a.version, "signed": signed, "artifacts": [p.name for p in artifacts]}, indent=2))
    LOG.info("artifacts: %s", ", ".join(p.name for p in artifacts))
    return 0


if __name__ == "__main__":
    sys.exit(main())

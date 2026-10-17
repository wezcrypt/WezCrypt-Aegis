#!/usr/bin/env python3
"""Verify security properties of the built Windows binaries.

Checks (PE headers, no execution):
  * WezCryptAegis.exe is CEF's bootstrap executable (sandbox host) and
    WezCryptAegis.dll exports RunWinMain
  * ASLR (DYNAMIC_BASE + HIGH_ENTROPY_VA), DEP (NX_COMPAT) and Control Flow
    Guard (GUARD_CF) are enabled on WezCryptAegis.dll and the executable
  * CET shadow-stack compatibility is reported when present
  * no unsandboxed helper executables are shipped (no browser_subprocess)
  * required runtime files are present
Writes a JSON report.
"""
import argparse
import hashlib
import json
import logging
import sys
from pathlib import Path

try:
    import pefile
except ImportError:  # pragma: no cover
    sys.exit("pefile is required: pip install pefile")

LOG = logging.getLogger("verify_build")
DYNAMIC_BASE = 0x0040
HIGH_ENTROPY_VA = 0x0020
NX_COMPAT = 0x0100
GUARD_CF = 0x4000
CET_COMPAT = 0x0001  # IMAGE_DLLCHARACTERISTICS_EX_CET_COMPAT


def sha256(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def pe_flags(path: Path) -> dict:
    pe = pefile.PE(str(path), fast_load=True)
    pe.parse_data_directories(directories=[
        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"],
        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_DEBUG"]])
    ch = pe.OPTIONAL_HEADER.DllCharacteristics
    cet = False
    for d in getattr(pe, "DIRECTORY_ENTRY_DEBUG", []):
        if d.struct.Type == 20:  # IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS
            data = pe.get_data(d.struct.AddressOfRawData, 4)
            cet = bool(int.from_bytes(data, "little") & CET_COMPAT)
    exports = []
    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        exports = [e.name.decode() for e in pe.DIRECTORY_ENTRY_EXPORT.symbols if e.name]
    return {"aslr": bool(ch & DYNAMIC_BASE), "high_entropy_va": bool(ch & HIGH_ENTROPY_VA),
            "dep": bool(ch & NX_COMPAT), "cfg": bool(ch & GUARD_CF), "cet_compat": cet,
            "exports": exports}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--browser-dir", type=Path, required=True)
    ap.add_argument("--cef-root", type=Path, required=True)
    ap.add_argument("--report", type=Path, default=Path("build-verification.json"))
    a = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    failures = []
    exe = a.browser_dir / "WezCryptAegis.exe"
    dll = a.browser_dir / "WezCryptAegis.dll"
    bootstrap = a.cef_root / "Release" / "bootstrap.exe"
    report = {"files": {}}
    for f in (exe, dll, bootstrap):
        if not f.exists():
            failures.append(f"missing {f}")
    if failures:
        LOG.error("; ".join(failures))
        return 1
    report["exe_is_cef_bootstrap"] = sha256(exe) == sha256(bootstrap)
    if not report["exe_is_cef_bootstrap"]:
        failures.append("WezCryptAegis.exe is not the CEF bootstrap executable")
    for f in (exe, dll):
        flags = pe_flags(f)
        report["files"][f.name] = flags
        for key in ("aslr", "high_entropy_va", "dep", "cfg"):
            if not flags[key]:
                failures.append(f"{f.name}: {key} not enabled")
    if "RunWinMain" not in report["files"][dll.name]["exports"]:
        failures.append("WezCryptAegis.dll does not export RunWinMain")
    for required in ("libcef.dll", "icudtl.dat", "resources.pak", "v8_context_snapshot.bin", "chrome_elf.dll",
                     "assets/data/public_suffix_list.dat", "assets/filters/easylist.txt"):
        if not (a.browser_dir / required).exists():
            failures.append(f"missing runtime file {required}")
    extra_exes = [p.name for p in a.browser_dir.glob("*.exe")
                  if p.name not in ("WezCryptAegis.exe", "bootstrap.exe", "bootstrapc.exe")]
    report["other_executables"] = extra_exes
    if extra_exes:
        failures.append(f"unexpected executables: {extra_exes}")
    report["failures"] = failures
    a.report.write_text(json.dumps(report, indent=2))
    for k, v in report["files"].items():
        LOG.info("%s: %s", k, {x: y for x, y in v.items() if x != "exports"})
    if failures:
        for f in failures:
            LOG.error(f)
        return 1
    LOG.info("build verification passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())

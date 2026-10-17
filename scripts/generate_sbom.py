#!/usr/bin/env python3
"""Generate a CycloneDX 1.5 SBOM for a staged WezCrypt Aegis package."""
import argparse
import datetime
import hashlib
import json
import logging
import re
import sys
import uuid
from pathlib import Path

LOG = logging.getLogger("sbom")
ROOT = Path(__file__).resolve().parent.parent


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def list_version(path: Path) -> str:
    if not path.exists():
        return "unknown"
    head = path.read_text(encoding="utf-8", errors="replace")[:4000]
    m = re.search(r"^! Version:\s*(\S+)", head, re.M)
    return m.group(1) if m else "unknown"


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--stage", type=Path, required=True)
    ap.add_argument("--version", required=True)
    ap.add_argument("--out", type=Path, required=True)
    a = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    cef = json.loads((ROOT / "third_party" / "cef.json").read_text(encoding="utf-8"))
    cef_version = cef["cef_version"]
    chromium = cef_version.split("chromium-")[-1] if "chromium-" in cef_version else "unknown"
    filters = a.stage / "assets" / "filters"
    components = [
        {"type": "framework", "bom-ref": "cef", "name": "Chromium Embedded Framework", "version": cef_version,
         "licenses": [{"license": {"id": "BSD-3-Clause"}}],
         "externalReferences": [{"type": "website", "url": "https://github.com/chromiumembedded/cef"}]},
        {"type": "framework", "bom-ref": "chromium", "name": "Chromium", "version": chromium,
         "licenses": [{"license": {"id": "BSD-3-Clause"}}],
         "externalReferences": [{"type": "website", "url": "https://www.chromium.org/"}]},
        {"type": "library", "bom-ref": "monocypher", "name": "Monocypher", "version": "4.0.2",
         "licenses": [{"expression": "BSD-2-Clause OR CC0-1.0"}],
         "hashes": [{"alg": "SHA-256", "content": sha256(ROOT / "third_party/monocypher/monocypher.c")}]},
        {"type": "data", "bom-ref": "psl", "name": "Public Suffix List",
         "licenses": [{"license": {"id": "MPL-2.0"}}],
         "hashes": [{"alg": "SHA-256", "content": sha256(a.stage / "assets/data/public_suffix_list.dat")}]},
    ]
    for lid, lname in (("easylist", "EasyList"), ("easyprivacy", "EasyPrivacy")):
        p = filters / f"{lid}.txt"
        components.append({"type": "data", "bom-ref": lid, "name": lname, "version": list_version(p),
                           "licenses": [{"expression": "GPL-3.0-or-later OR CC-BY-SA-3.0"}],
                           "hashes": [{"alg": "SHA-256", "content": sha256(p)}]})
    for f in sorted(a.stage.rglob("*")):
        if f.is_file():
            rel = f.relative_to(a.stage).as_posix()
            components.append({"type": "file", "name": rel, "hashes": [{"alg": "SHA-256", "content": sha256(f)}]})
    bom = {
        "bomFormat": "CycloneDX", "specVersion": "1.5", "serialNumber": f"urn:uuid:{uuid.uuid4()}", "version": 1,
        "metadata": {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "component": {"type": "application", "bom-ref": "wezcrypt-aegis", "name": "WezCrypt Aegis",
                          "version": a.version, "publisher": "WezCrypt",
                          "licenses": [{"license": {"id": "MIT"}}]},
        },
        "components": components,
        "dependencies": [{"ref": "wezcrypt-aegis", "dependsOn": ["cef", "monocypher", "psl", "easylist", "easyprivacy"]},
                         {"ref": "cef", "dependsOn": ["chromium"]}],
    }
    a.out.write_text(json.dumps(bom, indent=2), encoding="utf-8")
    LOG.info("SBOM with %d components written to %s", len(components), a.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())

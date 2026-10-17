#!/usr/bin/env python3
"""Download and verify the pinned CEF binary distribution.

Reads third_party/cef.json, looks the version up in the official CEF
automated-build index (https://cef-builds.spotifycdn.com/index.json),
downloads the archive over HTTPS, verifies the SHA-1 published in the index
and, when pinned in cef.json, the SHA-256, and extracts it safely.

Usage:
  python scripts/fetch_cef.py --out third_party/cef
  python scripts/fetch_cef.py --list            # show available stable versions
"""
import argparse
import hashlib
import json
import logging
import shutil
import sys
import tarfile
import tempfile
import urllib.request
from pathlib import Path

LOG = logging.getLogger("fetch_cef")
INDEX_URL = "https://cef-builds.spotifycdn.com/index.json"
BASE_URL = "https://cef-builds.spotifycdn.com/"
ROOT = Path(__file__).resolve().parent.parent
MAX_ARCHIVE_BYTES = 2 * 1024 ** 3


def fetch(url: str, dest: Path | None = None, max_bytes: int = MAX_ARCHIVE_BYTES) -> bytes | None:
    if not url.startswith("https://"):
        raise ValueError(f"refusing non-HTTPS URL: {url}")
    req = urllib.request.Request(url, headers={"User-Agent": "wezcrypt-aegis-build"})
    with urllib.request.urlopen(req, timeout=120) as resp:
        if dest is None:
            data = resp.read(max_bytes + 1)
            if len(data) > max_bytes:
                raise ValueError("response too large")
            return data
        total = 0
        with dest.open("wb") as out:
            while True:
                chunk = resp.read(1 << 20)
                if not chunk:
                    break
                total += len(chunk)
                if total > max_bytes:
                    raise ValueError("download exceeds size limit")
                out.write(chunk)
        LOG.info("downloaded %.1f MiB", total / (1 << 20))
    return None


def file_digest(path: Path, algo: str) -> str:
    h = hashlib.new(algo)
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def safe_extract(archive: Path, dest: Path) -> Path:
    dest.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive, "r:bz2") as tar:
        members = tar.getmembers()
        roots = {m.name.split("/", 1)[0] for m in members}
        if len(roots) != 1:
            raise ValueError(f"unexpected archive layout: {sorted(roots)[:5]}")
        dest_resolved = dest.resolve()
        for m in members:
            target = (dest / m.name).resolve()
            if dest_resolved not in target.parents and target != dest_resolved:
                raise ValueError(f"path traversal in archive member: {m.name}")
            if m.issym() or m.islnk():
                raise ValueError(f"links are not allowed in the archive: {m.name}")
        if sys.version_info >= (3, 12):
            tar.extractall(dest, filter="data")
        else:
            tar.extractall(dest)  # members validated above
    return dest / roots.pop()


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--config", type=Path, default=ROOT / "third_party" / "cef.json")
    p.add_argument("--out", type=Path, default=ROOT / "third_party" / "cef")
    p.add_argument("--list", action="store_true", help="list stable versions and exit")
    p.add_argument("--github-output", type=Path, help="append cef_root=<path> to this file")
    p.add_argument("-v", "--verbose", action="store_true")
    args = p.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO, format="%(levelname)s %(message)s")

    cfg = json.loads(args.config.read_text(encoding="utf-8"))
    platform = cfg.get("platform", "windows64")
    dist = cfg.get("distribution", "minimal")
    index = json.loads(fetch(INDEX_URL, max_bytes=64 * 1024 * 1024))
    versions = index[platform]["versions"]

    if args.list:
        for v in versions[:15]:
            print(f"{v['channel']:8} {v['cef_version']}  (chromium {v['chromium_version']})")
        return 0

    wanted = cfg["cef_version"]
    entry = next((v for v in versions if v["cef_version"] == wanted), None)
    if entry is None:
        LOG.error("CEF %s is not in the official index. Newest stable builds:", wanted)
        for v in [v for v in versions if v["channel"] == "stable"][:5]:
            LOG.error("  %s", v["cef_version"])
        return 2
    newest_stable = next((v for v in versions if v["channel"] == "stable"), None)
    if newest_stable and newest_stable["cef_version"] != wanted:
        LOG.warning("A newer stable CEF is available: %s (pinned %s). Update third_party/cef.json "
                    "to ship current Chromium security fixes.", newest_stable["cef_version"], wanted)

    file = next((f for f in entry["files"] if f["type"] == dist), None)
    if file is None:
        LOG.error("no '%s' distribution for %s", dist, wanted)
        return 2

    final_dir = args.out / file["name"].removesuffix(".tar.bz2")
    if (final_dir / "cmake" / "FindCEF.cmake").exists():
        LOG.info("already present: %s", final_dir)
    else:
        with tempfile.TemporaryDirectory() as tmp:
            archive = Path(tmp) / file["name"]
            LOG.info("downloading %s", file["name"])
            fetch(BASE_URL + urllib.request.quote(file["name"]), archive)
            sha1 = file_digest(archive, "sha1")
            if sha1 != file["sha1"]:
                LOG.error("SHA-1 mismatch: index %s, got %s", file["sha1"], sha1)
                return 3
            sha256 = file_digest(archive, "sha256")
            pinned = cfg.get("sha256", "")
            if pinned and pinned.lower() != sha256:
                LOG.error("SHA-256 mismatch: pinned %s, got %s", pinned, sha256)
                return 3
            if not pinned:
                LOG.warning("No SHA-256 pinned in %s. Archive SHA-256: %s", args.config, sha256)
            LOG.info("verified sha1=%s sha256=%s", sha1, sha256)
            if final_dir.exists():
                shutil.rmtree(final_dir)
            extracted = safe_extract(archive, args.out)
            if extracted != final_dir:
                extracted.rename(final_dir)

    if not (final_dir / "Release" / "bootstrap.exe").exists() and platform.startswith("windows"):
        LOG.error("bootstrap.exe missing from the distribution; CEF M138+ is required")
        return 4
    print(final_dir)
    if args.github_output:
        with args.github_output.open("a", encoding="utf-8") as f:
            f.write(f"cef_root={final_dir.as_posix()}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())

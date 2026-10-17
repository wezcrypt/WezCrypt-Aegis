#!/usr/bin/env python3
"""Release signing round trip: Python signer -> C++ verifier (aegis_tool).

Verifies that manifests produced by scripts/sign_manifest.py are accepted by
the exact verification code compiled into the browser, and that tampering,
wrong keys, rollback and artifact substitution are rejected.
"""
import argparse
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SIGN = [sys.executable, str(ROOT / "scripts" / "sign_manifest.py")]


def run(cmd, expect_ok=True):
    r = subprocess.run([str(c) for c in cmd], capture_output=True, text=True)
    ok = r.returncode == 0
    if ok != expect_ok:
        print(r.stdout, r.stderr)
        raise SystemExit(f"unexpected result ({'ok' if ok else 'fail'}): {' '.join(map(str, cmd))}")
    return r.stdout.strip()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("aegis_tool", type=Path)
    a = ap.parse_args()
    tool = a.aegis_tool
    with tempfile.TemporaryDirectory() as t:
        t = Path(t)
        run(SIGN + ["keygen", "--private", t / "key.pem", "--public-out", t / "pub.txt"])
        run(SIGN + ["keygen", "--private", t / "other.pem", "--public-out", t / "other.txt"])
        artifact = t / "WezCryptAegis-1.1.0-win-x64-setup.exe"
        artifact.write_bytes(b"synthetic installer payload\n" * 100)
        run(SIGN + ["create", "--version", "1.1.0", "--sequence", "7", "--chromium", "154.0.8037.98",
                    "--min-chromium", "154.0.8037.98",
                    "--artifact", f"{artifact.name}=https://downloads.example/{artifact.name}={artifact}",
                    "--out", t / "manifest.json"])
        run(SIGN + ["sign", "--private", t / "key.pem", "--manifest", t / "manifest.json"])
        run(SIGN + ["verify", "--public", t / "pub.txt", "--manifest", t / "manifest.json"])
        m, s = t / "manifest.json", t / "manifest.json.sig"
        print(run([tool, "verify-manifest", m, s, t / "pub.txt"]))
        print(run([tool, "verify-artifact", m, s, t / "pub.txt", artifact]))
        # Wrong key.
        run([tool, "verify-manifest", m, s, t / "other.txt"], expect_ok=False)
        # Rollback: last accepted sequence 7 rejects sequence 7.
        run([tool, "verify-manifest", m, s, t / "pub.txt", "--last-sequence", "7"], expect_ok=False)
        # Tampered manifest.
        tampered = t / "tampered.json"
        tampered.write_text(m.read_text().replace("1.1.0", "9.9.9"))
        (t / "tampered.json.sig").write_text(s.read_text())
        run([tool, "verify-manifest", tampered, t / "tampered.json.sig", t / "pub.txt"], expect_ok=False)
        # Substituted artifact with the same name.
        artifact.write_bytes(b"malicious replacement\n")
        run([tool, "verify-artifact", m, s, t / "pub.txt", artifact], expect_ok=False)
    print("signing round trip: all checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())

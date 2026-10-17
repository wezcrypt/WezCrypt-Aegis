#!/usr/bin/env python3
"""Create and sign WezCrypt Aegis release manifests (Ed25519).

Commands:
  keygen   --private key.pem --public-out pubkey.txt
  create   --version 1.0.0 --sequence N --chromium 154.0.8037.98
           --min-chromium 154.0.8037.98 --artifact NAME=URL=FILE [...]
           --out manifest.json [--valid-days 30]
  sign     --private key.pem --manifest manifest.json   (writes manifest.json.sig)
  verify   --public pubkey.txt --manifest manifest.json

The private key must be kept offline / in an HSM-backed signing service. The
public key (base64, 32 bytes) is compiled into the browser with
-DAEGIS_UPDATE_PUBLIC_KEYS=<base64>.
"""
import argparse
import base64
import hashlib
import json
import logging
import sys
import time
from pathlib import Path

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature
except ImportError:  # pragma: no cover
    sys.exit("The 'cryptography' package is required: pip install cryptography")

LOG = logging.getLogger("sign_manifest")


def load_private(path: Path) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise SystemExit("not an Ed25519 private key")
    return key


def load_public(path: Path) -> Ed25519PublicKey:
    raw = base64.b64decode(path.read_text().strip(), validate=True)
    if len(raw) != 32:
        raise SystemExit("public key must be 32 bytes (base64)")
    return Ed25519PublicKey.from_public_bytes(raw)


def cmd_keygen(a):
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption())
    if a.private.exists():
        raise SystemExit(f"refusing to overwrite {a.private}")
    a.private.write_bytes(pem)
    a.private.chmod(0o600)
    pub = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    a.public_out.write_text(base64.b64encode(pub).decode() + "\n")
    LOG.info("wrote %s and %s", a.private, a.public_out)


def cmd_create(a):
    artifacts = []
    for spec in a.artifact:
        try:
            name, url, file = spec.split("=", 2)
        except ValueError:
            raise SystemExit(f"--artifact expects NAME=URL=FILE, got {spec}")
        if not url.startswith("https://"):
            raise SystemExit("artifact URLs must use https://")
        data = Path(file).read_bytes()
        artifacts.append({"name": name, "url": url, "size": len(data),
                          "sha512": hashlib.sha512(data).hexdigest()})
    now = int(time.time())
    manifest = {
        "product": "wezcrypt-aegis",
        "channel": a.channel,
        "sequence": a.sequence,
        "version": a.version,
        "chromium_version": a.chromium,
        "minimum_safe_chromium_version": a.min_chromium,
        "issued_unix": now,
        "expires_unix": now + a.valid_days * 86400,
        "artifacts": artifacts,
        "security_notes": a.notes,
    }
    a.out.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    LOG.info("wrote %s", a.out)


def cmd_sign(a):
    key = load_private(a.private)
    data = a.manifest.read_bytes()
    sig = key.sign(data)
    out = Path(str(a.manifest) + ".sig")
    out.write_text(base64.b64encode(sig).decode() + "\n")
    LOG.info("wrote %s", out)


def cmd_verify(a):
    pub = load_public(a.public)
    data = a.manifest.read_bytes()
    sig = base64.b64decode(Path(str(a.manifest) + ".sig").read_text().strip(), validate=True)
    try:
        pub.verify(sig, data)
    except InvalidSignature:
        LOG.error("signature INVALID")
        return 1
    LOG.info("signature valid")
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("-v", "--verbose", action="store_true")
    sub = p.add_subparsers(dest="cmd", required=True)
    k = sub.add_parser("keygen")
    k.add_argument("--private", type=Path, required=True)
    k.add_argument("--public-out", type=Path, required=True)
    c = sub.add_parser("create")
    c.add_argument("--version", required=True)
    c.add_argument("--sequence", type=int, required=True)
    c.add_argument("--chromium", required=True)
    c.add_argument("--min-chromium", required=True)
    c.add_argument("--channel", default="stable")
    c.add_argument("--valid-days", type=int, default=30)
    c.add_argument("--notes", default="")
    c.add_argument("--artifact", action="append", default=[])
    c.add_argument("--out", type=Path, required=True)
    s = sub.add_parser("sign")
    s.add_argument("--private", type=Path, required=True)
    s.add_argument("--manifest", type=Path, required=True)
    v = sub.add_parser("verify")
    v.add_argument("--public", type=Path, required=True)
    v.add_argument("--manifest", type=Path, required=True)
    a = p.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if a.verbose else logging.INFO, format="%(levelname)s %(message)s")
    if a.sequence if a.cmd == "create" else False:
        if a.sequence <= 0:
            raise SystemExit("--sequence must be positive")
    return {"keygen": cmd_keygen, "create": cmd_create, "sign": cmd_sign, "verify": cmd_verify}[a.cmd](a) or 0


if __name__ == "__main__":
    sys.exit(main())

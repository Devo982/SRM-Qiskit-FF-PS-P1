#!/usr/bin/env python3
"""Provision local identities and the pinned trust store (design v2 section 1).

Generates fresh signing keypairs for client:alice and server:bob for BOTH
suites, writes private key files into identities/ (git-ignored - nothing
secret is ever committed) and a matching test-only public trust store at identities/trust_store.test.json. The committed root trust_store.json is never modified by local test provisioning.

    python scripts/provision_identities.py [--force]

The generated test trust store maps identity -> {role, verification keys per suite}.
Verification keys NEVER travel on the wire; verifiers look up pinned keys.
This tool prints metadata only - private key bytes are never displayed.
"""
from __future__ import annotations

import argparse
import base64
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from cryptography.hazmat.primitives.asymmetric import ed25519, mldsa  # noqa: E402

IDENTITIES = [
    ("alice", "client:alice", "client"),
    ("bob", "server:bob", "server"),
]


def b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--force", action="store_true", help="overwrite existing identity files")
    parser.add_argument(
        "--identities-dir", default=str(REPO_ROOT / "identities"),
        help="output directory for private identity files (default: identities/)",
    )
    parser.add_argument(
        "--trust-store", default=None,
        help="output path for the public trust store "
             "(default: <identities-dir>/trust_store.test.json)",
    )
    args = parser.parse_args()

    idir = Path(args.identities_dir)
    idir.mkdir(parents=True, exist_ok=True)

    trust: dict = {"version": 1, "identities": {}}

    for name, identity, role in IDENTITIES:
        path = idir / f"{name}.json"
        if path.exists() and not args.force:
            print(f"  keep existing {path} (use --force to regenerate)")
            data = json.loads(path.read_text(encoding="utf-8"))
        else:
            m = mldsa.MLDSA65PrivateKey.generate()
            e = ed25519.Ed25519PrivateKey.generate()
            data = {
                "identity": identity,
                "role": role,
                "mldsa65_private_b64": b64(m.private_bytes_raw()),
                "mldsa65_public_b64": b64(m.public_key().public_bytes_raw()),
                "ed25519_private_b64": b64(e.private_bytes_raw()),
                "ed25519_public_b64": b64(e.public_key().public_bytes_raw()),
            }
            path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
            print(f"  wrote {path} (private - git-ignored)")
        trust["identities"][identity] = {
            "role": data["role"],
            "keys": {
                "QFF26-PQC-1": data["mldsa65_public_b64"],
                "QFF26-CLASSICAL-1": data["ed25519_public_b64"],
            },
        }

    tpath = (
        Path(args.trust_store)
        if args.trust_store
        else idir / "trust_store.test.json"
    )
    tpath.parent.mkdir(parents=True, exist_ok=True)
    tpath.write_text(json.dumps(trust, indent=2) + "\n", encoding="utf-8")
    print(f"  wrote {tpath} (local test trust store - git-ignored)")
    print("provisioning complete: 2 identities, 2 suites each; no secrets printed or committed")


if __name__ == "__main__":
    main()


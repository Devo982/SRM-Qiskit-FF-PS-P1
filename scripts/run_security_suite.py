#!/usr/bin/env python3
"""Self-heal local test identities/test trust store, then run the PS-P1 T1-T9 suite.

Use from the repository root:
    python scripts/run_security_suite.py

This is for disposable/local test identities only, not production trust stores.
"""
from __future__ import annotations

import base64
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
IDENTITY_SPECS = (
    ("alice", "client:alice", "client"),
    ("bob", "server:bob", "server"),
)


def _b64decode(value: Any) -> bytes:
    if not isinstance(value, str) or not value:
        raise ValueError("missing or non-string base64 field")
    return base64.b64decode(value, validate=True)


def inspect_identities() -> tuple[list[str], list[str], dict[str, dict[str, Any]]]:
    """Return missing filenames, invalid existing files, and valid identity data."""
    missing: list[str] = []
    invalid: list[str] = []
    loaded: dict[str, dict[str, Any]] = {}

    try:
        from cryptography.hazmat.primitives.asymmetric import ed25519, mldsa
    except Exception as exc:  # dependency/backend errors should stop before tests
        return [], [f"cryptography cannot load required primitives ({type(exc).__name__})"], {}

    identity_dir = ROOT / "identities"
    for filename, expected_identity, expected_role in IDENTITY_SPECS:
        path = identity_dir / f"{filename}.json"
        if not path.is_file() or path.stat().st_size == 0:
            missing.append(path.name)
            continue

        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                raise ValueError("identity JSON must be an object")
            if data.get("identity") != expected_identity or data.get("role") != expected_role:
                raise ValueError("identity name/role mismatch")

            mldsa_seed = _b64decode(data.get("mldsa65_private_b64"))
            mldsa_public = _b64decode(data.get("mldsa65_public_b64"))
            ed_private = _b64decode(data.get("ed25519_private_b64"))
            ed_public = _b64decode(data.get("ed25519_public_b64"))

            derived_mldsa_public = (
                mldsa.MLDSA65PrivateKey.from_seed_bytes(mldsa_seed)
                .public_key().public_bytes_raw()
            )
            derived_ed_public = (
                ed25519.Ed25519PrivateKey.from_private_bytes(ed_private)
                .public_key().public_bytes_raw()
            )
            if derived_mldsa_public != mldsa_public:
                raise ValueError("ML-DSA private/public keys do not match")
            if derived_ed_public != ed_public:
                raise ValueError("Ed25519 private/public keys do not match")

            loaded[expected_identity] = data
        except Exception as exc:
            # Deliberately report only the filename and error type, never key material.
            invalid.append(f"{path.name} ({type(exc).__name__})")

    return missing, invalid, loaded


def inspect_trust_store(identities: dict[str, dict[str, Any]]) -> list[str]:
    """Check whether the public trust store exactly matches valid local identities."""
    path = ROOT / "identities" / "trust_store.test.json"
    if not path.is_file() or path.stat().st_size == 0:
        return ["identities/trust_store.test.json is missing or empty"]
    try:
        trust = json.loads(path.read_text(encoding="utf-8"))
        entries = trust.get("identities") if isinstance(trust, dict) else None
        expected_names = {spec[1] for spec in IDENTITY_SPECS}
        if trust.get("version") != 1 or not isinstance(entries, dict):
            return ["identities/trust_store.test.json has an invalid structure/version"]
        if set(entries) != expected_names:
            return ["identities/trust_store.test.json identity set differs from local test identities"]

        for filename, identity, role in IDENTITY_SPECS:
            data = identities[identity]
            entry = entries.get(identity)
            if not isinstance(entry, dict) or entry.get("role") != role:
                return [f"identities/trust_store.test.json role mismatch for {identity}"]
            keys = entry.get("keys")
            if not isinstance(keys, dict):
                return [f"identities/trust_store.test.json keys missing for {identity}"]
            if keys.get("QFF26-PQC-1") != data.get("mldsa65_public_b64"):
                return [f"identities/trust_store.test.json ML-DSA key mismatch for {identity}"]
            if keys.get("QFF26-CLASSICAL-1") != data.get("ed25519_public_b64"):
                return [f"identities/trust_store.test.json Ed25519 key mismatch for {identity}"]
    except Exception as exc:
        return [f"identities/trust_store.test.json cannot be validated ({type(exc).__name__})"]
    return []


def provision(force: bool) -> None:
    command = [
        sys.executable,
        str(ROOT / "scripts" / "provision_identities.py"),
        "--identities-dir", str(ROOT / "identities"),
        "--trust-store", str(ROOT / "identities" / "trust_store.test.json"),
    ]
    if force:
        command.append("--force")
        print(
            "[setup] Existing local identity data is invalid/inconsistent; "
            "regenerating local Alice/Bob test keys and their trust store.",
            flush=True,
        )
    else:
        print(
            "[setup] Provisioning missing test identities or rebuilding the "
            "trust store from valid local identities.",
            flush=True,
        )
    result = subprocess.run(command, cwd=ROOT, check=False)
    if result.returncode != 0:
        print("FAIL: local test identity provisioning failed.", flush=True)
        raise SystemExit(result.returncode)


def main() -> int:
    missing, invalid, identities = inspect_identities()
    should_provision = bool(missing or invalid)

    if invalid:
        provision(force=True)
    elif missing:
        provision(force=False)
    else:
        trust_issues = inspect_trust_store(identities)
        if trust_issues:
            print("[setup] Local identities are valid, but the trust store is stale.", flush=True)
            provision(force=False)
        else:
            print(
                "[setup] Alice/Bob key pairs and trust store are consistent; "
                "skipping provisioning.",
                flush=True,
            )

    missing, invalid, identities = inspect_identities()
    trust_issues = inspect_trust_store(identities) if not missing and not invalid else []
    if missing or invalid or trust_issues:
        if missing:
            print(f"FAIL: identity files still missing: {', '.join(missing)}", flush=True)
        if invalid:
            print(f"FAIL: identity files still invalid: {', '.join(invalid)}", flush=True)
        for issue in trust_issues:
            print(f"FAIL: {issue}", flush=True)
        return 2

    print("[setup] Local test identity material is consistent.", flush=True)
    print("[setup] Keep identities/trust_store.test.json local; it is git-ignored.", flush=True)
    print("\nRunning mandatory security tests T1-T9...\n", flush=True)
    result = subprocess.run(
        [sys.executable, "-m", "tests.run_security_tests"],
        cwd=ROOT,
        check=False,
    )
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())

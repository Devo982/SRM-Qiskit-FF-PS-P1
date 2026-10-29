#!/usr/bin/env python3
"""QFF 2026 PS-P1 - Phase 2 environment check (kit contract).

Usage:  python common/env_check.py
OK:     prints "READY - environment is correct." and writes
        platform_A_info.json at the repository root. Exit 0.
Fail:   prints "FAIL - <reason>" (+ hint). Exit 1.
"""
from __future__ import annotations

import json
import platform
import sys
from datetime import datetime, timezone
from importlib.metadata import version as _dist_version
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
REQUIRED_CRYPTOGRAPHY = "50.0.2"
SUPPORTED_PYTHON = {(3, 10), (3, 11), (3, 12), (3, 13)}
REQUIRED_ANALYSIS = ("psutil", "numpy", "pandas", "matplotlib")


def fail(msg: str, hint: str | None = None) -> None:
    print(f"FAIL - {msg}")
    if hint:
        print(hint)
    sys.exit(1)


def main() -> None:
    # 1) Python version (kit: 3.10-3.13, recommends 3.13)
    v = sys.version_info
    if (v.major, v.minor) not in SUPPORTED_PYTHON:
        fail(f"Python {v.major}.{v.minor} not supported (need 3.10-3.13; kit recommends 3.13)")

    # 2) cryptography, exact kit pin
    try:
        import cryptography
    except Exception as exc:  # noqa: BLE001
        hint = None
        if platform.system() == "Darwin" and platform.machine() == "x86_64":
            hint = ("Hint (Intel macOS): cryptography 50.0.2 ships no macOS x86_64 wheel. "
                    "Build from sdist: source ~/.qff26-openssl-env.sh && "
                    "uv pip install -r requirements.txt (see README platform notes).")
        fail(f"cryptography not importable: {exc}", hint)
    if cryptography.__version__ != REQUIRED_CRYPTOGRAPHY:
        fail(f"cryptography {cryptography.__version__} found; the kit pins {REQUIRED_CRYPTOGRAPHY}")

    # 3) Required primitive smoke test
    verified: list[str] = []
    try:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ed25519, mlkem, mldsa, x25519
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF

        k = mlkem.MLKEM768PrivateKey.generate()
        ss, ct = k.public_key().encapsulate()
        assert k.decapsulate(ct) == ss
        verified.append("ML-KEM-768")

        s = mldsa.MLDSA65PrivateKey.generate()
        sig = s.sign(b"env-check")
        s.public_key().verify(sig, b"env-check")
        verified.append("ML-DSA-65")

        x = x25519.X25519PrivateKey.generate()
        assert len(x.exchange(x.public_key())) == 32
        verified.append("X25519")

        e = ed25519.Ed25519PrivateKey.generate()
        e.public_key().verify(e.sign(b"env-check"), b"env-check")
        verified.append("Ed25519")

        key = HKDF(algorithm=hashes.SHA256(), length=32, salt=b"qff26", info=b"env-check").derive(ss)
        verified.append("HKDF-SHA256")

        aes = AESGCM(key)
        blob = aes.encrypt(b"\x00" * 12, b"env-check", b"aad")
        assert aes.decrypt(b"\x00" * 12, blob, b"aad") == b"env-check"
        verified.append("AES-256-GCM")
    except Exception as exc:  # noqa: BLE001
        fail(f"required primitive smoke test failed: {exc}")

    # 4) pqcrypto (optional per kit FAQ - report only, never fails)
    pq_ver: str | None = None
    try:
        import pqcrypto  # noqa: F401
        pq_ver = _dist_version("pqcrypto")
    except Exception:  # noqa: BLE001
        pass

    # 5) Analysis stack (required; delivered via requirements.txt)
    missing = [m for m in REQUIRED_ANALYSIS if not _importable(m)]
    if missing:
        fail(f"missing analysis dependencies: {', '.join(missing)} (install via requirements.txt)")

    # 6) Honest platform provenance for platform_A_info.json
    openssl_txt = None
    try:
        from cryptography.hazmat.backends.openssl import backend
        openssl_txt = backend.openssl_version_text()
    except Exception:  # noqa: BLE001
        openssl_txt = "OpenSSL (version string unavailable via backend)"
    is_intel_mac = platform.system() == "Darwin" and platform.machine() == "x86_64"
    origin = ("sdist source build (no official macOS x86_64 wheel for cryptography 50.0.2); "
              "statically linked local OpenSSL - see README platform notes"
              if is_intel_mac else "prebuilt wheel")

    info = {
        "generated_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "kit": "Qiskit Fall Fest 2026 - PS-P1 Quantum-Safe Secure Communication Channel",
        "phase": 2,
        "python": {
            "version": platform.python_version(),
            "implementation": platform.python_implementation(),
            "executable": sys.executable,
        },
        "platform": {
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
            "description": platform.platform(),
        },
        "crypto": {
            "cryptography_version": cryptography.__version__,
            "openssl_runtime": openssl_txt,
            "install_origin": origin,
            "pqcrypto_version": pq_ver,
            "pqcrypto_required_for_PS_P1": False,
        },
        "primitives_verified": verified,
    }
    out = REPO_ROOT / "platform_A_info.json"
    out.write_text(json.dumps(info, indent=2) + "\n", encoding="utf-8")

    print(f"environment: python {platform.python_version()} | cryptography {cryptography.__version__}"
          f" | primitives: {', '.join(verified)} | wrote {out.name}")
    print("READY - environment is correct.")


def _importable(mod: str) -> bool:
    try:
        __import__(mod)
        return True
    except Exception:  # noqa: BLE001
        return False


if __name__ == "__main__":
    main()

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
import subprocess
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
    # 1) Python version (kit: 3.10-3.13; analysis requirements use compatible minimums)
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

    # 6) Organizer Platform A fields and honest platform provenance.
    # psutil is a required analysis dependency, so these measurements are available
    # after the dependency check above. Missing platform-specific readings remain null.
    import psutil

    cpu_model = platform.processor().strip() or None
    generic_cpu_names = {"i386", "x86_64", "AMD64", "arm64", "aarch64"}
    if cpu_model in generic_cpu_names:
        cpu_model = None
    if not cpu_model and platform.system() == "Darwin":
        try:
            probe = subprocess.run(
                ["sysctl", "-n", "machdep.cpu.brand_string"],
                check=True,
                capture_output=True,
                text=True,
                timeout=2,
            )
            cpu_model = probe.stdout.strip() or None
        except (OSError, subprocess.SubprocessError):
            cpu_model = None

    cpu_frequency = None
    try:
        cpu_frequency = psutil.cpu_freq()
    except Exception:  # noqa: BLE001
        cpu_frequency = None
    cpu_max_mhz = (
        round(float(cpu_frequency.max), 2)
        if cpu_frequency is not None and cpu_frequency.max and cpu_frequency.max > 0
        else None
    )
    battery = None
    try:
        battery = psutil.sensors_battery()
    except Exception:  # noqa: BLE001
        battery = None
    on_battery = (
        not battery.power_plugged
        if battery is not None and battery.power_plugged is not None
        else None
    )

    os_name = platform.system()
    os_version = platform.mac_ver()[0] if os_name == "Darwin" else platform.release()
    if not os_version:
        os_version = platform.release()

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
        "platform_label": "A",
        "os": os_name,
        "os_version": os_version,
        "machine": platform.machine(),
        "cpu_model": cpu_model,
        "physical_cores": psutil.cpu_count(logical=False),
        "logical_cores": psutil.cpu_count(logical=True),
        "cpu_max_mhz": cpu_max_mhz,
        "ram_total_gb": round(psutil.virtual_memory().total / (1024 ** 3), 3),
        "on_battery": on_battery,
        "generated_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "kit": "Qiskit Fall Fest 2026 - PS-P1 Quantum-Safe Secure Communication Channel",
        "phase": 2,
        "python": {
            "version": platform.python_version(),
            "implementation": platform.python_implementation(),
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

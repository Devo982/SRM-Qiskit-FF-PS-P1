#!/usr/bin/env python3
"""Provision missing local test identities, then run the T1-T9 suite."""

from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]

required_files = [
    ROOT / "identities" / "alice.json",
    ROOT / "identities" / "bob.json",
    ROOT / "trust_store.json",
]

missing = [
    path for path in required_files
    if not path.is_file() or path.stat().st_size == 0
]

if missing:
    print("Local identity material is missing or empty:", flush=True)
    for path in missing:
        print(f"  - {path.relative_to(ROOT)}", flush=True)

    print(
        "Provisioning Alice and Bob and their matching trust store...",
        flush=True,
    )

    provisioner = ROOT / "scripts" / "provision_identities.py"
    result = subprocess.run(
        [sys.executable, str(provisioner)],
        cwd=ROOT,
        check=False,
    )

    if result.returncode != 0:
        print("FAIL: Identity provisioning failed.", flush=True)
        sys.exit(result.returncode)

    missing_after = [
        path for path in required_files
        if not path.is_file() or path.stat().st_size == 0
    ]
    if missing_after:
        print(
            "FAIL: Required identity files are still missing or empty.",
            flush=True,
        )
        sys.exit(1)
else:
    print(
        "Local identities and trust store already exist; "
        "skipping provisioning.",
        flush=True,
    )

print("\nRunning mandatory security tests T1-T9...\n", flush=True)

result = subprocess.run(
    [sys.executable, "-m", "tests.run_security_tests"],
    cwd=ROOT,
    check=False,
)

sys.exit(result.returncode)

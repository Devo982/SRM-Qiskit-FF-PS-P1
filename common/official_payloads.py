"""Official QFF 2026 Phase 2 PS-P1 deterministic test payloads."""

from __future__ import annotations

import hashlib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
PAYLOAD_DIR = REPO_ROOT / "data" / "payloads"
MANIFEST_PATH = PAYLOAD_DIR / "payload_sha256.txt"

PAYLOADS = (
    ("payload_1KB.bin", 1024),
    ("payload_100KB.bin", 100 * 1024),
    ("payload_10MB.bin", 10 * 1024 * 1024),
)

EXPECTED_SHA256 = {
    "payload_1KB.bin":
        "b581f87af96e450e8d49e13990d2753f6b4317f2228481c2d0f086c1463f084d",
    "payload_100KB.bin":
        "56d1e88b9066a2effcb2c6a97f6af99fc28c82b022902b996711fb15dcd59f04",
    "payload_10MB.bin":
        "c6bf29308ba5a7412a3a92a97d9618073da01eb68d57b6a9eb4b01819358c716",
}


def gen_payload(name: str, size: int) -> bytes:
    """Generate a payload exactly as specified by the official challenge kit."""
    expected_size = dict(PAYLOADS).get(name)

    if expected_size is None:
        raise ValueError(f"Unknown official payload: {name}")
    if size != expected_size:
        raise ValueError(
            f"Incorrect size for {name}: expected {expected_size}, got {size}"
        )

    return hashlib.shake_256(
        f"QFF2026-P1-{name}".encode()
    ).digest(size)


def verify_generated_payloads() -> dict[str, bytes]:
    """Generate payloads in memory and verify the official SHA-256 hashes."""
    result = {}

    for name, size in PAYLOADS:
        data = gen_payload(name, size)
        actual_hash = hashlib.sha256(data).hexdigest()
        expected_hash = EXPECTED_SHA256[name]

        if actual_hash != expected_hash:
            raise RuntimeError(
                f"Official payload hash mismatch for {name}: "
                f"expected {expected_hash}, got {actual_hash}"
            )

        result[name] = data

    return result


def official_manifest_text() -> str:
    """Return the manifest in the official two-column format."""
    return "".join(
        f"{EXPECTED_SHA256[name]}  {name}\n"
        for name, _ in PAYLOADS
    )


def ensure_payloads() -> dict[str, bytes]:
    """Verify the manifest and materialize correct local payload files."""
    expected_manifest = official_manifest_text()

    if not MANIFEST_PATH.is_file():
        raise RuntimeError(
            f"Missing official payload manifest: {MANIFEST_PATH}"
        )

    actual_manifest = MANIFEST_PATH.read_text(encoding="utf-8")
    if actual_manifest != expected_manifest:
        raise RuntimeError(
            "Payload manifest is not the official PS-P1 manifest. "
            "Review and update it explicitly before generating payload files."
        )

    payloads = verify_generated_payloads()
    PAYLOAD_DIR.mkdir(parents=True, exist_ok=True)

    for name, data in payloads.items():
        path = PAYLOAD_DIR / name
        if not path.is_file() or path.read_bytes() != data:
            path.write_bytes(data)

    return payloads

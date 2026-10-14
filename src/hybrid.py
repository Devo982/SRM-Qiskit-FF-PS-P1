"""HKDF-SHA-256 session-key derivation for the defined PS-P1 suites."""

from __future__ import annotations

import hashlib

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

SESSION_KEY_BYTES = 32
_ALLOWED_MODES = {"ecdh", "mlkem", "hybrid"}


def _encode_ikm(components: list[tuple[str, bytes]]) -> bytes:
    if not components:
        raise ValueError("At least one shared-secret component is required")
    output = bytearray()
    for label, secret in components:
        if not isinstance(secret, bytes) or not secret:
            raise ValueError(f"Missing/invalid shared secret for {label}")
        label_bytes = label.encode("ascii")
        output.extend(len(label_bytes).to_bytes(2, "big"))
        output.extend(label_bytes)
        output.extend(len(secret).to_bytes(2, "big"))
        output.extend(secret)
    return bytes(output)


def derive_session_key(
    mode: str,
    transcript: bytes,
    ecdh_secret: bytes | None = None,
    mlkem_secret: bytes | None = None,
) -> bytes:
    """Derive a 32-byte key, binding the suite and transcript with HKDF.

    This function does not authenticate peer identities. It is a prototype KDF
    for the benchmark's explicit protocol definition, not a security proof.
    """
    if mode not in _ALLOWED_MODES:
        raise ValueError(f"Unsupported suite: {mode}")
    components: list[tuple[str, bytes]] = []
    if mode in {"ecdh", "hybrid"}:
        if ecdh_secret is None:
            raise ValueError(f"{mode} suite requires an ECDH secret")
        components.append(("ecdh_p256", ecdh_secret))
    elif ecdh_secret is not None:
        raise ValueError("ECDH secret supplied to a suite that does not use ECDH")

    if mode in {"mlkem", "hybrid"}:
        if mlkem_secret is None:
            raise ValueError(f"{mode} suite requires an ML-KEM secret")
        components.append(("mlkem_768", mlkem_secret))
    elif mlkem_secret is not None:
        raise ValueError("ML-KEM secret supplied to a suite that does not use ML-KEM")

    ikm = _encode_ikm(components)
    transcript_hash = hashlib.sha256(transcript).digest()
    info = f"PS-P1/session-key/{mode}/v1".encode("ascii")
    return HKDF(
        algorithm=hashes.SHA256(),
        length=SESSION_KEY_BYTES,
        salt=transcript_hash,
        info=info,
    ).derive(ikm)

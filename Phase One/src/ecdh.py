"""P-256 ECDH helpers based on pyca/cryptography."""

from __future__ import annotations

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

CURVE = ec.SECP256R1()
PUBLIC_KEY_BYTES = 65
SHARED_SECRET_BYTES = 32


def generate_keypair() -> ec.EllipticCurvePrivateKey:
    """Create a fresh ephemeral NIST P-256 private key."""
    return ec.generate_private_key(CURVE)


def serialize_public_key(private_key: ec.EllipticCurvePrivateKey) -> bytes:
    """Serialize a public key as an uncompressed X9.62 point (65 bytes)."""
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    )


def load_public_key(encoded: bytes) -> ec.EllipticCurvePublicKey:
    """Parse an uncompressed P-256 point and reject unexpected encodings."""
    if not isinstance(encoded, bytes):
        raise TypeError("P-256 public key must be bytes")
    if len(encoded) != PUBLIC_KEY_BYTES:
        raise ValueError(f"Expected {PUBLIC_KEY_BYTES}-byte uncompressed P-256 point")
    if encoded[0] != 0x04:
        raise ValueError("Expected uncompressed X9.62 point prefix 0x04")
    try:
        return ec.EllipticCurvePublicKey.from_encoded_point(CURVE, encoded)
    except ValueError as exc:
        raise ValueError("Invalid P-256 public point") from exc


def exchange(private_key: ec.EllipticCurvePrivateKey, peer_public_key: bytes) -> bytes:
    """Derive a raw ECDH shared secret from a peer's serialized public key."""
    peer = load_public_key(peer_public_key)
    secret = private_key.exchange(ec.ECDH(), peer)
    if len(secret) != SHARED_SECRET_BYTES:
        raise RuntimeError("Unexpected P-256 ECDH shared-secret length")
    return secret

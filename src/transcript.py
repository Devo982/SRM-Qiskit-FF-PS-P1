"""Canonical length-prefixed transcript helpers."""

from __future__ import annotations

from collections.abc import Iterable

PROTOCOL_ID = b"PS-P1-HYBRID-KEY-EXCHANGE"
PROTOCOL_VERSION = b"v1"


def encode_transcript(fields: Iterable[tuple[str, bytes]]) -> bytes:
    """Encode fields as u16(name length) || name || u32(value length) || value."""
    output = bytearray()
    for name, value in fields:
        name_bytes = name.encode("ascii")
        if len(name_bytes) > 0xFFFF:
            raise ValueError("Transcript field name is too long")
        if not isinstance(value, bytes):
            raise TypeError(f"Transcript value for {name!r} must be bytes")
        if len(value) > 0xFFFFFFFF:
            raise ValueError(f"Transcript field {name!r} is too long")
        output.extend(len(name_bytes).to_bytes(2, "big"))
        output.extend(name_bytes)
        output.extend(len(value).to_bytes(4, "big"))
        output.extend(value)
    return bytes(output)


def handshake_transcript(
    mode: str,
    responder_ecdh_public: bytes | None,
    responder_mlkem_public: bytes | None,
    initiator_ecdh_public: bytes | None,
    mlkem_ciphertext: bytes | None,
) -> bytes:
    """Build the same ordered transcript at both simulated endpoints."""
    if mode not in {"ecdh", "mlkem", "hybrid"}:
        raise ValueError(f"Unsupported suite: {mode}")
    return encode_transcript(
        [
            ("protocol_id", PROTOCOL_ID),
            ("protocol_version", PROTOCOL_VERSION),
            ("suite", mode.encode("ascii")),
            ("responder_ecdh_public", responder_ecdh_public or b""),
            ("responder_mlkem_public", responder_mlkem_public or b""),
            ("initiator_ecdh_public", initiator_ecdh_public or b""),
            ("mlkem_ciphertext", mlkem_ciphertext or b""),
        ]
    )

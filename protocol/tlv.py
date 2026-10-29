"""Canonical TLV wire encoding (design v2 section 2).

Frame = ordered sequence of (tag:1B)(len:4B big-endian)(value) records.
Parsing is strict: exact expected tags in fixed order, no missing fields,
no duplicates, no trailing bytes.
"""
from __future__ import annotations

from .errors import TranscriptBindingError

# Tag registry (design v2 section 2)
TAG_PROTO_VERSION = 0x01
TAG_SUITE_ID = 0x02
TAG_ID_C = 0x03
TAG_KEM_PK_C = 0x04
TAG_NONCE_C = 0x05
TAG_ID_S = 0x06
TAG_KEM_CT = 0x07
TAG_NONCE_S = 0x08
TAG_SIG_S = 0x09
TAG_SIG_C = 0x0A
TAG_FIN_S = 0x0B
TAG_FIN_C = 0x0C

PROTO_VERSION = 0x02

# Message schemas: fixed tag order per message.
M1_TAGS = [TAG_PROTO_VERSION, TAG_SUITE_ID, TAG_ID_C, TAG_KEM_PK_C, TAG_NONCE_C]
M2_TAGS = [
    TAG_PROTO_VERSION, TAG_SUITE_ID, TAG_ID_S,
    TAG_KEM_CT, TAG_NONCE_S, TAG_SIG_S, TAG_FIN_S,
]
M3_TAGS = [TAG_SIG_C, TAG_FIN_C]


def encode_tlv(tag: int, value: bytes) -> bytes:
    if not 0x00 <= tag <= 0xFF:
        raise ValueError("tag out of range")
    return bytes([tag]) + len(value).to_bytes(4, "big") + value


def encode_message(schema: list[int], values: dict[int, bytes]) -> bytes:
    """Encode a full message frame from a schema and a tag->value map."""
    missing = [t for t in schema if t not in values]
    if missing:
        raise ValueError(f"missing tags for message: {[hex(t) for t in missing]}")
    return b"".join(encode_tlv(t, values[t]) for t in schema)


def parse_message(frame: bytes, schema: list[int]) -> dict[int, bytes]:
    """Strict parse: exact schema order, no missing/duplicate/trailing bytes."""
    out: dict[int, bytes] = {}
    i = 0
    for tag in schema:
        if i + 5 > len(frame):
            raise TranscriptBindingError(
                f"truncated frame: expected tag 0x{tag:02x} at offset {i}"
            )
        t = frame[i]
        ln = int.from_bytes(frame[i + 1:i + 5], "big")
        if t != tag:
            raise TranscriptBindingError(
                f"unexpected tag 0x{t:02x} at offset {i} (expected 0x{tag:02x})"
            )
        if i + 5 + ln > len(frame):
            raise TranscriptBindingError(f"TLV 0x{tag:02x} length {ln} overruns frame")
        out[tag] = frame[i + 5:i + 5 + ln]
        i += 5 + ln
    if i != len(frame):
        raise TranscriptBindingError(f"{len(frame) - i} trailing bytes after last TLV")
    return out


def tlv_walk(frame: bytes) -> list[tuple[int, bytes]]:
    """Loose walk used ONLY by test-harness fault injectors (not by the protocol)."""
    out: list[tuple[int, bytes]] = []
    i = 0
    while i < len(frame):
        if i + 5 > len(frame):
            raise ValueError("malformed frame for fault injection")
        t = frame[i]
        ln = int.from_bytes(frame[i + 1:i + 5], "big")
        if i + 5 + ln > len(frame):
            raise ValueError("malformed frame for fault injection")
        out.append((t, frame[i + 5:i + 5 + ln]))
        i += 5 + ln
    return out


def _rebuild(parts: list[tuple[int, bytes]]) -> bytes:
    return b"".join(encode_tlv(t, v) for t, v in parts)


def xor_field_byte(frame: bytes, tag: int, byte_index: int, mask: int = 0x01) -> bytes:
    """Fault injector: XOR one byte of a tag's value (same-length mutation)."""
    parts = tlv_walk(frame)
    for n, (t, v) in enumerate(parts):
        if t == tag:
            if byte_index >= len(v):
                raise ValueError(f"byte_index {byte_index} out of range for tag 0x{tag:02x}")
            b = bytearray(v)
            b[byte_index] ^= mask
            parts[n] = (t, bytes(b))
            return _rebuild(parts)
    raise ValueError(f"tag 0x{tag:02x} not found in frame")


def replace_field(frame: bytes, tag: int, new_value: bytes) -> bytes:
    """Fault injector: replace a tag's value (length may change)."""
    parts = tlv_walk(frame)
    found = False
    for n, (t, _v) in enumerate(parts):
        if t == tag:
            parts[n] = (t, new_value)
            found = True
            break
    if not found:
        raise ValueError(f"tag 0x{tag:02x} not found in frame")
    return _rebuild(parts)


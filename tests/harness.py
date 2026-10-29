"""Test harness: wire-level fault injectors + handshake helpers (design v2 section 7)."""
from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from protocol.channels import ClientChannel, ServerChannel  # noqa: E402
from protocol.suites import Suite, resolve_suite  # noqa: E402
from protocol.tlv import replace_field, tlv_walk, xor_field_byte  # noqa: E402
from protocol.wire import InMemoryWire  # noqa: E402

# ---------------------------------------------------------------------------
# Fault factories: every fault mutates raw wire bytes; the endpoints then run
# their real parse/policy/lookup/signature path on the mutated frame.
# ---------------------------------------------------------------------------

def flip_handshake_field(tag: int, byte_index: int = 0, mask: int = 0x01):
    """XOR one byte inside a TLV field (same-length mutation)."""
    def fn(frame: bytes) -> bytes:
        return xor_field_byte(frame, tag, byte_index, mask)
    return fn


def substitute_handshake_field(tag: int, value: bytes):
    """Replace a TLV field value (length may change)."""
    def fn(frame: bytes) -> bytes:
        return replace_field(frame, tag, value)
    return fn


def duplicate_frame():
    def fn(frame: bytes) -> list[bytes]:
        return [frame, frame]
    return fn


def flip_record_byte(offset: int, mask: int = 0x01):
    """XOR a raw byte anywhere in a record frame (header, ciphertext, or tag)."""
    def fn(frame: bytes) -> bytes:
        b = bytearray(frame)
        b[offset % len(b)] ^= mask
        return bytes(b)
    return fn


def extract_field(frame: bytes, tag: int) -> bytes:
    for t, v in tlv_walk(frame):
        if t == tag:
            return v
    raise ValueError(f"tag 0x{tag:02x} not present")


# ---------------------------------------------------------------------------
# Handshake helpers
# ---------------------------------------------------------------------------

def make_channels(
    suite_id: str,
    trust: dict,
    client_sk,
    server_sk,
    *,
    client_identity: str = "client:alice",
    server_identity: str = "server:bob",
    client_allowed: frozenset[str] | None = None,
    server_allowed: frozenset[str] | None = None,
    server_kwargs: dict | None = None,
    wire: InMemoryWire | None = None,
    max_records: int = 2 ** 40,
):
    wire = wire if wire is not None else InMemoryWire()
    kw = dict(max_records=max_records)
    if client_allowed is not None:
        kw["allowed_suites"] = client_allowed
    client = ClientChannel(
        suite_id=suite_id, trust_store=trust, identity=client_identity,
        sign_sk=client_sk, endpoint=wire.client_ep, **kw,
    )
    skw = dict(max_records=max_records)
    if server_allowed is not None:
        skw["allowed_suites"] = server_allowed
    if server_kwargs:
        skw.update(server_kwargs)
    server = ServerChannel(
        suite_id=suite_id, trust_store=trust, identity=server_identity,
        sign_sk=server_sk, endpoint=wire.server_ep, **skw,
    )
    return client, server, wire


def run_handshake(client: ClientChannel, server: ServerChannel, wire: InMemoryWire) -> None:
    client.start()
    wire.pump(client, server)


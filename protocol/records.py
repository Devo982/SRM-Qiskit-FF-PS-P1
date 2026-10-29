"""AES-256-GCM record layer with sliding-window replay defense (design v2 section 5).

Header (16 B, always AAD):
    version u16 = 0x0001 || type u8 (0x01 app-data, 0x02 close)
    || dir u8 (0x01 c2s, 0x02 s2c) || seq u64 BE || ct_len u32 BE

nonce(12 B) = nb_dir XOR (seq u64 BE left-padded to 12 B).
Per-record wire overhead = 32 B (16 B header + 16 B tag). Single record per
payload (no chunking in scope, documented in the design).

Honesty note (design v2 section 5): byte-identical replay of a GCM record
authenticates fine - GCM protects integrity, not freshness. The receiver
window/watermark state below is the replay defense, checked BEFORE any
decryption attempt.

State-mutation rule: replay eligibility is a READ-ONLY check performed before
decryption; the window state is committed ONLY after AES-GCM authentication
succeeds. Unauthenticated input can therefore never consume sequence space or
advance the watermark (regression-tested in tests/test_regressions.py).
"""
from __future__ import annotations

import struct

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .errors import (
    RecordAuthenticationError,
    RecordReplayDetected,
    SessionExhausted,
    TranscriptBindingError,
)

RECORD_VERSION = 0x0001
TYPE_APP_DATA = 0x01
TYPE_CLOSE = 0x02
DIR_C2S = 0x01
DIR_S2C = 0x02
HEADER_LEN = 16
TAG_LEN = 16
SEQ_HARD_CAP = 2 ** 63
DEFAULT_MAX_RECORDS = 2 ** 40  # configurable session cap (design v2 section 5)


def build_header(record_type: int, direction: int, seq: int, ct_len: int) -> bytes:
    return struct.pack(">HBBQI", RECORD_VERSION, record_type, direction, seq, ct_len)


def nonce_for(nb: bytes, seq: int) -> bytes:
    """12 B nonce = nonce base XOR (u64 BE seq, left-padded)."""
    if len(nb) != 12:
        raise ValueError("nonce base must be 12 bytes")
    seq_bytes = seq.to_bytes(8, "big")
    return bytes(n ^ s for n, s in zip(nb, b"\x00\x00\x00\x00" + seq_bytes))


class ReplayWindow:
    """Per-direction sliding window: (watermark, 64-bit bitmap of seen seqs).

    bit i of the bitmap corresponds to seq = watermark + i.
    """

    __slots__ = ("watermark", "bitmap")

    def __init__(self) -> None:
        self.watermark = 0
        self.bitmap = 0

    def check(self, seq: int) -> None:
        """READ-ONLY replay-eligibility check; never mutates state.

        Raises before decryption: SessionExhausted at the hard cap,
        RecordReplayDetected for stale (seq < watermark) or duplicate
        (seq already marked inside the 64-bit window) sequence numbers.
        Call commit(seq) only AFTER the record authenticates.
        """
        if seq >= SEQ_HARD_CAP:
            raise SessionExhausted("sequence reached hard cap 2^63")
        if seq < self.watermark:
            raise RecordReplayDetected(f"stale seq {seq} < watermark {self.watermark}")
        delta = seq - self.watermark
        if delta < 64 and (self.bitmap >> delta) & 1:
            raise RecordReplayDetected(f"duplicate seq {seq} in window")

    def commit(self, seq: int) -> None:
        """Commit window state for an AUTHENTICATED record (post-GCM-success).

        Precondition: check(seq) passed and no state change happened since
        (single-threaded receiver pipeline guarantees this). Large forward
        gaps (>= 64) advance the watermark here, so a forged record can
        never trigger the advance.
        """
        delta = seq - self.watermark
        if delta >= 64:
            # Large forward gap: advance watermark, discard older seqs.
            self.watermark = seq - 63
            self.bitmap = 1 << 63
        else:
            self.bitmap |= 1 << delta


def encrypt_record(
    key: bytes, nb: bytes, record_type: int, direction: int, seq: int, plaintext: bytes
) -> bytes:
    if seq >= SEQ_HARD_CAP:
        raise SessionExhausted("send sequence reached hard cap 2^63")
    header = build_header(record_type, direction, seq, len(plaintext) + TAG_LEN)
    nonce = nonce_for(nb, seq)
    ct = AESGCM(key).encrypt(nonce, plaintext, header)
    return header + ct


def parse_header(frame: bytes) -> tuple[int, int, int]:
    """Returns (record_type, direction, seq). Raises on short frames."""
    if len(frame) < HEADER_LEN:
        raise RecordAuthenticationError("record shorter than header")
    _version, rtype, direction, seq, _ct_len = struct.unpack(">HBBQI", frame[:HEADER_LEN])
    return rtype, direction, seq


def open_record(
    key: bytes,
    nb: bytes,
    window: ReplayWindow,
    expected_dir: int,
    frame: bytes,
) -> tuple[int, int, bytes]:
    """Window check (read-only, before decryption) -> decrypt -> commit.

    Returns (seq, record_type, plaintext). Raises RecordReplayDetected for
    stale/duplicate seq before touching AES-GCM; RecordAuthenticationError on
    any InvalidTag / length mismatch; TranscriptBindingError on direction
    mismatch; SessionExhausted at caps. The window state is committed only
    after successful authentication, so forged records cannot advance the
    replay window or consume sequence numbers.
    """
    if len(frame) < HEADER_LEN + TAG_LEN:
        raise RecordAuthenticationError("record shorter than header+tag")
    header = frame[:HEADER_LEN]
    version, rtype, direction, seq, ct_len = struct.unpack(">HBBQI", header)
    if version != RECORD_VERSION:
        raise RecordAuthenticationError(f"unknown record version 0x{version:04x}")
    if direction != expected_dir:
        raise TranscriptBindingError(
            f"record direction byte 0x{direction:02x} != expected 0x{expected_dir:02x}"
        )
    if len(frame) - HEADER_LEN != ct_len:
        raise RecordAuthenticationError("ct_len field does not match frame size")
    window.check(seq)  # read-only replay defense BEFORE any decryption
    nonce = nonce_for(nb, seq)
    try:
        plaintext = AESGCM(key).decrypt(nonce, frame[HEADER_LEN:], header)
    except InvalidTag as exc:
        raise RecordAuthenticationError("GCM authentication failed (InvalidTag)") from exc
    window.commit(seq)  # state mutation only AFTER successful authentication
    return seq, rtype, plaintext


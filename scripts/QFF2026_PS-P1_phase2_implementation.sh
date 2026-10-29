#!/usr/bin/env bash
# QFF 2026 PS-P1 - Phase 2 implementation package (protocol design v2)
# All code in this file was tested end-to-end: T1-T9 = 50/50 checks PASS,
# CLI demo OK, benchmarks OK (cryptography 50.0.2, CPython 3.12/3.13).
# Idempotent: safe to re-run.
set -euo pipefail

say() { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
ok()  { printf '\033[1;32m  OK\033[0m %s\n' "$*"; }

REPO="$(git rev-parse --show-toplevel 2>/dev/null || true)"
if [[ -z "$REPO" ]]; then echo "Error: run from inside the repo."; exit 1; fi
REMOTE="$(git -C "$REPO" remote get-url origin 2>/dev/null || true)"
if [[ "$REMOTE" != *"Devo982/SRM-Qiskit-FF-PS-P1"* ]]; then
  echo "Error: origin ($REMOTE) is not Devo982/SRM-Qiskit-FF-PS-P1 - refusing."; exit 1
fi
cd "$REPO"

if [[ ! -f common/env_check.py ]]; then
  echo "Error: common/env_check.py missing - run the scaffold script first."; exit 1
fi

if [[ -x ".venv-qff26/bin/python" ]]; then PY=".venv-qff26/bin/python"; else PY="python3"; fi

say "Writing protocol/__init__.py"
mkdir -p "$REPO/protocol"
cat > "$REPO/protocol/__init__.py" <<'QFF_IMPL_EOF'
"""QFF 2026 PS-P1 quantum-safe secure channel (protocol design v2)."""
from .errors import (
    AuthenticationFailure,
    ChannelError,
    HandshakeReplayDetected,
    PolicyViolation,
    RecordAuthenticationError,
    RecordReplayDetected,
    SessionExhausted,
    TranscriptBindingError,
    UntrustedIdentity,
)
from .channels import ClientChannel, ServerChannel

__all__ = [
    "ClientChannel",
    "ServerChannel",
    "AuthenticationFailure",
    "ChannelError",
    "HandshakeReplayDetected",
    "PolicyViolation",
    "RecordAuthenticationError",
    "RecordReplayDetected",
    "SessionExhausted",
    "TranscriptBindingError",
    "UntrustedIdentity",
]

QFF_IMPL_EOF
ok "written"

say "Writing protocol/errors.py"
mkdir -p "$REPO/protocol"
cat > "$REPO/protocol/errors.py" <<'QFF_IMPL_EOF'
"""QFF 2026 PS-P1 - typed protocol failures (design v2 section 4)."""
from __future__ import annotations


class ChannelError(Exception):
    """Base class for all typed channel failures."""

    category = "ChannelError"


class PolicyViolation(ChannelError):
    """Local policy rejected version/suite before any crypto (T9)."""

    category = "PolicyViolation"


class UntrustedIdentity(ChannelError):
    """Identity not pinned in the trust store, or role mismatch (T6, T7a)."""

    category = "UntrustedIdentity"


class AuthenticationFailure(ChannelError):
    """Signature or key-confirmation (Finished) verification failed (T3, T7b, T8b)."""

    category = "AuthenticationFailure"


class TranscriptBindingError(ChannelError):
    """Malformed/ambiguous transcript bytes or KEM input rejected (T2-owned fields)."""

    category = "TranscriptBindingError"


class HandshakeReplayDetected(ChannelError):
    """Server (id_C, nonce_C) freshness cache hit (T8c; hygiene, not the anchor)."""

    category = "HandshakeReplayDetected"


class RecordReplayDetected(ChannelError):
    """Record seq is stale or duplicate under the receiver window (T8a)."""

    category = "RecordReplayDetected"


class RecordAuthenticationError(ChannelError):
    """AES-256-GCM authentication failed on a record (T4, T5); plaintext withheld."""

    category = "RecordAuthenticationError"


class SessionExhausted(ChannelError):
    """Record-count or sequence cap reached; renegotiate via a new handshake."""

    category = "SessionExhausted"

QFF_IMPL_EOF
ok "written"

say "Writing protocol/tlv.py"
mkdir -p "$REPO/protocol"
cat > "$REPO/protocol/tlv.py" <<'QFF_IMPL_EOF'
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

QFF_IMPL_EOF
ok "written"

say "Writing protocol/suites.py"
mkdir -p "$REPO/protocol"
cat > "$REPO/protocol/suites.py" <<'QFF_IMPL_EOF'
"""Suite registry and algorithm abstraction (design v2: QFF26-PQC-1 / QFF26-CLASSICAL-1).

Suite selection is LOCAL POLICY on both endpoints; it is never negotiated on the
wire. A suite_id received on the wire that is not in the local allow-list raises
PolicyViolation before any cryptographic operation runs (T9).
"""
from __future__ import annotations

import base64
import json
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric import ed25519, mlkem, mldsa, x25519

from .errors import (
    AuthenticationFailure,
    PolicyViolation,
    TranscriptBindingError,
)


@dataclass(frozen=True)
class Suite:
    suite_id: str
    kem_name: str
    sig_name: str
    kem_pk_len: int
    kem_ct_len: int
    sig_len: int
    nonce_len: int = 32


QFF26_PQC_1 = Suite(
    suite_id="QFF26-PQC-1",
    kem_name="ML-KEM-768",
    sig_name="ML-DSA-65",
    kem_pk_len=1184,
    kem_ct_len=1088,
    sig_len=3309,
)

QFF26_CLASSICAL_1 = Suite(
    suite_id="QFF26-CLASSICAL-1",
    kem_name="X25519",
    sig_name="Ed25519",
    kem_pk_len=32,
    kem_ct_len=32,
    sig_len=64,
)

SUITES: dict[str, Suite] = {
    QFF26_PQC_1.suite_id: QFF26_PQC_1,
    QFF26_CLASSICAL_1.suite_id: QFF26_CLASSICAL_1,
}

DEFAULT_ALLOWED = frozenset(SUITES.keys())


def resolve_suite(suite_id: bytes, allowed: frozenset[str] | set[str]) -> Suite:
    """Policy gate: unknown or disallowed suite ids never reach crypto (T9)."""
    sid = suite_id.decode("utf-8", errors="replace")
    suite = SUITES.get(sid)
    if suite is None:
        raise PolicyViolation(f"suite_id '{sid}' is not a known suite")
    if sid not in allowed:
        raise PolicyViolation(f"suite_id '{sid}' is not allowed by local policy")
    return suite


# ---------------------------------------------------------------------------
# KEM abstraction
# ---------------------------------------------------------------------------

def kem_generate(suite: Suite) -> tuple[object, bytes]:
    if suite.kem_name == "ML-KEM-768":
        sk = mlkem.MLKEM768PrivateKey.generate()
        return sk, sk.public_key().public_bytes_raw()
    if suite.kem_name == "X25519":
        sk = x25519.X25519PrivateKey.generate()
        return sk, sk.public_key().public_bytes_raw()
    raise PolicyViolation(f"unsupported KEM {suite.kem_name}")


def kem_encapsulate(suite: Suite, pk_bytes: bytes) -> tuple[bytes, bytes]:
    """Returns (shared_secret, ciphertext).

    X25519 has no KEM ciphertext in the usual sense: the responder generates an
    ephemeral X25519 keypair, derives ss = ECDH(eph_sk, kem_pk_C) and sends its
    ephemeral public key as the 'ciphertext' (32 B, matching the design's
    classical kem_ct size). The initiator decapsulates by ECDH(eph_sk_C, ct).
    """
    try:
        if suite.kem_name == "ML-KEM-768":
            pk = mlkem.MLKEM768PublicKey.from_public_bytes(pk_bytes)
            return pk.encapsulate()
        if suite.kem_name == "X25519":
            sk = x25519.X25519PrivateKey.generate()
            pk = x25519.X25519PublicKey.from_public_bytes(pk_bytes)
            return sk.exchange(pk), sk.public_key().public_bytes_raw()
    except Exception as exc:  # malformed / rejected KEM input
        raise TranscriptBindingError(f"KEM encapsulation rejected input: {exc}") from exc
    raise PolicyViolation(f"unsupported KEM {suite.kem_name}")


def kem_decapsulate(suite: Suite, sk: object, ct_bytes: bytes) -> bytes:
    try:
        if suite.kem_name == "ML-KEM-768":
            assert isinstance(sk, mlkem.MLKEM768PrivateKey)
            return sk.decapsulate(ct_bytes)
        if suite.kem_name == "X25519":
            assert isinstance(sk, x25519.X25519PrivateKey)
            peer_ephemeral = x25519.X25519PublicKey.from_public_bytes(ct_bytes)
            return sk.exchange(peer_ephemeral)
    except Exception as exc:
        raise TranscriptBindingError(f"KEM decapsulation rejected input: {exc}") from exc
    raise PolicyViolation(f"unsupported KEM {suite.kem_name}")


# ---------------------------------------------------------------------------
# Signature abstraction (context domain-separation via length-prefixed prefix;
# the cryptography 50.x ML-DSA/Ed25519 APIs expose no context parameter).
# ---------------------------------------------------------------------------

def _signed_message(context: bytes, message: bytes) -> bytes:
    return len(context).to_bytes(2, "big") + context + message


def sig_generate(suite: Suite) -> tuple[object, bytes]:
    if suite.sig_name == "ML-DSA-65":
        sk = mldsa.MLDSA65PrivateKey.generate()
        return sk, sk.public_key().public_bytes_raw()
    if suite.sig_name == "Ed25519":
        sk = ed25519.Ed25519PrivateKey.generate()
        return sk, sk.public_key().public_bytes_raw()
    raise PolicyViolation(f"unsupported signature algorithm {suite.sig_name}")


def sig_sign(suite: Suite, sk: object, context: bytes, message: bytes) -> bytes:
    return sk.sign(_signed_message(context, message))  # type: ignore[attr-defined]


def sig_verify(suite: Suite, vk_bytes: bytes, context: bytes, message: bytes, sig: bytes) -> None:
    """Raises AuthenticationFailure on any verification failure."""
    try:
        if suite.sig_name == "ML-DSA-65":
            vk = mldsa.MLDSA65PublicKey.from_public_bytes(vk_bytes)
            vk.verify(sig, _signed_message(context, message))
            return
        if suite.sig_name == "Ed25519":
            vk = ed25519.Ed25519PublicKey.from_public_bytes(vk_bytes)
            vk.verify(sig, _signed_message(context, message))
            return
    except Exception as exc:
        raise AuthenticationFailure(f"signature verification failed: {type(exc).__name__}") from exc
    raise PolicyViolation(f"unsupported signature algorithm {suite.sig_name}")


# ---------------------------------------------------------------------------
# Identity helpers (private keys live only in git-ignored identities/)
# ---------------------------------------------------------------------------

def load_trust_store(path) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def load_identity_private_keys(path, suite: Suite) -> object:
    """Load a signing private key object for the suite from an identity file.

    ML-DSA-65: cryptography 50.x exposes seed-based restoration
    (from_seed_bytes); the stored 32 B raw private material IS the seed.
    """
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    raw = base64.b64decode(data["mldsa65_private_b64" if suite.sig_name == "ML-DSA-65"
                                else "ed25519_private_b64"])
    if suite.sig_name == "ML-DSA-65":
        return mldsa.MLDSA65PrivateKey.from_seed_bytes(raw)
    return ed25519.Ed25519PrivateKey.from_private_bytes(raw)

QFF_IMPL_EOF
ok "written"

say "Writing protocol/keyschedule.py"
mkdir -p "$REPO/protocol"
cat > "$REPO/protocol/keyschedule.py" <<'QFF_IMPL_EOF'
"""Key schedule and transcript hashes (design v2 sections 2-3).

HKDF-SHA256 implemented explicitly (RFC 5869) so every derivation step is
auditable against the design document. Derivation order is fixed and acyclic:

    ss -> sig_S -> TH2 -> PRK -> fk -> fin_S -> sig_C -> TH3 -> fin_C -> TH4
         -> c2s_key / s2c_key / nb_c2s / nb_s2c / exp
"""
from __future__ import annotations

import hashlib
import hmac

# Domain-separation prefixes (exact bytes, design v2 sections 2-3)
TH2_LABEL = b"QFF26-P1-TH2"
TH3_LABEL = b"QFF26-P1-TH3"
TH4_LABEL = b"QFF26-P1-TH4"
FIN_LABEL = b"QFF26-P1 fin"
FIN_S_LABEL = b"QFF26-P1 fin-S"
FIN_C_LABEL = b"QFF26-P1 fin-C"
C2S_LABEL = b"QFF26-P1 c2s"
S2C_LABEL = b"QFF26-P1 s2c"
NB_C2S_LABEL = b"QFF26-P1 nb c2s"
NB_S2C_LABEL = b"QFF26-P1 nb s2c"
EXPORT_LABEL = b"QFF26-P1 export"
CTX_SERVER = b"QFF26-P1-srv"
CTX_CLIENT = b"QFF26-P1-cli"


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    """RFC 5869: PRK = HMAC-Hash(salt, IKM)."""
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """RFC 5869 expand (SHA-256, L <= 255*32)."""
    if length > 255 * 32:
        raise ValueError("hkdf_expand length too large")
    out = b""
    t = b""
    counter = 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        out += t
        counter += 1
    return out[:length]


def transcript_hash_2(t3: bytes) -> bytes:
    """TH2 = H("QFF26-P1-TH2" || T2 || TLV(09, sig_S)) = H(TH2_LABEL || T3)."""
    return sha256(TH2_LABEL + t3)


def transcript_hash_3(t3: bytes, sig_c_tlv: bytes) -> bytes:
    """TH3 = H("QFF26-P1-TH3" || T3 || TLV(0A, sig_C))."""
    return sha256(TH3_LABEL + t3 + sig_c_tlv)


def transcript_hash_4(t3: bytes, sig_c_tlv: bytes, fin_c_tlv: bytes) -> bytes:
    """TH4 = H("QFF26-P1-TH4" || T3 || TLV(0A, sig_C) || TLV(0C, fin_C))."""
    return sha256(TH4_LABEL + t3 + sig_c_tlv + fin_c_tlv)


def derive_prk(th2: bytes, shared_secret: bytes) -> bytes:
    """PRK = HKDF-Extract(salt = TH2, IKM = ss)."""
    return hkdf_extract(th2, shared_secret)


def finished_key(prk: bytes) -> bytes:
    """fk = HKDF-Expand(PRK, "QFF26-P1 fin", 32)."""
    return hkdf_expand(prk, FIN_LABEL, 32)


def finished_server(fk: bytes, th2: bytes) -> bytes:
    """fin_S = HMAC(fk, "QFF26-P1 fin-S" || TH2)."""
    return hmac.new(fk, FIN_S_LABEL + th2, hashlib.sha256).digest()


def finished_client(fk: bytes, th3: bytes) -> bytes:
    """fin_C = HMAC(fk, "QFF26-P1 fin-C" || TH3)."""
    return hmac.new(fk, FIN_C_LABEL + th3, hashlib.sha256).digest()


def derive_traffic_keys(prk: bytes, th4: bytes) -> dict[str, bytes]:
    """Final stage: c2s/s2c 32 B keys, 12 B nonce bases, 32 B exporter.

    Kit quickstart labels QFF26 c2s / QFF26 s2c are preserved and strengthened
    with TH4 transcript binding.
    """
    return {
        "c2s_key": hkdf_expand(prk, C2S_LABEL + th4, 32),
        "s2c_key": hkdf_expand(prk, S2C_LABEL + th4, 32),
        "nb_c2s": hkdf_expand(prk, NB_C2S_LABEL + th4, 12),
        "nb_s2c": hkdf_expand(prk, NB_S2C_LABEL + th4, 12),
        "exporter": hkdf_expand(prk, EXPORT_LABEL + th4, 32),
    }


def zeroize(*byte_strings: bytes | bytearray | None) -> None:
    """Best-effort zeroization. Python cannot guarantee memory hygiene; this is
    a prototype defense-in-depth measure (documented limitation)."""
    for b in byte_strings:
        if isinstance(b, bytearray):
            for i in range(len(b)):
                b[i] = 0

QFF_IMPL_EOF
ok "written"

say "Writing protocol/records.py"
mkdir -p "$REPO/protocol"
cat > "$REPO/protocol/records.py" <<'QFF_IMPL_EOF'
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

    def check_and_update(self, seq: int) -> None:
        """Reject stale/duplicate BEFORE decryption; update state on accept."""
        if seq >= SEQ_HARD_CAP:
            raise SessionExhausted("sequence reached hard cap 2^63")
        if seq < self.watermark:
            raise RecordReplayDetected(f"stale seq {seq} < watermark {self.watermark}")
        delta = seq - self.watermark
        if delta < 64 and (self.bitmap >> delta) & 1:
            raise RecordReplayDetected(f"duplicate seq {seq} in window")
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
    """Window check (before decryption) -> decrypt/authenticate.

    Returns (seq, record_type, plaintext). Raises RecordReplayDetected for
    stale/duplicate seq before touching AES-GCM; RecordAuthenticationError on
    any InvalidTag / length mismatch; TranscriptBindingError on direction
    mismatch; SessionExhausted at caps.
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
    window.check_and_update(seq)  # replay defense BEFORE any decryption
    nonce = nonce_for(nb, seq)
    try:
        plaintext = AESGCM(key).decrypt(nonce, frame[HEADER_LEN:], header)
    except InvalidTag as exc:
        raise RecordAuthenticationError("GCM authentication failed (InvalidTag)") from exc
    return seq, rtype, plaintext

QFF_IMPL_EOF
ok "written"

say "Writing protocol/channels.py"
mkdir -p "$REPO/protocol"
cat > "$REPO/protocol/channels.py" <<'QFF_IMPL_EOF'
"""Authenticated handshake state machines (design v2 section 4) and record plumbing.

One state machine shape, two roles:
    Client: INIT -> M1_SENT -> M3_SENT -> ESTABLISHED -> CLOSED | FAILED(reason)
    Server: INIT -> M2_SENT -> ESTABLISHED -> CLOSED | FAILED(reason)

Verification order is FIXED on every authenticated input:
    policy -> trust-store lookup -> signature -> Finished
An attacker-supplied verification key is never reachable: there is no code path
that consumes a vk from the wire (design v2 section 1).

Prototype limitation (documented): Python cannot guarantee memory hygiene;
zeroization below is best-effort defense-in-depth.
"""
from __future__ import annotations

import base64
import hmac
import os
import time
from collections import OrderedDict

from . import keyschedule as ks
from . import records as rec
from .errors import (
    AuthenticationFailure,
    ChannelError,
    HandshakeReplayDetected,
    PolicyViolation,
    SessionExhausted,
    TranscriptBindingError,
    UntrustedIdentity,
)
from .suites import (
    DEFAULT_ALLOWED,
    Suite,
    kem_decapsulate,
    kem_encapsulate,
    kem_generate,
    resolve_suite,
    sig_sign,
    sig_verify,
)
from .tlv import (
    M1_TAGS,
    M2_TAGS,
    M3_TAGS,
    TAG_FIN_C,
    TAG_FIN_S,
    TAG_ID_S,
    TAG_KEM_CT,
    TAG_KEM_PK_C,
    TAG_NONCE_C,
    TAG_NONCE_S,
    TAG_PROTO_VERSION,
    TAG_SIG_C,
    TAG_SIG_S,
    TAG_SUITE_ID,
    encode_message,
    encode_tlv,
    parse_message,
)

STATE_INIT = "INIT"
STATE_M1_SENT = "M1_SENT"
STATE_M2_SENT = "M2_SENT"
STATE_M3_SENT = "M3_SENT"
STATE_ESTABLISHED = "ESTABLISHED"
STATE_CLOSED = "CLOSED"
STATE_FAILED = "FAILED"

_NONCE_LEN = 32


def _len_error(field: str, expected: int) -> TranscriptBindingError:
    return TranscriptBindingError(
        f"{field} length does not match suite parameters (expected {expected})"
    )


class Endpoint:
    """One end of an in-memory wire: outbox frames waiting for delivery."""

    def __init__(self, name: str = "endpoint") -> None:
        self.name = name
        self.outbox: list[bytes] = []

    def send(self, frame: bytes) -> None:
        self.outbox.append(frame)


class BaseChannel:
    role = "base"

    def __init__(
        self,
        *,
        suite_id: str,
        trust_store: dict,
        identity: str,
        sign_sk: object,
        endpoint: Endpoint,
        allowed_suites: frozenset[str] | set[str] = DEFAULT_ALLOWED,
        max_records: int = rec.DEFAULT_MAX_RECORDS,
    ) -> None:
        self._suite_id_cfg = suite_id
        self._suite: Suite | None = None
        self._trust = trust_store
        self.identity = identity
        self._sign_sk = sign_sk
        self._endpoint = endpoint
        self._allowed = frozenset(allowed_suites)
        self._max_records = max_records
        self.state = STATE_INIT
        self.failure_category: str | None = None
        self.failure_detail: str | None = None
        self._inbox: list[bytes] = []
        self._send_key: bytearray | None = None
        self._send_nb: bytes | None = None
        self._recv_key: bytearray | None = None
        self._recv_nb: bytes | None = None
        self._recv_window = rec.ReplayWindow()
        self._send_seq = 0
        self._send_dir = 0
        self._recv_dir = 0
        self.exporter: bytes | None = None
        # transient handshake secrets (best-effort zeroized on terminal states)
        self._kem_sk: object | None = None
        self._m1_frame: bytes | None = None
        self._ss: bytearray | None = None
        self._prk: bytearray | None = None
        self._fk: bytearray | None = None

    # -- introspection -------------------------------------------------------
    @property
    def established(self) -> bool:
        return self.state == STATE_ESTABLISHED

    @property
    def suite_id(self) -> str | None:
        return self._suite.suite_id if self._suite else None

    def _fail(self, exc: ChannelError) -> None:
        self.state = STATE_FAILED
        self.failure_category = exc.category
        self.failure_detail = str(exc)
        self._wipe_secrets()

    def _wipe_secrets(self) -> None:
        ks.zeroize(self._ss, self._prk, self._fk, self._send_key, self._recv_key)
        self._ss = self._prk = self._fk = None
        self._send_key = self._recv_key = None
        self._kem_sk = None
        self._m1_frame = None

    # -- trust store (design v2 section 1) ------------------------------------
    def _trust_lookup(self, identity: str, expected_role: str) -> bytes:
        entry = self._trust.get("identities", {}).get(identity)
        if entry is None:
            raise UntrustedIdentity(f"identity '{identity}' is not pinned in the trust store")
        if entry.get("role") != expected_role:
            raise UntrustedIdentity(
                f"identity '{identity}' has role '{entry.get('role')}', "
                f"expected '{expected_role}'"
            )
        vk_b64 = entry.get("keys", {}).get(self._suite.suite_id)  # type: ignore[union-attr]
        if not vk_b64:
            raise UntrustedIdentity(
                f"no pinned verification key for suite {self._suite.suite_id}"
            )
        return base64.b64decode(vk_b64)

    @staticmethod
    def _check_version(value: bytes) -> None:
        if value != bytes([0x02]):
            raise PolicyViolation(f"unsupported proto_version 0x{value.hex()}")

    # -- record layer (design v2 section 5) ------------------------------------
    def _init_records(self, keys: dict[str, bytes], send_dir: int, recv_dir: int) -> None:
        if send_dir == rec.DIR_C2S:
            self._send_key = bytearray(keys["c2s_key"])
            self._send_nb = keys["nb_c2s"]
            self._recv_key = bytearray(keys["s2c_key"])
            self._recv_nb = keys["nb_s2c"]
        else:
            self._send_key = bytearray(keys["s2c_key"])
            self._send_nb = keys["nb_s2c"]
            self._recv_key = bytearray(keys["c2s_key"])
            self._recv_nb = keys["nb_c2s"]
        self._send_dir = send_dir
        self._recv_dir = recv_dir
        self._recv_window = rec.ReplayWindow()
        self._send_seq = 0
        self.exporter = keys["exporter"]

    def send(self, data: bytes) -> None:
        if self.state != STATE_ESTABLISHED:
            raise ChannelError(f"send() requires ESTABLISHED, state is {self.state}")
        if self._send_seq >= min(self._max_records, rec.SEQ_HARD_CAP):
            raise SessionExhausted("session record cap reached; renegotiate via new handshake")
        frame = rec.encrypt_record(
            self._send_key, self._send_nb, rec.TYPE_APP_DATA, self._send_dir,
            self._send_seq, data,
        )
        self._send_seq += 1
        self._endpoint.send(frame)

    def close(self) -> None:
        """Authenticated close (type 0x02); forged closes fail authentication."""
        if self.state == STATE_ESTABLISHED and self._send_key is not None:
            frame = rec.encrypt_record(
                self._send_key, self._send_nb, rec.TYPE_CLOSE, self._send_dir,
                self._send_seq, b"",
            )
            self._send_seq += 1
            self._endpoint.send(frame)
        self.state = STATE_CLOSED
        self._wipe_secrets()

    def recv(self) -> bytes | None:
        """Pop one decrypted application record; None when nothing pending."""
        if self._inbox:
            return self._inbox.pop(0)
        return None

    def _on_record(self, frame: bytes) -> None:
        _seq, rtype, plaintext = rec.open_record(
            self._recv_key, self._recv_nb, self._recv_window, self._recv_dir, frame
        )
        if rtype == rec.TYPE_CLOSE:
            self.state = STATE_CLOSED
            self._wipe_secrets()
        else:
            self._inbox.append(plaintext)

    # -- dispatch ---------------------------------------------------------------
    def on_frame(self, frame: bytes) -> None:
        """Entry point for every wire frame. Typed failures are recorded on the
        channel (state FAILED + failure_category); the pump never crashes."""
        if self.state in (STATE_FAILED, STATE_CLOSED):
            return  # terminal states ignore late frames
        try:
            self._dispatch(frame)
        except ChannelError as exc:
            self._fail(exc)
        except Exception as exc:  # unexpected bug: still fail closed
            self._fail(ChannelError(f"internal error: {type(exc).__name__}: {exc}"))

    def _dispatch(self, frame: bytes) -> None:  # pragma: no cover - overridden
        raise NotImplementedError


class ClientChannel(BaseChannel):
    """Initiator (Alice). Sends M1, verifies M2, sends M3."""

    role = "client"

    def start(self) -> None:
        if self.state != STATE_INIT:
            raise ChannelError("start() already called")
        try:
            if self._suite_id_cfg not in self._allowed:
                raise PolicyViolation(f"suite {self._suite_id_cfg} not allowed by local policy")
            self._suite = resolve_suite(self._suite_id_cfg.encode(), self._allowed)
            self._kem_sk, kem_pk = kem_generate(self._suite)
            self._m1_frame = encode_message(M1_TAGS, {
                TAG_PROTO_VERSION: bytes([0x02]),
                TAG_SUITE_ID: self._suite.suite_id.encode(),
                0x03: self.identity.encode(),
                TAG_KEM_PK_C: kem_pk,
                0x05: os.urandom(_NONCE_LEN),
            })
            self._endpoint.send(self._m1_frame)
            self.state = STATE_M1_SENT
        except ChannelError as exc:
            self._fail(exc)

    def _dispatch(self, frame: bytes) -> None:
        if self.state == STATE_M1_SENT:
            self._on_m2(frame)
        elif self.state == STATE_ESTABLISHED:
            self._on_record(frame)
        else:
            raise ChannelError(f"unexpected frame in state {self.state}")

    def _on_m2(self, frame: bytes) -> None:
        suite = self._suite
        values = parse_message(frame, M2_TAGS)  # strict: order/dup/trailing (T2)
        self._check_version(values[TAG_PROTO_VERSION])
        echoed = resolve_suite(values[TAG_SUITE_ID], self._allowed)  # policy first (T9)
        if echoed.suite_id != suite.suite_id:
            raise PolicyViolation("server echoed a different suite than local policy chose")

        id_s = values[TAG_ID_S].decode("utf-8", errors="replace")
        self._suite = echoed
        vk_s = self._trust_lookup(id_s, expected_role="server")  # lookup before sig math

        kem_ct = values[TAG_KEM_CT]
        if len(kem_ct) != suite.kem_ct_len:
            raise _len_error("kem_ct", suite.kem_ct_len)
        if len(values[TAG_NONCE_S]) != _NONCE_LEN:
            raise _len_error("nonce_S", _NONCE_LEN)
        sig_s = values[TAG_SIG_S]
        if len(sig_s) != suite.sig_len:
            raise _len_error("sig_S", suite.sig_len)

        ss = kem_decapsulate(suite, self._kem_sk, kem_ct)

        # T2 = M1 exactly as sent || M2 core TLVs rebuilt from received values
        s_core = b"".join([
            encode_tlv(TAG_PROTO_VERSION, values[TAG_PROTO_VERSION]),
            encode_tlv(TAG_SUITE_ID, values[TAG_SUITE_ID]),
            encode_tlv(TAG_ID_S, values[TAG_ID_S]),
            encode_tlv(TAG_KEM_CT, kem_ct),
            encode_tlv(TAG_NONCE_S, values[TAG_NONCE_S]),
        ])
        t2 = self._m1_frame + s_core
        sig_verify(suite, vk_s, ks.CTX_SERVER, t2, sig_s)  # AuthenticationFailure on bad
        sig_s_tlv = encode_tlv(TAG_SIG_S, sig_s)
        t3 = t2 + sig_s_tlv

        th2 = ks.transcript_hash_2(t3)
        self._ss = bytearray(ss)
        self._prk = bytearray(ks.derive_prk(th2, ss))
        self._fk = bytearray(ks.finished_key(bytes(self._prk)))
        expected_fin_s = ks.finished_server(bytes(self._fk), th2)
        if not hmac.compare_digest(expected_fin_s, values[TAG_FIN_S]):
            raise AuthenticationFailure("server Finished (fin_S) verification failed")

        # client signs T3 (covers sig_S) and confirms keys
        sig_c = sig_sign(suite, self._sign_sk, ks.CTX_CLIENT, t3)
        sig_c_tlv = encode_tlv(TAG_SIG_C, sig_c)
        th3 = ks.transcript_hash_3(t3, sig_c_tlv)
        fin_c = ks.finished_client(bytes(self._fk), th3)
        fin_c_tlv = encode_tlv(TAG_FIN_C, fin_c)
        self._endpoint.send(sig_c_tlv + fin_c_tlv)  # M3

        th4 = ks.transcript_hash_4(t3, sig_c_tlv, fin_c_tlv)
        keys = ks.derive_traffic_keys(bytes(self._prk), th4)
        self._init_records(keys, send_dir=rec.DIR_C2S, recv_dir=rec.DIR_S2C)
        self.state = STATE_ESTABLISHED
        ks.zeroize(self._ss, self._prk, self._fk)
        self._ss = self._prk = self._fk = None


class ServerChannel(BaseChannel):
    """Responder (Bob). Verifies M1, sends M2, verifies M3."""

    role = "server"

    def __init__(
        self,
        *,
        handshake_cache_ttl: float = 300.0,
        handshake_cache_size: int = 4096,
        enable_handshake_cache: bool = True,
        handshake_cache: OrderedDict | None = None,
        **kwargs,
    ) -> None:
        super().__init__(**kwargs)
        self._cache_enabled = enable_handshake_cache
        self._cache_ttl = handshake_cache_ttl
        self._cache_size = handshake_cache_size
        # The cache models SERVER-DEPLOYMENT state across connections: pass the
        # same OrderedDict to multiple ServerChannel instances (connections).
        self._cache = handshake_cache if handshake_cache is not None else OrderedDict()
        # per-handshake state (derivation order: each step consumes earlier outputs)
        self._t2: bytes | None = None
        self._sig_s_tlv: bytes | None = None
        self._peer_id: str | None = None

    def _cache_check_and_add(self, id_c: str, nonce_c: bytes) -> None:
        """(id_C, nonce_C) freshness cache: DoS hygiene + early replay rejection.
        NOT the correctness anchor (design v2 section 6)."""
        if not self._cache_enabled:
            return
        key = (id_c, nonce_c)
        now = time.monotonic()
        ts = self._cache.get(key)
        if ts is not None and now - ts <= self._cache_ttl:
            raise HandshakeReplayDetected(f"M1 replay for '{id_c}' (nonce cache hit)")
        self._cache[key] = now
        self._cache.move_to_end(key)
        while len(self._cache) > self._cache_size:
            self._cache.popitem(last=False)

    def _dispatch(self, frame: bytes) -> None:
        if self.state == STATE_INIT:
            self._on_m1(frame)
        elif self.state == STATE_M2_SENT:
            self._on_m3(frame)
        elif self.state == STATE_ESTABLISHED:
            self._on_record(frame)
        else:
            raise ChannelError(f"unexpected frame in state {self.state}")

    def _on_m1(self, frame: bytes) -> None:
        values = parse_message(frame, M1_TAGS)  # strict
        self._check_version(values[TAG_PROTO_VERSION])
        suite = resolve_suite(values[TAG_SUITE_ID], self._allowed)  # policy first (T9)
        self._suite = suite

        id_c = values[0x03].decode("utf-8", errors="replace")
        self._peer_id = id_c
        self._trust_lookup(id_c, expected_role="client")  # before any signature math

        nonce_c = values[TAG_NONCE_C]
        if len(nonce_c) != _NONCE_LEN:
            raise _len_error("nonce_C", _NONCE_LEN)
        self._cache_check_and_add(id_c, nonce_c)  # T8c
        kem_pk = values[TAG_KEM_PK_C]
        if len(kem_pk) != suite.kem_pk_len:
            raise _len_error("kem_pk_C", suite.kem_pk_len)

        ss, kem_ct = kem_encapsulate(suite, kem_pk)

        nonce_s = os.urandom(_NONCE_LEN)
        s_core = b"".join([
            encode_tlv(TAG_PROTO_VERSION, values[TAG_PROTO_VERSION]),
            encode_tlv(TAG_SUITE_ID, values[TAG_SUITE_ID]),
            encode_tlv(TAG_ID_S, self.identity.encode()),
            encode_tlv(TAG_KEM_CT, kem_ct),
            encode_tlv(TAG_NONCE_S, nonce_s),
        ])
        t2 = frame + s_core  # M1 exactly as received || server core
        sig_s = sig_sign(suite, self._sign_sk, ks.CTX_SERVER, t2)
        sig_s_tlv = encode_tlv(TAG_SIG_S, sig_s)
        t3 = t2 + sig_s_tlv

        th2 = ks.transcript_hash_2(t3)
        self._ss = bytearray(ss)
        self._prk = bytearray(ks.derive_prk(th2, ss))
        self._fk = bytearray(ks.finished_key(bytes(self._prk)))
        fin_s = ks.finished_server(bytes(self._fk), th2)

        self._t2 = t2
        self._sig_s_tlv = sig_s_tlv
        self._endpoint.send(encode_message(M2_TAGS, {
            TAG_PROTO_VERSION: values[TAG_PROTO_VERSION],
            TAG_SUITE_ID: values[TAG_SUITE_ID],
            TAG_ID_S: self.identity.encode(),
            TAG_KEM_CT: kem_ct,
            TAG_NONCE_S: nonce_s,
            TAG_SIG_S: sig_s,
            TAG_FIN_S: fin_s,
        }))
        self.state = STATE_M2_SENT

    def _on_m3(self, frame: bytes) -> None:
        suite = self._suite
        values = parse_message(frame, M3_TAGS)
        sig_c = values[TAG_SIG_C]
        if len(sig_c) != suite.sig_len:
            raise _len_error("sig_C", suite.sig_len)

        # trust lookup AGAIN at M3 (design v2 section 4 server path)
        vk_c = self._trust_lookup(self._peer_id, expected_role="client")  # type: ignore[arg-type]

        t3 = self._t2 + self._sig_s_tlv  # type: ignore[operator]
        sig_verify(suite, vk_c, ks.CTX_CLIENT, t3, sig_c)
        sig_c_tlv = encode_tlv(TAG_SIG_C, sig_c)
        th3 = ks.transcript_hash_3(t3, sig_c_tlv)
        expected_fin_c = ks.finished_client(bytes(self._fk), th3)  # type: ignore[arg-type]
        if not hmac.compare_digest(expected_fin_c, values[TAG_FIN_C]):
            raise AuthenticationFailure("client Finished (fin_C) verification failed")
        fin_c_tlv = encode_tlv(TAG_FIN_C, values[TAG_FIN_C])

        th4 = ks.transcript_hash_4(t3, sig_c_tlv, fin_c_tlv)
        keys = ks.derive_traffic_keys(bytes(self._prk), th4)  # type: ignore[arg-type]
        self._init_records(keys, send_dir=rec.DIR_S2C, recv_dir=rec.DIR_C2S)
        self.state = STATE_ESTABLISHED
        self._t2 = None
        self._sig_s_tlv = None
        ks.zeroize(self._ss, self._prk, self._fk)
        self._ss = self._prk = self._fk = None

QFF_IMPL_EOF
ok "written"

say "Writing protocol/wire.py"
mkdir -p "$REPO/protocol"
cat > "$REPO/protocol/wire.py" <<'QFF_IMPL_EOF'
"""In-memory wire + synchronous pump.

Endpoints exchange serialized frames through this object; every fault in the
T1-T9 battery is injected HERE, on the bytes between two real endpoints, so
every fault travels the real parse/verify path (design v2 section 7).
"""
from __future__ import annotations

from .channels import BaseChannel, Endpoint


class InMemoryWire:
    """Bidirectional frame pipe with fault-injection hooks.

    Frame indices count per direction across the whole session (handshake
    frames included): c2s #0 = M1, c2s #1 = M3, c2s #2+ = app records;
    s2c #0 = M2, s2c #1+ = app records.
    """

    def __init__(self) -> None:
        self.client_ep = Endpoint("client")
        self.server_ep = Endpoint("server")
        self._faults: dict[str, list[tuple[int, object]]] = {"c2s": [], "s2c": []}
        self._counts = {"c2s": 0, "s2c": 0}
        # delivery log: (direction, frame_index, frame) — used by tests to
        # capture genuine frames for replay/splice scenarios (T7b, T8b, T8c)
        self.log: list[tuple[str, int, bytes]] = []

    @property
    def counts(self) -> dict[str, int]:
        return dict(self._counts)

    def add_fault(self, direction: str, frame_index: int, fn) -> None:
        """Register a fault fn(frame)->frame | list[frame] for one frame index."""
        if direction not in self._faults:
            raise ValueError("direction must be 'c2s' or 's2c'")
        self._faults[direction].append((frame_index, fn))

    def _deliver(self, direction: str, from_ep: Endpoint, to_channel: BaseChannel) -> int:
        delivered = 0
        while from_ep.outbox:
            frame = from_ep.outbox.pop(0)
            idx = self._counts[direction]
            self._counts[direction] = idx + 1
            for fi, fn in self._faults[direction]:
                if fi == idx:
                    frame = fn(frame)
            frames = frame if isinstance(frame, (list, tuple)) else [frame]
            for f in frames:
                self.log.append((direction, idx, f))
                to_channel.on_frame(f)
            delivered += 1
        return delivered

    def pump(self, client: BaseChannel, server: BaseChannel, max_rounds: int = 16) -> int:
        """Deliver every queued frame both ways until queues stay empty."""
        total = 0
        for _ in range(max_rounds):
            moved = self._deliver("c2s", self.client_ep, server)
            moved += self._deliver("s2c", self.server_ep, client)
            total += moved
            if moved == 0:
                break
        return total

QFF_IMPL_EOF
ok "written"

say "Writing tests/__init__.py"
mkdir -p "$REPO/tests"
cat > "$REPO/tests/__init__.py" <<'QFF_IMPL_EOF'

QFF_IMPL_EOF
ok "written"

say "Writing tests/harness.py"
mkdir -p "$REPO/tests"
cat > "$REPO/tests/harness.py" <<'QFF_IMPL_EOF'
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

QFF_IMPL_EOF
ok "written"

say "Writing tests/run_security_tests.py"
mkdir -p "$REPO/tests"
cat > "$REPO/tests/run_security_tests.py" <<'QFF_IMPL_EOF'
#!/usr/bin/env python3
"""QFF 2026 PS-P1 - automated security test battery T1-T9 (design v2 section 7).

Single command:
    python -m tests.run_security_tests        (repo root)
    python tests/run_security_tests.py        (also works)

Every fault is injected on the WIRE between two real endpoints - no test calls
internal functions with pre-broken values. Results are written to
results/security_tests.csv and printed as a table.

Requires: scripts/provision_identities.py to have been run once (identities/ +
trust_store.json). This tool asserts via PUBLIC confirmation status only
(states, failure categories, sizes) - key bytes are never printed.
"""
from __future__ import annotations

import csv
import hashlib
import json
import sys
import time
from collections import OrderedDict
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from protocol import records as rec  # noqa: E402
from protocol.channels import ClientChannel, ServerChannel  # noqa: E402
from protocol.suites import (  # noqa: E402
    QFF26_CLASSICAL_1,
    QFF26_PQC_1,
    SUITES,
    load_identity_private_keys,
    sig_generate,
)
from protocol.tlv import TAG_ID_C, TAG_ID_S, TAG_KEM_CT, TAG_KEM_PK_C  # noqa: E402
from protocol.tlv import (  # noqa: E402
    TAG_NONCE_C,
    TAG_NONCE_S,
    TAG_PROTO_VERSION,
    TAG_SIG_C,
    TAG_SIG_S,
    TAG_SUITE_ID,
)
from protocol.wire import Endpoint, InMemoryWire  # noqa: E402
from tests.harness import (  # noqa: E402
    duplicate_frame,
    extract_field,
    flip_handshake_field,
    flip_record_byte,
    make_channels,
    run_handshake,
    substitute_handshake_field,
)

PAYLOADS = [
    ("payload_1kb.bin", 1024),
    ("payload_100kb.bin", 102400),
    ("payload_10mb.bin", 10 * 1024 * 1024),
]
PAYLOAD_SEED = b"QFF26-PS-P1-payload-seed-v1"

ROWS: list[dict] = []
_FAILURES = 0


def check(tid: str, sub: str, suite: str, scenario: str, expected: str,
          observed: str, ok: bool, detail: str = "") -> bool:
    global _FAILURES
    if not ok:
        _FAILURES += 1
    ROWS.append({
        "test_id": tid, "sub": sub, "suite": suite, "scenario": scenario,
        "expected": expected, "observed": observed,
        "status": "PASS" if ok else "FAIL",
        "detail": detail, "timestamp_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    })
    mark = "PASS" if ok else "FAIL"
    print(f"  [{tid}/{sub}] {mark:<4} {scenario}  (expected {expected}; observed {observed})")
    if not ok and detail:
        print(f"          detail: {detail}")
    return ok


# ---------------------------------------------------------------------------
# Payloads: deterministic bytes -> stable SHA-256 manifest (committed);
# payload *.bin files are regenerated locally and never committed.
# ---------------------------------------------------------------------------

def gen_payload(n: int) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < n:
        out += hashlib.sha256(PAYLOAD_SEED + counter.to_bytes(8, "big")).digest()
        counter += 1
    return bytes(out[:n])


def ensure_payloads() -> dict[str, bytes]:
    pdir = REPO_ROOT / "data" / "payloads"
    pdir.mkdir(parents=True, exist_ok=True)
    data_map: dict[str, bytes] = {}
    for name, size in PAYLOADS:
        path = pdir / name
        if not path.exists() or path.stat().st_size != size:
            path.write_bytes(gen_payload(size))
            print(f"  generated {name} ({size} bytes)")
        data_map[name] = path.read_bytes()
    manifest = pdir / "payload_sha256.txt"
    lines = [f"{hashlib.sha256(data_map[name]).hexdigest()}  {name}" for name, _ in PAYLOADS]
    expected_manifest = "\n".join(lines) + "\n"
    if not manifest.exists():
        manifest.write_text(expected_manifest, encoding="utf-8")
        print(f"  wrote {manifest.name} (commit this manifest)")
    elif manifest.read_text(encoding="utf-8") != expected_manifest:
        raise SystemExit(
            f"FAIL - {manifest} does not match locally generated payloads; "
            "delete data/payloads/ and re-run to regenerate."
        )
    return data_map


# ---------------------------------------------------------------------------
# Context: trust store + identity private keys (never printed)
# ---------------------------------------------------------------------------

def load_context() -> tuple[dict, dict]:
    trust_path = REPO_ROOT / "trust_store.json"
    idir = REPO_ROOT / "identities"
    if not trust_path.exists() or not (idir / "alice.json").exists():
        raise SystemExit(
            "FAIL - identities not provisioned. Run: python scripts/provision_identities.py"
        )
    trust = json.loads(trust_path.read_text(encoding="utf-8"))
    return trust, {"alice": idir / "alice.json", "bob": idir / "bob.json"}


def fresh_handshake(suite, trust, a_sk, b_sk, **kw):
    client, server, wire = make_channels(suite.suite_id, trust, a_sk, b_sk, **kw)
    run_handshake(client, server, wire)
    return client, server, wire


# ---------------------------------------------------------------------------
# T1 - honest handshake + official payloads + authenticated close
# ---------------------------------------------------------------------------

def t1(suite, trust, a_sk, b_sk) -> None:
    sid = suite.suite_id
    client, server, wire = fresh_handshake(suite, trust, a_sk, b_sk)
    check("T1", "a", sid, "honest handshake establishes both endpoints",
          "both ESTABLISHED",
          f"client={client.state},server={server.state}",
          client.established and server.established)

    payloads = ensure_payloads()
    ok = True
    detail = ""
    for name, size in PAYLOADS:
        data = payloads[name]
        expected_sha = hashlib.sha256(data).hexdigest()
        client.send(data)
        wire.pump(client, server)
        got = server.recv()
        got_sha = hashlib.sha256(got).hexdigest() if got is not None else "none"
        if got != data:
            ok, detail = False, f"c2s {name}: byte comparison failed"
            break
        if got_sha != expected_sha:
            ok, detail = False, f"c2s {name}: SHA-256 mismatch"
            break
        server.send(data)
        wire.pump(client, server)
        got2 = client.recv()
        if got2 != data or hashlib.sha256(got2).hexdigest() != expected_sha:
            ok, detail = False, f"s2c {name}: byte/SHA verification failed"
            break
    check("T1", "b", sid, "3 official payloads (1KB/100KB/10MB), both directions, "
          "byte-level + SHA-256 vs payload_sha256.txt",
          "6/6 verified", "6/6 verified" if ok else "mismatch", ok, detail)

    client.close()
    wire.pump(client, server)
    check("T1", "c", sid, "authenticated close record tears down the peer",
          "server CLOSED", f"server={server.state}", server.state == "CLOSED")


# ---------------------------------------------------------------------------
# T2 - transcript-field bit flips (parametrized, abort at owning step)
# ---------------------------------------------------------------------------

T2_CASES = [
    ("kem_pk_C", "c2s", 0, TAG_KEM_PK_C, "client", "AuthenticationFailure"),
    ("nonce_C", "c2s", 0, TAG_NONCE_C, "client", "AuthenticationFailure"),
    ("id_C", "c2s", 0, TAG_ID_C, "server", "UntrustedIdentity"),
    ("proto_version", "c2s", 0, TAG_PROTO_VERSION, "server", "PolicyViolation"),
    ("suite_id", "c2s", 0, TAG_SUITE_ID, "server", "PolicyViolation"),
    ("kem_ct", "s2c", 0, TAG_KEM_CT, "client", "AuthenticationFailure"),
    ("nonce_S", "s2c", 0, TAG_NONCE_S, "client", "AuthenticationFailure"),
    ("id_S", "s2c", 0, TAG_ID_S, "client", "UntrustedIdentity"),
]


def t2(suite, trust, a_sk, b_sk) -> None:
    for label, direction, idx, tag, side, expected in T2_CASES:
        _t2_case(suite, trust, a_sk, b_sk, label, direction, idx, tag, side, expected)


def _t2_case(suite, trust, a_sk, b_sk, label, direction, idx, tag, side, expected) -> None:
    sid = suite.suite_id
    client, server, wire = make_channels(sid, trust, a_sk, b_sk)
    wire.add_fault(direction, idx, flip_handshake_field(tag))
    run_handshake(client, server, wire)
    observed_chan = client if side == "client" else server
    other = server if side == "client" else client
    cat = observed_chan.failure_category or f"no-failure(state={observed_chan.state})"
    ok = (observed_chan.failure_category == expected
          and not client.established and not server.established)
    check("T2", label, sid, f"bit-flip {label} on wire -> abort at owning step, "
          "traffic keys never established", f"{side}:{expected},no-establishment",
          f"{side}:{cat},established={client.established or server.established}", ok,
          observed_chan.failure_detail or "")


# ---------------------------------------------------------------------------
# T3 - signature flips
# ---------------------------------------------------------------------------

def t3(suite, trust, a_sk, b_sk) -> None:
    sid = suite.suite_id
    # sig_S flip in M2
    client, server, wire = _mk(suite, trust, a_sk, b_sk)
    wire.add_fault("s2c", 0, flip_handshake_field(TAG_SIG_S))
    run_handshake(client, server, wire)
    check("T3", "sig_S", sid, "bit-flip sig_S -> AuthenticationFailure at client",
          "client:AuthenticationFailure",
          f"client:{client.failure_category}",
          client.failure_category == "AuthenticationFailure")
    # sig_C flip in M3 (c2s frame #1)
    client, server, wire = _mk(suite, trust, a_sk, b_sk)
    wire.add_fault("c2s", 1, flip_handshake_field(TAG_SIG_C))
    run_handshake(client, server, wire)
    check("T3", "sig_C", sid, "bit-flip sig_C -> AuthenticationFailure at server",
          "server:AuthenticationFailure",
          f"server:{server.failure_category}",
          server.failure_category == "AuthenticationFailure")


def _mk(suite, trust, a_sk, b_sk, **kw):
    client, server, wire = make_channels(suite.suite_id, trust, a_sk, b_sk, **kw)
    return client, server, wire


# ---------------------------------------------------------------------------
# T4/T5 - record-layer flips (ciphertext / tag / header AAD / direction)
# ---------------------------------------------------------------------------

def t4_t5(suite, trust, a_sk, b_sk) -> None:
    sid = suite.suite_id
    cases = [
        ("T4", "record_ct", lambda i: flip_record_byte(rec.HEADER_LEN),
         "server", "RecordAuthenticationError"),
        ("T5", "gcm_tag", lambda i: flip_record_byte(-1),
         "server", "RecordAuthenticationError"),
        ("T5", "header_version", lambda i: flip_record_byte(0),
         "server", "RecordAuthenticationError"),
        ("T5", "header_direction", lambda i: flip_record_byte(3),
         "server", "TranscriptBindingError"),
    ]
    for tid, label, fault, side, expected in cases:
        client, server, wire = _mk(suite, trust, a_sk, b_sk)
        run_handshake(client, server, wire)
        idx = wire.counts["c2s"]  # next app record index (dynamic)
        wire.add_fault("c2s", idx, fault(idx))
        client.send(b"tamper-test")
        wire.pump(client, server)
        cat = server.failure_category or f"no-failure(state={server.state})"
        withheld = server.recv() is None
        ok = server.failure_category == expected and withheld
        check(tid, label, sid, f"record tamper ({label}) rejected, plaintext withheld",
              f"server:{expected},plaintext-withheld",
              f"server:{cat},withheld={withheld}", ok, server.failure_detail or "")


# ---------------------------------------------------------------------------
# T6 - untrusted identity (attacker with own valid key) rejected at lookup
# ---------------------------------------------------------------------------

def t6(suite, trust, a_sk, b_sk) -> None:
    sid = suite.suite_id
    _atk_vk, atk_sk = sig_generate(suite)
    client, server, wire = make_channels(
        sid, trust, atk_sk, b_sk,
        client_identity="client:mallory")
    run_handshake(client, server, wire)
    detail = server.failure_detail or ""
    ok = (server.failure_category == "UntrustedIdentity"
          and not server.established and not client.established)
    check("T6", "attacker-id", sid,
          "attacker identity + own valid key -> UntrustedIdentity at trust-store "
          "lookup, before any signature math",
          "server:UntrustedIdentity", f"server:{server.failure_category}", ok, detail)


# ---------------------------------------------------------------------------
# T7 - role swap + old-signature splice
# ---------------------------------------------------------------------------

def t7(suite, trust, id_paths, a_sk, b_sk) -> None:
    sid = suite.suite_id
    # (a) role swap: bob initiates as "client" using his genuine key
    bob_sk = load_identity_private_keys(id_paths["bob"], suite)
    client, server, wire = make_channels(
        sid, trust, bob_sk, b_sk, client_identity="server:bob")
    run_handshake(client, server, wire)
    ok = (server.failure_category == "UntrustedIdentity"
          and not server.established)
    check("T7", "a-role-swap", sid,
          "role swap (server:bob initiates as client) -> rejected at lookup",
          "server:UntrustedIdentity", f"server:{server.failure_category}", ok,
          server.failure_detail or "")

    # (b) genuine old sig_S spliced into a fresh session
    _c, _s, wire_a = _mk(suite, trust, a_sk, b_sk)
    run_handshake(_c, _s, wire_a)
    m2_a = next(f for d, i, f in wire_a.log if d == "s2c" and i == 0)
    old_sig = extract_field(m2_a, TAG_SIG_S)

    client, server, wire_b = _mk(suite, trust, a_sk, b_sk)
    wire_b.add_fault("s2c", 0, substitute_handshake_field(TAG_SIG_S, old_sig))
    run_handshake(client, server, wire_b)
    ok = (client.failure_category == "AuthenticationFailure"
          and not client.established and not server.established)
    check("T7", "b-sig-splice", sid,
          "genuine old sig_S spliced into a fresh session -> transcript binding rejects",
          "client:AuthenticationFailure", f"client:{client.failure_category}", ok,
          client.failure_detail or "")


# ---------------------------------------------------------------------------
# T8 - replay: app record, full handshake, M1 replay w/ cache
# ---------------------------------------------------------------------------

def t8(suite, trust, a_sk, b_sk) -> None:
    sid = suite.suite_id
    # (a) app-record replay: byte-identical duplicate arrives at the receiver
    client, server, wire = _mk(suite, trust, a_sk, b_sk)
    run_handshake(client, server, wire)
    idx = wire.counts["c2s"]
    wire.add_fault("c2s", idx, duplicate_frame())
    client.send(b"replay-me")
    wire.pump(client, server)
    got = server.recv()
    ok = (server.failure_category == "RecordReplayDetected" and got == b"replay-me")
    check("T8", "a-record-replay", sid,
          "byte-identical app-record replay -> RecordReplayDetected before decrypt",
          "server:RecordReplayDetected,first-copy-delivered",
          f"server:{server.failure_category},first-copy={got!r}", ok,
          server.failure_detail or "")

    # (b) full old-session replay against a fresh server (no cache)
    _c, _s, wire_a = _mk(suite, trust, a_sk, b_sk)
    run_handshake(_c, _s, wire_a)
    old_m1 = next(f for d, i, f in wire_a.log if d == "c2s" and i == 0)
    old_m3 = next(f for d, i, f in wire_a.log if d == "c2s" and i == 1)

    wire_b = InMemoryWire()
    server_b = ServerChannel(
        suite_id=sid, trust_store=trust, identity="server:bob", sign_sk=b_sk,
        endpoint=wire_b.server_ep, enable_handshake_cache=False)
    server_b.on_frame(old_m1)          # fresh M2' generated (fresh nonce_S/ct/sig_S)
    server_b.on_frame(old_m3)          # replayed sig_C/fin_C are over a different T3
    ok = (server_b.failure_category == "AuthenticationFailure"
          and not server_b.established)
    check("T8", "b-handshake-replay", sid,
          "full old-session replay -> fails at M3 verification",
          "server:AuthenticationFailure", f"server:{server_b.failure_category}", ok,
          server_b.failure_detail or "")

    # (c) M1 replay with the (id_C, nonce_C) deployment cache shared across connections
    shared_cache: OrderedDict = OrderedDict()
    s1 = ServerChannel(suite_id=sid, trust_store=trust, identity="server:bob",
                       sign_sk=b_sk, endpoint=Endpoint("s1"),
                       handshake_cache=shared_cache)
    s1.on_frame(old_m1)  # first connection: accepted, cached
    s2 = ServerChannel(suite_id=sid, trust_store=trust, identity="server:bob",
                       sign_sk=b_sk, endpoint=Endpoint("s2"),
                       handshake_cache=shared_cache)
    s2.on_frame(old_m1)  # second connection, same M1 bytes: cache hit
    ok = s2.failure_category == "HandshakeReplayDetected"
    check("T8", "c-m1-replay-cache", sid,
          "M1 replay with (id_C, nonce_C) freshness cache -> HandshakeReplayDetected",
          "server:HandshakeReplayDetected", f"server:{s2.failure_category}", ok,
          s2.failure_detail or "")


# ---------------------------------------------------------------------------
# T9 - suite policy violations (before any crypto)
# ---------------------------------------------------------------------------

def t9(suite, other_suite, trust, a_sk, b_sk) -> None:
    sid = suite.suite_id
    # (a) unknown suite id on the wire
    client, server, wire = _mk(suite, trust, a_sk, b_sk)
    wire.add_fault("c2s", 0, substitute_handshake_field(TAG_SUITE_ID, b"QFF26-BOGUS-1"))
    run_handshake(client, server, wire)
    check("T9", "a-unknown-suite", sid,
          "unknown suite_id -> PolicyViolation before any crypto",
          "server:PolicyViolation", f"server:{server.failure_category}",
          server.failure_category == "PolicyViolation", server.failure_detail or "")

    # (b) server echo substituted to the other VALID suite; client policy allows one.
    # The client must reject the echoed suite via LOCAL POLICY - no fallback to
    # whatever the wire carried. (M1-side substitution is covered by T2/suite_id.)
    other_id = other_suite.suite_id.encode()
    client, server, wire = _mk(suite, trust, a_sk, b_sk,
                               client_allowed=frozenset([sid]),
                               server_allowed=frozenset(SUITES.keys()))
    wire.add_fault("s2c", 0, substitute_handshake_field(TAG_SUITE_ID, other_id))
    run_handshake(client, server, wire)
    ok = (client.failure_category == "PolicyViolation"
          and not client.established and not server.established)
    check("T9", "b-suite-echo-substitution", sid,
          "M2 echoes a different VALID suite -> client local policy rejects, no fallback",
          "client:PolicyViolation,no-establishment",
          f"client:{client.failure_category},established={client.established or server.established}",
          ok, client.failure_detail or "")


# ---------------------------------------------------------------------------

def write_csv() -> Path:
    out = REPO_ROOT / "results" / "security_tests.csv"
    out.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = ["test_id", "sub", "suite", "scenario", "expected", "observed",
                  "status", "detail", "timestamp_utc"]
    with open(out, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(ROWS)
    return out


def main() -> None:
    t0 = time.perf_counter()
    print("QFF 2026 PS-P1 security test battery T1-T9 (wire-level fault injection)")
    trust, id_paths = load_context()
    ensure_payloads()

    for suite, other in [(QFF26_PQC_1, QFF26_CLASSICAL_1),
                         (QFF26_CLASSICAL_1, QFF26_PQC_1)]:
        a_sk = load_identity_private_keys(id_paths["alice"], suite)
        b_sk = load_identity_private_keys(id_paths["bob"], suite)
        print(f"\n== suite {suite.suite_id} ({suite.kem_name} + {suite.sig_name}) ==")
        t1(suite, trust, a_sk, b_sk)
        t2(suite, trust, a_sk, b_sk)
        t3(suite, trust, a_sk, b_sk)
        t4_t5(suite, trust, a_sk, b_sk)
        t6(suite, trust, a_sk, b_sk)
        t7(suite, trust, id_paths, a_sk, b_sk)
        t8(suite, trust, a_sk, b_sk)
        t9(suite, other, trust, a_sk, b_sk)

    out = write_csv()
    elapsed = time.perf_counter() - t0
    total = len(ROWS)
    print(f"\n{'ALL TESTS PASSED' if _FAILURES == 0 else 'FAILURES PRESENT'}: "
          f"{total - _FAILURES}/{total} checks in {elapsed:.2f}s")
    print(f"results written to {out.relative_to(REPO_ROOT)}")
    sys.exit(0 if _FAILURES == 0 else 1)


if __name__ == "__main__":
    main()

QFF_IMPL_EOF
ok "written"

say "Writing cli/__init__.py"
mkdir -p "$REPO/cli"
cat > "$REPO/cli/__init__.py" <<'QFF_IMPL_EOF'

QFF_IMPL_EOF
ok "written"

say "Writing cli/adapter.py"
mkdir -p "$REPO/cli"
cat > "$REPO/cli/adapter.py" <<'QFF_IMPL_EOF'
"""Reference façade for the UX layer (docs/INTEGRATION_CONTRACT.md section 4).

The UX layer NEVER touches private keys, shared secrets, or traffic keys: this
façade loads key material internally from identities/ and exposes only
open / send / recv / close plus typed failure categories (invariants I1-I5).
"""
from __future__ import annotations

import json
from pathlib import Path

from protocol.channels import ClientChannel, ServerChannel
from protocol.errors import ChannelError
from protocol.suites import (
    DEFAULT_ALLOWED,
    load_identity_private_keys,
    load_trust_store,
)


class SecureChannelFacade:
    """One façade instance per endpoint role. UX-visible surface only."""

    def __init__(
        self,
        role: str,
        identity: str,
        suite_id: str,
        *,
        trust_store_path: str | Path = "trust_store.json",
        identities_dir: str | Path = "identities",
        allowed_suites: frozenset[str] | set[str] = DEFAULT_ALLOWED,
    ) -> None:
        if role not in ("client", "server"):
            raise ValueError("role must be 'client' or 'server'")
        self.role = role
        self.identity = identity
        self.suite_id = suite_id
        self._trust = load_trust_store(Path(trust_store_path))
        if identity not in self._trust.get("identities", {}):
            raise ChannelError(f"identity '{identity}' is not pinned in the trust store")
        name = identity.split(":", 1)[1]
        idir = Path(identities_dir)
        # per-suite signing key stays encapsulated inside the façade
        from protocol.suites import SUITES
        self._sign_sk = load_identity_private_keys(idir / f"{name}.json", SUITES[suite_id])
        self._allowed = frozenset(allowed_suites)
        self._channel = None

    def open(self, endpoint) -> "SecureChannelFacade":
        """Perform the handshake over the given wire endpoint."""
        common = dict(
            suite_id=self.suite_id,
            trust_store=self._trust,
            identity=self.identity,
            sign_sk=self._sign_sk,
            endpoint=endpoint,
            allowed_suites=self._allowed,
        )
        if self.role == "client":
            self._channel = ClientChannel(**common)
            self._channel.start()
        else:
            self._channel = ServerChannel(**common)
        return self

    def accept_frame(self, frame: bytes) -> None:
        """Feed one wire frame into the channel (wire adapters call this)."""
        self._require_channel().on_frame(frame)

    def send(self, data: bytes) -> None:
        self._require_channel().send(data)

    def recv(self) -> bytes | None:
        return self._require_channel().recv()

    def close(self) -> None:
        self._require_channel().close()

    # metadata-only introspection (invariant I4)
    @property
    def state(self) -> str | None:
        return self._channel.state if self._channel else None

    @property
    def failure_category(self) -> str | None:
        return self._channel.failure_category if self._channel else None

    @property
    def established(self) -> bool:
        return self._channel.established if self._channel else False

    def _require_channel(self):
        if self._channel is None:
            raise ChannelError("open() must be called first")
        return self._channel

QFF_IMPL_EOF
ok "written"

say "Writing cli/demo.py"
mkdir -p "$REPO/cli"
cat > "$REPO/cli/demo.py" <<'QFF_IMPL_EOF'
"""End-to-end demo: python -m cli.demo --suite QFF26-PQC-1

Runs both endpoints in-process over the in-memory wire and prints METADATA
ONLY output (states, sizes, suite id, failure categories) - invariant I4:
never keys, never plaintext of failed records.

Requires provisioning: python scripts/provision_identities.py
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from cli.adapter import SecureChannelFacade  # noqa: E402
from protocol.suites import SUITES  # noqa: E402
from protocol.wire import InMemoryWire  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--suite", default="QFF26-PQC-1", choices=sorted(SUITES))
    args = parser.parse_args()

    if not (REPO_ROOT / "trust_store.json").exists():
        sys.exit("trust store missing - run: python scripts/provision_identities.py")

    wire = InMemoryWire()
    client = SecureChannelFacade("client", "client:alice", args.suite).open(wire.client_ep)
    server = SecureChannelFacade("server", "server:bob", args.suite).open(wire.server_ep)
    print(f"[demo] suite={args.suite} (local policy, no online negotiation)")

    def pump() -> None:
        wire.pump(client._channel, server._channel)  # façade-internal plumbing

    pump()
    print(f"[demo] client state={client.state} | server state={server.state}")
    if not client.established:
        sys.exit(f"[demo] handshake failed: {client.failure_category}: "
                 f"{client._channel.failure_detail}")

    message = b"Hello from Alice - post-quantum channel is live."
    client.send(message)
    pump()
    received = server.recv()
    print(f"[demo] c2s: sent {len(message)} B, received {len(received)} B, "
          f"match={received == message}")

    reply = b"Hello from Bob - authenticated and encrypted both ways."
    server.send(reply)
    pump()
    got_reply = client.recv()
    print(f"[demo] s2c: sent {len(reply)} B, received {len(got_reply)} B, "
          f"match={got_reply == reply}")

    client.close()
    pump()
    print(f"[demo] authenticated close -> client={client.state}, server={server.state}")
    print(f"[demo] exporter label available for audit: {len(client._channel.exporter)} B "
          "(value never displayed)")


if __name__ == "__main__":
    main()

QFF_IMPL_EOF
ok "written"

say "Writing bench/__init__.py"
mkdir -p "$REPO/bench"
cat > "$REPO/bench/__init__.py" <<'QFF_IMPL_EOF'

QFF_IMPL_EOF
ok "written"

say "Writing bench/bench_handshake.py"
mkdir -p "$REPO/bench"
cat > "$REPO/bench/bench_handshake.py" <<'QFF_IMPL_EOF'
"""Handshake latency benchmark (kit requirement: >=10 handshakes, median/IQR/p95).

    python bench/bench_handshake.py [--runs 15] [--runs-classical 15]

Ephemeral signing keys + a matching ephemeral trust store are generated per
invocation (handshake cost is representative; provisioning is not required).
Results are written to results/tables/bench_handshake.csv and printed.
"""
from __future__ import annotations

import argparse
import base64
import csv
import statistics
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from protocol.suites import QFF26_CLASSICAL_1, QFF26_PQC_1, sig_generate  # noqa: E402
from tests.harness import make_channels, run_handshake  # noqa: E402


def percentile(sorted_values: list[float], p: float) -> float:
    """Linear-interpolated percentile."""
    if not sorted_values:
        return float("nan")
    k = (len(sorted_values) - 1) * p / 100.0
    f = int(k)
    c = min(f + 1, len(sorted_values) - 1)
    return sorted_values[f] + (sorted_values[c] - sorted_values[f]) * (k - f)


def ephemeral_trust(suite, a_vk: bytes, b_vk: bytes) -> dict:
    b64 = base64.b64encode
    return {
        "version": 1,
        "identities": {
            "client:alice": {"role": "client",
                             "keys": {suite.suite_id: b64(a_vk).decode()}},
            "server:bob": {"role": "server",
                           "keys": {suite.suite_id: b64(b_vk).decode()}},
        },
    }


def bench_suite(suite, runs: int) -> dict:
    a_sk, a_vk = sig_generate(suite)
    b_sk, b_vk = sig_generate(suite)
    trust = ephemeral_trust(suite, a_vk, b_vk)
    samples_ms: list[float] = []
    for i in range(runs):
        client, server, wire = make_channels(suite.suite_id, trust, a_sk, b_sk)
        t0 = time.perf_counter()
        run_handshake(client, server, wire)
        dt_ms = (time.perf_counter() - t0) * 1000.0
        if not (client.established and server.established):
            raise SystemExit(
                f"handshake {i} failed: client={client.failure_detail} "
                f"server={server.failure_detail}"
            )
        samples_ms.append(dt_ms)
    s = sorted(samples_ms)
    q25, q75 = percentile(s, 25), percentile(s, 75)
    return {
        "suite": suite.suite_id,
        "runs": runs,
        "median_ms": round(statistics.median(s), 3),
        "iqr_ms": round(q75 - q25, 3),
        "p95_ms": round(percentile(s, 95), 3),
        "min_ms": round(s[0], 3),
        "max_ms": round(s[-1], 3),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runs", type=int, default=15, help="handshakes per suite (>=10)")
    args = parser.parse_args()
    if args.runs < 10:
        print("kit requires >=10 handshakes; forcing runs=10")
        args.runs = 10

    rows = [bench_suite(QFF26_PQC_1, args.runs), bench_suite(QFF26_CLASSICAL_1, args.runs)]

    out = REPO_ROOT / "results" / "tables" / "bench_handshake.csv"
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    print(f"handshake latency ({args.runs} runs per suite, in-process wire):")
    header = f"{'suite':<20}{'median':>10}{'IQR':>10}{'p95':>10}{'min':>10}{'max':>10}"
    print(header)
    for r in rows:
        print(f"{r['suite']:<20}{r['median_ms']:>9.2f}ms{r['iqr_ms']:>9.2f}ms"
              f"{r['p95_ms']:>9.2f}ms{r['min_ms']:>9.2f}ms{r['max_ms']:>9.2f}ms")
    print(f"results written to {out.relative_to(REPO_ROOT)}")


if __name__ == "__main__":
    main()

QFF_IMPL_EOF
ok "written"

say "Writing bench/bench_payload.py"
mkdir -p "$REPO/bench"
cat > "$REPO/bench/bench_payload.py" <<'QFF_IMPL_EOF'
"""Payload throughput benchmark (1KB / 100KB / 10MB, both directions, both suites).

    python bench/bench_payload.py [--repeats 5]

Results are written to results/tables/bench_payload.csv and printed.
"""
from __future__ import annotations

import argparse
import base64
import csv
import statistics
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from protocol.suites import QFF26_CLASSICAL_1, QFF26_PQC_1, sig_generate  # noqa: E402
from tests.run_security_tests import PAYLOADS, gen_payload  # noqa: E402
from tests.harness import make_channels, run_handshake  # noqa: E402


def ephemeral_trust(suite, a_vk: bytes, b_vk: bytes) -> dict:
    b64 = base64.b64encode
    return {
        "version": 1,
        "identities": {
            "client:alice": {"role": "client",
                             "keys": {suite.suite_id: b64(a_vk).decode()}},
            "server:bob": {"role": "server",
                           "keys": {suite.suite_id: b64(b_vk).decode()}},
        },
    }


def bench_pair(suite, data: bytes, repeats: int) -> tuple[float, float]:
    """Returns (c2s MB/s median, s2c MB/s median) over `repeats` transfers."""
    a_sk, a_vk = sig_generate(suite)
    b_sk, b_vk = sig_generate(suite)
    trust = ephemeral_trust(suite, a_vk, b_vk)
    client, server, wire = make_channels(suite.suite_id, trust, a_sk, b_sk)
    run_handshake(client, server, wire)
    if not (client.established and server.established):
        raise SystemExit("handshake failed in bench_payload")
    mb = len(data) / (1024.0 * 1024.0)

    c2s_rates: list[float] = []
    for _ in range(repeats):
        t0 = time.perf_counter()
        client.send(data)
        wire.pump(client, server)
        got = server.recv()
        if got != data:
            raise SystemExit("payload mismatch in bench")
        c2s_rates.append(mb / (time.perf_counter() - t0))

    s2c_rates: list[float] = []
    for _ in range(repeats):
        t0 = time.perf_counter()
        server.send(data)
        wire.pump(client, server)
        got = client.recv()
        if got != data:
            raise SystemExit("payload mismatch in bench")
        s2c_rates.append(mb / (time.perf_counter() - t0))

    return statistics.median(c2s_rates), statistics.median(s2c_rates)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repeats", type=int, default=5)
    args = parser.parse_args()

    rows = []
    for suite in (QFF26_PQC_1, QFF26_CLASSICAL_1):
        for name, size in PAYLOADS:
            data = gen_payload(size)
            c2s, s2c = bench_pair(suite, data, args.repeats)
            rows.append({
                "suite": suite.suite_id, "payload": name, "bytes": size,
                "repeats": args.repeats,
                "c2s_mb_s": round(c2s, 2), "s2c_mb_s": round(s2c, 2),
            })
            print(f"  {suite.suite_id:<20}{name:<18}{size:>10} B  "
                  f"c2s {c2s:8.1f} MB/s   s2c {s2c:8.1f} MB/s")

    out = REPO_ROOT / "results" / "tables" / "bench_payload.csv"
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
    print(f"results written to {out.relative_to(REPO_ROOT)}")


if __name__ == "__main__":
    main()

QFF_IMPL_EOF
ok "written"

say "Writing scripts/provision_identities.py"
mkdir -p "$REPO/scripts"
cat > "$REPO/scripts/provision_identities.py" <<'QFF_IMPL_EOF'
#!/usr/bin/env python3
"""Provision local identities and the pinned trust store (design v2 section 1).

Generates fresh signing keypairs for client:alice and server:bob for BOTH
suites, writes private key files into identities/ (git-ignored - nothing
secret is ever committed) and the public trust_store.json at the repo root.

    python scripts/provision_identities.py [--force]

trust_store.json maps identity -> {role, verification keys per suite}.
Verification keys NEVER travel on the wire; verifiers look up pinned keys.
This tool prints metadata only - private key bytes are never displayed.
"""
from __future__ import annotations

import argparse
import base64
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from cryptography.hazmat.primitives.asymmetric import ed25519, mldsa  # noqa: E402

IDENTITIES = [
    ("alice", "client:alice", "client"),
    ("bob", "server:bob", "server"),
]


def b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--force", action="store_true", help="overwrite existing identity files")
    parser.add_argument(
        "--identities-dir", default=str(REPO_ROOT / "identities"),
        help="output directory for private identity files (default: identities/)",
    )
    parser.add_argument(
        "--trust-store", default=str(REPO_ROOT / "trust_store.json"),
        help="output path for the public trust store (default: trust_store.json)",
    )
    args = parser.parse_args()

    idir = Path(args.identities_dir)
    idir.mkdir(parents=True, exist_ok=True)

    trust: dict = {"version": 1, "identities": {}}

    for name, identity, role in IDENTITIES:
        path = idir / f"{name}.json"
        if path.exists() and not args.force:
            print(f"  keep existing {path} (use --force to regenerate)")
            data = json.loads(path.read_text(encoding="utf-8"))
        else:
            m = mldsa.MLDSA65PrivateKey.generate()
            e = ed25519.Ed25519PrivateKey.generate()
            data = {
                "identity": identity,
                "role": role,
                "mldsa65_private_b64": b64(m.private_bytes_raw()),
                "mldsa65_public_b64": b64(m.public_key().public_bytes_raw()),
                "ed25519_private_b64": b64(e.private_bytes_raw()),
                "ed25519_public_b64": b64(e.public_key().public_bytes_raw()),
            }
            path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
            print(f"  wrote {path} (private - git-ignored)")
        trust["identities"][identity] = {
            "role": data["role"],
            "keys": {
                "QFF26-PQC-1": data["mldsa65_public_b64"],
                "QFF26-CLASSICAL-1": data["ed25519_public_b64"],
            },
        }

    tpath = Path(args.trust_store)
    tpath.write_text(json.dumps(trust, indent=2) + "\n", encoding="utf-8")
    print(f"  wrote {tpath} (public trust anchor - committed)")
    print("provisioning complete: 2 identities, 2 suites each; no secrets printed or committed")


if __name__ == "__main__":
    main()

QFF_IMPL_EOF
ok "written"

say "Writing README.md"
mkdir -p "$REPO/"
cat > "$REPO/README.md" <<'QFF_IMPL_EOF'
# QFF 2026 PS-P1 — Quantum-Safe Secure Communication Channel (Phase 2)

Track 5 · Qiskit Fall Fest 2026 · **PS-P1: Quantum-Safe Secure Communication Channel**

A hybrid-ready authenticated secure channel with **two complete protocol suites behind ONE
state machine**, automated wire-level attack testing (T1–T9), and byte-exact official
payload verification:

| Suite | KEM | Signature | KDF | AEAD |
|---|---|---|---|---|
| `QFF26-PQC-1` | **ML-KEM-768** (FIPS 203) | **ML-DSA-65** (FIPS 204) | HKDF-SHA256 (RFC 5869) | AES-256-GCM |
| `QFF26-CLASSICAL-1` | X25519 | Ed25519 | HKDF-SHA256 | AES-256-GCM |

Suite selection is **local policy on both endpoints and is never negotiated on the wire** —
there is no downgrade path. Directional keys (`QFF26 c2s` / `QFF26 s2c` labels preserved and
strengthened with transcript-hash binding), directional 12 B nonce bases, and an exporter
secret are derived from a fixed, acyclic schedule: `ss → sig_S → TH2 → PRK → fk → fin_S →
sig_C → TH3 → fin_C → TH4 → traffic keys`.

## Security properties (full analysis in the technical report)

- **Mutual authentication** against a pinned trust store (`trust_store.json`). Verification
  keys never travel on the wire; an unknown identity fails at lookup **before any signature
  math** (T6). Roles are enforced by trust-store labels and transcript tag positions (T7a).
- **Canonical TLV transcript** — signatures cover identities, roles, version, suite ids,
  both nonces, and all exchanged key material; no signature covers itself (T2, T3, T7b).
- **Replay defenses at both layers**: handshake freshness via client nonce inside `sig_S`
  plus an `(id_C, nonce_C)` server cache as hygiene (T8b/T8c); record layer via a
  per-direction sliding window + watermark checked **before decryption** — GCM alone is
  explicitly documented as NOT a replay defense (T8a).
- **AES-256-GCM record layer**: 16 B header (always AAD), 32 B total per-record overhead,
  nonce = nonce_base ⊕ seq (injective; reuse structurally excluded), authenticated close
  records, session caps → `SessionExhausted`.
- Fixed verification order `policy → trust lookup → signature → Finished`; every failure is
  a typed error (`PolicyViolation`, `UntrustedIdentity`, `AuthenticationFailure`,
  `TranscriptBindingError`, `HandshakeReplayDetected`, `RecordReplayDetected`,
  `RecordAuthenticationError`, `SessionExhausted`); no code path falls back to a weaker
  suite; ephemeral secrets are zeroized on terminal states (best effort — prototype note).

## Repository layout

```
common/env_check.py          kit environment contract -> READY + platform_A_info.json
protocol/                    TLV wire format, suites, key schedule, record layer,
                             Client/Server state machines, in-memory wire
cli/                         UX façade (docs/INTEGRATION_CONTRACT.md) + demo
tests/harness.py             wire-level fault injectors (flip/duplicate/substitute/splice)
tests/run_security_tests.py  T1–T9 battery -> results/security_tests.csv
bench/                       handshake + payload benchmarks -> results/tables/*.csv
scripts/provision_identities.py   generates identities/ (git-ignored) + trust_store.json
docs/INTEGRATION_CONTRACT.md security invariants for the UX layer
data/payloads/               official payloads (regenerated locally; *.bin not committed)
Phase One/                   archived Phase 1 submission (untouched)
```

## Quickstart (judge reproduction path)

Requirements: Python **3.10–3.13** (validated on 3.13.17), pip/uv. `cryptography==50.0.2`
is the kit pin and must not change.

```bash
git clone https://github.com/Devo982/SRM-Qiskit-FF-PS-P1.git
cd SRM-Qiskit-FF-PS-P1
python3 -m venv .venv && source .venv/bin/activate      # or: uv venv .venv
pip install -r requirements.txt

python common/env_check.py                # -> READY - environment is correct.
python scripts/provision_identities.py    # identities/ + trust_store.json (one command)
python -m tests.run_security_tests        # T1-T9, single command
python -m cli.demo --suite QFF26-PQC-1    # end-to-end demo (metadata-only output)
python bench/bench_handshake.py --runs 15 # median / IQR / p95 per suite
python bench/bench_payload.py             # 1KB / 100KB / 10MB throughput
```

Expected: `ALL TESTS PASSED: 50/50 checks` (25 checks × 2 suites) and
`results/security_tests.csv` written. The test battery asserts via **public confirmation
status only** (states, failure categories, sizes) — key bytes are never printed.

> **Intel macOS note.** `cryptography==50.0.2` publishes no macOS x86_64 wheel, so on Intel
> Macs pip builds it from sdist against a local static OpenSSL (see
> `scripts/QFF2026_intel_mac_env_setup.sh`; `source ~/.qff26-openssl-env.sh` first). Every
> other platform (Linux, Windows, Apple Silicon) installs the prebuilt wheel directly.
> `platform_A_info.json` records the honest install origin of this machine.

## T1–T9 (all faults injected on the wire between two real endpoints)

| ID | Scenario | Expected |
|----|----------|----------|
| T1 | honest handshake; 3 official payloads (1KB/100KB/10MB) both directions; byte + SHA-256 vs committed `payload_sha256.txt`; authenticated close | success, ESTABLISHED, 6/6 verified |
| T2 | parametrized bit-flips: kem_pk_C, kem_ct, nonce_C, nonce_S, id_C, id_S, version, suite_id | abort at the step that owns the field; keys never established |
| T3 | bit-flip sig_S / sig_C | `AuthenticationFailure` |
| T4 | bit-flip record ciphertext | `RecordAuthenticationError`, plaintext withheld |
| T5 | bit-flip GCM tag / header (AAD, direction) | typed rejection before/with decryption failure |
| T6 | attacker identity + own valid key | `UntrustedIdentity` at lookup, before signature math |
| T7 | (a) role swap with genuine key, (b) genuine old sig_S spliced into a fresh session | transcript/identity binding rejects both |
| T8 | (a) app-record replay, (b) full old-session replay, (c) M1 replay with cache | `RecordReplayDetected` / `AuthenticationFailure` / `HandshakeReplayDetected` |
| T9 | (a) unknown suite_id, (b) echoed suite substituted to the other valid suite | `PolicyViolation` before any crypto; no fallback |

## Prototype status and assumptions

This is a competition prototype, not a production library. Stated assumptions: trust-store
distribution/integrity is out-of-band; the OS CSPRNG is trusted; no side-channel
hardening; DoS resistance out of scope; single trust domain; identity-key compromise breaks
future impersonation resistance, not past session confidentiality (fresh KEM keypair per
session; best-effort zeroization — Python cannot guarantee memory hygiene); single
in-process wire for tests/benchmarks (the same frames a socket transport would carry);
auto-renegotiation after `SessionExhausted` is documented but not automated.

QFF_IMPL_EOF
ok "written"

say "7/6 Move Intel-mac env script into scripts/ (keep repo root clean)"
if [[ -f QFF2026_intel_mac_env_setup.sh ]]; then
  git mv QFF2026_intel_mac_env_setup.sh scripts/ 2>/dev/null || mv QFF2026_intel_mac_env_setup.sh scripts/
  ok "moved to scripts/"
else
  ok "already in place"
fi

say "8/6 Provision identities + trust store"
"$PY" scripts/provision_identities.py

say "8b/6 SAFETY: private identities must NEVER be committable (defense in depth)"
if ! git check-ignore -q identities/alice.json 2>/dev/null; then
  printf '\n# Private identity material - NEVER commit\nidentities/\n' >> .gitignore
  git check-ignore -q identities/alice.json || { echo "FATAL: identities/ still not ignored"; exit 1; }
  ok "appended identities/ to .gitignore and verified with git check-ignore"
else
  ok "identities/ already git-ignored"
fi

say "9/6 Env check (kit contract)"
"$PY" common/env_check.py

say "10/6 Security test battery T1-T9 (single command)"
"$PY" -m tests.run_security_tests

say "11/6 Demo (metadata-only output)"
"$PY" -m cli.demo --suite QFF26-PQC-1

cat <<'DONE'

Implementation complete and verified. Commit:
  git add -A
  git status --short
  git commit -m "phase2: protocol suites, T1-T9 wire-level security tests, CLI adapter, benchmarks, README"
  git push origin main

Then optionally:
  python bench/bench_handshake.py --runs 15   # median/IQR/p95 per suite
  python bench/bench_payload.py               # payload throughput
DONE

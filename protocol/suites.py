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


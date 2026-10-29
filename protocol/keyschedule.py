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


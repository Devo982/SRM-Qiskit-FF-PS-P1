"""Key schedule and transcript hashes (design v2 sections 2-3).

All derivation uses the vetted `cryptography` HKDF (RFC 5869) and HMAC
primitives - no hand-rolled crypto. Output compatibility with the earlier
explicit implementation is pinned by tests/test_regressions.py: RFC 5869
Appendix A test vectors plus an independent-oracle cross-check over the exact
QFF26 label scheme below.

Derivation order is fixed and acyclic:

    ss -> sig_S -> TH2 -> [PRK] -> fk -> fin_S -> sig_C -> TH3 -> fin_C -> TH4
         -> c2s_key / s2c_key / nb_c2s / nb_s2c / exporter

PRK = HKDF-Extract(salt = TH2, IKM = ss) is performed inside the library's
HKDF; the raw PRK is never materialized. Every expansion is therefore
expressed as HKDF(salt = TH2, ikm = ss, info = <label> || <context>, len),
which is byte-identical to Extract(salt=TH2, ikm=ss) followed by
Expand(PRK, <label> || <context>, len).
"""
from __future__ import annotations

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import hmac as chmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

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


def _hkdf(salt: bytes, ikm: bytes, info: bytes, length: int) -> bytes:
    """One RFC 5869 extract+expand via the vetted library (SHA-256)."""
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info).derive(ikm)


def _hmac(key: bytes, data: bytes) -> bytes:
    """HMAC-SHA256 via the vetted library."""
    h = chmac.HMAC(key, hashes.SHA256())
    h.update(data)
    return h.finalize()


def sha256(data: bytes) -> bytes:
    d = hashes.Hash(hashes.SHA256())
    d.update(data)
    return d.finalize()


def transcript_hash_2(t3: bytes) -> bytes:
    """TH2 = H("QFF26-P1-TH2" || T2 || TLV(09, sig_S)) = H(TH2_LABEL || T3)."""
    return sha256(TH2_LABEL + t3)


def transcript_hash_3(t3: bytes, sig_c_tlv: bytes) -> bytes:
    """TH3 = H("QFF26-P1-TH3" || T3 || TLV(0A, sig_C))."""
    return sha256(TH3_LABEL + t3 + sig_c_tlv)


def transcript_hash_4(t3: bytes, sig_c_tlv: bytes, fin_c_tlv: bytes) -> bytes:
    """TH4 = H("QFF26-P1-TH4" || T3 || TLV(0A, sig_C) || TLV(0C, fin_C))."""
    return sha256(TH4_LABEL + t3 + sig_c_tlv + fin_c_tlv)


def finished_key(th2: bytes, shared_secret: bytes) -> bytes:
    """fk = HKDF-Expand(HKDF-Extract(salt=TH2, ikm=ss), "QFF26-P1 fin", 32)."""
    return _hkdf(th2, shared_secret, FIN_LABEL, 32)


def finished_server(fk: bytes, th2: bytes) -> bytes:
    """fin_S = HMAC(fk, "QFF26-P1 fin-S" || TH2)."""
    return _hmac(fk, FIN_S_LABEL + th2)


def finished_client(fk: bytes, th3: bytes) -> bytes:
    """fin_C = HMAC(fk, "QFF26-P1 fin-C" || TH3)."""
    return _hmac(fk, FIN_C_LABEL + th3)


def derive_traffic_keys(th2: bytes, shared_secret: bytes, th4: bytes) -> dict[str, bytes]:
    """Final stage: c2s/s2c 32 B keys, 12 B nonce bases, 32 B exporter.

    Kit quickstart labels QFF26 c2s / QFF26 s2c are preserved and strengthened
    with TH4 transcript binding.
    """
    return {
        "c2s_key": _hkdf(th2, shared_secret, C2S_LABEL + th4, 32),
        "s2c_key": _hkdf(th2, shared_secret, S2C_LABEL + th4, 32),
        "nb_c2s": _hkdf(th2, shared_secret, NB_C2S_LABEL + th4, 12),
        "nb_s2c": _hkdf(th2, shared_secret, NB_S2C_LABEL + th4, 12),
        "exporter": _hkdf(th2, shared_secret, EXPORT_LABEL + th4, 32),
    }


def zeroize(*byte_strings: bytes | bytearray | None) -> None:
    """Best-effort zeroization. Python cannot guarantee memory hygiene; this is
    a prototype defense-in-depth measure (documented limitation)."""
    for b in byte_strings:
        if isinstance(b, bytearray):
            for i in range(len(b)):
                b[i] = 0

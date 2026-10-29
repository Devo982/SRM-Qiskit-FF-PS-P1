"""Regression tests beyond the T1-T9 battery (run: python -m tests.test_regressions).

R1  RFC 5869 Appendix A test vectors (A.1, A.3) against the same vetted-library
    HKDF call pattern used by protocol.keyschedule.
R2  Independent-oracle cross-check: a self-contained RFC 5869 implementation
    written in THIS file (hmac/hashlib only) must reproduce every QFF26
    schedule output bit-for-bit - finished_key, fin_S/fin_C, and all traffic
    keys with the exact labels of design v2 (100 randomized trials).
R3  Replay-window commit-after-authentication: a forged record with a
    far-ahead sequence number and an invalid GCM tag must NOT mutate the
    persistent replay-window state, and a legitimate record with a lower
    valid sequence number must still be accepted afterwards.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import sys

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from protocol import keyschedule as ks
from protocol.records import (
    DIR_C2S,
    ReplayWindow,
    TYPE_APP_DATA,
    build_header,
    encrypt_record,
    open_record,
)

PASS = 0


def ok(name: str, detail: str = "") -> None:
    global PASS
    PASS += 1
    print(f"  [R] PASS {name}" + (f"  ({detail})" if detail else ""))


# ---------------------------------------------------------------------------
# Independent RFC 5869 oracle (deliberately implemented here, stdlib only)
# ---------------------------------------------------------------------------

def oracle_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def oracle_expand(prk: bytes, info: bytes, length: int) -> bytes:
    out, t, counter = b"", b"", 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        out += t
        counter += 1
    return out[:length]


def lib_hkdf(salt: bytes, ikm: bytes, info: bytes, length: int) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info).derive(ikm)


# ---------------------------------------------------------------------------
# R1: RFC 5869 Appendix A vectors (SHA-256)
# ---------------------------------------------------------------------------

def r1_rfc5869_vectors() -> None:
    # A.1: IKM=0x0b*22, salt=0x00..0c, info=0xf0..0xf9, L=42
    ikm = b"\x0b" * 22
    salt = bytes(range(0x00, 0x0D))
    info = bytes(range(0xF0, 0xFA))
    okm = lib_hkdf(salt, ikm, info, 42)
    assert okm.hex() == (
        "3cb25f25faacd57a90434f64d0362f2a"
        "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        "34007208d5b887185865"
    ), f"A.1 OKM mismatch: {okm.hex()}"
    # A.1 PRK (validates the oracle's extract against the published constant)
    assert oracle_extract(salt, ikm).hex() == (
        "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
    ), "A.1 PRK mismatch in oracle"
    # A.3: IKM=0x0b*22, salt empty, info empty, L=42
    okm3 = lib_hkdf(b"", ikm, b"", 42)
    assert okm3.hex() == (
        "8da4e775a563c18f715f802a063c5a31"
        "b8a11f5c5ee1879ec3454e5f3c738d2d"
        "9d201395faa4b61a96c8"
    ), f"A.3 OKM mismatch: {okm3.hex()}"
    assert oracle_extract(b"", ikm).hex() == (
        "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04"
    ), "A.3 PRK mismatch in oracle"
    ok("R1 RFC 5869 Appendix A vectors (A.1, A.3) match published OKM/PRK")


# ---------------------------------------------------------------------------
# R2: QFF26 schedule == independent oracle (bit-for-bit, 100 trials)
# ---------------------------------------------------------------------------

def r2_qff26_oracle_crosscheck() -> None:
    for trial in range(100):
        ss = os.urandom(32)
        th2 = os.urandom(32)
        th4 = os.urandom(32)
        prk = oracle_extract(th2, ss)

        # fk and Finished values
        assert ks.finished_key(th2, ss) == oracle_expand(prk, ks.FIN_LABEL, 32)
        fk = ks.finished_key(th2, ss)
        assert ks.finished_server(fk, th2) == hmac.new(
            fk, ks.FIN_S_LABEL + th2, hashlib.sha256
        ).digest()
        th3 = os.urandom(32)
        assert ks.finished_client(fk, th3) == hmac.new(
            fk, ks.FIN_C_LABEL + th3, hashlib.sha256
        ).digest()

        # traffic keys / nonce bases / exporter with the exact QFF26 labels
        keys = ks.derive_traffic_keys(th2, ss, th4)
        expected = {
            "c2s_key": oracle_expand(prk, ks.C2S_LABEL + th4, 32),
            "s2c_key": oracle_expand(prk, ks.S2C_LABEL + th4, 32),
            "nb_c2s": oracle_expand(prk, ks.NB_C2S_LABEL + th4, 12),
            "nb_s2c": oracle_expand(prk, ks.NB_S2C_LABEL + th4, 12),
            "exporter": oracle_expand(prk, ks.EXPORT_LABEL + th4, 32),
        }
        assert keys == expected, f"traffic-key mismatch at trial {trial}"
    ok("R2 QFF26 schedule bit-identical to independent RFC 5869 oracle (100 trials)")


# ---------------------------------------------------------------------------
# R3: replay-window state must never mutate on unauthenticated input
# ---------------------------------------------------------------------------

def r3_replay_window_commit_after_auth() -> None:
    key = os.urandom(32)
    nb = os.urandom(12)
    window = ReplayWindow()

    # Forged record: far-ahead sequence number (1000), garbage ciphertext
    # (invalid GCM tag). Must fail authentication AND leave the window intact.
    forged = build_header(TYPE_APP_DATA, DIR_C2S, 1000, 32) + os.urandom(32)
    try:
        open_record(key, nb, window, DIR_C2S, forged)
        raise AssertionError("forged far-ahead record was accepted")
    except Exception as exc:
        assert type(exc).__name__ == "RecordAuthenticationError", (
            f"expected RecordAuthenticationError, got {type(exc).__name__}"
        )
    assert window.watermark == 0 and window.bitmap == 0, (
        f"window mutated by forged record: watermark={window.watermark} bitmap={window.bitmap}"
    )

    # A legitimate record with a LOWER valid sequence number must still be
    # accepted after the forgery attempt.
    legit0 = encrypt_record(key, nb, TYPE_APP_DATA, DIR_C2S, 0, b"hello")
    seq0, _rtype, pt0 = open_record(key, nb, window, DIR_C2S, legit0)
    assert seq0 == 0 and pt0 == b"hello"
    assert window.bitmap == 1  # only seq 0 marked

    # Second forgery with a small forward gap (seq 5, invalid tag): still no
    # state mutation.
    forged2 = build_header(TYPE_APP_DATA, DIR_C2S, 5, 32) + os.urandom(32)
    try:
        open_record(key, nb, window, DIR_C2S, forged2)
        raise AssertionError("forged seq-5 record was accepted")
    except Exception as exc:
        assert type(exc).__name__ == "RecordAuthenticationError", type(exc).__name__
    assert window.bitmap == 1, f"window mutated by forged seq-5: bitmap={window.bitmap}"

    # Legitimate seq 1 still accepted; byte-identical replay of seq 0 still
    # rejected before decryption (T8a invariant at the record layer).
    legit1 = encrypt_record(key, nb, TYPE_APP_DATA, DIR_C2S, 1, b"world")
    seq1, _rtype, pt1 = open_record(key, nb, window, DIR_C2S, legit1)
    assert seq1 == 1 and pt1 == b"world"
    try:
        open_record(key, nb, window, DIR_C2S, legit0)
        raise AssertionError("byte-identical replay was accepted")
    except Exception as exc:
        assert type(exc).__name__ == "RecordReplayDetected", type(exc).__name__

    # Commit-time watermark advance still works for a genuinely far-ahead
    # AUTHENTICATED record (sender-side behavior), and older seqs then go stale.
    far = encrypt_record(key, nb, TYPE_APP_DATA, DIR_C2S, 100, b"jump")
    seq_far, _rtype, pt_far = open_record(key, nb, window, DIR_C2S, far)
    assert seq_far == 100 and pt_far == b"jump"
    assert window.watermark == 100 - 63
    ok(
        "R3 forged far-ahead seq cannot mutate window; legit lower seq accepted; "
        "commit-time advance preserved"
    )


def main() -> None:
    print("QFF 2026 PS-P1 regression tests (beyond T1-T9)")
    r1_rfc5869_vectors()
    r2_qff26_oracle_crosscheck()
    r3_replay_window_commit_after_auth()
    print(f"ALL REGRESSION TESTS PASSED: {PASS}/3 groups")
    print("results written to stdout only (no CSV - informational battery)")


if __name__ == "__main__":
    main()

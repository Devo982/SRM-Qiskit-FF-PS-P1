import pytest

from src.hybrid import derive_session_key
from src.transcript import encode_transcript, handshake_transcript


def test_hybrid_kdf_is_32_bytes_and_deterministic():
    transcript = handshake_transcript("hybrid", b"r-ec", b"r-kem", b"i-ec", b"ct")
    ecdh_secret = b"E" * 32
    mlkem_secret = b"M" * 32
    first = derive_session_key("hybrid", transcript, ecdh_secret, mlkem_secret)
    second = derive_session_key("hybrid", transcript, ecdh_secret, mlkem_secret)
    assert first == second
    assert len(first) == 32


def test_hybrid_kdf_requires_both_secrets():
    transcript = b"test"
    with pytest.raises(ValueError):
        derive_session_key("hybrid", transcript, ecdh_secret=b"E" * 32)
    with pytest.raises(ValueError):
        derive_session_key("hybrid", transcript, mlkem_secret=b"M" * 32)


def test_hybrid_kdf_binds_both_secrets_and_transcript():
    transcript = b"transcript-a"
    base = derive_session_key("hybrid", transcript, b"E" * 32, b"M" * 32)
    assert base != derive_session_key("hybrid", b"transcript-b", b"E" * 32, b"M" * 32)
    assert base != derive_session_key("hybrid", transcript, b"F" * 32, b"M" * 32)
    assert base != derive_session_key("hybrid", transcript, b"E" * 32, b"N" * 32)


def test_transcript_encoding_is_unambiguous_and_deterministic():
    a = encode_transcript([("x", b"ab"), ("y", b"c")])
    b = encode_transcript([("x", b"a"), ("y", b"bc")])
    assert a != b
    assert a == encode_transcript([("x", b"ab"), ("y", b"c")])


def test_transcript_binds_each_protocol_field():
    baseline = handshake_transcript("hybrid", b"r-ec", b"r-kem", b"i-ec", b"ct")
    assert baseline != handshake_transcript("hybrid", b"r-EC", b"r-kem", b"i-ec", b"ct")
    assert baseline != handshake_transcript("hybrid", b"r-ec", b"r-KEM", b"i-ec", b"ct")
    assert baseline != handshake_transcript("hybrid", b"r-ec", b"r-kem", b"i-EC", b"ct")
    assert baseline != handshake_transcript("hybrid", b"r-ec", b"r-kem", b"i-ec", b"CT")
    assert baseline != handshake_transcript("ecdh", b"r-ec", b"r-kem", b"i-ec", b"ct")


def test_distinct_suites_use_distinct_labels():
    transcript = b"same-transcript"
    secret = b"S" * 32
    ecdh_key = derive_session_key("ecdh", transcript, ecdh_secret=secret)
    mlkem_key = derive_session_key("mlkem", transcript, mlkem_secret=secret)
    hybrid_key = derive_session_key("hybrid", transcript, ecdh_secret=secret, mlkem_secret=secret)
    assert len({ecdh_key, mlkem_key, hybrid_key}) == 3

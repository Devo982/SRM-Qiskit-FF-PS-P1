import pytest

from src.handshake import run_handshake


def test_ecdh_full_handshake_and_payload():
    result = run_handshake("ecdh")
    assert result["key_match"] is True
    assert result["p256_public_key_bytes"] == 65
    assert result["total_payload_bytes"] == 130


def test_mlkem_full_handshake_and_payload():
    try:
        result = run_handshake("mlkem")
    except RuntimeError as exc:
        pytest.skip(f"ML-KEM native dependency unavailable in this test environment: {exc}")
    assert result["key_match"] is True
    assert result["mlkem_public_key_bytes"] == 1184
    assert result["mlkem_ciphertext_bytes"] == 1088
    assert result["total_payload_bytes"] == 2272


def test_hybrid_full_handshake_and_payload():
    try:
        result = run_handshake("hybrid")
    except RuntimeError as exc:
        pytest.skip(f"ML-KEM native dependency unavailable in this test environment: {exc}")
    assert result["key_match"] is True
    assert result["p256_public_key_bytes"] == 65
    assert result["mlkem_public_key_bytes"] == 1184
    assert result["mlkem_ciphertext_bytes"] == 1088
    assert result["total_payload_bytes"] == 2402

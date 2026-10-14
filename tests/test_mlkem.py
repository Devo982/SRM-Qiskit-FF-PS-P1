import pytest

from src.mlkem import (
    ALGORITHM,
    CIPHERTEXT_BYTES,
    PUBLIC_KEY_BYTES,
    SECRET_KEY_BYTES,
    SHARED_SECRET_BYTES,
    require_oqs,
)


def _oqs_or_skip():
    try:
        return require_oqs()
    except RuntimeError as exc:
        pytest.skip(f"ML-KEM native dependency unavailable in this test environment: {exc}")


def test_mlkem_768_key_exchange_and_sizes():
    oqs = _oqs_or_skip()
    with oqs.KeyEncapsulation(ALGORITHM) as responder:
        public_key = responder.generate_keypair()
        secret_key = responder.export_secret_key()
        with oqs.KeyEncapsulation(ALGORITHM) as initiator:
            ciphertext, initiator_secret = initiator.encap_secret(public_key)
        responder_secret = responder.decap_secret(ciphertext)

    assert len(public_key) == PUBLIC_KEY_BYTES == 1184
    assert len(secret_key) == SECRET_KEY_BYTES == 2400
    assert len(ciphertext) == CIPHERTEXT_BYTES == 1088
    assert len(initiator_secret) == SHARED_SECRET_BYTES == 32
    assert initiator_secret == responder_secret


def test_mlkem_ciphertext_mutation_does_not_preserve_shared_secret():
    oqs = _oqs_or_skip()
    with oqs.KeyEncapsulation(ALGORITHM) as responder:
        public_key = responder.generate_keypair()
        with oqs.KeyEncapsulation(ALGORITHM) as initiator:
            ciphertext, initiator_secret = initiator.encap_secret(public_key)
        mutated = bytes([ciphertext[0] ^ 0x01]) + ciphertext[1:]
        # ML-KEM uses implicit rejection: decapsulation may return a secret rather
        # than raising. The mutated ciphertext must not yield the original secret.
        altered_secret = responder.decap_secret(mutated)
    assert altered_secret != initiator_secret


def test_mlkem_implicit_rejection_changes_derived_session_key():
    from src.hybrid import derive_session_key
    from src.transcript import handshake_transcript

    oqs = _oqs_or_skip()
    with oqs.KeyEncapsulation(ALGORITHM) as responder:
        public_key = responder.generate_keypair()
        with oqs.KeyEncapsulation(ALGORITHM) as initiator:
            ciphertext, initiator_secret = initiator.encap_secret(public_key)
        mutated = bytes([ciphertext[0] ^ 0x01]) + ciphertext[1:]
        # Must not raise; ML-KEM implicitly rejects and returns a pseudorandom secret.
        altered_secret = responder.decap_secret(mutated)

    good_transcript = handshake_transcript("mlkem", None, public_key, None, ciphertext)
    bad_transcript = handshake_transcript("mlkem", None, public_key, None, mutated)
    good_key = derive_session_key("mlkem", good_transcript, mlkem_secret=initiator_secret)
    bad_key = derive_session_key("mlkem", bad_transcript, mlkem_secret=altered_secret)
    assert good_key != bad_key
    assert len(good_key) == 32 and len(bad_key) == 32

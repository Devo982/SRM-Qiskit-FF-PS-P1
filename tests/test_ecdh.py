import pytest

from src.ecdh import PUBLIC_KEY_BYTES, SHARED_SECRET_BYTES, exchange, generate_keypair, load_public_key, serialize_public_key


def test_ecdh_two_parties_agree_and_lengths_match():
    alice = generate_keypair()
    bob = generate_keypair()
    alice_public = serialize_public_key(alice)
    bob_public = serialize_public_key(bob)

    assert len(alice_public) == PUBLIC_KEY_BYTES == 65
    assert len(bob_public) == PUBLIC_KEY_BYTES == 65
    assert exchange(alice, bob_public) == exchange(bob, alice_public)
    assert len(exchange(alice, bob_public)) == SHARED_SECRET_BYTES == 32


def test_ecdh_rejects_bad_length():
    with pytest.raises(ValueError):
        load_public_key(b"\x04" + b"\x00" * 20)


def test_ecdh_rejects_bad_prefix():
    with pytest.raises(ValueError):
        load_public_key(b"\x02" + b"\x00" * 64)


def test_ecdh_rejects_invalid_point():
    # Correct uncompressed length/prefix, but not a valid P-256 point.
    with pytest.raises(ValueError):
        load_public_key(b"\x04" + b"\x00" * 64)

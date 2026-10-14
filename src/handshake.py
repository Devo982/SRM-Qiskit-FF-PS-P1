"""Complete local-simulation handshakes for benchmark comparison."""

from __future__ import annotations

from contextlib import ExitStack
from time import perf_counter_ns
from typing import Any

from src.ecdh import exchange as ecdh_exchange
from src.ecdh import generate_keypair as ecdh_generate_keypair
from src.ecdh import serialize_public_key as ecdh_serialize_public
from src.hybrid import derive_session_key
from src.transcript import handshake_transcript

MODES = ("ecdh", "mlkem", "hybrid")


def _timed(timings: dict[str, int], name: str, fn):
    start = perf_counter_ns()
    result = fn()
    timings[name] = perf_counter_ns() - start
    return result


def run_handshake(mode: str = "hybrid") -> dict[str, Any]:
    """Simulate both endpoints sequentially and return non-secret metrics.

    This is local compute timing, not network RTT or TLS timing. All returned
    fields exclude private keys and shared/session key bytes.
    """
    if mode not in MODES:
        raise ValueError(f"mode must be one of {MODES}; got {mode!r}")

    total_start = perf_counter_ns()
    timings: dict[str, int] = {}
    responder_ec_private = None
    initiator_ec_private = None
    responder_ec_public = b""
    initiator_ec_public = b""
    responder_mlkem_public = b""
    mlkem_ciphertext = b""
    ecdh_secret_initiator = None
    ecdh_secret_responder = None
    mlkem_secret_initiator = None
    mlkem_secret_responder = None

    with ExitStack() as stack:
        responder_kem = None
        initiator_kem = None
        if mode in {"mlkem", "hybrid"}:
            from src.mlkem import ALGORITHM, require_oqs

            oqs = require_oqs()
            responder_kem = stack.enter_context(oqs.KeyEncapsulation(ALGORITHM))
            responder_mlkem_public = _timed(
                timings, "mlkem_keygen_ns", responder_kem.generate_keypair
            )

        if mode in {"ecdh", "hybrid"}:
            responder_ec_private = _timed(
                timings, "responder_ecdh_keygen_ns", ecdh_generate_keypair
            )
            responder_ec_public = ecdh_serialize_public(responder_ec_private)
            initiator_ec_private = _timed(
                timings, "initiator_ecdh_keygen_ns", ecdh_generate_keypair
            )
            initiator_ec_public = ecdh_serialize_public(initiator_ec_private)
            ecdh_secret_initiator = _timed(
                timings,
                "ecdh_exchange_initiator_ns",
                lambda: ecdh_exchange(initiator_ec_private, responder_ec_public),
            )
            ecdh_secret_responder = _timed(
                timings,
                "ecdh_exchange_responder_ns",
                lambda: ecdh_exchange(responder_ec_private, initiator_ec_public),
            )

        if mode in {"mlkem", "hybrid"}:
            initiator_kem = stack.enter_context(oqs.KeyEncapsulation(ALGORITHM))
            encapsulated = _timed(
                timings,
                "mlkem_encap_ns",
                lambda: initiator_kem.encap_secret(responder_mlkem_public),
            )
            mlkem_ciphertext, mlkem_secret_initiator = encapsulated
            mlkem_secret_responder = _timed(
                timings,
                "mlkem_decap_ns",
                lambda: responder_kem.decap_secret(mlkem_ciphertext),
            )

        transcript = handshake_transcript(
            mode=mode,
            responder_ecdh_public=responder_ec_public if responder_ec_public else None,
            responder_mlkem_public=responder_mlkem_public if responder_mlkem_public else None,
            initiator_ecdh_public=initiator_ec_public if initiator_ec_public else None,
            mlkem_ciphertext=mlkem_ciphertext if mlkem_ciphertext else None,
        )
        key_initiator = _timed(
            timings,
            "hkdf_initiator_ns",
            lambda: derive_session_key(
                mode,
                transcript,
                ecdh_secret=ecdh_secret_initiator,
                mlkem_secret=mlkem_secret_initiator,
            ),
        )
        key_responder = _timed(
            timings,
            "hkdf_responder_ns",
            lambda: derive_session_key(
                mode,
                transcript,
                ecdh_secret=ecdh_secret_responder,
                mlkem_secret=mlkem_secret_responder,
            ),
        )
        key_match = key_initiator == key_responder
        if not key_match:
            raise RuntimeError("Initiator and responder derived different session keys")

    handshake_wall_ns = perf_counter_ns() - total_start
    responder_to_initiator_bytes = len(responder_ec_public) + len(responder_mlkem_public)
    initiator_to_responder_bytes = len(initiator_ec_public) + len(mlkem_ciphertext)

    return {
        "mode": mode,
        "key_match": key_match,
        "handshake_wall_ns": handshake_wall_ns,
        "responder_to_initiator_bytes": responder_to_initiator_bytes,
        "initiator_to_responder_bytes": initiator_to_responder_bytes,
        "total_payload_bytes": responder_to_initiator_bytes + initiator_to_responder_bytes,
        "p256_public_key_bytes": len(responder_ec_public) if responder_ec_public else 0,
        "mlkem_public_key_bytes": len(responder_mlkem_public),
        "mlkem_ciphertext_bytes": len(mlkem_ciphertext),
        **timings,
    }

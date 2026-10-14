"""Preflight and correctness CLI."""

from __future__ import annotations

import argparse
import json
import sys

from src.ecdh import PUBLIC_KEY_BYTES, SHARED_SECRET_BYTES, exchange, generate_keypair, serialize_public_key
from src.handshake import MODES, run_handshake
from src.mlkem import (
    ALGORITHM,
    CIPHERTEXT_BYTES,
    PUBLIC_KEY_BYTES as MLKEM_PUBLIC_KEY_BYTES,
    SECRET_KEY_BYTES,
    SHARED_SECRET_BYTES as MLKEM_SHARED_SECRET_BYTES,
    check_details,
    require_oqs,
)


def _check() -> int:
    report: dict[str, object] = {"preflight": "running"}
    try:
        # Independent ECDH agreement test.
        a = generate_keypair()
        b = generate_keypair()
        a_pub = serialize_public_key(a)
        b_pub = serialize_public_key(b)
        assert len(a_pub) == PUBLIC_KEY_BYTES
        assert len(b_pub) == PUBLIC_KEY_BYTES
        a_secret = exchange(a, b_pub)
        b_secret = exchange(b, a_pub)
        assert a_secret == b_secret and len(a_secret) == SHARED_SECRET_BYTES
        report["ecdh"] = "PASS"

        report["mlkem"] = check_details()
        report["expected_mlkem_sizes"] = {
            "public_key_bytes": MLKEM_PUBLIC_KEY_BYTES,
            "secret_key_bytes": SECRET_KEY_BYTES,
            "ciphertext_bytes": CIPHERTEXT_BYTES,
            "shared_secret_bytes": MLKEM_SHARED_SECRET_BYTES,
        }
        enabled = require_oqs().get_enabled_kem_mechanisms()
        report["mlkem_768_enabled"] = ALGORITHM in enabled
        if not report["mlkem_768_enabled"]:
            raise RuntimeError(f"{ALGORITHM} is not enabled")
        report["preflight"] = "PASS"
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0
    except Exception as exc:
        report["preflight"] = "FAIL"
        report["error_type"] = type(exc).__name__
        report["error"] = str(exc)
        print(json.dumps(report, indent=2, sort_keys=True), file=sys.stderr)
        return 1


def _handshake(mode: str) -> int:
    try:
        modes = MODES if mode == "all" else (mode,)
        outcomes = []
        for selected in modes:
            result = run_handshake(selected)
            if not result["key_match"]:
                raise RuntimeError(f"Key mismatch for mode {selected}")
            outcomes.append(
                {
                    "mode": selected,
                    "key_match": result["key_match"],
                    "handshake_wall_ns": result["handshake_wall_ns"],
                    "responder_to_initiator_bytes": result["responder_to_initiator_bytes"],
                    "initiator_to_responder_bytes": result["initiator_to_responder_bytes"],
                    "total_payload_bytes": result["total_payload_bytes"],
                }
            )
        print(json.dumps({"status": "PASS", "outcomes": outcomes}, indent=2))
        return 0
    except Exception as exc:
        print(json.dumps({"status": "FAIL", "error_type": type(exc).__name__, "error": str(exc)}, indent=2), file=sys.stderr)
        return 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("check", help="Check P-256 and native standardized ML-KEM-768 availability")
    handshake_parser = subparsers.add_parser("handshake", help="Run one local handshake for suite(s)")
    handshake_parser.add_argument("--mode", choices=[*MODES, "all"], default="all")
    args = parser.parse_args()
    if args.command == "check":
        return _check()
    return _handshake(args.mode)


if __name__ == "__main__":
    raise SystemExit(main())

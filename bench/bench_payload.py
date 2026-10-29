"""Payload benchmark using the official PS-P1 payloads.

Measures record-layer encryption/decryption separately and retains end-to-end
throughput as supplementary evidence. All measurements are local/in-process.
"""

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import statistics
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from protocol import records as rec
from protocol.suites import QFF26_CLASSICAL_1, QFF26_PQC_1, sig_generate
from common.official_payloads import (
    EXPECTED_SHA256,
    PAYLOADS,
    ensure_payloads,
)
from tests.harness import make_channels, run_handshake


def ephemeral_trust(suite, a_vk: bytes, b_vk: bytes) -> dict:
    b64 = base64.b64encode
    return {
        "version": 1,
        "identities": {
            "client:alice": {
                "role": "client",
                "keys": {suite.suite_id: b64(a_vk).decode()},
            },
            "server:bob": {
                "role": "server",
                "keys": {suite.suite_id: b64(b_vk).decode()},
            },
        },
    }


def write_csv(path: Path, rows: list[dict], fieldnames: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def bench_pair(suite, data: bytes, repeats: int, expected_sha256: str) -> dict:
    a_sk, a_vk = sig_generate(suite)
    b_sk, b_vk = sig_generate(suite)
    trust = ephemeral_trust(suite, a_vk, b_vk)
    client, server, wire = make_channels(
        suite.suite_id, trust, a_sk, b_sk
    )

    run_handshake(client, server, wire)
    if not (client.established and server.established):
        raise RuntimeError("Handshake failed in payload benchmark")

    encrypt_samples_ms: list[float] = []
    decrypt_samples_ms: list[float] = []
    frame_lengths: list[int] = []
    c2s_rates: list[float] = []
    s2c_rates: list[float] = []

    original_encrypt = rec.encrypt_record
    original_decrypt = rec.open_record

    def timed_encrypt(*args, **kwargs):
        start_ns = time.perf_counter_ns()
        try:
            return original_encrypt(*args, **kwargs)
        finally:
            encrypt_samples_ms.append(
                (time.perf_counter_ns() - start_ns) / 1_000_000
            )

    def timed_decrypt(*args, **kwargs):
        start_ns = time.perf_counter_ns()
        try:
            return original_decrypt(*args, **kwargs)
        finally:
            decrypt_samples_ms.append(
                (time.perf_counter_ns() - start_ns) / 1_000_000
            )

    rec.encrypt_record = timed_encrypt
    rec.open_record = timed_decrypt

    try:
        for _ in range(repeats):
            transfers = (
                (client, server, "c2s", c2s_rates),
                (server, client, "s2c", s2c_rates),
            )

            for sender, receiver, direction, rates in transfers:
                log_start = len(wire.log)
                sender.send(data)
                wire.pump(client, server)
                received = receiver.recv()

                entries = wire.log[log_start:]

                if len(entries) != 1:
                    raise RuntimeError(
                        f"Expected one record in {direction}, got {len(entries)}"
                    )

                actual_direction, _, frame = entries[0]
                if actual_direction != direction:
                    raise RuntimeError(
                        f"Expected {direction} frame, got {actual_direction}"
                    )

                if received != data:
                    raise RuntimeError(
                        f"Payload mismatch in {direction} transfer"
                    )

                received_hash = hashlib.sha256(received).hexdigest()
                if received_hash != expected_sha256:
                    raise RuntimeError(
                        f"Official SHA-256 mismatch in {direction} transfer"
                    )

                frame_lengths.append(len(frame))
    finally:
        rec.encrypt_record = original_encrypt
        rec.open_record = original_decrypt

    # Measure throughput separately with the original record functions restored.
    mb = len(data) / (1024.0 * 1024.0)

    for _ in range(repeats):
        transfers = (
            (client, server, "c2s", c2s_rates),
            (server, client, "s2c", s2c_rates),
        )

        for sender, receiver, direction, rates in transfers:
            log_start = len(wire.log)
            start = time.perf_counter()

            sender.send(data)
            wire.pump(client, server)
            received = receiver.recv()

            elapsed_s = time.perf_counter() - start
            entries = wire.log[log_start:]

            if len(entries) != 1:
                raise RuntimeError(
                    f"Expected one throughput frame in {direction}, "
                    f"got {len(entries)}"
                )

            actual_direction, _, frame = entries[0]
            if actual_direction != direction:
                raise RuntimeError(
                    f"Expected {direction} frame, got {actual_direction}"
                )

            if len(frame) != len(data) + rec.HEADER_LEN + rec.TAG_LEN:
                raise RuntimeError("Unexpected serialized record size")

            if received != data:
                raise RuntimeError(
                    f"Payload mismatch in uninstrumented {direction} transfer"
                )

            if hashlib.sha256(received).hexdigest() != expected_sha256:
                raise RuntimeError(
                    f"Official SHA-256 mismatch in {direction} throughput transfer"
                )

            rates.append(mb / elapsed_s)

    expected_samples = 2 * repeats
    if len(encrypt_samples_ms) != expected_samples:
        raise RuntimeError("Unexpected encryption timing sample count")
    if len(decrypt_samples_ms) != expected_samples:
        raise RuntimeError("Unexpected decryption timing sample count")

    if len(set(frame_lengths)) != 1:
        raise RuntimeError("Serialized record sizes varied for identical payloads")

    serialized_bytes = frame_lengths[0]
    expected_serialized_bytes = len(data) + rec.HEADER_LEN + rec.TAG_LEN

    if serialized_bytes != expected_serialized_bytes:
        raise RuntimeError(
            f"Unexpected serialized record size: {serialized_bytes}; "
            f"expected {expected_serialized_bytes}"
        )

    return {
        "trials": expected_samples,
        "ciphertext_bytes": serialized_bytes,
        "overhead_bytes": serialized_bytes - len(data),
        "median_encrypt_ms": statistics.median(encrypt_samples_ms),
        "median_decrypt_ms": statistics.median(decrypt_samples_ms),
        "c2s_mib_s": statistics.median(c2s_rates),
        "s2c_mib_s": statistics.median(s2c_rates),
        "sha256_match": "true",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repeats", type=int, default=15,
        help="complete bidirectional rounds per payload and suite (default 15)",
    )
    parser.add_argument(
        "--platform-label", choices=("A", "B", "D", "LOCAL"), default="LOCAL",
        help="machine label written into result rows (default LOCAL; use A only on the designated Platform A machine)",
    )
    parser.add_argument(
        "--output-dir", type=Path, default=Path("results/runs/manual/tables"),
        help="directory for CSV outputs (default is an ignored local scratch folder; use results/tables only when intentionally updating official evidence)",
    )
    args = parser.parse_args()

    if args.repeats < 1:
        parser.error("--repeats must be at least 1")
    output_dir = args.output_dir if args.output_dir.is_absolute() else REPO_ROOT / args.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)

    payloads = ensure_payloads()
    official_rows = []
    throughput_rows = []

    suites = (
        (QFF26_PQC_1, "PQC"),
        (QFF26_CLASSICAL_1, "classical-baseline"),
    )

    for suite, mode in suites:
        for name, size in PAYLOADS:
            data = payloads[name]
            result = bench_pair(
                suite,
                data,
                args.repeats,
                EXPECTED_SHA256[name],
            )

            official_rows.append({
                "platform": args.platform_label,
                "mode": mode,
                "payload": name,
                "plaintext_bytes": size,
                "ciphertext_bytes": result["ciphertext_bytes"],
                "overhead_bytes": result["overhead_bytes"],
                "trials": result["trials"],
                "median_encrypt_ms": round(result["median_encrypt_ms"], 6),
                "median_decrypt_ms": round(result["median_decrypt_ms"], 6),
                "sha256_match": result["sha256_match"],
            })

            throughput_rows.append({
                "suite": suite.suite_id,
                "payload": name,
                "bytes": size,
                "repeats": args.repeats,
                "c2s_mib_s": round(result["c2s_mib_s"], 2),
                "s2c_mib_s": round(result["s2c_mib_s"], 2),
            })

            print(
                f"{mode:<20} {name:<18} "
                f"encrypt={result['median_encrypt_ms']:.6f} ms  "
                f"decrypt={result['median_decrypt_ms']:.6f} ms  "
                f"record={result['ciphertext_bytes']} B  "
                f"overhead={result['overhead_bytes']} B  "
                f"samples={result['trials']}  "
                f"SHA-256={result['sha256_match']}"
            )

    template_columns = [
        "platform",
        "mode",
        "payload",
        "plaintext_bytes",
        "ciphertext_bytes",
        "overhead_bytes",
        "trials",
        "median_encrypt_ms",
        "median_decrypt_ms",
        "sha256_match",
    ]

    write_csv(
        output_dir / "payload_results.csv",
        official_rows,
        template_columns,
    )

    write_csv(
        output_dir / "bench_payload.csv",
        throughput_rows,
        [
            "suite",
            "payload",
            "bytes",
            "repeats",
            "c2s_mib_s",
            "s2c_mib_s",
        ],
    )

    print(
        "Per-record accounting: 16-byte header + 16-byte GCM tag; "
        "12-byte nonce is derived and not transmitted; total wire overhead = 32 B."
    )
    print("Measurements are local/in-process.")
    print(f"Official payload results: {output_dir / 'payload_results.csv'}")
    print(f"Supplementary throughput: {output_dir / 'bench_payload.csv'}")


if __name__ == "__main__":
    main()

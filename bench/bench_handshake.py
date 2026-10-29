"""PS-P1 handshake benchmark with measured wire-frame sizes.

Runs local in-process handshakes, records latency statistics, and captures
serialized M1, M2 and M3 lengths from InMemoryWire.log.
"""

from __future__ import annotations

import argparse
import base64
import csv
import statistics
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from protocol.suites import QFF26_CLASSICAL_1, QFF26_PQC_1, sig_generate
from tests.harness import make_channels, run_handshake


def percentile(sorted_values: list[float], p: float) -> float:
    """Calculate a linearly interpolated percentile."""
    if not sorted_values:
        raise ValueError("Cannot calculate a percentile without samples")

    k = (len(sorted_values) - 1) * p / 100.0
    lower = int(k)
    upper = min(lower + 1, len(sorted_values) - 1)
    return sorted_values[lower] + (
        sorted_values[upper] - sorted_values[lower]
    ) * (k - lower)


def ephemeral_trust(suite, client_vk: bytes, server_vk: bytes) -> dict:
    b64 = base64.b64encode
    return {
        "version": 1,
        "identities": {
            "client:alice": {
                "role": "client",
                "keys": {suite.suite_id: b64(client_vk).decode()},
            },
            "server:bob": {
                "role": "server",
                "keys": {suite.suite_id: b64(server_vk).decode()},
            },
        },
    }


def write_csv(path: Path, rows: list[dict], fields: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(
            fh, fieldnames=fields, lineterminator="\n"
        )
        writer.writeheader()
        writer.writerows(rows)


def bench_suite(
    suite,
    mode: str,
    kem_name: str,
    signature_name: str,
    runs: int,
    run_id: str,
) -> tuple[dict, dict, list[dict]]:
    client_sk, client_vk = sig_generate(suite)
    server_sk, server_vk = sig_generate(suite)
    trust = ephemeral_trust(suite, client_vk, server_vk)

    samples_ms: list[float] = []
    raw_sample_rows: list[dict] = []
    observed_sizes: list[tuple[int, int, int]] = []
    failure_count = 0

    for trial in range(1, runs + 1):
        client, server, wire = make_channels(
            suite.suite_id, trust, client_sk, server_sk
        )

        start_ns = time.perf_counter_ns()

        try:
            run_handshake(client, server, wire)
            elapsed_ms = (
                time.perf_counter_ns() - start_ns
            ) / 1_000_000

            if not (client.established and server.established):
                raise RuntimeError(
                    "handshake did not establish both endpoints"
                )

            frames = {
                (direction, index): frame
                for direction, index, frame in wire.log
            }

            # The wire documents c2s frame 0=M1, s2c frame 0=M2,
            # and c2s frame 1=M3. These are actual delivered bytes.
            required = (
                ("c2s", 0),
                ("s2c", 0),
                ("c2s", 1),
            )
            if any(key not in frames for key in required):
                raise RuntimeError(
                    "one or more serialized handshake frames are missing"
                )

            m1 = frames[("c2s", 0)]
            m2 = frames[("s2c", 0)]
            m3 = frames[("c2s", 1)]

            observed_sizes.append((len(m1), len(m2), len(m3)))
            samples_ms.append(elapsed_ms)
            raw_sample_rows.append({
                "suite": suite.suite_id,
                "trial": trial,
                "ms": round(elapsed_ms, 6),
            })

        except Exception as exc:
            failure_count += 1
            print(
                f"FAIL {suite.suite_id} trial {trial}: "
                f"{type(exc).__name__}: {exc}"
            )

    success_count = len(samples_ms)

    if success_count < 10:
        raise RuntimeError(
            f"{suite.suite_id}: only {success_count} successful handshakes; "
            "at least 10 are required"
        )

    # For these fixed-format suites, the measured message sizes should remain
    # stable. Do not silently report a single size if actual lengths vary.
    if len(set(observed_sizes)) != 1:
        raise RuntimeError(
            f"{suite.suite_id}: serialized handshake sizes varied between runs"
        )

    m1_bytes, m2_bytes, m3_bytes = observed_sizes[0]
    c2s_bytes = m1_bytes + m3_bytes
    s2c_bytes = m2_bytes
    total_bytes = c2s_bytes + s2c_bytes

    ordered = sorted(samples_ms)
    q25 = percentile(ordered, 25)
    q75 = percentile(ordered, 75)
    median_ms = statistics.median(ordered)
    iqr_ms = q75 - q25
    p95_ms = percentile(ordered, 95)

    official_row = {
        "run_id": run_id,
        "platform": "A",
        "mode": mode,
        "kem": kem_name,
        "signature": signature_name,
        "trials": runs,
        "median_handshake_ms": round(median_ms, 3),
        "iqr_ms": round(iqr_ms, 3),
        "p95_ms": round(p95_ms, 3),
        "client_to_server_bytes": c2s_bytes,
        "server_to_client_bytes": s2c_bytes,
        "total_handshake_bytes": total_bytes,
        "success_count": success_count,
        "failure_count": failure_count,
        "local_or_network": "local",
    }

    supplementary_row = {
        "suite": suite.suite_id,
        "runs": runs,
        "median_ms": round(median_ms, 3),
        "iqr_ms": round(iqr_ms, 3),
        "p95_ms": round(p95_ms, 3),
        "min_ms": round(ordered[0], 3),
        "max_ms": round(ordered[-1], 3),
        "run_id": run_id,
        "platform": "A",
        "mode": mode,
        "kem": kem_name,
        "signature": signature_name,
        "success_count": success_count,
        "failure_count": failure_count,
        "m1_bytes": m1_bytes,
        "m2_bytes": m2_bytes,
        "m3_bytes": m3_bytes,
        "client_to_server_bytes": c2s_bytes,
        "server_to_client_bytes": s2c_bytes,
        "total_handshake_bytes": total_bytes,
        "local_or_network": "local",
    }

    print(
        f"{suite.suite_id}: "
        f"successful={success_count}/{runs}, failures={failure_count}, "
        f"median={median_ms:.3f} ms, IQR={iqr_ms:.3f} ms, "
        f"p95={p95_ms:.3f} ms"
    )
    print(
        f"  measured M1={m1_bytes} B, M2={m2_bytes} B, M3={m3_bytes} B; "
        f"c2s={c2s_bytes} B, s2c={s2c_bytes} B, total={total_bytes} B"
    )

    return official_row, supplementary_row, raw_sample_rows


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--runs",
        type=int,
        default=100,
        help="handshake attempts per suite (minimum 10)",
    )
    args = parser.parse_args()

    if args.runs < 10:
        parser.error("--runs must be at least 10")

    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

    configs = (
        (QFF26_PQC_1, "PQC", "ML-KEM-768", "ML-DSA-65"),
        (
            QFF26_CLASSICAL_1,
            "classical-baseline",
            "X25519",
            "Ed25519",
        ),
    )

    official_rows = []
    supplementary_rows = []
    raw_sample_rows = []

    for suite, mode, kem_name, signature_name in configs:
        official, supplementary, raw_samples = bench_suite(
            suite,
            mode,
            kem_name,
            signature_name,
            args.runs,
            run_id,
        )
        official_rows.append(official)
        supplementary_rows.append(supplementary)
        raw_sample_rows.extend(raw_samples)

    official_fields = [
        "run_id",
        "platform",
        "mode",
        "kem",
        "signature",
        "trials",
        "median_handshake_ms",
        "iqr_ms",
        "p95_ms",
        "client_to_server_bytes",
        "server_to_client_bytes",
        "total_handshake_bytes",
        "success_count",
        "failure_count",
        "local_or_network",
    ]

    supplementary_fields = [
        "suite",
        "runs",
        "median_ms",
        "iqr_ms",
        "p95_ms",
        "min_ms",
        "max_ms",
        "run_id",
        "platform",
        "mode",
        "kem",
        "signature",
        "success_count",
        "failure_count",
        "m1_bytes",
        "m2_bytes",
        "m3_bytes",
        "client_to_server_bytes",
        "server_to_client_bytes",
        "total_handshake_bytes",
        "local_or_network",
    ]

    write_csv(
        REPO_ROOT / "results" / "tables" / "handshake_results.csv",
        official_rows,
        official_fields,
    )
    write_csv(
        REPO_ROOT / "results" / "tables" / "bench_handshake.csv",
        supplementary_rows,
        supplementary_fields,
    )
    write_csv(
        REPO_ROOT / "results" / "tables" / "handshake_raw_samples.csv",
        raw_sample_rows,
        ["suite", "trial", "ms"],
    )

    print("Measurements are local/in-process, not network measurements.")
    print("Official results: results/tables/handshake_results.csv")
    print("Supplementary results: results/tables/bench_handshake.csv")
    print("Raw successful-trial timings: results/tables/handshake_raw_samples.csv")


if __name__ == "__main__":
    main()

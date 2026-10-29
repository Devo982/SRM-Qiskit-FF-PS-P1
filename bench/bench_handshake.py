"""Handshake latency benchmark (kit requirement: >=10 handshakes, median/IQR/p95).

    python bench/bench_handshake.py [--runs 15] [--runs-classical 15]

Ephemeral signing keys + a matching ephemeral trust store are generated per
invocation (handshake cost is representative; provisioning is not required).
Results are written to results/tables/bench_handshake.csv and printed.
"""
from __future__ import annotations

import argparse
import base64
import csv
import statistics
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from protocol.suites import QFF26_CLASSICAL_1, QFF26_PQC_1, sig_generate  # noqa: E402
from tests.harness import make_channels, run_handshake  # noqa: E402


def percentile(sorted_values: list[float], p: float) -> float:
    """Linear-interpolated percentile."""
    if not sorted_values:
        return float("nan")
    k = (len(sorted_values) - 1) * p / 100.0
    f = int(k)
    c = min(f + 1, len(sorted_values) - 1)
    return sorted_values[f] + (sorted_values[c] - sorted_values[f]) * (k - f)


def ephemeral_trust(suite, a_vk: bytes, b_vk: bytes) -> dict:
    b64 = base64.b64encode
    return {
        "version": 1,
        "identities": {
            "client:alice": {"role": "client",
                             "keys": {suite.suite_id: b64(a_vk).decode()}},
            "server:bob": {"role": "server",
                           "keys": {suite.suite_id: b64(b_vk).decode()}},
        },
    }


def bench_suite(suite, runs: int) -> dict:
    a_sk, a_vk = sig_generate(suite)
    b_sk, b_vk = sig_generate(suite)
    trust = ephemeral_trust(suite, a_vk, b_vk)
    samples_ms: list[float] = []
    for i in range(runs):
        client, server, wire = make_channels(suite.suite_id, trust, a_sk, b_sk)
        t0 = time.perf_counter()
        run_handshake(client, server, wire)
        dt_ms = (time.perf_counter() - t0) * 1000.0
        if not (client.established and server.established):
            raise SystemExit(
                f"handshake {i} failed: client={client.failure_detail} "
                f"server={server.failure_detail}"
            )
        samples_ms.append(dt_ms)
    s = sorted(samples_ms)
    q25, q75 = percentile(s, 25), percentile(s, 75)
    return {
        "suite": suite.suite_id,
        "runs": runs,
        "median_ms": round(statistics.median(s), 3),
        "iqr_ms": round(q75 - q25, 3),
        "p95_ms": round(percentile(s, 95), 3),
        "min_ms": round(s[0], 3),
        "max_ms": round(s[-1], 3),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runs", type=int, default=15, help="handshakes per suite (>=10)")
    args = parser.parse_args()
    if args.runs < 10:
        print("kit requires >=10 handshakes; forcing runs=10")
        args.runs = 10

    rows = [bench_suite(QFF26_PQC_1, args.runs), bench_suite(QFF26_CLASSICAL_1, args.runs)]

    out = REPO_ROOT / "results" / "tables" / "bench_handshake.csv"
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    print(f"handshake latency ({args.runs} runs per suite, in-process wire):")
    header = f"{'suite':<20}{'median':>10}{'IQR':>10}{'p95':>10}{'min':>10}{'max':>10}"
    print(header)
    for r in rows:
        print(f"{r['suite']:<20}{r['median_ms']:>9.2f}ms{r['iqr_ms']:>9.2f}ms"
              f"{r['p95_ms']:>9.2f}ms{r['min_ms']:>9.2f}ms{r['max_ms']:>9.2f}ms")
    print(f"results written to {out.relative_to(REPO_ROOT)}")


if __name__ == "__main__":
    main()


"""Payload throughput benchmark (1KB / 100KB / 10MB, both directions, both suites).

    python bench/bench_payload.py [--repeats 5]

Results are written to results/tables/bench_payload.csv and printed.
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
from tests.run_security_tests import PAYLOADS, gen_payload  # noqa: E402
from tests.harness import make_channels, run_handshake  # noqa: E402


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


def bench_pair(suite, data: bytes, repeats: int) -> tuple[float, float]:
    """Returns (c2s MB/s median, s2c MB/s median) over `repeats` transfers."""
    a_sk, a_vk = sig_generate(suite)
    b_sk, b_vk = sig_generate(suite)
    trust = ephemeral_trust(suite, a_vk, b_vk)
    client, server, wire = make_channels(suite.suite_id, trust, a_sk, b_sk)
    run_handshake(client, server, wire)
    if not (client.established and server.established):
        raise SystemExit("handshake failed in bench_payload")
    mb = len(data) / (1024.0 * 1024.0)

    c2s_rates: list[float] = []
    for _ in range(repeats):
        t0 = time.perf_counter()
        client.send(data)
        wire.pump(client, server)
        got = server.recv()
        if got != data:
            raise SystemExit("payload mismatch in bench")
        c2s_rates.append(mb / (time.perf_counter() - t0))

    s2c_rates: list[float] = []
    for _ in range(repeats):
        t0 = time.perf_counter()
        server.send(data)
        wire.pump(client, server)
        got = client.recv()
        if got != data:
            raise SystemExit("payload mismatch in bench")
        s2c_rates.append(mb / (time.perf_counter() - t0))

    return statistics.median(c2s_rates), statistics.median(s2c_rates)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repeats", type=int, default=5)
    args = parser.parse_args()

    rows = []
    for suite in (QFF26_PQC_1, QFF26_CLASSICAL_1):
        for name, size in PAYLOADS:
            data = gen_payload(size)
            c2s, s2c = bench_pair(suite, data, args.repeats)
            rows.append({
                "suite": suite.suite_id, "payload": name, "bytes": size,
                "repeats": args.repeats,
                "c2s_mb_s": round(c2s, 2), "s2c_mb_s": round(s2c, 2),
            })
            print(f"  {suite.suite_id:<20}{name:<18}{size:>10} B  "
                  f"c2s {c2s:8.1f} MB/s   s2c {s2c:8.1f} MB/s")

    out = REPO_ROOT / "results" / "tables" / "bench_payload.csv"
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
    print(f"results written to {out.relative_to(REPO_ROOT)}")


if __name__ == "__main__":
    main()


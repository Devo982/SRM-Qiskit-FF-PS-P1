"""Reproducible benchmark runner for ECDH-only, ML-KEM-only, and hybrid modes."""

from __future__ import annotations

import argparse
import csv
import gc
import json
import math
import os
import subprocess
import sys
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from statistics import mean, pstdev
from typing import Any

import psutil

from src.handshake import MODES, run_handshake
from src.platforms import ROOT, environment_metadata


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def quantile(values: list[float], q: float) -> float | None:
    """Linearly interpolated sample quantile (inclusive convention)."""
    if not values:
        return None
    if not 0.0 <= q <= 1.0:
        raise ValueError("q must be between 0 and 1")
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    position = (len(ordered) - 1) * q
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    fraction = position - lower
    return ordered[lower] * (1 - fraction) + ordered[upper] * fraction


def _memory_child(mode: str, repetitions: int, warmup: int, interval_seconds: float) -> dict[str, Any]:
    for _ in range(warmup):
        run_handshake(mode)
    gc.collect()

    proc = psutil.Process(os.getpid())
    baseline_rss = proc.memory_info().rss
    peak_box = {"rss": baseline_rss}
    stop = threading.Event()

    def sample() -> None:
        while not stop.is_set():
            try:
                peak_box["rss"] = max(peak_box["rss"], proc.memory_info().rss)
            except (psutil.Error, OSError):
                pass
            stop.wait(interval_seconds)

    sampler = threading.Thread(target=sample, name="rss-sampler", daemon=True)
    sampler.start()
    try:
        for _ in range(repetitions):
            run_handshake(mode)
    finally:
        stop.set()
        sampler.join(timeout=max(1.0, interval_seconds * 4))
        try:
            peak_box["rss"] = max(peak_box["rss"], proc.memory_info().rss)
        except (psutil.Error, OSError):
            pass

    peak_rss = int(peak_box["rss"])
    return {
        "mode": mode,
        "memory_probe_repetitions": repetitions,
        "memory_probe_warmup": warmup,
        "rss_sample_interval_seconds": interval_seconds,
        "baseline_rss_bytes": int(baseline_rss),
        "sampled_peak_rss_bytes": peak_rss,
        "sampled_peak_delta_bytes": max(0, peak_rss - int(baseline_rss)),
        "memory_probe_method": "separate subprocess; psutil process RSS sampled by background thread after warmup",
    }


def _spawn_memory_probe(mode: str, reps: int, warmup: int, interval: float) -> dict[str, Any]:
    command = [
        sys.executable,
        "-m",
        "src.benchmark",
        "--memory-child",
        mode,
        str(reps),
        str(warmup),
        str(interval),
    ]
    completed = subprocess.run(
        command,
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    marker_lines = [line for line in completed.stdout.splitlines() if line.startswith("MEMORY_JSON:")]
    if completed.returncode != 0 or not marker_lines:
        raise RuntimeError(
            f"Memory probe failed for {mode} (exit={completed.returncode}). "
            f"stdout tail={completed.stdout[-2000:]!r}; stderr tail={completed.stderr[-2000:]!r}"
        )
    return json.loads(marker_lines[-1].split("MEMORY_JSON:", 1)[1])


def _run_latency_batch(
    mode: str,
    platform_id: str,
    platform_verified: bool,
    run_id: str,
    batch_num: int,
    iterations: int,
    warmup: int,
    environment_json: str,
) -> tuple[list[dict[str, Any]], int]:
    for _ in range(warmup):
        run_handshake(mode)

    rows: list[dict[str, Any]] = []
    batch_start = time.perf_counter_ns()
    for sample_num in range(1, iterations + 1):
        external_start = time.perf_counter_ns()
        row: dict[str, Any] = {
            "run_id": run_id,
            "timestamp_utc": utc_now(),
            "platform_id": platform_id,
            "platform_verified": platform_verified,
            "suite": mode,
            "batch": batch_num,
            "sample_index": sample_num,
            "success": False,
            "key_match": False,
            "handshake_wall_ns": None,
            "measurement_elapsed_ns": None,
            "error_type": None,
            "environment_json": environment_json,
        }
        try:
            result = run_handshake(mode)
            row.update(result)
            row["success"] = True
            row["error_type"] = None
        except Exception as exc:
            # Do not write exception payloads or secret-bearing context to raw results.
            row["error_type"] = type(exc).__name__
        row["measurement_elapsed_ns"] = time.perf_counter_ns() - external_start
        if row.get("handshake_wall_ns") is None:
            row["handshake_wall_ns"] = row["measurement_elapsed_ns"]
        rows.append(row)
    elapsed_ns = time.perf_counter_ns() - batch_start
    return rows, elapsed_ns


def _summarize(rows: list[dict[str, Any]], batch_elapsed_ns: list[int]) -> dict[str, Any]:
    successful = [row for row in rows if row.get("success") is True]
    latencies_ms = [float(row["handshake_wall_ns"]) / 1e6 for row in successful]
    all_latencies_ms = [float(row["handshake_wall_ns"]) / 1e6 for row in rows]
    total_elapsed_seconds = sum(batch_elapsed_ns) / 1e9
    payloads = [int(row["total_payload_bytes"]) for row in successful if row.get("total_payload_bytes") is not None]
    mlkem_ct = [int(row["mlkem_ciphertext_bytes"]) for row in successful if row.get("mlkem_ciphertext_bytes") is not None]
    output = {
        "platform_id": rows[0]["platform_id"] if rows else None,
        "platform_verified": rows[0]["platform_verified"] if rows else False,
        "suite": rows[0]["suite"] if rows else None,
        "n_attempted": len(rows),
        "n_successful": len(successful),
        "n_failed": len(rows) - len(successful),
        "success_rate": len(successful) / len(rows) if rows else 0.0,
        "median_latency_ms": quantile(latencies_ms, 0.50),
        "p95_latency_ms": quantile(latencies_ms, 0.95),
        "p99_latency_ms": quantile(latencies_ms, 0.99),
        "mean_latency_ms": mean(latencies_ms) if latencies_ms else None,
        "latency_stddev_ms_population": pstdev(latencies_ms) if len(latencies_ms) > 1 else (0.0 if latencies_ms else None),
        "throughput_successful_handshakes_per_second": len(successful) / total_elapsed_seconds if total_elapsed_seconds > 0 else None,
        "payload_bytes_min": min(payloads) if payloads else None,
        "payload_bytes_max": max(payloads) if payloads else None,
        "mlkem_ciphertext_bytes_min": min(mlkem_ct) if mlkem_ct else None,
        "mlkem_ciphertext_bytes_max": max(mlkem_ct) if mlkem_ct else None,
        "quantile_method": "linear interpolation of sorted samples at (n-1)*q (inclusive)",
        "batch_elapsed_seconds_total": total_elapsed_seconds,
    }
    return output


def _write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        raise ValueError(f"Refusing to write empty result file: {path}")
    keys: list[str] = []
    for row in rows:
        for key in row:
            if key not in keys:
                keys.append(key)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=keys, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def _main_run(args: argparse.Namespace) -> int:
    platform_id = args.platform
    env = environment_metadata(platform_id)
    platform_verified = bool(env["platform_verified"])
    if platform_id == "B" and not platform_verified and not args.allow_unverified_platform:
        print(json.dumps({
            "status": "BLOCKED",
            "reason": "Platform B limits were not verifiably enforced; run inside the configured constrained container, or use --allow-unverified-platform for a clearly marked pilot only.",
            "environment": env,
        }, indent=2), file=sys.stderr)
        return 3

    # Hard fail on missing/disabled standardized ML-KEM before any benchmark results are claimed.
    from src.mlkem import require_oqs
    try:
        require_oqs()
    except Exception as exc:
        print(json.dumps({
            "status": "BLOCKED",
            "reason": "Required standardized ML-KEM-768 dependency is unavailable.",
            "error_type": type(exc).__name__,
            "error": str(exc),
        }, indent=2), file=sys.stderr)
        return 1

    run_id = f"{platform_id}_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}_{uuid.uuid4().hex[:8]}"
    env_json = json.dumps(env, sort_keys=True, separators=(",", ":"))
    raw_rows: list[dict[str, Any]] = []
    summaries: list[dict[str, Any]] = []
    memory_summaries: list[dict[str, Any]] = []

    print(f"Run ID: {run_id}")
    print(f"Platform {platform_id} verified: {platform_verified}")
    print(f"Run plan: {args.batches} batches × {args.iterations} measured handshakes per suite; warmup={args.warmup}")

    for mode in MODES:
        mode_rows: list[dict[str, Any]] = []
        batch_elapsed_ns: list[int] = []
        for batch_num in range(1, args.batches + 1):
            rows, elapsed_ns = _run_latency_batch(
                mode=mode,
                platform_id=platform_id,
                platform_verified=platform_verified,
                run_id=run_id,
                batch_num=batch_num,
                iterations=args.iterations,
                warmup=args.warmup,
                environment_json=env_json,
            )
            mode_rows.extend(rows)
            batch_elapsed_ns.append(elapsed_ns)
            failures = sum(not row["success"] for row in rows)
            print(f"  {mode} batch {batch_num}/{args.batches}: {len(rows) - failures}/{len(rows)} successful")
        raw_rows.extend(mode_rows)
        summary = _summarize(mode_rows, batch_elapsed_ns)
        summary["run_id"] = run_id
        summary["timestamp_utc"] = utc_now()
        summaries.append(summary)

        memory = _spawn_memory_probe(mode, args.memory_reps, min(10, args.warmup), args.memory_interval)
        memory.update({
            "run_id": run_id,
            "platform_id": platform_id,
            "platform_verified": platform_verified,
            "timestamp_utc": utc_now(),
            "environment_json": env_json,
        })
        memory_summaries.append(memory)

    raw_path = ROOT / "data" / "raw" / f"benchmark_{run_id}.csv"
    summary_path = ROOT / "results" / "tables" / f"summary_{run_id}.csv"
    memory_path = ROOT / "results" / "tables" / f"memory_{run_id}.csv"
    metadata_path = ROOT / "data" / "processed" / f"environment_{run_id}.json"
    _write_csv(raw_path, raw_rows)
    _write_csv(summary_path, summaries)
    _write_csv(memory_path, memory_summaries)
    metadata_path.parent.mkdir(parents=True, exist_ok=True)
    metadata_path.write_text(json.dumps(env, indent=2, sort_keys=True), encoding="utf-8")

    acceptance = {
        "status": "PASS" if all(s["n_failed"] == 0 for s in summaries) and platform_verified else "WARNING",
        "run_id": run_id,
        "platform_id": platform_id,
        "platform_verified": platform_verified,
        "raw_csv": str(raw_path.relative_to(ROOT)),
        "summary_csv": str(summary_path.relative_to(ROOT)),
        "memory_csv": str(memory_path.relative_to(ROOT)),
        "environment_json": str(metadata_path.relative_to(ROOT)),
        "summaries": summaries,
        "memory": memory_summaries,
        "caveat": "Sampled process RSS delta is not exact allocation size. Benchmark timings exclude network transport and library cold-start unless explicitly measured separately.",
    }
    acceptance_path = ROOT / "results" / "tables" / f"run_manifest_{run_id}.json"
    acceptance_path.write_text(json.dumps(acceptance, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps({
        "status": acceptance["status"],
        "run_id": run_id,
        "raw_csv": acceptance["raw_csv"],
        "summary_csv": acceptance["summary_csv"],
        "memory_csv": acceptance["memory_csv"],
        "manifest": str(acceptance_path.relative_to(ROOT)),
    }, indent=2))

    if any(summary["n_failed"] > 0 for summary in summaries):
        return 2
    if platform_id == "B" and not platform_verified:
        return 3
    return 0


def main() -> int:
    # Hidden child mode keeps memory polling out of the latency sample process.
    if len(sys.argv) >= 2 and sys.argv[1] == "--memory-child":
        if len(sys.argv) != 6:
            print("usage: --memory-child MODE REPETITIONS WARMUP INTERVAL_SECONDS", file=sys.stderr)
            return 2
        mode, reps, warmup, interval = sys.argv[2], int(sys.argv[3]), int(sys.argv[4]), float(sys.argv[5])
        try:
            result = _memory_child(mode, reps, warmup, interval)
            print("MEMORY_JSON:" + json.dumps(result, sort_keys=True))
            return 0
        except Exception as exc:
            print(f"memory probe error: {type(exc).__name__}: {exc}", file=sys.stderr)
            return 1

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--platform", choices=["A", "B"], required=True)
    parser.add_argument("--iterations", type=int, default=1000, help="Measured handshakes per suite per batch")
    parser.add_argument("--warmup", type=int, default=100)
    parser.add_argument("--batches", type=int, default=5)
    parser.add_argument("--memory-reps", type=int, default=100)
    parser.add_argument("--memory-interval", type=float, default=0.002)
    parser.add_argument("--allow-unverified-platform", action="store_true", help="Pilot only; Platform B data will be marked unverified")
    args = parser.parse_args()
    if args.iterations < 1 or args.warmup < 0 or args.batches < 1 or args.memory_reps < 1 or args.memory_interval <= 0:
        parser.error("iterations, batches, memory-reps must be positive; warmup non-negative; memory interval positive")
    try:
        return _main_run(args)
    except KeyboardInterrupt:
        print("Interrupted; partial results may not have been written.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())

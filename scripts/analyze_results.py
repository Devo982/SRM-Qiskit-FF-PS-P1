"""Aggregate generated raw benchmark CSVs and produce comparison tables/plots."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import pandas as pd  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
RAW_DIR = ROOT / "data" / "raw"
TABLE_DIR = ROOT / "results" / "tables"
FIGURE_DIR = ROOT / "results" / "figures"


def _as_bool(series: pd.Series) -> pd.Series:
    return series.astype(str).str.lower().isin({"true", "1", "yes"})


def _matches(path: Path, run_ids: list[str]) -> bool:
    if not run_ids:
        return True
    return any(run_id in path.name for run_id in run_ids)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--run-ids",
        nargs="*",
        default=[],
        help="Only aggregate raw/memory files whose name contains one of these run IDs. "
        "Use this to keep pilot runs out of the final comparison.",
    )
    parser.add_argument(
        "--output-suffix",
        default="",
        help="Suffix appended to comparison_summary_* output names for this analysis set.",
    )
    args = parser.parse_args(argv)
    run_ids = [r for r in args.run_ids if r]
    suffix = f"_{args.output_suffix}" if args.output_suffix else ""

    files = [p for p in sorted(RAW_DIR.glob("benchmark_*.csv")) if _matches(p, run_ids)]
    if not files:
        print("No raw benchmark CSVs found (after run-id filter). Run src.benchmark first.", file=sys.stderr)
        return 2

    frames = []
    for path in files:
        try:
            frame = pd.read_csv(path)
        except Exception as exc:
            print(f"Could not read {path.name}: {exc}", file=sys.stderr)
            return 2
        frame["source_file"] = path.name
        frames.append(frame)

    df = pd.concat(frames, ignore_index=True)
    required = {"platform_id", "platform_verified", "suite", "success", "handshake_wall_ns"}
    missing = required.difference(df.columns)
    if missing:
        print(f"Missing required columns: {sorted(missing)}", file=sys.stderr)
        return 2

    df["success_bool"] = _as_bool(df["success"])
    df["platform_verified_bool"] = _as_bool(df["platform_verified"])
    df["latency_ms"] = pd.to_numeric(df["handshake_wall_ns"], errors="coerce") / 1e6
    df["payload_bytes"] = pd.to_numeric(df.get("total_payload_bytes"), errors="coerce")

    summaries = []
    group_columns = ["platform_id", "platform_verified_bool", "suite"]
    for keys, group in df.groupby(group_columns, dropna=False):
        platform_id, verified, suite = keys
        successes = group[group["success_bool"] & group["latency_ms"].notna()]
        latencies = successes["latency_ms"]
        total_ns = group["handshake_wall_ns"].fillna(0).astype(float).sum()
        summaries.append({
            "platform_id": platform_id,
            "platform_verified": bool(verified),
            "suite": suite,
            "n_attempted": len(group),
            "n_successful": len(successes),
            "n_failed": len(group) - len(successes),
            "success_rate": len(successes) / len(group) if len(group) else 0,
            "median_latency_ms": latencies.median() if len(latencies) else None,
            "p95_latency_ms": latencies.quantile(0.95, interpolation="linear") if len(latencies) else None,
            "p99_latency_ms": latencies.quantile(0.99, interpolation="linear") if len(latencies) else None,
            "iqr_latency_ms": (latencies.quantile(0.75, interpolation="linear") - latencies.quantile(0.25, interpolation="linear")) if len(latencies) else None,
            "stddev_latency_ms": latencies.std(ddof=1) if len(latencies) > 1 else (0.0 if len(latencies) else None),
            "mean_latency_ms": latencies.mean() if len(latencies) else None,
            "throughput_approx_handshakes_per_second": len(successes) / (total_ns / 1e9) if total_ns > 0 else None,
            "payload_bytes_min": successes["payload_bytes"].min() if successes["payload_bytes"].notna().any() else None,
            "payload_bytes_max": successes["payload_bytes"].max() if successes["payload_bytes"].notna().any() else None,
            "source_files": ";".join(sorted(group["source_file"].unique())),
        })

    TABLE_DIR.mkdir(parents=True, exist_ok=True)
    FIGURE_DIR.mkdir(parents=True, exist_ok=True)
    summary_df = pd.DataFrame(summaries).sort_values(["platform_id", "suite"])
    summary_path = TABLE_DIR / f"comparison_summary_all_runs{suffix}.csv"
    summary_df.to_csv(summary_path, index=False)

    # Per-batch medians and component-level medians, both derived from raw rows.
    candidate_components = [
        "responder_ecdh_keygen_ns",
        "initiator_ecdh_keygen_ns",
        "ecdh_exchange_initiator_ns",
        "ecdh_exchange_responder_ns",
        "mlkem_keygen_ns",
        "mlkem_encap_ns",
        "mlkem_decap_ns",
        "hkdf_initiator_ns",
        "hkdf_responder_ns",
    ]
    component_columns = [c for c in candidate_components if c in df.columns]
    per_batch_rows = []
    component_rows = []
    for keys, group in df.groupby(group_columns, dropna=False):
        platform_id, verified, suite = keys
        successes = group[group["success_bool"]]
        for batch, batch_group in successes.groupby("batch"):
            per_batch_rows.append({
                "platform_id": platform_id,
                "platform_verified": bool(verified),
                "suite": suite,
                "batch": batch,
                "n": len(batch_group),
                "median_latency_ms": pd.to_numeric(batch_group["handshake_wall_ns"], errors="coerce").median() / 1e6,
                "p95_latency_ms": pd.to_numeric(batch_group["handshake_wall_ns"], errors="coerce").quantile(0.95, interpolation="linear") / 1e6,
            })
        row = {
            "platform_id": platform_id,
            "platform_verified": bool(verified),
            "suite": suite,
            "n_successful": len(successes),
        }
        for component in component_columns:
            values = pd.to_numeric(successes[component], errors="coerce").dropna()
            row[f"{component}_median_us"] = values.median() / 1e3 if len(values) else None
        component_rows.append(row)
    per_batch_path = TABLE_DIR / f"per_batch_stats{suffix}.csv"
    pd.DataFrame(per_batch_rows).sort_values(["platform_id", "suite", "batch"]).to_csv(per_batch_path, index=False)
    component_path = TABLE_DIR / f"component_timings{suffix}.csv"
    pd.DataFrame(component_rows).sort_values(["platform_id", "suite"]).to_csv(component_path, index=False)

    # Primary comparison excludes unverified Platform B runs. Keep them visible in
    # the all-runs table rather than deleting or hiding them.
    valid_platform_rows = summary_df[
        (summary_df["platform_id"] == "A")
        | ((summary_df["platform_id"] == "B") & summary_df["platform_verified"])
    ].copy()
    valid_path = TABLE_DIR / f"comparison_summary_verified{suffix}.csv"
    valid_platform_rows.to_csv(valid_path, index=False)

    if ((summary_df["platform_id"] == "B") & (~summary_df["platform_verified"])).any():
        print("WARNING: unverified Platform B rows are retained in the all-runs table but excluded from the primary comparison.")

    if not valid_platform_rows.empty:
        pivot = valid_platform_rows.pivot_table(
            index="suite", columns="platform_id", values="median_latency_ms", aggfunc="mean"
        )
        ax = pivot.plot(kind="bar", rot=0)
        ax.set_title("Median local handshake latency by suite and platform")
        ax.set_ylabel("Median latency (ms)")
        ax.set_xlabel("Suite")
        ax.grid(axis="y", alpha=0.25)
        plt.tight_layout()
        plt.savefig(FIGURE_DIR / f"median_latency_comparison{suffix}.png", dpi=180)
        plt.close()

        payload = valid_platform_rows.pivot_table(
            index="suite", columns="platform_id", values="payload_bytes_min", aggfunc="min"
        )
        ax = payload.plot(kind="bar", rot=0)
        ax.set_title("Raw handshake payload bytes (not packet/frame overhead)")
        ax.set_ylabel("Bytes per handshake")
        ax.set_xlabel("Suite")
        ax.grid(axis="y", alpha=0.25)
        plt.tight_layout()
        plt.savefig(FIGURE_DIR / f"payload_bytes_comparison{suffix}.png", dpi=180)
        plt.close()

    memory_files = [
        p for p in sorted(TABLE_DIR.glob("memory_*.csv")) if _matches(p, run_ids)
    ]
    if memory_files:
        memories = pd.concat([pd.read_csv(path).assign(source_file=path.name) for path in memory_files], ignore_index=True)
        if "platform_verified" in memories:
            memories["platform_verified_bool"] = _as_bool(memories["platform_verified"])
        else:
            memories["platform_verified_bool"] = False
        memories["baseline_rss_mib"] = pd.to_numeric(memories["baseline_rss_bytes"], errors="coerce") / (1024 * 1024)
        memories["sampled_peak_rss_mib"] = pd.to_numeric(memories["sampled_peak_rss_bytes"], errors="coerce") / (1024 * 1024)
        memories["sampled_peak_delta_mib"] = pd.to_numeric(memories["sampled_peak_delta_bytes"], errors="coerce") / (1024 * 1024)
        mem_out = TABLE_DIR / f"memory_comparison_all_runs{suffix}.csv"
        memories.to_csv(mem_out, index=False)
        valid_memory = memories[
            (memories["platform_id"] == "A")
            | ((memories["platform_id"] == "B") & memories["platform_verified_bool"])
        ]
        if not valid_memory.empty:
            pivot = valid_memory.pivot_table(
                index="mode", columns="platform_id", values="sampled_peak_delta_mib", aggfunc="mean"
            )
            ax = pivot.plot(kind="bar", rot=0)
            ax.set_title("Sampled peak RSS increase in separate memory probe")
            ax.set_ylabel("MiB above warmed baseline")
            ax.set_xlabel("Suite")
            ax.grid(axis="y", alpha=0.25)
            plt.tight_layout()
            plt.savefig(FIGURE_DIR / f"memory_delta_comparison{suffix}.png", dpi=180)
            plt.close()

    print(f"Wrote: {summary_path.relative_to(ROOT)}")
    print(f"Wrote: {valid_path.relative_to(ROOT)}")
    print(f"Wrote: {per_batch_path.relative_to(ROOT)}")
    print(f"Wrote: {component_path.relative_to(ROOT)}")
    print("Plots written only for available verified data.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

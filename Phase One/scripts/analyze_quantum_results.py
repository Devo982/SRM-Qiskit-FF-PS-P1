
"""Validate, summarize and visualize the raw Processor A/B results."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import pandas as pd

from src.visualization import (
    load_quantum_metrics,
    plot_coupling_maps,
    plot_depth_cx_swap_comparison,
    plot_fidelity_error_comparison,
)


SUMMARY_COLUMNS = [
    "run_id",
    "timestamp_utc",
    "processor_id",
    "processor_name",
    "processor_config_sha256",
    "reps",
    "logical_qubit_count",
    "physical_qubit_budget",
    "logical_depth",
    "transpiled_depth",
    "native_cx_count",
    "explicit_routing_swap_count",
    "unconstrained_cx_count",
    "extra_cx_count",
    "swap_equivalent_cx_overhead",
    "ideal_observable_expectation",
    "noisy_observable_estimate",
    "absolute_observable_error",
    "distribution_fidelity",
    "shots",
    "seed_transpiler",
    "seed_simulator",
    "noise_rates",
]


COMPARISON_METRICS = {
    "transpiled_depth": "transpiled_depth",
    "native_cx_count": "native_cx_count",
    "explicit_routing_swap_count": "diagnostic_swap_count",
    "swap_equivalent_cx_overhead": "swap_equivalent_cx_proxy",
    "distribution_fidelity": "distribution_fidelity",
    "absolute_observable_error": "absolute_observable_error",
    "noisy_observable_estimate": "noisy_observable_estimate",
}


def build_comparison_table(frame: pd.DataFrame) -> pd.DataFrame:
    """Build paired A/B metrics and signed B-minus-A differences."""
    rows = []

    for reps in (1, 2, 3):
        a = frame[
            (frame["processor_id"] == "A") & (frame["reps"] == reps)
        ].iloc[0]
        b = frame[
            (frame["processor_id"] == "B") & (frame["reps"] == reps)
        ].iloc[0]

        row = {
            "reps": reps,
            "logical_depth": int(a["logical_depth"]),
            "processor_A_physical_qubit_budget": int(a["physical_qubit_budget"]),
            "processor_B_physical_qubit_budget": int(b["physical_qubit_budget"]),
        }

        for source_column, output_prefix in COMPARISON_METRICS.items():
            a_value = a[source_column]
            b_value = b[source_column]
            row[f"processor_A_{output_prefix}"] = a_value
            row[f"processor_B_{output_prefix}"] = b_value

            if pd.isna(a_value) or pd.isna(b_value):
                delta = float("nan")
            else:
                delta = float(b_value) - float(a_value)

            row[f"delta_B_minus_A_{output_prefix}"] = delta

        rows.append(row)

    return pd.DataFrame(rows)


def run_analysis(
    metrics_csv: str | Path = REPO_ROOT / "data/raw/quantum_metrics.csv",
    processors_dir: str | Path = REPO_ROOT / "processors",
    output_root: str | Path = REPO_ROOT,
) -> dict[str, str]:
    """Validate the raw CSV and regenerate summary tables and figures."""
    metrics_csv = Path(metrics_csv)
    processors_dir = Path(processors_dir)
    output_root = Path(output_root)

    frame = load_quantum_metrics(metrics_csv)

    summary_path = output_root / "data/processed/quantum_summary.csv"
    comparison_path = output_root / "results/tables/processor_A_vs_B.csv"
    figures_dir = output_root / "results/figures"

    summary_path.parent.mkdir(parents=True, exist_ok=True)
    comparison_path.parent.mkdir(parents=True, exist_ok=True)
    figures_dir.mkdir(parents=True, exist_ok=True)

    summary = frame[SUMMARY_COLUMNS].copy()
    summary.to_csv(summary_path, index=False, float_format="%.12g")

    comparison = build_comparison_table(frame)
    comparison.to_csv(
        comparison_path,
        index=False,
        float_format="%.12g",
    )

    figure_paths = {
        "coupling_maps": plot_coupling_maps(
            processors_dir,
            figures_dir / "coupling_maps.png",
        ),
        "depth_cx_swap_comparison": plot_depth_cx_swap_comparison(
            frame,
            figures_dir / "depth_cx_swap_comparison.png",
        ),
        "fidelity_error_comparison": plot_fidelity_error_comparison(
            frame,
            figures_dir / "noisy_fidelity_by_reps.png",
        ),
    }

    outputs = {
        "summary_csv": str(summary_path),
        "comparison_csv": str(comparison_path),
        **{key: str(path) for key, path in figure_paths.items()},
    }

    print(f"Validated raw run: {frame['run_id'].iloc[0]}")
    print(f"Validated cases: {len(frame)}")
    for name, path in outputs.items():
        print(f"{name}: {path}")

    return outputs


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Validate raw quantum metrics, create comparison tables and "
            "generate architecture benchmark figures."
        )
    )
    parser.add_argument(
        "--metrics-csv",
        type=Path,
        default=REPO_ROOT / "data/raw/quantum_metrics.csv",
    )
    parser.add_argument(
        "--processors-dir",
        type=Path,
        default=REPO_ROOT / "processors",
    )
    parser.add_argument(
        "--output-root",
        type=Path,
        default=REPO_ROOT,
    )
    args = parser.parse_args()

    run_analysis(
        metrics_csv=args.metrics_csv,
        processors_dir=args.processors_dir,
        output_root=args.output_root,
    )


if __name__ == "__main__":
    main()

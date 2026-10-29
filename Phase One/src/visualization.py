
"""Validation and visualization of quantum architecture benchmark results."""

import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")

import matplotlib.pyplot as plt
import networkx as nx
import numpy as np
import pandas as pd


EXPECTED_CASES = {
    (processor_id, reps)
    for processor_id in ("A", "B")
    for reps in (1, 2, 3)
}

REQUIRED_COLUMNS = {
    "run_id",
    "processor_id",
    "processor_name",
    "reps",
    "shots",
    "seed_transpiler",
    "seed_simulator",
    "logical_depth",
    "transpiled_depth",
    "logical_qubit_count",
    "physical_qubit_budget",
    "native_cx_count",
    "explicit_routing_swap_count",
    "unconstrained_cx_count",
    "extra_cx_count",
    "swap_equivalent_cx_overhead",
    "ideal_observable_expectation",
    "noisy_observable_estimate",
    "absolute_observable_error",
    "distribution_fidelity",
    "processor_config_sha256",
}


def load_quantum_metrics(metrics_csv: str | Path) -> pd.DataFrame:
    """Load and validate the canonical six-case benchmark CSV."""
    path = Path(metrics_csv)
    if not path.is_file():
        raise FileNotFoundError(f"Metrics CSV does not exist: {path}")

    frame = pd.read_csv(path)
    missing = REQUIRED_COLUMNS - set(frame.columns)

    if missing:
        raise ValueError(f"Metrics CSV is missing columns: {sorted(missing)}")

    if frame.empty:
        raise ValueError("Metrics CSV contains no result rows")

    if frame["run_id"].nunique(dropna=False) != 1:
        raise ValueError("Metrics rows must belong to exactly one run")

    pairs = list(zip(frame["processor_id"], frame["reps"]))
    if len(pairs) != len(set(pairs)):
        raise ValueError("Duplicate processor/repetition results detected")

    if set(pairs) != EXPECTED_CASES:
        raise ValueError(
            f"Expected cases {sorted(EXPECTED_CASES)}, got {sorted(set(pairs))}"
        )

    numeric_columns = [
        "reps",
        "shots",
        "seed_transpiler",
        "seed_simulator",
        "logical_depth",
        "transpiled_depth",
        "logical_qubit_count",
        "physical_qubit_budget",
        "native_cx_count",
        "explicit_routing_swap_count",
        "unconstrained_cx_count",
        "extra_cx_count",
        "ideal_observable_expectation",
        "noisy_observable_estimate",
        "absolute_observable_error",
        "distribution_fidelity",
    ]

    for column in numeric_columns:
        frame[column] = pd.to_numeric(frame[column], errors="raise")

    if not (frame["shots"] == 4096).all():
        raise ValueError("All canonical baseline cases must use 4096 shots")

    if not (frame["seed_transpiler"] == 42).all():
        raise ValueError("All cases must use transpiler seed 42")

    if not (frame["seed_simulator"] == 42).all():
        raise ValueError("All cases must use simulator seed 42")

    metric_values = frame[
        [
            "transpiled_depth",
            "native_cx_count",
            "absolute_observable_error",
            "distribution_fidelity",
        ]
    ].to_numpy(dtype=float)

    if not np.isfinite(metric_values).all():
        raise ValueError("Metrics contain non-finite values")

    if not frame["distribution_fidelity"].between(0.0, 1.0).all():
        raise ValueError("Distribution fidelity must lie within [0, 1]")

    if (frame["absolute_observable_error"] < 0).any():
        raise ValueError("Absolute observable error cannot be negative")

    # Both topologies must use the same logical workload and exact reference.
    for reps in (1, 2, 3):
        a = frame[(frame["processor_id"] == "A") & (frame["reps"] == reps)].iloc[0]
        b = frame[(frame["processor_id"] == "B") & (frame["reps"] == reps)].iloc[0]

        if a["logical_depth"] != b["logical_depth"]:
            raise ValueError(f"Logical depths differ for reps={reps}")

        if not np.isclose(
            a["ideal_observable_expectation"],
            b["ideal_observable_expectation"],
            atol=1e-10,
            rtol=0.0,
        ):
            raise ValueError(f"Ideal references differ for reps={reps}")

    return frame.sort_values(
        ["processor_id", "reps"]
    ).reset_index(drop=True)


def plot_coupling_maps(
    processors_dir: str | Path,
    output_path: str | Path,
) -> Path:
    """Draw both configured undirected physical connectivity graphs."""
    processors_dir = Path(processors_dir)
    output_path = Path(output_path)

    fig, axes = plt.subplots(1, 2, figsize=(10, 4.7))

    try:
        for axis, processor_id in zip(axes, ("A", "B")):
            config_path = processors_dir / f"processor_{processor_id}.json"
            spec = json.loads(config_path.read_text(encoding="utf-8"))

            graph = nx.Graph()
            graph.add_nodes_from(range(int(spec["num_qubits"])))
            graph.add_edges_from(
                tuple(edge)
                for edge in spec["coupling_edges_undirected"]
            )

            if not nx.is_connected(graph):
                raise ValueError(f"{spec['name']} graph is disconnected")

            if processor_id == "A":
                positions = {node: (node, 0) for node in graph.nodes}
            else:
                positions = {
                    node: (node % 3, -(node // 3))
                    for node in graph.nodes
                }

            nx.draw_networkx(
                graph,
                pos=positions,
                ax=axis,
                with_labels=True,
                node_size=780,
                font_size=10,
                width=1.8,
            )
            axis.set_title(
                f"{spec['name']}\n"
                f"{spec['num_qubits']} qubits, {graph.number_of_edges()} couplings"
            )
            axis.set_axis_off()

        fig.tight_layout()
        output_path.parent.mkdir(parents=True, exist_ok=True)
        fig.savefig(output_path, dpi=180, bbox_inches="tight")
    finally:
        plt.close(fig)

    return output_path


def _grouped_bar(
    axis,
    frame: pd.DataFrame,
    column: str,
    title: str,
    ylabel: str,
) -> None:
    reps = np.array([1, 2, 3])
    width = 0.36

    for offset, processor_id in enumerate(("A", "B")):
        subset = (
            frame[frame["processor_id"] == processor_id]
            .set_index("reps")
            .reindex(reps)
        )
        values = pd.to_numeric(
            subset[column], errors="coerce"
        ).to_numpy(dtype=float)

        axis.bar(
            reps + (offset - 0.5) * width,
            values,
            width=width,
            label=f"Processor {processor_id}",
        )

    axis.set_title(title)
    axis.set_xlabel("Workload repetitions")
    axis.set_ylabel(ylabel)
    axis.set_xticks(reps)
    axis.legend(fontsize=8)


def plot_depth_cx_swap_comparison(
    frame: pd.DataFrame,
    output_path: str | Path,
) -> Path:
    """Plot native-basis cost and diagnostic routing metrics side by side."""
    output_path = Path(output_path)

    chart_fields = [
        (
            "transpiled_depth",
            "Transpiled depth",
            "Circuit depth (layers)",
        ),
        (
            "native_cx_count",
            "Native CX count",
            "CX gates",
        ),
        (
            "explicit_routing_swap_count",
            "Diagnostic SWAP count",
            "Explicit SWAP gates",
        ),
        (
            "swap_equivalent_cx_overhead",
            "SWAP-equivalent CX proxy",
            "Extra CX / 3 (proxy)",
        ),
    ]

    fig, axes = plt.subplots(1, 4, figsize=(17, 4.8))
    try:
        for axis, (column, title, ylabel) in zip(axes, chart_fields):
            _grouped_bar(axis, frame, column, title, ylabel)

        fig.suptitle(
            "Processor A vs B: compiled circuit cost and routing diagnostics",
            fontsize=12,
        )
        fig.tight_layout()
        output_path.parent.mkdir(parents=True, exist_ok=True)
        fig.savefig(output_path, dpi=180, bbox_inches="tight")
    finally:
        plt.close(fig)

    return output_path


def plot_fidelity_error_comparison(
    frame: pd.DataFrame,
    output_path: str | Path,
) -> Path:
    """Plot classical distribution fidelity and absolute observable error."""
    output_path = Path(output_path)

    fig, axes = plt.subplots(1, 2, figsize=(11, 4.5))

    try:
        for processor_id in ("A", "B"):
            subset = frame[frame["processor_id"] == processor_id].sort_values(
                "reps"
            )
            label = f"Processor {processor_id}"

            axes[0].plot(
                subset["reps"],
                subset["distribution_fidelity"],
                marker="o",
                label=label,
            )
            axes[1].plot(
                subset["reps"],
                subset["absolute_observable_error"],
                marker="o",
                label=label,
            )

        axes[0].set_title("Classical distribution fidelity")
        axes[0].set_ylabel("Fidelity (0 to 1)")
        axes[0].set_ylim(0.0, 1.02)

        axes[1].set_title("Absolute observable error")
        axes[1].set_ylabel("Absolute expectation-value error")

        for axis in axes:
            axis.set_xlabel("Workload repetitions")
            axis.set_xticks([1, 2, 3])
            axis.legend()

        fig.suptitle(
            "Noisy simulation results: 4096 shots, simulator seed 42",
            fontsize=12,
        )
        fig.tight_layout()
        output_path.parent.mkdir(parents=True, exist_ok=True)
        fig.savefig(output_path, dpi=180, bbox_inches="tight")
    finally:
        plt.close(fig)

    return output_path

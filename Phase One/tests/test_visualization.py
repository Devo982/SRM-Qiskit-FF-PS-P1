
import csv
import math
from pathlib import Path

import pytest

from scripts.analyze_quantum_results import run_analysis
from src.visualization import load_quantum_metrics


REPO_ROOT = Path(__file__).resolve().parents[1]


def write_synthetic_metrics(path: Path, *, omit_case=None) -> None:
    rows = []

    for processor_id, qubits in (("A", 5), ("B", 9)):
        for reps in (1, 2, 3):
            if (processor_id, reps) == omit_case:
                continue

            rows.append({
                "run_id": "TEST_RUN",
                "timestamp_utc": "2026-01-01T00:00:00+00:00",
                "processor_id": processor_id,
                "processor_name": f"Processor {processor_id}",
                "processor_config_sha256": processor_id * 64,
                "reps": reps,
                "logical_depth": 8 * reps,
                "transpiled_depth": (30 + reps) if processor_id == "A" else (25 + reps),
                "logical_qubit_count": 5,
                "physical_qubit_budget": qubits,
                "transpiled_physical_qubit_count": qubits,
                "native_cx_count": (25 * reps) if processor_id == "A" else (16 * reps),
                "native_explicit_swap_count": 0,
                "explicit_routing_swap_count": (5 * reps) if processor_id == "A" else reps,
                "unconstrained_cx_count": 14 * reps,
                "extra_cx_count": (10 * reps) if processor_id == "A" else (2 * reps),
                "swap_equivalent_cx_overhead": (
                    (10 * reps / 3) if processor_id == "A" else (2 * reps / 3)
                ),
                "optimization_level": 1,
                "seed_transpiler": 42,
                "native_basis_gates": '["rz","sx","x","cx"]',
                "native_operation_counts": "{}",
                "diagnostic_operation_counts": "{}",
                "shots": 4096,
                "seed_simulator": 42,
                "ideal_observable_expectation": 0.8 * reps,
                "noisy_observable_estimate": 0.7 * reps,
                "absolute_observable_error": 0.1 * reps,
                "distribution_fidelity": 0.99 - 0.01 * reps,
                "measurement_outcome_count": 4096,
                "ideal_state_norm": 1.0,
                "noise_rates": "{}",
            })

    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def test_valid_metrics_create_tables_and_all_figures(tmp_path):
    input_csv = tmp_path / "input/quantum_metrics.csv"
    output_root = tmp_path / "output"
    write_synthetic_metrics(input_csv)

    outputs = run_analysis(
        metrics_csv=input_csv,
        processors_dir=REPO_ROOT / "processors",
        output_root=output_root,
    )

    assert len(outputs) == 5
    assert Path(outputs["summary_csv"]).is_file()
    assert Path(outputs["comparison_csv"]).is_file()

    expected_figures = [
        "coupling_maps",
        "depth_cx_swap_comparison",
        "fidelity_error_comparison",
    ]
    for key in expected_figures:
        figure = Path(outputs[key])
        assert figure.is_file()
        assert figure.stat().st_size > 1000


def test_missing_case_is_rejected(tmp_path):
    input_csv = tmp_path / "incomplete.csv"
    write_synthetic_metrics(input_csv, omit_case=("B", 3))

    with pytest.raises(ValueError, match="Expected cases"):
        load_quantum_metrics(input_csv)


def test_out_of_range_fidelity_is_rejected(tmp_path):
    input_csv = tmp_path / "invalid_fidelity.csv"
    write_synthetic_metrics(input_csv)

    with input_csv.open(newline="", encoding="utf-8") as stream:
        rows = list(csv.DictReader(stream))
        fields = list(rows[0])

    rows[0]["distribution_fidelity"] = str(1.1)
    with input_csv.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)

    with pytest.raises(ValueError, match="fidelity"):
        load_quantum_metrics(input_csv)

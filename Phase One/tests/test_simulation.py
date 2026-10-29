
from pathlib import Path

import pytest

from src.processors import load_processor
from src.simulation import run_noisy_case


@pytest.mark.parametrize("processor_id", ["A", "B"])
def test_noisy_simulation_returns_valid_metrics(processor_id):
    path = Path("processors") / f"processor_{processor_id}.json"
    spec, _graph, coupling_map, noise_model = load_processor(path)

    result = run_noisy_case(
        spec,
        coupling_map,
        noise_model,
        reps=1,
        seed_simulator=42,
    )

    metrics = result["metrics"]
    counts = result["counts"]

    assert sum(counts.values()) == 4096
    assert metrics["shots"] == 4096
    assert metrics["seed_simulator"] == 42
    assert metrics["logical_qubit_count"] == 5
    assert metrics["logical_depth"] > 0
    assert metrics["transpiled_depth"] > 0
    assert metrics["native_cx_count"] >= 0

    assert 0.0 <= metrics["distribution_fidelity"] <= 1.0
    assert metrics["absolute_observable_error"] >= 0.0
    assert metrics["ideal_state_norm"] == pytest.approx(1.0, abs=1e-10)

    assert metrics["noise_rates"]["one_qubit_depolarizing_probability"] == 0.001
    assert metrics["noise_rates"]["cx_depolarizing_probability"] == 0.005
    assert metrics["noise_rates"]["readout_error_probability"] == 0.01


def test_fixed_simulator_seed_reproduces_counts():
    path = Path("processors") / "processor_A.json"
    spec, _graph, coupling_map, noise_model = load_processor(path)

    first = run_noisy_case(
        spec, coupling_map, noise_model, reps=1, seed_simulator=42
    )
    second = run_noisy_case(
        spec, coupling_map, noise_model, reps=1, seed_simulator=42
    )

    assert first["counts"] == second["counts"]

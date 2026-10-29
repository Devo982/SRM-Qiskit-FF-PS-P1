
from pathlib import Path

import pytest

from src.problem import build_logical_circuit
from src.processors import load_processor
from src.routing import compile_for_processor


@pytest.mark.parametrize("processor_id", ["A", "B"])
def test_native_transpilation_obeys_processor_basis(processor_id):
    processor_path = (
        Path("processors") / f"processor_{processor_id}.json"
    )
    spec, graph, coupling_map, _noise = load_processor(processor_path)

    result = compile_for_processor(
        build_logical_circuit(1),
        spec,
        coupling_map,
    )

    native = result["native_circuit"]
    metrics = result["metrics"]

    allowed = set(spec["basis_gates"]) | {
        "measure",
        "barrier",
        "delay",
        "reset",
    }
    actual_operations = {operation.name for operation in native.data}

    assert actual_operations <= allowed
    assert native.num_qubits == spec["num_qubits"]
    assert metrics["logical_qubit_count"] == 5
    assert metrics["physical_qubit_budget"] == spec["num_qubits"]
    assert metrics["transpiled_depth"] == native.depth()
    assert metrics["native_cx_count"] == native.count_ops().get("cx", 0)
    assert metrics["native_explicit_swap_count"] == 0
    assert metrics["seed_transpiler"] == 42
    assert metrics["optimization_level"] == 1


@pytest.mark.parametrize("processor_id", ["A", "B"])
def test_routing_diagnostics_and_cx_proxy_are_consistent(processor_id):
    processor_path = (
        Path("processors") / f"processor_{processor_id}.json"
    )
    spec, _graph, coupling_map, _noise = load_processor(processor_path)

    result = compile_for_processor(
        build_logical_circuit(1),
        spec,
        coupling_map,
    )
    metrics = result["metrics"]

    expected_delta = (
        metrics["native_cx_count"] - metrics["unconstrained_cx_count"]
    )
    assert metrics["extra_cx_count"] == expected_delta
    assert metrics["explicit_routing_swap_count"] >= 0
    assert metrics["routing_diagnostic_depth"] > 0

    if expected_delta > 0:
        assert metrics["swap_equivalent_cx_overhead"] == pytest.approx(
            expected_delta / 3.0
        )
    else:
        assert metrics["swap_equivalent_cx_overhead"] is None

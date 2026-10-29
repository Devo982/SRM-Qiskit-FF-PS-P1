
"""Transpile logical circuits for Processor A/B and measure routing overhead."""

from qiskit import QuantumCircuit, transpile


NON_GATE_OPERATIONS = {"measure", "barrier", "delay", "reset"}


def compile_for_processor(
    logical_circuit: QuantumCircuit,
    spec: dict,
    coupling_map,
) -> dict:
    """Compile one logical circuit into native, diagnostic, and unconstrained forms.

    The native circuit is the executable-basis result. The diagnostic circuit
    includes SWAP in its allowed basis to expose explicit routing SWAPs when
    supported by the installed Qiskit transpiler.
    """
    settings = spec["transpilation"]
    basis_gates = list(spec["basis_gates"])
    num_physical_qubits = int(spec["num_qubits"])

    if logical_circuit.num_qubits > num_physical_qubits:
        raise ValueError(
            f"{spec['name']} has {num_physical_qubits} physical qubits, "
            f"but the logical circuit needs {logical_circuit.num_qubits}"
        )

    optimization_level = int(settings["optimization_level"])
    seed_transpiler = int(settings["seed_transpiler"])

    common_settings = {
        "basis_gates": basis_gates,
        "optimization_level": optimization_level,
        "seed_transpiler": seed_transpiler,
    }

    # Actual executable circuit: enforce the processor's connectivity and basis.
    native_circuit = transpile(
        logical_circuit,
        coupling_map=coupling_map,
        **common_settings,
    )

    # Diagnostic only: include SWAP as an allowed operation so that routing
    # swaps can remain explicit instead of necessarily being decomposed to CX.
    diagnostic_basis = list(dict.fromkeys([*basis_gates, "swap"]))
    diagnostic_circuit = transpile(
        logical_circuit,
        coupling_map=coupling_map,
        basis_gates=diagnostic_basis,
        optimization_level=optimization_level,
        seed_transpiler=seed_transpiler,
    )

    # Reference compilation: same basis and optimization settings, but no
    # connectivity restriction.
    unconstrained_circuit = transpile(
        logical_circuit,
        **common_settings,
    )

    native_ops = native_circuit.count_ops()
    diagnostic_ops = diagnostic_circuit.count_ops()
    unconstrained_ops = unconstrained_circuit.count_ops()

    native_cx_count = int(native_ops.get("cx", 0))
    unconstrained_cx_count = int(unconstrained_ops.get("cx", 0))
    extra_cx_count = native_cx_count - unconstrained_cx_count

    # This is only a CX-cost proxy, not an exact count of routing SWAPs.
    swap_equivalent_overhead = (
        extra_cx_count / 3.0 if extra_cx_count > 0 else None
    )

    metrics = {
        "processor_name": spec["name"],
        "logical_depth": int(logical_circuit.depth()),
        "transpiled_depth": int(native_circuit.depth()),
        "logical_qubit_count": int(logical_circuit.num_qubits),
        "physical_qubit_budget": num_physical_qubits,
        "transpiled_physical_qubit_count": int(native_circuit.num_qubits),
        "native_cx_count": native_cx_count,
        "native_explicit_swap_count": int(native_ops.get("swap", 0)),
        "routing_diagnostic_depth": int(diagnostic_circuit.depth()),
        "explicit_routing_swap_count": int(diagnostic_ops.get("swap", 0)),
        "unconstrained_cx_count": unconstrained_cx_count,
        "extra_cx_count": extra_cx_count,
        "swap_equivalent_cx_overhead": swap_equivalent_overhead,
        "optimization_level": optimization_level,
        "seed_transpiler": seed_transpiler,
        "native_basis_gates": basis_gates,
        "native_operation_counts": {
            str(name): int(count) for name, count in native_ops.items()
        },
        "diagnostic_operation_counts": {
            str(name): int(count) for name, count in diagnostic_ops.items()
        },
    }

    return {
        "native_circuit": native_circuit,
        "diagnostic_circuit": diagnostic_circuit,
        "unconstrained_circuit": unconstrained_circuit,
        "metrics": metrics,
    }

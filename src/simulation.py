
"""Run reproducible noisy simulations for the Processor A/B benchmark."""

from numbers import Integral

from qiskit_aer import AerSimulator
from qiskit_aer.noise import NoiseModel
from qiskit.transpiler import CouplingMap

from src.metrics import (
    absolute_observable_error,
    distribution_fidelity,
    estimate_zz_observable,
)
from src.problem import build_logical_circuit, ideal_reference
from src.routing import compile_for_processor


def run_noisy_case(
    spec: dict,
    coupling_map: CouplingMap,
    noise_model: NoiseModel,
    reps: int,
    seed_simulator: int = 42,
) -> dict:
    """Compile, simulate and evaluate one processor/repetition configuration."""
    if (
        isinstance(seed_simulator, bool)
        or not isinstance(seed_simulator, Integral)
        or seed_simulator < 0
    ):
        raise ValueError("seed_simulator must be a non-negative integer")

    shots = spec["transpilation"]["shots"]
    if isinstance(shots, bool) or not isinstance(shots, Integral) or shots <= 0:
        raise ValueError("Configured shots must be a positive integer")

    # Build both forms: use the unmeasured circuit to record logical depth,
    # and the measured circuit for end-to-end transpilation and execution.
    logical_circuit = build_logical_circuit(reps, measure=False)
    measured_circuit = build_logical_circuit(reps, measure=True)

    ideal_state, ideal_expectation, ideal_probabilities = ideal_reference(reps)

    compilation = compile_for_processor(
        measured_circuit,
        spec,
        coupling_map,
    )
    compiled = compilation["native_circuit"]

    simulator = AerSimulator(noise_model=noise_model)
    result = simulator.run(
        compiled,
        shots=int(shots),
        seed_simulator=int(seed_simulator),
    ).result()

    if not result.success:
        raise RuntimeError(
            f"Noisy simulation failed for {spec['name']}, reps={reps}: "
            f"{result.status}"
        )

    counts = result.get_counts()
    if not counts or sum(counts.values()) != shots:
        raise RuntimeError(
            f"Expected {shots} measured shots; received "
            f"{sum(counts.values()) if counts else 0}"
        )

    noisy_expectation = estimate_zz_observable(counts)
    observable_error = absolute_observable_error(
        noisy_expectation,
        ideal_expectation,
    )
    fidelity = distribution_fidelity(
        ideal_probabilities,
        counts,
    )

    metrics = dict(compilation["metrics"])
    metrics.update({
        "reps": int(reps),
        "shots": int(shots),
        "seed_simulator": int(seed_simulator),
        "logical_depth": int(logical_circuit.depth()),
        "ideal_observable_expectation": float(ideal_expectation),
        "noisy_observable_estimate": float(noisy_expectation),
        "absolute_observable_error": float(observable_error),
        "distribution_fidelity": float(fidelity),
        "measurement_outcome_count": int(sum(counts.values())),
        "ideal_state_norm": float(
            (ideal_state.data.conj() @ ideal_state.data).real
        ),
        "noise_rates": dict(spec["noise"]),
    })

    return {
        "metrics": metrics,
        "counts": {str(key): int(value) for key, value in counts.items()},
        "ideal_probabilities": dict(ideal_probabilities),
        "compiled_circuit": compiled,
        "diagnostic_circuit": compilation["diagnostic_circuit"],
        "unconstrained_circuit": compilation["unconstrained_circuit"],
    }

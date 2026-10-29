
"""Fixed five-qubit workload and exact ideal reference for the architecture benchmark."""

from math import isclose, isfinite

from qiskit import QuantumCircuit
from qiskit.quantum_info import SparsePauliOp, Statevector


N_LOGICAL_QUBITS = 5
THETA = 0.37
BETA = 0.23
SUPPORTED_REPS = (1, 2, 3)

# (logical qubit i, logical qubit j, interaction weight)
INTERACTIONS = (
    (0, 1, 1.0),
    (1, 2, 0.8),
    (2, 3, 1.2),
    (3, 4, 0.9),
    (4, 0, 1.1),
    (0, 2, 0.6),
    (1, 3, 0.7),
)


def _validate_reps(reps: int) -> None:
    """Accept only the predeclared repetition sweep."""
    if (
        isinstance(reps, bool)
        or not isinstance(reps, int)
        or reps not in SUPPORTED_REPS
    ):
        raise ValueError(
            f"reps must be one of {SUPPORTED_REPS}; received {reps!r}"
        )

def zz_pauli_label(num_qubits: int, i: int, j: int) -> str:
    """Build a Qiskit Pauli label for Z_i Z_j.

    Qiskit Pauli labels place qubit 0 at the rightmost character.
    """
    if num_qubits < 1:
        raise ValueError("num_qubits must be positive")
    if not (0 <= i < num_qubits and 0 <= j < num_qubits):
        raise ValueError("Pauli qubit indices are out of range")
    if i == j:
        raise ValueError("A ZZ interaction requires two distinct qubits")

    label = ["I"] * num_qubits
    label[num_qubits - 1 - i] = "Z"
    label[num_qubits - 1 - j] = "Z"
    return "".join(label)


def build_zz_observable() -> SparsePauliOp:
    """Construct H_ZZ = sum(weight * Z_i Z_j)."""
    terms = [
        (zz_pauli_label(N_LOGICAL_QUBITS, i, j), weight)
        for i, j, weight in INTERACTIONS
    ]
    return SparsePauliOp.from_list(terms)


def build_logical_circuit(
    reps: int = 1, *, measure: bool = False
) -> QuantumCircuit:
    """Build the deterministic workload, with optional final measurements."""
    _validate_reps(reps)

    if measure:
        circuit = QuantumCircuit(N_LOGICAL_QUBITS, N_LOGICAL_QUBITS)
    else:
        circuit = QuantumCircuit(N_LOGICAL_QUBITS)

    for _ in range(reps):
        # Create a nontrivial input state.
        circuit.h(range(N_LOGICAL_QUBITS))

        # Apply the fixed weighted ZZ interactions.
        for i, j, weight in INTERACTIONS:
            circuit.rzz(THETA * weight, i, j)

        # Apply the fixed single-qubit rotations.
        for qubit in range(N_LOGICAL_QUBITS):
            circuit.rx(BETA, qubit)

    if measure:
        # Map logical qubit i directly to classical bit i.
        circuit.measure(range(N_LOGICAL_QUBITS), range(N_LOGICAL_QUBITS))

    return circuit


def ideal_reference(
    reps: int = 1,
) -> tuple[Statevector, float, dict[str, float]]:
    """Return the ideal state, exact H_ZZ expectation, and ideal probabilities."""
    circuit = build_logical_circuit(reps, measure=False)
    state = Statevector.from_instruction(circuit)
    observable = build_zz_observable()

    expectation = float(state.expectation_value(observable).real)

    # Normalize key formatting to five-bit output strings.
    probabilities = {
        format(int(bitstring, 2), f"0{N_LOGICAL_QUBITS}b"): float(probability)
        for bitstring, probability in state.probabilities_dict().items()
    }

    probability_sum = sum(probabilities.values())
    theoretical_bound = sum(abs(weight) for _, _, weight in INTERACTIONS)

    if not isclose(float((state.data.conj() @ state.data).real), 1.0, abs_tol=1e-10):
        raise ValueError("Ideal statevector is not normalized")

    if not isclose(probability_sum, 1.0, abs_tol=1e-10):
        raise ValueError(f"Ideal probabilities sum to {probability_sum}, not 1")

    if not isfinite(expectation):
        raise ValueError("Exact observable expectation is not finite")

    if abs(expectation) > theoretical_bound + 1e-10:
        raise ValueError("Exact observable expectation exceeds its theoretical bound")

    return state, expectation, probabilities

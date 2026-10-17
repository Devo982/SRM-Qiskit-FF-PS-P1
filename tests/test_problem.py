
from math import isclose, isfinite

import numpy as np
import pytest
from qiskit.quantum_info import SparsePauliOp

from src.problem import (
    INTERACTIONS,
    N_LOGICAL_QUBITS,
    SUPPORTED_REPS,
    build_logical_circuit,
    build_zz_observable,
    ideal_reference,
    zz_pauli_label,
)


def test_logical_and_measured_circuit_dimensions():
    logical = build_logical_circuit(1)
    measured = build_logical_circuit(1, measure=True)

    assert logical.num_qubits == 5
    assert logical.num_clbits == 0
    assert measured.num_qubits == 5
    assert measured.num_clbits == 5


def test_interactions_and_observable_are_consistent():
    observable = build_zz_observable()

    assert len(INTERACTIONS) == 7
    assert observable.num_qubits == N_LOGICAL_QUBITS
    assert len(observable.to_list()) == len(INTERACTIONS)


@pytest.mark.parametrize(
    ("i", "j", "expected"),
    [
        (0, 1, "IIIZZ"),
        (4, 0, "ZIIIZ"),
        (1, 3, "IZIZI"),
    ],
)
def test_pauli_label_qubit_order(i, j, expected):
    assert zz_pauli_label(5, i, j) == expected


def test_two_qubit_zz_label_matches_direct_matrix():
    observable = SparsePauliOp.from_list(
        [(zz_pauli_label(2, 0, 1), 1.0)]
    )

    expected = np.diag([1, -1, -1, 1])
    assert np.array_equal(observable.to_matrix(), expected)


@pytest.mark.parametrize(
    ("num_qubits", "i", "j"),
    [
        (0, 0, 1),
        (5, -1, 1),
        (5, 0, 5),
        (5, 2, 2),
    ],
)
def test_invalid_pauli_indices_raise(num_qubits, i, j):
    with pytest.raises(ValueError):
        zz_pauli_label(num_qubits, i, j)


@pytest.mark.parametrize("reps", SUPPORTED_REPS)
def test_exact_reference_is_normalized_and_bounded(reps):
    state, expectation, probabilities = ideal_reference(reps)

    state_norm = float((state.data.conj() @ state.data).real)
    probability_sum = sum(probabilities.values())
    theoretical_bound = sum(abs(weight) for _, _, weight in INTERACTIONS)

    assert isclose(state_norm, 1.0, abs_tol=1e-10)
    assert isclose(probability_sum, 1.0, abs_tol=1e-10)
    assert isfinite(expectation)
    assert abs(expectation) <= theoretical_bound + 1e-10
    assert len(probabilities) <= 2**N_LOGICAL_QUBITS
    assert all(len(bitstring) == N_LOGICAL_QUBITS for bitstring in probabilities)
    assert all(0.0 <= probability <= 1.0 for probability in probabilities.values())


@pytest.mark.parametrize("reps", [0, -1, 4, True, 1.0, "1", None])
def test_invalid_repetitions_raise(reps):
    with pytest.raises(ValueError):
        build_logical_circuit(reps)

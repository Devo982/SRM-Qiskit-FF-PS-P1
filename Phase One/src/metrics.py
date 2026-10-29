
"""Metric calculations for ideal references and sampled quantum outcomes."""

from collections.abc import Mapping, Sequence
from math import isfinite, sqrt
from numbers import Integral

from src.problem import INTERACTIONS, N_LOGICAL_QUBITS


def _validate_num_bits(num_bits: int) -> None:
    if isinstance(num_bits, bool) or not isinstance(num_bits, int):
        raise ValueError("num_bits must be a positive integer")
    if num_bits < 1:
        raise ValueError("num_bits must be a positive integer")


def _canonical_bitstring(key: object, num_bits: int) -> str:
    """Normalize a count/probability key to a fixed-width binary string."""
    _validate_num_bits(num_bits)

    if not isinstance(key, (str, int)) or isinstance(key, bool):
        raise ValueError(f"Invalid bitstring key: {key!r}")

    bitstring = str(key).replace(" ", "")
    if bitstring.startswith("0b"):
        bitstring = bitstring[2:]

    if not bitstring or any(bit not in "01" for bit in bitstring):
        raise ValueError(f"Invalid binary outcome: {key!r}")

    if len(bitstring) > num_bits:
        raise ValueError(
            f"Outcome {key!r} exceeds the {num_bits}-bit register"
        )

    return bitstring.zfill(num_bits)


def _count_distribution(
    counts: Mapping[object, int],
    num_bits: int,
) -> dict[str, float]:
    """Convert measurement counts to normalized frequencies."""
    if not isinstance(counts, Mapping) or not counts:
        raise ValueError("counts must be a non-empty mapping")

    canonical_counts: dict[str, int] = {}

    for key, count in counts.items():
        bitstring = _canonical_bitstring(key, num_bits)

        if (
            isinstance(count, bool)
            or not isinstance(count, Integral)
            or count < 0
        ):
            raise ValueError(f"Invalid measurement count for {key!r}: {count!r}")

        canonical_counts[bitstring] = (
            canonical_counts.get(bitstring, 0) + int(count)
        )

    total = sum(canonical_counts.values())
    if total <= 0:
        raise ValueError("Total measurement count must be positive")

    return {
        bitstring: count / total
        for bitstring, count in canonical_counts.items()
    }


def _validate_ideal_probabilities(
    probabilities: Mapping[object, float],
    num_bits: int,
) -> dict[str, float]:
    """Validate and normalize bitstring formatting, not probability mass."""
    if not isinstance(probabilities, Mapping) or not probabilities:
        raise ValueError("ideal probabilities must be a non-empty mapping")

    canonical: dict[str, float] = {}

    for key, probability in probabilities.items():
        bitstring = _canonical_bitstring(key, num_bits)

        try:
            value = float(probability)
        except (TypeError, ValueError, OverflowError) as exc:
            raise ValueError(
                f"Invalid probability for {key!r}: {probability!r}"
            ) from exc

        if not isfinite(value) or value < 0.0 or value > 1.0:
            raise ValueError(
                f"Probability for {key!r} must be finite and in [0, 1]"
            )

        canonical[bitstring] = canonical.get(bitstring, 0.0) + value

    total = sum(canonical.values())
    if not isfinite(total) or not abs(total - 1.0) <= 1e-10:
        raise ValueError(f"Ideal probabilities must sum to 1; got {total}")

    return canonical


def estimate_zz_observable(
    counts: Mapping[object, int],
    interactions: Sequence[tuple[int, int, float]] = INTERACTIONS,
    num_bits: int = N_LOGICAL_QUBITS,
) -> float:
    """Estimate sum(weight * Z_i Z_j) from measurement counts.

    Qiskit count strings put classical bit 0 at the rightmost position.
    The caller must have mapped logical qubit i to classical bit i.
    """
    distribution = _count_distribution(counts, num_bits)
    estimate = 0.0

    for i, j, weight in interactions:
        if (
            isinstance(i, bool)
            or isinstance(j, bool)
            or not isinstance(i, Integral)
            or not isinstance(j, Integral)
            or i < 0
            or j < 0
            or i >= num_bits
            or j >= num_bits
            or i == j
        ):
            raise ValueError(f"Invalid ZZ interaction indices: {(i, j)!r}")

        try:
            weight_value = float(weight)
        except (TypeError, ValueError, OverflowError) as exc:
            raise ValueError(f"Invalid interaction weight: {weight!r}") from exc

        if not isfinite(weight_value):
            raise ValueError(f"Interaction weight must be finite: {weight!r}")

        correlation = 0.0
        for bitstring, probability in distribution.items():
            # The rightmost character is classical bit 0.
            bit_i = int(bitstring[-1 - int(i)])
            bit_j = int(bitstring[-1 - int(j)])
            parity_sign = 1.0 if bit_i == bit_j else -1.0
            correlation += probability * parity_sign

        estimate += weight_value * correlation

    if not isfinite(estimate):
        raise ValueError("Estimated observable is not finite")

    theoretical_bound = sum(abs(float(weight)) for _, _, weight in interactions)
    if abs(estimate) > theoretical_bound + 1e-10:
        raise ValueError(
            f"Estimated observable {estimate} exceeds bound {theoretical_bound}"
        )

    return float(estimate)


def absolute_observable_error(
    noisy_estimate: float,
    ideal_expectation: float,
) -> float:
    """Return absolute difference between sampled and exact expectations."""
    noisy_value = float(noisy_estimate)
    ideal_value = float(ideal_expectation)

    if not isfinite(noisy_value) or not isfinite(ideal_value):
        raise ValueError("Observable estimates must be finite")

    return abs(noisy_value - ideal_value)


def distribution_fidelity(
    ideal_probabilities: Mapping[object, float],
    counts: Mapping[object, int],
    num_bits: int = N_LOGICAL_QUBITS,
) -> float:
    """Squared Bhattacharyya coefficient of ideal and sampled distributions.

    This is classical measurement-distribution fidelity, not quantum-state
    fidelity. Missing bitstrings are assigned zero probability.
    """
    ideal = _validate_ideal_probabilities(ideal_probabilities, num_bits)
    sampled = _count_distribution(counts, num_bits)

    all_bitstrings = set(ideal) | set(sampled)
    coefficient = sum(
        sqrt(ideal.get(bitstring, 0.0) * sampled.get(bitstring, 0.0))
        for bitstring in all_bitstrings
    )
    fidelity = coefficient * coefficient

    if not isfinite(fidelity) or fidelity < -1e-12 or fidelity > 1.0 + 1e-12:
        raise ValueError(
            f"Distribution fidelity is outside its valid range: {fidelity}"
        )

    # Correct only negligible floating-point excursions.
    return min(1.0, max(0.0, float(fidelity)))

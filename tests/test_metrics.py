
import pytest

from src.metrics import (
    absolute_observable_error,
    distribution_fidelity,
    estimate_zz_observable,
)


def test_zz_estimator_respects_qiskit_bitstring_order():
    # In Qiskit's five-bit output, q0 is the rightmost bit.
    assert estimate_zz_observable(
        {"00001": 10}, interactions=((0, 1, 1.0),)
    ) == pytest.approx(-1.0)

    assert estimate_zz_observable(
        {"00010": 10}, interactions=((0, 1, 1.0),)
    ) == pytest.approx(-1.0)

    assert estimate_zz_observable(
        {"00011": 10}, interactions=((0, 1, 1.0),)
    ) == pytest.approx(1.0)


def test_zz_estimator_averages_sampled_correlations():
    counts = {"00000": 50, "00001": 50}
    estimate = estimate_zz_observable(
        counts, interactions=((0, 1, 1.0),)
    )
    assert estimate == pytest.approx(0.0)


def test_all_zero_outcome_reaches_positive_weight_bound():
    estimate = estimate_zz_observable({"00000": 20})
    expected = sum(abs(weight) for _, _, weight in __import__(
        "src.problem", fromlist=["INTERACTIONS"]
    ).INTERACTIONS)
    assert estimate == pytest.approx(expected)


def test_absolute_observable_error():
    assert absolute_observable_error(1.2, 1.0) == pytest.approx(0.2)
    assert absolute_observable_error(-1.0, 1.0) == pytest.approx(2.0)


def test_identical_distributions_have_unit_fidelity():
    ideal = {"00000": 0.5, "00001": 0.5}
    counts = {"00000": 100, "00001": 100}
    assert distribution_fidelity(ideal, counts) == pytest.approx(1.0)


def test_disjoint_distributions_have_zero_fidelity():
    ideal = {"00000": 1.0}
    counts = {"00001": 100}
    assert distribution_fidelity(ideal, counts) == pytest.approx(0.0)


def test_fidelity_handles_missing_bitstrings():
    ideal = {"00000": 0.25, "00001": 0.25, "00010": 0.5}
    counts = {"00000": 50, "00010": 50}
    fidelity = distribution_fidelity(ideal, counts)

    expected = (
        (0.25 * 0.5) ** 0.5
        + (0.5 * 0.5) ** 0.5
    ) ** 2

    assert 0.0 <= fidelity <= 1.0
    assert fidelity == pytest.approx(expected)

@pytest.mark.parametrize("counts", [{}, {"00000": 0}, {"00000": -1}])
def test_invalid_counts_raise(counts):
    with pytest.raises(ValueError):
        estimate_zz_observable(counts)


@pytest.mark.parametrize(
    "ideal",
    [
        {},
        {"00000": -0.1, "00001": 1.1},
        {"00000": 0.5},
    ],
)
def test_invalid_ideal_distribution_raises(ideal):
    with pytest.raises(ValueError):
        distribution_fidelity(ideal, {"00000": 10})


def test_invalid_observable_indices_raise():
    with pytest.raises(ValueError):
        estimate_zz_observable(
            {"00000": 10}, interactions=((0, 0, 1.0),)
        )

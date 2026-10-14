import pytest

from src.benchmark import quantile


def test_quantile_inclusive_convention():
    assert quantile([0.0, 10.0], 0.5) == 5.0
    assert quantile([1.0, 2.0, 3.0, 4.0], 0.95) == pytest.approx(3.85)
    assert quantile([], 0.95) is None

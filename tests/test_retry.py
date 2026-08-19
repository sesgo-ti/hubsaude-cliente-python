from __future__ import annotations

import pytest

from hubsaude_client.retry import compute_retry_delay_seconds


@pytest.mark.parametrize(
    ("attempt", "expected_seconds"),
    [
        (1, 1.0),
        (2, 2.0),
        (3, 4.0),
        (4, 8.0),
        (5, 16.0),
        (6, 32.0),
        (10, 512.0),
    ],
)
def test_exponential_backoff_formula(attempt: int, expected_seconds: float) -> None:
    """1s x 2^(attempt-1): 1s, 2s, 4s, 8s... — sem jitter."""
    assert compute_retry_delay_seconds(attempt) == expected_seconds


def test_first_attempt_is_base_delay() -> None:
    assert compute_retry_delay_seconds(1) == 1.0


def test_returns_float() -> None:
    assert isinstance(compute_retry_delay_seconds(1), float)


def test_delay_doubles_between_consecutive_attempts() -> None:
    for attempt in range(1, 20):
        assert compute_retry_delay_seconds(attempt + 1) == compute_retry_delay_seconds(attempt) * 2


def test_no_cap_grows_unbounded() -> None:
    """RetryPolicy.java nao aplica cap/teto superior ao delay calculado."""
    assert compute_retry_delay_seconds(20) == pytest.approx(2**19)


@pytest.mark.parametrize("attempt", [0, -1, -100])
def test_non_positive_attempt_raises(attempt: int) -> None:
    with pytest.raises(ValueError, match="attempt deve ser >= 1"):
        compute_retry_delay_seconds(attempt)


def test_is_deterministic() -> None:
    """Sem jitter: mesma tentativa sempre produz o mesmo delay."""
    assert compute_retry_delay_seconds(4) == compute_retry_delay_seconds(4) == compute_retry_delay_seconds(4)

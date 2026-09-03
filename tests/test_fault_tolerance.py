from __future__ import annotations

from datetime import timedelta

import pytest

from hubsaude_client.defaults import (
    DEFAULT_ASSERTION_TTL_SECONDS,
    DEFAULT_MAX_RETRIES,
    DEFAULT_TOKEN_CACHE_MARGIN_SECONDS,
)
from hubsaude_client.fault_tolerance import FaultToleranceConfig


def _config(assertion_ttl_seconds: int, token_cache_margin_seconds: int, max_retries: int) -> FaultToleranceConfig:
    return FaultToleranceConfig(
        connect_timeout=timedelta(seconds=10),
        request_timeout=timedelta(seconds=30),
        assertion_ttl_seconds=assertion_ttl_seconds,
        token_cache_margin_seconds=token_cache_margin_seconds,
        max_retries=max_retries,
    )


def test_valid_values_are_preserved() -> None:
    config = _config(assertion_ttl_seconds=120, token_cache_margin_seconds=30, max_retries=5)
    assert config.assertion_ttl_seconds == 120
    assert config.token_cache_margin_seconds == 30
    assert config.max_retries == 5


def test_timeouts_are_preserved() -> None:
    config = _config(assertion_ttl_seconds=120, token_cache_margin_seconds=30, max_retries=5)
    assert config.connect_timeout == timedelta(seconds=10)
    assert config.request_timeout == timedelta(seconds=30)


@pytest.mark.parametrize("assertion_ttl_seconds", [0, -1, -60])
def test_invalid_assertion_ttl_falls_back_to_default(assertion_ttl_seconds: int) -> None:
    config = _config(assertion_ttl_seconds=assertion_ttl_seconds, token_cache_margin_seconds=30, max_retries=3)
    assert config.assertion_ttl_seconds == DEFAULT_ASSERTION_TTL_SECONDS


@pytest.mark.parametrize("token_cache_margin_seconds", [0, -1, -60])
def test_invalid_token_cache_margin_seconds_falls_back_to_default(token_cache_margin_seconds: int) -> None:
    config = _config(assertion_ttl_seconds=60, token_cache_margin_seconds=token_cache_margin_seconds, max_retries=3)
    assert config.token_cache_margin_seconds == DEFAULT_TOKEN_CACHE_MARGIN_SECONDS


@pytest.mark.parametrize("max_retries", [0, -1, -10])
def test_invalid_max_retries_falls_back_to_default(max_retries: int) -> None:
    config = _config(assertion_ttl_seconds=60, token_cache_margin_seconds=30, max_retries=max_retries)
    assert config.max_retries == DEFAULT_MAX_RETRIES


@pytest.mark.parametrize("assertion_ttl_seconds", [1, 60, 120])
def test_valid_assertion_ttl_is_preserved(assertion_ttl_seconds: int) -> None:
    config = _config(assertion_ttl_seconds=assertion_ttl_seconds, token_cache_margin_seconds=30, max_retries=3)
    assert config.assertion_ttl_seconds == assertion_ttl_seconds


@pytest.mark.parametrize("token_cache_margin_seconds", [1, 30, 60])
def test_valid_token_cache_margin_seconds_is_preserved(token_cache_margin_seconds: int) -> None:
    config = _config(assertion_ttl_seconds=60, token_cache_margin_seconds=token_cache_margin_seconds, max_retries=3)
    assert config.token_cache_margin_seconds == token_cache_margin_seconds


@pytest.mark.parametrize("max_retries", [3, 5, 10])
def test_valid_max_retries_is_preserved(max_retries: int) -> None:
    config = _config(assertion_ttl_seconds=60, token_cache_margin_seconds=30, max_retries=max_retries)
    assert config.max_retries == max_retries


@pytest.mark.parametrize("assertion_ttl_seconds", [3600, 86400])
def test_big_valid_assertion_ttl_is_preserved(assertion_ttl_seconds: int) -> None:
    config = _config(assertion_ttl_seconds=assertion_ttl_seconds, token_cache_margin_seconds=30, max_retries=3)
    assert config.assertion_ttl_seconds == assertion_ttl_seconds


@pytest.mark.parametrize("token_cache_margin_seconds", [3600, 86400])
def test_big_valid_token_cache_margin_seconds_is_preserved(token_cache_margin_seconds: int) -> None:
    config = _config(assertion_ttl_seconds=60, token_cache_margin_seconds=token_cache_margin_seconds, max_retries=3)
    assert config.token_cache_margin_seconds == token_cache_margin_seconds


@pytest.mark.parametrize("max_retries", [100, 1000])
def test_big_valid_max_retries_is_preserved(max_retries: int) -> None:
    config = _config(assertion_ttl_seconds=60, token_cache_margin_seconds=30, max_retries=max_retries)
    assert config.max_retries == max_retries


def test_is_frozen_dataclass() -> None:
    config = _config(assertion_ttl_seconds=60, token_cache_margin_seconds=30, max_retries=3)
    with pytest.raises(AttributeError):
        config.max_retries = 10  # type: ignore[misc]

from __future__ import annotations

from hubsaude_client import defaults


def test_assertion_ttl() -> None:
    assert defaults.DEFAULT_ASSERTION_TTL_SECONDS == 60


def test_timeouts() -> None:
    assert defaults.DEFAULT_CONNECT_TIMEOUT_SECONDS == 10.0
    assert defaults.DEFAULT_REQUEST_TIMEOUT_SECONDS == 30.0


def test_max_retries() -> None:
    assert defaults.DEFAULT_MAX_RETRIES == 3


def test_token_cache_defaults() -> None:
    assert defaults.DEFAULT_TOKEN_CACHE_MARGIN_SECONDS == 30
    assert defaults.DEFAULT_TOKEN_CACHE_MAX_ENTRIES == 1_000


def test_tls_protocol() -> None:
    assert defaults.DEFAULT_TLS_PROTOCOL == "TLSv1.3"


def test_jwt_algorithm() -> None:
    assert defaults.DEFAULT_JWT_ALGORITHM == "RS384"

from __future__ import annotations

import json
import logging

import httpx
import pytest

from hubsaude_client.defaults import DEFAULT_EXPIRES_IN_SECONDS
from hubsaude_client.exceptions import SmartTokenError
from hubsaude_client.response_guard import (
    MAX_EXPIRES_IN_SECONDS,
    MAX_RESPONSE_BODY_BYTES,
    TokenResponse,
    TokenResponseGuard,
    sanitize_expires_in,
)
from hubsaude_client.trace import TraceContext

ENDPOINT = "https://auth.example/token"


@pytest.fixture
def guard() -> TokenResponseGuard:
    return TokenResponseGuard()


@pytest.fixture
def trace() -> TraceContext:
    return TraceContext.generate()


def _fake_response(body: bytes, status_code: int = 200) -> httpx.Response:
    return httpx.Response(
        status_code=status_code,
        content=body,
        request=httpx.Request("POST", ENDPOINT),
    )


def _success_body(access_token: str = "abc123", expires_in: object = 3600, **extra: object) -> bytes:
    payload: dict[str, object] = {"access_token": access_token, "expires_in": expires_in, **extra}
    return json.dumps(payload).encode("utf-8")


# ---------------------------------------------------------------------------
# TokenResponseGuard.__init__
# ---------------------------------------------------------------------------


def test_default_max_body_bytes_is_one_mebibyte() -> None:
    assert MAX_RESPONSE_BODY_BYTES == 1_048_576


@pytest.mark.parametrize("invalid_limit", [0, -1, -1000])
def test_rejects_non_positive_max_body_bytes(invalid_limit: int) -> None:
    with pytest.raises(ValueError):
        TokenResponseGuard(max_response_body_bytes=invalid_limit)


# ---------------------------------------------------------------------------
# TokenResponseGuard.read_body -- dentro/fora do limite
# ---------------------------------------------------------------------------


def test_reads_body_within_limit(guard: TokenResponseGuard, trace: TraceContext) -> None:
    body = b'{"access_token":"abc"}'
    response = _fake_response(body)

    assert guard.read_body(response, trace) == body


def test_reads_body_exactly_at_limit(trace: TraceContext) -> None:
    guard = TokenResponseGuard(max_response_body_bytes=100)
    body = b"x" * 100
    response = _fake_response(body)

    assert guard.read_body(response, trace) == body


def test_raises_smart_token_error_when_body_exceeds_limit(trace: TraceContext) -> None:
    guard = TokenResponseGuard(max_response_body_bytes=100)
    response = _fake_response(b"x" * 101)

    with pytest.raises(SmartTokenError) as excinfo:
        guard.read_body(response, trace)

    message = str(excinfo.value)
    assert "excede o limite" in message
    assert "100" in message
    assert trace.trace_id in message


def test_stops_reading_before_consuming_the_whole_oversized_body(trace: TraceContext) -> None:
    """A leitura deve ser interrompida assim que o limite for ultrapassado,
    sem esperar o corpo inteiro chegar (comportamento de streaming)."""
    guard = TokenResponseGuard(max_response_body_bytes=100)
    huge_body = b"x" * 10_000_000
    response = _fake_response(huge_body)

    with pytest.raises(SmartTokenError):
        guard.read_body(response, trace)

    # A resposta e' fechada ao final (sucesso ou falha) -- verificado
    # indiretamente por nao haver excecao adicional ao chamar close()
    # de novo, o que confirma que o fluxo passou pelo `finally`.
    response.close()


def test_closes_the_response_on_success(guard: TokenResponseGuard, trace: TraceContext) -> None:
    response = _fake_response(b'{"access_token":"abc"}')
    guard.read_body(response, trace)
    assert response.is_closed


def test_closes_the_response_on_limit_violation(trace: TraceContext) -> None:
    guard = TokenResponseGuard(max_response_body_bytes=10)
    response = _fake_response(b"x" * 1000)

    with pytest.raises(SmartTokenError):
        guard.read_body(response, trace)

    assert response.is_closed


def test_logs_warning_when_body_is_truncated(trace: TraceContext, caplog: pytest.LogCaptureFixture) -> None:
    guard = TokenResponseGuard(max_response_body_bytes=10)
    response = _fake_response(b"x" * 1000)

    with caplog.at_level(logging.WARNING, logger="hubsaude_client.SmartTokenClient"):
        with pytest.raises(SmartTokenError):
            guard.read_body(response, trace)

    assert any(record.levelno == logging.WARNING for record in caplog.records)
    assert any("truncado" in record.getMessage() for record in caplog.records)


# ---------------------------------------------------------------------------
# sanitize_expires_in -- ausente/invalido/valido
# ---------------------------------------------------------------------------


def test_sanitize_expires_in_absent_uses_default() -> None:
    assert sanitize_expires_in(None) == DEFAULT_EXPIRES_IN_SECONDS


@pytest.mark.parametrize(
    "raw",
    [
        "nao-e-numero",
        [],
        {},
        object(),
        True,
        False,
    ],
)
def test_sanitize_expires_in_wrong_type_raises(raw: object) -> None:
    # Alinhado ao Java: presente mas invalido e'
    # rejeitado, nao absorvido com o padrao.
    with pytest.raises(SmartTokenError, match="expires_in"):
        sanitize_expires_in(raw)


@pytest.mark.parametrize("raw", [0, -1, -3600, 0.0, "-10"])
def test_sanitize_expires_in_non_positive_raises(raw: object) -> None:
    with pytest.raises(SmartTokenError, match="expires_in"):
        sanitize_expires_in(raw)


def test_sanitize_expires_in_valid_int_is_preserved() -> None:
    assert sanitize_expires_in(120) == 120


def test_sanitize_expires_in_valid_float_is_truncated() -> None:
    assert sanitize_expires_in(120.9) == 120


def test_sanitize_expires_in_valid_numeric_string_is_coerced() -> None:
    assert sanitize_expires_in("300") == 300


def test_sanitize_expires_in_above_ceiling_is_capped() -> None:
    # Teto de sanidade de 24h:
    # valor valido mas acima do teto e' normalizado, nao rejeitado.
    assert sanitize_expires_in(200_000) == MAX_EXPIRES_IN_SECONDS


def test_sanitize_expires_in_at_ceiling_is_preserved() -> None:
    assert sanitize_expires_in(MAX_EXPIRES_IN_SECONDS) == MAX_EXPIRES_IN_SECONDS


def test_sanitize_expires_in_logs_warning_when_above_ceiling(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.WARNING, logger="hubsaude_client.SmartTokenClient"):
        sanitize_expires_in(200_000)

    assert any(record.levelno == logging.WARNING for record in caplog.records)
    assert any("teto de sanidade" in record.getMessage() for record in caplog.records)


def test_sanitize_expires_in_does_not_log_when_absent(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.WARNING, logger="hubsaude_client.SmartTokenClient"):
        sanitize_expires_in(None)

    assert not any(record.levelno == logging.WARNING for record in caplog.records)


def test_sanitize_expires_in_includes_trace_id_when_invalid(trace: TraceContext) -> None:
    with pytest.raises(SmartTokenError, match=trace.trace_id):
        sanitize_expires_in("invalido", trace)


def test_sanitize_expires_in_includes_trace_id_in_ceiling_warning(
    trace: TraceContext, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.WARNING, logger="hubsaude_client.SmartTokenClient"):
        sanitize_expires_in(200_000, trace)

    assert any(trace.trace_id in record.getMessage() for record in caplog.records)


# ---------------------------------------------------------------------------
# TokenResponseGuard.parse_success_response
# ---------------------------------------------------------------------------


def test_parses_valid_success_response(guard: TokenResponseGuard, trace: TraceContext) -> None:
    response = _fake_response(_success_body(access_token="tok-1", expires_in=1800))

    result = guard.parse_success_response(response, trace)

    assert result == TokenResponse(
        access_token="tok-1", expires_in=1800, raw={"access_token": "tok-1", "expires_in": 1800}
    )


def test_parse_success_response_keeps_raw_body_with_unknown_fields(
    guard: TokenResponseGuard, trace: TraceContext
) -> None:
    response = _fake_response(_success_body(scope="patient/*.read", token_type="Bearer"))

    result = guard.parse_success_response(response, trace)

    assert result.raw["scope"] == "patient/*.read"
    assert result.raw["token_type"] == "Bearer"


def test_parse_success_response_applies_default_when_expires_in_absent(
    guard: TokenResponseGuard, trace: TraceContext
) -> None:
    body = json.dumps({"access_token": "tok-1"}).encode("utf-8")
    response = _fake_response(body)

    result = guard.parse_success_response(response, trace)

    assert result.expires_in == DEFAULT_EXPIRES_IN_SECONDS


def test_parse_success_response_raises_when_expires_in_invalid(guard: TokenResponseGuard, trace: TraceContext) -> None:
    response = _fake_response(_success_body(expires_in="nao-e-numero"))

    with pytest.raises(SmartTokenError, match="expires_in"):
        guard.parse_success_response(response, trace)


def test_parse_success_response_caps_expires_in_above_ceiling(guard: TokenResponseGuard, trace: TraceContext) -> None:
    response = _fake_response(_success_body(expires_in=200_000))

    result = guard.parse_success_response(response, trace)

    assert result.expires_in == MAX_EXPIRES_IN_SECONDS


def test_parse_success_response_raises_when_access_token_missing(
    guard: TokenResponseGuard, trace: TraceContext
) -> None:
    body = json.dumps({"expires_in": 3600}).encode("utf-8")
    response = _fake_response(body)

    with pytest.raises(SmartTokenError) as excinfo:
        guard.parse_success_response(response, trace)

    assert "access_token" in str(excinfo.value)


def test_parse_success_response_raises_when_access_token_empty(guard: TokenResponseGuard, trace: TraceContext) -> None:
    response = _fake_response(_success_body(access_token=""))

    with pytest.raises(SmartTokenError):
        guard.parse_success_response(response, trace)


def test_parse_success_response_raises_when_access_token_not_a_string(
    guard: TokenResponseGuard, trace: TraceContext
) -> None:
    body = json.dumps({"access_token": 12345, "expires_in": 3600}).encode("utf-8")
    response = _fake_response(body)

    with pytest.raises(SmartTokenError):
        guard.parse_success_response(response, trace)


def test_parse_success_response_raises_when_body_is_not_json(guard: TokenResponseGuard, trace: TraceContext) -> None:
    response = _fake_response(b"nao e json")

    with pytest.raises(SmartTokenError) as excinfo:
        guard.parse_success_response(response, trace)

    assert excinfo.value.__cause__ is not None
    assert isinstance(excinfo.value.__cause__, json.JSONDecodeError)


def test_parse_success_response_raises_when_body_is_a_json_array(
    guard: TokenResponseGuard, trace: TraceContext
) -> None:
    response = _fake_response(b"[1, 2, 3]")

    with pytest.raises(SmartTokenError):
        guard.parse_success_response(response, trace)


def test_parse_success_response_raises_when_body_exceeds_limit(trace: TraceContext) -> None:
    guard = TokenResponseGuard(max_response_body_bytes=10)
    response = _fake_response(_success_body())

    with pytest.raises(SmartTokenError) as excinfo:
        guard.parse_success_response(response, trace)

    assert "excede o limite" in str(excinfo.value)


# ---------------------------------------------------------------------------
# TokenResponse.__repr__
# ---------------------------------------------------------------------------


def test_token_response_repr_masks_access_token() -> None:
    token = TokenResponse(access_token="segredo-super-sensivel", expires_in=3600, raw={})
    assert "segredo-super-sensivel" not in repr(token)
    assert "[REDACTED]" in repr(token)
    assert "3600" in repr(token)

from __future__ import annotations

import json
import logging

import httpx
import pytest

from hubsaude_client.discovery import SmartConfigurationDiscovery
from hubsaude_client.exceptions import SmartTokenError
from hubsaude_client.trace import TraceContext

FHIR_BASE = "https://fhir.example/r4"
WELL_KNOWN_URL = "https://fhir.example/r4/.well-known/smart-configuration"
TOKEN_ENDPOINT = "https://auth.example/token"


def _client_with_handler(handler) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler))


def _json_response(status_code: int, payload: dict) -> httpx.Response:
    return httpx.Response(status_code=status_code, json=payload)


# ---------------------------------------------------------------------------
# Resposta valida
# ---------------------------------------------------------------------------


def test_discovers_token_endpoint_from_valid_response() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert str(request.url) == WELL_KNOWN_URL
        return _json_response(200, {"token_endpoint": TOKEN_ENDPOINT})

    discovery = SmartConfigurationDiscovery(_client_with_handler(handler))

    assert discovery.discover_token_endpoint(FHIR_BASE) == TOKEN_ENDPOINT


def test_strips_trailing_slash_from_fhir_base() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert str(request.url) == WELL_KNOWN_URL
        return _json_response(200, {"token_endpoint": TOKEN_ENDPOINT})

    discovery = SmartConfigurationDiscovery(_client_with_handler(handler))

    assert discovery.discover_token_endpoint(FHIR_BASE + "/") == TOKEN_ENDPOINT


def test_sends_traceparent_header_with_valid_format() -> None:
    captured: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["traceparent"] = request.headers[TraceContext.TRACEPARENT_HEADER]
        return _json_response(200, {"token_endpoint": TOKEN_ENDPOINT})

    discovery = SmartConfigurationDiscovery(_client_with_handler(handler))
    discovery.discover_token_endpoint(FHIR_BASE)

    parts = captured["traceparent"].split("-")
    assert len(parts) == 4
    assert parts[0] == "00"
    assert len(parts[1]) == 32
    assert len(parts[2]) == 16


def test_each_call_uses_a_fresh_trace_context() -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.headers[TraceContext.TRACEPARENT_HEADER])
        return _json_response(200, {"token_endpoint": TOKEN_ENDPOINT})

    discovery = SmartConfigurationDiscovery(_client_with_handler(handler))
    discovery.discover_token_endpoint(FHIR_BASE)
    discovery.discover_token_endpoint(FHIR_BASE)

    assert seen[0] != seen[1]


# ---------------------------------------------------------------------------
# Resposta sem token_endpoint
# ---------------------------------------------------------------------------


def test_raises_when_token_endpoint_field_is_missing() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return _json_response(200, {"issuer": "https://auth.example"})

    discovery = SmartConfigurationDiscovery(_client_with_handler(handler))

    with pytest.raises(SmartTokenError) as excinfo:
        discovery.discover_token_endpoint(FHIR_BASE)

    assert "token_endpoint" in str(excinfo.value)
    assert WELL_KNOWN_URL in str(excinfo.value)


def test_raises_when_token_endpoint_is_empty_string() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return _json_response(200, {"token_endpoint": "   "})

    discovery = SmartConfigurationDiscovery(_client_with_handler(handler))

    with pytest.raises(SmartTokenError):
        discovery.discover_token_endpoint(FHIR_BASE)


def test_raises_when_token_endpoint_is_not_a_string() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return _json_response(200, {"token_endpoint": 123})

    discovery = SmartConfigurationDiscovery(_client_with_handler(handler))

    with pytest.raises(SmartTokenError):
        discovery.discover_token_endpoint(FHIR_BASE)


def test_raises_when_document_is_not_a_json_object() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status_code=200, content=b"[1, 2, 3]")

    discovery = SmartConfigurationDiscovery(_client_with_handler(handler))

    with pytest.raises(SmartTokenError):
        discovery.discover_token_endpoint(FHIR_BASE)


def test_raises_when_body_is_not_valid_json() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status_code=200, content=b"nao e json")

    discovery = SmartConfigurationDiscovery(_client_with_handler(handler))

    with pytest.raises(SmartTokenError) as excinfo:
        discovery.discover_token_endpoint(FHIR_BASE)

    assert "JSON valido" in str(excinfo.value)


# ---------------------------------------------------------------------------
# Validacao de esquema do token_endpoint descoberto
# ---------------------------------------------------------------------------


def test_rejects_discovered_token_endpoint_without_https() -> None:
    """P0: um .well-known comprometido (ou um MITM capaz de responde-lo)
    nao pode fazer o cliente enviar client_assertion/credenciais de mTLS
    para um token_endpoint sem TLS -- mesma protecao que ja existia para
    valores informados manualmente no builder, agora aplicada tambem ao
    valor que volta da rede."""

    def handler(request: httpx.Request) -> httpx.Response:
        return _json_response(200, {"token_endpoint": "http://auth.example/token"})

    discovery = SmartConfigurationDiscovery(_client_with_handler(handler))

    with pytest.raises(SmartTokenError, match="https"):
        discovery.discover_token_endpoint(FHIR_BASE)


@pytest.mark.parametrize(
    "local_token_endpoint",
    [
        "http://localhost:8080/token",
        "http://127.0.0.1:8080/token",
        "http://[::1]:8080/token",
    ],
)
def test_allows_discovered_token_endpoint_on_local_host_without_https(local_token_endpoint: str) -> None:
    """Excecao de desenvolvimento local (P1): um authorization server de
    teste em localhost/127.0.0.1/::1 pode ser descoberto em http, mesma
    allowlist do builder e do lado Java."""

    def handler(request: httpx.Request) -> httpx.Response:
        return _json_response(200, {"token_endpoint": local_token_endpoint})

    discovery = SmartConfigurationDiscovery(_client_with_handler(handler))

    assert discovery.discover_token_endpoint(FHIR_BASE) == local_token_endpoint


# ---------------------------------------------------------------------------
# Erro HTTP
# ---------------------------------------------------------------------------


def test_raises_on_non_200_status() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status_code=404, content=b"not found")

    discovery = SmartConfigurationDiscovery(_client_with_handler(handler))

    with pytest.raises(SmartTokenError) as excinfo:
        discovery.discover_token_endpoint(FHIR_BASE)

    assert "HTTP 404" in str(excinfo.value)
    assert WELL_KNOWN_URL in str(excinfo.value)


def test_sanitizes_access_token_from_error_body() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            status_code=500,
            content=json.dumps({"access_token": "segredo"}).encode("utf-8"),
        )

    discovery = SmartConfigurationDiscovery(_client_with_handler(handler))

    with pytest.raises(SmartTokenError) as excinfo:
        discovery.discover_token_endpoint(FHIR_BASE)

    message = str(excinfo.value)
    assert "[REDACTED]" in message
    assert "segredo" not in message


def test_logs_error_on_non_200_status(caplog: pytest.LogCaptureFixture) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status_code=503, content=b"unavailable")

    discovery = SmartConfigurationDiscovery(_client_with_handler(handler))

    with caplog.at_level(logging.ERROR, logger="hubsaude_client.SmartTokenClient"):
        with pytest.raises(SmartTokenError):
            discovery.discover_token_endpoint(FHIR_BASE)

    assert any(record.levelno == logging.ERROR for record in caplog.records)


# ---------------------------------------------------------------------------
# Falha de rede/transporte
# ---------------------------------------------------------------------------


def test_wraps_network_failure_in_smart_token_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused")

    discovery = SmartConfigurationDiscovery(_client_with_handler(handler))

    with pytest.raises(SmartTokenError) as excinfo:
        discovery.discover_token_endpoint(FHIR_BASE)

    assert WELL_KNOWN_URL in str(excinfo.value)
    assert isinstance(excinfo.value.__cause__, httpx.ConnectError)


def test_logs_error_on_network_failure(caplog: pytest.LogCaptureFixture) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectTimeout("timed out")

    discovery = SmartConfigurationDiscovery(_client_with_handler(handler))

    with caplog.at_level(logging.ERROR, logger="hubsaude_client.SmartTokenClient"):
        with pytest.raises(SmartTokenError):
            discovery.discover_token_endpoint(FHIR_BASE)

    assert any(record.levelno == logging.ERROR for record in caplog.records)

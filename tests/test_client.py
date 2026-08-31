"""Testes de ``client.SmartTokenClient``.

Nenhuma rede real e usada: o ``httpx.Client`` construido internamente por
``SmartTokenClient.__init__`` e interceptado via ``install_mock_transport``
(monkeypatch de ``httpx.Client`` por um factory que injeta
``httpx.MockTransport(handler)`` -- mesma tecnica de
``tests/test_discovery.py``, só que aplicada uma camada acima, já que
``client.py`` não expõe um jeito de injetar o transporte/``httpx.Client``
diretamente). ``FakeSigningStrategy``/``FakeTlsContextProvider``
(``tests/fakes.py``) cobrem os dois ports (``ports.SigningStrategy``/
``ports.TlsContextProvider``); os demais colaboradores (``token_cache``,
``error_classifier``, ``response_guard``, ``retry``, ``trace``) são usados
em suas implementações reais -- não há necessidade de fake para eles.
"""

from __future__ import annotations

import base64
import json
import ssl
import threading
import time
from datetime import timedelta
from urllib.parse import parse_qsl

import httpx
import pytest

from hubsaude_client.builder import HubContext
from hubsaude_client.client import SmartTokenClient, TokenResult, _ReadersWriterLock
from hubsaude_client.exceptions import SmartTokenError
from hubsaude_client.fault_tolerance import FaultToleranceConfig
from hubsaude_client.token_cache import TokenCacheStrategy
from hubsaude_client.trace import TraceContext

from .fakes import FakeSigningStrategy, FakeTlsContextProvider

CLIENT_ID = "cliente-teste"
TOKEN_ENDPOINT = "https://auth.example/token"
FHIR_BASE = "https://fhir.example/r4"
WELL_KNOWN_URL = "https://fhir.example/r4/.well-known/smart-configuration"


# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def install_mock_transport(monkeypatch: pytest.MonkeyPatch):
    """Faz o ``httpx.Client`` construído dentro de ``SmartTokenClient.__init__``
    usar ``httpx.MockTransport(handler)`` em vez de tentar acesso real de
    rede/TLS.

    ``client.py`` não expõe um jeito de injetar ``transport=`` (por design --
    não é um parâmetro do contrato público, ver docstring de ``__init__``),
    então a interceptação acontece um nível acima: substitui-se
    ``httpx.Client`` (a classe, referenciada por ``client.py`` via
    ``import httpx``; como módulos Python são singletons, isso é o mesmo
    objeto em qualquer lugar que importe ``httpx``) por um factory que
    descarta ``verify`` (irrelevante com ``MockTransport``, que nunca chega a
    abrir uma conexão TLS de verdade) e injeta o transporte fake, preservando
    ``timeout`` para que testes de timeout/retry continuem exercitando a
    configuração real passada pelo cliente.
    """
    real_client_cls = httpx.Client

    def _install(handler) -> None:
        def _factory(*, verify=None, timeout=None, **_ignored: object) -> httpx.Client:
            return real_client_cls(transport=httpx.MockTransport(handler), timeout=timeout)

        monkeypatch.setattr(httpx, "Client", _factory)

    return _install


def _base_kwargs(**overrides: object) -> dict[str, object]:
    """Kwargs válidos mínimos para ``SmartTokenClient``, com token_endpoint
    explícito (sem descoberta) -- mesma forma que ``builder.build()`` chama
    o construtor (ver ``builder.py``)."""
    kwargs: dict[str, object] = dict(
        client_id=CLIENT_ID,
        token_endpoint=TOKEN_ENDPOINT,
        fhir_base=None,
        signing_strategy=FakeSigningStrategy(),
        tls_context_provider=FakeTlsContextProvider(),
        fault_tolerance=FaultToleranceConfig(
            connect_timeout=timedelta(seconds=5),
            request_timeout=timedelta(seconds=5),
            assertion_ttl_seconds=60,
            max_retries=3,
        ),
        token_cache=TokenCacheStrategy(enabled=True),
        jwt_algorithm="RS384",
        key_id=None,
        hub_context=None,
    )
    kwargs.update(overrides)
    return kwargs


def _token_success_handler(
    access_token: str = "tok-abc",
    expires_in: int = 3600,
    captured: list[httpx.Request] | None = None,
):
    """Handler de sucesso (HTTP 200) para o token endpoint; opcionalmente
    acumula as requisições recebidas em ``captured``, para inspeção."""

    def handler(request: httpx.Request) -> httpx.Response:
        if captured is not None:
            captured.append(request)
        return httpx.Response(status_code=200, json={"access_token": access_token, "expires_in": expires_in})

    return handler


def _b64url_decode(value: str) -> bytes:
    """Decodifica Base64URL, restaurando o padding removido na codificação."""
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _decode_assertion(assertion: str) -> tuple[dict[str, object], dict[str, object]]:
    """Decodifica header e payload (sem verificar assinatura) de um JWT
    compacto, para inspeção nos testes."""
    header_b64, payload_b64, _signature_b64 = assertion.split(".")
    header = json.loads(_b64url_decode(header_b64))
    payload = json.loads(_b64url_decode(payload_b64))
    return header, payload


def _form_data(request: httpx.Request) -> dict[str, str]:
    """Decodifica o corpo ``application/x-www-form-urlencoded`` da requisição."""
    return dict(parse_qsl(request.content.decode("utf-8")))


# ---------------------------------------------------------------------------
# Construção / descoberta (RF-09)
# ---------------------------------------------------------------------------


def test_uses_token_endpoint_directly_without_any_http_call(install_mock_transport) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError(f"nenhuma requisicao HTTP era esperada na construcao, recebida: {request.url}")

    install_mock_transport(handler)
    client = SmartTokenClient(**_base_kwargs())

    assert client.get_token_endpoint() == TOKEN_ENDPOINT
    client.close()


def test_discovers_token_endpoint_from_fhir_base_once_at_construction(install_mock_transport) -> None:
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        assert str(request.url) == WELL_KNOWN_URL
        return httpx.Response(status_code=200, json={"token_endpoint": TOKEN_ENDPOINT})

    install_mock_transport(handler)
    client = SmartTokenClient(**_base_kwargs(token_endpoint=None, fhir_base=FHIR_BASE))

    assert client.get_token_endpoint() == TOKEN_ENDPOINT
    assert calls == [WELL_KNOWN_URL]  # descoberta ocorreu exatamente uma vez, na construcao
    client.close()


def test_discovery_failure_propagates_as_smart_token_error(install_mock_transport) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status_code=404, content=b"not found")

    install_mock_transport(handler)
    with pytest.raises(SmartTokenError):
        SmartTokenClient(**_base_kwargs(token_endpoint=None, fhir_base=FHIR_BASE))


def test_discovered_endpoint_is_used_for_token_requests(install_mock_transport) -> None:
    captured: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url) == WELL_KNOWN_URL:
            return httpx.Response(status_code=200, json={"token_endpoint": TOKEN_ENDPOINT})
        return _token_success_handler(captured=captured)(request)

    install_mock_transport(handler)
    client = SmartTokenClient(**_base_kwargs(token_endpoint=None, fhir_base=FHIR_BASE))

    client.obtain_token()

    assert len(captured) == 1
    assert str(captured[0].url) == TOKEN_ENDPOINT
    client.close()


# ---------------------------------------------------------------------------
# Client assertion / JWT (RF-01)
# ---------------------------------------------------------------------------


def test_assertion_claims_match_spec(install_mock_transport) -> None:
    captured: list[httpx.Request] = []
    install_mock_transport(_token_success_handler(captured=captured))
    client = SmartTokenClient(**_base_kwargs())

    client.obtain_token("system/Patient.rs")

    form = _form_data(captured[0])
    header, payload = _decode_assertion(form["client_assertion"])

    assert header == {"alg": "RS384", "typ": "JWT"}
    assert payload["iss"] == CLIENT_ID
    assert payload["sub"] == CLIENT_ID
    assert payload["aud"] == TOKEN_ENDPOINT
    assert payload["exp"] - payload["iat"] == 60  # assertion_ttl_seconds configurado
    assert isinstance(payload["jti"], str) and payload["jti"]
    assert "hub_ctx" not in payload
    client.close()


def test_assertion_ttl_reflects_fault_tolerance_config(install_mock_transport) -> None:
    captured: list[httpx.Request] = []
    install_mock_transport(_token_success_handler(captured=captured))
    fault_tolerance = FaultToleranceConfig(
        connect_timeout=timedelta(seconds=5),
        request_timeout=timedelta(seconds=5),
        assertion_ttl_seconds=120,
        max_retries=3,
    )
    client = SmartTokenClient(**_base_kwargs(fault_tolerance=fault_tolerance))

    client.obtain_token()

    _header, payload = _decode_assertion(_form_data(captured[0])["client_assertion"])
    assert payload["exp"] - payload["iat"] == 120
    client.close()


def test_assertion_header_includes_kid_when_configured(install_mock_transport) -> None:
    captured: list[httpx.Request] = []
    install_mock_transport(_token_success_handler(captured=captured))
    client = SmartTokenClient(**_base_kwargs(key_id="minha-chave-01"))

    client.obtain_token()

    header, _payload = _decode_assertion(_form_data(captured[0])["client_assertion"])
    assert header["kid"] == "minha-chave-01"
    client.close()


def test_get_key_id_returns_configured_value(install_mock_transport) -> None:
    install_mock_transport(_token_success_handler(captured=[]))
    client = SmartTokenClient(**_base_kwargs(key_id="minha-chave-01"))

    assert client.get_key_id() == "minha-chave-01"
    client.close()


def test_get_key_id_returns_none_when_not_configured(install_mock_transport) -> None:
    install_mock_transport(_token_success_handler(captured=[]))
    client = SmartTokenClient(**_base_kwargs(key_id=None))

    assert client.get_key_id() is None
    client.close()


def test_verify_key_pair_consistency_static_wrapper_accepts_matching_pair(fake_pem_pair) -> None:
    from hubsaude_client import pem_loader

    key = pem_loader.load_private_key(fake_pem_pair["key"])
    cert = pem_loader.load_certificate(fake_pem_pair["cert"])
    SmartTokenClient.verify_key_pair_consistency(key, cert)  # nao deve lancar


def test_verify_key_pair_consistency_static_wrapper_rejects_mismatched_pair(fake_mismatched_pem_pair) -> None:
    from hubsaude_client import pem_loader

    key = pem_loader.load_private_key(fake_mismatched_pem_pair["matching_key"])
    mismatched_cert = pem_loader.load_certificate(fake_mismatched_pem_pair["mismatched_cert"])
    with pytest.raises(SmartTokenError, match="nao corresponde"):
        SmartTokenClient.verify_key_pair_consistency(key, mismatched_cert)


def test_assertion_header_omits_kid_when_not_configured(install_mock_transport) -> None:
    captured: list[httpx.Request] = []
    install_mock_transport(_token_success_handler(captured=captured))
    client = SmartTokenClient(**_base_kwargs(key_id=None))

    client.obtain_token()

    header, _payload = _decode_assertion(_form_data(captured[0])["client_assertion"])
    assert "kid" not in header
    client.close()


def test_assertion_includes_hub_ctx_claim_when_configured(install_mock_transport) -> None:
    captured: list[httpx.Request] = []
    install_mock_transport(_token_success_handler(captured=captured))
    hub_context = HubContext(ig="ig-teste", versao="1.2.3")
    client = SmartTokenClient(**_base_kwargs(hub_context=hub_context))

    client.obtain_token()

    _header, payload = _decode_assertion(_form_data(captured[0])["client_assertion"])
    assert payload["hub_ctx"] == {"ig": "ig-teste", "versao": "1.2.3"}
    client.close()


def test_assertion_algorithm_reflects_configured_algorithm(install_mock_transport) -> None:
    captured: list[httpx.Request] = []
    install_mock_transport(_token_success_handler(captured=captured))
    client = SmartTokenClient(**_base_kwargs(jwt_algorithm="ES384"))

    assert client.get_jwt_algorithm() == "ES384"
    client.obtain_token()

    header, _payload = _decode_assertion(_form_data(captured[0])["client_assertion"])
    assert header["alg"] == "ES384"
    client.close()


def test_assertion_is_base64url_without_padding(install_mock_transport) -> None:
    captured: list[httpx.Request] = []
    install_mock_transport(_token_success_handler(captured=captured))
    client = SmartTokenClient(**_base_kwargs())

    client.obtain_token()

    assertion = _form_data(captured[0])["client_assertion"]
    header_b64, payload_b64, signature_b64 = assertion.split(".")
    for part in (header_b64, payload_b64, signature_b64):
        assert "=" not in part
        assert "+" not in part and "/" not in part  # alfabeto URL-safe, nao o padrao
    client.close()


def test_signing_strategy_receives_header_dot_payload(install_mock_transport) -> None:
    install_mock_transport(_token_success_handler())
    signing_strategy = FakeSigningStrategy()
    client = SmartTokenClient(**_base_kwargs(signing_strategy=signing_strategy))

    client.obtain_token()

    signed = signing_strategy.last_signed_data
    assert signed is not None
    header_part, payload_part = signed.decode("ascii").split(".")
    header, payload = _decode_assertion(f"{header_part}.{payload_part}.x")
    assert header["typ"] == "JWT"
    assert payload["iss"] == CLIENT_ID
    client.close()


def test_each_real_fetch_uses_a_fresh_jti(install_mock_transport) -> None:
    captured: list[httpx.Request] = []
    install_mock_transport(_token_success_handler(captured=captured))
    # Cache desligado: garante que a segunda chamada tambem vai a rede.
    client = SmartTokenClient(**_base_kwargs(token_cache=TokenCacheStrategy(enabled=False)))

    client.obtain_token("scope-a")
    client.obtain_token("scope-b")

    assert len(captured) == 2
    _h1, payload1 = _decode_assertion(_form_data(captured[0])["client_assertion"])
    _h2, payload2 = _decode_assertion(_form_data(captured[1])["client_assertion"])
    assert payload1["jti"] != payload2["jti"]
    client.close()


# ---------------------------------------------------------------------------
# Requisicao de token / trace (RF-02)
# ---------------------------------------------------------------------------


def test_sends_expected_form_fields(install_mock_transport) -> None:
    captured: list[httpx.Request] = []
    install_mock_transport(_token_success_handler(captured=captured))
    client = SmartTokenClient(**_base_kwargs())

    client.obtain_token("system/Patient.rs")

    form = _form_data(captured[0])
    assert form["grant_type"] == "client_credentials"
    assert form["client_id"] == CLIENT_ID
    assert form["client_assertion_type"] == "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
    assert form["scope"] == "system/Patient.rs"
    assert "client_assertion" in form
    client.close()


def test_omits_scope_field_when_scope_is_none(install_mock_transport) -> None:
    captured: list[httpx.Request] = []
    install_mock_transport(_token_success_handler(captured=captured))
    client = SmartTokenClient(**_base_kwargs())

    client.obtain_token(None)

    assert "scope" not in _form_data(captured[0])
    client.close()


def test_normalizes_scope_with_surrounding_whitespace(install_mock_transport) -> None:
    captured: list[httpx.Request] = []
    install_mock_transport(_token_success_handler(captured=captured))
    client = SmartTokenClient(**_base_kwargs(token_cache=TokenCacheStrategy(enabled=False)))

    client.obtain_token("  system/Patient.rs  ")

    assert _form_data(captured[0])["scope"] == "system/Patient.rs"
    client.close()


def test_sends_valid_traceparent_header(install_mock_transport) -> None:
    captured: list[httpx.Request] = []
    install_mock_transport(_token_success_handler(captured=captured))
    client = SmartTokenClient(**_base_kwargs())

    client.obtain_token()

    traceparent = captured[0].headers[TraceContext.TRACEPARENT_HEADER]
    parts = traceparent.split("-")
    assert len(parts) == 4
    assert parts[0] == "00"
    assert len(parts[1]) == 32
    assert len(parts[2]) == 16
    client.close()


def test_each_real_fetch_uses_a_fresh_trace_context(install_mock_transport) -> None:
    captured: list[httpx.Request] = []
    install_mock_transport(_token_success_handler(captured=captured))
    client = SmartTokenClient(**_base_kwargs(token_cache=TokenCacheStrategy(enabled=False)))

    client.obtain_token("scope-a")
    client.obtain_token("scope-b")

    trace_1 = captured[0].headers[TraceContext.TRACEPARENT_HEADER]
    trace_2 = captured[1].headers[TraceContext.TRACEPARENT_HEADER]
    assert trace_1 != trace_2
    client.close()


# ---------------------------------------------------------------------------
# Sucesso, cache e invalidacao (RF-03/RF-04/RF-06)
# ---------------------------------------------------------------------------


def test_obtain_token_returns_access_token(install_mock_transport) -> None:
    install_mock_transport(_token_success_handler(access_token="tok-xyz"))
    client = SmartTokenClient(**_base_kwargs())

    assert client.obtain_token() == "tok-xyz"
    client.close()


def test_obtain_token_response_includes_raw_body_on_network_fetch(install_mock_transport) -> None:
    install_mock_transport(_token_success_handler(access_token="tok-xyz", expires_in=1234))
    client = SmartTokenClient(**_base_kwargs())

    result = client.obtain_token_response()

    assert isinstance(result, TokenResult)
    assert result.access_token == "tok-xyz"
    assert result.expires_in == 1234
    assert result.raw == {"access_token": "tok-xyz", "expires_in": 1234}
    client.close()


def test_second_call_for_same_scope_is_served_from_cache(install_mock_transport) -> None:
    captured: list[httpx.Request] = []
    install_mock_transport(_token_success_handler(captured=captured))
    client = SmartTokenClient(**_base_kwargs())

    first = client.obtain_token("system/Patient.rs")
    second = client.obtain_token("system/Patient.rs")

    assert first == second
    assert len(captured) == 1  # segunda chamada nao foi a rede
    client.close()


def test_cache_hit_has_no_raw_body(install_mock_transport) -> None:
    install_mock_transport(_token_success_handler())
    client = SmartTokenClient(**_base_kwargs())

    client.obtain_token_response("escopo")
    cached = client.obtain_token_response("escopo")

    assert cached.raw is None
    client.close()


def test_none_and_empty_scope_share_the_same_cache_entry(install_mock_transport) -> None:
    captured: list[httpx.Request] = []
    install_mock_transport(_token_success_handler(captured=captured))
    client = SmartTokenClient(**_base_kwargs())

    client.obtain_token(None)
    client.obtain_token("")

    assert len(captured) == 1
    client.close()


def test_disabled_cache_fetches_every_call(install_mock_transport) -> None:
    captured: list[httpx.Request] = []
    install_mock_transport(_token_success_handler(captured=captured))
    client = SmartTokenClient(**_base_kwargs(token_cache=TokenCacheStrategy(enabled=False)))

    client.obtain_token("mesmo-escopo")
    client.obtain_token("mesmo-escopo")

    assert len(captured) == 2
    client.close()


def test_invalidate_cache_for_specific_scope_forces_new_fetch(install_mock_transport) -> None:
    captured: list[httpx.Request] = []
    install_mock_transport(_token_success_handler(captured=captured))
    client = SmartTokenClient(**_base_kwargs())

    client.obtain_token("scope-a")
    client.invalidate_cache("scope-a")
    client.obtain_token("scope-a")

    assert len(captured) == 2
    client.close()


def test_invalidate_cache_all_scopes_forces_new_fetch_for_every_scope(install_mock_transport) -> None:
    captured: list[httpx.Request] = []
    install_mock_transport(_token_success_handler(captured=captured))
    client = SmartTokenClient(**_base_kwargs())

    client.obtain_token("scope-a")
    client.obtain_token("scope-b")
    client.invalidate_cache()
    client.obtain_token("scope-a")
    client.obtain_token("scope-b")

    assert len(captured) == 4
    client.close()


# ---------------------------------------------------------------------------
# Single-flight / concorrencia (RF-05)
# ---------------------------------------------------------------------------


def test_single_flight_dedupes_concurrent_calls_for_same_scope(install_mock_transport) -> None:
    """N threads pedindo o mesmo scope simultaneamente devem resultar em
    apenas UMA requisicao HTTP real (lock striping + double-checked
    locking, RF-05)."""
    call_count = 0
    count_lock = threading.Lock()

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal call_count
        with count_lock:
            call_count += 1
        time.sleep(0.05)  # alarga a janela de corrida entre as threads
        return httpx.Response(status_code=200, json={"access_token": "tok-compartilhado", "expires_in": 3600})

    install_mock_transport(handler)
    client = SmartTokenClient(**_base_kwargs())

    start = threading.Event()
    results: list[str] = []
    errors: list[BaseException] = []
    results_lock = threading.Lock()

    def worker() -> None:
        start.wait()
        try:
            token = client.obtain_token("system/Patient.rs")
            with results_lock:
                results.append(token)
        except BaseException as exc:  # noqa: BLE001 - captura para assert fora da thread
            with results_lock:
                errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(16)]
    for t in threads:
        t.start()
    start.set()
    for t in threads:
        t.join(timeout=10)

    assert not errors, f"excecoes inesperadas durante acesso concorrente: {errors}"
    assert results == ["tok-compartilhado"] * 16
    assert call_count == 1
    client.close()


def test_single_flight_does_not_serialize_distinct_scopes(install_mock_transport) -> None:
    """Scopes distintos nao devem competir pelo mesmo lock de stripe a
    ponto de impedir progresso -- aqui apenas confirma que ambos os scopes
    completam com sucesso quando pedidos concorrentemente."""
    scopes_seen: list[str] = []
    seen_lock = threading.Lock()

    def handler(request: httpx.Request) -> httpx.Response:
        form = _form_data(request)
        with seen_lock:
            scopes_seen.append(form.get("scope", ""))
        return httpx.Response(
            status_code=200, json={"access_token": f"tok-{form.get('scope', '')}", "expires_in": 3600}
        )

    install_mock_transport(handler)
    client = SmartTokenClient(**_base_kwargs())

    results: dict[str, str] = {}
    results_lock = threading.Lock()

    def worker(scope: str) -> None:
        token = client.obtain_token(scope)
        with results_lock:
            results[scope] = token

    threads = [threading.Thread(target=worker, args=(scope,)) for scope in ("scope-a", "scope-b")]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10)

    assert results == {"scope-a": "tok-scope-a", "scope-b": "tok-scope-b"}
    client.close()


# ---------------------------------------------------------------------------
# Retry em falha transitoria (RF-07)
# ---------------------------------------------------------------------------


def test_retries_and_recovers_from_transient_transport_failures(install_mock_transport, monkeypatch) -> None:
    attempts = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        if attempts < 3:
            raise httpx.ConnectError("connection refused")
        return httpx.Response(status_code=200, json={"access_token": "tok-recuperado", "expires_in": 3600})

    install_mock_transport(handler)
    sleep_calls: list[float] = []
    monkeypatch.setattr("hubsaude_client.client.time.sleep", sleep_calls.append)

    client = SmartTokenClient(**_base_kwargs())

    assert client.obtain_token() == "tok-recuperado"
    assert attempts == 3
    assert sleep_calls == [1.0, 2.0]  # backoff 1s x 2^(n-1) entre as duas primeiras falhas
    client.close()


def test_exhausts_retries_and_raises_smart_token_error(install_mock_transport, monkeypatch) -> None:
    attempts = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        raise httpx.ConnectTimeout("timed out")

    install_mock_transport(handler)
    monkeypatch.setattr("hubsaude_client.client.time.sleep", lambda _seconds: None)

    fault_tolerance = FaultToleranceConfig(
        connect_timeout=timedelta(seconds=5),
        request_timeout=timedelta(seconds=5),
        assertion_ttl_seconds=60,
        max_retries=2,
    )
    client = SmartTokenClient(**_base_kwargs(fault_tolerance=fault_tolerance))

    with pytest.raises(SmartTokenError) as excinfo:
        client.obtain_token()

    assert attempts == 2  # nao excede max_retries
    assert isinstance(excinfo.value.__cause__, httpx.ConnectTimeout)


def test_non_200_http_response_is_not_retried(install_mock_transport) -> None:
    attempts = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        return httpx.Response(status_code=500, content=b"erro interno")

    install_mock_transport(handler)
    client = SmartTokenClient(**_base_kwargs())

    with pytest.raises(SmartTokenError) as excinfo:
        client.obtain_token()

    assert attempts == 1  # resposta HTTP recebida nunca sofre retry (RF-07)
    assert "HTTP 500" in str(excinfo.value)


def test_rate_limit_response_is_not_retried(install_mock_transport) -> None:
    attempts = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        return httpx.Response(status_code=429, content=b"slow down")

    install_mock_transport(handler)
    client = SmartTokenClient(**_base_kwargs())

    with pytest.raises(SmartTokenError):
        client.obtain_token()

    assert attempts == 1


def test_non_transient_transport_failure_propagates_unwrapped(install_mock_transport) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.RemoteProtocolError("resposta inesperada do servidor")

    install_mock_transport(handler)
    client = SmartTokenClient(**_base_kwargs())

    # Nao e' timeout/connect/read/write nem EOF prematuro -> ErrorClassifier
    # nao considera transitorio e relanca a excecao original, sem retry
    # nem wrapping em SmartTokenError.
    with pytest.raises(httpx.RemoteProtocolError):
        client.obtain_token()


def test_likely_client_certificate_rejection_raises_smart_token_error(install_mock_transport) -> None:
    attempts = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        try:
            raise ssl.SSLError("certificate_revoked: bad cert")
        except ssl.SSLError as ssl_exc:
            raise httpx.ConnectError("mTLS handshake failed") from ssl_exc

    install_mock_transport(handler)
    client = SmartTokenClient(**_base_kwargs())

    with pytest.raises(SmartTokenError) as excinfo:
        client.obtain_token()

    assert attempts == 1  # sem retry: suspeita de rejeicao de certificado e' definitiva
    assert "certificado de cliente" in str(excinfo.value)


# ---------------------------------------------------------------------------
# Ciclo de vida / close (RF-17, RNF-01)
# ---------------------------------------------------------------------------


def test_close_is_idempotent(install_mock_transport) -> None:
    install_mock_transport(_token_success_handler())
    client = SmartTokenClient(**_base_kwargs())

    client.close()
    client.close()  # nao deve levantar excecao


def test_obtain_token_after_close_raises_smart_token_error(install_mock_transport) -> None:
    install_mock_transport(_token_success_handler())
    client = SmartTokenClient(**_base_kwargs())
    client.close()

    with pytest.raises(SmartTokenError, match="fechado"):
        client.obtain_token()


def test_close_invalidates_the_cache(install_mock_transport) -> None:
    install_mock_transport(_token_success_handler())
    token_cache = TokenCacheStrategy(enabled=True)
    client = SmartTokenClient(**_base_kwargs(token_cache=token_cache))

    client.obtain_token("system/Patient.rs")
    assert token_cache.size() == 1

    client.close()

    assert token_cache.size() == 0


def test_context_manager_closes_on_exit(install_mock_transport) -> None:
    install_mock_transport(_token_success_handler())

    with SmartTokenClient(**_base_kwargs()) as client:
        client.obtain_token()

    with pytest.raises(SmartTokenError):
        client.obtain_token()


# ---------------------------------------------------------------------------
# TokenResult
# ---------------------------------------------------------------------------


def test_token_result_repr_masks_access_token() -> None:
    result = TokenResult(
        access_token="segredo-super-secreto", expires_in=3600, raw={"access_token": "segredo-super-secreto"}
    )

    text = repr(result)

    assert "segredo-super-secreto" not in text
    assert "[REDACTED]" in text


# ---------------------------------------------------------------------------
# _ReadersWriterLock -- contencao real entre leitores/escritor (RNF-01)
# ---------------------------------------------------------------------------
#
# Os testes de single-flight acima ja exercitam varios leitores concorrentes
# sem contencao com um escritor. Os dois testes abaixo forcam deliberadamente
# a espera em `_acquire_read`/`_acquire_write` (via `threading.Condition.wait`)
# -- cenario que so' ocorre quando um escritor esta ativo e um leitor chega
# (ou vice-versa) -- para exercitar o unico ramo de `_ReadersWriterLock` que
# os testes de fluxo normal do client nao alcancam.


def test_reader_waits_while_writer_is_active() -> None:
    lock = _ReadersWriterLock()
    writer_holding = threading.Event()
    release_writer = threading.Event()
    reader_acquired = threading.Event()

    def writer() -> None:
        with lock.write_lock():
            writer_holding.set()
            release_writer.wait(timeout=5)

    def reader() -> None:
        writer_holding.wait(timeout=5)
        # Aqui o escritor certamente esta ativo -- _acquire_read cai no
        # `while self._writer_active: self._condition.wait()`.
        with lock.read_lock():
            reader_acquired.set()

    writer_thread = threading.Thread(target=writer)
    reader_thread = threading.Thread(target=reader)
    writer_thread.start()
    writer_thread_started = writer_holding.wait(timeout=5)
    assert writer_thread_started, "escritor nao sinalizou posse do lock a tempo"

    reader_thread.start()
    # Da tempo do leitor de fato bloquear em `condition.wait()` antes de liberar
    # o escritor -- sem isso o teste nao garante que o ramo de espera rodou.
    time.sleep(0.05)
    assert not reader_acquired.is_set(), "leitor nao deveria progredir com o escritor ainda ativo"

    release_writer.set()
    writer_thread.join(timeout=5)
    reader_thread.join(timeout=5)

    assert reader_acquired.is_set(), "leitor deveria progredir apos o escritor liberar o lock"


def test_writer_waits_while_reader_is_active() -> None:
    lock = _ReadersWriterLock()
    reader_holding = threading.Event()
    release_reader = threading.Event()
    writer_acquired = threading.Event()

    def reader() -> None:
        with lock.read_lock():
            reader_holding.set()
            release_reader.wait(timeout=5)

    def writer() -> None:
        reader_holding.wait(timeout=5)
        # Aqui o leitor certamente esta ativo -- _acquire_write cai no
        # `while self._writer_active or self._active_readers > 0: self._condition.wait()`.
        with lock.write_lock():
            writer_acquired.set()

    reader_thread = threading.Thread(target=reader)
    writer_thread = threading.Thread(target=writer)
    reader_thread.start()
    reader_thread_started = reader_holding.wait(timeout=5)
    assert reader_thread_started, "leitor nao sinalizou posse do lock a tempo"

    writer_thread.start()
    time.sleep(0.05)
    assert not writer_acquired.is_set(), "escritor nao deveria progredir com o leitor ainda ativo"

    release_reader.set()
    reader_thread.join(timeout=5)
    writer_thread.join(timeout=5)

    assert writer_acquired.is_set(), "escritor deveria progredir apos o leitor liberar o lock"

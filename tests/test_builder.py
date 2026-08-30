"""Testes de ``builder.SmartTokenClientBuilder``.

Nota sobre o fake de ``client.py``: ``build()`` faz um import tardio de
``hubsaude_client.client.SmartTokenClient`` (ver docstring de
``builder.py``, que explica o motivo -- quebrar um ciclo de import real
entre os dois modulos). Para testar a construcao minima valida sem
acoplar os testes do builder aos detalhes internos da implementacao
real de ``SmartTokenClient`` (rede, threads, etc.), os testes injetam
um modulo fake em ``sys.modules`` antes de chamar ``build()`` -- ver
fixture ``fake_smart_token_client_module``. Isso mantem os testes deste
modulo focados exclusivamente na responsabilidade do builder (validacao
fail-fast e montagem dos kwargs); o comportamento do
``SmartTokenClient`` real e testado a parte, em ``test_client.py``. Os
testes de validacao (fail-fast) nao precisam dessa fixture: todos
levantam ``SmartTokenError`` antes de ``build()`` alcancar o import
tardio.
"""

from __future__ import annotations

import logging
import sys
import types
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

import pytest

from hubsaude_client.builder import HubContext, SmartTokenClientBuilder
from hubsaude_client.exceptions import SmartTokenError
from hubsaude_client.fault_tolerance import FaultToleranceConfig
from hubsaude_client.private_key_signing_strategy import PrivateKeySigningStrategy
from hubsaude_client.token_cache import TokenCacheStrategy

from .fakes import FakeSigningStrategy, FakeTlsContextProvider

CLIENT_ID = "cliente-teste"
TOKEN_ENDPOINT = "https://auth.example/token"
FHIR_BASE = "https://fhir.example/r4"


@dataclass
class _FakeSmartTokenClient:
    """Substituto de ``client.SmartTokenClient`` para os testes deste
    modulo -- captura os kwargs recebidos de ``builder.build()`` para
    inspecao, sem exigir a implementacao real (isola dos detalhes
    internos de ``SmartTokenClient`` -- ver docstring do modulo).
    """

    client_id: str
    token_endpoint: str | None
    fhir_base: str | None
    signing_strategy: object
    tls_context_provider: object
    fault_tolerance: FaultToleranceConfig
    token_cache: TokenCacheStrategy
    jwt_algorithm: str
    key_id: str | None
    hub_context: HubContext | None


@pytest.fixture
def fake_smart_token_client_module(monkeypatch: pytest.MonkeyPatch) -> type[_FakeSmartTokenClient]:
    """Injeta um ``hubsaude_client.client`` fake em ``sys.modules``.

    Permite testar ``SmartTokenClientBuilder.build()`` de ponta a ponta
    (import tardio incluido) isolado dos detalhes internos da
    implementacao real de ``client.py`` -- ver docstring do modulo.
    """
    fake_module = types.ModuleType("hubsaude_client.client")
    fake_module.SmartTokenClient = _FakeSmartTokenClient  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "hubsaude_client.client", fake_module)
    return _FakeSmartTokenClient


def _valid_builder() -> SmartTokenClientBuilder:
    return (
        SmartTokenClientBuilder()
        .client_id(CLIENT_ID)
        .token_endpoint(TOKEN_ENDPOINT)
        .signing_strategy(FakeSigningStrategy())
        .tls_context_provider(FakeTlsContextProvider())
    )


# ---------------------------------------------------------------------------
# Construcao minima valida
# ---------------------------------------------------------------------------


def test_builds_client_with_minimal_valid_configuration(
    fake_smart_token_client_module: type[_FakeSmartTokenClient],
) -> None:
    client = _valid_builder().build()

    assert isinstance(client, fake_smart_token_client_module)
    assert client.client_id == CLIENT_ID
    assert client.token_endpoint == TOKEN_ENDPOINT
    assert client.fhir_base is None
    assert client.jwt_algorithm == "RS384"
    assert client.key_id is None
    assert client.hub_context is None


def test_builds_client_with_fhir_base_instead_of_token_endpoint(
    fake_smart_token_client_module: type[_FakeSmartTokenClient],
) -> None:
    client = (
        SmartTokenClientBuilder()
        .client_id(CLIENT_ID)
        .fhir_base(FHIR_BASE)
        .signing_strategy(FakeSigningStrategy())
        .tls_context_provider(FakeTlsContextProvider())
        .build()
    )

    assert client.token_endpoint is None
    assert client.fhir_base == FHIR_BASE


def test_strips_whitespace_from_client_id_and_token_endpoint(
    fake_smart_token_client_module: type[_FakeSmartTokenClient],
) -> None:
    client = (
        SmartTokenClientBuilder()
        .client_id("  " + CLIENT_ID + "  ")
        .token_endpoint("  " + TOKEN_ENDPOINT + "  ")
        .signing_strategy(FakeSigningStrategy())
        .tls_context_provider(FakeTlsContextProvider())
        .build()
    )

    assert client.client_id == CLIENT_ID
    assert client.token_endpoint == TOKEN_ENDPOINT


def test_uses_configured_fault_tolerance_and_cache_settings(
    fake_smart_token_client_module: type[_FakeSmartTokenClient],
) -> None:
    client = (
        _valid_builder()
        .assertion_ttl_seconds(120)
        .max_retries(5)
        .connect_timeout(timedelta(seconds=3))
        .request_timeout(timedelta(seconds=9))
        .enable_token_cache(False)
        .token_cache_margin_seconds(15)
        .token_cache_max_entries(50)
        .build()
    )

    assert client.fault_tolerance.assertion_ttl_seconds == 120
    assert client.fault_tolerance.max_retries == 5
    assert client.fault_tolerance.connect_timeout == timedelta(seconds=3)
    assert client.fault_tolerance.request_timeout == timedelta(seconds=9)
    assert isinstance(client.token_cache, TokenCacheStrategy)
    assert client.token_cache.size() == 0


def test_normalizes_jwt_algorithm_case(fake_smart_token_client_module: type[_FakeSmartTokenClient]) -> None:
    client = _valid_builder().jwt_algorithm("es384").build()

    assert client.jwt_algorithm == "ES384"


def test_key_id_is_passed_through(fake_smart_token_client_module: type[_FakeSmartTokenClient]) -> None:
    client = _valid_builder().key_id("chave-01").build()

    assert client.key_id == "chave-01"


def test_blank_key_id_is_normalized_to_none(fake_smart_token_client_module: type[_FakeSmartTokenClient]) -> None:
    client = _valid_builder().key_id("   ").build()

    assert client.key_id is None


def test_hub_context_is_built_when_valid(fake_smart_token_client_module: type[_FakeSmartTokenClient]) -> None:
    client = _valid_builder().hub_context("meu-ig", "1.2.3").build()

    assert client.hub_context == HubContext(ig="meu-ig", versao="1.2.3")


def test_returns_self_for_chaining() -> None:
    builder = SmartTokenClientBuilder()

    assert builder.client_id(CLIENT_ID) is builder
    assert builder.token_endpoint(TOKEN_ENDPOINT) is builder
    assert builder.signing_strategy(FakeSigningStrategy()) is builder
    assert builder.tls_context_provider(FakeTlsContextProvider()) is builder


def test_logs_debug_when_building(
    caplog: pytest.LogCaptureFixture, fake_smart_token_client_module: type[_FakeSmartTokenClient]
) -> None:
    with caplog.at_level(logging.DEBUG, logger="hubsaude_client.SmartTokenClient"):
        _valid_builder().build()

    assert any(CLIENT_ID in record.message for record in caplog.records)


# ---------------------------------------------------------------------------
# client_id
# ---------------------------------------------------------------------------


def test_raises_when_client_id_missing() -> None:
    builder = (
        SmartTokenClientBuilder()
        .token_endpoint(TOKEN_ENDPOINT)
        .signing_strategy(FakeSigningStrategy())
        .tls_context_provider(FakeTlsContextProvider())
    )

    with pytest.raises(SmartTokenError, match="client_id"):
        builder.build()


def test_raises_when_client_id_is_blank() -> None:
    builder = _valid_builder().client_id("   ")

    with pytest.raises(SmartTokenError, match="client_id"):
        builder.build()


# ---------------------------------------------------------------------------
# signing_strategy / tls_context_provider
# ---------------------------------------------------------------------------


def test_raises_when_signing_strategy_missing() -> None:
    builder = (
        SmartTokenClientBuilder()
        .client_id(CLIENT_ID)
        .token_endpoint(TOKEN_ENDPOINT)
        .tls_context_provider(FakeTlsContextProvider())
    )

    with pytest.raises(SmartTokenError, match="signing_strategy"):
        builder.build()


def test_raises_when_signing_strategy_does_not_satisfy_protocol() -> None:
    class _NotASigningStrategy:
        def verify(self, data: bytes) -> bool:
            return True

    builder = (
        SmartTokenClientBuilder()
        .client_id(CLIENT_ID)
        .token_endpoint(TOKEN_ENDPOINT)
        .signing_strategy(_NotASigningStrategy())  # type: ignore[arg-type]
        .tls_context_provider(FakeTlsContextProvider())
    )

    with pytest.raises(SmartTokenError, match="SigningStrategy"):
        builder.build()


def test_raises_when_tls_context_provider_missing() -> None:
    builder = (
        SmartTokenClientBuilder()
        .client_id(CLIENT_ID)
        .token_endpoint(TOKEN_ENDPOINT)
        .signing_strategy(FakeSigningStrategy())
    )

    with pytest.raises(SmartTokenError, match="tls_context_provider"):
        builder.build()


def test_raises_when_tls_context_provider_does_not_satisfy_protocol() -> None:
    class _NotATlsContextProvider:
        def get_context(self) -> object:
            return object()

    builder = (
        SmartTokenClientBuilder()
        .client_id(CLIENT_ID)
        .token_endpoint(TOKEN_ENDPOINT)
        .signing_strategy(FakeSigningStrategy())
        .tls_context_provider(_NotATlsContextProvider())  # type: ignore[arg-type]
    )

    with pytest.raises(SmartTokenError, match="TlsContextProvider"):
        builder.build()


# ---------------------------------------------------------------------------
# token_endpoint / fhir_base
# ---------------------------------------------------------------------------


def test_raises_when_neither_token_endpoint_nor_fhir_base_set() -> None:
    builder = (
        SmartTokenClientBuilder()
        .client_id(CLIENT_ID)
        .signing_strategy(FakeSigningStrategy())
        .tls_context_provider(FakeTlsContextProvider())
    )

    with pytest.raises(SmartTokenError, match="token_endpoint.*fhir_base|fhir_base.*token_endpoint"):
        builder.build()


def test_raises_when_both_token_endpoint_and_fhir_base_set() -> None:
    builder = _valid_builder().fhir_base(FHIR_BASE)

    with pytest.raises(SmartTokenError, match="mutuamente exclusivos"):
        builder.build()


@pytest.mark.parametrize(
    "url",
    ["http://auth.example/token", "ftp://auth.example/token", "auth.example/token"],
)
def test_raises_when_token_endpoint_is_not_https(url: str) -> None:
    builder = (
        SmartTokenClientBuilder()
        .client_id(CLIENT_ID)
        .token_endpoint(url)
        .signing_strategy(FakeSigningStrategy())
        .tls_context_provider(FakeTlsContextProvider())
    )

    with pytest.raises(SmartTokenError, match="https"):
        builder.build()


def test_raises_when_fhir_base_is_not_https() -> None:
    builder = (
        SmartTokenClientBuilder()
        .client_id(CLIENT_ID)
        .fhir_base("http://fhir.example/r4")
        .signing_strategy(FakeSigningStrategy())
        .tls_context_provider(FakeTlsContextProvider())
    )

    with pytest.raises(SmartTokenError, match="https"):
        builder.build()


# ---------------------------------------------------------------------------
# jwt_algorithm
# ---------------------------------------------------------------------------


def test_raises_when_jwt_algorithm_is_invalid() -> None:
    builder = _valid_builder().jwt_algorithm("HS256")

    with pytest.raises(SmartTokenError, match="Algoritmo JWT nao suportado"):
        builder.build()


# ---------------------------------------------------------------------------
# timeouts
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("seconds", [0, -1])
def test_raises_when_connect_timeout_is_not_positive(seconds: int) -> None:
    builder = _valid_builder().connect_timeout(timedelta(seconds=seconds))

    with pytest.raises(SmartTokenError, match="connect_timeout"):
        builder.build()


@pytest.mark.parametrize("seconds", [0, -1])
def test_raises_when_request_timeout_is_not_positive(seconds: int) -> None:
    builder = _valid_builder().request_timeout(timedelta(seconds=seconds))

    with pytest.raises(SmartTokenError, match="request_timeout"):
        builder.build()


# ---------------------------------------------------------------------------
# token_cache_max_entries
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("max_entries", [0, -1, -100])
def test_raises_when_token_cache_max_entries_is_not_positive(max_entries: int) -> None:
    builder = _valid_builder().token_cache_max_entries(max_entries)

    with pytest.raises(SmartTokenError, match="token_cache_max_entries"):
        builder.build()


# ---------------------------------------------------------------------------
# hub_context
# ---------------------------------------------------------------------------


def test_raises_when_hub_context_ig_has_invalid_format() -> None:
    builder = _valid_builder().hub_context("IG-Invalido", "1.0.0")

    with pytest.raises(SmartTokenError, match="ig invalido"):
        builder.build()


@pytest.mark.parametrize("versao", ["1.0", "1.0.0-beta", "v1.0.0", "1.0.0.0"])
def test_raises_when_hub_context_versao_has_invalid_format(versao: str) -> None:
    builder = _valid_builder().hub_context("meu-ig", versao)

    with pytest.raises(SmartTokenError, match="versao invalida"):
        builder.build()


# ---------------------------------------------------------------------------
# Metodos de conveniencia da Fatia A (ainda nao implementados)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "call",
    [
        lambda b: b.certificate_pem("cert.pem"),
        lambda b: b.client_key_store("store.p12", b"senha"),
        lambda b: b.server_trust_anchor("trust.pem"),
    ],
)
def test_fatia_a_convenience_methods_are_not_implemented(call: Any) -> None:
    with pytest.raises(NotImplementedError):
        call(SmartTokenClientBuilder())


# ---------------------------------------------------------------------------
# private_key_pem() -- delega a strategy_factory.from_pem_file
# ---------------------------------------------------------------------------


def test_private_key_pem_builds_client_from_pem_file(
    fake_pem_pair, fake_smart_token_client_module: type[_FakeSmartTokenClient]
) -> None:
    client = (
        SmartTokenClientBuilder()
        .client_id(CLIENT_ID)
        .token_endpoint(TOKEN_ENDPOINT)
        .private_key_pem(fake_pem_pair["key"])
        .tls_context_provider(FakeTlsContextProvider())
        .build()
    )

    assert isinstance(client.signing_strategy, PrivateKeySigningStrategy)


def test_private_key_pem_resolution_is_deferred_to_build_so_jwt_algorithm_order_is_irrelevant(
    fake_pem_pair, fake_smart_token_client_module: type[_FakeSmartTokenClient]
) -> None:
    client = (
        SmartTokenClientBuilder()
        .client_id(CLIENT_ID)
        .token_endpoint(TOKEN_ENDPOINT)
        .private_key_pem(fake_pem_pair["key"])
        .jwt_algorithm("rs256")
        .tls_context_provider(FakeTlsContextProvider())
        .build()
    )

    assert client.jwt_algorithm == "RS256"
    assert client.signing_strategy.jwt_algorithm == "RS256"


def test_private_key_pem_and_signing_strategy_are_mutually_exclusive(fake_pem_pair) -> None:
    builder = _valid_builder().private_key_pem(fake_pem_pair["key"])

    with pytest.raises(SmartTokenError, match="mutuamente exclusivos"):
        builder.build()


def test_private_key_pem_with_invalid_pem_content_raises_smart_token_error(tmp_path) -> None:
    garbage_path = tmp_path / "garbage.pem"
    garbage_path.write_text("nao e um PEM valido")
    builder = (
        SmartTokenClientBuilder()
        .client_id(CLIENT_ID)
        .token_endpoint(TOKEN_ENDPOINT)
        .private_key_pem(garbage_path)
        .tls_context_provider(FakeTlsContextProvider())
    )

    with pytest.raises(SmartTokenError, match="formato"):
        builder.build()


# ---------------------------------------------------------------------------
# TTL acima do recomendado (aviso, nao bloqueia)
# ---------------------------------------------------------------------------


def test_warns_but_does_not_raise_when_ttl_exceeds_recommended(
    caplog: pytest.LogCaptureFixture, fake_smart_token_client_module: type[_FakeSmartTokenClient]
) -> None:
    with caplog.at_level(logging.WARNING, logger="hubsaude_client.SmartTokenClient"):
        client = _valid_builder().assertion_ttl_seconds(600).build()

    assert client.fault_tolerance.assertion_ttl_seconds == 600
    assert any(record.levelno == logging.WARNING for record in caplog.records)

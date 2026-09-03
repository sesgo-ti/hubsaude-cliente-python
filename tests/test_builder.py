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
import ssl
import sys
import types
from dataclasses import dataclass
from datetime import timedelta

import pytest

from hubsaude_client import strategy_factory
from hubsaude_client.builder import HubContext, SmartTokenClientBuilder
from hubsaude_client.defaults import DEFAULT_TOKEN_CACHE_MARGIN_SECONDS
from hubsaude_client.exceptions import SmartTokenError
from hubsaude_client.fault_tolerance import FaultToleranceConfig
from hubsaude_client.pkcs11_signing_strategy import Pkcs11SigningStrategy
from hubsaude_client.private_key_signing_strategy import PrivateKeySigningStrategy
from hubsaude_client.token_cache import TokenCacheStrategy

from .fakes import FakeSigningStrategy, FakeTlsContextProvider
from .pkcs11_softhsm_helper import (
    _pkcs11_lib,  # noqa: F401  (fixture, used transitively by softhsm2_token)
    softhsm2_available,
    softhsm2_token,  # noqa: F401  (fixture)
)

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
        .token_cache_margin_seconds(15)
        .max_retries(5)
        .connect_timeout(timedelta(seconds=3))
        .request_timeout(timedelta(seconds=9))
        .enable_token_cache(False)
        .token_cache_max_entries(50)
        .build()
    )

    assert client.fault_tolerance.assertion_ttl_seconds == 120
    assert client.fault_tolerance.token_cache_margin_seconds == 15
    assert client.fault_tolerance.max_retries == 5
    assert client.fault_tolerance.connect_timeout == timedelta(seconds=3)
    assert client.fault_tolerance.request_timeout == timedelta(seconds=9)
    assert isinstance(client.token_cache, TokenCacheStrategy)
    assert client.token_cache.size() == 0


@pytest.mark.parametrize("token_cache_margin_seconds", [0, -1, -60])
def test_invalid_token_cache_margin_seconds_is_normalized_the_same_way_in_cache_and_fault_tolerance(
    fake_smart_token_client_module: type[_FakeSmartTokenClient], token_cache_margin_seconds: int
) -> None:
    """Regressao: uma margem de cache invalida (``<= 0``) deve virar o
    mesmo valor normalizado (``DEFAULT_TOKEN_CACHE_MARGIN_SECONDS``) tanto
    em ``fault_tolerance.token_cache_margin_seconds`` quanto no
    ``TokenCacheStrategy`` efetivamente usado pelo cliente. Antes desta
    correcao, ``build()`` repassava o valor cru (nao normalizado) para
    ``TokenCacheStrategy``, divergindo do valor ja normalizado em
    ``FaultToleranceConfig`` -- um token expirado podia ser servido do
    cache como valido por ate ``|margem|`` segundos apos a expiracao real."""
    client = _valid_builder().token_cache_margin_seconds(token_cache_margin_seconds).build()

    assert client.fault_tolerance.token_cache_margin_seconds == DEFAULT_TOKEN_CACHE_MARGIN_SECONDS
    assert client.token_cache._margin_seconds == DEFAULT_TOKEN_CACHE_MARGIN_SECONDS


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


@pytest.mark.parametrize(
    "url",
    [
        "http://localhost:8080/token",
        "http://127.0.0.1:8080/token",
        "http://[::1]:8080/token",
    ],
)
def test_allows_token_endpoint_on_local_host_without_https(url: str) -> None:
    """Excecao de desenvolvimento local: um
    authorization server local sem TLS nao deve quebrar o builder, mesma
    allowlist do lado Java (localhost/127.0.0.1/::1)."""
    builder = (
        SmartTokenClientBuilder()
        .client_id(CLIENT_ID)
        .token_endpoint(url)
        .signing_strategy(FakeSigningStrategy())
        .tls_context_provider(FakeTlsContextProvider())
    )

    client = builder.build()

    assert client.get_token_endpoint() == url


def test_does_not_reject_fhir_base_on_local_host_for_scheme(monkeypatch: pytest.MonkeyPatch) -> None:
    """``fhir_base`` em localhost/127.0.0.1/::1 sem https nao deve ser
    rejeitado por ``_validate_endpoint_config`` (RF-18). A resolucao do
    ``token_endpoint`` via descoberta SMART e' testada separadamente em
    ``test_discovery.py``; aqui isolamos apenas a validacao de esquema do
    builder, sem depender de rede real."""
    builder = (
        SmartTokenClientBuilder()
        .client_id(CLIENT_ID)
        .fhir_base("http://localhost:8080/r4")
        .signing_strategy(FakeSigningStrategy())
        .tls_context_provider(FakeTlsContextProvider())
    )

    builder._validate_endpoint_config()  # nao deve lancar por causa do esquema


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


def test_raises_when_hub_context_ig_is_blank_but_versao_is_present() -> None:
    """``hub_context(ig, versao)`` sempre atribui os dois juntos, mas um
    dos dois pode normalizar para ``None`` (string vazia/so espacos) sem o
    outro -- e' o unico jeito de alcancar a validacao de "os dois juntos"
    em `_build_hub_context`, que fica logo antes da validacao de formato."""
    builder = _valid_builder().hub_context("   ", "1.0.0")

    with pytest.raises(SmartTokenError, match="hub_context exige ig e versao juntos"):
        builder.build()


def test_raises_when_hub_context_versao_is_blank_but_ig_is_present() -> None:
    builder = _valid_builder().hub_context("meu-ig", "   ")

    with pytest.raises(SmartTokenError, match="hub_context exige ig e versao juntos"):
        builder.build()


@pytest.mark.parametrize("versao", ["1.0", "1.0.0-beta", "v1.0.0", "1.0.0.0"])
def test_raises_when_hub_context_versao_has_invalid_format(versao: str) -> None:
    builder = _valid_builder().hub_context("meu-ig", versao)

    with pytest.raises(SmartTokenError, match="versao invalida"):
        builder.build()


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
# certificate_pem() -- exige private_key_pem(), verifica consistencia (RF-15)
# ---------------------------------------------------------------------------


def test_certificate_pem_builds_client_with_tls_settings_provider(
    fake_pem_pair, fake_smart_token_client_module: type[_FakeSmartTokenClient]
) -> None:
    client = (
        SmartTokenClientBuilder()
        .client_id(CLIENT_ID)
        .token_endpoint(TOKEN_ENDPOINT)
        .private_key_pem(fake_pem_pair["key"])
        .certificate_pem(fake_pem_pair["cert"])
        .build()
    )
    context = client.tls_context_provider.ssl_context()
    assert isinstance(context, ssl.SSLContext)


def test_certificate_pem_without_private_key_pem_raises(fake_pem_pair) -> None:
    builder = (
        SmartTokenClientBuilder()
        .client_id(CLIENT_ID)
        .token_endpoint(TOKEN_ENDPOINT)
        .signing_strategy(FakeSigningStrategy())
        .certificate_pem(fake_pem_pair["cert"])
    )
    with pytest.raises(SmartTokenError, match="certificate_pem exige private_key_pem"):
        builder.build()


def test_certificate_pem_with_mismatched_certificate_raises(fake_mismatched_pem_pair) -> None:
    builder = (
        SmartTokenClientBuilder()
        .client_id(CLIENT_ID)
        .token_endpoint(TOKEN_ENDPOINT)
        .private_key_pem(fake_mismatched_pem_pair["matching_key"])
        .certificate_pem(fake_mismatched_pem_pair["mismatched_cert"])
    )
    # Nota: o desvio abaixo (match="nao corresponde", nao "consistencia") esta
    # documentado no relatorio desta task -- key_certificate_consistency.
    # verify_strategy() (Task 5, ja existe) levanta SmartTokenError com a
    # mensagem exata "Chave privada nao corresponde ao certificado: assinatura
    # invalida" no caminho InvalidSignature, que nao contem a substring
    # "consistencia" (essa so aparece no log de debug de sucesso e na
    # mensagem generica de excecao inesperada, nenhum dos dois exercitado
    # aqui).
    with pytest.raises(SmartTokenError, match="nao corresponde"):
        builder.build()


# ---------------------------------------------------------------------------
# client_key_store() -- PKCS#12: fornece assinatura E certificado de cliente
# ---------------------------------------------------------------------------


def test_client_key_store_builds_client_with_signing_and_tls(
    fake_pkcs12_bundle, fake_smart_token_client_module: type[_FakeSmartTokenClient]
) -> None:
    client = (
        SmartTokenClientBuilder()
        .client_id(CLIENT_ID)
        .token_endpoint(TOKEN_ENDPOINT)
        .client_key_store(fake_pkcs12_bundle["path"], fake_pkcs12_bundle["password"])
        .build()
    )
    assert isinstance(client.signing_strategy, PrivateKeySigningStrategy)
    context = client.tls_context_provider.ssl_context()
    assert isinstance(context, ssl.SSLContext)


def test_client_key_store_password_is_zeroed_after_build(
    fake_pkcs12_bundle, fake_smart_token_client_module: type[_FakeSmartTokenClient]
) -> None:
    password = fake_pkcs12_bundle["password"]
    (
        SmartTokenClientBuilder()
        .client_id(CLIENT_ID)
        .token_endpoint(TOKEN_ENDPOINT)
        .client_key_store(fake_pkcs12_bundle["path"], password)
        .build()
    )
    assert password == bytearray(len(password))


def test_client_key_store_and_private_key_pem_are_mutually_exclusive(fake_pkcs12_bundle, fake_pem_pair) -> None:
    builder = (
        SmartTokenClientBuilder()
        .client_id(CLIENT_ID)
        .token_endpoint(TOKEN_ENDPOINT)
        .private_key_pem(fake_pem_pair["key"])
        .client_key_store(fake_pkcs12_bundle["path"], fake_pkcs12_bundle["password"])
        .tls_context_provider(FakeTlsContextProvider())
    )
    with pytest.raises(SmartTokenError, match="mutuamente exclusivos"):
        builder.build()


def test_client_key_store_and_certificate_pem_are_mutually_exclusive(fake_pkcs12_bundle, fake_pem_pair) -> None:
    builder = (
        SmartTokenClientBuilder()
        .client_id(CLIENT_ID)
        .token_endpoint(TOKEN_ENDPOINT)
        .client_key_store(fake_pkcs12_bundle["path"], fake_pkcs12_bundle["password"])
        .certificate_pem(fake_pem_pair["cert"])
    )
    with pytest.raises(SmartTokenError, match="mutuamente exclusivos"):
        builder.build()


# ---------------------------------------------------------------------------
# server_trust_anchor() -- Path/str ou x509.Certificate em memoria
# ---------------------------------------------------------------------------


def test_server_trust_anchor_with_path_builds_client(
    fake_pem_pair, fake_smart_token_client_module: type[_FakeSmartTokenClient]
) -> None:
    # Nota: nao usa _valid_builder() aqui (desvio do brief documentado no
    # relatorio) -- _valid_builder() ja chama .tls_context_provider(...), o
    # que colidiria com server_trust_anchor() (mutuamente exclusivos, ver
    # test_server_trust_anchor_and_tls_context_provider_are_mutually_exclusive
    # abaixo, que usa _valid_builder() de proposito para exercitar exatamente
    # esse conflito).
    client = (
        SmartTokenClientBuilder()
        .client_id(CLIENT_ID)
        .token_endpoint(TOKEN_ENDPOINT)
        .signing_strategy(FakeSigningStrategy())
        .server_trust_anchor(fake_pem_pair["cert"])
        .build()
    )
    context = client.tls_context_provider.ssl_context()
    assert isinstance(context, ssl.SSLContext)


def test_server_trust_anchor_with_certificate_object_builds_client(
    fake_pem_pair, fake_smart_token_client_module: type[_FakeSmartTokenClient]
) -> None:
    from hubsaude_client import pem_loader

    cert = pem_loader.load_certificate(fake_pem_pair["cert"])
    client = (
        SmartTokenClientBuilder()
        .client_id(CLIENT_ID)
        .token_endpoint(TOKEN_ENDPOINT)
        .signing_strategy(FakeSigningStrategy())
        .server_trust_anchor(cert)
        .build()
    )
    context = client.tls_context_provider.ssl_context()
    assert isinstance(context, ssl.SSLContext)


def test_server_trust_anchor_and_tls_context_provider_are_mutually_exclusive(fake_pem_pair) -> None:
    builder = _valid_builder().server_trust_anchor(fake_pem_pair["cert"])
    with pytest.raises(SmartTokenError, match="mutuamente exclusivos"):
        builder.build()


# ---------------------------------------------------------------------------
# tls_protocol() -- sobrescreve a versao do protocolo TLS (padrao: TLSv1.3)
# ---------------------------------------------------------------------------


def test_tls_protocol_overrides_default_version(
    fake_pem_pair, fake_smart_token_client_module: type[_FakeSmartTokenClient]
) -> None:
    client = (
        SmartTokenClientBuilder()
        .client_id(CLIENT_ID)
        .token_endpoint(TOKEN_ENDPOINT)
        .signing_strategy(FakeSigningStrategy())
        .server_trust_anchor(fake_pem_pair["cert"])
        .tls_protocol("TLSv1.2")
        .build()
    )
    context = client.tls_context_provider.ssl_context()
    assert context.minimum_version == ssl.TLSVersion.TLSv1_2
    assert context.maximum_version == ssl.TLSVersion.TLSv1_2


def test_tls_protocol_alone_builds_client_with_default_trust_store(
    fake_smart_token_client_module: type[_FakeSmartTokenClient],
) -> None:
    client = (
        SmartTokenClientBuilder()
        .client_id(CLIENT_ID)
        .token_endpoint(TOKEN_ENDPOINT)
        .signing_strategy(FakeSigningStrategy())
        .tls_protocol("TLSv1.2")
        .build()
    )
    context = client.tls_context_provider.ssl_context()
    assert context.minimum_version == ssl.TLSVersion.TLSv1_2


def test_tls_protocol_and_tls_context_provider_are_mutually_exclusive() -> None:
    builder = _valid_builder().tls_protocol("TLSv1.2")
    with pytest.raises(SmartTokenError, match="mutuamente exclusivos"):
        builder.build()


def test_tls_protocol_invalid_value_raises_on_context_resolution(
    fake_pem_pair, fake_smart_token_client_module: type[_FakeSmartTokenClient]
) -> None:
    # Assim como as demais opcoes de TlsSettings, a validacao do valor de
    # tls_protocol e adiada para a resolucao efetiva do ssl.SSLContext
    # (ver docstring do modulo) -- build() em si so guarda a configuracao.
    client = (
        SmartTokenClientBuilder()
        .client_id(CLIENT_ID)
        .token_endpoint(TOKEN_ENDPOINT)
        .signing_strategy(FakeSigningStrategy())
        .server_trust_anchor(fake_pem_pair["cert"])
        .tls_protocol("TLSv1.0")
        .build()
    )
    with pytest.raises(SmartTokenError, match="Protocolo TLS nao suportado"):
        client.tls_context_provider.ssl_context()


# ---------------------------------------------------------------------------
# signing_strategy() com PKCS#11 -- prova de conexao ponta a ponta.
#
# strategy_factory.from_pkcs11 (Task 7) nao tem metodo de conveniencia
# dedicado no builder (ver docstring do modulo);
# e usado via signing_strategy(strategy_factory.from_pkcs11(...)), o mesmo
# caminho de qualquer SigningStrategy customizada. Este teste roda contra um
# token SoftHSM2 real (nao mock), provando que o resultado de from_pkcs11 e
# aceito pelo builder de ponta a ponta.
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not softhsm2_available(), reason="SoftHSM2 nao disponivel no ambiente")
def test_signing_strategy_accepts_pkcs11_strategy_end_to_end(
    softhsm2_token,  # noqa: F811
    fake_smart_token_client_module: type[_FakeSmartTokenClient],
) -> None:
    pkcs11_strategy = strategy_factory.from_pkcs11(
        pkcs11_module_path=softhsm2_token["module_path"],
        token_label=softhsm2_token["token_label"],
        key_label=softhsm2_token["key_label"],
        user_pin=softhsm2_token["user_pin"],
        jwt_algorithm="RS256",
    )

    client = (
        SmartTokenClientBuilder()
        .client_id(CLIENT_ID)
        .token_endpoint(TOKEN_ENDPOINT)
        .signing_strategy(pkcs11_strategy)
        .tls_context_provider(FakeTlsContextProvider())
        .build()
    )

    assert isinstance(client.signing_strategy, Pkcs11SigningStrategy)
    assert client.signing_strategy.jwt_algorithm == "RS256"
    # A chave nunca sai do hardware -- prova indireta: assinar pelo objeto
    # que o builder efetivamente guardou funciona (delega ao token real).
    assert len(client.signing_strategy.sign(b"header.payload")) > 0


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

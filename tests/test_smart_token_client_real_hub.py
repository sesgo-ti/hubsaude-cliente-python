"""Testes contra um HubSaude *real* (nao o simulador), via mTLS de
verdade com certificado real de um estabelecimento.

Diferente de ``test_smart_token_client_integration.py`` (marker
``integration``, sobe o simulador local via subprocess), este modulo
fala com um servidor que voce nao controla -- por isso e' um marker
separado (``real_hub``), sempre opt-in, nunca disparado por
`tox -e integration` nem por CI. Roda so com:

    pytest -m real_hub -v

Pre-requisitos (senao os testes sao SKIPPED, nao falham):

- ``HUBSAUDE_REAL_CLIENT_ID``       -- client_id cadastrado no hub
- ``HUBSAUDE_REAL_KEY_PATH``        -- caminho da chave privada (PEM)
- ``HUBSAUDE_REAL_CERT_PATH``       -- caminho do certificado (PEM)
- ``HUBSAUDE_REAL_FHIR_BASE``       -- opcional; default = homolog SES-GO
- ``HUBSAUDE_REAL_IG`` / ``HUBSAUDE_REAL_IG_VERSAO`` -- opcional (hub_ctx)
- ``HUBSAUDE_REAL_SCOPE``           -- opcional; default = sem scope

O que isto valida que o simulador sozinho nao garante: que o hub real
aceita o client_assertion/handshake mTLS produzidos pelo caminho de
producao da lib (nao uma reimplementacao), e devolve uma resposta que
``response_guard``/``client.py`` conseguem processar de ponta a ponta.
"""

from __future__ import annotations

import os

import pytest

from hubsaude_client.builder import SmartTokenClientBuilder
from hubsaude_client.exceptions import SmartTokenError

_DEFAULT_FHIR_BASE = "https://hub-homolog.saude.go.gov.br/"

_REQUIRED_ENV = ("HUBSAUDE_REAL_CLIENT_ID", "HUBSAUDE_REAL_KEY_PATH", "HUBSAUDE_REAL_CERT_PATH")

pytestmark = [
    pytest.mark.real_hub,
    pytest.mark.skipif(
        any(not os.environ.get(name) for name in _REQUIRED_ENV),
        reason=(
            "HubSaude real indisponivel neste ambiente: defina "
            f"{', '.join(_REQUIRED_ENV)} (e opcionalmente HUBSAUDE_REAL_FHIR_BASE/"
            "HUBSAUDE_REAL_IG/HUBSAUDE_REAL_IG_VERSAO/HUBSAUDE_REAL_SCOPE)."
        ),
    ),
]


@pytest.fixture
def real_client():
    builder = (
        SmartTokenClientBuilder()
        .client_id(os.environ["HUBSAUDE_REAL_CLIENT_ID"])
        .fhir_base(os.environ.get("HUBSAUDE_REAL_FHIR_BASE", _DEFAULT_FHIR_BASE))
        .private_key_pem(os.environ["HUBSAUDE_REAL_KEY_PATH"])
        .certificate_pem(os.environ["HUBSAUDE_REAL_CERT_PATH"])
        # hub-homolog.saude.go.gov.br nao fala TLS 1.3 (handshake_failure
        # confirmado via openssl s_client puro, sem lib nenhuma no meio) --
        # default TLSv1.2 aqui, mas ainda configuravel via env var caso
        # outro ambiente real precise de 1.3.
        .tls_protocol(os.environ.get("HUBSAUDE_REAL_TLS_PROTOCOL", "TLSv1.2"))
    )

    ig = os.environ.get("HUBSAUDE_REAL_IG")
    ig_versao = os.environ.get("HUBSAUDE_REAL_IG_VERSAO")
    if ig and ig_versao:
        builder = builder.hub_context(ig, ig_versao)

    with builder.build() as client:
        yield client


def test_discovery_resolves_https_token_endpoint(real_client) -> None:
    """RF-09: o token endpoint efetivo (via .well-known/smart-configuration
    contra o fhir_base real) deve existir e ser HTTPS -- confirma que a
    descoberta funciona contra o hub de verdade, nao so contra o mock do
    simulador."""
    endpoint = real_client.get_token_endpoint()

    assert endpoint
    assert endpoint.startswith("https://")


def test_obtain_token_against_real_hub(real_client) -> None:
    """Fim a fim contra o servidor real: client_assertion assinado +
    handshake mTLS real + POST real devem resultar num access_token
    utilizavel. Se o hub rejeitar o certificado de cliente ou a
    assertion, isto falha com SmartTokenError -- e' o sinal mais direto
    de que algo no par chave/certificado ou no cadastro do client_id
    esta errado, sem precisar decifrar log manualmente."""
    scope = os.environ.get("HUBSAUDE_REAL_SCOPE") or None

    try:
        resultado = real_client.obtain_token_response(scope=scope)
    except SmartTokenError as exc:
        pytest.fail(f"obtain_token_response falhou contra o hub real: {exc}")

    assert resultado.access_token
    assert resultado.expires_in > 0
    # veio de rede (nao de cache), entao o corpo cru deve estar presente
    assert resultado.raw is not None
    assert "access_token" in resultado.raw


def test_second_call_same_scope_is_served_from_cache(real_client) -> None:
    """RF-04: uma segunda chamada para o mesmo scope, dentro da validade,
    deve vir do cache -- sem novo round-trip ao servidor. Como o cache
    nao retem o corpo cru (ver TokenResult.raw), isto se observa por
    ``raw`` vir None na segunda chamada."""
    scope = os.environ.get("HUBSAUDE_REAL_SCOPE") or None

    primeira = real_client.obtain_token_response(scope=scope)
    segunda = real_client.obtain_token_response(scope=scope)

    assert segunda.access_token == primeira.access_token
    assert segunda.raw is None, "esperava hit de cache (raw=None) na segunda chamada"


def test_invalidate_cache_forces_new_network_round_trip(real_client) -> None:
    """Depois de invalidate_cache, a proxima chamada deve ir a rede de
    novo (raw preenchido), confirmando que a invalidacao realmente
    limpa a entrada -- e nao so' localmente, contra o comportamento
    real do authorization server."""
    scope = os.environ.get("HUBSAUDE_REAL_SCOPE") or None

    real_client.obtain_token_response(scope=scope)
    real_client.invalidate_cache(scope=scope)
    resultado = real_client.obtain_token_response(scope=scope)

    assert resultado.raw is not None, "esperava ida a rede apos invalidate_cache (raw preenchido)"

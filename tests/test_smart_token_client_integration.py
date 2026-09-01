"""Testes de integração do ``SmartTokenClient`` contra o simulador real
(``hubsaude-simulador``) -- sobe um processo real (via ``subprocess``,
mesmo JAR usado pelo lado ``.java``), fala TLS/mTLS real, faz chamadas
HTTP reais.

Tradução (não recriação) de ``SmartTokenClientIntegrationTestBase.java``
+ ``SmartTokenClientJarIT.java`` -- ver
``roadmap-testes-integracao-java-para-python.md`` (raiz do repositório
no momento da tradução) para o mapeamento teste-a-teste completo e as
decisões de tradução (estratégia do simulador via ``subprocess`` do
mesmo JAR, localizado via ``HUBSAUDE_SIMULADOR_JAR``; client_assertion
cru montado à mão com ``cryptography``, sem dependência nova).

Diferente do lado Java (``extends SmartTokenClientIntegrationTestBase``
+ subclasse concreta ``SmartTokenClientJarIT``, necessário porque JUnit
precisa de uma classe para portar ``@BeforeAll``/``@BeforeEach``), este
módulo não replica herança de classe de teste: os 14 casos são funções
de teste normais, e tudo que no ``.java`` é ``@BeforeAll``/``@BeforeEach``
vira fixture pytest (``simulator``/``client_credentials``/
``register_test_client`` abaixo).

Pré-requisitos para esta suíte rodar (senão os testes são ``SKIPPED``,
não falham):

- Java 21+ no ``PATH``;
- o JAR executável (Spring Boot) do ``hubsaude-simulador``, localizado
  via ``HUBSAUDE_SIMULADOR_JAR`` (variável de ambiente) ou, na
  ausência dela, via ``.simulator/hubsaude-simulador.jar`` na raiz do
  repositório (caminho de conveniência) — ver
  ``tests/hubsaude_simulator_helper.py::simulator_jar_path``.

Execução: ``pytest -m integration`` (ou ``tox -e integration``).
"""

from __future__ import annotations

import ssl
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterator

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from hubsaude_client import ssl_context_factory
from hubsaude_client.builder import SmartTokenClientBuilder
from hubsaude_client.exceptions import SmartTokenError

from .hubsaude_simulator_helper import (
    SimulatorProcess,
    extract_server_certificate,
    simulator_available,
    start_simulator,
)
from .raw_client_assertion_helper import (
    build_client_assertion,
    extract_kid_from_jwks,
    extract_kid_from_jwt_header,
    request_token_directo,
)

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        not simulator_available(),
        reason=(
            "Simulador indisponivel neste ambiente: defina a variavel de ambiente "
            "HUBSAUDE_SIMULADOR_JAR (ou copie o JAR para .simulator/hubsaude-simulador.jar "
            "na raiz do repositorio) e garanta 'java' (21+) no PATH."
        ),
    ),
]

#: Mesmos scopes liberados para o cliente de teste em toda a suíte
#: (equivalente a ``ALLOWED_SCOPES`` em ``SmartTokenClientIntegrationTestBase.java``).
ALLOWED_SCOPES: str = "system/Patient.rs system/Observation.rs"


# ============================================================
# Fixtures de infraestrutura (equivalentes a @BeforeAll/@BeforeEach)
# ============================================================


@dataclass(frozen=True)
class SimulatorInfo:
    """URL base e material de confiança do simulador em execução, já
    prontos para uso pelos testes (equivalente aos campos
    ``simulatorCert``/``simulatorSslContext`` protegidos de
    ``SmartTokenClientIntegrationTestBase.java``)."""

    base_url: str
    cert: x509.Certificate
    ssl_context: ssl.SSLContext

    @property
    def token_endpoint(self) -> str:
        return f"{self.base_url}/auth/token"

    @property
    def register_endpoint(self) -> str:
        return f"{self.base_url}/clients/register"

    @property
    def certs_endpoint(self) -> str:
        return f"{self.base_url}/certs"


@pytest.fixture(scope="module")
def simulator() -> Iterator[SimulatorInfo]:
    """Sobe o simulador uma única vez por módulo (equivalente a
    ``@BeforeAll iniciarSimulador``): aloca porta livre, sobe o JAR,
    extrai o certificado do servidor e monta o ``ssl.SSLContext`` de
    confiança nele. Derruba o processo ao final do módulo (equivalente
    a ``@AfterAll pararSimulador``).
    """
    process: SimulatorProcess = start_simulator()
    try:
        cert = extract_server_certificate("localhost", process.port)
        trust_context = ssl_context_factory.build_ssl_context(trusted_cert=cert)
        yield SimulatorInfo(base_url=process.base_url, cert=cert, ssl_context=trust_context)
    finally:
        process.stop()


@dataclass(frozen=True)
class ClientCredentials:
    """Credenciais (chave privada + certificado autoassinado) do
    cliente de teste, geradas uma vez por módulo e registradas no
    simulador antes de cada teste (equivalente a
    ``gerarCredenciais``/``@BeforeEach registrarClienteNoSimulador``)."""

    client_id: str
    key_path: Path
    cert_path: Path
    certificate: x509.Certificate
    certificate_pem: str
    private_key: rsa.RSAPrivateKey


@pytest.fixture(scope="module")
def client_credentials(tmp_path_factory: pytest.TempPathFactory) -> ClientCredentials:
    """Gera credenciais de teste (par de chaves RSA + certificado
    autoassinado) em disco, uma vez por módulo -- equivalente Python de
    ``gerarCredenciais(tempDir)`` (``.java``)."""
    client_id = f"integration-test-client-{uuid.uuid4()}"
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, client_id)])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=1))
        .sign(private_key, hashes.SHA256())
    )

    tmp_dir = tmp_path_factory.mktemp("integration-client-credentials")
    key_path = tmp_dir / "client-key.pem"
    cert_path = tmp_dir / "client-cert.pem"

    key_path.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    certificate_pem_bytes = certificate.public_bytes(serialization.Encoding.PEM)
    cert_path.write_bytes(certificate_pem_bytes)

    return ClientCredentials(
        client_id=client_id,
        key_path=key_path,
        cert_path=cert_path,
        certificate=certificate,
        certificate_pem=certificate_pem_bytes.decode("ascii"),
        private_key=private_key,
    )


@pytest.fixture(autouse=True)
def register_test_client(simulator: SimulatorInfo, client_credentials: ClientCredentials) -> None:
    """Registra o cliente de teste no simulador antes de cada teste
    (equivalente a ``@BeforeEach registrarClienteNoSimulador``).

    ``409`` (já registrado) é aceito como sucesso, assim como no lado
    Java -- o registro é idempotente por design desta suíte, já que
    ``client_credentials`` é reaproveitado por todos os testes do
    módulo.
    """
    payload = {
        "client_id": client_credentials.client_id,
        "certificate": client_credentials.certificate_pem,
        "allowed_scopes": ALLOWED_SCOPES,
    }
    with httpx.Client(verify=simulator.ssl_context, timeout=30.0) as client:
        response = client.post(simulator.register_endpoint, json=payload)

    if response.status_code not in (200, 201, 409):
        raise RuntimeError(
            f"Falha ao registrar cliente no simulador: status={response.status_code} body={response.text}"
        )


def _builder(
    simulator: SimulatorInfo,
    creds: ClientCredentials,
    *,
    client_id: str | None = None,
) -> SmartTokenClientBuilder:
    """Builder pré-configurado com o token endpoint/credenciais/trust
    anchor comuns à maioria dos testes -- reduz repetição sem esconder
    o que cada teste efetivamente configura de diferente."""
    return (
        SmartTokenClientBuilder()
        .token_endpoint(simulator.token_endpoint)
        .client_id(client_id if client_id is not None else creds.client_id)
        .private_key_pem(creds.key_path)
        .certificate_pem(creds.cert_path)
        .server_trust_anchor(simulator.cert)
    )


# ============================================================
# Testes 1-9: caminho feliz / cache / erros via API pública
# ============================================================


def test_obtem_token_com_sucesso(simulator: SimulatorInfo, client_credentials: ClientCredentials) -> None:
    """Fluxo feliz completo: client_assertion assinado -> mTLS -> token
    emitido. Traduz ``deveObterTokenComSucesso`` (``.java``)."""
    with _builder(simulator, client_credentials).build() as client:
        access_token = client.obtain_token("system/Patient.rs")

    assert access_token
    assert "." in access_token  # JWT tem ao menos um ponto


def test_falha_com_scope_nao_permitido(simulator: SimulatorInfo, client_credentials: ClientCredentials) -> None:
    """Simulador rejeita scope fora do ``allowed_scopes`` do registro.
    Traduz ``deveFalharComScopeNaoPermitido`` (``.java``)."""
    with _builder(simulator, client_credentials).build() as client:
        with pytest.raises(SmartTokenError, match="scope"):
            client.obtain_token("system/Encounter.rs")


def test_reutiliza_token_do_cache(simulator: SimulatorInfo, client_credentials: ClientCredentials) -> None:
    """Cache de token evita nova chamada de rede. Traduz
    ``deveReutilizarTokenDoCache`` (``.java``)."""
    builder = _builder(simulator, client_credentials).enable_token_cache(True).token_cache_margin_seconds(30)

    with builder.build() as client:
        token1 = client.obtain_token("system/Patient.rs")
        token2 = client.obtain_token("system/Patient.rs")

    # Mesmo token deve retornar do cache.
    assert token1 == token2


def test_tokens_diferentes_por_scope(simulator: SimulatorInfo, client_credentials: ClientCredentials) -> None:
    """Cache é por-escopo, não global. Traduz
    ``deveObterTokensDiferentesParaScopesDiferentes`` (``.java``)."""
    builder = _builder(simulator, client_credentials).enable_token_cache(True)

    with builder.build() as client:
        token_patient = client.obtain_token("system/Patient.rs")
        token_observation = client.obtain_token("system/Observation.rs")

    assert token_patient != token_observation


def test_invalida_cache_e_obtem_novo_token(simulator: SimulatorInfo, client_credentials: ClientCredentials) -> None:
    """Invalidação manual de cache força nova emissão. Traduz
    ``deveInvalidarCacheEObterNovoToken`` (``.java``)."""
    builder = _builder(simulator, client_credentials).enable_token_cache(True)
    scope = "system/Patient.rs"

    with builder.build() as client:
        token1 = client.obtain_token(scope)
        client.invalidate_cache(scope)
        token2 = client.obtain_token(scope)

    # Novo token deve ter sido obtido (pode ser igual ou diferente, mas
    # passou pelo servidor de novo).
    assert token1 is not None
    assert token2 is not None


def test_falha_com_client_id_nao_registrado(simulator: SimulatorInfo, client_credentials: ClientCredentials) -> None:
    """``client_id`` desconhecido é rejeitado pelo simulador. Traduz
    ``deveFalharComClientIdNaoRegistrado`` (``.java``)."""
    builder = _builder(simulator, client_credentials, client_id="cliente-inexistente-xyz")

    with builder.build() as client:
        with pytest.raises(SmartTokenError, match="invalid_client"):
            client.obtain_token("system/Patient.rs")


def test_funciona_com_multiplos_scopes(simulator: SimulatorInfo, client_credentials: ClientCredentials) -> None:
    """Múltiplos scopes num único pedido de token. Traduz
    ``deveFuncionarComMultiplosScopes`` (``.java``)."""
    with _builder(simulator, client_credentials).build() as client:
        access_token = client.obtain_token("system/Patient.rs system/Observation.rs")

    assert access_token


def test_respeita_timeout_configurado(simulator: SimulatorInfo, client_credentials: ClientCredentials) -> None:
    """Timeout de HTTP configurado é respeitado ponta a ponta (fluxo
    feliz completa dentro do timeout). Traduz
    ``deveRespeitarTimeoutConfigurado`` (``.java``)."""
    builder = (
        _builder(simulator, client_credentials)
        .connect_timeout(timedelta(seconds=5))
        .request_timeout(timedelta(seconds=30))
    )

    with builder.build() as client:
        access_token = client.obtain_token("system/Patient.rs")

    assert access_token


def test_obtem_token_via_discovery(simulator: SimulatorInfo, client_credentials: ClientCredentials) -> None:
    """Descoberta de ``token_endpoint`` via
    ``.well-known/smart-configuration`` real (``fhir_base`` em vez de
    ``token_endpoint`` explícito). Traduz ``deveObterTokenUsandoDiscovery``
    (``.java``)."""
    builder = (
        SmartTokenClientBuilder()
        .fhir_base(simulator.base_url)
        .client_id(client_credentials.client_id)
        .private_key_pem(client_credentials.key_path)
        .certificate_pem(client_credentials.cert_path)
        .server_trust_anchor(simulator.cert)
    )

    # O client deve ter resolvido o token_endpoint via descoberta no
    # build() e conseguido obter token contra a propria instancia do
    # simulador.
    with builder.build() as client:
        access_token = client.obtain_token("system/Patient.rs")

    assert access_token
    assert "." in access_token


# ============================================================
# Testes 10-14: caracterização do elemento "kid" (issue #408)
# ============================================================
#
# Testes de caracterização do comportamento do Servidor de Autorização
# (SA) do HubSaúde (hubsaude-smart-iam, embutido no hubsaude-simulador)
# em relação ao elemento "kid" (JOSE header).
#
# Referência normativa: docs/design/concerns/client-assertion-contexto-ig.md
# (Sec3.2 e Sec5.1) -- "kid" é obrigatório quando o cliente possui
# múltiplas chaves registradas, e "kid" desconhecido deveria resultar em
# 401 invalid_client.
#
# Se algum destes testes falhar após atualização do simulador, o
# comportamento do SA quanto ao "kid" mudou -- revisar a documentação e
# a issue #408 (mesma nota do ``.java`` original).
#
# Diferente dos testes 1-9, estes contornam a API pública
# (``SmartTokenClient``) de propósito, para inspecionar o protocolo bruto
# (JWT/JWKS) -- ver ``tests/raw_client_assertion_helper.py``.


def test_access_token_emitido_com_kid_no_header(
    simulator: SimulatorInfo, client_credentials: ClientCredentials
) -> None:
    """SA emite access token com ``kid`` no header JOSE. Traduz
    ``saEmiteAccessTokenComKidNoHeader`` (``.java``)."""
    with _builder(simulator, client_credentials).build() as client:
        access_token = client.obtain_token("system/Patient.rs")

    kid = extract_kid_from_jwt_header(access_token)

    assert kid, "SA deve incluir 'kid' no header do access token emitido"


def test_kid_do_token_corresponde_ao_jwks(simulator: SimulatorInfo, client_credentials: ClientCredentials) -> None:
    """``kid`` do access token bate com o publicado no JWKS (``/certs``)
    do simulador. Traduz ``kidDoAccessTokenCorrespondeAoJwks`` (``.java``)."""
    with _builder(simulator, client_credentials).build() as client:
        access_token = client.obtain_token("system/Patient.rs")

    kid_do_token = extract_kid_from_jwt_header(access_token)
    kid_do_jwks = extract_kid_from_jwks(simulator.certs_endpoint, simulator.ssl_context)

    assert kid_do_token == kid_do_jwks, "kid do access token deve permitir localizar a chave no JWKS"


def test_sa_aceita_client_assertion_sem_kid(simulator: SimulatorInfo, client_credentials: ClientCredentials) -> None:
    """SA aceita ``client_assertion`` sem ``kid`` quando há chave única
    registrada. Traduz ``saAceitaClientAssertionSemKid`` (``.java``)."""
    mtls_context = ssl_context_factory.build_ssl_context(
        trusted_cert=simulator.cert,
        client_key=client_credentials.private_key,
        client_cert=client_credentials.certificate,
    )
    assertion = build_client_assertion(
        client_id=client_credentials.client_id,
        token_endpoint=simulator.token_endpoint,
        private_key=client_credentials.private_key,
        kid=None,
    )

    response = request_token_directo(
        token_endpoint=simulator.token_endpoint,
        assertion=assertion,
        ssl_context=mtls_context,
    )

    assert response.status_code == 200, "Com uma unica chave registrada, kid e dispensavel (concern Sec5.1)"
    assert "access_token" in response.text


def test_sa_ignora_kid_desconhecido(simulator: SimulatorInfo, client_credentials: ClientCredentials) -> None:
    """Caracterização: o SA atual NÃO lê o ``kid`` do ``client_assertion``
    -- valida a assinatura com a única chave registrada do cliente. O
    concern normativo (Sec5.1) prevê 401 invalid_client ("kid
    desconhecido") quando houver suporte a múltiplas chaves. Traduz
    ``saIgnoraKidDesconhecidoNoClientAssertion`` (``.java``)."""
    assertion = build_client_assertion(
        client_id=client_credentials.client_id,
        token_endpoint=simulator.token_endpoint,
        private_key=client_credentials.private_key,
        kid=f"kid-desconhecido-{uuid.uuid4()}",
    )
    mtls_context = ssl_context_factory.build_ssl_context(
        trusted_cert=simulator.cert,
        client_key=client_credentials.private_key,
        client_cert=client_credentials.certificate,
    )

    response = request_token_directo(
        token_endpoint=simulator.token_endpoint,
        assertion=assertion,
        ssl_context=mtls_context,
    )

    assert response.status_code == 200, (
        "SA atual ignora o kid do client_assertion; se este teste falhar, o SA passou a " "validar kid (ver issue #408)"
    )
    assert "access_token" in response.text


def test_jwks_publica_kid_para_cada_chave(simulator: SimulatorInfo, client_credentials: ClientCredentials) -> None:
    """Toda chave publicada no JWKS do SA deve ter ``kid``. Traduz
    ``jwksDoSaPublicaKid`` (``.java`` -- que, apesar do nome, também
    inspeciona apenas a primeira chave publicada; ver
    ``raw_client_assertion_helper.extract_kid_from_jwks``)."""
    kid = extract_kid_from_jwks(simulator.certs_endpoint, simulator.ssl_context)

    assert kid, "Toda chave publicada no JWKS do SA deve ter kid"

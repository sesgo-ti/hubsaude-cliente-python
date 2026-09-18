"""Builder público da lib: ``SmartTokenClientBuilder`` (SMART Backend
Services, RF-17/RF-18).

A API pública mais visível da biblioteca, responsável por validar a
configuração *fail-fast* na construção e produzir um ``SmartTokenClient``
pronto para uso.

Decisão de design: optou-se por um **builder mutável com métodos encadeáveis**
(``self`` retornado a cada chamada) em vez de
``@dataclass`` + ``build()`` sobre campos públicos. Motivo: a classe reúne
mais de uma dezena de parâmetros opcionais com validação cruzada (ex.:
``token_endpoint``/``fhir_base`` mutuamente exclusivos, ``hub_context``
exigindo ``ig``/``versão`` juntos) — um builder fluente deixa a ordem de
chamadas irrelevante e a intenção de cada parâmetro explícita no ponto de
uso, o que uma dataclass com dezenas de campos posicionais/kwargs não
oferece com a mesma clareza. O builder em si **não precisa ser
thread-safe**: construção e passo único no bootstrap da aplicação
integradora (quem precisa ser thread-safe e o ``SmartTokenClient``
retornado — responsabilidade de ``client.py``).

Métodos de conveniência para as fontes de credencial mais comuns
(carga de PEM, PKCS#12, trust anchor) ja estão todos
ligados nesta base de código. ``private_key_pem()`` delega a
``strategy_factory.from_pem_file``/``SigningSettings``;
``certificate_pem()`` e ``server_trust_anchor()`` delegam a
``pem_loader``/``TlsSettings`` (``ssl_context_factory.py``);
``client_key_store()`` delega a
``strategy_factory.load_pkcs12_key_and_certificate`` para prover, de um
único bundle PKCS#12, tanto a estratégia de assinatura quanto o
certificado de cliente para mTLS. Em todos os casos a resolução efetiva e
adiada para :meth:`SmartTokenClientBuilder.build` -- não acontece na
própria chamada do método de conveniência (ver docstring de cada um). O
builder continua aceitando, como via alternativa/escape hatch, instâncias
que satisfazem diretamente os Protocols de ``ports.py``
(``SigningStrategy``, ``TlsContextProvider``) via :meth:`signing_strategy`
e :meth:`tls_context_provider` -- útil quando a fonte de credenciais não
se encaixa nos atalhos acima (ex.: cofre de segredos remoto).

PKCS#11/HSM (``strategy_factory.from_pkcs11``) já está disponível
mas **não tem um método de conveniência dedicado no builder** -- a
configuração (módulo, token, PIN) não tem um equivalente natural de
"caminho de arquivo" como os demais atalhos, então o uso e via
``.signing_strategy(...)`` com a factory, ja funcional hoje:

    SmartTokenClientBuilder()
        .signing_strategy(strategy_factory.from_pkcs11(
            pkcs11_module_path=..., token_label=..., key_label=..., user_pin=...,
        ))
        ...

    SmartTokenClient(
        client_id: str,
        token_endpoint: str | None,      # mutuamente exclusivo c/ fhir_base
        fhir_base: str | None,           # mutuamente exclusivo c/ token_endpoint
        signing_strategy: SigningStrategy,
        tls_context_provider: TlsContextProvider,
        fault_tolerance: FaultToleranceConfig,
        token_cache: TokenCacheStrategy,
        jwt_algorithm: str,              # ja normalizado (uppercase) e validado
        key_id: str | None,
        hub_context: HubContext | None,
    )

Quando ``fhir_base`` e informado (em vez de ``token_endpoint``), a
resolução via ``SmartConfigurationDiscovery`` (RF-09) **não** acontece
aqui: RF-09 item 5 exige que ela ocorra uma única vez, na construção do
cliente, usando a mesma configuração TLS/mTLS e os mesmos timeouts do
cliente principal — como e ``client.py`` quem monta o
``httpx.Client`` interno a partir de ``tls_context_provider``,
é ele quem deve, no seu ``__init__``, invocar
``SmartConfigurationDiscovery`` com esse mesmo ``httpx.Client`` quando
``fhir_base`` estiver presente. Este builder só valida eagerly o esquema
(``https``) da URL base fornecida; o ``token_endpoint`` efetivamente
resolvido via descoberta não é revalidado aqui.
"""

from __future__ import annotations

import re
import ssl
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from typing import TYPE_CHECKING

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes

from hubsaude_client import algorithms, key_certificate_consistency, pem_loader, strategy_factory
from hubsaude_client._log import get_logger
from hubsaude_client.defaults import (
    DEFAULT_ASSERTION_TTL_SECONDS,
    DEFAULT_CONNECT_TIMEOUT_SECONDS,
    DEFAULT_JWT_ALGORITHM,
    DEFAULT_MAX_RETRIES,
    DEFAULT_REQUEST_TIMEOUT_SECONDS,
    DEFAULT_TLS_PROTOCOL,
    DEFAULT_TOKEN_CACHE_MARGIN_SECONDS,
    DEFAULT_TOKEN_CACHE_MAX_ENTRIES,
)
from hubsaude_client.exceptions import SmartTokenError
from hubsaude_client.fault_tolerance import FaultToleranceConfig
from hubsaude_client.ports import SigningStrategy, TlsContextProvider
from hubsaude_client.settings import SigningSettings
from hubsaude_client.tls_settings import TlsSettings
from hubsaude_client.token_cache import TokenCacheStrategy
from hubsaude_client.url_validation import require_https_scheme

if TYPE_CHECKING:
    # Só resolvido por mypy/type checkers -- não importar em runtime aqui.
    #
    # client.py importa HubContext deste módulo (builder.py) sob o
    # próprio TYPE_CHECKING dele -- um import em runtime nos dois
    # sentidos criaria um ciclo real (builder.py -> client.py ->
    # builder.py). Por isso este import fica restrito a type checking, e
    # o import em runtime de SmartTokenClient (usado em build(), abaixo)
    # e tardio -- dentro do método, não no topo do módulo.
    from hubsaude_client.client import SmartTokenClient

#: TTL RECOMENDADO (RF-01 item 4, "DEVERIA"): o servidor rejeita
#: exp > iat + 300s. Valores acima disso não são rejeitados por este
#: builder (a regra é SHOULD, não MUST) -- apenas logados como aviso.
_RECOMMENDED_MAX_ASSERTION_TTL_SECONDS = 300

#: Formato exigido para o alias de Guia de Implementação em hub_context
#: (client-assertion-contexto-ig.md Sec3.4, RF-01 item 3).
#:
#: Âncora de fim em ``\Z`` (fim absoluto da string), NÃO ``$`` -- no módulo
#: ``re`` do Python, ``$`` casa também imediatamente antes de uma única
#: quebra de linha final, o que aceitaria incorretamente um valor como
#: ``"meu-ig\n"``.
_HUB_CONTEXT_IG_PATTERN = re.compile(r"^[a-z][a-z0-9-]{1,30}\Z")

#: Formato exigido para a versão em hub_context: SemVer completo
#: MAJOR.MINOR.PATCH, sem pre-release/build metadata (RF-01 item 3). Mesma
#: nota sobre ``\Z`` vs ``$`` do ``_HUB_CONTEXT_IG_PATTERN`` acima.
_HUB_CONTEXT_VERSAO_PATTERN = re.compile(r"^\d+\.\d+\.\d+\Z")

#: Logger compartilhado com o restante da lib (ver _log.py).
_LOG = get_logger()


@dataclass(frozen=True)
class HubContext:
    """Contexto de Guia de Implementação (IG) pretendido para o
    ``client_assertion`` (claim ``hub_ctx``, RF-01 item 3,
    ``client-assertion-contexto-ig.md`` Sec3.4).

    Instâncias só são construídas por :meth:`SmartTokenClientBuilder.hub_context`
    após validação de formato -- ``ig``/``versão`` aqui ja estão validados.

    Attributes:
        ig: alias do Guia de Implementação (``[a-z][a-z0-9-]{1,30}``).
        versão: versão SemVer completa (``MAJOR.MINOR.PATCH``, sem
            pre-release).
    """

    ig: str
    versao: str


class _TlsSettingsProvider:
    """Adapta TlsSettings (Task 8) ao Protocol TlsContextProvider exigido
    pelo builder -- os nomes de método divergem de propósito
    (``TlsSettings.resolve_ssl_context()`` vs
    ``TlsContextProvider.ssl_context()``, ver ``ports.py``).
    """

    __slots__ = ("_settings",)

    def __init__(self, settings: TlsSettings) -> None:
        self._settings = settings

    def ssl_context(self) -> ssl.SSLContext:
        return self._settings.resolve_ssl_context()


class SmartTokenClientBuilder:
    """Builder fluente e público do ``SmartTokenClient``.

    Instâncias são de uso único e descartável: configure via os métodos
    encadeáveis abaixo e chame :meth:`build` uma vez. Não e thread-safe
    (ver nota de design no docstring do módulo) -- não compartilhe uma
    instância de builder entre threads.
    """

    __slots__ = (
        "_client_id",
        "_token_endpoint",
        "_fhir_base",
        "_signing_strategy",
        "_private_key_pem_path",
        "_private_key_pem_password",
        "_tls_context_provider",
        "_jwt_algorithm",
        "_key_id",
        "_assertion_ttl_seconds",
        "_max_retries",
        "_connect_timeout",
        "_request_timeout",
        "_enable_token_cache",
        "_token_cache_margin_seconds",
        "_token_cache_max_entries",
        "_hub_context_ig",
        "_hub_context_versao",
        "_certificate_pem_path",
        "_client_key_store_path",
        "_client_key_store_password",
        "_server_trust_anchor_path",
        "_server_trust_anchor_cert",
        "_tls_protocol",
    )

    def __init__(self) -> None:
        """Cria um builder novo, com todos os padrões de ``defaults.py``."""
        self._client_id: str | None = None
        self._token_endpoint: str | None = None
        self._fhir_base: str | None = None
        self._signing_strategy: SigningStrategy | None = None
        self._private_key_pem_path: Path | None = None
        self._private_key_pem_password: bytearray | None = None
        self._tls_context_provider: TlsContextProvider | None = None
        self._jwt_algorithm: str = DEFAULT_JWT_ALGORITHM
        self._key_id: str | None = None
        self._assertion_ttl_seconds: int = DEFAULT_ASSERTION_TTL_SECONDS
        self._max_retries: int = DEFAULT_MAX_RETRIES
        self._connect_timeout: timedelta = timedelta(seconds=DEFAULT_CONNECT_TIMEOUT_SECONDS)
        self._request_timeout: timedelta = timedelta(seconds=DEFAULT_REQUEST_TIMEOUT_SECONDS)
        self._enable_token_cache: bool = True
        self._token_cache_margin_seconds: int = DEFAULT_TOKEN_CACHE_MARGIN_SECONDS
        self._token_cache_max_entries: int = DEFAULT_TOKEN_CACHE_MAX_ENTRIES
        self._hub_context_ig: str | None = None
        self._hub_context_versao: str | None = None
        self._certificate_pem_path: Path | None = None
        self._client_key_store_path: Path | None = None
        self._client_key_store_password: bytearray | None = None
        self._server_trust_anchor_path: Path | None = None
        self._server_trust_anchor_cert: x509.Certificate | None = None
        self._tls_protocol: str | None = None

    # ------------------------------------------------------------------
    # Métodos encadeáveis (fluent setters)
    # ------------------------------------------------------------------

    def client_id(self, client_id: str) -> SmartTokenClientBuilder:
        """Define o ``client_id`` emitido no credenciamento (obrigatório)."""
        self._client_id = client_id
        return self

    def token_endpoint(self, token_endpoint: str) -> SmartTokenClientBuilder:
        """Define o token endpoint explícito.

        Mutuamente exclusivo com :meth:`fhir_base` (RF-09 item 2) --
        exatamente um dos dois deve ser informado antes de :meth:`build`.
        """
        self._token_endpoint = token_endpoint
        return self

    def fhir_base(self, fhir_base: str) -> SmartTokenClientBuilder:
        """Define a URL base FHIR para descoberta via
        ``.well-known/smart-configuration`` (RF-09).

        Mutuamente exclusivo com :meth:`token_endpoint`. A resolução em si
        não acontece neste builder -- ver nota no docstring do módulo.
        """
        self._fhir_base = fhir_base
        return self

    def signing_strategy(self, signing_strategy: SigningStrategy) -> SmartTokenClientBuilder:
        """Define a estratégia de assinatura do ``client_assertion`` (obrigatório).

        Aceita qualquer implementação que satisfaça ``ports.SigningStrategy``
        -- em memória, PEM ja carregado por fora, HSM/PKCS#11 (via
        ``strategy_factory.from_pkcs11``), etc. Mutuamente exclusivo com
        :meth:`private_key_pem` -- exatamente um dos dois deve ser
        informado antes de :meth:`build`.
        """
        self._signing_strategy = signing_strategy
        return self

    def tls_context_provider(self, tls_context_provider: TlsContextProvider) -> SmartTokenClientBuilder:
        """Define o fornecedor de contexto TLS/mTLS (obrigatório).

        Aceita qualquer implementação que satisfaça
        ``ports.TlsContextProvider``. Mutuamente exclusivo com os métodos de
        conveniência ``certificate_pem``/``client_key_store``/
        ``server_trust_anchor`` -- se nenhum deles for usado, este método
        continua obrigatório.
        """
        self._tls_context_provider = tls_context_provider
        return self

    def jwt_algorithm(self, jwt_algorithm: str) -> SmartTokenClientBuilder:
        """Define o algoritmo JWT (``alg``). Padrão: ``RS384``.

        Aceita qualquer um dos 9 valores de ``algorithms.VALID_JWT_ALGORITHMS``,
        *case-insensitive* -- a normalização e validação final acontecem em
        :meth:`build`.
        """
        self._jwt_algorithm = jwt_algorithm
        return self

    def key_id(self, key_id: str) -> SmartTokenClientBuilder:
        """Define o ``kid`` (identificador de chave) incluído no header do JWT.

        RECOMENDADO quando a chave de assinatura tiver um identificador
        conhecido (ex.: publicado num JWKS); opcional.
        """
        self._key_id = key_id
        return self

    def assertion_ttl_seconds(self, seconds: int) -> SmartTokenClientBuilder:
        """Define o TTL do ``client_assertion``, em segundos. Padrão: 60s.

        Valores ``<= 0`` são normalizados para o padrão por
        ``FaultToleranceConfig`` (não por este método). Valores acima de
        300s são aceitos mas geram aviso em log em :meth:`build` -- o
        servidor rejeita ``exp`` maior que ``iat + 300`` (RF-01 item 4,
        regra "DEVERIA").
        """
        self._assertion_ttl_seconds = seconds
        return self

    def max_retries(self, max_retries: int) -> SmartTokenClientBuilder:
        """Define o número máximo de tentativas em falha transitória. Padrão: 3.

        Valores ``<= 0`` são normalizados para o padrão por
        ``FaultToleranceConfig``.
        """
        self._max_retries = max_retries
        return self

    def connect_timeout(self, timeout: timedelta) -> SmartTokenClientBuilder:
        """Define o timeout de conexão TCP. Padrão: 10s."""
        self._connect_timeout = timeout
        return self

    def request_timeout(self, timeout: timedelta) -> SmartTokenClientBuilder:
        """Define o timeout de requisição HTTP. Padrão: 30s."""
        self._request_timeout = timeout
        return self

    def enable_token_cache(self, enabled: bool) -> SmartTokenClientBuilder:
        """Habilita/desabilita o cache de tokens por scope. Padrão: habilitado."""
        self._enable_token_cache = enabled
        return self

    def token_cache_margin_seconds(self, seconds: int) -> SmartTokenClientBuilder:
        """Define a margem de renovação antecipada do cache. Padrão: 30s.

        Valores ``<= 0`` são normalizados para o padrão por
        ``FaultToleranceConfig`` -- e :meth:`build` garante que o mesmo
        valor ja normalizado (nunca o valor cru passado aqui) é o que
        chega ao cache de tokens efetivamente usado pelo cliente.
        """
        self._token_cache_margin_seconds = seconds
        return self

    def token_cache_max_entries(self, max_entries: int) -> SmartTokenClientBuilder:
        """Define o teto de scopes retidos no cache (janela LRU). Padrão: 1000.

        Deve ser positivo -- validado em :meth:`build` (RF-18).
        """
        self._token_cache_max_entries = max_entries
        return self

    def hub_context(self, ig: str, versao: str) -> SmartTokenClientBuilder:
        """Define o contexto de Guia de Implementação (claim ``hub_ctx``).

        Ambos os argumentos são obrigatórios juntos -- não há forma de
        limpar apenas um dos dois depois de configurado. Quando nenhuma
        chamada a este método e feita, o claim ``hub_ctx`` e omitido do
        JWT (RF-01 item 3), que e o padrão.

        Args:
            ig: alias do Guia de Implementação (``[a-z][a-z0-9-]{1,30}``).
            versão: versão SemVer completa (``MAJOR.MINOR.PATCH``).
        """
        self._hub_context_ig = ig
        self._hub_context_versao = versao
        return self

    # ------------------------------------------------------------------
    # Métodos de conveniência
    # ------------------------------------------------------------------

    def private_key_pem(self, path: Path | str, password: bytearray | None = None) -> SmartTokenClientBuilder:
        """Carrega a chave privada de assinatura a partir de um arquivo PEM.

        Atalho para ``strategy_factory.from_pem_file`` (detecção automática
        de formato -- PKCS#1, PKCS#8 cifrado ou não, OpenSSL tradicional
        cifrado -- RF-13) seguido de :meth:`signing_strategy`. Mutuamente
        exclusivo com :meth:`signing_strategy`.

        A resolução da chave é adiada para :meth:`build` (não acontece
        nesta chamada) -- por isso o algoritmo JWT usado é o configurado
        em :meth:`jwt_algorithm` no momento de :meth:`build`, não no
        momento desta chamada; a ordem entre as duas chamadas é
        irrelevante (ver nota de design no docstring do módulo).

        Args:
            path: caminho para o arquivo PEM da chave privada.
            password: senha para decriptar a chave (``None`` se não
                criptografada). E consumida: repassada a ``pem_loader``, que
                zera o array ao final de :meth:`build`. O chamador não deve
                reutiliza-la.

        Raises:
            SmartTokenError: em :meth:`build`, se o arquivo não existir, o
                formato for inválido, ou a senha for incorreta.
        """
        self._private_key_pem_path = Path(path)
        self._private_key_pem_password = password
        return self

    def certificate_pem(self, path: Path | str) -> SmartTokenClientBuilder:
        """Carrega o certificado de cliente (mTLS) a partir de um arquivo PEM.

        Só faz sentido combinado com :meth:`private_key_pem` -- e o mesmo par
        chave/certificado usado tanto para assinar o ``client_assertion``
        quanto para a apresentação do certificado de cliente no handshake TLS.
        A resolução (incluindo a verificação de consistência chave-certificado,
        RF-15, via ``key_certificate_consistency.verify_strategy``) e adiada
        para :meth:`build`.

        Args:
            path: caminho para o arquivo PEM do certificado.

        Raises:
            SmartTokenError: em :meth:`build`, se ``private_key_pem`` não tiver
                sido informado, se o certificado não puder ser carregado, ou se
                não corresponder a chave privada configurada.
        """
        self._certificate_pem_path = Path(path)
        return self

    def client_key_store(
        self, path: Path | str, password: bytearray, alias: str | None = None
    ) -> SmartTokenClientBuilder:
        """Carrega chave e certificado de cliente a partir de um bundle PKCS#12.

        Atalho para ``strategy_factory.load_pkcs12_key_and_certificate``: o
        mesmo bundle fornece tanto a estratégia de assinatura do
        ``client_assertion`` quanto o certificado de cliente para mTLS.
        Mutuamente exclusivo com :meth:`private_key_pem`/:meth:`signing_strategy`
        (fonte de assinatura) e com :meth:`certificate_pem` (ja fornece seu
        próprio certificado).

        Args:
            path: caminho para o arquivo PKCS#12 (``.p12``/``.pfx``).
            password: senha do bundle. E consumida: repassada a
                ``strategy_factory``, que zera o array ao final de
                :meth:`build` (RNF-03). O chamador não deve reutiliza-la.
            alias: aceito para manter a mesma assinatura de método entre as
                implementações do SDK; sem efeito aqui --
                ``cryptography.hazmat...pkcs12.load_key_and_certificates`` não
                indexa por alias (API de base da biblioteca, não escolha deste
                projeto -- ver docstring de ``strategy_factory``).

        Raises:
            SmartTokenError: em :meth:`build`, se a senha for incorreta, o
                arquivo for inválido, ou o bundle não contiver chave/certificado.
        """
        self._client_key_store_path = Path(path)
        self._client_key_store_password = password
        return self

    def server_trust_anchor(self, trust_anchor: Path | str | x509.Certificate) -> SmartTokenClientBuilder:
        """Define um trust anchor customizado (substitui o trust store padrão).

        Aceita um caminho de arquivo PEM ou um certificado ``x509.Certificate``
        ja em memória (ex: obtido dinamicamente em testes de integração),
        resolvido num único método via dispatch por tipo. Uso pretendido:
        homologação/simuladores locais, não produção (que deve confiar no
        trust store padrão do sistema).

        Args:
            trust_anchor: caminho do certificado PEM, ou o certificado ja
                carregado em memória.
        """
        if isinstance(trust_anchor, x509.Certificate):
            self._server_trust_anchor_cert = trust_anchor
        else:
            self._server_trust_anchor_path = Path(trust_anchor)
        return self

    def tls_protocol(self, tls_protocol: str) -> SmartTokenClientBuilder:
        """Sobrescreve a versão do protocolo TLS (padrão: ``TlsSettings``/"TLSv1.3").

        Efetivo apenas quando o contexto TLS e resolvido internamente pelos
        métodos de conveniência (``certificate_pem``/``client_key_store``/
        ``server_trust_anchor``, ou nenhum deles, usando o trust store
        padrão) -- sem efeito, e mutuamente exclusivo, com
        ``tls_context_provider()`` customizado (o contexto SSL, nesse caso,
        e responsabilidade inteira do provider informado).

        Args:
            tls_protocol: nome do protocolo aceito por
                ``ssl_context_factory.build_ssl_context`` (ex: "TLSv1.3",
                "TLSv1.2"); validado apenas em :meth:`build`.
        """
        self._tls_protocol = tls_protocol
        return self

    # ------------------------------------------------------------------
    # build()
    # ------------------------------------------------------------------

    def build(self) -> "SmartTokenClient":
        """Valida a configuração (fail-fast) e constrói o ``SmartTokenClient``.

        Ordem de validação: ``client_id`` -> ``signing_strategy``/
        ``private_key_pem``/``tls_context_provider`` -> exclusividade e
        esquema de ``token_endpoint``/``fhir_base`` -> ``jwt_algorithm`` ->
        timeouts -> ``token_cache_max_entries`` -> ``hub_context``. Nenhuma
        chamada de rede e feita aqui (a eventual descoberta via
        ``fhir_base`` acontece dentro de ``SmartTokenClient.__init__`` --
        ver nota no docstring do módulo).

        Returns:
            Um ``SmartTokenClient`` pronto para uso.

        Raises:
            SmartTokenError: se qualquer validação falhar.
        """
        client_id = _require_non_blank(self._client_id, "client_id")
        signing_strategy, client_key, client_cert_from_key_store = self._resolve_signing_material()
        tls_context_provider = self._resolve_tls_context_provider(
            signing_strategy, client_key, client_cert_from_key_store
        )
        self._validate_endpoint_config()
        resolved_algorithm = self._resolve_jwt_algorithm()
        self._validate_timeouts()
        self._validate_token_cache_max_entries()
        hub_context = self._build_hub_context()
        self._warn_if_ttl_exceeds_recommended()

        fault_tolerance = FaultToleranceConfig(
            connect_timeout=self._connect_timeout,
            request_timeout=self._request_timeout,
            assertion_ttl_seconds=self._assertion_ttl_seconds,
            token_cache_margin_seconds=self._token_cache_margin_seconds,
            max_retries=self._max_retries,
        )
        token_cache = TokenCacheStrategy(
            enabled=self._enable_token_cache,
            # Usa o valor ja normalizado por FaultToleranceConfig (nunca
            # self._token_cache_margin_seconds cru): TokenCacheStrategy não
            # normaliza internamente (ver docstring de seu __init__), então
            # repassar o valor cru aqui reintroduziria margens <= 0 vivas no
            # cache mesmo quando fault_tolerance ja caiu para o default --
            # os dois colaboradores devem enxergar exatamente a mesma margem
            # efetiva.
            margin_seconds=fault_tolerance.token_cache_margin_seconds,
            max_entries=self._token_cache_max_entries,
        )

        _LOG.debug(
            "Construindo SmartTokenClient para clientId=%s (token_endpoint=%s, fhir_base=%s)",
            client_id,
            self._token_endpoint,
            self._fhir_base,
        )

        # Import tardio (dentro do método, não no topo do módulo): evita o
        # ciclo real de import com client.py, que importa HubContext deste
        # módulo sob o próprio TYPE_CHECKING dele -- ver comentário junto
        # ao import sob TYPE_CHECKING no topo deste arquivo.
        from hubsaude_client.client import SmartTokenClient as _SmartTokenClient

        return _SmartTokenClient(
            client_id=client_id,
            token_endpoint=self._token_endpoint,
            fhir_base=self._fhir_base,
            signing_strategy=signing_strategy,
            tls_context_provider=tls_context_provider,
            fault_tolerance=fault_tolerance,
            token_cache=token_cache,
            jwt_algorithm=resolved_algorithm,
            key_id=_normalize_optional_str(self._key_id),
            hub_context=hub_context,
        )

    # ------------------------------------------------------------------
    # Validações internas
    # ------------------------------------------------------------------

    def _resolve_signing_material(self) -> tuple[SigningStrategy, PrivateKeyTypes | None, x509.Certificate | None]:
        """Resolve a estratégia de assinatura efetiva e, quando aplicável, o
        material reaproveitável para mTLS (chave/certificado carregados da
        mesma fonte).

        ``signing_strategy()``, ``private_key_pem()`` e ``client_key_store()``
        são mutuamente exclusivos entre si -- exatamente uma fonte de
        assinatura deve ser informada antes de :meth:`build`.

        Returns:
            A estratégia efetiva; a chave privada em memória reaproveitável
            para mTLS (``None`` quando a estratégia veio de HSM/cofre de
            segredos, que nunca expõe a chave); e o certificado de cliente
            ja resolvido quando a fonte foi ``client_key_store`` (``None``
            nos demais casos -- ``certificate_pem`` resolve o certificado
            separadamente em :meth:`_resolve_tls_context_provider`).
        """
        sources = (self._signing_strategy, self._private_key_pem_path, self._client_key_store_path)
        if sum(source is not None for source in sources) > 1:
            raise SmartTokenError(
                "signing_strategy, private_key_pem e client_key_store são mutuamente"
                " exclusivos; informe apenas um dos três"
            )

        if self._client_key_store_path is not None:
            # _client_key_store_password e sempre preenchida junto com
            # _client_key_store_path (as duas só são atribuídas juntas, em
            # client_key_store()) -- o None aqui e inalcançável na prática,
            # mas mypy não faz narrowing entre campos distintos; SmartTokenError
            # explícito narrowa o tipo para o restante do bloco.
            if self._client_key_store_password is None:
                raise SmartTokenError(  # pragma: no cover -- guarda defensiva inalcançável, ver comentário acima
                    "estado interno inconsistente: client_key_store_path definido sem client_key_store_password"
                )
            resolved_algorithm = algorithms.resolve(self._jwt_algorithm).jwt_algorithm
            client_key, client_cert = strategy_factory.load_pkcs12_key_and_certificate(
                self._client_key_store_path, self._client_key_store_password
            )
            strategy = strategy_factory.from_private_key(client_key, resolved_algorithm)
            return strategy, client_key, client_cert

        if self._private_key_pem_path is not None:
            # Normalizado aqui (mesma lógica de _resolve_jwt_algorithm) para que
            # strategy.jwt_algorithm coincida com o jwt_algorithm efetivo do
            # cliente, independente da caixa informada em jwt_algorithm().
            resolved_algorithm = algorithms.resolve(self._jwt_algorithm).jwt_algorithm
            resolved = SigningSettings(
                private_key_pem=self._private_key_pem_path,
                private_key_password=self._private_key_pem_password,
                jwt_algorithm=resolved_algorithm,
            ).resolve()
            return resolved.strategy, resolved.client_key, None

        return self._require_signing_strategy(), None, None

    def _resolve_tls_context_provider(
        self,
        signing_strategy: SigningStrategy,
        client_key: PrivateKeyTypes | None,
        client_cert_from_key_store: x509.Certificate | None,
    ) -> TlsContextProvider:
        """Resolve o fornecedor de contexto TLS/mTLS efetivo.

        ``tls_context_provider()`` e os métodos de conveniência
        (``certificate_pem``/``client_key_store``/``server_trust_anchor``)
        são mutuamente exclusivos entre si -- quando nenhum dos últimos e
        usado, ``tls_context_provider()`` continua obrigatório
        (comportamento inalterado).
        """
        convenience_used = (
            self._certificate_pem_path is not None
            or client_cert_from_key_store is not None
            or self._server_trust_anchor_path is not None
            or self._server_trust_anchor_cert is not None
            or self._tls_protocol is not None
        )
        if not convenience_used:
            return self._require_tls_context_provider()
        if self._tls_context_provider is not None:
            raise SmartTokenError(
                "tls_context_provider e os métodos de conveniência TLS"
                " (certificate_pem/client_key_store/server_trust_anchor) são"
                " mutuamente exclusivos; informe apenas uma forma"
            )

        client_certificate = client_cert_from_key_store
        if self._certificate_pem_path is not None:
            if client_cert_from_key_store is not None:
                raise SmartTokenError(
                    "certificate_pem e client_key_store são mutuamente exclusivos"
                    " (client_key_store ja fornece seu próprio certificado)"
                )
            if client_key is None:
                raise SmartTokenError(
                    "certificate_pem exige private_key_pem também (mTLS precisa da chave e do certificado do mesmo par)"
                )
            client_certificate = pem_loader.load_certificate(self._certificate_pem_path)
            # RF-15: confirma que a chave carregada por private_key_pem() de
            # fato corresponde a este certificado antes de aceitar a
            # configuração -- no-op silencioso para estratégias customizadas
            # (não PrivateKeySigningStrategy, ver key_certificate_consistency).
            key_certificate_consistency.verify_strategy(signing_strategy, client_certificate)

        settings = TlsSettings(
            client_certificate=client_certificate,
            client_private_key=client_key if client_certificate is not None else None,
            server_trust_anchor_path=self._server_trust_anchor_path,
            server_trust_anchor_cert=self._server_trust_anchor_cert,
            tls_protocol=self._tls_protocol if self._tls_protocol is not None else DEFAULT_TLS_PROTOCOL,
        )
        return _TlsSettingsProvider(settings)

    def _require_signing_strategy(self) -> SigningStrategy:
        if self._signing_strategy is None:
            raise SmartTokenError(
                "signing_strategy e obrigatório (client_credentials + private_key_jwt"
                " exige uma estratégia de assinatura do client_assertion, via"
                " signing_strategy() ou private_key_pem())"
            )
        if not isinstance(self._signing_strategy, SigningStrategy):
            raise SmartTokenError(
                "signing_strategy fornecido não satisfaz o protocolo"
                " ports.SigningStrategy (método sign(data: bytes) -> bytes)"
            )
        return self._signing_strategy

    def _require_tls_context_provider(self) -> TlsContextProvider:
        if self._tls_context_provider is None:
            raise SmartTokenError(
                "tls_context_provider e obrigatório (toda comunicação com o"
                " servidor de autorização e feita sobre TLS/mTLS)"
            )
        if not isinstance(self._tls_context_provider, TlsContextProvider):
            raise SmartTokenError(
                "tls_context_provider fornecido não satisfaz o protocolo"
                " ports.TlsContextProvider (método ssl_context() -> ssl.SSLContext)"
            )
        return self._tls_context_provider

    def _validate_endpoint_config(self) -> None:
        """Valida a exclusividade mútua e o esquema https de
        ``token_endpoint``/``fhir_base`` (RF-09 item 2, RF-18).
        """
        token_endpoint = _normalize_optional_str(self._token_endpoint)
        fhir_base = _normalize_optional_str(self._fhir_base)
        if token_endpoint is None and fhir_base is None:
            raise SmartTokenError("informe token_endpoint() ou fhir_base() -- exatamente um dos dois e obrigatório")
        if token_endpoint is not None and fhir_base is not None:
            raise SmartTokenError(
                "token_endpoint e fhir_base são mutuamente exclusivos (RF-09 item 2); informe apenas um dos dois"
            )
        if token_endpoint is not None:
            require_https_scheme(token_endpoint, "token_endpoint")
        elif fhir_base is not None:
            require_https_scheme(fhir_base, "fhir_base")
        else:
            # Inalcançável: os dois ifs acima ja garantem que exatamente um
            # dos dois está preenchido neste ponto. Sem "assert" (removido
            # em bytecode otimizado, ver B101) -- SmartTokenError explícito
            # também ajuda o narrowing de tipos do mypy no ramo anterior.
            raise SmartTokenError(  # pragma: no cover -- guarda defensiva inalcançável, ver comentário acima
                "estado inesperado: nem token_endpoint nem fhir_base preenchidos após validação de exclusividade mútua"
            )
        # Reatribui as versões normalizadas (strip aplicado), preservando o
        # contrato de que build() só consome valores ja normalizados.
        self._token_endpoint = token_endpoint
        self._fhir_base = fhir_base

    def _resolve_jwt_algorithm(self) -> str:
        """Valida e normaliza (uppercase) o algoritmo JWT configurado.

        Delega a validação propriamente dita para ``algorithms.resolve``,
        que ja lança ``SmartTokenError`` com a lista de algoritmos válidos
        quando o valor informado não e reconhecido (RF-16 item 2).
        """
        return algorithms.resolve(self._jwt_algorithm).jwt_algorithm

    def _validate_timeouts(self) -> None:
        """Rejeita timeouts nulos ou não positivos (RF-18)."""
        if self._connect_timeout is None or self._connect_timeout.total_seconds() <= 0:
            raise SmartTokenError(f"connect_timeout deve ser positivo, recebido: {self._connect_timeout!r}")
        if self._request_timeout is None or self._request_timeout.total_seconds() <= 0:
            raise SmartTokenError(f"request_timeout deve ser positivo, recebido: {self._request_timeout!r}")

    def _validate_token_cache_max_entries(self) -> None:
        """Rejeita ``token_cache_max_entries <= 0`` (RF-18).

        Validado aqui (com ``SmartTokenError``, o tipo de exceção público
        da lib) além de em ``TokenCacheStrategy.__init__`` (que lança
        ``ValueError``) -- defesa em profundidade; este builder e o ponto
        de entrada público e deve falhar com o tipo de exceção esperado
        pelos consumidores.
        """
        if self._token_cache_max_entries <= 0:
            raise SmartTokenError(
                f"token_cache_max_entries deve ser positivo, recebido: {self._token_cache_max_entries}"
            )

    def _build_hub_context(self) -> HubContext | None:
        """Valida e constrói o ``HubContext`` opcional (RF-01 item 3)."""
        ig = _normalize_optional_str(self._hub_context_ig)
        versao = _normalize_optional_str(self._hub_context_versao)
        if ig is None and versao is None:
            return None
        if ig is None or versao is None:
            raise SmartTokenError(
                "hub_context exige ig e versão juntos; informe os dois em uma única chamada a hub_context(ig, versão)"
            )
        if not _HUB_CONTEXT_IG_PATTERN.match(ig):
            raise SmartTokenError(f"hub_context: ig inválido ({ig!r}); deve seguir o padrão [a-z][a-z0-9-]{{1,30}}")
        if not _HUB_CONTEXT_VERSAO_PATTERN.match(versao):
            raise SmartTokenError(
                f"hub_context: versão inválida ({versao!r}); deve ser SemVer completo"
                " MAJOR.MINOR.PATCH, sem pre-release"
            )
        return HubContext(ig=ig, versao=versao)

    def _warn_if_ttl_exceeds_recommended(self) -> None:
        """Loga aviso (não bloqueia) quando o TTL excede o recomendado.

        RF-01 item 4 usa "DEVERIA" (SHOULD, RFC 2119) -- o servidor
        rejeita ``exp`` acima de ``iat + 300``, mas isso e responsabilidade
        do orquestrador (``client.py``) reportar como falha; aqui e só um
        aviso preventivo na construção.
        """
        if self._assertion_ttl_seconds > _RECOMMENDED_MAX_ASSERTION_TTL_SECONDS:
            _LOG.warning(
                "assertion_ttl_seconds=%s excede o recomendado de %ss (RF-01 item 4);"
                " o servidor de autorização pode rejeitar o client_assertion",
                self._assertion_ttl_seconds,
                _RECOMMENDED_MAX_ASSERTION_TTL_SECONDS,
            )


def _require_non_blank(value: str | None, field_name: str) -> str:
    """Exige uma string não nula e não vazia (após ``strip()``).

    Args:
        value: valor a validar.
        field_name: nome do campo, para a mensagem de erro.

    Returns:
        O valor com espaços laterais removidos.

    Raises:
        SmartTokenError: se ``value`` for ``None`` ou vazio após ``strip()``.
    """
    if value is None or not value.strip():
        raise SmartTokenError(f"{field_name} e obrigatório e não pode ser vazio")
    return value.strip()


def _normalize_optional_str(value: str | None) -> str | None:
    """Normaliza uma string opcional: ``strip()``; vazio/``None`` -> ``None``.

    Args:
        value: valor a normalizar.

    Returns:
        O valor sem espaços laterais, ou ``None`` quando ausente/vazio.
    """
    if value is None:
        return None
    stripped = value.strip()
    return stripped or None

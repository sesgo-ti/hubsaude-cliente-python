"""Builder publico da lib: ``SmartTokenClientBuilder`` (SMART Backend
Services, RF-17/RF-18).

Porte de ``SmartTokenClientBuilder.java`` (622 linhas): a API publica mais
visivel da biblioteca, responsavel por validar a configuracao *fail-fast*
na construcao e produzir um ``SmartTokenClient`` pronto para uso.

Decisao de design (documentada aqui, conforme pedido pela Tarefa B9 do
roadmap): optou-se por um **builder mutavel com metodos encadeaveis**
(``self`` retornado a cada chamada), como no ``.java`` original, em vez de
``@dataclass`` + ``build()`` sobre campos publicos. Motivo: a classe reune
mais de uma dezena de parametros opcionais com validacao cruzada (ex.:
``token_endpoint``/``fhir_base`` mutuamente exclusivos, ``hub_context``
exigindo ``ig``/``versao`` juntos) — um builder fluente deixa a ordem de
chamadas irrelevante e a intencao de cada parametro explicita no ponto de
uso, o que uma dataclass com dezenas de campos posicionais/kwargs nao
oferece com a mesma clareza. O builder em si **nao precisa ser
thread-safe**: construcao e passo unico no bootstrap da aplicacao
integradora (quem precisa ser thread-safe e o ``SmartTokenClient``
retornado — responsabilidade de ``client.py``, Tarefa B8).

Metodos de conveniencia que, no ``.java``, recebem ``Path``/``KeyStore``
(carga de PEM, PKCS#12/JKS, trust anchor) pertencem a Fatia A e ainda nao
tem implementacao concreta nesta base de codigo (ver ``pem_loader.py`` e o
``# TODO(fatia-a)`` nos metodos abaixo). Por ora, o builder aceita
diretamente instancias que satisfazem os Protocols ja prontos em
``ports.py`` (``SigningStrategy``, ``TlsContextProvider``) — os
consumidores atuais devem construir essas instancias por fora do builder.

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
resolucao via ``SmartConfigurationDiscovery`` (RF-09) **nao** acontece
aqui: RF-09 item 5 exige que ela ocorra uma unica vez, na construcao do
cliente, usando a mesma configuracao TLS/mTLS e os mesmos timeouts do
cliente principal — como e ``client.py`` (Tarefa B8) quem monta o
``httpx.Client`` interno a partir de ``tls_context_provider`` (ver roadmap
da Tarefa B8), e' ele quem deve, no seu ``__init__``, invocar
``SmartConfigurationDiscovery`` com esse mesmo ``httpx.Client`` quando
``fhir_base`` estiver presente. Este builder so valida eagerly o esquema
(``https``) da URL base fornecida; o ``token_endpoint`` efetivamente
resolvido via descoberta nao e' revalidado aqui.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import timedelta
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

from hubsaude_client import algorithms
from hubsaude_client._log import get_logger
from hubsaude_client.defaults import (
    DEFAULT_ASSERTION_TTL_SECONDS,
    DEFAULT_CONNECT_TIMEOUT_SECONDS,
    DEFAULT_JWT_ALGORITHM,
    DEFAULT_MAX_RETRIES,
    DEFAULT_REQUEST_TIMEOUT_SECONDS,
    DEFAULT_TOKEN_CACHE_MARGIN_SECONDS,
    DEFAULT_TOKEN_CACHE_MAX_ENTRIES,
)
from hubsaude_client.exceptions import SmartTokenError
from hubsaude_client.fault_tolerance import FaultToleranceConfig
from hubsaude_client.ports import SigningStrategy, TlsContextProvider
from hubsaude_client.token_cache import TokenCacheStrategy

if TYPE_CHECKING:
    # So resolvido por mypy/type checkers -- ver nota de dependencia
    # futura no docstring do modulo. Nao importar em runtime aqui.
    #
    # client.py ainda nao existe nesta base de codigo (Tarefa B8, depois
    # desta -- B9 -- no roadmap): o pacote instalado (editable ou sdist)
    # nao expoe esse submodulo nem um marcador py.typed para ele, entao
    # mypy nao consegue resolver o import como "de codigo-fonte" e cai no
    # caminho de pacote instalado sem stubs. Silenciado propositalmente
    # ate a Tarefa B8 aterrissar em develop; ver o contrato de kwargs
    # documentado acima, que client.py deve satisfazer quando existir.
    from hubsaude_client.client import SmartTokenClient  # type: ignore[import-untyped]

#: TTL RECOMENDADO (RF-01 item 4, "DEVERIA"): o servidor rejeita
#: exp > iat + 300s. Valores acima disso nao sao rejeitados por este
#: builder (a regra e' SHOULD, nao MUST) -- apenas logados como aviso.
_RECOMMENDED_MAX_ASSERTION_TTL_SECONDS = 300

#: Esquema exigido para token_endpoint/fhir_base (RF-10/RF-18: nenhum
#: material de credencial deve trafegar fora de TLS).
_REQUIRED_URL_SCHEME = "https"

#: Formato exigido para o alias de Guia de Implementacao em hub_context
#: (client-assertion-contexto-ig.md Sec3.4, RF-01 item 3).
_HUB_CONTEXT_IG_PATTERN = re.compile(r"^[a-z][a-z0-9-]{1,30}$")

#: Formato exigido para a versao em hub_context: SemVer completo
#: MAJOR.MINOR.PATCH, sem pre-release/build metadata (RF-01 item 3).
_HUB_CONTEXT_VERSAO_PATTERN = re.compile(r"^\d+\.\d+\.\d+$")

#: Logger compartilhado com o restante da lib (ver _log.py).
_LOG = get_logger()


@dataclass(frozen=True)
class HubContext:
    """Contexto de Guia de Implementacao (IG) pretendido para o
    ``client_assertion`` (claim ``hub_ctx``, RF-01 item 3,
    ``client-assertion-contexto-ig.md`` Sec3.4).

    Instancias so sao construidas por :meth:`SmartTokenClientBuilder.hub_context`
    apos validacao de formato -- ``ig``/``versao`` aqui ja estao validados.

    Attributes:
        ig: alias do Guia de Implementacao (``[a-z][a-z0-9-]{1,30}``).
        versao: versao SemVer completa (``MAJOR.MINOR.PATCH``, sem
            pre-release).
    """

    ig: str
    versao: str


class SmartTokenClientBuilder:
    """Builder fluente e publico do ``SmartTokenClient``.

    Instancias sao de uso unico e descartavel: configure via os metodos
    encadeaveis abaixo e chame :meth:`build` uma vez. Nao e thread-safe
    (ver nota de design no docstring do modulo) -- nao compartilhe uma
    instancia de builder entre threads.
    """

    __slots__ = (
        "_client_id",
        "_token_endpoint",
        "_fhir_base",
        "_signing_strategy",
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
    )

    def __init__(self) -> None:
        """Cria um builder novo, com todos os padroes de ``defaults.py``."""
        self._client_id: str | None = None
        self._token_endpoint: str | None = None
        self._fhir_base: str | None = None
        self._signing_strategy: SigningStrategy | None = None
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

    # ------------------------------------------------------------------
    # Metodos encadeaveis (fluent setters)
    # ------------------------------------------------------------------

    def client_id(self, client_id: str) -> SmartTokenClientBuilder:
        """Define o ``client_id`` emitido no credenciamento (obrigatorio)."""
        self._client_id = client_id
        return self

    def token_endpoint(self, token_endpoint: str) -> SmartTokenClientBuilder:
        """Define o token endpoint explicito.

        Mutuamente exclusivo com :meth:`fhir_base` (RF-09 item 2) --
        exatamente um dos dois deve ser informado antes de :meth:`build`.
        """
        self._token_endpoint = token_endpoint
        return self

    def fhir_base(self, fhir_base: str) -> SmartTokenClientBuilder:
        """Define a URL base FHIR para descoberta via
        ``.well-known/smart-configuration`` (RF-09).

        Mutuamente exclusivo com :meth:`token_endpoint`. A resolucao em si
        nao acontece neste builder -- ver nota no docstring do modulo.
        """
        self._fhir_base = fhir_base
        return self

    def signing_strategy(self, signing_strategy: SigningStrategy) -> SmartTokenClientBuilder:
        """Define a estrategia de assinatura do ``client_assertion`` (obrigatorio).

        Aceita qualquer implementacao que satisfaca ``ports.SigningStrategy``
        -- em memoria, PEM ja carregado por fora, HSM/PKCS#11, etc. Os
        metodos de conveniencia que carregam PEM/KeyStore diretamente ainda
        nao existem (Fatia A) -- ver os metodos ``# TODO(fatia-a)`` abaixo.
        """
        self._signing_strategy = signing_strategy
        return self

    def tls_context_provider(self, tls_context_provider: TlsContextProvider) -> SmartTokenClientBuilder:
        """Define o fornecedor de contexto TLS/mTLS (obrigatorio).

        Aceita qualquer implementacao que satisfaca
        ``ports.TlsContextProvider``. Os metodos de conveniencia que montam
        esse contexto a partir de certificado/chave em disco ainda nao
        existem (Fatia A) -- ver os metodos ``# TODO(fatia-a)`` abaixo.
        """
        self._tls_context_provider = tls_context_provider
        return self

    def jwt_algorithm(self, jwt_algorithm: str) -> SmartTokenClientBuilder:
        """Define o algoritmo JWT (``alg``). Padrao: ``RS384``.

        Aceita qualquer um dos 9 valores de ``algorithms.VALID_JWT_ALGORITHMS``,
        *case-insensitive* -- a normalizacao e validacao final acontecem em
        :meth:`build`.
        """
        self._jwt_algorithm = jwt_algorithm
        return self

    def key_id(self, key_id: str) -> SmartTokenClientBuilder:
        """Define o ``kid`` (identificador de chave) incluido no header do JWT.

        RECOMENDADO quando a chave de assinatura tiver um identificador
        conhecido (ex.: publicado num JWKS); opcional.
        """
        self._key_id = key_id
        return self

    def assertion_ttl_seconds(self, seconds: int) -> SmartTokenClientBuilder:
        """Define o TTL do ``client_assertion``, em segundos. Padrao: 60s.

        Valores ``<= 0`` sao normalizados para o padrao por
        ``FaultToleranceConfig`` (nao por este metodo). Valores acima de
        300s sao aceitos mas geram aviso em log em :meth:`build` -- o
        servidor rejeita ``exp`` maior que ``iat + 300`` (RF-01 item 4,
        regra "DEVERIA").
        """
        self._assertion_ttl_seconds = seconds
        return self

    def max_retries(self, max_retries: int) -> SmartTokenClientBuilder:
        """Define o numero maximo de tentativas em falha transitoria. Padrao: 3.

        Valores ``<= 0`` sao normalizados para o padrao por
        ``FaultToleranceConfig``.
        """
        self._max_retries = max_retries
        return self

    def connect_timeout(self, timeout: timedelta) -> SmartTokenClientBuilder:
        """Define o timeout de conexao TCP. Padrao: 10s."""
        self._connect_timeout = timeout
        return self

    def request_timeout(self, timeout: timedelta) -> SmartTokenClientBuilder:
        """Define o timeout de requisicao HTTP. Padrao: 30s."""
        self._request_timeout = timeout
        return self

    def enable_token_cache(self, enabled: bool) -> SmartTokenClientBuilder:
        """Habilita/desabilita o cache de tokens por scope. Padrao: habilitado."""
        self._enable_token_cache = enabled
        return self

    def token_cache_margin_seconds(self, seconds: int) -> SmartTokenClientBuilder:
        """Define a margem de renovacao antecipada do cache. Padrao: 30s."""
        self._token_cache_margin_seconds = seconds
        return self

    def token_cache_max_entries(self, max_entries: int) -> SmartTokenClientBuilder:
        """Define o teto de scopes retidos no cache (janela LRU). Padrao: 1000.

        Deve ser positivo -- validado em :meth:`build` (RF-18).
        """
        self._token_cache_max_entries = max_entries
        return self

    def hub_context(self, ig: str, versao: str) -> SmartTokenClientBuilder:
        """Define o contexto de Guia de Implementacao (claim ``hub_ctx``).

        Ambos os argumentos sao obrigatorios juntos -- nao ha forma de
        limpar apenas um dos dois depois de configurado. Quando nenhuma
        chamada a este metodo e feita, o claim ``hub_ctx`` e omitido do
        JWT (RF-01 item 3), que e o padrao.

        Args:
            ig: alias do Guia de Implementacao (``[a-z][a-z0-9-]{1,30}``).
            versao: versao SemVer completa (``MAJOR.MINOR.PATCH``).
        """
        self._hub_context_ig = ig
        self._hub_context_versao = versao
        return self

    # ------------------------------------------------------------------
    # Metodos de conveniencia (Fatia A) -- ainda nao implementados
    # ------------------------------------------------------------------

    # TODO(fatia-a): implementar quando PemLoader/SslContextFactory
    # existirem. Deve construir uma SigningStrategy em memoria a partir da
    # chave PEM (com deteccao automatica de formato -- RF-13) e chamar
    # self.signing_strategy(...) internamente.
    def private_key_pem(self, path: object, password: bytes | None = None) -> SmartTokenClientBuilder:
        """Carrega a chave privada de assinatura a partir de um arquivo PEM.

        Ainda nao implementado -- depende da Fatia A (``pem_loader.py``/
        estrategia de assinatura em memoria, RF-12/RF-13). Use
        :meth:`signing_strategy` diretamente por enquanto.

        Raises:
            NotImplementedError: sempre, nesta versao do SDK.
        """
        raise NotImplementedError(
            "private_key_pem() depende da Fatia A (carregamento de PEM, RF-13)"
            " e ainda nao esta implementado. Use signing_strategy() com uma"
            " implementacao propria de ports.SigningStrategy por enquanto."
        )

    # TODO(fatia-a): implementar junto com private_key_pem() -- verificacao
    # de consistencia chave-certificado (RF-15) tambem depende deste metodo.
    def certificate_pem(self, path: object) -> SmartTokenClientBuilder:
        """Carrega o certificado de cliente (mTLS) a partir de um arquivo PEM.

        Ainda nao implementado -- depende da Fatia A (RF-11/RF-14). Use
        :meth:`tls_context_provider` diretamente por enquanto.

        Raises:
            NotImplementedError: sempre, nesta versao do SDK.
        """
        raise NotImplementedError(
            "certificate_pem() depende da Fatia A (validacao de certificado,"
            " RF-14) e ainda nao esta implementado. Use tls_context_provider()"
            " com uma implementacao propria de ports.TlsContextProvider por"
            " enquanto."
        )

    # TODO(fatia-a): implementar quando houver suporte a KeyStore
    # (PKCS#12/JKS) do lado de assinatura (RF-12 item 2).
    def client_key_store(self, path: object, password: bytes, alias: str | None = None) -> SmartTokenClientBuilder:
        """Carrega chave e certificado de cliente a partir de um KeyStore
        (PKCS#12/JKS).

        Ainda nao implementado -- depende da Fatia A (RF-12 item 2). Use
        :meth:`signing_strategy` e :meth:`tls_context_provider` diretamente
        por enquanto.

        Raises:
            NotImplementedError: sempre, nesta versao do SDK.
        """
        raise NotImplementedError(
            "client_key_store() depende da Fatia A (suporte a KeyStore"
            " PKCS#12/JKS, RF-12) e ainda nao esta implementado."
        )

    # TODO(fatia-a): implementar junto com a configuracao TLS/mTLS
    # (RF-10 item 3 -- trust anchor customizado).
    def server_trust_anchor(self, path: object) -> SmartTokenClientBuilder:
        """Define um trust anchor customizado (substitui o trust store padrao).

        Ainda nao implementado -- depende da Fatia A (RF-10 item 3). Use
        :meth:`tls_context_provider` com um ``ssl.SSLContext`` ja
        configurado por enquanto.

        Raises:
            NotImplementedError: sempre, nesta versao do SDK.
        """
        raise NotImplementedError(
            "server_trust_anchor() depende da Fatia A (configuracao TLS/mTLS,"
            " RF-10) e ainda nao esta implementado. Use tls_context_provider()"
            " com um ssl.SSLContext ja configurado com o trust anchor"
            " desejado por enquanto."
        )

    # ------------------------------------------------------------------
    # build()
    # ------------------------------------------------------------------

    def build(self) -> "SmartTokenClient":
        """Valida a configuracao (fail-fast) e constroi o ``SmartTokenClient``.

        Ordem de validacao: ``client_id`` -> ``signing_strategy``/
        ``tls_context_provider`` -> exclusividade e esquema de
        ``token_endpoint``/``fhir_base`` -> ``jwt_algorithm`` -> timeouts
        -> ``token_cache_max_entries`` -> ``hub_context``. Nenhuma chamada
        de rede e feita aqui (a eventual descoberta via ``fhir_base``
        acontece dentro de ``SmartTokenClient.__init__`` -- ver nota no
        docstring do modulo).

        Returns:
            Um ``SmartTokenClient`` pronto para uso.

        Raises:
            SmartTokenError: se qualquer validacao falhar.
        """
        client_id = _require_non_blank(self._client_id, "client_id")
        signing_strategy = self._require_signing_strategy()
        tls_context_provider = self._require_tls_context_provider()
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
            max_retries=self._max_retries,
        )
        token_cache = TokenCacheStrategy(
            enabled=self._enable_token_cache,
            margin_seconds=self._token_cache_margin_seconds,
            max_entries=self._token_cache_max_entries,
        )

        _LOG.debug(
            "Construindo SmartTokenClient para clientId=%s (token_endpoint=%s, fhir_base=%s)",
            client_id,
            self._token_endpoint,
            self._fhir_base,
        )

        # Import tardio: ver nota de dependencia futura no docstring do
        # modulo (B9 e sequenciado antes de B8 no roadmap).
        # Sem "# type: ignore" aqui: mypy so emite import-untyped uma vez
        # por modulo (ja reportado/silenciado no import sob TYPE_CHECKING
        # acima); repetir o ignore neste import em runtime dispara
        # "Unused type: ignore comment" (unused-ignore) em modo strict.
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
    # Validacoes internas
    # ------------------------------------------------------------------

    def _require_signing_strategy(self) -> SigningStrategy:
        if self._signing_strategy is None:
            raise SmartTokenError(
                "signing_strategy e obrigatorio (client_credentials + private_key_jwt"
                " exige uma estrategia de assinatura do client_assertion)"
            )
        if not isinstance(self._signing_strategy, SigningStrategy):
            raise SmartTokenError(
                "signing_strategy fornecido nao satisfaz o protocolo"
                " ports.SigningStrategy (metodo sign(data: bytes) -> bytes)"
            )
        return self._signing_strategy

    def _require_tls_context_provider(self) -> TlsContextProvider:
        if self._tls_context_provider is None:
            raise SmartTokenError(
                "tls_context_provider e obrigatorio (toda comunicacao com o"
                " servidor de autorizacao e feita sobre TLS/mTLS)"
            )
        if not isinstance(self._tls_context_provider, TlsContextProvider):
            raise SmartTokenError(
                "tls_context_provider fornecido nao satisfaz o protocolo"
                " ports.TlsContextProvider (metodo ssl_context() -> ssl.SSLContext)"
            )
        return self._tls_context_provider

    def _validate_endpoint_config(self) -> None:
        """Valida a exclusividade mutua e o esquema https de
        ``token_endpoint``/``fhir_base`` (RF-09 item 2, RF-18).
        """
        token_endpoint = _normalize_optional_str(self._token_endpoint)
        fhir_base = _normalize_optional_str(self._fhir_base)
        if token_endpoint is None and fhir_base is None:
            raise SmartTokenError("informe token_endpoint() ou fhir_base() -- exatamente um dos dois e obrigatorio")
        if token_endpoint is not None and fhir_base is not None:
            raise SmartTokenError(
                "token_endpoint e fhir_base sao mutuamente exclusivos (RF-09 item 2);" " informe apenas um dos dois"
            )
        if token_endpoint is not None:
            _require_https_scheme(token_endpoint, "token_endpoint")
        elif fhir_base is not None:
            _require_https_scheme(fhir_base, "fhir_base")
        else:
            # Inalcancavel: os dois ifs acima ja garantem que exatamente um
            # dos dois esta preenchido neste ponto. Sem "assert" (removido
            # em bytecode otimizado, ver B101) -- SmartTokenError explicito
            # tambem ajuda o narrowing de tipos do mypy no ramo anterior.
            raise SmartTokenError(
                "estado inesperado: nem token_endpoint nem fhir_base preenchidos"
                " apos validacao de exclusividade mutua"
            )
        # Reatribui as versoes normalizadas (strip aplicado), preservando o
        # contrato de que build() so consome valores ja normalizados.
        self._token_endpoint = token_endpoint
        self._fhir_base = fhir_base

    def _resolve_jwt_algorithm(self) -> str:
        """Valida e normaliza (uppercase) o algoritmo JWT configurado.

        Delega a validacao propriamente dita para ``algorithms.resolve``,
        que ja lanca ``SmartTokenError`` com a lista de algoritmos validos
        quando o valor informado nao e reconhecido (RF-16 item 2).
        """
        return algorithms.resolve(self._jwt_algorithm).jwt_algorithm

    def _validate_timeouts(self) -> None:
        """Rejeita timeouts nulos ou nao positivos (RF-18)."""
        if self._connect_timeout is None or self._connect_timeout.total_seconds() <= 0:
            raise SmartTokenError(f"connect_timeout deve ser positivo, recebido: {self._connect_timeout!r}")
        if self._request_timeout is None or self._request_timeout.total_seconds() <= 0:
            raise SmartTokenError(f"request_timeout deve ser positivo, recebido: {self._request_timeout!r}")

    def _validate_token_cache_max_entries(self) -> None:
        """Rejeita ``token_cache_max_entries <= 0`` (RF-18).

        Validado aqui (com ``SmartTokenError``, o tipo de excecao publico
        da lib) alem de em ``TokenCacheStrategy.__init__`` (que lanca
        ``ValueError``) -- defesa em profundidade; este builder e o ponto
        de entrada publico e deve falhar com o tipo de excecao esperado
        pelos consumidores.
        """
        if self._token_cache_max_entries <= 0:
            raise SmartTokenError(
                f"token_cache_max_entries deve ser positivo, recebido: {self._token_cache_max_entries}"
            )

    def _build_hub_context(self) -> HubContext | None:
        """Valida e constroi o ``HubContext`` opcional (RF-01 item 3)."""
        ig = _normalize_optional_str(self._hub_context_ig)
        versao = _normalize_optional_str(self._hub_context_versao)
        if ig is None and versao is None:
            return None
        if ig is None or versao is None:
            raise SmartTokenError(
                "hub_context exige ig e versao juntos; informe os dois em uma"
                " unica chamada a hub_context(ig, versao)"
            )
        if not _HUB_CONTEXT_IG_PATTERN.match(ig):
            raise SmartTokenError(f"hub_context: ig invalido ({ig!r}); deve seguir o padrao [a-z][a-z0-9-]{{1,30}}")
        if not _HUB_CONTEXT_VERSAO_PATTERN.match(versao):
            raise SmartTokenError(
                f"hub_context: versao invalida ({versao!r}); deve ser SemVer completo"
                " MAJOR.MINOR.PATCH, sem pre-release"
            )
        return HubContext(ig=ig, versao=versao)

    def _warn_if_ttl_exceeds_recommended(self) -> None:
        """Loga aviso (nao bloqueia) quando o TTL excede o recomendado.

        RF-01 item 4 usa "DEVERIA" (SHOULD, RFC 2119) -- o servidor
        rejeita ``exp`` acima de ``iat + 300``, mas isso e responsabilidade
        do orquestrador (``client.py``) reportar como falha; aqui e so um
        aviso preventivo na construcao.
        """
        if self._assertion_ttl_seconds > _RECOMMENDED_MAX_ASSERTION_TTL_SECONDS:
            _LOG.warning(
                "assertion_ttl_seconds=%s excede o recomendado de %ss (RF-01 item 4);"
                " o servidor de autorizacao pode rejeitar o client_assertion",
                self._assertion_ttl_seconds,
                _RECOMMENDED_MAX_ASSERTION_TTL_SECONDS,
            )


def _require_non_blank(value: str | None, field_name: str) -> str:
    """Exige uma string nao nula e nao vazia (apos ``strip()``).

    Args:
        value: valor a validar.
        field_name: nome do campo, para a mensagem de erro.

    Returns:
        O valor com espacos laterais removidos.

    Raises:
        SmartTokenError: se ``value`` for ``None`` ou vazio apos ``strip()``.
    """
    if value is None or not value.strip():
        raise SmartTokenError(f"{field_name} e obrigatorio e nao pode ser vazio")
    return value.strip()


def _normalize_optional_str(value: str | None) -> str | None:
    """Normaliza uma string opcional: ``strip()``; vazio/``None`` -> ``None``.

    Args:
        value: valor a normalizar.

    Returns:
        O valor sem espacos laterais, ou ``None`` quando ausente/vazio.
    """
    if value is None:
        return None
    stripped = value.strip()
    return stripped or None


def _require_https_scheme(url: str, field_name: str) -> None:
    """Exige que ``url`` use o esquema ``https`` (RF-10, RF-18).

    Args:
        url: URL a validar (ja normalizada/sem espacos laterais).
        field_name: nome do campo, para a mensagem de erro.

    Raises:
        SmartTokenError: se o esquema nao for ``https`` (case-insensitive).
    """
    scheme = urlsplit(url).scheme.lower()
    if scheme != _REQUIRED_URL_SCHEME:
        raise SmartTokenError(
            f"{field_name} deve usar o esquema https, recebido: {url!r}"
            " (credenciais e client_assertion nao podem trafegar fora de TLS)"
        )

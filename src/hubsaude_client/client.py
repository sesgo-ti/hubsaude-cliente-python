"""Orquestracao principal do SDK: ``SmartTokenClient`` (SMART Backend
Services, RF-01/RF-02/RF-03/RF-05/RF-07/RF-09/RF-17).

Porte de ``SmartTokenClient.java`` (810 linhas) -- Tarefa 5/B8 do roadmap
de port Java -> Python. E a peca central que os demais colaboradores ja
implementados (``ports.SigningStrategy``/``TlsContextProvider``,
``token_cache.TokenCacheStrategy``, ``error_classifier.ErrorClassifier``,
``response_guard.TokenResponseGuard``, ``discovery.SmartConfigurationDiscovery``,
``retry.compute_retry_delay_seconds``, ``trace.TraceContext``) foram
projetados para compor. Este modulo **nao** implementa assinatura
criptografica (delegada a ``signing_strategy.sign(...)``, port de
``ports.py``) nem monta o ``ssl.SSLContext`` (delegado a
``tls_context_provider.ssl_context()``, mesmo port) -- ambos sao
consumidos prontos, preservando o desacoplamento Fatia A / Fatia B
descrito em ``lib-orquestracao-14-08-26.md``.

Instancias sao pensadas como **singleton por processo**: thread-safe e
reutilizavel pelo ciclo de vida da aplicacao integradora (RNF-01), nunca
recriada por chamada de ``obtain_token``.

Concorrencia (RF-05, RNF-01):

- *Lock striping* fixo (``_SCOPE_LOCK_STRIPES`` locks) selecionado por
  ``hash(scope) % _SCOPE_LOCK_STRIPES`` garante, na pratica, no maximo
  uma requisicao de renovacao em voo por scope (*single-flight*), com
  memoria O(1) em relacao ao numero de scopes distintos (RF-05 item 3).
- *Double-checked locking*: o cache e reconsultado apos adquirir o lock
  do stripe, para que uma thread que esperou o lock reaproveite o
  resultado ja obtido por outra em vez de refazer a chamada de rede
  (RF-05 item 2).
- Um ``_ReadersWriterLock`` privado (sem equivalente direto no stdlib)
  protege o ciclo de vida: ``obtain_token``/``obtain_token_response``
  tomam o lock de leitura (permite fan-out concorrente entre scopes
  distintos); ``close()`` toma o lock de escrita, que so e concedido
  apos todas as leituras em voo terminarem -- fechamento idempotente
  que aguarda operacoes em curso antes de liberar recursos (RNF-01).

Nao ha *circuit breaker* nem metricas/tracing aqui (ESPECIFICACAO.md
Sec1.2, fora de escopo do SDK) -- apenas a instancia reutilizavel e as
excecoes diagnosticas (``SmartTokenError``) que permitem a camada de
orquestracao do integrador implementar isso por fora.
"""

from __future__ import annotations

import base64
import json
import threading
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Final, Iterator

import httpx

from hubsaude_client._log import get_logger
from hubsaude_client.discovery import SmartConfigurationDiscovery
from hubsaude_client.error_classifier import ErrorClassifier
from hubsaude_client.exceptions import SmartTokenError
from hubsaude_client.fault_tolerance import FaultToleranceConfig
from hubsaude_client.ports import SigningStrategy, TlsContextProvider
from hubsaude_client.response_guard import TokenResponseGuard
from hubsaude_client.retry import compute_retry_delay_seconds
from hubsaude_client.token_cache import TokenCacheStrategy
from hubsaude_client.trace import TraceContext

if TYPE_CHECKING:
    # So resolvido por mypy/type checkers -- evita import em runtime de
    # builder.py (que ja importa este modulo em runtime dentro de
    # build()), o que criaria um ciclo de import real.
    from hubsaude_client.builder import HubContext

#: Grant type OAuth2 usado por toda requisicao ao token endpoint (RFC 6749).
_GRANT_TYPE: Final[str] = "client_credentials"

#: Tipo de assertion do client_assertion (RFC 7523 Sec2.2).
_CLIENT_ASSERTION_TYPE: Final[str] = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

#: Tipo fixo do header JWT (RF-01 item 2).
_JWT_TYPE: Final[str] = "JWT"

#: Quantidade fixa de locks para o *lock striping* de single-flight por
#: scope (RF-05 item 3) -- memoria O(1) independente do numero de scopes
#: distintos observados pelo cliente.
_SCOPE_LOCK_STRIPES: Final[int] = 32

#: Logger compartilhado com o restante da lib (ver _log.py): este e' o
#: proprio modulo que da nome ao logger compartilhado
#: (hubsaude_client.SmartTokenClient) -- nunca logging.getLogger(__name__).
_LOG = get_logger()


@dataclass(frozen=True)
class TokenResult:
    """Resultado publico de :meth:`SmartTokenClient.obtain_token_response`.

    Unifica o resultado de um *hit* de cache (``token_cache.CachedTokenResponse``,
    sem corpo cru) e o de uma obtencao real via rede
    (``response_guard.TokenResponse``, com corpo cru) num unico tipo
    publico, para que o chamador nao precise distinguir a origem.

    Attributes:
        access_token: token de acesso obtido (cache ou rede).
        expires_in: segundos restantes de validade a partir de agora
            (RF-04 item 4) -- nunca negativo.
        raw: corpo JSON cru da resposta do token endpoint, quando o
            resultado veio de uma obtencao real; ``None`` quando servido
            do cache (o cache nao retem o corpo cru -- apenas
            access_token/expiracao, ver ``token_cache.py``).
    """

    access_token: str
    expires_in: int
    raw: dict[str, object] | None = field(default=None)

    def __repr__(self) -> str:
        """Representacao textual com o token mascarado (evita vazamento em logs)."""
        return f"TokenResult(access_token=[REDACTED], expires_in={self.expires_in}, raw={'...' if self.raw else None})"


class SmartTokenClient:
    """Cliente SMART Backend Services: orquestra assertion JWT, cache,
    retry/tolerancia a falhas e TLS/mTLS para obter ``access_token`` do
    authorization server do HubSaude.

    Pensado como **singleton por processo**: construa uma unica instancia
    (via :class:`hubsaude_client.builder.SmartTokenClientBuilder`) e
    reutilize-a pelo ciclo de vida da aplicacao integradora. Thread-safe
    (ver nota de concorrencia no docstring do modulo); chame :meth:`close`
    exatamente uma vez ao encerrar a aplicacao (idempotente -- chamadas
    extras sao no-op).

    Nao deve ser instanciado diretamente pelo consumidor externo -- use
    ``SmartTokenClientBuilder``, que valida a configuracao *fail-fast*
    antes de construir esta classe (RF-18).
    """

    __slots__ = (
        "_client_id",
        "_token_endpoint",
        "_signing_strategy",
        "_fault_tolerance",
        "_token_cache",
        "_jwt_algorithm",
        "_key_id",
        "_hub_context",
        "_http_client",
        "_error_classifier",
        "_response_guard",
        "_scope_locks",
        "_rw_lock",
        "_closed",
    )

    def __init__(
        self,
        *,
        client_id: str,
        token_endpoint: str | None,
        fhir_base: str | None,
        signing_strategy: SigningStrategy,
        tls_context_provider: TlsContextProvider,
        fault_tolerance: FaultToleranceConfig,
        token_cache: TokenCacheStrategy,
        jwt_algorithm: str,
        key_id: str | None,
        hub_context: "HubContext | None",
    ) -> None:
        """Constroi o cliente pronto para uso.

        Nao chamado diretamente pelo consumidor externo -- ver
        :class:`hubsaude_client.builder.SmartTokenClientBuilder`, que ja
        validou (fail-fast) toda a configuracao recebida aqui: exatamente
        um entre ``token_endpoint``/``fhir_base`` esta preenchido,
        ``jwt_algorithm`` ja foi normalizado/validado, timeouts sao
        positivos, etc. Este construtor nao revalida essas invariantes.

        Quando ``fhir_base`` e informado, a resolucao do token endpoint
        via ``.well-known/smart-configuration`` (RF-09) acontece aqui,
        uma unica vez (RF-09 item 5), usando o mesmo ``httpx.Client``
        (mesma configuracao TLS/mTLS e mesmos timeouts) que este cliente
        usara para as obtencoes de token subsequentes.

        Args:
            client_id: identificador do cliente (credenciamento previo).
            token_endpoint: URL do token endpoint, quando conhecida
                explicitamente. Mutuamente exclusivo com ``fhir_base``
                (ja validado pelo builder).
            fhir_base: URL base FHIR para descoberta via
                ``.well-known/smart-configuration``, quando
                ``token_endpoint`` nao e informado.
            signing_strategy: estrategia de assinatura do
                ``client_assertion`` (port ``ports.SigningStrategy``).
            tls_context_provider: fornecedor do contexto TLS/mTLS (port
                ``ports.TlsContextProvider``) usado para configurar o
                ``httpx.Client`` interno.
            fault_tolerance: timeouts, TTL da assertion e numero maximo
                de tentativas em falha transitoria.
            token_cache: estrategia de cache de tokens por scope.
            jwt_algorithm: algoritmo JWT (``alg``) ja normalizado
                (uppercase) e validado pelo builder.
            key_id: ``kid`` a incluir no header do JWT, ou ``None`` para
                omiti-lo.
            hub_context: contexto de Guia de Implementacao (claim
                ``hub_ctx``) ja validado pelo builder, ou ``None`` para
                omitir o claim.

        Raises:
            SmartTokenError: se ``fhir_base`` for informado e a
                descoberta do token endpoint falhar (ver
                ``discovery.SmartConfigurationDiscovery``).
        """
        self._client_id = client_id
        self._signing_strategy = signing_strategy
        self._fault_tolerance = fault_tolerance
        self._token_cache = token_cache
        self._jwt_algorithm = jwt_algorithm
        self._key_id = key_id
        self._hub_context = hub_context

        timeout = httpx.Timeout(
            connect=fault_tolerance.connect_timeout.total_seconds(),
            read=fault_tolerance.request_timeout.total_seconds(),
            write=fault_tolerance.request_timeout.total_seconds(),
            pool=fault_tolerance.connect_timeout.total_seconds(),
        )
        self._http_client = httpx.Client(verify=tls_context_provider.ssl_context(), timeout=timeout)

        if fhir_base is not None:
            _LOG.debug("Resolvendo token_endpoint via descoberta SMART em fhir_base=%s", fhir_base)
            discovery = SmartConfigurationDiscovery(self._http_client)
            self._token_endpoint = discovery.discover_token_endpoint(fhir_base)
            _LOG.debug("token_endpoint resolvido via descoberta: %s", self._token_endpoint)
        elif token_endpoint is not None:
            self._token_endpoint = token_endpoint
        else:
            # Inalcancavel: o builder ja garante exclusividade mutua entre
            # token_endpoint/fhir_base antes de construir este cliente.
            # Sem "assert" aqui (removido em bytecode otimizado, ver B101,
            # mesmo criterio ja aplicado em builder.py) -- SmartTokenError
            # explicito tambem ajuda o narrowing de tipos do mypy.
            raise SmartTokenError(
                "estado inesperado: nem token_endpoint nem fhir_base preenchidos"
                " na construcao de SmartTokenClient (deveria ter sido validado"
                " pelo builder)"
            )

        self._error_classifier = ErrorClassifier(client_id, self._token_endpoint)
        self._response_guard = TokenResponseGuard()
        self._scope_locks: list[threading.Lock] = [threading.Lock() for _ in range(_SCOPE_LOCK_STRIPES)]
        self._rw_lock = _ReadersWriterLock()
        self._closed = False

    # ------------------------------------------------------------------
    # API publica (RF-17)
    # ------------------------------------------------------------------

    def obtain_token(self, scope: str | None = None) -> str:
        """Obtem (do cache ou via rede) o ``access_token`` para o scope.

        Args:
            scope: scope SMART solicitado (ex.: ``"system/Patient.rs"``).
                ``None``/vazio equivale a "sem scope" (RF-04 item 1).

        Returns:
            O ``access_token`` valido.

        Raises:
            SmartTokenError: em qualquer falha de obtencao (ver
                :meth:`obtain_token_response`), ou se o cliente ja tiver
                sido fechado.
        """
        return self.obtain_token_response(scope).access_token

    def obtain_token_response(self, scope: str | None = None) -> TokenResult:
        """Obtem (do cache ou via rede) a resposta completa de token.

        Fluxo (ESPECIFICACAO.md Sec5): cache-aside -> em caso de miss,
        adquire o lock do stripe do scope -> reconsulta o cache
        (*double-checked locking*, RF-05 item 2) -> monta e assina um
        novo ``client_assertion`` -> ``POST`` ao token endpoint, com
        retry em falha transitoria de transporte (nunca em resposta HTTP
        recebida, RF-07) -> grava no cache -> retorna.

        Args:
            scope: scope SMART solicitado. ``None``/vazio equivale a
                "sem scope" (RF-04 item 1).

        Returns:
            A resposta de token, do cache ou recem-obtida.

        Raises:
            SmartTokenError: falha ao contatar o servidor (transporte
                esgotado, resposta HTTP != 200, corpo invalido/excedendo
                o limite, ou suspeita de rejeicao do certificado de
                cliente no mTLS), ou se o cliente ja tiver sido fechado.
            SigningError: falha criptografica na estrategia de assinatura.
        """
        with self._rw_lock.read_lock():
            self._check_not_closed()
            normalized_scope = _normalize_scope(scope)

            cached = self._token_cache.cached_if_valid(normalized_scope)
            if cached is not None:
                return TokenResult(access_token=cached.access_token, expires_in=cached.expires_in, raw=None)

            stripe_lock = self._scope_locks[hash(normalized_scope) % _SCOPE_LOCK_STRIPES]
            with stripe_lock:
                # Double-checked: outra thread pode ja ter renovado
                # enquanto esta esperava o lock do stripe.
                cached = self._token_cache.cached_if_valid(normalized_scope)
                if cached is not None:
                    return TokenResult(access_token=cached.access_token, expires_in=cached.expires_in, raw=None)

                token_response = self._fetch_token(normalized_scope)
                self._token_cache.store(normalized_scope, token_response.access_token, token_response.expires_in)
                return TokenResult(
                    access_token=token_response.access_token,
                    expires_in=token_response.expires_in,
                    raw=token_response.raw,
                )

    def invalidate_cache(self, scope: str | None = None) -> None:
        """Invalida o cache de tokens (RF-06).

        Args:
            scope: quando informado, invalida somente o scope
                normalizado correspondente; quando ``None``, invalida o
                cache inteiro (todos os scopes).
        """
        if scope is None:
            self._token_cache.invalidate_all()
        else:
            self._token_cache.invalidate(_normalize_scope(scope))

    def get_token_endpoint(self) -> str:
        """Retorna o token endpoint efetivo em uso.

        Quando o cliente foi construido com ``fhir_base``, este e o
        endpoint ja resolvido pela descoberta SMART (RF-09) -- nunca a
        URL base FHIR original.
        """
        return self._token_endpoint

    def get_jwt_algorithm(self) -> str:
        """Retorna o algoritmo JWT (``alg``) configurado para a assinatura."""
        return self._jwt_algorithm

    def close(self) -> None:
        """Libera os recursos do cliente (idempotente).

        Aguarda todas as operacoes ``obtain_token``/``obtain_token_response``
        em voo terminarem (lock de escrita do ``_ReadersWriterLock``),
        invalida todo o cache e fecha o ``httpx.Client`` interno.
        Chamadas subsequentes sao no-op.
        """
        with self._rw_lock.write_lock():
            if self._closed:
                return
            self._closed = True
            self._token_cache.invalidate_all()
            self._http_client.close()

    def __enter__(self) -> "SmartTokenClient":
        """Permite uso como *context manager* (``with SmartTokenClient(...) as c``)."""
        return self

    def __exit__(self, *_exc_info: object) -> None:
        """Chama :meth:`close` ao sair do bloco ``with``."""
        self.close()

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _check_not_closed(self) -> None:
        """Levanta erro explicito se o cliente ja tiver sido fechado.

        Raises:
            SmartTokenError: se :meth:`close` ja tiver sido chamado.
        """
        if self._closed:
            raise SmartTokenError(
                f"SmartTokenClient (clientId={self._client_id}) ja foi fechado (close());"
                " nao e possivel obter novos tokens"
            )

    def _fetch_token(self, normalized_scope: str):  # type: ignore[no-untyped-def]
        """Executa a obtencao real do token via rede, com retry em falha
        transitoria de transporte (RF-01/RF-02/RF-03/RF-07).

        Um novo ``client_assertion`` (com ``jti`` proprio) e um novo
        ``TraceContext`` sao gerados a cada tentativa real ao token
        endpoint, inclusive em retries (RF-01 item 7, RF-02 item 3).
        Retry so ocorre para falha de transporte classificada como
        transitoria por ``ErrorClassifier`` -- qualquer resposta HTTP
        efetivamente recebida (inclusive 429/5xx) resulta em erro
        imediato, sem nova tentativa (RF-03 item 3/4, RF-07 item 2).

        Args:
            normalized_scope: scope ja normalizado (``""`` para "sem
                scope").

        Returns:
            A resposta de sucesso validada
            (``response_guard.TokenResponse``).

        Raises:
            SmartTokenError: tentativas esgotadas em falha transitoria,
                resposta HTTP != 200, ou suspeita de rejeicao do
                certificado de cliente no mTLS.
        """
        max_retries = self._fault_tolerance.max_retries
        last_exc: BaseException | None = None

        for attempt in range(1, max_retries + 1):
            trace = TraceContext.generate()
            assertion = self._build_client_assertion()
            data: dict[str, str] = {
                "grant_type": _GRANT_TYPE,
                "client_id": self._client_id,
                "client_assertion_type": _CLIENT_ASSERTION_TYPE,
                "client_assertion": assertion,
            }
            if normalized_scope:
                data["scope"] = normalized_scope
            headers = {TraceContext.TRACEPARENT_HEADER: trace.traceparent()}

            try:
                response = self._http_client.post(self._token_endpoint, data=data, headers=headers)
            except httpx.RequestError as exc:
                # Relanca diretamente se nao-retriavel (ou levanta
                # SmartTokenError na heuristica de rejeicao do
                # certificado de cliente); devolve a excecao quando
                # retriavel, para a logica de retry abaixo.
                last_exc = self._error_classifier.retriable_or_reraise(exc, trace)
                if attempt < max_retries:
                    _LOG.warning(
                        "Falha transitoria ao obter token (tentativa %d/%d) clientId=%s traceId=%s: %s",
                        attempt,
                        max_retries,
                        self._client_id,
                        trace.trace_id,
                        last_exc,
                    )
                    time.sleep(compute_retry_delay_seconds(attempt))
                    continue
                raise SmartTokenError(
                    f"Falha ao obter token para clientId={self._client_id} apos {attempt}"
                    f" tentativa(s) (traceId={trace.trace_id}): {last_exc}",
                    last_exc,
                ) from last_exc
            else:
                if response.status_code == 200:
                    return self._response_guard.parse_success_response(response, trace)
                raise self._error_classifier.http_failure(response, trace)

        # Inalcancavel: o laco acima sempre retorna ou levanta antes de
        # terminar (max_retries >= 1, normalizado por FaultToleranceConfig).
        raise SmartTokenError(f"estado inesperado: retry esgotado sem resultado para clientId={self._client_id}")

    def _build_client_assertion(self) -> str:
        """Monta e assina um novo ``client_assertion`` (JWT, RF-01).

        Gera um JWS compacto (``header.payload.assinatura``), cada parte
        em Base64URL sem padding, com um ``jti`` (UUID) novo -- nunca
        reutilizado entre chamadas (RF-01 item 7).

        Returns:
            O JWT ``client_assertion`` compacto, pronto para o form body.

        Raises:
            SigningError: se a estrategia de assinatura falhar.
        """
        now = int(datetime.now(timezone.utc).timestamp())
        header: dict[str, object] = {"alg": self._jwt_algorithm, "typ": _JWT_TYPE}
        if self._key_id is not None:
            header["kid"] = self._key_id

        payload: dict[str, object] = {
            "iss": self._client_id,
            "sub": self._client_id,
            "aud": self._token_endpoint,
            "iat": now,
            "exp": now + self._fault_tolerance.assertion_ttl_seconds,
            "jti": str(uuid.uuid4()),
        }
        if self._hub_context is not None:
            payload["hub_ctx"] = {"ig": self._hub_context.ig, "versao": self._hub_context.versao}

        signing_input = f"{_base64url_encode(_json_dumps(header))}.{_base64url_encode(_json_dumps(payload))}"
        signature = self._signing_strategy.sign(signing_input.encode("ascii"))
        return f"{signing_input}.{_base64url_encode(signature)}"


class _ReadersWriterLock:
    """Lock leitor-escritor simples (sem equivalente direto no stdlib).

    Multiplos leitores podem manter o lock simultaneamente; um escritor
    exige exclusividade total (nenhum leitor nem outro escritor ativo).
    Usado por :class:`SmartTokenClient` para permitir fan-out concorrente
    em ``obtain_token``/``obtain_token_response`` (leitores) enquanto
    ``close()`` (escritor) aguarda toda operacao em voo terminar antes de
    liberar recursos (RNF-01).

    Implementado com um ``threading.Condition`` sobre um
    ``threading.Lock`` -- sem prioridade especial para escritores
    (aceitavel aqui: ``close()`` e chamado no maximo uma vez, no
    encerramento do processo, entao inanicao do escritor por leitores
    continuos nao e um cenario realista para este uso).
    """

    def __init__(self) -> None:
        self._condition = threading.Condition(threading.Lock())
        self._active_readers = 0
        self._writer_active = False

    @contextmanager
    def read_lock(self) -> Iterator[None]:
        """Bloco protegido por leitura -- concorrente com outros leitores."""
        self._acquire_read()
        try:
            yield
        finally:
            self._release_read()

    @contextmanager
    def write_lock(self) -> Iterator[None]:
        """Bloco protegido por escrita -- exclusivo (sem leitores nem outro escritor)."""
        self._acquire_write()
        try:
            yield
        finally:
            self._release_write()

    def _acquire_read(self) -> None:
        with self._condition:
            while self._writer_active:
                self._condition.wait()
            self._active_readers += 1

    def _release_read(self) -> None:
        with self._condition:
            self._active_readers -= 1
            if self._active_readers == 0:
                self._condition.notify_all()

    def _acquire_write(self) -> None:
        with self._condition:
            while self._writer_active or self._active_readers > 0:
                self._condition.wait()
            self._writer_active = True

    def _release_write(self) -> None:
        with self._condition:
            self._writer_active = False
            self._condition.notify_all()


def _normalize_scope(scope: str | None) -> str:
    """Normaliza o scope para uso no cache/requisicao (RF-04 item 1).

    Args:
        scope: scope informado pelo chamador (aceita ``None``).

    Returns:
        O scope com espacos laterais removidos; ``""`` quando ``None``.
    """
    if scope is None:
        return ""
    return scope.strip()


def _json_dumps(value: dict[str, object]) -> bytes:
    """Serializa um dict em JSON compacto (sem espacos), com *escaping*
    correto (RF-01 item 5), como bytes UTF-8.

    Args:
        value: objeto a serializar (header ou payload do JWT).

    Returns:
        JSON compacto, codificado em UTF-8.
    """
    return json.dumps(value, separators=(",", ":")).encode("utf-8")


def _base64url_encode(data: bytes) -> str:
    """Codifica em Base64URL sem padding (RFC 7515 Sec2), como exigido
    para cada parte de um JWS compacto.

    Args:
        data: bytes a codificar.

    Returns:
        Representacao Base64URL, sem caracteres ``=`` de padding.
    """
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

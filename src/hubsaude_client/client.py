"""Orquestração principal do SDK: ``SmartTokenClient`` (SMART Backend
Services, RF-01/RF-02/RF-03/RF-05/RF-07/RF-09/RF-17).

E a peça central que os demais colaboradores já
implementados (``ports.SigningStrategy``/``TlsContextProvider``,
``token_cache.TokenCacheStrategy``, ``error_classifier.ErrorClassifier``,
``response_guard.TokenResponseGuard``, ``discovery.SmartConfigurationDiscovery``,
``retry.compute_retry_delay_seconds``, ``trace.TraceContext``) foram
projetados para compor. Este módulo **não** implementa assinatura
criptográfica (delegada a ``signing_strategy.sign(...)``, port de
``ports.py``) nem monta o ``ssl.SSLContext`` (delegado a
``tls_context_provider.ssl_context()``, mesmo port) -- ambos são
consumidos prontos, preservando o desacoplamento entre assinatura, TLS e
orquestração HTTP.

Instâncias são pensadas como **singleton por processo**: thread-safe e
reutilizável pelo ciclo de vida da aplicação integradora (RNF-01), nunca
recriada por chamada de ``obtain_token``.

Concorrência (RF-05, RNF-01):

- *Lock striping* fixo (``_SCOPE_LOCK_STRIPES`` locks) selecionado por
  ``hash(scope) % _SCOPE_LOCK_STRIPES`` garante, na prática, no máximo
  uma requisição de renovação em voo por scope (*single-flight*), com
  memória O(1) em relação ao número de scopes distintos (RF-05 item 3).
- *Double-checked locking*: o cache é reconsultado após adquirir o lock
  do stripe, para que uma thread que esperou o lock reaproveite o
  resultado já obtido por outra em vez de refazer a chamada de rede
  (RF-05 item 2).
- Um ``_ReadersWriterLock`` privado (sem equivalente direto no stdlib)
  protege o ciclo de vida: ``obtain_token``/``obtain_token_response``
  tomam o lock de leitura (permite fan-out concorrente entre scopes
  distintos); ``close()`` toma o lock de escrita, que só é concedido
  após todas as leituras em voo terminarem -- fechamento idempotente
  que aguarda operações em curso antes de liberar recursos (RNF-01).

Não há *circuit breaker* nem métricas/tracing aqui (ESPECIFICAÇÃO.md
Sec1.2, fora de escopo do SDK) -- apenas a instância reutilizável e as
exceções diagnósticas (``SmartTokenError``) que permitem a camada de
orquestração do integrador implementar isso por fora.
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
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes

from hubsaude_client import key_certificate_consistency
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
    # Só resolvido por mypy/type checkers -- evita import em runtime de
    # builder.py (que já importa este módulo em runtime dentro de
    # build()), o que criaria um ciclo de import real.
    from hubsaude_client.builder import HubContext

#: Grant type OAuth2 usado por toda requisição ao token endpoint (RFC 6749).
_GRANT_TYPE: Final[str] = "client_credentials"

#: Tipo de assertion do client_assertion (RFC 7523 Sec2.2).
_CLIENT_ASSERTION_TYPE: Final[str] = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

#: Tipo fixo do header JWT (RF-01 item 2).
_JWT_TYPE: Final[str] = "JWT"

#: Quantidade fixa de locks para o *lock striping* de single-flight por
#: scope (RF-05 item 3) -- memória O(1) independente do número de scopes
#: distintos observados pelo cliente.
_SCOPE_LOCK_STRIPES: Final[int] = 32

#: Logger compartilhado com o restante da lib (ver _log.py): este é o
#: próprio módulo que da nome ao logger compartilhado
#: (hubsaude_client.SmartTokenClient) -- nunca logging.getLogger(__name__).
_LOG = get_logger()


@dataclass(frozen=True)
class TokenResult:
    """Resultado público de :meth:`SmartTokenClient.obtain_token_response`.

    Unifica o resultado de um *hit* de cache (``token_cache.CachedTokenResponse``,
    sem corpo cru) e o de uma obtenção real via rede
    (``response_guard.TokenResponse``, com corpo cru) num único tipo
    público, para que o chamador não precise distinguir a origem.

    Attributes:
        access_token: token de acesso obtido (cache ou rede).
        expires_in: segundos restantes de validade a partir de agora
            (RF-04 item 4) -- nunca negativo.
        raw: corpo JSON cru da resposta do token endpoint, quando o
            resultado veio de uma obtenção real; ``None`` quando servido
            do cache (o cache não retém o corpo cru -- apenas
            access_token/expiração, ver ``token_cache.py``).
    """

    access_token: str
    expires_in: int
    raw: dict[str, object] | None = field(default=None)

    def __repr__(self) -> str:
        """Representação textual com o token mascarado (evita vazamento em logs)."""
        return f"TokenResult(access_token=[REDACTED], expires_in={self.expires_in}, raw={'...' if self.raw else None})"


class SmartTokenClient:
    """Cliente SMART Backend Services: orquestra assertion JWT, cache,
    retry/tolerância a falhas e TLS/mTLS para obter ``access_token`` do
    authorization server do HubSaude.

    Pensado como **singleton por processo**: construa uma única instância
    (via :class:`hubsaude_client.builder.SmartTokenClientBuilder`) e
    reutilize-a pelo ciclo de vida da aplicação integradora. Thread-safe
    (ver nota de concorrência no docstring do módulo); chame :meth:`close`
    exatamente uma vez ao encerrar a aplicação (idempotente -- chamadas
    extras são no-op).

    Não deve ser instanciado diretamente pelo consumidor externo -- use
    ``SmartTokenClientBuilder``, que valida a configuração *fail-fast*
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
        """Constrói o cliente pronto para uso.

        Não chamado diretamente pelo consumidor externo -- ver
        :class:`hubsaude_client.builder.SmartTokenClientBuilder`, que já
        validou (fail-fast) toda a configuração recebida aqui: exatamente
        um entre ``token_endpoint``/``fhir_base`` está preenchido,
        ``jwt_algorithm`` já foi normalizado/validado, timeouts são
        positivos, etc. Este construtor não revalida essas invariantes.

        Quando ``fhir_base`` é informado, a resolução do token endpoint
        via ``.well-known/smart-configuration`` (RF-09) acontece aqui,
        uma única vez (RF-09 item 5), usando o mesmo ``httpx.Client``
        (mesma configuração TLS/mTLS e mesmos timeouts) que este cliente
        usara para as obtenções de token subsequentes.

        Args:
            client_id: identificador do cliente (credenciamento prévio).
            token_endpoint: URL do token endpoint, quando conhecida
                explicitamente. Mutuamente exclusivo com ``fhir_base``
                (já validado pelo builder).
            fhir_base: URL base FHIR para descoberta via
                ``.well-known/smart-configuration``, quando
                ``token_endpoint`` não é informado.
            signing_strategy: estratégia de assinatura do
                ``client_assertion`` (port ``ports.SigningStrategy``).
            tls_context_provider: fornecedor do contexto TLS/mTLS (port
                ``ports.TlsContextProvider``) usado para configurar o
                ``httpx.Client`` interno.
            fault_tolerance: timeouts, TTL da assertion e número máximo
                de tentativas em falha transitória.
            token_cache: estratégia de cache de tokens por scope.
            jwt_algorithm: algoritmo JWT (``alg``) já normalizado
                (uppercase) e validado pelo builder.
            key_id: ``kid`` a incluir no header do JWT, ou ``None`` para
                omiti-lo.
            hub_context: contexto de Guia de Implementação (claim
                ``hub_ctx``) já validado pelo builder, ou ``None`` para
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
            # Inalcançável: o builder já garante exclusividade mútua entre
            # token_endpoint/fhir_base antes de construir este cliente.
            # Sem "assert" aqui (removido em bytecode otimizado, ver B101,
            # mesmo critério já aplicado em builder.py) -- SmartTokenError
            # explícito também ajuda o narrowing de tipos do mypy.
            raise SmartTokenError(  # pragma: no cover -- guarda defensiva inalcançável, ver comentário acima
                "estado inesperado: nem token_endpoint nem fhir_base preenchidos"
                " na construção de SmartTokenClient (deveria ter sido validado"
                " pelo builder)"
            )

        self._error_classifier = ErrorClassifier(client_id, self._token_endpoint)
        self._response_guard = TokenResponseGuard()
        self._scope_locks: list[threading.Lock] = [threading.Lock() for _ in range(_SCOPE_LOCK_STRIPES)]
        self._rw_lock = _ReadersWriterLock()
        self._closed = False

    # ------------------------------------------------------------------
    # API pública (RF-17)
    # ------------------------------------------------------------------

    def obtain_token(self, scope: str | None = None) -> str:
        """Obtém (do cache ou via rede) o ``access_token`` para o scope.

        Args:
            scope: scope SMART solicitado (ex.: ``"system/Patient.rs"``).
                ``None``/vazio equivale a "sem scope" (RF-04 item 1).

        Returns:
            O ``access_token`` válido.

        Raises:
            SmartTokenError: em qualquer falha de obtenção (ver
                :meth:`obtain_token_response`), ou se o cliente já tiver
                sido fechado.
        """
        return self.obtain_token_response(scope).access_token

    def obtain_token_response(self, scope: str | None = None) -> TokenResult:
        """Obtém (do cache ou via rede) a resposta completa de token.

        Fluxo (ESPECIFICAÇÃO.md Sec5): cache-aside -> em caso de miss,
        adquire o lock do stripe do scope -> reconsulta o cache
        (*double-checked locking*, RF-05 item 2) -> monta e assina um
        novo ``client_assertion`` -> ``POST`` ao token endpoint, com
        retry em falha transitória de transporte (nunca em resposta HTTP
        recebida, RF-07) -> grava no cache -> retorna.

        Args:
            scope: scope SMART solicitado. ``None``/vazio equivale a
                "sem scope" (RF-04 item 1).

        Returns:
            A resposta de token, do cache ou recém-obtida.

        Raises:
            SmartTokenError: falha ao contatar o servidor (transporte
                esgotado, resposta HTTP != 200, corpo inválido/excedendo
                o limite, ou suspeita de rejeição do certificado de
                cliente no mTLS), ou se o cliente já tiver sido fechado.
            SigningError: falha criptográfica na estratégia de assinatura.
        """
        with self._rw_lock.read_lock():
            self._check_not_closed()
            normalized_scope = _normalize_scope(scope)

            cached = self._token_cache.cached_if_valid(normalized_scope)
            if cached is not None:
                return TokenResult(access_token=cached.access_token, expires_in=cached.expires_in, raw=None)

            stripe_lock = self._scope_locks[hash(normalized_scope) % _SCOPE_LOCK_STRIPES]
            with stripe_lock:
                # Double-checked: outra thread pode já ter renovado
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

        Quando o cliente foi construído com ``fhir_base``, este é o
        endpoint já resolvido pela descoberta SMART (RF-09) -- nunca a
        URL base FHIR original.
        """
        return self._token_endpoint

    def get_jwt_algorithm(self) -> str:
        """Retorna o algoritmo JWT (``alg``) configurado para a assinatura."""
        return self._jwt_algorithm

    def get_key_id(self) -> str | None:
        """Retorna o ``kid`` configurado para o header do client_assertion,
        ou ``None`` quando não configurado.
        """
        return self._key_id

    @staticmethod
    def verify_key_pair_consistency(private_key: PrivateKeyTypes, certificate: x509.Certificate) -> None:
        """Verifica, de forma fail-fast, que uma chave privada corresponde
        a chave pública de um certificado X.509.

        Útil para quem monta a
        própria ``SigningStrategy`` fora do builder (cenário HSM/cofre de
        segredos customizado) e quer confirmar, antes de usar, que a chave
        e o certificado formam o mesmo par -- em vez de descobrir isso
        apenas quando o authorization server rejeitar o
        ``client_assertion``.

        Não exige uma instância de ``SmartTokenClient``: é um método
        estático, chamável diretamente como
        ``SmartTokenClient.verify_key_pair_consistency(...)``.

        Args:
            private_key: chave privada RSA ou EC a validar.
            certificate: certificado X.509 com a chave pública
                correspondente.

        Raises:
            SmartTokenError: se o tipo/curva da chave não for suportado
                para esta verificação, ou se a chave e o certificado não
                formarem um par válido.
        """
        key_certificate_consistency.verify_key_pair(private_key, certificate)

    def close(self) -> None:
        """Libera os recursos do cliente (idempotente).

        Aguarda todas as operações ``obtain_token``/``obtain_token_response``
        em voo terminarem (lock de escrita do ``_ReadersWriterLock``),
        invalida todo o cache, fecha o ``httpx.Client`` interno e, quando a
        ``signing_strategy`` configurada expuser um ``close()`` (ex.:
        estratégia PKCS#11 que mantém uma sessão de hardware aberta),
        invoca-o em modo best-effort -- ver nota em ``ports.SigningStrategy``.
        Chamadas subsequentes são no-op.
        """
        with self._rw_lock.write_lock():
            if self._closed:
                return
            self._closed = True
            self._token_cache.invalidate_all()
            self._http_client.close()
            self._close_signing_strategy_if_supported()

    def _close_signing_strategy_if_supported(self) -> None:
        """Fecha a ``signing_strategy``, se ela expuser ``close()`` (duck
        typing best-effort -- ``close()`` não faz parte do Protocol
        ``ports.SigningStrategy``, ver docstring la).

        Falhas aqui são apenas logadas (não propagadas): o cliente já está
        encerrando e o cache/http client já foram liberados nesta chamada
        a :meth:`close`.
        """
        close_fn = getattr(self._signing_strategy, "close", None)
        if not callable(close_fn):
            return
        try:
            close_fn()
        except Exception as exc:  # noqa: BLE001 -- best-effort, nunca propaga de close()
            _LOG.warning(
                "Falha ao fechar signing_strategy (clientId=%s): %s",
                self._client_id,
                exc,
            )

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
        """Levanta erro explícito se o cliente já tiver sido fechado.

        Raises:
            SmartTokenError: se :meth:`close` já tiver sido chamado.
        """
        if self._closed:
            raise SmartTokenError(
                f"SmartTokenClient (clientId={self._client_id}) já foi fechado (close());"
                " não é possível obter novos tokens"
            )

    def _fetch_token(self, normalized_scope: str):  # type: ignore[no-untyped-def]
        """Executa a obtenção real do token via rede, com retry em falha
        transitória de transporte (RF-01/RF-02/RF-03/RF-07).

        Um novo ``client_assertion`` (com ``jti`` próprio) e um novo
        ``TraceContext`` são gerados a cada tentativa real ao token
        endpoint, inclusive em retries (RF-01 item 7, RF-02 item 3).
        Retry só ocorre para falha de transporte classificada como
        transitória por ``ErrorClassifier`` -- qualquer resposta HTTP
        efetivamente recebida (inclusive 429/5xx) resulta em erro
        imediato, sem nova tentativa (RF-03 item 3/4, RF-07 item 2).

        Args:
            normalized_scope: scope já normalizado (``""`` para "sem
                scope").

        Returns:
            A resposta de sucesso validada
            (``response_guard.TokenResponse``).

        Raises:
            SmartTokenError: tentativas esgotadas em falha transitória,
                resposta HTTP != 200, ou suspeita de rejeição do
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
                # ``stream=True`` (via Client.stream(), não Client.post()) é
                # essencial para que o limite de tamanho do corpo em
                # response_guard.read_body() interrompa a leitura durante o
                # transporte -- sem streaming, httpx já baixa o corpo
                # inteiro para memória antes de response_guard poder agir,
                # tornando a proteção apenas cosmética.
                with self._http_client.stream("POST", self._token_endpoint, data=data, headers=headers) as response:
                    if response.status_code == 200:
                        return self._response_guard.parse_success_response(response, trace)
                    # Caminho de erro: também lê em streaming, respeitando o
                    # mesmo limite de tamanho (response.text exigiria o
                    # corpo inteiro já lido, o que httpx não faz sozinho em
                    # modo stream -- é preciso ler explicitamente aqui,
                    # ainda dentro do "with", antes da conexão ser fechada).
                    body_bytes = self._response_guard.read_body(response, trace)
                    body_text = body_bytes.decode("utf-8", errors="replace")
                    raise self._error_classifier.http_failure(response, trace, body_text)
            except httpx.RequestError as exc:
                # Relança diretamente se não-retriável (ou levanta
                # SmartTokenError quando a rejeição do certificado de
                # cliente é CONFIRMADA); devolve a exceção quando
                # retriável -- inclusive no sinal AMBÍGUO de rejeição do
                # certificado (ver ErrorClassifier.retriable_or_reraise) --
                # para a lógica de retry abaixo.
                last_exc = self._error_classifier.retriable_or_reraise(exc, trace)
                if attempt < max_retries:
                    _LOG.warning(
                        "Falha transitória ao obter token (tentativa %d/%d) clientId=%s traceId=%s: %s",
                        attempt,
                        max_retries,
                        self._client_id,
                        trace.trace_id,
                        last_exc,
                    )
                    time.sleep(compute_retry_delay_seconds(attempt))
                    continue
                # exhaustion_hint() acrescenta um alerta sobre possível
                # rejeição de certificado quando a última falha carrega
                # esse sinal ambíguo (string vazia nos demais casos).
                raise SmartTokenError(
                    f"Falha ao obter token para clientId={self._client_id} após {attempt}"
                    f" tentativa(s) (traceId={trace.trace_id}): {last_exc}."
                    f"{self._error_classifier.exhaustion_hint(last_exc)}",
                    last_exc,
                ) from last_exc

        # Inalcançável: o laço acima sempre retorna ou levanta antes de
        # terminar (max_retries >= 1, normalizado por FaultToleranceConfig).
        raise SmartTokenError(  # pragma: no cover -- guarda defensiva inalcançável, ver comentário acima
            f"estado inesperado: retry esgotado sem resultado para clientId={self._client_id}"
        )

    def _build_client_assertion(self) -> str:
        """Monta e assina um novo ``client_assertion`` (JWT, RF-01).

        Gera um JWS compacto (``header.payload.assinatura``), cada parte
        em Base64URL sem padding, com um ``jti`` (UUID) novo -- nunca
        reutilizado entre chamadas (RF-01 item 7).

        Returns:
            O JWT ``client_assertion`` compacto, pronto para o form body.

        Raises:
            SigningError: se a estratégia de assinatura falhar.
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

    Múltiplos leitores podem manter o lock simultaneamente; um escritor
    exige exclusividade total (nenhum leitor nem outro escritor ativo).
    Usado por :class:`SmartTokenClient` para permitir fan-out concorrente
    em ``obtain_token``/``obtain_token_response`` (leitores) enquanto
    ``close()`` (escritor) aguarda toda operação em voo terminar antes de
    liberar recursos (RNF-01).

    Implementado com um ``threading.Condition`` sobre um
    ``threading.Lock`` -- sem prioridade especial para escritores
    (aceitável aqui: ``close()`` é chamado no máximo uma vez, no
    encerramento do processo, então inanição do escritor por leitores
    contínuos não é um cenário realista para este uso).
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
    """Normaliza o scope para uso no cache/requisição (RF-04 item 1).

    Args:
        scope: scope informado pelo chamador (aceita ``None``).

    Returns:
        O scope com espaços laterais removidos; ``""`` quando ``None``.
    """
    if scope is None:
        return ""
    return scope.strip()


def _json_dumps(value: dict[str, object]) -> bytes:
    """Serializa um dict em JSON compacto (sem espaços), com *escaping*
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
        Representação Base64URL, sem caracteres ``=`` de padding.
    """
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

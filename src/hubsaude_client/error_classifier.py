"""Classifica falhas na obtencao de token: distingue falhas transitorias de
rede (elegiveis a retry) de falhas definitivas, reconhece o padrao de
rejeicao do certificado de cliente no mTLS e materializa respostas HTTP de
erro em ``SmartTokenError`` com corpo sanitizado.

Colaborador interno de ``SmartTokenClient``: concentra a taxonomia de
erros que, no cliente HTTP (``client.py``), inflaria a complexidade da
orquestracao principal. Nao faz parte da API publica da biblioteca (nao
exportado em ``__init__.py``).

Falhas de transporte tratadas como transitorias, elegiveis a retry, sao
listadas em ``_TRANSIENT_NETWORK_EXCEPTION_TYPES``: timeout de conexao ou
de requisicao (``httpx.TimeoutException`` e subclasses) e recusa/queda de
conexao TCP durante leitura ou escrita (``httpx.ConnectError``,
``httpx.ReadError``, ``httpx.WriteError``). Falhas de TLS
(``ssl.SSLError``) nunca sao tratadas como transitorias -- ver
:func:`is_transient_network_failure` e
:func:`is_likely_client_certificate_rejection`.

A stdlib ``ssl`` nao expoe um tipo proprio para "falha durante o
handshake": alertas TLS recebidos do servidor (ex.:
``certificate_revoked``) chegam como ``ssl.SSLError`` generico, entao a
identificacao de rejeicao do certificado de cliente usa o texto do
alerta (``_CLIENT_CERT_REJECTION_ALERT_FRAGMENTS``), cobrindo tanto o
codigo de alerta OpenSSL (com "_") quanto o texto descritivo (com
espaco).

O modulo ``ssl`` tambem nao expoe uma excecao propria para falha de tag
AEAD -- detalhe interno do OpenSSL, nao presente no binding Python.
Testes com handshake mTLS real (``tests/test_error_classifier_real_mtls.py``,
nao apenas ``ssl.SSLError`` simulado) confirmam como essa superficie se
manifesta na pratica: sob TLS 1.2, um certificado de cliente com CA
desconhecida do servidor produz ``ssl.SSLError`` com o alerta
``unknown ca`` do lado do cliente. Sob TLS 1.3 (protocolo padrao desta
lib, ver ``defaults.DEFAULT_TLS_PROTOCOL``), a superficie exata do erro
que chega ao cliente para o mesmo cenario de rejeicao **varia por
plataforma/versao do OpenSSL**: em algumas combinacoes (ex.:
``OpenSSL 3.0.13``) o cliente recebe ``ssl.SSLEOFError`` ("EOF occurred
in violation of protocol"), sem alerta textual reconhecivel; em outras,
o mesmo cenario produz um alerta ``unknown ca`` limpo, ja coberto pelo
fragmento acima. Essa variante ``ssl.SSLEOFError`` tambem
passou a ser reconhecida por
:func:`is_likely_client_certificate_rejection` (fragmento
``_TLS13_EOF_AFTER_HANDSHAKE_MESSAGE_FRAGMENT``, restrito ao tipo
exato ``ssl.SSLEOFError`` e a essa mensagem, para nao capturar EOFs
genuinamente transitorios). Em qualquer uma das duas variantes a
conexao e' relancada corretamente e nunca e' tratada como retriavel
(``is_transient_network_failure`` ja exclui todo ``ssl.SSLError``,
incluindo ``ssl.SSLEOFError``).

A cadeia de causas e' percorrida (``__cause__``, com fallback para
``__context__`` quando a excecao nao foi relancada explicitamente com
``raise ... from ...``) porque ``httpx``/``httpcore`` costumam envolver a
falha original numa excecao de nivel mais alto (ex.:
``httpx.ConnectError`` com ``__cause__`` apontando para o
``ssl.SSLError``/``OSError`` de origem).
"""

from __future__ import annotations

import re
import ssl
from typing import Final

import httpx

from hubsaude_client._log import get_logger
from hubsaude_client.exceptions import SmartTokenError
from hubsaude_client.trace import TraceContext

#: Codigo HTTP: Rate Limit Exceeded.
HTTP_TOO_MANY_REQUESTS: Final[int] = 429

#: Limite maximo para sanitizacao de respostas de erro.
_MAX_ERROR_RESPONSE_LENGTH: Final[int] = 500

#: Logger compartilhado com o restante da lib (ver _log.py): este
#: colaborador e' detalhe interno de implementacao e o contrato de
#: observabilidade (filtros de log por nome da classe publica) deve
#: permanecer estavel independente de como a implementacao interna e'
#: dividida em modulos.
_LOG = get_logger()

#: Padrao de token/access_token em JSON, para redacao antes do truncamento.
_JSON_TOKEN_PATTERN = re.compile(r'("(?:access_token|token)")\s*:\s*"[^"]*"')

#: Padrao de token/access_token form-encoded, para redacao antes do truncamento.
_FORM_TOKEN_PATTERN = re.compile(r"(access_token|token)=[^&\s]*")

#: Excecoes httpx que, na camada de transporte, representam falha
#: transitoria elegivel a retry: timeout (conexao ou requisicao) e
#: recusa/queda de conexao TCP durante leitura ou escrita.
_TRANSIENT_NETWORK_EXCEPTION_TYPES: Final[tuple[type[BaseException], ...]] = (
    httpx.TimeoutException,
    httpx.ConnectError,
    httpx.ReadError,
    httpx.WriteError,
)

#: Fragmentos de mensagem que indicam que o servidor encerrou a conexao
#: antes de qualquer byte de resposta (EOF prematuro).
_PREMATURE_EOF_MESSAGE_FRAGMENTS: Final[tuple[str, ...]] = (
    "received no bytes",
    "disconnected without sending a response",
)

#: Fragmentos de alerta/mensagem TLS que, fora do contexto de verificacao
#: local do certificado do SERVIDOR, indicam rejeicao do certificado de
#: CLIENTE pelo servidor durante o handshake mTLS (revogado, expirado, nao
#: confiavel, CA desconhecida, ou conexao corrompida apos o Finished).
#: Cobrem tanto o codigo de alerta OpenSSL (com "_") quanto o texto
#: descritivo (com espaco), ja que ``ssl.SSLError`` mistura os dois
#: conforme a plataforma.
#:
#: ``unknown_ca``/``unknown ca`` foi adicionado apos reproducao com
#: handshake mTLS real (TLS 1.2, ver
#: ``tests/test_error_classifier_real_mtls.py``): um certificado de
#: cliente assinado por uma CA que o servidor nao confia produz
#: exatamente esse alerta do lado do cliente, e o fragmento nao estava
#: coberto -- o caso mais comum de "certificado de cliente nao confiavel"
#: na pratica, nao apenas um caso de borda teorico.
_CLIENT_CERT_REJECTION_ALERT_FRAGMENTS: Final[tuple[str, ...]] = (
    "bad_record_mac",
    "bad record mac",
    "handshake_failure",
    "handshake failure",
    "certificate_revoked",
    "certificate revoked",
    "certificate_expired",
    "certificate expired",
    "certificate_unknown",
    "certificate unknown",
    "unknown_ca",
    "unknown ca",
    "decrypt_error",
    "decrypt error",
    "access_denied",
    "access denied",
)

#: Mensagem exata (minusculas) com que alguns builds de OpenSSL encerram a
#: conexao sob TLS 1.3, sem alerta textual reconhecivel, quando o servidor
#: rejeita o certificado de cliente apos o ``Finished`` (ver nota no topo
#: do modulo). So' e' considerada quando o tipo da excecao e' exatamente
#: ``ssl.SSLEOFError`` (nunca ``ssl.SSLError`` generico) para nao capturar
#: EOFs genuinamente transitorios (ex.: queda de conexao TCP antes do
#: handshake completar) que por acaso mencionem "EOF" na mensagem.
_TLS13_EOF_AFTER_HANDSHAKE_MESSAGE_FRAGMENT: Final[str] = "eof occurred in violation of protocol"


class ErrorClassifier:
    """Classificador de falhas na obtencao de token, ligado a um
    cliente/endpoint especificos.

    Colaborador interno de ``SmartTokenClient`` (``client.py``); nao faz
    parte da API publica da biblioteca.
    """

    __slots__ = ("_client_id", "_token_endpoint")

    def __init__(self, client_id: str, token_endpoint: str) -> None:
        """Cria o classificador para um cliente/endpoint especificos.

        Args:
            client_id: identificador do cliente (para logs).
            token_endpoint: URL do token endpoint (para mensagens de erro).
        """
        self._client_id = client_id
        self._token_endpoint = token_endpoint

    def retriable_or_reraise(self, exc: httpx.RequestError, trace: TraceContext) -> httpx.RequestError:
        """Classifica a excecao de transporte: devolve-a quando representa
        falha transitoria de rede (timeout de conexao ou de requisicao,
        recusa ou queda de conexao TCP) para que o chamador realize retry;
        caso contrario, relanca.

        Args:
            exc: excecao capturada na tentativa.
            trace: contexto de trace W3C enviado na tentativa que falhou.

        Returns:
            A propria excecao, quando retriavel.

        Raises:
            httpx.RequestError: quando a excecao nao e' retriavel.
            SmartTokenError: quando a falha aparenta ser rejeicao do
                certificado de cliente no mTLS.
        """
        if is_likely_client_certificate_rejection(exc):
            _LOG.error(
                "Falha de TLS apos handshake mTLS para clientId=%s endpoint=%s "
                "traceId=%s: %s. Causa provavel: certificado de cliente rejeitado "
                "pelo servidor (revogado, expirado ou nao confiavel) — o servidor "
                "abortou a conexao em vez de retornar uma resposta HTTP de erro.",
                self._client_id,
                self._token_endpoint,
                trace.trace_id,
                exc,
            )
            raise SmartTokenError(
                "Conexao TLS abortada pelo servidor apos o handshake mTLS contra "
                f"{self._token_endpoint}. Causa provavel: certificado de cliente "
                "rejeitado (revogado, expirado ou nao confiavel). Verifique a "
                "validade do certificado em uso e, se ele estiver correto, "
                "contate o operador do servidor de autorizacao — a resposta "
                "esperada nesse cenario seria um alerta TLS "
                "(certificate_revoked/certificate_expired) ou HTTP 401, e nao "
                "o encerramento abrupto da conexao.",
                exc,
            ) from exc
        if is_transient_network_failure(exc):
            return exc
        raise exc

    def http_failure(
        self,
        response: httpx.Response,
        trace: TraceContext,
        body_text: str | None = None,
    ) -> SmartTokenError:
        """Materializa uma resposta HTTP de erro (status != 200) em
        ``SmartTokenError``, registrando o log adequado: WARNING para rate
        limit (HTTP 429, sem retry automatico) e ERROR para os demais.

        Args:
            response: resposta recebida do servidor de autorizacao.
            trace: contexto de trace W3C enviado na requisicao.
            body_text: corpo da resposta ja lido pelo chamador (ex.: via
                ``TokenResponseGuard.read_body`` sobre uma resposta em
                streaming, respeitando o limite de tamanho). Quando ``None`` (compatibilidade com
                chamadores que ja tem a resposta integralmente lida em
                memoria, ex.: ``discovery.py`` e os testes deste modulo),
                cai de volta para ``response.text``.

        Returns:
            Excecao pronta para ser lancada pelo chamador.
        """
        status_code = response.status_code
        if status_code == HTTP_TOO_MANY_REQUESTS:
            _LOG.warning(
                "Rate limit (HTTP 429) para clientId=%s traceId=%s — sem retry automatico",
                self._client_id,
                trace.trace_id,
            )
        else:
            _LOG.error(
                "Falha ao obter token: HTTP %s para clientId=%s traceId=%s",
                status_code,
                self._client_id,
                trace.trace_id,
            )
        return SmartTokenError(_build_http_error_message(status_code, response, trace, body_text))


def is_transient_network_failure(exc: BaseException) -> bool:
    """Identifica falhas transitorias de rede elegiveis a retry: timeout de
    conexao ou de requisicao HTTP e recusa/queda de conexao TCP (conexao
    recusada, connection reset ou EOF prematuro).

    A cadeia de causas e' percorrida porque ``httpx``/``httpcore``
    frequentemente envolvem a causa original numa excecao de transporte
    generica (ex.: ``httpx.ConnectError`` com causa ``ConnectionRefusedError``,
    ou ``httpx.RemoteProtocolError`` quando o servidor encerra a conexao
    antes de qualquer byte de resposta). Falhas da camada TLS
    (``ssl.SSLError``) nunca sao consideradas transitorias — sao tratadas
    pela heuristica de :func:`is_likely_client_certificate_rejection` ou
    propagadas como estao.

    Nota de implementacao: ``httpx``/``httpcore`` costumam envolver uma
    falha de handshake TLS numa excecao de transporte mais generica (ex.:
    ``httpx.ConnectError``), que por si so' tambem casaria com a checagem
    de falha transitoria se avaliada ingenuamente. Por isso aqui a cadeia e'
    percorrida em duas passagens: primeiro se confirma a ausencia de
    qualquer ``ssl.SSLError`` em toda a cadeia (preservando a garantia de
    que falha TLS nunca e' transitoria, custe a posicao em que apareca),
    so' depois os tipos de falha de transporte transitoria sao checados.

    Args:
        exc: excecao de transporte capturada na tentativa.

    Returns:
        ``True`` quando a falha e' transitoria de rede.
    """
    chain = _cause_chain(exc)
    if any(isinstance(cause, ssl.SSLError) for cause in chain):
        return False
    for cause in chain:
        if isinstance(cause, _TRANSIENT_NETWORK_EXCEPTION_TYPES):
            return True
        message = str(cause).lower()
        if any(fragment in message for fragment in _PREMATURE_EOF_MESSAGE_FRAGMENTS):
            return True
    return False


def is_likely_client_certificate_rejection(exc: BaseException | None) -> bool:
    """Heuristica para identificar falhas de TLS que tipicamente indicam
    que o servidor rejeitou o certificado de cliente (revogado, expirado
    ou nao confiavel) sem produzir uma resposta HTTP de erro adequada.

    Sao tratadas como suspeitas: qualquer ``ssl.SSLError`` (exceto
    ``ssl.SSLCertVerificationError``, ver abaixo) cuja mensagem contenha um
    alerta TLS tipico desse cenario (``handshake_failure``,
    ``certificate_revoked``, ``certificate_expired``, ``certificate_unknown``,
    ``unknown_ca``, ``bad_record_mac``, ``decrypt_error``, ``access_denied``
    — ver nota no topo do modulo); e qualquer
    ``ssl.SSLEOFError`` (tipo exato, nao ``ssl.SSLError`` generico) cuja
    mensagem seja a variante sem alerta textual que builds de OpenSSL sob
    TLS 1.3 produzem para o mesmo cenario. Validado com handshake mTLS
    real sob TLS 1.2 (alerta ``unknown ca``) e sob TLS 1.3 (ambas as
    superficies observadas: alerta limpo e ``ssl.SSLEOFError``) — ver
    ``tests/test_error_classifier_real_mtls.py``.

    Falhas cuja cadeia de causas contenha ``ssl.SSLCertVerificationError``
    sao excluidas: indicam que foi ESTE cliente que rejeitou o certificado
    do servidor (ex.: "certificate verify failed" por trust anchor ausente
    ou incorreto), e nao o contrario.

    Esta verificacao e' heuristica e deve ser usada apenas para enriquecer
    mensagens de erro; nao substitui o diagnostico do servidor.

    Args:
        exc: excecao a inspecionar (aceita ``None``).

    Returns:
        ``True`` quando o padrao sugere rejeicao do certificado de cliente
        pelo servidor.
    """
    chain = _cause_chain(exc)
    if any(isinstance(cause, ssl.SSLCertVerificationError) for cause in chain):
        # Cliente rejeitou o certificado do SERVIDOR (validacao local do
        # trust anchor) — nao e' rejeicao mTLS pelo servidor.
        return False
    for cause in chain:
        if isinstance(cause, ssl.SSLEOFError):
            message = str(cause).lower()
            if _TLS13_EOF_AFTER_HANDSHAKE_MESSAGE_FRAGMENT in message:
                return True
            continue
        if isinstance(cause, ssl.SSLError):
            message = str(cause).lower()
            if any(fragment in message for fragment in _CLIENT_CERT_REJECTION_ALERT_FRAGMENTS):
                return True
    return False


def sanitize_error_response(response_body: str | None) -> str:
    """Sanitiza a resposta de erro para evitar vazamento de tokens em logs.

    A redacao de tokens e' aplicada antes do truncamento, garantindo que
    nenhum token apareca mesmo em respostas longas.

    Args:
        response_body: corpo da resposta HTTP (aceita ``None``).

    Returns:
        Resposta sanitizada.
    """
    if response_body is None:
        return "<empty>"
    # Remove possiveis tokens do erro (JSON e form-encoded) ANTES de truncar.
    redacted = _JSON_TOKEN_PATTERN.sub(r'\1:"[REDACTED]"', response_body)
    redacted = _FORM_TOKEN_PATTERN.sub(r"\1=[REDACTED]", redacted)
    if len(redacted) > _MAX_ERROR_RESPONSE_LENGTH:
        return redacted[:_MAX_ERROR_RESPONSE_LENGTH] + "..."
    return redacted


def _build_http_error_message(
    status_code: int,
    response: httpx.Response,
    trace: TraceContext,
    body_text: str | None = None,
) -> str:
    """Monta a mensagem de erro para resposta HTTP != 200: status,
    trace-id enviado na requisicao (correlaciona com o ``correlation-id``
    da plataforma), valor de ``Retry-After`` quando presente (apenas
    diagnostico — nenhuma resposta HTTP recebida sofre retry automatico; a
    decisao de aguardar e reenviar e' do chamador) e corpo sanitizado.

    Args:
        status_code: status HTTP da resposta.
        response: resposta recebida do servidor de autorizacao.
        trace: contexto de trace W3C enviado na requisicao.
        body_text: corpo ja lido pelo chamador (ver ``http_failure``);
            quando ``None``, usa ``response.text``.

    Returns:
        Mensagem de erro pronta para ``SmartTokenError``.
    """
    retry_after = response.headers.get("Retry-After")
    retry_after_part = f" (Retry-After: {retry_after.strip()})" if retry_after else ""
    hint = (
        " Rate limit atingido; a decisao de aguardar e reenviar e' do chamador."
        if status_code == HTTP_TOO_MANY_REQUESTS
        else ""
    )
    text = response.text if body_text is None else body_text
    return (
        f"Falha ao obter token: HTTP {status_code}{retry_after_part}"
        f" (traceId={trace.trace_id})"
        f" — {sanitize_error_response(text)}{hint}"
    )


def _cause_chain(exc: BaseException | None) -> list[BaseException]:
    """Percorre a cadeia de causas de uma excecao (``__cause__``, com
    fallback para ``__context__`` quando nao houve ``raise ... from ...``
    explicito).

    Protegido contra ciclos (excecoes nao devem formar ciclo, mas a
    travessia nao deve travar caso um cause aponte para si mesmo/anterior).

    Args:
        exc: excecao inicial da cadeia (aceita ``None``).

    Returns:
        Lista com a excecao inicial e todas as suas causas, na ordem.
    """
    chain: list[BaseException] = []
    seen: set[int] = set()
    current = exc
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        chain.append(current)
        current = current.__cause__ if current.__cause__ is not None else current.__context__
    return chain

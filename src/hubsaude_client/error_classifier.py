"""Classifica falhas na obtenção de token: distingue falhas transitórias de
rede (elegíveis a retry) de falhas definitivas, reconhece o padrão de
rejeição do certificado de cliente no mTLS e materializa respostas HTTP de
erro em ``SmartTokenError`` com corpo sanitizado.

Colaborador interno de ``SmartTokenClient``: concentra a taxonomia de
erros que, no cliente HTTP (``client.py``), inflaria a complexidade da
orquestração principal. Não faz parte da API pública da biblioteca (não
exportado em ``__init__.py``).

Falhas de transporte tratadas como transitórias por
:func:`is_transient_network_failure`, elegíveis a retry, são listadas em
``_TRANSIENT_NETWORK_EXCEPTION_TYPES``: timeout de conexão ou de
requisição (``httpx.TimeoutException`` e subclasses) e recusa/queda de
conexão TCP durante leitura ou escrita (``httpx.ConnectError``,
``httpx.ReadError``, ``httpx.WriteError``). Falhas de TLS
(``ssl.SSLError``) nunca são consideradas transitórias por essa função.
Isso não significa, porém, que toda falha de TLS interrompe o retry: ver
:func:`is_likely_client_certificate_rejection` e
:class:`CertRejectionConfidence` -- o sinal CONFIRMED interrompe
imediatamente, mas o sinal PROBABLE (ambíguo) é tratado como retriável
por :meth:`ErrorClassifier.retriable_or_reraise`, por caminho separado
de :func:`is_transient_network_failure`.

A stdlib ``ssl`` não expõe um tipo próprio para "falha durante o
handshake": alertas TLS recebidos do servidor (ex.:
``certificate_revoked``) chegam como ``ssl.SSLError`` genérico, então a
identificação de rejeição do certificado de cliente usa o texto do
alerta (``_CLIENT_CERT_REJECTION_ALERT_FRAGMENTS``), cobrindo tanto o
código de alerta OpenSSL (com "_") quanto o texto descritivo (com
espaço).

O módulo ``ssl`` também não expõe uma exceção própria para falha de tag
AEAD -- detalhe interno do OpenSSL, não presente no binding Python.
Testes com handshake mTLS real (``tests/test_error_classifier_real_mtls.py``,
não apenas ``ssl.SSLError`` simulado) confirmam como essa superfície se
manifesta na prática: sob TLS 1.2, um certificado de cliente com CA
desconhecida do servidor produz ``ssl.SSLError`` com o alerta
``unknown ca`` do lado do cliente. Sob TLS 1.3 (protocolo padrão desta
lib, ver ``defaults.DEFAULT_TLS_PROTOCOL``), a superfície exata do erro
que chega ao cliente para o mesmo cenário de rejeição **varia por
plataforma/versão do OpenSSL**: em algumas combinações (ex.:
``OpenSSL 3.0.13``) o cliente recebe ``ssl.SSLEOFError`` ("EOF occurred
in violation of protocol"), sem alerta textual reconhecível; em outras,
o mesmo cenário produz um alerta ``unknown ca`` limpo, já coberto pelo
fragmento acima. Essa variante ``ssl.SSLEOFError`` também
passou a ser reconhecida por
:func:`is_likely_client_certificate_rejection` (fragmento
``_TLS13_EOF_AFTER_HANDSHAKE_MESSAGE_FRAGMENT``, restrito ao tipo
exato ``ssl.SSLEOFError`` e a essa mensagem, para não capturar EOFs
genuinamente transitórios) -- mas como sinal ``PROBABLE``, não
``CONFIRMED`` (ver :class:`CertRejectionConfidence`): o mesmo texto
também pode surgir de uma instabilidade de rede comum sem relação com o
certificado, então essa variante não interrompe o retry por si só,
diferente do alerta limpo (``CONFIRMED``). Em nenhuma das duas variantes
a exceção é tratada como transitória por
``is_transient_network_failure`` (que já exclui todo ``ssl.SSLError``,
incluindo ``ssl.SSLEOFError``) -- a retriabilidade do sinal ``PROBABLE``
vem de um caminho separado, em
:meth:`ErrorClassifier.retriable_or_reraise`.

A cadeia de causas é percorrida (``__cause__``, com fallback para
``__context__`` quando a exceção não foi relançada explicitamente com
``raise ... from ...``) porque ``httpx``/``httpcore`` costumam envolver a
falha original numa exceção de nível mais alto (ex.:
``httpx.ConnectError`` com ``__cause__`` apontando para o
``ssl.SSLError``/``OSError`` de origem).
"""

from __future__ import annotations

import enum
import re
import ssl
from typing import Final

import httpx

from hubsaude_client._log import get_logger
from hubsaude_client.exceptions import SmartTokenError
from hubsaude_client.trace import TraceContext

#: Código HTTP: Rate Limit Exceeded.
HTTP_TOO_MANY_REQUESTS: Final[int] = 429

#: Limite máximo para sanitização de respostas de erro.
_MAX_ERROR_RESPONSE_LENGTH: Final[int] = 500

#: Logger compartilhado com o restante da lib (ver _log.py): este
#: colaborador é detalhe interno de implementação e o contrato de
#: observabilidade (filtros de log por nome da classe pública) deve
#: permanecer estável independente de como a implementação interna é
#: dividida em módulos.
_LOG = get_logger()

#: Padrão de token/access_token em JSON, para redação antes do truncamento.
_JSON_TOKEN_PATTERN = re.compile(r'("(?:access_token|token)")\s*:\s*"[^"]*"')

#: Padrão de token/access_token form-encoded, para redação antes do truncamento.
_FORM_TOKEN_PATTERN = re.compile(r"(access_token|token)=[^&\s]*")

#: Exceções httpx que, na camada de transporte, representam falha
#: transitória elegível a retry: timeout (conexão ou requisição) e
#: recusa/queda de conexão TCP durante leitura ou escrita.
_TRANSIENT_NETWORK_EXCEPTION_TYPES: Final[tuple[type[BaseException], ...]] = (
    httpx.TimeoutException,
    httpx.ConnectError,
    httpx.ReadError,
    httpx.WriteError,
)

#: Fragmentos de mensagem que indicam que o servidor encerrou a conexão
#: antes de qualquer byte de resposta (EOF prematuro).
_PREMATURE_EOF_MESSAGE_FRAGMENTS: Final[tuple[str, ...]] = (
    "received no bytes",
    "disconnected without sending a response",
)

#: Fragmentos de alerta/mensagem TLS que, fora do contexto de verificação
#: local do certificado do SERVIDOR, indicam rejeição do certificado de
#: CLIENTE pelo servidor durante o handshake mTLS (revogado, expirado, não
#: confiável, CA desconhecida, ou conexão corrompida após o Finished).
#: Cobrem tanto o código de alerta OpenSSL (com "_") quanto o texto
#: descritivo (com espaço), já que ``ssl.SSLError`` mistura os dois
#: conforme a plataforma.
#:
#: ``unknown_ca``/``unknown ca`` foi adicionado após reprodução com
#: handshake mTLS real (TLS 1.2, ver
#: ``tests/test_error_classifier_real_mtls.py``): um certificado de
#: cliente assinado por uma CA que o servidor não confia produz
#: exatamente esse alerta do lado do cliente, e o fragmento não estava
#: coberto -- o caso mais comum de "certificado de cliente não confiável"
#: na prática, não apenas um caso de borda teórico.
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

#: Mensagem exata (minúsculas) com que alguns builds de OpenSSL encerram a
#: conexão sob TLS 1.3, sem alerta textual reconhecível, quando o servidor
#: rejeita o certificado de cliente após o ``Finished`` (ver nota no topo
#: do módulo). Só é considerada quando o tipo da exceção é exatamente
#: ``ssl.SSLEOFError`` (nunca ``ssl.SSLError`` genérico) para não capturar
#: EOFs genuinamente transitórios (ex.: queda de conexão TCP antes do
#: handshake completar) que por acaso mencionem "EOF" na mensagem.
_TLS13_EOF_AFTER_HANDSHAKE_MESSAGE_FRAGMENT: Final[str] = "eof occurred in violation of protocol"


class CertRejectionConfidence(enum.Enum):
    """Nível de confiança de que uma falha de TLS representa rejeição do
    certificado de cliente pelo servidor, devolvido por
    :func:`is_likely_client_certificate_rejection`.

    Os dois níveis existem porque nem todo sinal reconhecido tem a mesma
    força: um alerta TLS explícito do servidor é inequívoco, mas um
    ``ssl.SSLEOFError`` sem alerta textual (variante observada sob TLS
    1.3, ver nota no topo do módulo) também pode ser apenas uma
    instabilidade de rede comum, sem relação com o certificado.
    """

    #: Nenhum sinal reconhecido de rejeição do certificado de cliente.
    NONE = "none"
    #: Sinal ambíguo (``ssl.SSLEOFError`` sem alerta textual explícito) --
    #: não deve interromper o retry por si só, apenas enriquecer a
    #: mensagem de erro final caso as tentativas se esgotem por outro
    #: motivo.
    PROBABLE = "probable"
    #: Alerta TLS explícito e inequívoco recebido do servidor --
    #: interrompe o retry imediatamente.
    CONFIRMED = "confirmed"


class ErrorClassifier:
    """Classificador de falhas na obtenção de token, ligado a um
    cliente/endpoint específicos.

    Colaborador interno de ``SmartTokenClient`` (``client.py``); não faz
    parte da API pública da biblioteca.
    """

    __slots__ = ("_client_id", "_token_endpoint")

    def __init__(self, client_id: str, token_endpoint: str) -> None:
        """Cria o classificador para um cliente/endpoint específicos.

        Args:
            client_id: identificador do cliente (para logs).
            token_endpoint: URL do token endpoint (para mensagens de erro).
        """
        self._client_id = client_id
        self._token_endpoint = token_endpoint

    def retriable_or_reraise(self, exc: httpx.RequestError, trace: TraceContext) -> httpx.RequestError:
        """Classifica a exceção de transporte: devolve-a quando representa
        falha transitória de rede (timeout de conexão ou de requisição,
        recusa ou queda de conexão TCP) ou sinal AMBÍGUO de rejeição do
        certificado de cliente (``CertRejectionConfidence.PROBABLE``) para
        que o chamador realize retry; caso contrário, relança.

        Só o sinal CONFIRMADO (``CertRejectionConfidence.CONFIRMED`` --
        alerta TLS explícito e inequívoco) interrompe o retry
        imediatamente. O sinal PROVÁVEL (``ssl.SSLEOFError`` sem alerta
        textual, ver :class:`CertRejectionConfidence`) é tratado como
        retriável: pode ser rejeição de certificado, mas também pode ser
        apenas instabilidade de rede comum, e não há como distinguir os
        dois casos só com essa exceção -- interromper o retry por um sinal
        ambíguo negaria ao mecanismo de recuperação a chance de atuar.
        Quando o retry se esgota com esse sinal na última tentativa, o
        chamador deve enriquecer a mensagem final com
        :meth:`exhaustion_hint`.

        Args:
            exc: exceção capturada na tentativa.
            trace: contexto de trace W3C enviado na tentativa que falhou.

        Returns:
            A própria exceção, quando retriável.

        Raises:
            httpx.RequestError: quando a exceção não é retriável.
            SmartTokenError: quando a falha é confirmada como rejeição do
                certificado de cliente no mTLS.
        """
        confidence = is_likely_client_certificate_rejection(exc)
        if confidence is CertRejectionConfidence.CONFIRMED:
            _LOG.error(
                "Falha de TLS após handshake mTLS para clientId=%s endpoint=%s "
                "traceId=%s: %s. Causa provável: certificado de cliente rejeitado "
                "pelo servidor (revogado, expirado ou não confiável) — o servidor "
                "abortou a conexão em vez de retornar uma resposta HTTP de erro.",
                self._client_id,
                self._token_endpoint,
                trace.trace_id,
                exc,
            )
            raise SmartTokenError(
                "Conexão TLS abortada pelo servidor após o handshake mTLS contra "
                f"{self._token_endpoint}. Causa provável: certificado de cliente "
                "rejeitado (revogado, expirado ou não confiável). Verifique a "
                "validade do certificado em uso e, se ele estiver correto, "
                "contate o operador do servidor de autorização — a resposta "
                "esperada nesse cenário seria um alerta TLS "
                "(certificate_revoked/certificate_expired) ou HTTP 401, e não "
                "o encerramento abrupto da conexão.",
                exc,
            )
        if confidence is CertRejectionConfidence.PROBABLE or is_transient_network_failure(exc):
            return exc
        raise exc

    def exhaustion_hint(self, last_exc: BaseException) -> str:
        """Complemento textual para a mensagem final de erro quando o
        retry se esgota, usado apenas quando a última falha carrega um
        sinal AMBÍGUO (``CertRejectionConfidence.PROBABLE``) de rejeição
        do certificado de cliente -- ver :meth:`retriable_or_reraise` e
        :class:`CertRejectionConfidence`. Retorna string vazia nos demais
        casos.

        Diferente do sinal CONFIRMADO (que interrompe o retry
        imediatamente com uma mensagem dedicada), o sinal PROVÁVEL deixa o
        retry seguir seu curso normal; esta dica evita descartar essa
        pista caso, mesmo assim, todas as tentativas se esgotem.

        Args:
            last_exc: última exceção capturada antes do retry se esgotar.

        Returns:
            Trecho adicional pronto para concatenar na mensagem final
            (começa com espaço), ou string vazia.
        """
        if is_likely_client_certificate_rejection(last_exc) is CertRejectionConfidence.PROBABLE:
            return (
                " Um sinal ambíguo de possível rejeição do certificado de "
                "cliente pelo servidor também foi observado na última "
                "tentativa (EOF após o handshake mTLS, sem alerta TLS "
                "explícito) — considere verificar a validade do "
                "certificado em uso."
            )
        return ""

    def http_failure(
        self,
        response: httpx.Response,
        trace: TraceContext,
        body_text: str | None = None,
    ) -> SmartTokenError:
        """Materializa uma resposta HTTP de erro (status != 200) em
        ``SmartTokenError``, registrando o log adequado: WARNING para rate
        limit (HTTP 429, sem retry automático) e ERROR para os demais.

        Args:
            response: resposta recebida do servidor de autorização.
            trace: contexto de trace W3C enviado na requisição.
            body_text: corpo da resposta já lido pelo chamador (ex.: via
                ``TokenResponseGuard.read_body`` sobre uma resposta em
                streaming, respeitando o limite de tamanho). Quando ``None`` (compatibilidade com
                chamadores que já têm a resposta integralmente lida em
                memória, ex.: ``discovery.py`` e os testes deste módulo),
                cai de volta para ``response.text``.

        Returns:
            Exceção pronta para ser lançada pelo chamador.
        """
        status_code = response.status_code
        if status_code == HTTP_TOO_MANY_REQUESTS:
            _LOG.warning(
                "Rate limit (HTTP 429) para clientId=%s traceId=%s — sem retry automático",
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
    """Identifica falhas transitórias de rede elegíveis a retry: timeout de
    conexão ou de requisição HTTP e recusa/queda de conexão TCP (conexão
    recusada, connection reset ou EOF prematuro).

    A cadeia de causas é percorrida porque ``httpx``/``httpcore``
    frequentemente envolvem a causa original numa exceção de transporte
    genérica (ex.: ``httpx.ConnectError`` com causa ``ConnectionRefusedError``,
    ou ``httpx.RemoteProtocolError`` quando o servidor encerra a conexão
    antes de qualquer byte de resposta). Falhas da camada TLS
    (``ssl.SSLError``) nunca são consideradas transitórias — são tratadas
    pela heurística de :func:`is_likely_client_certificate_rejection` ou
    propagadas como estão.

    Nota de implementação: ``httpx``/``httpcore`` costumam envolver uma
    falha de handshake TLS numa exceção de transporte mais genérica (ex.:
    ``httpx.ConnectError``), que por si só também casaria com a checagem
    de falha transitória se avaliada ingenuamente. Por isso aqui a cadeia é
    percorrida em duas passagens: primeiro se confirma a ausência de
    qualquer ``ssl.SSLError`` em toda a cadeia (preservando a garantia de
    que falha TLS nunca é transitória, custe a posição em que apareça),
    só depois os tipos de falha de transporte transitória são checados.

    Args:
        exc: exceção de transporte capturada na tentativa.

    Returns:
        ``True`` quando a falha é transitória de rede.
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


def is_likely_client_certificate_rejection(exc: BaseException | None) -> CertRejectionConfidence:
    """Heurística para identificar falhas de TLS que tipicamente indicam
    que o servidor rejeitou o certificado de cliente (revogado, expirado
    ou não confiável) sem produzir uma resposta HTTP de erro adequada.
    Distingue dois níveis de confiança (ver :class:`CertRejectionConfidence`):

    CONFIRMED: qualquer ``ssl.SSLError`` (exceto
    ``ssl.SSLCertVerificationError``, ver abaixo) cuja mensagem contenha um
    alerta TLS típico e inequívoco desse cenário (``handshake_failure``,
    ``certificate_revoked``, ``certificate_expired``, ``certificate_unknown``,
    ``unknown_ca``, ``bad_record_mac``, ``decrypt_error``, ``access_denied``
    — ver nota no topo do módulo).

    PROBABLE: qualquer ``ssl.SSLEOFError`` (tipo exato, não
    ``ssl.SSLError`` genérico) cuja mensagem seja a variante sem alerta
    textual que builds de OpenSSL sob TLS 1.3 produzem para o mesmo
    cenário -- sinal ambíguo, já que o mesmo texto também pode surgir de
    uma instabilidade de rede comum sem relação com o certificado.

    Validado com handshake mTLS real sob TLS 1.2 (alerta ``unknown ca``,
    CONFIRMED) e sob TLS 1.3 (ambas as superfícies observadas: alerta
    limpo CONFIRMED e ``ssl.SSLEOFError`` PROBABLE) — ver
    ``tests/test_error_classifier_real_mtls.py``.

    Falhas cuja cadeia de causas contenha ``ssl.SSLCertVerificationError``
    são excluídas (``NONE``): indicam que foi ESTE cliente que rejeitou o
    certificado do servidor (ex.: "certificate verify failed" por trust
    anchor ausente ou incorreto), e não o contrário.

    Esta verificação é heurística e deve ser usada apenas para decidir
    interromper o retry (CONFIRMED) ou enriquecer a mensagem de erro final
    (PROBABLE); não substitui o diagnóstico do servidor.

    Args:
        exc: exceção a inspecionar (aceita ``None``).

    Returns:
        O nível de confiança de que o padrão observado indica rejeição do
        certificado de cliente pelo servidor.
    """
    chain = _cause_chain(exc)
    if any(isinstance(cause, ssl.SSLCertVerificationError) for cause in chain):
        # Cliente rejeitou o certificado do SERVIDOR (validação local do
        # trust anchor) — não é rejeição mTLS pelo servidor.
        return CertRejectionConfidence.NONE
    for cause in chain:
        if isinstance(cause, ssl.SSLEOFError):
            message = str(cause).lower()
            if _TLS13_EOF_AFTER_HANDSHAKE_MESSAGE_FRAGMENT in message:
                return CertRejectionConfidence.PROBABLE
            continue
        if isinstance(cause, ssl.SSLError):
            message = str(cause).lower()
            if any(fragment in message for fragment in _CLIENT_CERT_REJECTION_ALERT_FRAGMENTS):
                return CertRejectionConfidence.CONFIRMED
    return CertRejectionConfidence.NONE


def sanitize_error_response(response_body: str | None) -> str:
    """Sanitiza a resposta de erro para evitar vazamento de tokens em logs.

    A redação de tokens é aplicada antes do truncamento, garantindo que
    nenhum token apareça mesmo em respostas longas.

    Args:
        response_body: corpo da resposta HTTP (aceita ``None``).

    Returns:
        Resposta sanitizada.
    """
    if response_body is None:
        return "<empty>"
    # Remove possíveis tokens do erro (JSON e form-encoded) ANTES de truncar.
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
    trace-id enviado na requisição (correlaciona com o ``correlation-id``
    da plataforma), valor de ``Retry-After`` quando presente (apenas
    diagnóstico — nenhuma resposta HTTP recebida sofre retry automático; a
    decisão de aguardar e reenviar é do chamador) e corpo sanitizado.

    Args:
        status_code: status HTTP da resposta.
        response: resposta recebida do servidor de autorização.
        trace: contexto de trace W3C enviado na requisição.
        body_text: corpo já lido pelo chamador (ver ``http_failure``);
            quando ``None``, usa ``response.text``.

    Returns:
        Mensagem de erro pronta para ``SmartTokenError``.
    """
    retry_after = response.headers.get("Retry-After")
    retry_after_part = f" (Retry-After: {retry_after.strip()})" if retry_after else ""
    hint = (
        " Rate limit atingido; a decisão de aguardar e reenviar é do chamador."
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
    """Percorre a cadeia de causas de uma exceção (``__cause__``, com
    fallback para ``__context__`` quando não houve ``raise ... from ...``
    explícito).

    Protegido contra ciclos (exceções não devem formar ciclo, mas a
    travessia não deve travar caso um cause aponte para si mesmo/anterior).

    Args:
        exc: exceção inicial da cadeia (aceita ``None``).

    Returns:
        Lista com a exceção inicial e todas as suas causas, na ordem.
    """
    chain: list[BaseException] = []
    seen: set[int] = set()
    current = exc
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        chain.append(current)
        current = current.__cause__ if current.__cause__ is not None else current.__context__
    return chain

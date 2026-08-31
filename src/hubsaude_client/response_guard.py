"""Valida e sanitiza a resposta bem-sucedida (HTTP 200) do token endpoint:
impoe um limite de tamanho no corpo lido via streaming (protegendo contra
corpos anormalmente grandes, maliciosos ou por bug do servidor) e sanitiza
o campo ``expires_in``, aplicando o padrao documentado quando ausente ou
invalido.

Porte de ``TokenResponseGuard.java`` (colaborador interno de
``SmartTokenClient``). Nao
faz parte da API publica da biblioteca (nao exportado em ``__init__.py``).

- o valor exato de ``MAX_RESPONSE_BODY_BYTES`` usado em producao no Java
  (aqui adotado 1 MiB, sem referencia direta -- ver comentario na
  constante abaixo, que coincide com o valor documentado no ``.java``);
- ``expires_in`` como string numerica e' aceito (por tolerancia a
  respostas nao estritamente conformes); qualquer outro tipo diferente
  de inteiro/float/string numerica e' tratado como invalido de imediato
  -- decisao alinhada ao Java: ``expires_in``
  *ausente* aplica o padrao silenciosamente, mas ``expires_in``
  *presente e invalido* (zero, negativo ou nao numerico) e' rejeitado
  com ``SmartTokenError`` em vez de absorvido com um warning -- um
  ``expires_in`` adulterado nao pode reter tokens no cache (a mesma
  protecao da issue #730 do Java). Um ``expires_in`` valido mas acima do
  teto de sanidade (``MAX_EXPIRES_IN_SECONDS``, 24h) e' normalizado para
  o teto com apenas um warning, tambem espelhando o Java.

Validacao de sucesso (RF-03, ``ESPECIFICACAO.md``):

- Exclusivamente HTTP 200 e sucesso -- decidir se a resposta vai para
  este guard (sucesso) ou para ``ErrorClassifier.http_failure`` (demais
  status) e responsabilidade do chamador (``client.py``); este modulo
  nao inspeciona ``response.status_code``.
- ``access_token`` ausente ou vazio e erro (``SmartTokenError``).
- ``expires_in`` ausente recebe o padrao documentado
  (``DEFAULT_EXPIRES_IN_SECONDS``, 3600s -- RF-03.2); presente mas
  invalido e' erro (``SmartTokenError``); presente, valido e acima de
  ``MAX_EXPIRES_IN_SECONDS`` e' normalizado para o teto. Campos
  desconhecidos sao ignorados pela validacao mas o corpo JSON cru fica
  disponivel ao chamador via ``TokenResponse.raw``.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Final

import httpx

from hubsaude_client._log import get_logger
from hubsaude_client.defaults import DEFAULT_EXPIRES_IN_SECONDS
from hubsaude_client.exceptions import SmartTokenError
from hubsaude_client.trace import TraceContext

#: Limite maximo padrao do corpo da resposta do token endpoint, em bytes.
#: Mantido local (nao em defaults.py): ``discovery.py`` (Tarefa 3/B6, ja
#: concluida) le o corpo da resposta de descoberta via
#: ``response.json()`` diretamente, sem limite de tamanho em streaming --
#: nao e um segundo consumidor deste valor. Continua sem outro
#: colaborador da lib que precise do mesmo limite; se isso mudar, mover
#: para defaults.py nesse momento (mesmo criterio ja aplicado aqui a
#: DEFAULT_EXPIRES_IN_SECONDS, que foi para defaults.py por ja nascer
#: como constante DEFAULT_* neutra).
MAX_RESPONSE_BODY_BYTES: Final[int] = 1_048_576  # 1 MiB

#: Teto de sanidade para ``expires_in``, em segundos (24h). Valores
#: validos acima deste teto sao normalizados para ele antes de
#: alimentar o cache de tokens (nao e' um erro -- apenas um limite
#: superior de sanidade). Mantido local pela mesma razao de
#: ``MAX_RESPONSE_BODY_BYTES`` acima: nenhum outro colaborador da lib
#: precisa deste valor hoje.
MAX_EXPIRES_IN_SECONDS: Final[int] = 86_400  # 24h

#: Granularidade de leitura em streaming ao aplicar o limite acima --
#: menor que MAX_RESPONSE_BODY_BYTES para permitir interromper a leitura
#: antes de consumir o corpo inteiro quando ele excede o limite.
_STREAM_CHUNK_SIZE: Final[int] = 8192

#: Logger compartilhado com o restante da lib (ver _log.py): este
#: colaborador e detalhe interno de implementacao e o contrato de
#: observabilidade (filtros de log por nome da classe publica) deve
#: permanecer estavel independente de como a implementacao interna e
#: dividida em modulos.
_LOG = get_logger()


@dataclass(frozen=True)
class TokenResponse:
    """Resposta de sucesso do token endpoint, ja validada e sanitizada.

    Attributes:
        access_token: token de acesso extraido da resposta (nao vazio).
        expires_in: validade em segundos, sanitizada -- ausente ou
            invalida no corpo original vira ``DEFAULT_EXPIRES_IN_SECONDS``.
        raw: corpo JSON cru da resposta (RF-03.2: campos desconhecidos
            sao ignorados pela validacao mas permanecem disponiveis aqui
            para o chamador).
    """

    access_token: str
    expires_in: int
    raw: dict[str, object]

    def __repr__(self) -> str:
        """Representacao textual com o token mascarado.

        Evita exposicao acidental do access token em logs/repr.
        """
        return f"TokenResponse(access_token=[REDACTED], expires_in={self.expires_in})"


class TokenResponseGuard:
    """Guarda de sanidade da resposta de sucesso do token endpoint.

    Colaborador interno de ``SmartTokenClient`` (``client.py``); nao faz
    parte da API publica da biblioteca.
    """

    __slots__ = ("_max_response_body_bytes",)

    def __init__(self, max_response_body_bytes: int = MAX_RESPONSE_BODY_BYTES) -> None:
        """Cria o guard.

        Args:
            max_response_body_bytes: limite maximo, em bytes, do corpo
                lido via streaming. Deve ser positivo.

        Raises:
            ValueError: se ``max_response_body_bytes`` nao for positivo.
        """
        if max_response_body_bytes <= 0:
            raise ValueError(f"max_response_body_bytes deve ser positivo, recebido: {max_response_body_bytes}")
        self._max_response_body_bytes = max_response_body_bytes

    def read_body(self, response: httpx.Response, trace: TraceContext) -> bytes:
        """Le o corpo da resposta em streaming, interrompendo assim que
        ultrapassar o limite configurado -- sem esperar o corpo inteiro
        chegar (equivalente a ``unwrapBodyLimitViolation`` do ``.java``).

        Args:
            response: resposta do token endpoint (idealmente obtida com
                ``stream=True`` no ``httpx.Client``, para que a
                interrupcao evite consumir a conexao inteira; funciona
                tambem sobre uma resposta ja lida por completo).
            trace: contexto de trace W3C enviado na requisicao.

        Returns:
            O corpo completo, quando dentro do limite.

        Raises:
            SmartTokenError: quando o corpo excede
                ``max_response_body_bytes``. A conexao/stream e sempre
                fechada antes do metodo retornar, mesmo nesse caso.
        """
        chunks: list[bytes] = []
        total = 0
        try:
            for chunk in response.iter_bytes(chunk_size=_STREAM_CHUNK_SIZE):
                total += len(chunk)
                if total > self._max_response_body_bytes:
                    _LOG.warning(
                        "Corpo da resposta do token endpoint truncado apos %d bytes "
                        "(limite: %d) traceId=%s -- descartando o restante sem processar.",
                        total,
                        self._max_response_body_bytes,
                        trace.trace_id,
                    )
                    raise SmartTokenError(
                        "Corpo da resposta do token endpoint excede o limite maximo de "
                        f"{self._max_response_body_bytes} bytes (traceId={trace.trace_id})."
                    )
                chunks.append(chunk)
        finally:
            response.close()
        return b"".join(chunks)

    def parse_success_response(self, response: httpx.Response, trace: TraceContext) -> TokenResponse:
        """Le, parseia e valida uma resposta de sucesso (HTTP 200) do
        token endpoint.

        Args:
            response: resposta HTTP 200 do token endpoint -- a checagem
                do status e responsabilidade do chamador (RF-03.1);
                este metodo assume que ja foi confirmada.
            trace: contexto de trace W3C enviado na requisicao.

        Returns:
            A resposta validada, com ``expires_in`` sanitizado.

        Raises:
            SmartTokenError: o corpo excede o limite de tamanho, nao e
                JSON valido, nao e um objeto JSON, ou nao contem
                ``access_token``.
        """
        body = self.read_body(response, trace)
        try:
            parsed = json.loads(body)
        except json.JSONDecodeError as exc:
            raise SmartTokenError(
                f"Resposta do token endpoint nao e JSON valido (traceId={trace.trace_id}).",
                exc,
            ) from exc
        if not isinstance(parsed, dict):
            raise SmartTokenError(f"Resposta do token endpoint nao e um objeto JSON (traceId={trace.trace_id}).")
        access_token = parsed.get("access_token")
        if not isinstance(access_token, str) or not access_token:
            raise SmartTokenError(f"Resposta do token endpoint nao contem access_token (traceId={trace.trace_id}).")
        expires_in = sanitize_expires_in(parsed.get("expires_in"), trace)
        return TokenResponse(access_token=access_token, expires_in=expires_in, raw=parsed)


def sanitize_expires_in(raw_expires_in: object, trace: TraceContext | None = None) -> int:
    """Sanitiza o campo ``expires_in`` da resposta do token endpoint.

    Regras explicitas (alinhadas ao Java
    ``TokenResponseGuard.sanitizeExpiresIn``):

    - **Ausente** (``None``): assume ``DEFAULT_EXPIRES_IN_SECONDS``
      (1h) silenciosamente -- caso esperado quando o servidor
      simplesmente omite o campo (RFC 6749 Sec5.1, RF-03.2).
    - **Zero, negativo ou nao numerico** (tipo inesperado, ou string nao
      numerica): rejeitado com ``SmartTokenError``. Um ``expires_in``
      adulterado (por bug ou por um servidor de autorizacao
      comprometido) nunca deve alimentar o cache de tokens -- e' a
      mesma protecao da issue #730 do Java; ver nota de porte no topo
      do modulo.
    - **Acima de ``MAX_EXPIRES_IN_SECONDS``** (24h): normalizado para o
      teto, com log de aviso -- o token continua utilizavel, mas o
      cache nao retem entradas alem do limite de sanidade.

    Valores numericos validos (incluindo strings numericas, por
    tolerancia a respostas nao estritamente conformes) sao truncados
    para ``int`` -- segundos fracionarios nao fazem sentido para o
    calculo de expiracao do cache de tokens.

    Args:
        raw_expires_in: valor cru do campo ``expires_in`` no JSON
            decodificado (``None`` quando ausente).
        trace: contexto de trace W3C, usado apenas para enriquecer as
            mensagens de erro/aviso; opcional para permitir testar esta
            funcao isoladamente, sem montar um ``TraceContext``.

    Returns:
        Validade em segundos, sempre positiva e no maximo
        ``MAX_EXPIRES_IN_SECONDS``.

    Raises:
        SmartTokenError: quando ``expires_in`` esta presente mas e'
            zero, negativo ou nao numerico.
    """
    if raw_expires_in is None:
        # Ausencia e o caso esperado quando o servidor simplesmente nao
        # envia o campo (RF-03.2) -- nao e' um valor "invalido", apenas
        # a aplicacao silenciosa do padrao.
        return DEFAULT_EXPIRES_IN_SECONDS
    if isinstance(raw_expires_in, bool) or not isinstance(raw_expires_in, (int, float, str)):
        raise _invalid_expires_in_error(raw_expires_in, trace)
    try:
        value = float(raw_expires_in)
    except ValueError:
        raise _invalid_expires_in_error(raw_expires_in, trace) from None
    if value <= 0:
        raise _invalid_expires_in_error(raw_expires_in, trace)
    if value > MAX_EXPIRES_IN_SECONDS:
        trace_part = f" traceId={trace.trace_id}" if trace is not None else ""
        _LOG.warning(
            "expires_in=%ss acima do teto de sanidade de %ds na resposta do token endpoint -- normalizando para %ds.%s",
            raw_expires_in,
            MAX_EXPIRES_IN_SECONDS,
            MAX_EXPIRES_IN_SECONDS,
            trace_part,
        )
        return MAX_EXPIRES_IN_SECONDS
    return int(value)


def _invalid_expires_in_error(raw_expires_in: object, trace: TraceContext | None) -> SmartTokenError:
    """Constroi o erro para um ``expires_in`` presente mas invalido (zero,
    negativo ou nao numerico)."""
    trace_part = f" (traceId={trace.trace_id})" if trace is not None else ""
    return SmartTokenError(
        f"'expires_in' invalido na resposta do token endpoint: {raw_expires_in!r}"
        f" (esperado numero em 0 < x <= {MAX_EXPIRES_IN_SECONDS}){trace_part}"
    )

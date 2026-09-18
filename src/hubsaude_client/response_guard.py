"""Valida e sanitiza a resposta bem-sucedida (HTTP 200) do token endpoint:
impõe um limite de tamanho no corpo lido via streaming (protegendo contra
corpos anormalmente grandes, maliciosos ou por bug do servidor) e sanitiza
o campo ``expires_in``, aplicando o padrão documentado quando ausente ou
inválido.

Colaborador interno de ``SmartTokenClient``. Não
faz parte da API pública da biblioteca (não exportado em ``__init__.py``).

- ``MAX_RESPONSE_BODY_BYTES`` (1 MiB) e um teto de sanidade para o corpo
  da resposta -- ver comentário na constante abaixo;
- ``expires_in`` como string numérica é aceito (por tolerância a
  respostas não estritamente conformes); qualquer outro tipo diferente
  de inteiro/float/string numérica é tratado como inválido de imediato:
  ``expires_in``
  *ausente* aplica o padrão silenciosamente, mas ``expires_in``
  *presente e inválido* (zero, negativo ou não numérico) é rejeitado
  com ``SmartTokenError`` em vez de absorvido com um warning -- um
  ``expires_in`` adulterado não pode reter tokens indevidamente no
  cache. Um ``expires_in`` válido mas acima do
  teto de sanidade (``MAX_EXPIRES_IN_SECONDS``, 24h) é normalizado para
  o teto com apenas um warning.

Validação de sucesso (RF-03, ``ESPECIFICAÇÃO.md``):

- Exclusivamente HTTP 200 e sucesso -- decidir se a resposta vai para
  este guard (sucesso) ou para ``ErrorClassifier.http_failure`` (demais
  status) e responsabilidade do chamador (``client.py``); este módulo
  não inspeciona ``response.status_code``.
- ``access_token`` ausente ou vazio e erro (``SmartTokenError``).
- ``expires_in`` ausente recebe o padrão documentado
  (``DEFAULT_EXPIRES_IN_SECONDS``, 3600s -- RF-03.2); presente mas
  inválido é erro (``SmartTokenError``); presente, válido e acima de
  ``MAX_EXPIRES_IN_SECONDS`` é normalizado para o teto. Campos
  desconhecidos são ignorados pela validação mas o corpo JSON cru fica
  disponível ao chamador via ``TokenResponse.raw``.
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

#: Limite máximo padrão do corpo da resposta do token endpoint, em bytes.
#: Mantido local (não em defaults.py): ``discovery.py`` (Tarefa 3/B6, ja
#: concluída) le o corpo da resposta de descoberta via
#: ``response.json()`` diretamente, sem limite de tamanho em streaming --
#: não e um segundo consumidor deste valor. Continua sem outro
#: colaborador da lib que precise do mesmo limite; se isso mudar, mover
#: para defaults.py nesse momento (mesmo critério ja aplicado aqui a
#: DEFAULT_EXPIRES_IN_SECONDS, que foi para defaults.py por ja nascer
#: como constante DEFAULT_* neutra).
MAX_RESPONSE_BODY_BYTES: Final[int] = 1_048_576  # 1 MiB

#: Teto de sanidade para ``expires_in``, em segundos (24h). Valores
#: válidos acima deste teto são normalizados para ele antes de
#: alimentar o cache de tokens (não é um erro -- apenas um limite
#: superior de sanidade). Mantido local pela mesma razão de
#: ``MAX_RESPONSE_BODY_BYTES`` acima: nenhum outro colaborador da lib
#: precisa deste valor hoje.
MAX_EXPIRES_IN_SECONDS: Final[int] = 86_400  # 24h

#: Granularidade de leitura em streaming ao aplicar o limite acima --
#: menor que MAX_RESPONSE_BODY_BYTES para permitir interromper a leitura
#: antes de consumir o corpo inteiro quando ele excede o limite.
_STREAM_CHUNK_SIZE: Final[int] = 8192

#: Logger compartilhado com o restante da lib (ver _log.py): este
#: colaborador e detalhe interno de implementação e o contrato de
#: observabilidade (filtros de log por nome da classe pública) deve
#: permanecer estável independente de como a implementação interna e
#: dividida em módulos.
_LOG = get_logger()


@dataclass(frozen=True)
class TokenResponse:
    """Resposta de sucesso do token endpoint, ja validada e sanitizada.

    Attributes:
        access_token: token de acesso extraído da resposta (não vazio).
        expires_in: validade em segundos, sanitizada -- ausente ou
            inválida no corpo original vira ``DEFAULT_EXPIRES_IN_SECONDS``.
        raw: corpo JSON cru da resposta (RF-03.2: campos desconhecidos
            são ignorados pela validação mas permanecem disponíveis aqui
            para o chamador).
    """

    access_token: str
    expires_in: int
    raw: dict[str, object]

    def __repr__(self) -> str:
        """Representação textual com o token mascarado.

        Evita exposição acidental do access token em logs/repr.
        """
        return f"TokenResponse(access_token=[REDACTED], expires_in={self.expires_in})"


class TokenResponseGuard:
    """Guarda de sanidade da resposta de sucesso do token endpoint.

    Colaborador interno de ``SmartTokenClient`` (``client.py``); não faz
    parte da API pública da biblioteca.
    """

    __slots__ = ("_max_response_body_bytes",)

    def __init__(self, max_response_body_bytes: int = MAX_RESPONSE_BODY_BYTES) -> None:
        """Cria o guard.

        Args:
            max_response_body_bytes: limite máximo, em bytes, do corpo
                lido via streaming. Deve ser positivo.

        Raises:
            ValueError: se ``max_response_body_bytes`` não for positivo.
        """
        if max_response_body_bytes <= 0:
            raise ValueError(f"max_response_body_bytes deve ser positivo, recebido: {max_response_body_bytes}")
        self._max_response_body_bytes = max_response_body_bytes

    def read_body(self, response: httpx.Response, trace: TraceContext) -> bytes:
        """Le o corpo da resposta em streaming, interrompendo assim que
        ultrapassar o limite configurado -- sem esperar o corpo inteiro
        chegar.

        Args:
            response: resposta do token endpoint (idealmente obtida com
                ``stream=True`` no ``httpx.Client``, para que a
                interrupção evite consumir a conexão inteira; funciona
                também sobre uma resposta ja lida por completo).
            trace: contexto de trace W3C enviado na requisição.

        Returns:
            O corpo completo, quando dentro do limite.

        Raises:
            SmartTokenError: quando o corpo excede
                ``max_response_body_bytes``. A conexão/stream e sempre
                fechada antes do método retornar, mesmo nesse caso.
        """
        chunks: list[bytes] = []
        total = 0
        try:
            for chunk in response.iter_bytes(chunk_size=_STREAM_CHUNK_SIZE):
                total += len(chunk)
                if total > self._max_response_body_bytes:
                    _LOG.warning(
                        "Corpo da resposta do token endpoint truncado após %d bytes "
                        "(limite: %d) traceId=%s -- descartando o restante sem processar.",
                        total,
                        self._max_response_body_bytes,
                        trace.trace_id,
                    )
                    raise SmartTokenError(
                        "Corpo da resposta do token endpoint excede o limite máximo de "
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
                este método assume que ja foi confirmada.
            trace: contexto de trace W3C enviado na requisição.

        Returns:
            A resposta validada, com ``expires_in`` sanitizado.

        Raises:
            SmartTokenError: o corpo excede o limite de tamanho, não e
                JSON válido, não e um objeto JSON, não contém
                ``access_token``, ou o campo ``expires_in`` da resposta e
                inválido (delegado a :func:`sanitize_expires_in`).
        """
        body = self.read_body(response, trace)
        try:
            parsed = json.loads(body)
        except json.JSONDecodeError as exc:
            raise SmartTokenError(
                f"Resposta do token endpoint não e JSON válido (traceId={trace.trace_id}).",
                exc,
            )
        if not isinstance(parsed, dict):
            raise SmartTokenError(f"Resposta do token endpoint não e um objeto JSON (traceId={trace.trace_id}).")
        access_token = parsed.get("access_token")
        if not isinstance(access_token, str) or not access_token:
            raise SmartTokenError(f"Resposta do token endpoint não contém access_token (traceId={trace.trace_id}).")
        expires_in = sanitize_expires_in(parsed.get("expires_in"), trace)
        return TokenResponse(access_token=access_token, expires_in=expires_in, raw=parsed)


def sanitize_expires_in(raw_expires_in: object, trace: TraceContext | None = None) -> int:
    """Sanitiza o campo ``expires_in`` da resposta do token endpoint.

    Regras explícitas:

    - **Ausente** (``None``): assume ``DEFAULT_EXPIRES_IN_SECONDS``
      (1h) silenciosamente -- caso esperado quando o servidor
      simplesmente omite o campo (RFC 6749 Sec5.1, RF-03.2).
    - **Zero, negativo ou não numérico** (tipo inesperado, ou string não
      numérica): rejeitado com ``SmartTokenError``. Um ``expires_in``
      adulterado (por bug ou por um servidor de autorização
      comprometido) nunca deve alimentar o cache de tokens.
    - **Acima de ``MAX_EXPIRES_IN_SECONDS``** (24h): normalizado para o
      teto, com log de aviso -- o token continua utilizável, mas o
      cache não retém entradas além do limite de sanidade.

    Valores numéricos válidos (incluindo strings numéricas, por
    tolerância a respostas não estritamente conformes) são truncados
    para ``int`` -- segundos fracionários não fazem sentido para o
    cálculo de expiração do cache de tokens.

    Args:
        raw_expires_in: valor cru do campo ``expires_in`` no JSON
            decodificado (``None`` quando ausente).
        trace: contexto de trace W3C, usado apenas para enriquecer as
            mensagens de erro/aviso; opcional para permitir testar esta
            função isoladamente, sem montar um ``TraceContext``.

    Returns:
        Validade em segundos, sempre positiva e no máximo
        ``MAX_EXPIRES_IN_SECONDS``.

    Raises:
        SmartTokenError: quando ``expires_in`` está presente mas é
            zero, negativo ou não numérico.
    """
    if raw_expires_in is None:
        # Ausência e o caso esperado quando o servidor simplesmente não
        # envia o campo (RF-03.2) -- não é um valor "inválido", apenas
        # a aplicação silenciosa do padrão.
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
    """Constrói o erro para um ``expires_in`` presente mas inválido (zero,
    negativo ou não numérico)."""
    trace_part = f" (traceId={trace.trace_id})" if trace is not None else ""
    return SmartTokenError(
        f"'expires_in' inválido na resposta do token endpoint: {raw_expires_in!r}"
        f" (esperado número em 0 < x <= {MAX_EXPIRES_IN_SECONDS}){trace_part}"
    )

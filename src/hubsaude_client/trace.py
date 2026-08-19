"""Contexto de trace W3C Trace Context, gerado localmente por requisicao.

Portado de TraceContext.java.

O HubSaude deriva o identificador de correlacao de cada requisicao
exclusivamente do header ``traceparent`` (W3C Trace Context); headers
como ``X-Correlation-Id`` enviados pelo cliente sao ignorados pelo
gateway. Este modulo gera o par trace-id/span-id por requisicao — sem
dependencia do SDK OpenTelemetry — permitindo correlacionar logs locais
com o ``correlation-id`` registrado pela plataforma.

Formato emitido (W3C Trace Context Sec3.2):
``00-<trace-id>-<parent-id>-<trace-flags>``, onde:

- **version**: ``00``;
- **trace-id**: 16 bytes aleatorios criptograficamente (32 caracteres
  hexadecimais minusculos), nunca todo-zeros;
- **parent-id** (span-id): 8 bytes aleatorios criptograficamente (16
  caracteres hexadecimais minusculos), nunca todo-zeros;
- **trace-flags**: ``00`` — flag ``sampled`` desligada, pois esta
  biblioteca nao grava spans.

Instancias sao imutaveis e validadas na construcao: componentes fora do
formato W3C (tamanho, maiusculas, todo-zeros) sao rejeitados com
``ValueError``.
"""

from __future__ import annotations

import re
import secrets
from dataclasses import dataclass
from typing import ClassVar

#: Versao do formato traceparent suportada (W3C Trace Context Sec3.2.2.2).
_VERSION = "00"

#: Flags de trace: "sampled" desligado — a lib nao grava spans.
_FLAGS_NOT_SAMPLED = "00"

#: Tamanho do trace-id em bytes (W3C Trace Context Sec3.2.2.3).
_TRACE_ID_BYTES = 16

#: Tamanho do span-id (parent-id) em bytes (W3C Trace Context Sec3.2.2.4).
_SPAN_ID_BYTES = 8

#: Formato valido do trace-id: 32 hex minusculos, nao todo-zeros.
_TRACE_ID_PATTERN = re.compile(r"^(?!0{32}$)[0-9a-f]{32}$")

#: Formato valido do span-id: 16 hex minusculos, nao todo-zeros.
_SPAN_ID_PATTERN = re.compile(r"^(?!0{16}$)[0-9a-f]{16}$")


@dataclass(frozen=True)
class TraceContext:
    """Contexto de trace W3C imutavel, com trace-id e span-id.

    Equivalente Python do ``record TraceContext`` (Java).

    Attributes:
        trace_id: identificador do trace — 32 caracteres hexadecimais
            minusculos, nao todo-zeros.
        span_id: identificador do span (parent-id no header) — 16
            caracteres hexadecimais minusculos, nao todo-zeros.

    Raises:
        ValueError: se ``trace_id`` ou ``span_id`` nao seguirem o
            formato exigido.
    """

    #: Nome do header HTTP de contexto de trace (W3C Trace Context).
    TRACEPARENT_HEADER: ClassVar[str] = "traceparent"
    # Header público, espelhando TraceContext.TRACEPARENT_HEADER do Java

    trace_id: str
    span_id: str

    def __post_init__(self) -> None:
        if not _TRACE_ID_PATTERN.match(self.trace_id):
            raise ValueError(
                "trace-id invalido: exige 32 caracteres hexadecimais minusculos,"
                " nao todo-zeros (W3C Trace Context Sec3.2.2.3)"
            )
        if not _SPAN_ID_PATTERN.match(self.span_id):
            raise ValueError(
                "span-id invalido: exige 16 caracteres hexadecimais minusculos,"
                " nao todo-zeros (W3C Trace Context Sec3.2.2.4)"
            )

    @staticmethod
    def generate() -> "TraceContext":
        """Gera um novo contexto de trace com ids aleatorios criptograficamente.

        Deve ser invocado uma vez por requisicao HTTP: cada tentativa
        (inclusive retries) carrega um par trace-id/span-id proprio.

        Returns:
            Novo contexto de trace, nunca todo-zeros.
        """
        return TraceContext(
            trace_id=_random_lower_hex(_TRACE_ID_BYTES),
            span_id=_random_lower_hex(_SPAN_ID_BYTES),
        )

    def traceparent(self) -> str:
        """Monta o valor do header ``traceparent``.

        Formato ``00-<trace-id>-<parent-id>-00``, onde parent-id e o
        span-id desta instancia (W3C Trace Context Sec3.2.2).

        Returns:
            Valor pronto para envio no header ``traceparent``.
        """
        return f"{_VERSION}-{self.trace_id}-{self.span_id}-{_FLAGS_NOT_SAMPLED}"


def _random_lower_hex(num_bytes: int) -> str:
    """Produz bytes aleatorios criptograficamente, em hex minusculo.

    Garante que o resultado nunca seja todo-zeros (valor invalido pelo
    W3C Trace Context).

    Args:
        num_bytes: quantidade de bytes aleatorios.

    Returns:
        Representacao hexadecimal minuscula, nao todo-zeros.
    """
    while True:
        raw = secrets.token_bytes(num_bytes)
        if any(raw):
            return raw.hex()

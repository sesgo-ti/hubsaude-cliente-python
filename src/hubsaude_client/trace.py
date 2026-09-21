"""Contexto de trace W3C Trace Context, gerado localmente por requisição.

O HubSaude deriva o identificador de correlação de cada requisição
exclusivamente do header ``traceparent`` (W3C Trace Context); headers
como ``X-Correlation-Id`` enviados pelo cliente são ignorados pelo
gateway. Este módulo gera o par trace-id/span-id por requisição — sem
dependência do SDK OpenTelemetry — permitindo correlacionar logs locais
com o ``correlation-id`` registrado pela plataforma.

Formato emitido (W3C Trace Context Sec3.2):
``00-<trace-id>-<parent-id>-<trace-flags>``, onde:

- **version**: ``00``;
- **trace-id**: 16 bytes aleatórios criptograficamente (32 caracteres
  hexadecimais minúsculos), nunca todo-zeros;
- **parent-id** (span-id): 8 bytes aleatórios criptograficamente (16
  caracteres hexadecimais minúsculos), nunca todo-zeros;
- **trace-flags**: ``00`` — flag ``sampled`` desligada, pois esta
  biblioteca não grava spans.

Instâncias são imutáveis e validadas na construção: componentes fora do
formato W3C (tamanho, maiúsculas, todo-zeros) são rejeitados com
``ValueError``.
"""

from __future__ import annotations

import re
import secrets
from dataclasses import dataclass
from typing import ClassVar

#: Versão do formato traceparent suportada (W3C Trace Context Sec3.2.2.2).
_VERSION = "00"

#: Flags de trace: "sampled" desligado — a lib não grava spans.
_FLAGS_NOT_SAMPLED = "00"

#: Tamanho do trace-id em bytes (W3C Trace Context Sec3.2.2.3).
_TRACE_ID_BYTES = 16

#: Tamanho do span-id (parent-id) em bytes (W3C Trace Context Sec3.2.2.4).
_SPAN_ID_BYTES = 8

#: Formato válido do trace-id: 32 hex minúsculos, não todo-zeros.
#:
#: Âncora de fim em ``\Z`` (fim absoluto da string), NÃO ``$`` -- no módulo
#: ``re`` do Python, ``$`` casa também imediatamente antes de uma única
#: quebra de linha final, o que aceitaria incorretamente um valor como
#: ``"a" * 32 + "\n"``.
_TRACE_ID_PATTERN = re.compile(r"^(?!0{32}\Z)[0-9a-f]{32}\Z")

#: Formato válido do span-id: 16 hex minúsculos, não todo-zeros. Mesma nota
#: sobre ``\Z`` vs ``$`` do ``_TRACE_ID_PATTERN`` acima.
_SPAN_ID_PATTERN = re.compile(r"^(?!0{16}\Z)[0-9a-f]{16}\Z")


@dataclass(frozen=True)
class TraceContext:
    """Contexto de trace W3C imutável, com trace-id e span-id.

    Attributes:
        trace_id: identificador do trace — 32 caracteres hexadecimais
            minúsculos, não todo-zeros.
        span_id: identificador do span (parent-id no header) — 16
            caracteres hexadecimais minúsculos, não todo-zeros.

    Raises:
        ValueError: se ``trace_id`` ou ``span_id`` não seguirem o
            formato exigido.
    """

    #: Nome do header HTTP de contexto de trace (W3C Trace Context).
    TRACEPARENT_HEADER: ClassVar[str] = "traceparent"
    # Nome do header HTTP público definido pelo W3C Trace Context.

    trace_id: str
    span_id: str

    def __post_init__(self) -> None:
        if not _TRACE_ID_PATTERN.match(self.trace_id):
            raise ValueError(
                "trace-id inválido: exige 32 caracteres hexadecimais minúsculos,"
                " não todo-zeros (W3C Trace Context Sec3.2.2.3)"
            )
        if not _SPAN_ID_PATTERN.match(self.span_id):
            raise ValueError(
                "span-id inválido: exige 16 caracteres hexadecimais minúsculos,"
                " não todo-zeros (W3C Trace Context Sec3.2.2.4)"
            )

    @staticmethod
    def generate() -> "TraceContext":
        """Gera um novo contexto de trace com ids aleatórios criptograficamente.

        Deve ser invocado uma vez por requisição HTTP: cada tentativa
        (inclusive retries) carrega um par trace-id/span-id próprio.

        Returns:
            Novo contexto de trace, nunca todo-zeros.
        """
        return TraceContext(
            trace_id=_random_lower_hex(_TRACE_ID_BYTES),
            span_id=_random_lower_hex(_SPAN_ID_BYTES),
        )

    def traceparent(self) -> str:
        """Monta o valor do header ``traceparent``.

        Formato ``00-<trace-id>-<parent-id>-00``, onde parent-id é o
        span-id desta instância (W3C Trace Context Sec3.2.2).

        Returns:
            Valor pronto para envio no header ``traceparent``.
        """
        return f"{_VERSION}-{self.trace_id}-{self.span_id}-{_FLAGS_NOT_SAMPLED}"


def _random_lower_hex(num_bytes: int) -> str:
    """Produz bytes aleatórios criptograficamente, em hex minúsculo.

    Garante que o resultado nunca seja todo-zeros (valor inválido pelo
    W3C Trace Context).

    Args:
        num_bytes: quantidade de bytes aleatórios.

    Returns:
        Representação hexadecimal minúscula, não todo-zeros.
    """
    while True:
        raw = secrets.token_bytes(num_bytes)
        if any(raw):
            return raw.hex()

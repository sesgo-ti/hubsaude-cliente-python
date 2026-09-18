"""Configuração imutável de tolerância a falhas do cliente.

Agrupa os parâmetros relacionados a resiliência (timeouts, TTL da
assertion, margem de cache de token e número de tentativas) numa única
classe coesa. Valores inválidos (zero ou negativos) para
assertion_ttl_seconds, token_cache_margin_seconds e
max_retries são automaticamente substituídos pelos defaults de
defaults.py — não de client.py —, preservando o desacoplamento
entre os componentes de assinatura/certificados e os de cliente
HTTP/orquestração de token desta biblioteca.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta

from hubsaude_client.defaults import (
    DEFAULT_ASSERTION_TTL_SECONDS,
    DEFAULT_MAX_RETRIES,
    DEFAULT_TOKEN_CACHE_MARGIN_SECONDS,
)


@dataclass(frozen=True)
class FaultToleranceConfig:
    """Configuração de tolerância a falhas para o cliente SMART.

    Attributes:
        connect_timeout: tempo máximo para estabelecer a conexão TCP.
        request_timeout: tempo máximo para completar a requisição HTTP.
        assertion_ttl_seconds: TTL do JWT ``client_assertion``, em
            segundos. Valores ``<= 0`` são substituídos por
            ``DEFAULT_ASSERTION_TTL_SECONDS``.
        token_cache_margin_seconds: margem de segurança em segundos
            utilizada para expirar o cache do token antecipadamente.
            Valores ``<= 0`` são substituídos por
            ``DEFAULT_TOKEN_CACHE_MARGIN_SECONDS``.
        max_retries: número de tentativas em caso de falha transitória.
            Valores ``<= 0`` são substituídos por ``DEFAULT_MAX_RETRIES``.
    """

    connect_timeout: timedelta
    request_timeout: timedelta
    assertion_ttl_seconds: int
    token_cache_margin_seconds: int
    max_retries: int

    def __post_init__(self) -> None:
        """Normaliza campos inválidos.

        ``connect_timeout``/``request_timeout`` são obrigatórios; a
        tipagem (``timedelta``, não ``timedelta | None``) ja documenta o
        contrato — nenhuma checagem adicional em runtime e feita para
        esses dois campos, pelo mesmo motivo que o resto da lib não
        valida ``None`` em atributos tipados como não-opcionais.

        ``assertion_ttl_seconds``, ``token_cache_margin_seconds`` e
        ``max_retries`` iguais a zero ou negativos são silenciosamente
        trocados pelos defaults — como a dataclass e ``frozen``, a
        substituição usa ``object.__setattr__`` (mesma técnica de
        ``__post_init__`` em dataclasses imutáveis).
        """
        if self.assertion_ttl_seconds <= 0:
            object.__setattr__(self, "assertion_ttl_seconds", DEFAULT_ASSERTION_TTL_SECONDS)
        if self.token_cache_margin_seconds <= 0:
            object.__setattr__(self, "token_cache_margin_seconds", DEFAULT_TOKEN_CACHE_MARGIN_SECONDS)
        if self.max_retries <= 0:
            object.__setattr__(self, "max_retries", DEFAULT_MAX_RETRIES)

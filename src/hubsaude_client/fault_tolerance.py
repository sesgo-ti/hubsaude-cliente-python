"""Configuracao imutavel de tolerancia a falhas do cliente.

Agrupa os parametros relacionados a resiliencia (timeouts, TTL da
assertion, margem de cache de token e numero de tentativas) numa unica
classe coesa. Valores invalidos (zero ou negativos) para
assertion_ttl_seconds, token_cache_margin_seconds e
max_retries sao automaticamente substituidos pelos defaults de
defaults.py — nao de client.py —, preservando o desacoplamento
entre os componentes de assinatura/certificados e os de cliente
HTTP/orquestracao de token desta biblioteca.
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
    """Configuracao de tolerancia a falhas para o cliente SMART.

    Attributes:
        connect_timeout: tempo maximo para estabelecer a conexao TCP.
        request_timeout: tempo maximo para completar a requisicao HTTP.
        assertion_ttl_seconds: TTL do JWT ``client_assertion``, em
            segundos. Valores ``<= 0`` sao substituidos por
            ``DEFAULT_ASSERTION_TTL_SECONDS``.
        token_cache_margin_seconds: margem de seguranca em segundos
            utilizada para expirar o cache do token antecipadamente.
            Valores ``<= 0`` sao substituidos por
            ``DEFAULT_TOKEN_CACHE_MARGIN_SECONDS``.
        max_retries: numero de tentativas em caso de falha transitoria.
            Valores ``<= 0`` sao substituidos por ``DEFAULT_MAX_RETRIES``.
    """

    connect_timeout: timedelta
    request_timeout: timedelta
    assertion_ttl_seconds: int
    token_cache_margin_seconds: int
    max_retries: int

    def __post_init__(self) -> None:
        """Normaliza campos invalidos.

        ``connect_timeout``/``request_timeout`` sao obrigatorios; a
        tipagem (``timedelta``, nao ``timedelta | None``) ja documenta o
        contrato — nenhuma checagem adicional em runtime e feita para
        esses dois campos, pelo mesmo motivo que o resto da lib nao
        valida ``None`` em atributos tipados como nao-opcionais.

        ``assertion_ttl_seconds``, ``token_cache_margin_seconds`` e
        ``max_retries`` iguais a zero ou negativos sao silenciosamente
        trocados pelos defaults — como a dataclass e ``frozen``, a
        substituicao usa ``object.__setattr__`` (mesma tecnica de
        ``__post_init__`` em dataclasses imutaveis).
        """
        if self.assertion_ttl_seconds <= 0:
            object.__setattr__(self, "assertion_ttl_seconds", DEFAULT_ASSERTION_TTL_SECONDS)
        if self.token_cache_margin_seconds <= 0:
            object.__setattr__(self, "token_cache_margin_seconds", DEFAULT_TOKEN_CACHE_MARGIN_SECONDS)
        if self.max_retries <= 0:
            object.__setattr__(self, "max_retries", DEFAULT_MAX_RETRIES)

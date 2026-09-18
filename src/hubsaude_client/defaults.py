"""Constantes DEFAULT_* neutras do hubsaude_client.

Reunidas num módulo único, sem dono, para que nenhum colaborador
interno precise depender de outro só para ler um valor padrão.
"""

from __future__ import annotations

from typing import Final

#: TTL padrão do client_assertion em segundos.
DEFAULT_ASSERTION_TTL_SECONDS: Final[int] = 60

#: Timeout padrão de conexão, em segundos.
DEFAULT_CONNECT_TIMEOUT_SECONDS: Final[float] = 10.0

#: Timeout padrão de requisição, em segundos.
DEFAULT_REQUEST_TIMEOUT_SECONDS: Final[float] = 30.0

#: Número máximo padrão de tentativas em caso de falha transitória.
DEFAULT_MAX_RETRIES: Final[int] = 3

#: Margem padrão em segundos para renovar token antes da expiração.
DEFAULT_TOKEN_CACHE_MARGIN_SECONDS: Final[int] = 30

#: Quantidade máxima padrão de scopes retidos no cache de tokens.
DEFAULT_TOKEN_CACHE_MAX_ENTRIES: Final[int] = 1_000

#: Protocolo TLS padrão.
DEFAULT_TLS_PROTOCOL: Final[str] = "TLSv1.3"

#: Algoritmo JWT padrão. RS384 — o Servidor de Autorização SMART aceita
#: apenas RS384 e ES384 (client-assertion-contexto-ig.md Sec3.2).
DEFAULT_JWT_ALGORITHM: Final[str] = "RS384"

#: Validade padrão (segundos) do access_token quando o campo
#: ``expires_in`` vem ausente ou inválido na resposta do token endpoint
#: (ESPECIFICAÇÃO.md RF-03.2). Usado por ``response_guard.py``.
DEFAULT_EXPIRES_IN_SECONDS: Final[int] = 3600

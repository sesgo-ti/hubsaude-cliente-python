"""Constantes DEFAULT_* neutras do hubsaude_client.

Reunidas num modulo unico, sem dono, para que nenhum colaborador
interno precise depender de outro so para ler um valor padrao.
"""

from __future__ import annotations

from typing import Final

#: TTL padrao do client_assertion em segundos.
DEFAULT_ASSERTION_TTL_SECONDS: Final[int] = 60

#: Timeout padrao de conexao, em segundos.
DEFAULT_CONNECT_TIMEOUT_SECONDS: Final[float] = 10.0

#: Timeout padrao de requisicao, em segundos.
DEFAULT_REQUEST_TIMEOUT_SECONDS: Final[float] = 30.0

#: Numero maximo padrao de tentativas em caso de falha transitoria.
DEFAULT_MAX_RETRIES: Final[int] = 3

#: Margem padrao em segundos para renovar token antes da expiracao.
DEFAULT_TOKEN_CACHE_MARGIN_SECONDS: Final[int] = 30

#: Quantidade maxima padrao de scopes retidos no cache de tokens.
DEFAULT_TOKEN_CACHE_MAX_ENTRIES: Final[int] = 1_000

#: Protocolo TLS padrao.
DEFAULT_TLS_PROTOCOL: Final[str] = "TLSv1.3"

#: Algoritmo JWT padrao. RS384 — o Servidor de Autorizacao SMART aceita
#: apenas RS384 e ES384 (client-assertion-contexto-ig.md Sec3.2).
DEFAULT_JWT_ALGORITHM: Final[str] = "RS384"

#: Validade padrao (segundos) do access_token quando o campo
#: ``expires_in`` vem ausente ou invalido na resposta do token endpoint
#: (ESPECIFICACAO.md RF-03.2). Usado por ``response_guard.py``.
DEFAULT_EXPIRES_IN_SECONDS: Final[int] = 3600

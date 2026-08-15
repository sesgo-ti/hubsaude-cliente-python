"""Constantes DEFAULT_* neutras do hubsaude_client.

Reunidas num modulo unico, sem dono, para que nenhum colaborador
interno precise depender de outro so para ler um valor padrao (no
projeto Java de origem essas constantes vivem soltas em
``SmartTokenClient``/``SmartTokenClientBuilder``/``SslContextFactory``,
o que gera acoplamentos cruzados evitaveis).

Valores portados literalmente de ``SmartTokenClient.java`` e de
``SslContextFactory.java``.
"""

from __future__ import annotations

from typing import Final

#: TTL padrao do client_assertion em segundos.
#: Origem: SmartTokenClient.DEFAULT_ASSERTION_TTL_SECONDS.
DEFAULT_ASSERTION_TTL_SECONDS: Final[int] = 60

#: Timeout padrao de conexao, em segundos.
#: Origem: SmartTokenClient.DEFAULT_CONNECT_TIMEOUT (Duration.ofSeconds(10)).
DEFAULT_CONNECT_TIMEOUT_SECONDS: Final[float] = 10.0

#: Timeout padrao de requisicao, em segundos.
#: Origem: SmartTokenClient.DEFAULT_REQUEST_TIMEOUT (Duration.ofSeconds(30)).
DEFAULT_REQUEST_TIMEOUT_SECONDS: Final[float] = 30.0

#: Numero maximo padrao de tentativas em caso de falha transitoria.
#: Origem: SmartTokenClient.DEFAULT_MAX_RETRIES.
DEFAULT_MAX_RETRIES: Final[int] = 3

#: Margem padrao em segundos para renovar token antes da expiracao.
#: Origem: SmartTokenClient.DEFAULT_TOKEN_CACHE_MARGIN_SECONDS.
DEFAULT_TOKEN_CACHE_MARGIN_SECONDS: Final[int] = 30

#: Quantidade maxima padrao de scopes retidos no cache de tokens.
#: Origem: SmartTokenClient.DEFAULT_TOKEN_CACHE_MAX_ENTRIES.
DEFAULT_TOKEN_CACHE_MAX_ENTRIES: Final[int] = 1_000

#: Protocolo TLS padrao.
#: Origem: SslContextFactory.DEFAULT_TLS_PROTOCOL (via
#: SmartTokenClient.DEFAULT_TLS_PROTOCOL).
DEFAULT_TLS_PROTOCOL: Final[str] = "TLSv1.3"

#: Algoritmo JWT padrao. RS384 — o Servidor de Autorizacao SMART aceita
#: apenas RS384 e ES384 (client-assertion-contexto-ig.md Sec3.2 no
#: projeto Java de origem).
#: Origem: SmartTokenClient.DEFAULT_JWT_ALGORITHM.
DEFAULT_JWT_ALGORITHM: Final[str] = "RS384"

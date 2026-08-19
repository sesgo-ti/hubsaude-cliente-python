"""Biblioteca cliente Python do HubSaude para obtencao de access tokens
SMART Backend Services (``client_credentials`` + ``private_key_jwt``,
RFC 7523).

O ponto de entrada e o cliente HTTP (ainda a ser implementado), que assina o
``client_assertion`` com o material criptografico do estabelecimento e
negocia o token no authorization server. O pacote reune os
colaboradores dessa jornada: estrategias de assinatura
(``SigningStrategy``), carga e validacao de material PEM, tolerancia a
falhas com retry exponencial, salvaguardas de sanidade da resposta do
token endpoint, configuracao TLS/mTLS (via ``ssl.SSLContext`` direto,
sem Protocol proprio) e propagacao de contexto de trace W3C.

A biblioteca e distribuida para consumidores externos; suas excecoes de
dominio (``SmartTokenError``) nao devem vazar detalhes de
credenciais.
"""

from __future__ import annotations

from hubsaude_client.exceptions import SmartTokenError
from hubsaude_client.ports import SigningStrategy
from hubsaude_client.trace import TraceContext

__all__: list[str] = [
    "SmartTokenError",
    "SigningStrategy",
    "TraceContext",
]

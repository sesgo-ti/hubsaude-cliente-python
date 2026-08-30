"""Biblioteca cliente Python do HubSaude para obtencao de access tokens
SMART Backend Services (``client_credentials`` + ``private_key_jwt``,
RFC 7523).

O ponto de entrada e ``hubsaude_client.builder.SmartTokenClientBuilder``,
que produz um ``hubsaude_client.client.SmartTokenClient`` ja validado
(fail-fast) e pronto para assinar o ``client_assertion`` com o material
criptografico do estabelecimento e negociar o token no authorization
server. O pacote reune os colaboradores dessa jornada: estrategias de
assinatura (``SigningStrategy``), carga e validacao de material PEM,
tolerancia a falhas com retry exponencial, salvaguardas de sanidade da
resposta do token endpoint, configuracao TLS/mTLS (via
``TlsContextProvider``, port em ``ports.py`` que abstrai de onde vem o
``ssl.SSLContext`` pronto) e propagacao de contexto de trace W3C.

``SmartTokenClientBuilder``/``SmartTokenClient`` nao sao reexportados
aqui -- consumidores importam de ``hubsaude_client.builder``/
``hubsaude_client.client`` diretamente (mesma convencao ja usada pelos
demais colaboradores internos desta lib).

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

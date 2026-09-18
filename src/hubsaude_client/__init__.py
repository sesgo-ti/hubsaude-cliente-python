"""Biblioteca cliente Python do HubSaude para obtenção de access tokens
SMART Backend Services (``client_credentials`` + ``private_key_jwt``,
RFC 7523).

O ponto de entrada e ``hubsaude_client.builder.SmartTokenClientBuilder``,
que produz um ``hubsaude_client.client.SmartTokenClient`` ja validado
(fail-fast) e pronto para assinar o ``client_assertion`` com o material
criptográfico do estabelecimento e negociar o token no authorization
server. O pacote reúne os colaboradores dessa jornada: estratégias de
assinatura (``SigningStrategy``), carga e validação de material PEM,
tolerância a falhas com retry exponencial, salvaguardas de sanidade da
resposta do token endpoint, configuração TLS/mTLS (via
``TlsContextProvider``, port em ``ports.py`` que abstrai de onde vem o
``ssl.SSLContext`` pronto) e propagação de contexto de trace W3C.

``SmartTokenClientBuilder``/``SmartTokenClient`` não são reexportados
aqui -- consumidores importam de ``hubsaude_client.builder``/
``hubsaude_client.client`` diretamente (mesma convenção ja usada pelos
demais colaboradores internos desta lib).

A biblioteca e distribuída para consumidores externos; suas exceções de
domínio (``SmartTokenError``) não devem vazar detalhes de
credenciais.
"""

from __future__ import annotations

from hubsaude_client.exceptions import SmartTokenError
from hubsaude_client.ports import SigningStrategy
from hubsaude_client.settings import ResolvedSigning, SigningSettings
from hubsaude_client.tls_settings import TlsSettings
from hubsaude_client.trace import TraceContext

__all__: list[str] = [
    "ResolvedSigning",
    "SigningSettings",
    "SigningStrategy",
    "SmartTokenError",
    "TlsSettings",
    "TraceContext",
]

"""Fronteira (typing.Protocol) entre o cliente HTTP/orquestracao de token
e a assinatura (carga de PEM, certificados, HSM/PKCS#11, servicos remotos).

Define ``SigningStrategy`` e ``TlsContextProvider``. O restante do
cliente programa contra esses Protocols; implementacoes concretas de
assinatura e de contexto TLS/mTLS so precisam satisfazer as respectivas
assinaturas.
"""

from __future__ import annotations

import ssl
from typing import Protocol, runtime_checkable


@runtime_checkable
class SigningStrategy(Protocol):
    """Estrategia de assinatura digital que abstrai o mecanismo criptografico.

    Interface com um unico metodo, permitindo que chaves em memoria,
    HSM/PKCS#11 ou servicos remotos de assinatura sejam intercambiaveis
    sem alterar o cliente (padrao Strategy).
    """

    def sign(self, data: bytes) -> bytes:
        """Assina os dados fornecidos usando o mecanismo configurado.

        Args:
            data: bytes a serem assinados (tipicamente o
                ``header.payload`` do JWT).

        Returns:
            A assinatura digital em formato raw (nao Base64).

        Raises:
            SigningError: se ocorrer erro durante a assinatura
                (implementacao concreta; nao definida neste modulo).
        """
        ...


@runtime_checkable
class TlsContextProvider(Protocol):
    """Fornecedor de contexto TLS/mTLS pronto para uso pelo cliente HTTP.

    Abstrai de onde vem o ``ssl.SSLContext`` (certificado/chave em disco,
    KeyStore, HSM, cofre de segredos) — o cliente HTTP so consome o
    contexto pronto, sem saber como foi montado.
    """

    def ssl_context(self) -> ssl.SSLContext:
        """Monta/retorna o contexto TLS/mTLS pronto para a requisicao.

        Returns:
            ``ssl.SSLContext`` configurado (certificado de cliente,
            trust store, protocolo TLS) pronto para uso pelo cliente HTTP.
        """
        ...

"""Fronteira (typing.Protocol) entre o cliente HTTP/orquestração de token
e a assinatura (carga de PEM, certificados, HSM/PKCS#11, serviços remotos).

Define ``SigningStrategy`` e ``TlsContextProvider``. O restante do
cliente programa contra esses Protocols; implementações concretas de
assinatura e de contexto TLS/mTLS só precisam satisfazer as respectivas
assinaturas.
"""

from __future__ import annotations

import ssl
from typing import Protocol, runtime_checkable


@runtime_checkable
class SigningStrategy(Protocol):
    """Estratégia de assinatura digital que abstrai o mecanismo criptográfico.

    Interface com um único método obrigatório, permitindo que chaves em
    memória, HSM/PKCS#11 ou serviços remotos de assinatura sejam
    intercambiáveis sem alterar o cliente (padrão Strategy).

    Método opcional ``close() -> None``: implementações que retenham um
    recurso que precise ser liberado explicitamente (ex.: uma sessão
    PKCS#11 aberta em hardware com limite de sessões simultâneas) podem
    definir ``close()``. Deliberadamente NÃO faz parte da assinatura
    formal deste ``Protocol`` (checagem via ``isinstance`` continua
    exigindo apenas ``sign()``) para não quebrar, de forma retroativa,
    implementações de terceiros existentes que só implementam ``sign()``.
    Quando presente, ``SmartTokenClient.close()`` a invoca via duck typing
    (``getattr(strategy, "close", None)``), em modo best-effort.
    """

    def sign(self, data: bytes) -> bytes:
        """Assina os dados fornecidos usando o mecanismo configurado.

        Args:
            data: bytes a serem assinados (tipicamente o
                ``header.payload`` do JWT).

        Returns:
            A assinatura digital em formato raw (não Base64).

        Raises:
            SigningError: se ocorrer erro durante a assinatura
                (implementação concreta; não definida neste módulo).
        """
        ...


@runtime_checkable
class TlsContextProvider(Protocol):
    """Fornecedor de contexto TLS/mTLS pronto para uso pelo cliente HTTP.

    Abstrai de onde vem o ``ssl.SSLContext`` (certificado/chave em disco,
    KeyStore, HSM, cofre de segredos) — o cliente HTTP só consome o
    contexto pronto, sem saber como foi montado.
    """

    def ssl_context(self) -> ssl.SSLContext:
        """Monta/retorna o contexto TLS/mTLS pronto para a requisição.

        Returns:
            ``ssl.SSLContext`` configurado (certificado de cliente,
            trust store, protocolo TLS) pronto para uso pelo cliente HTTP.
        """
        ...

"""Fronteira (typing.Protocol) entre o cliente HTTP/orquestracao de token
e a assinatura (carga de PEM, certificados, HSM/PKCS#11, servicos remotos).

Define ``SigningStrategy`` (equivalente a ``SigningStrategy.java``). O
restante do cliente programa contra este Protocol; implementacoes
concretas de assinatura so precisam satisfazer essa assinatura.

Nota de design: a configuracao TLS/mTLS NAO usa um Protocol proprio.
No Java, ``TlsSettings``/``SslContextFactory`` sao internos ao builder
(package-private) e o unico contrato que cruza a fronteira Fatia A /
Fatia B e um ``javax.net.ssl.SSLContext`` ja pronto. O equivalente
Python e o proprio ``ssl.SSLContext`` da stdlib, passado diretamente
como parametro — introduzir um Protocol para isso seria uma abstracao
sem correspondente real no design original.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable


@runtime_checkable
class SigningStrategy(Protocol):
    """Estrategia de assinatura digital que abstrai o mecanismo criptografico.

    Equivalente Python de ``SigningStrategy.java``: interface funcional
    com um unico metodo, permitindo que chaves em memoria, HSM/PKCS#11
    ou servicos remotos de assinatura sejam intercambiaveis sem alterar
    o cliente (padrao Strategy).
    """

    def sign(self, data: bytes) -> bytes:
        """Assina os dados fornecidos usando o mecanismo configurado.

        Args:
            data: bytes a serem assinados (tipicamente o
                ``header.payload`` do JWT).

        Returns:
            A assinatura digital em formato raw (nao Base64).

        Raises:
            SigningException: se ocorrer erro durante a assinatura
                (implementacao concreta; nao definida neste modulo).
        """
        ...

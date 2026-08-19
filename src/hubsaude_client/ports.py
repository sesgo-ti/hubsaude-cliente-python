"""Fronteira (typing.Protocol) entre o cliente HTTP/orquestracao de token
e a assinatura (carga de PEM, certificados, HSM/PKCS#11, servicos remotos).

Define ``SigningStrategy``. O restante do cliente programa contra este
Protocol; implementacoes concretas de assinatura so precisam satisfazer
essa assinatura.

Nota de design: a configuracao TLS/mTLS NAO usa um Protocol proprio. O
unico contrato que cruza essa fronteira e um ``ssl.SSLContext`` ja
pronto, passado diretamente como parametro — introduzir um Protocol so
para isso seria uma abstracao sem necessidade real, ja que a stdlib
oferece o tipo pronto.
"""

from __future__ import annotations

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

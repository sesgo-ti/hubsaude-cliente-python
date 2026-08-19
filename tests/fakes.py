"""
Implementacoes fake dos ports, para testar o cliente HTTP/orquestracao
de token sem depender de uma implementacao real de assinatura.
"""

from __future__ import annotations


class FakeSigningStrategy:
    """Satisfaz hubsaude_client.ports.SigningStrategy sem criptografia real."""

    def __init__(self, signature: bytes = b"fake-signature") -> None:
        self._signature = signature
        self.last_signed_data: bytes | None = None

    def sign(self, data: bytes) -> bytes:
        self.last_signed_data = data
        return self._signature

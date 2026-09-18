"""Agregação da configuração TLS/mTLS e resolução do ssl.SSLContext efetivo.

Precedência: ``custom_ssl_context`` (fornecido pronto) > trust anchor em
memória > trust anchor em arquivo/trust store padrão, cruzado com
mTLS-ou-não (a partir de ``client_private_key``+``client_certificate``,
independente de terem vindo de PEM ou PKCS#12 -- ambos resolvem para o
mesmo par chave/certificado).
"""

from __future__ import annotations

import ssl
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes

from hubsaude_client.defaults import DEFAULT_TLS_PROTOCOL


@dataclass
class TlsSettings:
    """Configuração TLS/mTLS resolvida em um ssl.SSLContext.

    Precedência na resolução (ver resolve_ssl_context): custom_ssl_context >
    trust anchor em memória (server_trust_anchor_cert) > trust anchor em
    arquivo ou trust store padrão (server_trust_anchor_path) -- cruzado com
    mTLS quando client_private_key e client_certificate estão presentes.
    """

    client_certificate: x509.Certificate | None = None
    client_private_key: PrivateKeyTypes | None = None
    server_trust_anchor_path: Path | None = None
    server_trust_anchor_cert: x509.Certificate | None = None
    custom_ssl_context: ssl.SSLContext | None = None
    tls_protocol: str = DEFAULT_TLS_PROTOCOL

    def resolve_ssl_context(self) -> ssl.SSLContext:
        """Resolve o ssl.SSLContext efetivo conforme a precedência documentada.

        Returns:
            Contexto SSL pronto para uso, com mTLS habilitado quando o
            material do cliente está disponível.
        """
        if self.custom_ssl_context is not None:
            return self.custom_ssl_context

        from hubsaude_client import ssl_context_factory

        return ssl_context_factory.build_ssl_context(
            server_trust_anchor_path=self.server_trust_anchor_path,
            trusted_cert=self.server_trust_anchor_cert,
            tls_protocol=self.tls_protocol,
            client_key=self.client_private_key,
            client_cert=self.client_certificate,
        )

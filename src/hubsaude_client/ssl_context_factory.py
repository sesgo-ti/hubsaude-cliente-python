"""Construcao do ssl.SSLContext efetivo a partir de material de confianca do
servidor e (opcionalmente) do certificado/chave do cliente para mTLS.

- ssl.SSLContext.load_cert_chain() exige caminho de arquivo real; os
  parametros chegam sempre como objetos em memoria (PrivateKeyTypes/
  x509.Certificate), entao um arquivo temporario de vida curta e sempre
  necessario para a apresentacao do certificado do cliente em mTLS.
- ssl.SSLContext(PROTOCOL_TLS_CLIENT) NAO carrega nenhum CA
  automaticamente -- e preciso chamar load_default_certs()
  explicitamente quando nao ha trust anchor customizado.
"""

from __future__ import annotations

import os
import ssl
import stat
import tempfile
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes

from hubsaude_client.defaults import DEFAULT_TLS_PROTOCOL
from hubsaude_client.exceptions import SmartTokenError
from hubsaude_client.pem_loader import check_certificate_validity, load_certificate

_TLS_VERSIONS: dict[str, ssl.TLSVersion] = {
    "TLSv1.2": ssl.TLSVersion.TLSv1_2,
    "TLSv1.3": ssl.TLSVersion.TLSv1_3,
}


def build_ssl_context(
    *,
    server_trust_anchor_path: Path | None = None,
    trusted_cert: x509.Certificate | None = None,
    tls_protocol: str = DEFAULT_TLS_PROTOCOL,
    client_key: PrivateKeyTypes | None = None,
    client_cert: x509.Certificate | None = None,
) -> ssl.SSLContext:
    """Constroi um ssl.SSLContext configurado para o cliente HubSaude.

    Args:
        server_trust_anchor_path: caminho de um certificado PEM do servidor
            a confiar; ignorado se ``trusted_cert`` for fornecido.
        trusted_cert: certificado do servidor a confiar, ja em memoria; tem
            precedencia sobre ``server_trust_anchor_path``.
        tls_protocol: protocolo TLS ("TLSv1.2" ou "TLSv1.3").
        client_key: chave privada do cliente, para mTLS.
        client_cert: certificado do cliente, para mTLS.

    Returns:
        Contexto SSL configurado. Quando nem ``trusted_cert`` nem
        ``server_trust_anchor_path`` sao fornecidos, usa o trust store padrao
        do sistema. Quando ``client_key``/``client_cert`` estao presentes,
        habilita mTLS.

    Raises:
        SmartTokenError: se o protocolo nao for suportado, ou algum
            certificado estiver fora do periodo de validade.
    """
    version = _resolve_tls_version(tls_protocol)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = version
    context.maximum_version = version

    _configure_trust(context, server_trust_anchor_path, trusted_cert)

    if client_key is not None and client_cert is not None:
        check_certificate_validity(client_cert, _subject_of(client_cert))
        _load_client_cert_chain(context, client_key, client_cert)

    return context


def _resolve_tls_version(tls_protocol: str) -> ssl.TLSVersion:
    try:
        return _TLS_VERSIONS[tls_protocol]
    except KeyError as exc:
        raise SmartTokenError(
            f"Protocolo TLS nao suportado: {tls_protocol}. Protocolos validos: {', '.join(_TLS_VERSIONS)}"
        ) from exc


def _configure_trust(
    context: ssl.SSLContext, server_trust_anchor_path: Path | None, trusted_cert: x509.Certificate | None
) -> None:
    if trusted_cert is not None:
        check_certificate_validity(trusted_cert, _subject_of(trusted_cert))
        context.load_verify_locations(cadata=_to_pem_str(trusted_cert))
    elif server_trust_anchor_path is not None:
        trusted = load_certificate(server_trust_anchor_path)  # ja valida periodo de validade
        context.load_verify_locations(cadata=_to_pem_str(trusted))
    else:
        context.load_default_certs(ssl.Purpose.SERVER_AUTH)


def _load_client_cert_chain(
    context: ssl.SSLContext, client_key: PrivateKeyTypes, client_cert: x509.Certificate
) -> None:
    key_pem = client_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    cert_pem = client_cert.public_bytes(serialization.Encoding.PEM)
    fd, path_str = tempfile.mkstemp(suffix=".pem")
    try:
        os.chmod(path_str, stat.S_IRUSR | stat.S_IWUSR)
        with os.fdopen(fd, "wb") as handle:
            handle.write(key_pem)
            handle.write(cert_pem)
        context.load_cert_chain(certfile=path_str)
    finally:
        os.remove(path_str)


def _to_pem_str(cert: x509.Certificate) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode("ascii")


def _subject_of(cert: x509.Certificate) -> str:
    return cert.subject.rfc4514_string()

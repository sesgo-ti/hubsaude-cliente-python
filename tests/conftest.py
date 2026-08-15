"""Fixtures compartilhadas para a suíte de testes do hubsaude_client."""

from __future__ import annotations

import logging
from collections.abc import Iterator

import pytest


@pytest.fixture(autouse=True)
def _configure_test_logging(caplog: pytest.LogCaptureFixture) -> Iterator[None]:
    """Garante que os logs do pacote fiquem visíveis nos testes."""
    caplog.set_level(logging.DEBUG, logger="hubsaude_client")
    yield


@pytest.fixture
def fake_pem_pair(tmp_path):
    """Gera um par de certificado/chave PEM autoassinado em disco,
    para testes de PemLoader e SslContextFactory sem depender de
    arquivos reais versionados no repositório."""
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "hubsaude-test-client")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )

    key_path = tmp_path / "test_key.pem"
    cert_path = tmp_path / "test_cert.pem"

    key_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

    return {"cert": cert_path, "key": key_path}

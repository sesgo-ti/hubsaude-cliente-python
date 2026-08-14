"""Fixtures compartilhadas para a suíte de testes do hubsaude_client."""

from __future__ import annotations

import logging
from collections.abc import Iterator

import pytest


@pytest.fixture(autouse=True)
def _configure_test_logging(caplog: pytest.LogCaptureFixture) -> Iterator[None]:
    """Garante que os logs do pacote fiquem visíveis nos testes,
    equivalente ao papel do logback-test.xml no projeto Java."""
    caplog.set_level(logging.DEBUG, logger="hubsaude_client")  # TODO: inserir o correto
    yield


@pytest.fixture
def fake_pem_pair(tmp_path):
    # TODO: validar essa implementação do Claude
    """Gera um par de certificado/chave PEM autoassinado em disco,
    para testes de PemLoader e SslContextFactory sem depender de
    arquivos reais versionados no repositório."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    import datetime

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "hubsaude-test-client")]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(
            datetime.datetime.now(datetime.timezone.utc)
            + datetime.timedelta(days=1)
        )
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


@pytest.fixture
def smart_configuration_response() -> dict:
    """Payload de descoberta SMART (.well-known/smart-configuration)
    usado nos testes de SmartConfigurationDiscovery."""
    return {
        "token_endpoint": "PLACEHOLDER",  # TODO: inserir o correto
        "token_endpoint_auth_methods_supported": ["PLACEHOLDER"],  # TODO: inserir o correto
        "grant_types_supported": ["PLACEHOLDER"],  # TODO: inserir o correto
    }


@pytest.fixture
def trace_context():
    """Contexto de rastreio limpo para cada teste, evitando vazamento
    de estado entre testes (equivalente ao TraceContextTest.java)."""
    from hubsaude_client.trace_context import TraceContext  # TODO: inserir o correto (confirmar módulo/classe real)

    ctx = TraceContext.new()  # TODO: inserir o correto (confirmar API real: construtor vs. factory method)
    yield ctx
    ctx.clear()  # TODO: inserir o correto (confirmar método real de limpeza, se existir)
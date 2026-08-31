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


@pytest.fixture
def fake_ec_pem_pair(tmp_path):
    """Par de certificado/chave EC (P-256) autoassinado em disco."""
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "hubsaude-test-client-ec")])
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

    key_path = tmp_path / "test_ec_key.pem"
    cert_path = tmp_path / "test_ec_cert.pem"
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
def fake_mismatched_pem_pair(tmp_path, fake_pem_pair):
    """Certificado de uma chave RSA diferente da chave de fake_pem_pair,
    para testar deteccao de par chave/certificado inconsistente."""
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "hubsaude-test-other")])
    other_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(other_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1))
        .sign(other_key, hashes.SHA256())
    )
    other_cert_path = tmp_path / "other_cert.pem"
    other_cert_path.write_bytes(other_cert.public_bytes(serialization.Encoding.PEM))
    return {"matching_key": fake_pem_pair["key"], "mismatched_cert": other_cert_path}


@pytest.fixture
def fake_mismatched_ec_pem_pair(tmp_path, fake_ec_pem_pair):
    """Certificado de uma chave EC diferente da chave de fake_ec_pem_pair,
    para testar deteccao de par chave/certificado EC inconsistente."""
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    other_key = ec.generate_private_key(ec.SECP256R1())
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "hubsaude-test-other-ec")])
    other_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(other_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1))
        .sign(other_key, hashes.SHA256())
    )
    other_cert_path = tmp_path / "other_ec_cert.pem"
    other_cert_path.write_bytes(other_cert.public_bytes(serialization.Encoding.PEM))
    return {"matching_key": fake_ec_pem_pair["key"], "mismatched_cert": other_cert_path}


@pytest.fixture
def fake_encrypted_pem_key(tmp_path):
    """Chave privada RSA cifrada com senha conhecida, em disco."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    password = b"senha-correta-123"
    key_path = tmp_path / "test_key_encrypted.pem"
    key_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(password),
        )
    )
    # bytearray (mutavel): pem_loader.load_private_key consome e zera a senha apos o uso.
    return {"key": key_path, "password": bytearray(password)}


@pytest.fixture
def fake_expired_cert_pem(tmp_path):
    """Certificado X.509 autoassinado ja expirado, em disco."""
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "hubsaude-test-expired")])
    not_before = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=10)
    not_after = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .sign(key, hashes.SHA256())
    )
    cert_path = tmp_path / "test_cert_expired.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return cert_path


@pytest.fixture
def fake_not_yet_valid_cert_pem(tmp_path):
    """Certificado X.509 autoassinado ainda nao valido (not_before no futuro), em disco."""
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "hubsaude-test-not-yet-valid")])
    not_before = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1)
    not_after = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=10)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .sign(key, hashes.SHA256())
    )
    cert_path = tmp_path / "test_cert_not_yet_valid.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return cert_path


@pytest.fixture
def fake_pkcs12_bundle(tmp_path):
    """Bundle PKCS#12 (chave + certificado) autoassinado, cifrado, em disco."""
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.serialization import pkcs12
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "hubsaude-test-pkcs12")])
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
    password = b"p12-senha-123"
    p12_bytes = pkcs12.serialize_key_and_certificates(
        b"hubsaude-client", key, cert, None, serialization.BestAvailableEncryption(password)
    )
    p12_path = tmp_path / "bundle.p12"
    p12_path.write_bytes(p12_bytes)
    return {"path": p12_path, "bytes": p12_bytes, "password": password}


@pytest.fixture
def fake_pkcs12_bundle_without_key(tmp_path):
    """Bundle PKCS#12 valido mas sem chave privada (so certificado)."""
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.serialization import pkcs12
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "hubsaude-test-pkcs12-no-key")])
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
    password = b"p12-sem-chave-123"
    p12_bytes = pkcs12.serialize_key_and_certificates(
        b"hubsaude-client-no-key", None, cert, None, serialization.BestAvailableEncryption(password)
    )
    p12_path = tmp_path / "bundle_no_key.p12"
    p12_path.write_bytes(p12_bytes)
    return {"path": p12_path, "password": password}


@pytest.fixture
def fake_pkcs12_bundle_without_certificate(tmp_path):
    """Bundle PKCS#12 valido mas sem certificado (so chave privada)."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.serialization import pkcs12

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    password = b"p12-sem-certificado-123"
    p12_bytes = pkcs12.serialize_key_and_certificates(
        b"hubsaude-client-no-cert", key, None, None, serialization.BestAvailableEncryption(password)
    )
    p12_path = tmp_path / "bundle_no_cert.p12"
    p12_path.write_bytes(p12_bytes)
    return {"path": p12_path, "password": password}


@pytest.fixture
def real_mtls_client_cert_rejection(tmp_path):
    """Fabrica de handshakes mTLS *reais* (sockets loopback + OpenSSL de
    verdade, sem ``ssl.SSLError`` simulado a mao) em que o servidor
    rejeita o certificado de cliente por CA desconhecida.

    Devolve uma funcao ``handshake(tls_protocol) -> BaseException | None``
    que: gera uma CA de servidor e uma CA de cliente *distintas* (o
    servidor so' confia na propria), sobe um servidor TLS efemero em
    ``127.0.0.1`` exigindo certificado de cliente, conecta usando
    ``hubsaude_client.ssl_context_factory.build_ssl_context`` -- o mesmo
    caminho de producao usado pelo builder/client.py -- e devolve a
    excecao capturada do lado do cliente (``None`` se o handshake, ao
    contrario do esperado, tiver sucesso).

    Usada para validar heuristicas de classificacao de erro
    (``error_classifier.is_likely_client_certificate_rejection``) contra
    o comportamento real do OpenSSL, e nao apenas contra mensagens de
    ``ssl.SSLError`` construidas manualmente no restante da suite.
    """
    import datetime
    import socket
    import ssl
    import threading

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    from hubsaude_client import ssl_context_factory

    def _make_ca(cn: str):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1))
            .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA256())
        )
        return key, cert

    def _make_leaf(ca_key, ca_cert, cn: str, *, is_server: bool):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
        builder = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(ca_cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1))
            .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1))
        )
        if is_server:
            builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
        return key, builder.sign(ca_key, hashes.SHA256())

    server_ca_key, server_ca_cert = _make_ca("hubsaude-test Server CA")
    server_key, server_cert = _make_leaf(server_ca_key, server_ca_cert, "localhost", is_server=True)
    # CA distinta e propositalmente NAO confiada pelo servidor -- e' isso
    # que faz o servidor rejeitar o certificado de cliente.
    client_ca_key, client_ca_cert = _make_ca("hubsaude-test Client CA (untrusted)")
    client_key, client_cert = _make_leaf(client_ca_key, client_ca_cert, "hubsaude-test-client", is_server=False)

    server_ca_path = tmp_path / "server_ca.pem"
    server_ca_path.write_bytes(server_ca_cert.public_bytes(serialization.Encoding.PEM))
    server_cert_path = tmp_path / "server_cert.pem"
    server_cert_path.write_bytes(server_cert.public_bytes(serialization.Encoding.PEM))
    server_key_path = tmp_path / "server_key.pem"
    server_key_path.write_bytes(
        server_key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
    )

    def handshake(tls_protocol: str) -> BaseException | None:
        version = ssl_context_factory._resolve_tls_version(tls_protocol)  # mesma resolucao de producao

        server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_ctx.load_cert_chain(str(server_cert_path), str(server_key_path))
        server_ctx.verify_mode = ssl.CERT_REQUIRED
        server_ctx.load_verify_locations(cafile=str(server_ca_path))
        server_ctx.minimum_version = version
        server_ctx.maximum_version = version

        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]

        def _accept_and_reject() -> None:
            try:
                raw_conn, _addr = listener.accept()
                try:
                    with server_ctx.wrap_socket(raw_conn, server_side=True) as tls_conn:
                        tls_conn.recv(16)  # forca a troca pos-handshake sob TLS 1.3
                except ssl.SSLError:
                    pass  # esperado: e' exatamente a rejeicao sob teste
            except OSError:
                pass

        server_thread = threading.Thread(target=_accept_and_reject, daemon=True)
        server_thread.start()

        client_context = ssl_context_factory.build_ssl_context(
            trusted_cert=server_ca_cert,
            tls_protocol=tls_protocol,
            client_key=client_key,
            client_cert=client_cert,
        )
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.settimeout(5)
        client_socket.connect(("127.0.0.1", port))
        captured: BaseException | None = None
        try:
            with client_context.wrap_socket(client_socket, server_hostname="localhost") as tls_client:
                tls_client.send(b"ping")
                tls_client.recv(16)
        except ssl.SSLError as exc:
            captured = exc
        finally:
            server_thread.join(timeout=5)
            listener.close()
        return captured

    return handshake

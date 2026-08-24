from __future__ import annotations

from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from hubsaude_client import pem_loader
from hubsaude_client.exceptions import SmartTokenError


def test_load_private_key_rsa_unencrypted(fake_pem_pair) -> None:
    key = pem_loader.load_private_key(fake_pem_pair["key"])
    assert isinstance(key, rsa.RSAPrivateKey)
    assert key.key_size == 2048


def test_load_private_key_ec(fake_ec_pem_pair) -> None:
    key = pem_loader.load_private_key(fake_ec_pem_pair["key"])
    assert isinstance(key, ec.EllipticCurvePrivateKey)
    assert key.curve.name == "secp256r1"


def test_load_private_key_encrypted_with_correct_password(fake_encrypted_pem_key) -> None:
    key = pem_loader.load_private_key(fake_encrypted_pem_key["key"], fake_encrypted_pem_key["password"])
    assert isinstance(key, rsa.RSAPrivateKey)


def test_load_private_key_encrypted_without_password_raises(fake_encrypted_pem_key) -> None:
    with pytest.raises(SmartTokenError, match="requer senha"):
        pem_loader.load_private_key(fake_encrypted_pem_key["key"])


def test_load_private_key_encrypted_with_wrong_password_raises(fake_encrypted_pem_key) -> None:
    with pytest.raises(SmartTokenError, match="verifique a senha"):
        pem_loader.load_private_key(fake_encrypted_pem_key["key"], bytearray(b"senha-errada"))


def test_load_private_key_password_is_zeroed_after_use(fake_encrypted_pem_key) -> None:
    password = fake_encrypted_pem_key["password"]
    pem_loader.load_private_key(fake_encrypted_pem_key["key"], password)
    assert password == bytearray(len(password))


def test_load_private_key_invalid_format_raises(tmp_path: Path) -> None:
    garbage_path = tmp_path / "garbage.pem"
    garbage_path.write_text("nao e um PEM valido")
    with pytest.raises(SmartTokenError, match="formato"):
        pem_loader.load_private_key(garbage_path)


def test_load_private_key_from_string(fake_pem_pair) -> None:
    pem_content = fake_pem_pair["key"].read_text()
    key = pem_loader.load_private_key_from_string(pem_content, None, "<string>")
    assert isinstance(key, rsa.RSAPrivateKey)


def test_validate_minimum_key_size_rejects_weak_rsa() -> None:
    weak_key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    with pytest.raises(SmartTokenError, match="1024 bits"):
        pem_loader.validate_minimum_key_size(weak_key, "teste")


def test_load_certificate(fake_pem_pair) -> None:
    cert = pem_loader.load_certificate(fake_pem_pair["cert"])
    assert cert.subject.rfc4514_string() == "CN=hubsaude-test-client"


def test_load_certificate_expired_raises(fake_expired_cert_pem) -> None:
    with pytest.raises(SmartTokenError, match="expirado"):
        pem_loader.load_certificate(fake_expired_cert_pem)


def test_load_certificate_from_string_not_a_certificate_raises(fake_pem_pair) -> None:
    key_pem_content = fake_pem_pair["key"].read_text()
    with pytest.raises(SmartTokenError, match="certificado"):
        pem_loader.load_certificate_from_string(key_pem_content, "<string>")

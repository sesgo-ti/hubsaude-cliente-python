from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from hubsaude_client import strategy_factory
from hubsaude_client.exceptions import SmartTokenError
from hubsaude_client.ports import SigningStrategy
from hubsaude_client.private_key_signing_strategy import PrivateKeySigningStrategy


def test_from_private_key_returns_signing_strategy() -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    strategy = strategy_factory.from_private_key(key)
    assert isinstance(strategy, SigningStrategy)
    assert isinstance(strategy, PrivateKeySigningStrategy)
    assert strategy.jwt_algorithm == "RS384"


def test_from_pem_file_loads_and_signs(fake_pem_pair) -> None:
    strategy = strategy_factory.from_pem_file(fake_pem_pair["key"], jwt_algorithm="RS256")
    signature = strategy.sign(b"data")
    assert len(signature) > 0


def test_from_pem_string_loads_and_signs(fake_pem_pair) -> None:
    pem_content = fake_pem_pair["key"].read_text()
    strategy = strategy_factory.from_pem_string(pem_content, jwt_algorithm="RS256")
    signature = strategy.sign(b"data")
    assert len(signature) > 0


def test_from_pem_file_password_is_zeroed_after_use(fake_encrypted_pem_key) -> None:
    password = fake_encrypted_pem_key["password"]
    strategy_factory.from_pem_file(fake_encrypted_pem_key["key"], password)
    assert password == bytearray(len(password))


def test_from_pkcs12_with_path_loads_and_signs(fake_pkcs12_bundle) -> None:
    strategy = strategy_factory.from_pkcs12(
        fake_pkcs12_bundle["path"], fake_pkcs12_bundle["password"], jwt_algorithm="RS256"
    )
    signature = strategy.sign(b"data")
    assert len(signature) > 0


def test_from_pkcs12_with_bytes_loads_and_signs(fake_pkcs12_bundle) -> None:
    strategy = strategy_factory.from_pkcs12(
        fake_pkcs12_bundle["bytes"], fake_pkcs12_bundle["password"], jwt_algorithm="RS256"
    )
    signature = strategy.sign(b"data")
    assert len(signature) > 0


def test_from_pkcs12_wrong_password_raises(fake_pkcs12_bundle) -> None:
    with pytest.raises(SmartTokenError, match="senha incorreta"):
        strategy_factory.from_pkcs12(fake_pkcs12_bundle["path"], b"senha-errada")


def test_from_pkcs12_without_private_key_raises(fake_pkcs12_bundle_without_key) -> None:
    with pytest.raises(SmartTokenError, match="nao contem chave privada"):
        strategy_factory.from_pkcs12(fake_pkcs12_bundle_without_key["path"], fake_pkcs12_bundle_without_key["password"])


def test_load_pkcs12_key_and_certificate_returns_both(fake_pkcs12_bundle) -> None:
    key, cert = strategy_factory.load_pkcs12_key_and_certificate(
        fake_pkcs12_bundle["path"], fake_pkcs12_bundle["password"]
    )
    assert key is not None
    assert cert is not None


def test_load_pkcs12_key_and_certificate_wrong_password_raises(fake_pkcs12_bundle) -> None:
    with pytest.raises(SmartTokenError, match="senha incorreta"):
        strategy_factory.load_pkcs12_key_and_certificate(fake_pkcs12_bundle["path"], b"senha-errada")


def test_load_pkcs12_key_and_certificate_without_private_key_raises(fake_pkcs12_bundle_without_key) -> None:
    with pytest.raises(SmartTokenError, match="nao contem chave privada"):
        strategy_factory.load_pkcs12_key_and_certificate(
            fake_pkcs12_bundle_without_key["path"], fake_pkcs12_bundle_without_key["password"]
        )


def test_load_pkcs12_key_and_certificate_without_certificate_raises(fake_pkcs12_bundle_without_certificate) -> None:
    with pytest.raises(SmartTokenError, match="nao contem certificado"):
        strategy_factory.load_pkcs12_key_and_certificate(
            fake_pkcs12_bundle_without_certificate["path"], fake_pkcs12_bundle_without_certificate["password"]
        )

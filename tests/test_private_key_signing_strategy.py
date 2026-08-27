from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils

from hubsaude_client.exceptions import SigningError
from hubsaude_client.ports import SigningStrategy
from hubsaude_client.private_key_signing_strategy import PrivateKeySigningStrategy


def test_satisfies_signing_strategy_protocol() -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    strategy = PrivateKeySigningStrategy(key)
    assert isinstance(strategy, SigningStrategy)


def test_default_jwt_algorithm_is_rs384() -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    strategy = PrivateKeySigningStrategy(key)
    assert strategy.jwt_algorithm == "RS384"


def test_sign_rsa_pkcs1_produces_verifiable_signature() -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    strategy = PrivateKeySigningStrategy(key, "RS256")
    data = b"header.payload"
    signature = strategy.sign(data)
    key.public_key().verify(signature, data, padding.PKCS1v15(), _sha256())


def test_sign_rsa_pss_produces_verifiable_signature() -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    strategy = PrivateKeySigningStrategy(key, "PS256")
    data = b"header.payload"
    signature = strategy.sign(data)
    key.public_key().verify(signature, data, padding.PSS(mgf=padding.MGF1(_sha256()), salt_length=32), _sha256())


def test_sign_ecdsa_produces_p1363_signature_of_expected_length() -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    strategy = PrivateKeySigningStrategy(key, "ES256")
    data = b"header.payload"
    signature = strategy.sign(data)
    assert len(signature) == 64  # 32 bytes R + 32 bytes S

    half = len(signature) // 2
    r = int.from_bytes(signature[:half], "big")
    s = int.from_bytes(signature[half:], "big")
    der_signature = utils.encode_dss_signature(r, s)
    key.public_key().verify(der_signature, data, ec.ECDSA(_sha256()))


def test_sign_ecdsa_p521_pads_to_fixed_length() -> None:
    key = ec.generate_private_key(ec.SECP521R1())
    strategy = PrivateKeySigningStrategy(key, "ES512")
    signature = strategy.sign(b"data")
    assert len(signature) == 132  # 66 bytes R + 66 bytes S, mesmo se r/s < 66 bytes


def test_sign_wraps_key_type_mismatch_in_signing_error() -> None:
    ec_key = ec.generate_private_key(ec.SECP256R1())
    strategy = PrivateKeySigningStrategy(ec_key, "RS256")  # RS256 exige chave RSA
    with pytest.raises(SigningError, match="RSA"):
        strategy.sign(b"data")


def test_rejects_weak_rsa_key_on_construction() -> None:
    weak_key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    with pytest.raises(Exception):  # SmartTokenError, via pem_loader.validate_minimum_key_size
        PrivateKeySigningStrategy(weak_key)


def test_algorithm_params_property_matches_configured_algorithm() -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    strategy = PrivateKeySigningStrategy(key, "RS256")
    assert strategy.algorithm_params.jwt_algorithm == "RS256"


def test_sign_wraps_ecdsa_algorithm_with_rsa_key_in_signing_error() -> None:
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    strategy = PrivateKeySigningStrategy(rsa_key, "ES256")  # ES256 exige chave EC
    with pytest.raises(SigningError, match="EC"):
        strategy.sign(b"data")


def test_sign_wraps_unexpected_error_in_signing_error(monkeypatch: pytest.MonkeyPatch) -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    strategy = PrivateKeySigningStrategy(key, "ES256")

    def _boom(*_args: object, **_kwargs: object) -> bytes:
        raise ValueError("erro inesperado na conversao da assinatura")

    monkeypatch.setattr("hubsaude_client.private_key_signing_strategy.algorithms.encode_p1363", _boom)
    with pytest.raises(SigningError, match="Falha ao assinar dados"):
        strategy.sign(b"data")


def test_sign_raises_for_unsupported_algorithm_params(monkeypatch: pytest.MonkeyPatch) -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    strategy = PrivateKeySigningStrategy(key, "RS256")
    monkeypatch.setattr(strategy, "_params", object())
    with pytest.raises(SigningError, match="nao suportado"):
        strategy.sign(b"data")


def _sha256():
    from cryptography.hazmat.primitives import hashes

    return hashes.SHA256()

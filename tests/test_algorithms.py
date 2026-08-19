from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric import ec, utils

from hubsaude_client import algorithms
from hubsaude_client.exceptions import SmartTokenError


@pytest.mark.parametrize(
    ("jwt_algorithm", "expected_hash_name"),
    [("RS256", "sha256"), ("rs256", "sha256"), ("RS384", "sha384"), ("RS512", "sha512")],
)
def test_resolve_rsa_pkcs1(jwt_algorithm: str, expected_hash_name: str) -> None:
    params = algorithms.resolve(jwt_algorithm)
    assert isinstance(params, algorithms.RsaPkcs1Params)
    assert params.jwt_algorithm == jwt_algorithm.upper()
    assert params.hash_algorithm.name == expected_hash_name


@pytest.mark.parametrize(
    ("jwt_algorithm", "expected_hash_name", "expected_salt_length"),
    [("PS256", "sha256", 32), ("PS384", "sha384", 48), ("PS512", "sha512", 64)],
)
def test_resolve_rsa_pss(jwt_algorithm: str, expected_hash_name: str, expected_salt_length: int) -> None:
    params = algorithms.resolve(jwt_algorithm)
    assert isinstance(params, algorithms.RsaPssParams)
    assert params.hash_algorithm.name == expected_hash_name
    assert params.salt_length == expected_salt_length


@pytest.mark.parametrize(
    ("jwt_algorithm", "expected_hash_name", "expected_curve_name", "expected_sig_len"),
    [
        ("ES256", "sha256", "secp256r1", 64),
        ("ES384", "sha384", "secp384r1", 96),
        ("ES512", "sha512", "secp521r1", 132),
    ],
)
def test_resolve_ecdsa(
    jwt_algorithm: str, expected_hash_name: str, expected_curve_name: str, expected_sig_len: int
) -> None:
    params = algorithms.resolve(jwt_algorithm)
    assert isinstance(params, algorithms.EcdsaParams)
    assert params.hash_algorithm.name == expected_hash_name
    assert params.curve.name == expected_curve_name
    assert params.signature_length == expected_sig_len


def test_resolve_unknown_algorithm_lists_valid_ones() -> None:
    with pytest.raises(SmartTokenError) as excinfo:
        algorithms.resolve("HS256")
    message = str(excinfo.value)
    assert "HS256" in message
    for valid in algorithms.VALID_JWT_ALGORITHMS:
        assert valid in message


def test_encode_decode_p1363_roundtrip() -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    der_signature = key.sign(b"data", ec.ECDSA(algorithms.resolve("ES256").hash_algorithm))
    p1363 = algorithms.encode_p1363(der_signature, signature_length=64)
    assert len(p1363) == 64

    der_roundtrip = algorithms.decode_p1363(p1363)
    r, s = utils.decode_dss_signature(der_roundtrip)
    r_original, s_original = utils.decode_dss_signature(der_signature)
    assert (r, s) == (r_original, s_original)

"""Tabela alg JWT (JWA) -> parametros criptograficos, e conversao de
assinaturas ECDSA entre DER e o formato bruto R||S exigido pela RFC 7518 §3.4.

Modulo compartilhado: tanto a estrategia de assinatura quanto a validacao de
consistencia chave/certificado precisam do mesmo mapeamento algoritmo ->
parametros criptograficos, entao ele vive aqui para evitar duplicacao.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Union

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

from hubsaude_client.exceptions import SmartTokenError

VALID_JWT_ALGORITHMS: tuple[str, ...] = (
    "RS256",
    "RS384",
    "RS512",
    "PS256",
    "PS384",
    "PS512",
    "ES256",
    "ES384",
    "ES512",
)


@dataclass(frozen=True)
class RsaPkcs1Params:
    """Parametros para RSA PKCS#1 v1.5 (RS256/RS384/RS512)."""

    jwt_algorithm: str
    hash_algorithm: hashes.HashAlgorithm


@dataclass(frozen=True)
class RsaPssParams:
    """Parametros para RSA-PSS (PS256/PS384/PS512), RFC 7518 §3.5."""

    jwt_algorithm: str
    hash_algorithm: hashes.HashAlgorithm
    salt_length: int


@dataclass(frozen=True)
class EcdsaParams:
    """Parametros para ECDSA (ES256/ES384/ES512), RFC 7518 §3.4.

    signature_length e o comprimento total, em bytes, da assinatura R||S
    (2x o comprimento de cada coordenada, arredondado para cima).
    """

    jwt_algorithm: str
    hash_algorithm: hashes.HashAlgorithm
    curve: ec.EllipticCurve
    signature_length: int


AlgorithmParams = Union[RsaPkcs1Params, RsaPssParams, EcdsaParams]

_PKCS1: dict[str, hashes.HashAlgorithm] = {
    "RS256": hashes.SHA256(),
    "RS384": hashes.SHA384(),
    "RS512": hashes.SHA512(),
}

_PSS: dict[str, tuple[hashes.HashAlgorithm, int]] = {
    "PS256": (hashes.SHA256(), 32),
    "PS384": (hashes.SHA384(), 48),
    "PS512": (hashes.SHA512(), 64),
}

_ECDSA: dict[str, tuple[hashes.HashAlgorithm, ec.EllipticCurve, int]] = {
    "ES256": (hashes.SHA256(), ec.SECP256R1(), 64),
    "ES384": (hashes.SHA384(), ec.SECP384R1(), 96),
    "ES512": (hashes.SHA512(), ec.SECP521R1(), 132),
}


def resolve(jwt_algorithm: str) -> AlgorithmParams:
    """Resolve os parametros criptograficos para um algoritmo JWT (JWA).

    Args:
        jwt_algorithm: nome do algoritmo, case-insensitive (ex: RS256, rs256).

    Returns:
        Os parametros criptograficos correspondentes.

    Raises:
        SmartTokenError: se o algoritmo nao for reconhecido.
    """
    normalized = jwt_algorithm.upper()
    if normalized in _PKCS1:
        return RsaPkcs1Params(jwt_algorithm=normalized, hash_algorithm=_PKCS1[normalized])
    if normalized in _PSS:
        hash_algorithm, salt_length = _PSS[normalized]
        return RsaPssParams(jwt_algorithm=normalized, hash_algorithm=hash_algorithm, salt_length=salt_length)
    if normalized in _ECDSA:
        hash_algorithm, curve, signature_length = _ECDSA[normalized]
        return EcdsaParams(
            jwt_algorithm=normalized,
            hash_algorithm=hash_algorithm,
            curve=curve,
            signature_length=signature_length,
        )
    raise SmartTokenError(
        f"Algoritmo JWT nao suportado: {jwt_algorithm}. " f"Algoritmos validos: {', '.join(VALID_JWT_ALGORITHMS)}"
    )


def encode_p1363(der_signature: bytes, signature_length: int) -> bytes:
    """Converte uma assinatura ECDSA de DER para o formato bruto R||S.

    Args:
        der_signature: assinatura no formato DER, produzida por
            ``PrivateKey.sign(data, ec.ECDSA(hash))``.
        signature_length: comprimento total esperado da saida (2x o
            comprimento de cada coordenada, ver EcdsaParams.signature_length).

    Returns:
        Assinatura no formato R||S (big-endian, largura fixa), exigido pela
        RFC 7518 §3.4 para um JWS.
    """
    r, s = utils.decode_dss_signature(der_signature)
    coord_length = signature_length // 2
    return r.to_bytes(coord_length, "big") + s.to_bytes(coord_length, "big")


def decode_p1363(p1363_signature: bytes) -> bytes:
    """Converte uma assinatura ECDSA do formato bruto R||S para DER.

    Necessario porque ``PublicKey.verify(..., ec.ECDSA(hash))`` da biblioteca
    ``cryptography`` exige o formato DER.

    Args:
        p1363_signature: assinatura no formato R||S (largura fixa).

    Returns:
        Assinatura no formato DER.
    """
    half = len(p1363_signature) // 2
    r = int.from_bytes(p1363_signature[:half], "big")
    s = int.from_bytes(p1363_signature[half:], "big")
    return utils.encode_dss_signature(r, s)

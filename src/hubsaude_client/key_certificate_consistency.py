"""Validacao fail-fast de consistencia entre o material de assinatura
(chave privada ou SigningStrategy) e o certificado X.509 do cliente.

Assina um desafio fixo e confere a assinatura com a chave publica
extraida do certificado -- porte de ``KeyCertificateConsistency.java``.
Dois pontos de entrada:

- :func:`verify_key_pair`: recebe uma chave privada "solta" (RSA ou EC)
  diretamente -- equivalente publico de
  ``SmartTokenClient.verifyKeyPairConsistency``. O algoritmo da assinatura de teste e' inferido do tipo/curva da
  chave (RSA -> RS256; EC -> ES256/ES384/ES512 conforme a curva).
- :func:`verify_strategy`: recebe uma ``SigningStrategy`` ja construida.
  Limitacao: so e possivel verificar quando a estrategia e uma
  ``PrivateKeySigningStrategy``, pois e necessario conhecer o algoritmo
  para verificar a assinatura -- estrategias customizadas (HSM/cofre de
  segredos com algoritmo nao exposto) sao aceitas sem validacao.
"""

from __future__ import annotations

import logging

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes

from hubsaude_client import algorithms
from hubsaude_client.algorithms import AlgorithmParams, EcdsaParams, RsaPkcs1Params, RsaPssParams
from hubsaude_client.exceptions import SmartTokenError
from hubsaude_client.ports import SigningStrategy
from hubsaude_client.private_key_signing_strategy import PrivateKeySigningStrategy

_LOGGER = logging.getLogger(__name__)

_CHALLENGE = b"key-pair-consistency-check"

#: Mapeia a curva EC (nome retornado por ``EllipticCurve.name``) para o
#: algoritmo JWT (JWA) cujo tamanho de assinatura R||S (RFC 7518 Sec3.4)
#: e' compativel -- necessario porque, ao contrario do lado Java (que usa
#: sempre "SHA256withECDSA", independente da curva), a conversao
#: DER->R||S do Python (``algorithms.encode_p1363``) exige um
#: ``signature_length`` que corresponde ao tamanho da curva; usar sempre
#: ES256 quebraria (overflow) para chaves P-384/P-521.
_EC_CURVE_TO_JWT_ALGORITHM: dict[str, str] = {
    "secp256r1": "ES256",
    "secp384r1": "ES384",
    "secp521r1": "ES512",
}


def verify_key_pair(private_key: PrivateKeyTypes, certificate: x509.Certificate) -> None:
    """Verifica que uma chave privada "solta" corresponde a chave publica
    do certificado, assinando um desafio e conferindo a assinatura.

    Porte de ``KeyCertificateConsistency.verifyKeyPair`` (``.java``, via o
    wrapper publico ``SmartTokenClient.verifyKeyPairConsistency``).
    Complementa :func:`verify_strategy`: aquela
    funcao exige uma :class:`~hubsaude_client.ports.SigningStrategy` ja
    construida (e so consegue validar quando ela e uma
    ``PrivateKeySigningStrategy``); esta aceita a chave privada
    diretamente, para quem monta a propria estrategia fora do builder
    (cenario HSM/customizado) e quer testar a consistencia chave<->certificado
    antes de usar.

    Args:
        private_key: chave privada RSA ou EC a validar.
        certificate: certificado X.509 com a chave publica correspondente.

    Raises:
        SmartTokenError: se o tipo/curva da chave nao for suportado para
            esta verificacao, ou se a assinatura de teste nao puder ser
            verificada com a chave publica do certificado.
    """
    jwt_algorithm = _determine_verification_algorithm(private_key)
    try:
        strategy = PrivateKeySigningStrategy(private_key, jwt_algorithm)
    except SmartTokenError:
        raise
    except Exception as exc:
        raise SmartTokenError(f"Falha ao verificar consistencia entre chave privada e certificado: {exc}", exc) from exc
    verify_strategy(strategy, certificate)


def _determine_verification_algorithm(private_key: PrivateKeyTypes) -> str:
    """Determina o algoritmo JWT (JWA) a usar na assinatura de teste, a
    partir do tipo (e, para EC, da curva) da chave privada.

    Args:
        private_key: chave privada a inspecionar.

    Returns:
        O algoritmo JWT (JWA) compativel com o tipo/curva da chave.

    Raises:
        SmartTokenError: se o tipo de chave, ou a curva EC, nao for
            suportado por esta biblioteca (ver ``algorithms.py`` --
            apenas RSA e EC/P-256/P-384/P-521 sao suportados; ao
            contrario do Java, que tambem aceita Ed25519/Ed448, este
            pacote nao os mapeia em ``algorithms.py``).
    """
    if isinstance(private_key, rsa.RSAPrivateKey):
        return "RS256"
    if isinstance(private_key, ec.EllipticCurvePrivateKey):
        curve_name = private_key.curve.name
        algorithm = _EC_CURVE_TO_JWT_ALGORITHM.get(curve_name)
        if algorithm is not None:
            return algorithm
        raise SmartTokenError(
            f"Curva EC nao suportada para validacao de consistencia chave-certificado: {curve_name!r}"
            f" (suportadas: {', '.join(sorted(_EC_CURVE_TO_JWT_ALGORITHM))})"
        )
    raise SmartTokenError(
        f"Tipo de chave nao suportado para validacao de consistencia chave-certificado:"
        f" {type(private_key).__name__} (suportados: RSA, EC)"
    )


def verify_strategy(strategy: SigningStrategy, certificate: x509.Certificate) -> None:
    """Verifica que a estrategia de assinatura corresponde ao certificado.

    Args:
        strategy: estrategia de assinatura a validar.
        certificate: certificado X.509 com a chave publica correspondente.

    Raises:
        SmartTokenError: se a assinatura de teste nao puder ser verificada
            com a chave publica do certificado.
    """
    if not isinstance(strategy, PrivateKeySigningStrategy):
        _LOGGER.debug(
            "Estrategia de assinatura customizada: consistencia com o certificado "
            "nao pode ser verificada automaticamente"
        )
        return
    try:
        signature = strategy.sign(_CHALLENGE)
        _verify_signature(certificate.public_key(), strategy.algorithm_params, signature)
        _LOGGER.debug("Verificacao de consistencia estrategia-certificado concluida com sucesso")
    except SmartTokenError:
        raise
    except Exception as exc:
        raise SmartTokenError(f"Falha ao verificar consistencia entre chave privada e certificado: {exc}", exc) from exc


def _verify_signature(public_key: object, params: AlgorithmParams, signature: bytes) -> None:
    try:
        if isinstance(params, RsaPkcs1Params):
            if not isinstance(public_key, rsa.RSAPublicKey):
                raise SmartTokenError(f"Certificado nao contem chave publica RSA, recebida {type(public_key).__name__}")
            public_key.verify(signature, _CHALLENGE, padding.PKCS1v15(), params.hash_algorithm)
        elif isinstance(params, RsaPssParams):
            if not isinstance(public_key, rsa.RSAPublicKey):
                raise SmartTokenError(f"Certificado nao contem chave publica RSA, recebida {type(public_key).__name__}")
            public_key.verify(
                signature,
                _CHALLENGE,
                padding.PSS(mgf=padding.MGF1(params.hash_algorithm), salt_length=params.salt_length),
                params.hash_algorithm,
            )
        elif isinstance(params, EcdsaParams):
            if not isinstance(public_key, ec.EllipticCurvePublicKey):
                raise SmartTokenError(f"Certificado nao contem chave publica EC, recebida {type(public_key).__name__}")
            der_signature = algorithms.decode_p1363(signature)
            public_key.verify(der_signature, _CHALLENGE, ec.ECDSA(params.hash_algorithm))
        else:
            raise SmartTokenError(f"Parametro de algoritmo nao suportado: {type(params).__name__}")
    except InvalidSignature as exc:
        raise SmartTokenError("Chave privada nao corresponde ao certificado: assinatura invalida", exc) from exc

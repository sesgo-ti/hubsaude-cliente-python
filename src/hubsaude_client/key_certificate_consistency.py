"""Validacao fail-fast de consistencia entre a estrategia de assinatura e o
certificado X.509 do cliente.

Assina um desafio fixo com a estrategia e confere a assinatura com a
chave publica extraida do certificado. Limitacao: so e possivel
verificar quando a estrategia e uma PrivateKeySigningStrategy, pois e
necessario conhecer o algoritmo para verificar a assinatura --
estrategias customizadas sao aceitas sem validacao.
"""

from __future__ import annotations

import logging

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

from hubsaude_client import algorithms
from hubsaude_client.algorithms import AlgorithmParams, EcdsaParams, RsaPkcs1Params, RsaPssParams
from hubsaude_client.exceptions import SmartTokenError
from hubsaude_client.ports import SigningStrategy
from hubsaude_client.private_key_signing_strategy import PrivateKeySigningStrategy

_LOGGER = logging.getLogger(__name__)

_CHALLENGE = b"key-pair-consistency-check"


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

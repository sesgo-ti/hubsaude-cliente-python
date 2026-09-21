"""Validação fail-fast de consistência entre o material de assinatura
(chave privada ou SigningStrategy) e o certificado X.509 do cliente.

Assina um desafio fixo e confere a assinatura com a chave pública
extraída do certificado. Dois pontos de entrada:

- :func:`verify_key_pair`: recebe uma chave privada "solta" (RSA ou EC)
  diretamente. O algoritmo da assinatura de teste é inferido do tipo/curva da
  chave (RSA -> RS256; EC -> ES256/ES384/ES512 conforme a curva).
- :func:`verify_strategy`: recebe uma ``SigningStrategy`` já construída.
  Limitação: só e possível verificar quando a estratégia e uma
  ``PrivateKeySigningStrategy``, pois e necessário conhecer o algoritmo
  para verificar a assinatura -- estratégias customizadas (HSM/cofre de
  segredos com algoritmo não exposto) são aceitas sem validação.
"""

from __future__ import annotations

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes

from hubsaude_client import algorithms
from hubsaude_client._log import get_logger
from hubsaude_client.algorithms import AlgorithmParams, EcdsaParams, RsaPkcs1Params, RsaPssParams
from hubsaude_client.exceptions import SmartTokenError
from hubsaude_client.ports import SigningStrategy
from hubsaude_client.private_key_signing_strategy import PrivateKeySigningStrategy

# Logger compartilhado com o restante da lib (ver _log.py) -- usar
# logging.getLogger(__name__) diretamente faria os logs deste módulo
# saírem sob um nome distinto do contrato de observabilidade estável
# (hubsaude_client.SmartTokenClient) documentado em _log.py.
_LOGGER = get_logger()

_CHALLENGE = b"key-pair-consistency-check"

#: Mapeia a curva EC (nome retornado por ``EllipticCurve.name``) para o
#: algoritmo JWT (JWA) cujo tamanho de assinatura R||S (RFC 7518 Sec3.4)
#: é compatível -- necessário porque a conversão DER->R||S
#: (``algorithms.encode_p1363``) exige um ``signature_length`` que
#: corresponde ao tamanho da curva; usar sempre ES256 quebraria (overflow)
#: para chaves P-384/P-521.
_EC_CURVE_TO_JWT_ALGORITHM: dict[str, str] = {
    "secp256r1": "ES256",
    "secp384r1": "ES384",
    "secp521r1": "ES512",
}


def verify_key_pair(private_key: PrivateKeyTypes, certificate: x509.Certificate) -> None:
    """Verifica que uma chave privada "solta" corresponde a chave pública
    do certificado, assinando um desafio e conferindo a assinatura.

    Complementa :func:`verify_strategy`: aquela
    função exige uma :class:`~hubsaude_client.ports.SigningStrategy` já
    construída (e só consegue validar quando ela é uma
    ``PrivateKeySigningStrategy``); esta aceita a chave privada
    diretamente, para quem monta a própria estratégia fora do builder
    (cenário HSM/customizado) e quer testar a consistência chave<->certificado
    antes de usar.

    Args:
        private_key: chave privada RSA ou EC a validar.
        certificate: certificado X.509 com a chave pública correspondente.

    Raises:
        SmartTokenError: se o tipo/curva da chave não for suportado para
            esta verificação, ou se a assinatura de teste não puder ser
            verificada com a chave pública do certificado.
    """
    jwt_algorithm = _determine_verification_algorithm(private_key)
    try:
        strategy = PrivateKeySigningStrategy(private_key, jwt_algorithm)
    except SmartTokenError:
        raise
    except Exception as exc:
        raise SmartTokenError(f"Falha ao verificar consistência entre chave privada e certificado: {exc}", exc)
    verify_strategy(strategy, certificate)


def _determine_verification_algorithm(private_key: PrivateKeyTypes) -> str:
    """Determina o algoritmo JWT (JWA) a usar na assinatura de teste, a
    partir do tipo (e, para EC, da curva) da chave privada.

    Args:
        private_key: chave privada a inspecionar.

    Returns:
        O algoritmo JWT (JWA) compatível com o tipo/curva da chave.

    Raises:
        SmartTokenError: se o tipo de chave, ou a curva EC, não for
            suportado por esta biblioteca (ver ``algorithms.py`` --
            apenas RSA e EC/P-256/P-384/P-521 são suportados; Ed25519/Ed448
            não são mapeados em ``algorithms.py``).
    """
    if isinstance(private_key, rsa.RSAPrivateKey):
        return "RS256"
    if isinstance(private_key, ec.EllipticCurvePrivateKey):
        curve_name = private_key.curve.name
        algorithm = _EC_CURVE_TO_JWT_ALGORITHM.get(curve_name)
        if algorithm is not None:
            return algorithm
        raise SmartTokenError(
            f"Curva EC não suportada para validação de consistência chave-certificado: {curve_name!r}"
            f" (suportadas: {', '.join(sorted(_EC_CURVE_TO_JWT_ALGORITHM))})"
        )
    raise SmartTokenError(
        f"Tipo de chave não suportado para validação de consistência chave-certificado:"
        f" {type(private_key).__name__} (suportados: RSA, EC)"
    )


def verify_strategy(strategy: SigningStrategy, certificate: x509.Certificate) -> None:
    """Verifica que a estratégia de assinatura corresponde ao certificado.

    Args:
        strategy: estratégia de assinatura a validar.
        certificate: certificado X.509 com a chave pública correspondente.

    Raises:
        SmartTokenError: se a assinatura de teste não puder ser verificada
            com a chave pública do certificado.
    """
    if not isinstance(strategy, PrivateKeySigningStrategy):
        _LOGGER.debug(
            "Estratégia de assinatura customizada: consistência com o certificado "
            "não pode ser verificada automaticamente"
        )
        return
    try:
        signature = strategy.sign(_CHALLENGE)
        _verify_signature(certificate.public_key(), strategy.algorithm_params, signature)
        _LOGGER.debug("Verificação de consistência estratégia-certificado concluída com sucesso")
    except SmartTokenError:
        raise
    except Exception as exc:
        raise SmartTokenError(f"Falha ao verificar consistência entre chave privada e certificado: {exc}", exc)


def _verify_signature(public_key: object, params: AlgorithmParams, signature: bytes) -> None:
    try:
        if isinstance(params, RsaPkcs1Params):
            if not isinstance(public_key, rsa.RSAPublicKey):
                raise SmartTokenError(f"Certificado não contém chave pública RSA, recebida {type(public_key).__name__}")
            public_key.verify(signature, _CHALLENGE, padding.PKCS1v15(), params.hash_algorithm)
        elif isinstance(params, RsaPssParams):
            if not isinstance(public_key, rsa.RSAPublicKey):
                raise SmartTokenError(f"Certificado não contém chave pública RSA, recebida {type(public_key).__name__}")
            public_key.verify(
                signature,
                _CHALLENGE,
                padding.PSS(mgf=padding.MGF1(params.hash_algorithm), salt_length=params.salt_length),
                params.hash_algorithm,
            )
        elif isinstance(params, EcdsaParams):
            if not isinstance(public_key, ec.EllipticCurvePublicKey):
                raise SmartTokenError(f"Certificado não contém chave pública EC, recebida {type(public_key).__name__}")
            der_signature = algorithms.decode_p1363(signature)
            public_key.verify(der_signature, _CHALLENGE, ec.ECDSA(params.hash_algorithm))
        else:
            raise SmartTokenError(f"Parâmetro de algoritmo não suportado: {type(params).__name__}")
    except InvalidSignature as exc:
        raise SmartTokenError("Chave privada não corresponde ao certificado: assinatura inválida", exc)

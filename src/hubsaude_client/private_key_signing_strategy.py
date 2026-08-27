"""Implementacao de SigningStrategy baseada em chave privada em memoria.

Thread safety (RF-12.4): cada chamada a sign() usa apenas a chave
imutavel recebida no construtor, sem estado mutavel compartilhado --
naturalmente thread-safe, sem necessidade de locks.
"""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes

from hubsaude_client import algorithms
from hubsaude_client.algorithms import AlgorithmParams, EcdsaParams, RsaPkcs1Params, RsaPssParams
from hubsaude_client.defaults import DEFAULT_JWT_ALGORITHM
from hubsaude_client.exceptions import SigningError
from hubsaude_client.pem_loader import validate_minimum_key_size


class PrivateKeySigningStrategy:
    """Estrategia de assinatura para uma chave privada ja carregada em memoria.

    Implementa o Protocol ``hubsaude_client.ports.SigningStrategy``. Reutilizada
    por todas as fontes de material criptografico resolvidas em
    ``strategy_factory.py`` (PEM, PKCS#12, PKCS#11 -- este ultimo delega a
    assinatura ao hardware de forma transparente, pois o objeto de chave
    permanece apenas um handle).
    """

    def __init__(self, private_key: PrivateKeyTypes, jwt_algorithm: str = DEFAULT_JWT_ALGORITHM) -> None:
        """Cria a estrategia, validando o tamanho minimo da chave (fail-fast).

        Args:
            private_key: chave privada RSA ou EC ja carregada.
            jwt_algorithm: algoritmo JWT (JWA) a usar na assinatura.

        Raises:
            SmartTokenError: se o algoritmo nao for reconhecido, ou se a
                chave estiver abaixo do tamanho minimo aceito.
        """
        validate_minimum_key_size(private_key, "privateKey")
        self._private_key = private_key
        self._jwt_algorithm = jwt_algorithm
        self._params: AlgorithmParams = algorithms.resolve(jwt_algorithm)

    @property
    def jwt_algorithm(self) -> str:
        """Algoritmo JWT (JWA) configurado para esta estrategia."""
        return self._jwt_algorithm

    @property
    def algorithm_params(self) -> AlgorithmParams:
        """Parametros criptograficos resolvidos para o algoritmo configurado."""
        return self._params

    def sign(self, data: bytes) -> bytes:
        """Assina os dados usando a chave privada configurada.

        Args:
            data: bytes a serem assinados.

        Returns:
            A assinatura digital em formato raw (RSA: PKCS#1v1.5/PSS; ECDSA:
            R||S conforme RFC 7518 §3.4).

        Raises:
            SigningError: se ocorrer erro criptografico, incluindo
                incompatibilidade entre o tipo de chave e o algoritmo configurado.
        """
        try:
            return self._sign(data)
        except SigningError:
            raise
        except Exception as exc:
            raise SigningError(f"Falha ao assinar dados com algoritmo {self._jwt_algorithm}", exc) from exc

    def _sign(self, data: bytes) -> bytes:
        params = self._params
        key = self._private_key
        if isinstance(params, (RsaPkcs1Params, RsaPssParams)):
            if not isinstance(key, rsa.RSAPrivateKey):
                raise SigningError(f"Algoritmo {self._jwt_algorithm} requer chave RSA, recebida {type(key).__name__}")
            if isinstance(params, RsaPkcs1Params):
                return key.sign(data, padding.PKCS1v15(), params.hash_algorithm)
            return key.sign(
                data,
                padding.PSS(mgf=padding.MGF1(params.hash_algorithm), salt_length=params.salt_length),
                params.hash_algorithm,
            )
        if isinstance(params, EcdsaParams):
            if not isinstance(key, ec.EllipticCurvePrivateKey):
                raise SigningError(f"Algoritmo {self._jwt_algorithm} requer chave EC, recebida {type(key).__name__}")
            der_signature = key.sign(data, ec.ECDSA(params.hash_algorithm))
            return algorithms.encode_p1363(der_signature, params.signature_length)
        raise SigningError(f"Parametro de algoritmo nao suportado: {type(params).__name__}")

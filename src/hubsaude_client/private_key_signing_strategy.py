"""Implementação de SigningStrategy baseada em chave privada em memória.

Thread safety (RF-12.4): cada chamada a sign() usa apenas a chave
imutável recebida no construtor, sem estado mutável compartilhado --
naturalmente thread-safe, sem necessidade de locks.
"""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes

from hubsaude_client import algorithms
from hubsaude_client.algorithms import AlgorithmParams, EcdsaParams, RsaPkcs1Params, RsaPssParams
from hubsaude_client.defaults import DEFAULT_JWT_ALGORITHM
from hubsaude_client.exceptions import SigningError, SmartTokenError
from hubsaude_client.pem_loader import validate_minimum_key_size


class PrivateKeySigningStrategy:
    """Estratégia de assinatura para uma chave privada já carregada em memória.

    Implementa o Protocol ``hubsaude_client.ports.SigningStrategy``. Reutilizada
    por todas as fontes de material criptográfico resolvidas em
    ``strategy_factory.py`` (PEM, PKCS#12, PKCS#11 -- este último delega a
    assinatura ao hardware de forma transparente, pois o objeto de chave
    permanece apenas um handle).
    """

    def __init__(self, private_key: PrivateKeyTypes, jwt_algorithm: str = DEFAULT_JWT_ALGORITHM) -> None:
        """Cria a estratégia, validando o tamanho mínimo da chave e a
        compatibilidade entre o tipo de chave e o algoritmo (fail-fast).

        Args:
            private_key: chave privada RSA ou EC já carregada.
            jwt_algorithm: algoritmo JWT (JWA) a usar na assinatura.

        Raises:
            SmartTokenError: se o algoritmo não for reconhecido, se a
                chave estiver abaixo do tamanho mínimo aceito, ou se o
                tipo da chave (RSA/EC) não for compatível com o algoritmo
                configurado (ex.: chave RSA com algoritmo ECDSA) -- validado
                aqui, na construção, em vez de só na primeira chamada real a
                :meth:`sign`.
        """
        validate_minimum_key_size(private_key, "privateKey")
        self._private_key = private_key
        self._jwt_algorithm = jwt_algorithm
        self._params: AlgorithmParams = algorithms.resolve(jwt_algorithm)
        _require_compatible_key_type(private_key, self._params, jwt_algorithm)

    @property
    def jwt_algorithm(self) -> str:
        """Algoritmo JWT (JWA) configurado para esta estratégia."""
        return self._jwt_algorithm

    @property
    def algorithm_params(self) -> AlgorithmParams:
        """Parâmetros criptográficos resolvidos para o algoritmo configurado."""
        return self._params

    def sign(self, data: bytes) -> bytes:
        """Assina os dados usando a chave privada configurada.

        Args:
            data: bytes a serem assinados.

        Returns:
            A assinatura digital em formato raw (RSA: PKCS#1v1.5/PSS; ECDSA:
            R||S conforme RFC 7518 §3.4).

        Raises:
            SigningError: se ocorrer erro criptográfico, incluindo
                incompatibilidade entre o tipo de chave e o algoritmo configurado.
        """
        try:
            return self._sign(data)
        except SigningError:
            raise
        except Exception as exc:
            raise SigningError(f"Falha ao assinar dados com algoritmo {self._jwt_algorithm}", exc)

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
        raise SigningError(f"Parâmetro de algoritmo não suportado: {type(params).__name__}")


def _require_compatible_key_type(key: PrivateKeyTypes, params: AlgorithmParams, jwt_algorithm: str) -> None:
    """Valida, na construção (fail-fast), que o tipo da chave é compatível
    com o algoritmo configurado -- a mesma checagem que :meth:`_sign` já
    fazia, só que só era exercitada na primeira assinatura real.

    Args:
        key: chave privada a validar.
        params: parâmetros do algoritmo já resolvidos (RSA PKCS#1v1.5/PSS
            ou ECDSA).
        jwt_algorithm: algoritmo JWT (JWA) configurado, para a mensagem
            de erro.

    Raises:
        SmartTokenError: se o tipo da chave não corresponder ao exigido
            pelo algoritmo (RSA para PKCS#1v1.5/PSS, EC para ECDSA).
    """
    if isinstance(params, (RsaPkcs1Params, RsaPssParams)) and not isinstance(key, rsa.RSAPrivateKey):
        raise SmartTokenError(f"Algoritmo {jwt_algorithm} requer chave RSA, recebida {type(key).__name__}")
    if isinstance(params, EcdsaParams) and not isinstance(key, ec.EllipticCurvePrivateKey):
        raise SmartTokenError(f"Algoritmo {jwt_algorithm} requer chave EC, recebida {type(key).__name__}")

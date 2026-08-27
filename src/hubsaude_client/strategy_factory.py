"""Funcoes de fabrica para criacao de SigningStrategy a partir de diferentes
fontes de material criptografico.

Funcoes de modulo em vez de uma classe factory: em Python, funcoes soltas
sao o idiomatico para agrupar construtores alternativos sem estado.

``from_pkcs12`` nao tem parametro ``alias`` --
``cryptography.hazmat.primitives.serialization.pkcs12
.load_key_and_certificates`` nao indexa por alias (API de base da
biblioteca, nao uma escolha deste projeto).
"""

from __future__ import annotations

from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes
from cryptography.hazmat.primitives.serialization import pkcs12

from hubsaude_client import pem_loader
from hubsaude_client.defaults import DEFAULT_JWT_ALGORITHM
from hubsaude_client.exceptions import SmartTokenError
from hubsaude_client.ports import SigningStrategy
from hubsaude_client.private_key_signing_strategy import PrivateKeySigningStrategy


def from_private_key(private_key: PrivateKeyTypes, jwt_algorithm: str = DEFAULT_JWT_ALGORITHM) -> SigningStrategy:
    """Cria estrategia a partir de chave privada ja carregada em memoria.

    Util quando a chave foi obtida de outra fonte (ex: Vault API).

    Args:
        private_key: chave privada RSA ou EC.
        jwt_algorithm: algoritmo JWT (JWA) a usar na assinatura.

    Returns:
        Estrategia de assinatura configurada.
    """
    return PrivateKeySigningStrategy(private_key, jwt_algorithm)


def from_pem_file(
    path: Path, password: bytearray | None = None, jwt_algorithm: str = DEFAULT_JWT_ALGORITHM
) -> SigningStrategy:
    """Cria estrategia a partir de arquivo PEM.

    Args:
        path: caminho para o arquivo PEM da chave privada.
        password: senha para decriptar a chave (``None`` se nao criptografada).
            E consumida: repassada a ``pem_loader``, que zera o array ao
            final da chamada, em sucesso ou erro. O chamador nao deve
            reutiliza-la.
        jwt_algorithm: algoritmo JWT (JWA) a usar na assinatura.

    Returns:
        Estrategia de assinatura configurada.

    Raises:
        SmartTokenError: se o formato nao for valido ou a senha for incorreta.
    """
    key = pem_loader.load_private_key(path, password)
    return PrivateKeySigningStrategy(key, jwt_algorithm)


def from_pem_string(
    pem_content: str,
    password: bytearray | None = None,
    jwt_algorithm: str = DEFAULT_JWT_ALGORITHM,
    source: str = "<string>",
) -> SigningStrategy:
    """Cria estrategia a partir de conteudo PEM em string.

    Util quando o PEM e obtido de variavel de ambiente ou secret manager.

    Args:
        pem_content: conteudo PEM da chave privada.
        password: senha para decriptar (``None`` se nao criptografada). E
            consumida: repassada a ``pem_loader``, que zera o array ao
            final da chamada, em sucesso ou erro. O chamador nao deve
            reutiliza-la.
        jwt_algorithm: algoritmo JWT (JWA) a usar na assinatura.
        source: identificador da fonte para mensagens de erro.

    Returns:
        Estrategia de assinatura configurada.
    """
    key = pem_loader.load_private_key_from_string(pem_content, password, source)
    return PrivateKeySigningStrategy(key, jwt_algorithm)


def from_pkcs12(data: bytes | Path, password: bytes, jwt_algorithm: str = DEFAULT_JWT_ALGORITHM) -> SigningStrategy:
    """Cria estrategia a partir de bundle PKCS#12 (chave + certificado).

    Args:
        data: conteudo do arquivo PKCS#12, em bytes, ou o caminho do arquivo.
        password: senha do bundle.
        jwt_algorithm: algoritmo JWT (JWA) a usar na assinatura.

    Returns:
        Estrategia de assinatura configurada.

    Raises:
        SmartTokenError: se a senha for incorreta, o arquivo for invalido,
            ou o bundle nao contiver chave privada.
    """
    raw = data.read_bytes() if isinstance(data, Path) else data
    try:
        private_key, _certificate, _additional = pkcs12.load_key_and_certificates(raw, password)
    except ValueError as exc:
        raise SmartTokenError(f"Falha ao carregar PKCS#12 (senha incorreta ou arquivo invalido?): {exc}", exc) from exc
    if private_key is None:
        raise SmartTokenError("Bundle PKCS#12 nao contem chave privada")
    pem_loader.validate_minimum_key_size(private_key, "pkcs12")
    return PrivateKeySigningStrategy(private_key, jwt_algorithm)

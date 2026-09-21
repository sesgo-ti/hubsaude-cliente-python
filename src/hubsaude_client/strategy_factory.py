"""Funções de fábrica para criação de SigningStrategy a partir de diferentes
fontes de material criptográfico.

Funções de módulo em vez de uma classe factory: em Python, funções soltas
são o idiomático para agrupar construtores alternativos sem estado.

``from_pkcs12`` não tem parâmetro ``alias`` --
``cryptography.hazmat.primitives.serialization.pkcs12
.load_key_and_certificates`` não indexa por alias (API de base da
biblioteca, não uma escolha deste projeto).
"""

from __future__ import annotations

from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes
from cryptography.hazmat.primitives.serialization import pkcs12

from hubsaude_client import pem_loader
from hubsaude_client.defaults import DEFAULT_JWT_ALGORITHM
from hubsaude_client.exceptions import SmartTokenError
from hubsaude_client.pkcs11_signing_strategy import Pkcs11SigningStrategy
from hubsaude_client.ports import SigningStrategy
from hubsaude_client.private_key_signing_strategy import PrivateKeySigningStrategy


def from_private_key(private_key: PrivateKeyTypes, jwt_algorithm: str = DEFAULT_JWT_ALGORITHM) -> SigningStrategy:
    """Cria estratégia a partir de chave privada já carregada em memória.

    Útil quando a chave foi obtida de outra fonte (ex: Vault API).

    Args:
        private_key: chave privada RSA ou EC.
        jwt_algorithm: algoritmo JWT (JWA) a usar na assinatura.

    Returns:
        Estratégia de assinatura configurada.
    """
    return PrivateKeySigningStrategy(private_key, jwt_algorithm)


def from_pem_file(
    path: Path, password: bytearray | None = None, jwt_algorithm: str = DEFAULT_JWT_ALGORITHM
) -> SigningStrategy:
    """Cria estratégia a partir de arquivo PEM.

    Args:
        path: caminho para o arquivo PEM da chave privada.
        password: senha para decriptar a chave (``None`` se não criptografada).
            É consumida: repassada a ``pem_loader``, que zera o array ao
            final da chamada, em sucesso ou erro. O chamador não deve
            reutiliza-la.
        jwt_algorithm: algoritmo JWT (JWA) a usar na assinatura.

    Returns:
        Estratégia de assinatura configurada.

    Raises:
        SmartTokenError: se o formato não for válido ou a senha for incorreta.
    """
    key = pem_loader.load_private_key(path, password)
    return PrivateKeySigningStrategy(key, jwt_algorithm)


def from_pem_string(
    pem_content: str,
    password: bytearray | None = None,
    jwt_algorithm: str = DEFAULT_JWT_ALGORITHM,
    source: str = "<string>",
) -> SigningStrategy:
    """Cria estratégia a partir de conteúdo PEM em string.

    Útil quando o PEM é obtido de variável de ambiente ou secret manager.

    Args:
        pem_content: conteúdo PEM da chave privada.
        password: senha para decriptar (``None`` se não criptografada). E
            consumida: repassada a ``pem_loader``, que zera o array ao
            final da chamada, em sucesso ou erro. O chamador não deve
            reutiliza-la.
        jwt_algorithm: algoritmo JWT (JWA) a usar na assinatura.
        source: identificador da fonte para mensagens de erro.

    Returns:
        Estratégia de assinatura configurada.
    """
    key = pem_loader.load_private_key_from_string(pem_content, password, source)
    return PrivateKeySigningStrategy(key, jwt_algorithm)


def from_pkcs12(data: bytes | Path, password: bytearray, jwt_algorithm: str = DEFAULT_JWT_ALGORITHM) -> SigningStrategy:
    """Cria estratégia a partir de bundle PKCS#12 (chave + certificado).

    Args:
        data: conteúdo do arquivo PKCS#12, em bytes, ou o caminho do arquivo.
        password: senha do bundle. É consumida: o array é zerado ao final da
            chamada, em sucesso ou erro (RNF-03). O chamador não deve
            reutiliza-la.
        jwt_algorithm: algoritmo JWT (JWA) a usar na assinatura.

    Returns:
        Estratégia de assinatura configurada.

    Raises:
        SmartTokenError: se a senha for incorreta, o arquivo for inválido,
            ou o bundle não contiver chave privada.
    """
    raw = data.read_bytes() if isinstance(data, Path) else data
    try:
        # A lib cryptography exige `bytes` (imutável) neste parâmetro; a cópia
        # temporária criada aqui fica sem outra referência viva assim que a
        # chamada retorna. O bytearray original do chamador é zerado no finally.
        private_key, _certificate, _additional = pkcs12.load_key_and_certificates(raw, bytes(password))
    except ValueError as exc:
        raise SmartTokenError(f"Falha ao carregar PKCS#12 (senha incorreta ou arquivo inválido?): {exc}", exc)
    finally:
        pem_loader.clear_password(password)
    if private_key is None:
        raise SmartTokenError("Bundle PKCS#12 não contém chave privada")
    pem_loader.validate_minimum_key_size(private_key, "pkcs12")
    return PrivateKeySigningStrategy(private_key, jwt_algorithm)


def from_pkcs11(
    pkcs11_module_path: str | Path,
    token_label: str,
    key_label: str,
    user_pin: str,
    jwt_algorithm: str = DEFAULT_JWT_ALGORITHM,
) -> SigningStrategy:
    """Cria estratégia para HSM/smart token via PKCS#11.

    A chave privada nunca sai do hardware: o objeto retornado guarda apenas
    um handle de sessão e a referência a chave no token.

    Args:
        pkcs11_module_path: caminho para a biblioteca PKCS#11 do fabricante
            (ex: ``/usr/lib/softhsm/libsofthsm2.so``).
        token_label: rótulo do token/slot.
        key_label: rótulo da chave privada no token.
        user_pin: PIN de acesso ao token. Permanece ``str`` (não
            ``bytearray`` + zeragem como em ``from_pem_file``/
            ``from_pkcs12`` -- RNF-03): é usado uma única vez, aqui mesmo,
            para abrir a sessão PKCS#11, e descartado ao final desta
            função (nunca fica retido em campo de builder entre chamadas,
            ao contrário da senha de ``client_key_store()``). Decisão
            deliberada e final, não pendência.
        jwt_algorithm: algoritmo JWT (JWA) a usar na assinatura.

    Returns:
        Estratégia de assinatura que usa o hardware.

    Raises:
        SmartTokenError: se o módulo PKCS#11 não puder ser carregado, o
            token não for encontrado pelo rótulo informado, o PIN for
            inválido, a sessão não puder ser aberta, ou a chave não for
            encontrada no token.
    """
    # Import local, não no topo do módulo: python-pkcs11 e dependência
    # opcional (extra "hsm" em pyproject.toml), com bindings nativos que a
    # maioria dos consumidores não instala. strategy_factory.py é um único
    # arquivo com todas as factories -- um import no topo faria qualquer
    # uso de from_pem_file/from_pkcs12 (sem PKCS#11) falhar com
    # ModuleNotFoundError para quem não instalou o extra.
    import pkcs11 as pkcs11_lib

    try:
        lib = pkcs11_lib.lib(str(pkcs11_module_path))
    except Exception as exc:
        raise SmartTokenError(f"Falha ao carregar módulo PKCS#11: {pkcs11_module_path}: {exc}", exc)
    try:
        token = lib.get_token(token_label=token_label)
    except Exception as exc:
        raise SmartTokenError(f"Token PKCS#11 não encontrado: {token_label}: {exc}", exc)
    try:
        session = token.open(user_pin=user_pin)
    except pkcs11_lib.PKCS11Error as exc:
        raise SmartTokenError(f"Falha ao abrir sessão PKCS#11 (PIN incorreto?): {exc}", exc)
    try:
        key = session.get_key(label=key_label, object_class=pkcs11_lib.ObjectClass.PRIVATE_KEY)
    except pkcs11_lib.NoSuchKey as exc:
        session.close()
        raise SmartTokenError(f"Chave não encontrada no token PKCS#11: {key_label}", exc)
    except Exception as exc:
        session.close()
        raise SmartTokenError(f"Falha ao acessar chave PKCS#11: {exc}", exc)
    return Pkcs11SigningStrategy(session, key, jwt_algorithm)


def load_pkcs12_key_and_certificate(
    data: bytes | Path, password: bytearray
) -> tuple[PrivateKeyTypes, x509.Certificate]:
    """Carrega chave privada E certificado de um bundle PKCS#12.

    Uso: quando o mesmo bundle precisa fornecer tanto a chave para
    assinatura quanto o certificado para apresentação em mTLS (builder
    ``client_key_store()``). Para uso apenas como SigningStrategy (sem
    precisar do certificado), use ``from_pkcs12`` diretamente.

    Args:
        data: conteúdo do arquivo PKCS#12, em bytes, ou o caminho do arquivo.
        password: senha do bundle. É consumida: o array é zerado ao final
            da chamada, em sucesso ou erro (RNF-03). O chamador não deve
            reutiliza-la.

    Returns:
        A chave privada e o certificado, ambos já validados (tamanho
        mínimo de chave, período de validade do certificado).

    Raises:
        SmartTokenError: se a senha for incorreta, o arquivo for inválido,
            ou o bundle não contiver chave privada ou certificado.
    """
    raw = data.read_bytes() if isinstance(data, Path) else data
    try:
        private_key, certificate, _additional = pkcs12.load_key_and_certificates(raw, bytes(password))
    except ValueError as exc:
        raise SmartTokenError(f"Falha ao carregar PKCS#12 (senha incorreta ou arquivo inválido?): {exc}", exc)
    finally:
        pem_loader.clear_password(password)
    if private_key is None:
        raise SmartTokenError("Bundle PKCS#12 não contém chave privada")
    if certificate is None:
        raise SmartTokenError("Bundle PKCS#12 não contém certificado")
    pem_loader.validate_minimum_key_size(private_key, "pkcs12")
    pem_loader.check_certificate_validity(certificate, "pkcs12")
    return private_key, certificate

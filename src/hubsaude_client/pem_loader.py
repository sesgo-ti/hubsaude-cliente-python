"""Carregamento e validacao de material criptografico de arquivo/string PEM.

``cryptography.hazmat.primitives.serialization.load_pem_private_key``
detecta automaticamente o formato da chave (PKCS#1, PKCS#8 cifrado/nao
cifrado, OpenSSL tradicional cifrado) sem exigir parsing manual por tipo
de header PEM. O trabalho deste modulo fica concentrado em mensagens de
erro corretas por causa (senha ausente vs. incorreta vs. formato nao
suportado), nao em parsing.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes

from hubsaude_client.exceptions import SmartTokenError

MIN_RSA_KEY_BITS = 2048
MIN_EC_FIELD_BITS = 256


def validate_minimum_key_size(key: PrivateKeyTypes, source: str) -> None:
    """Valida o tamanho minimo de uma chave privada (fail-fast).

    Chaves RSA com modulo menor que MIN_RSA_KEY_BITS bits e chaves EC com
    campo menor que MIN_EC_FIELD_BITS bits (P-256) sao consideradas
    criptograficamente fracas (NIST SP 800-57) e rejeitadas. Chaves de
    outros tipos (ex: Ed25519, ou handles PKCS#11 opacos) nao sao validadas.

    Args:
        key: chave privada a validar.
        source: identificador da fonte para mensagens de erro.

    Raises:
        SmartTokenError: se a chave estiver abaixo do tamanho minimo aceito.
    """
    if isinstance(key, rsa.RSAPrivateKey):
        bits = key.key_size
        if bits < MIN_RSA_KEY_BITS:
            raise SmartTokenError(
                f"Chave RSA de {bits} bits rejeitada: o tamanho minimo aceito e "
                f"{MIN_RSA_KEY_BITS} bits (NIST SP 800-57). Fonte: {source}"
            )
    elif isinstance(key, ec.EllipticCurvePrivateKey):
        bits = key.curve.key_size
        if bits < MIN_EC_FIELD_BITS:
            raise SmartTokenError(
                f"Chave EC com campo de {bits} bits rejeitada: a curva minima aceita e P-256 "
                f"({MIN_EC_FIELD_BITS} bits, NIST SP 800-57). Fonte: {source}"
            )


def load_private_key(path: Path, password: bytearray | None = None) -> PrivateKeyTypes:
    """Carrega chave privada de arquivo PEM, com suporte a senha.

    Args:
        path: caminho para o arquivo PEM.
        password: senha para chaves criptografadas (``None`` se nao
            criptografada). E consumida: o array e zerado ao final da
            chamada, em sucesso ou erro (minimiza a exposicao do segredo em
            memoria). O chamador nao deve reutiliza-lo.

    Returns:
        A chave privada carregada.

    Raises:
        SmartTokenError: se a chave requer senha nao fornecida, a senha for
            incorreta, ou o formato for invalido.
    """
    pem_bytes = path.read_bytes()
    return _load_private_key_from_bytes(pem_bytes, password, str(path))


def load_private_key_from_string(pem: str, password: bytearray | None, source: str) -> PrivateKeyTypes:
    """Carrega chave privada de conteudo PEM em string.

    Args:
        pem: conteudo PEM da chave privada.
        password: senha para chaves criptografadas (``None`` se nao
            criptografada). E consumida: o array e zerado ao final da
            chamada, em sucesso ou erro (minimiza a exposicao do segredo em
            memoria). O chamador nao deve reutiliza-lo.
        source: identificador da fonte para mensagens de erro.

    Returns:
        A chave privada carregada.

    Raises:
        SmartTokenError: se a chave requer senha nao fornecida, a senha for
            incorreta, ou o formato for invalido.
    """
    return _load_private_key_from_bytes(pem.encode("utf-8"), password, source)


def _load_private_key_from_bytes(pem_bytes: bytes, password: bytearray | None, source: str) -> PrivateKeyTypes:
    try:
        # A lib cryptography exige `bytes` (imutavel) neste parametro; a copia
        # temporaria criada aqui fica sem outra referencia viva assim que a
        # chamada retorna. O bytearray original do chamador e zerado no finally.
        password_bytes = bytes(password) if password is not None else None
        key = serialization.load_pem_private_key(pem_bytes, password=password_bytes)
    except TypeError as exc:
        if password is None:
            raise SmartTokenError(f"Chave criptografada requer senha: {source}", exc) from exc
        raise SmartTokenError(f"Senha fornecida para chave nao criptografada: {source}", exc) from exc
    except ValueError as exc:
        if password is not None:
            raise SmartTokenError(f"Falha ao decriptar chave, verifique a senha fornecida: {source}", exc) from exc
        raise SmartTokenError(f"formato de chave PEM invalido: {source}", exc) from exc
    finally:
        clear_password(password)
    validate_minimum_key_size(key, source)
    return key


def clear_password(password: bytearray | None) -> None:
    """Zera o conteudo do array de senha em memoria, apos o uso.

    RNF-03 (higiene de segredos em memoria): minimiza a janela em que a
    senha em texto puro fica exposta num dump de memoria/heap. Publica
    (nao prefixada) porque tambem e reaproveitada por outras fontes de
    senha/PIN mutaveis fora deste modulo (ex: ``strategy_factory.py``,
    bundle PKCS#12).
    """
    if password is not None:
        password[:] = bytes(len(password))


def load_certificate(path: Path) -> x509.Certificate:
    """Carrega certificado X.509 de arquivo PEM.

    Args:
        path: caminho para o arquivo PEM do certificado.

    Returns:
        O certificado X.509, ja validado quanto ao periodo de validade.

    Raises:
        SmartTokenError: se nao for um certificado X.509 valido ou estiver
            fora do periodo de validade.
    """
    pem = path.read_text(encoding="utf-8")
    return load_certificate_from_string(pem, str(path))


def load_certificate_from_string(pem: str, source: str) -> x509.Certificate:
    """Carrega certificado X.509 de string PEM.

    Args:
        pem: conteudo PEM do certificado.
        source: identificador da fonte para mensagens de erro.

    Returns:
        O certificado X.509, ja validado quanto ao periodo de validade.

    Raises:
        SmartTokenError: se nao for um certificado X.509 valido ou estiver
            fora do periodo de validade.
    """
    try:
        cert = x509.load_pem_x509_certificate(pem.encode("utf-8"))
    except ValueError as exc:
        raise SmartTokenError(f"Arquivo PEM nao contem certificado X.509 valido: {source}", exc) from exc
    check_certificate_validity(cert, source)
    return cert


def check_certificate_validity(cert: x509.Certificate, source: str) -> None:
    """Verifica o periodo de validade do certificado (fail-fast).

    Args:
        cert: certificado a verificar.
        source: identificador da fonte para mensagens de erro (caminho do
            arquivo ou subject DN).

    Raises:
        SmartTokenError: se o certificado estiver expirado ou ainda nao for valido.
    """
    now = datetime.now(timezone.utc)
    not_before = getattr(cert, "not_valid_before_utc", None) or cert.not_valid_before.replace(tzinfo=timezone.utc)
    not_after = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after.replace(tzinfo=timezone.utc)
    if now < not_before:
        raise SmartTokenError(f"Certificado ainda nao e valido: {source}")
    if now > not_after:
        raise SmartTokenError(f"Certificado expirado: {source}")

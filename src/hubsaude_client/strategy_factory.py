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


def from_pkcs12(data: bytes | Path, password: bytearray, jwt_algorithm: str = DEFAULT_JWT_ALGORITHM) -> SigningStrategy:
    """Cria estrategia a partir de bundle PKCS#12 (chave + certificado).

    Args:
        data: conteudo do arquivo PKCS#12, em bytes, ou o caminho do arquivo.
        password: senha do bundle. E consumida: o array e zerado ao final da
            chamada, em sucesso ou erro (RNF-03). O chamador nao deve
            reutiliza-la.
        jwt_algorithm: algoritmo JWT (JWA) a usar na assinatura.

    Returns:
        Estrategia de assinatura configurada.

    Raises:
        SmartTokenError: se a senha for incorreta, o arquivo for invalido,
            ou o bundle nao contiver chave privada.
    """
    raw = data.read_bytes() if isinstance(data, Path) else data
    try:
        # A lib cryptography exige `bytes` (imutavel) neste parametro; a copia
        # temporaria criada aqui fica sem outra referencia viva assim que a
        # chamada retorna. O bytearray original do chamador e zerado no finally.
        private_key, _certificate, _additional = pkcs12.load_key_and_certificates(raw, bytes(password))
    except ValueError as exc:
        raise SmartTokenError(f"Falha ao carregar PKCS#12 (senha incorreta ou arquivo invalido?): {exc}", exc) from exc
    finally:
        pem_loader.clear_password(password)
    if private_key is None:
        raise SmartTokenError("Bundle PKCS#12 nao contem chave privada")
    pem_loader.validate_minimum_key_size(private_key, "pkcs12")
    return PrivateKeySigningStrategy(private_key, jwt_algorithm)


def from_pkcs11(
    pkcs11_module_path: str | Path,
    token_label: str,
    key_label: str,
    user_pin: str,
    jwt_algorithm: str = DEFAULT_JWT_ALGORITHM,
) -> SigningStrategy:
    """Cria estrategia para HSM/smart token via PKCS#11.

    A chave privada nunca sai do hardware: o objeto retornado guarda apenas
    um handle de sessao e a referencia a chave no token.

    Args:
        pkcs11_module_path: caminho para a biblioteca PKCS#11 do fabricante
            (ex: ``/usr/lib/softhsm/libsofthsm2.so``).
        token_label: rotulo do token/slot.
        key_label: rotulo da chave privada no token.
        user_pin: PIN de acesso ao token. Permanece ``str`` (nao
            ``bytearray`` + zeragem como em ``from_pem_file``/
            ``from_pkcs12`` -- RNF-03): e usado uma unica vez, aqui mesmo,
            para abrir a sessao PKCS#11, e descartado ao final desta
            funcao (nunca fica retido em campo de builder entre chamadas,
            ao contrario da senha de ``client_key_store()``). Decisao
            deliberada e final, nao pendencia.
        jwt_algorithm: algoritmo JWT (JWA) a usar na assinatura.

    Returns:
        Estrategia de assinatura que usa o hardware.

    Raises:
        SmartTokenError: se o PIN for invalido, a sessao nao puder ser
            aberta, ou a chave nao for encontrada no token.
    """
    # Import local, nao no topo do modulo: python-pkcs11 e dependencia
    # opcional (extra "hsm" em pyproject.toml), com bindings nativos que a
    # maioria dos consumidores nao instala. strategy_factory.py e um unico
    # arquivo com todas as factories -- um import no topo faria qualquer
    # uso de from_pem_file/from_pkcs12 (sem PKCS#11) falhar com
    # ModuleNotFoundError para quem nao instalou o extra. Diferente do
    # .java, que resolve PKCS#11 via SunPKCS11 (provider embutido na JVM,
    # sem dependencia de terceiros).
    import pkcs11 as pkcs11_lib

    lib = pkcs11_lib.lib(str(pkcs11_module_path))
    token = lib.get_token(token_label=token_label)
    try:
        session = token.open(user_pin=user_pin)
    except pkcs11_lib.PKCS11Error as exc:
        raise SmartTokenError(f"Falha ao abrir sessao PKCS#11 (PIN incorreto?): {exc}", exc) from exc
    try:
        key = session.get_key(label=key_label, object_class=pkcs11_lib.ObjectClass.PRIVATE_KEY)
    except pkcs11_lib.NoSuchKey as exc:
        session.close()
        raise SmartTokenError(f"Chave nao encontrada no token PKCS#11: {key_label}", exc) from exc
    except Exception as exc:
        session.close()
        raise SmartTokenError(f"Falha ao acessar chave PKCS#11: {exc}", exc) from exc
    return Pkcs11SigningStrategy(session, key, jwt_algorithm)


def load_pkcs12_key_and_certificate(
    data: bytes | Path, password: bytearray
) -> tuple[PrivateKeyTypes, x509.Certificate]:
    """Carrega chave privada E certificado de um bundle PKCS#12.

    Uso: quando o mesmo bundle precisa fornecer tanto a chave para
    assinatura quanto o certificado para apresentacao em mTLS (builder
    ``client_key_store()``). Para uso apenas como SigningStrategy (sem
    precisar do certificado), use ``from_pkcs12`` diretamente.

    Args:
        data: conteudo do arquivo PKCS#12, em bytes, ou o caminho do arquivo.
        password: senha do bundle. E consumida: o array e zerado ao final
            da chamada, em sucesso ou erro (RNF-03). O chamador nao deve
            reutiliza-la.

    Returns:
        A chave privada e o certificado, ambos ja validados (tamanho
        minimo de chave, periodo de validade do certificado).

    Raises:
        SmartTokenError: se a senha for incorreta, o arquivo for invalido,
            ou o bundle nao contiver chave privada ou certificado.
    """
    raw = data.read_bytes() if isinstance(data, Path) else data
    try:
        private_key, certificate, _additional = pkcs12.load_key_and_certificates(raw, bytes(password))
    except ValueError as exc:
        raise SmartTokenError(f"Falha ao carregar PKCS#12 (senha incorreta ou arquivo invalido?): {exc}", exc) from exc
    finally:
        pem_loader.clear_password(password)
    if private_key is None:
        raise SmartTokenError("Bundle PKCS#12 nao contem chave privada")
    if certificate is None:
        raise SmartTokenError("Bundle PKCS#12 nao contem certificado")
    pem_loader.validate_minimum_key_size(private_key, "pkcs12")
    pem_loader.check_certificate_validity(certificate, "pkcs12")
    return private_key, certificate

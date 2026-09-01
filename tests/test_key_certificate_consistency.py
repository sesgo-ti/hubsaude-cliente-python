from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from hubsaude_client import key_certificate_consistency, pem_loader
from hubsaude_client.exceptions import SmartTokenError
from hubsaude_client.private_key_signing_strategy import PrivateKeySigningStrategy


def test_verify_strategy_accepts_matching_key_and_certificate(fake_pem_pair) -> None:
    key = pem_loader.load_private_key(fake_pem_pair["key"])
    cert = pem_loader.load_certificate(fake_pem_pair["cert"])
    strategy = PrivateKeySigningStrategy(key, "RS256")
    key_certificate_consistency.verify_strategy(strategy, cert)  # nao deve lancar


def test_verify_strategy_accepts_matching_ec_key_and_certificate(fake_ec_pem_pair) -> None:
    key = pem_loader.load_private_key(fake_ec_pem_pair["key"])
    cert = pem_loader.load_certificate(fake_ec_pem_pair["cert"])
    strategy = PrivateKeySigningStrategy(key, "ES256")
    key_certificate_consistency.verify_strategy(strategy, cert)  # nao deve lancar


def test_verify_strategy_accepts_matching_rsa_pss_key_and_certificate(fake_pem_pair) -> None:
    key = pem_loader.load_private_key(fake_pem_pair["key"])
    cert = pem_loader.load_certificate(fake_pem_pair["cert"])
    strategy = PrivateKeySigningStrategy(key, "PS256")
    key_certificate_consistency.verify_strategy(strategy, cert)  # nao deve lancar


def test_verify_strategy_rejects_mismatched_pair(fake_mismatched_pem_pair) -> None:
    key = pem_loader.load_private_key(fake_mismatched_pem_pair["matching_key"])
    mismatched_cert = pem_loader.load_certificate(fake_mismatched_pem_pair["mismatched_cert"])
    strategy = PrivateKeySigningStrategy(key, "RS256")
    with pytest.raises(SmartTokenError, match="nao corresponde"):
        key_certificate_consistency.verify_strategy(strategy, mismatched_cert)


def test_verify_strategy_skips_custom_strategy_without_raising(fake_pem_pair, caplog) -> None:
    class _CustomStrategy:
        def sign(self, data: bytes) -> bytes:
            return b"fake"

    cert = pem_loader.load_certificate(fake_pem_pair["cert"])
    key_certificate_consistency.verify_strategy(_CustomStrategy(), cert)  # nao deve lancar
    assert "customizada" in caplog.text


def test_verify_strategy_rejects_mismatched_ec_pair(fake_mismatched_ec_pem_pair) -> None:
    key = pem_loader.load_private_key(fake_mismatched_ec_pem_pair["matching_key"])
    mismatched_cert = pem_loader.load_certificate(fake_mismatched_ec_pem_pair["mismatched_cert"])
    strategy = PrivateKeySigningStrategy(key, "ES256")
    with pytest.raises(SmartTokenError, match="nao corresponde"):
        key_certificate_consistency.verify_strategy(strategy, mismatched_cert)


def test_verify_strategy_rejects_rsa_strategy_with_ec_certificate(fake_pem_pair, fake_ec_pem_pair) -> None:
    """Estrategia RSA validada contra certificado com chave publica EC:
    cobre o branch defensivo de tipo de chave publica em _verify_signature
    (RsaPkcs1Params/RsaPssParams), que so e alcancavel com um par
    chave-privada/certificado de familias criptograficas diferentes."""
    key = pem_loader.load_private_key(fake_pem_pair["key"])
    ec_cert = pem_loader.load_certificate(fake_ec_pem_pair["cert"])
    strategy = PrivateKeySigningStrategy(key, "RS256")
    with pytest.raises(SmartTokenError, match="RSA"):
        key_certificate_consistency.verify_strategy(strategy, ec_cert)


def test_verify_strategy_rejects_ec_strategy_with_rsa_certificate(fake_ec_pem_pair, fake_pem_pair) -> None:
    """Estrategia EC validada contra certificado com chave publica RSA:
    cobre o branch defensivo de tipo de chave publica em _verify_signature
    (EcdsaParams)."""
    key = pem_loader.load_private_key(fake_ec_pem_pair["key"])
    rsa_cert = pem_loader.load_certificate(fake_pem_pair["cert"])
    strategy = PrivateKeySigningStrategy(key, "ES256")
    with pytest.raises(SmartTokenError, match="EC"):
        key_certificate_consistency.verify_strategy(strategy, rsa_cert)


def test_verify_strategy_rejects_rsa_pss_strategy_with_ec_certificate(fake_pem_pair, fake_ec_pem_pair) -> None:
    """Estrategia PS256 (RSA-PSS) validada contra certificado com chave publica EC:
    cobre o branch defensivo de tipo de chave publica no ramo RsaPssParams de
    _verify_signature, distinto do ramo RsaPkcs1Params ja coberto acima."""
    key = pem_loader.load_private_key(fake_pem_pair["key"])
    ec_cert = pem_loader.load_certificate(fake_ec_pem_pair["cert"])
    strategy = PrivateKeySigningStrategy(key, "PS256")
    with pytest.raises(SmartTokenError, match="RSA"):
        key_certificate_consistency.verify_strategy(strategy, ec_cert)


def test_verify_signature_raises_for_unsupported_algorithm_params(fake_pem_pair, monkeypatch) -> None:
    # Branch defensivo `else: raise SmartTokenError(...)` em _verify_signature:
    # inalcancavel via API publica porque PrivateKeySigningStrategy.algorithm_params
    # so retorna tipos reconhecidos (algorithms.resolve valida o alg no construtor).
    # Mesmo padrao usado em test_private_key_signing_strategy.py para o branch
    # analogo em PrivateKeySigningStrategy._sign. A assinatura precisa continuar
    # valida (nao pode falhar em strategy.sign()), entao so o parametro de
    # algoritmo e trocado via a property de classe, apos capturar uma assinatura
    # real.
    key = pem_loader.load_private_key(fake_pem_pair["key"])
    cert = pem_loader.load_certificate(fake_pem_pair["cert"])
    strategy = PrivateKeySigningStrategy(key, "RS256")
    valid_signature = strategy.sign(key_certificate_consistency._CHALLENGE)
    monkeypatch.setattr(strategy, "sign", lambda _data: valid_signature)
    monkeypatch.setattr(type(strategy), "algorithm_params", property(lambda self: object()))
    with pytest.raises(SmartTokenError, match="Parametro de algoritmo nao suportado"):
        key_certificate_consistency.verify_strategy(strategy, cert)


def test_verify_strategy_wraps_unexpected_error(fake_pem_pair, monkeypatch) -> None:
    key = pem_loader.load_private_key(fake_pem_pair["key"])
    cert = pem_loader.load_certificate(fake_pem_pair["cert"])
    strategy = PrivateKeySigningStrategy(key, "RS256")

    def _boom(_data: bytes) -> bytes:
        raise ValueError("erro inesperado ao assinar o desafio")

    monkeypatch.setattr(strategy, "sign", _boom)
    with pytest.raises(SmartTokenError, match="Falha ao verificar consistencia"):
        key_certificate_consistency.verify_strategy(strategy, cert)


# ---------------------------------------------------------------------------
# verify_key_pair -- equivalente publico de
# KeyCertificateConsistency.verifyKeyPair / SmartTokenClient.verifyKeyPairConsistency
# ---------------------------------------------------------------------------


def test_verify_key_pair_accepts_matching_rsa_key_and_certificate(fake_pem_pair) -> None:
    key = pem_loader.load_private_key(fake_pem_pair["key"])
    cert = pem_loader.load_certificate(fake_pem_pair["cert"])
    key_certificate_consistency.verify_key_pair(key, cert)  # nao deve lancar


def test_verify_key_pair_accepts_matching_ec_key_and_certificate(fake_ec_pem_pair) -> None:
    key = pem_loader.load_private_key(fake_ec_pem_pair["key"])
    cert = pem_loader.load_certificate(fake_ec_pem_pair["cert"])
    key_certificate_consistency.verify_key_pair(key, cert)  # nao deve lancar


def test_verify_key_pair_rejects_mismatched_rsa_pair(fake_mismatched_pem_pair) -> None:
    key = pem_loader.load_private_key(fake_mismatched_pem_pair["matching_key"])
    mismatched_cert = pem_loader.load_certificate(fake_mismatched_pem_pair["mismatched_cert"])
    with pytest.raises(SmartTokenError, match="nao corresponde"):
        key_certificate_consistency.verify_key_pair(key, mismatched_cert)


def test_verify_key_pair_rejects_mismatched_ec_pair(fake_mismatched_ec_pem_pair) -> None:
    key = pem_loader.load_private_key(fake_mismatched_ec_pem_pair["matching_key"])
    mismatched_cert = pem_loader.load_certificate(fake_mismatched_ec_pem_pair["mismatched_cert"])
    with pytest.raises(SmartTokenError, match="nao corresponde"):
        key_certificate_consistency.verify_key_pair(key, mismatched_cert)


def test_verify_key_pair_rejects_rsa_key_with_ec_certificate(fake_pem_pair, fake_ec_pem_pair) -> None:
    key = pem_loader.load_private_key(fake_pem_pair["key"])
    ec_cert = pem_loader.load_certificate(fake_ec_pem_pair["cert"])
    with pytest.raises(SmartTokenError, match="RSA"):
        key_certificate_consistency.verify_key_pair(key, ec_cert)


def test_verify_key_pair_rejects_ec_key_with_rsa_certificate(fake_ec_pem_pair, fake_pem_pair) -> None:
    key = pem_loader.load_private_key(fake_ec_pem_pair["key"])
    rsa_cert = pem_loader.load_certificate(fake_pem_pair["cert"])
    with pytest.raises(SmartTokenError, match="EC"):
        key_certificate_consistency.verify_key_pair(key, rsa_cert)


@pytest.mark.parametrize(
    ("curve", "expected_algorithm"),
    [
        (ec.SECP256R1(), "ES256"),
        (ec.SECP384R1(), "ES384"),
        (ec.SECP521R1(), "ES512"),
    ],
)
def test_verify_key_pair_maps_ec_curve_to_matching_algorithm(curve, expected_algorithm) -> None:
    # P-384/P-521 (nao cobertas por fake_ec_pem_pair, que e' sempre P-256):
    # o algoritmo de verificacao precisa ser escolhido pela curva real da
    # chave, ou a conversao DER->R||S (algorithms.encode_p1363) quebra por
    # incompatibilidade de comprimento -- ver comentario em
    # _EC_CURVE_TO_JWT_ALGORITHM.
    key = ec.generate_private_key(curve)
    assert key_certificate_consistency._determine_verification_algorithm(key) == expected_algorithm

    cert = _self_signed_ec_cert(key)
    key_certificate_consistency.verify_key_pair(key, cert)  # nao deve lancar


def test_verify_key_pair_rejects_unsupported_ec_curve() -> None:
    key = ec.generate_private_key(ec.SECP192R1())
    cert = _self_signed_ec_cert(key)
    with pytest.raises(SmartTokenError, match="[Cc]urva EC nao suportada"):
        key_certificate_consistency.verify_key_pair(key, cert)


def test_verify_key_pair_rejects_unsupported_key_type(fake_pem_pair) -> None:
    cert = pem_loader.load_certificate(fake_pem_pair["cert"])
    with pytest.raises(SmartTokenError, match="[Tt]ipo de chave nao suportado"):
        key_certificate_consistency.verify_key_pair(object(), cert)  # type: ignore[arg-type]


def test_verify_key_pair_wraps_unexpected_strategy_construction_failure(fake_pem_pair, monkeypatch) -> None:
    """Se a construcao da ``PrivateKeySigningStrategy`` interna falhar com
    uma excecao que NAO seja ``SmartTokenError`` (ex.: um erro inesperado
    fora do fail-fast conhecido de ``validate_minimum_key_size``), o erro
    deve ser envolvido em ``SmartTokenError`` com a causa original
    preservada, em vez de vazar a excecao crua para quem chamou
    ``verify_key_pair`` (ramo de guarda do fail-fast)."""
    key = pem_loader.load_private_key(fake_pem_pair["key"])
    cert = pem_loader.load_certificate(fake_pem_pair["cert"])
    original_error = ValueError("falha inesperada e nao relacionada a tamanho de chave")

    def _boom(*args: object, **kwargs: object) -> None:
        raise original_error

    monkeypatch.setattr(key_certificate_consistency, "PrivateKeySigningStrategy", _boom)

    with pytest.raises(SmartTokenError, match="Falha ao verificar consistencia") as exc_info:
        key_certificate_consistency.verify_key_pair(key, cert)

    assert exc_info.value.__cause__ is original_error


def test_verify_key_pair_does_not_wrap_smart_token_error_from_strategy_construction(fake_pem_pair, monkeypatch) -> None:
    """Quando a construcao da estrategia interna ja falha com
    ``SmartTokenError`` (ex.: chave abaixo do tamanho minimo, validada por
    ``validate_minimum_key_size``), ``verify_key_pair`` deve deixar essa
    excecao propagar sem envolve-la de novo (o ramo ``except
    SmartTokenError: raise`` deve preceder o ``except Exception`` generico)."""
    key = pem_loader.load_private_key(fake_pem_pair["key"])
    cert = pem_loader.load_certificate(fake_pem_pair["cert"])
    original_error = SmartTokenError("chave rejeitada por tamanho minimo")

    def _boom(*args: object, **kwargs: object) -> None:
        raise original_error

    monkeypatch.setattr(key_certificate_consistency, "PrivateKeySigningStrategy", _boom)

    with pytest.raises(SmartTokenError) as exc_info:
        key_certificate_consistency.verify_key_pair(key, cert)

    assert exc_info.value is original_error


def _self_signed_ec_cert(key) -> "x509.Certificate":
    """Gera um certificado autoassinado minimo para uma chave EC de teste,
    usado pelos testes de curva que nao dependem das fixtures PEM fixas
    (P-256) de conftest.py."""
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "teste-ec")])
    now = datetime.now(timezone.utc)
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(minutes=10))
        .sign(key, hashes.SHA256())
    )

from __future__ import annotations

import pytest

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

from __future__ import annotations

import pytest

from hubsaude_client.settings import ResolvedSigning, SigningSettings


def test_default_jwt_algorithm_is_rs384() -> None:
    assert SigningSettings().jwt_algorithm == "RS384"


def test_resolve_from_private_key_pem(fake_pem_pair) -> None:
    settings = SigningSettings(private_key_pem=fake_pem_pair["key"], jwt_algorithm="RS256")
    resolved = settings.resolve()
    assert isinstance(resolved, ResolvedSigning)
    assert resolved.client_key is not None
    signature = resolved.strategy.sign(b"data")
    assert len(signature) > 0


def test_resolve_from_custom_signing_strategy() -> None:
    class _CustomStrategy:
        def sign(self, data: bytes) -> bytes:
            return b"fake-signature"

    custom = _CustomStrategy()
    settings = SigningSettings(signing_strategy=custom)
    resolved = settings.resolve()
    assert resolved.strategy is custom
    assert resolved.client_key is None


def test_resolve_with_both_sources_raises_value_error(fake_pem_pair) -> None:
    class _CustomStrategy:
        def sign(self, data: bytes) -> bytes:
            return b"fake"

    settings = SigningSettings(signing_strategy=_CustomStrategy(), private_key_pem=fake_pem_pair["key"])
    with pytest.raises(ValueError, match="nao ambos"):
        settings.resolve()


def test_resolve_with_no_source_raises_value_error() -> None:
    settings = SigningSettings()
    with pytest.raises(ValueError, match="obrigatorio"):
        settings.resolve()


def test_key_id_is_optional_and_defaults_to_none() -> None:
    assert SigningSettings().key_id is None
    assert SigningSettings(key_id="minha-chave-01").key_id == "minha-chave-01"


def test_private_key_password_is_bytearray_and_zeroed_after_resolve(fake_encrypted_pem_key) -> None:
    """Prova que SigningSettings propaga a garantia de zeroizacao de senha
    (Task 3/6) ate a ponta -- password precisa ser bytearray, nao bytes,
    para o pem_loader poder zera-lo apos o uso.

    fake_encrypted_pem_key ja retorna {"key": <Path>, "password": <bytearray>}
    (ver tests/conftest.py) -- copiamos a senha para um bytearray novo aqui
    para nao zerar o bytearray compartilhado da propria fixture."""
    password = bytearray(fake_encrypted_pem_key["password"])
    settings = SigningSettings(private_key_pem=fake_encrypted_pem_key["key"], private_key_password=password)
    settings.resolve()
    assert password == bytearray(len(password))


def test_re_exported_from_init() -> None:
    """SigningSettings/ResolvedSigning/TlsSettings devem ser acessiveis
    direto de hubsaude_client, nao so do submodulo -- Step 4."""
    import hubsaude_client

    assert hubsaude_client.SigningSettings is SigningSettings
    assert hubsaude_client.ResolvedSigning is ResolvedSigning
    from hubsaude_client.tls_settings import TlsSettings as _TlsSettings

    assert hubsaude_client.TlsSettings is _TlsSettings

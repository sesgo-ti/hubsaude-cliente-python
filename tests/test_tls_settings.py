from __future__ import annotations

import ssl
from unittest.mock import MagicMock, patch

from hubsaude_client.tls_settings import TlsSettings


def test_default_tls_protocol_is_tls13() -> None:
    settings = TlsSettings()
    assert settings.tls_protocol == "TLSv1.3"


def test_custom_ssl_context_takes_precedence_over_everything() -> None:
    custom_context = MagicMock(spec=ssl.SSLContext)
    settings = TlsSettings(custom_ssl_context=custom_context, server_trust_anchor_cert=MagicMock())
    assert settings.resolve_ssl_context() is custom_context


@patch("hubsaude_client.ssl_context_factory.build_ssl_context")
def test_resolve_without_mtls_delegates_unidirectional(mock_build) -> None:
    mock_build.return_value = MagicMock(spec=ssl.SSLContext)
    settings = TlsSettings()
    result = settings.resolve_ssl_context()
    assert result is mock_build.return_value
    mock_build.assert_called_once()
    _, kwargs = mock_build.call_args
    assert kwargs["client_key"] is None
    assert kwargs["client_cert"] is None


@patch("hubsaude_client.ssl_context_factory.build_ssl_context")
def test_resolve_with_mtls_material_passes_client_key_and_cert(mock_build) -> None:
    mock_build.return_value = MagicMock(spec=ssl.SSLContext)
    fake_key = MagicMock()
    fake_cert = MagicMock()
    settings = TlsSettings(client_private_key=fake_key, client_certificate=fake_cert)
    settings.resolve_ssl_context()
    _, kwargs = mock_build.call_args
    assert kwargs["client_key"] is fake_key
    assert kwargs["client_cert"] is fake_cert


@patch("hubsaude_client.ssl_context_factory.build_ssl_context")
def test_resolve_with_trust_anchor_in_memory_passes_trusted_cert(mock_build) -> None:
    mock_build.return_value = MagicMock(spec=ssl.SSLContext)
    trust_anchor = MagicMock()
    settings = TlsSettings(server_trust_anchor_cert=trust_anchor)
    settings.resolve_ssl_context()
    _, kwargs = mock_build.call_args
    assert kwargs["trusted_cert"] is trust_anchor


def test_resolve_integrates_for_real_with_ssl_context_factory(fake_pem_pair) -> None:
    """Sem mock: prova que TlsSettings realmente monta um ssl.SSLContext de
    verdade atraves de ssl_context_factory.build_ssl_context (Task 9, ja
    commitada nesta branch) -- os testes acima isolam com @patch para testar
    a logica de precedencia de TlsSettings; este aqui prova a integracao
    real entre as duas tasks, pedido explicito do fluxo de trabalho atual
    (Tasks 8 e 9 implementadas juntas)."""
    settings = TlsSettings(server_trust_anchor_path=fake_pem_pair["cert"])
    context = settings.resolve_ssl_context()
    assert isinstance(context, ssl.SSLContext)

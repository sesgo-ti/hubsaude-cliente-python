from __future__ import annotations

import ssl

import pytest

from hubsaude_client import pem_loader, ssl_context_factory
from hubsaude_client.exceptions import SmartTokenError


def test_build_ssl_context_default_uses_system_trust_store() -> None:
    context = ssl_context_factory.build_ssl_context()
    assert isinstance(context, ssl.SSLContext)
    assert len(context.get_ca_certs(binary_form=True)) > 0


def test_build_ssl_context_pins_tls13_by_default() -> None:
    context = ssl_context_factory.build_ssl_context()
    assert context.minimum_version == ssl.TLSVersion.TLSv1_3
    assert context.maximum_version == ssl.TLSVersion.TLSv1_3


def test_build_ssl_context_unsupported_protocol_raises() -> None:
    with pytest.raises(SmartTokenError, match="Protocolo TLS nao suportado"):
        ssl_context_factory.build_ssl_context(tls_protocol="SSLv3")


def test_build_ssl_context_with_trust_anchor_path(fake_pem_pair) -> None:
    context = ssl_context_factory.build_ssl_context(server_trust_anchor_path=fake_pem_pair["cert"])
    # Nao usar get_ca_certs() aqui: so lista certs com BasicConstraints
    # CA:true, e fake_pem_pair gera um cert de teste sem essa extensao
    # (nao e uma CA). cert_store_stats()["x509"] conta o cert carregado
    # independente da flag -- ver nota no topo deste brief.
    assert context.cert_store_stats()["x509"] == 1


def test_build_ssl_context_with_trust_anchor_in_memory(fake_pem_pair) -> None:
    trusted_cert = pem_loader.load_certificate(fake_pem_pair["cert"])
    context = ssl_context_factory.build_ssl_context(trusted_cert=trusted_cert)
    assert context.cert_store_stats()["x509"] == 1


def test_build_ssl_context_with_expired_trust_anchor_raises(fake_expired_cert_pem) -> None:
    with pytest.raises(SmartTokenError, match="expirado"):
        ssl_context_factory.build_ssl_context(server_trust_anchor_path=fake_expired_cert_pem)


def test_build_ssl_context_with_mtls_material_loads_cert_chain(fake_pem_pair) -> None:
    client_key = pem_loader.load_private_key(fake_pem_pair["key"])
    client_cert = pem_loader.load_certificate(fake_pem_pair["cert"])
    context = ssl_context_factory.build_ssl_context(client_key=client_key, client_cert=client_cert)
    assert isinstance(context, ssl.SSLContext)


def test_build_ssl_context_with_expired_client_cert_raises(fake_pem_pair, fake_expired_cert_pem) -> None:
    from cryptography import x509

    client_key = pem_loader.load_private_key(fake_pem_pair["key"])
    # Carrega o certificado expirado direto da lib, sem passar por
    # pem_loader.load_certificate (que ja rejeitaria antes de chegar em
    # build_ssl_context) -- o objetivo aqui e testar a validacao dentro de
    # ssl_context_factory especificamente.
    expired_cert = x509.load_pem_x509_certificate(fake_expired_cert_pem.read_bytes())
    with pytest.raises(SmartTokenError, match="expirado"):
        ssl_context_factory.build_ssl_context(client_key=client_key, client_cert=expired_cert)

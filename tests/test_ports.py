from __future__ import annotations

import ssl

from hubsaude_client.ports import SigningStrategy, TlsContextProvider

from .fakes import FakeTlsContextProvider


class _FakeSigningStrategy:
    def sign(self, data: bytes) -> bytes:
        return data[::-1]


class _NotASigningStrategy:
    def verify(self, data: bytes) -> bool:
        return True


class _NotATlsContextProvider:
    def get_context(self) -> ssl.SSLContext:
        return ssl.create_default_context()


def test_conforming_class_satisfies_protocol() -> None:
    assert isinstance(_FakeSigningStrategy(), SigningStrategy)


def test_non_conforming_class_does_not_satisfy_protocol() -> None:
    assert not isinstance(_NotASigningStrategy(), SigningStrategy)


def test_fake_signing_strategy_behavior() -> None:
    strategy: SigningStrategy = _FakeSigningStrategy()
    assert strategy.sign(b"abc") == b"cba"


def test_conforming_class_satisfies_tls_context_provider_protocol() -> None:
    assert isinstance(FakeTlsContextProvider(), TlsContextProvider)


def test_non_conforming_class_does_not_satisfy_tls_context_provider_protocol() -> None:
    assert not isinstance(_NotATlsContextProvider(), TlsContextProvider)


def test_fake_tls_context_provider_behavior() -> None:
    provider: TlsContextProvider = FakeTlsContextProvider()
    assert isinstance(provider.ssl_context(), ssl.SSLContext)

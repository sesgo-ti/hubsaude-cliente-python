from __future__ import annotations

from hubsaude_client.ports import SigningStrategy


class _FakeSigningStrategy:
    def sign(self, data: bytes) -> bytes:
        return data[::-1]


class _NotASigningStrategy:
    def verify(self, data: bytes) -> bool:
        return True


def test_conforming_class_satisfies_protocol() -> None:
    assert isinstance(_FakeSigningStrategy(), SigningStrategy)


def test_non_conforming_class_does_not_satisfy_protocol() -> None:
    assert not isinstance(_NotASigningStrategy(), SigningStrategy)


def test_fake_signing_strategy_behavior() -> None:
    strategy: SigningStrategy = _FakeSigningStrategy()
    assert strategy.sign(b"abc") == b"cba"

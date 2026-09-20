from __future__ import annotations

import logging

import pytest

from hubsaude_client.pkcs11_signing_strategy import Pkcs11SigningStrategy


class _FakeSession:
    """Sessao PKCS#11 fake cujo ``close()`` levanta, para exercitar o
    branch ``except Exception`` (best-effort) de
    ``Pkcs11SigningStrategy.close()``."""

    def close(self) -> None:
        raise RuntimeError("falha simulada ao fechar sessao PKCS#11")


def test_close_logs_warning_and_swallows_error_when_session_close_fails(
    caplog: pytest.LogCaptureFixture,
) -> None:
    strategy = Pkcs11SigningStrategy(session=_FakeSession(), key=object(), jwt_algorithm="ES256")

    with caplog.at_level(logging.WARNING, logger="hubsaude_client.SmartTokenClient"):
        strategy.close()  # nao deve levantar excecao

    assert any(
        record.levelno == logging.WARNING and "sessao PKCS#11" in record.getMessage() for record in caplog.records
    )

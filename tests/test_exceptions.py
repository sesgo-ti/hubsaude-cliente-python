from __future__ import annotations

import pytest

from hubsaude_client.exceptions import SmartTokenException


def test_message_only() -> None:
    exc = SmartTokenException("falha ao processar PEM")
    assert str(exc) == "falha ao processar PEM"
    assert exc.__cause__ is None


def test_message_with_cause_sets_cause_and_suppresses_context() -> None:
    original = ValueError("bytes invalidos")
    exc = SmartTokenException("falha ao assinar", original)
    assert exc.__cause__ is original
    assert exc.__suppress_context__ is True


def test_is_runtime_error() -> None:
    assert isinstance(SmartTokenException("x"), RuntimeError)


def test_raised_and_caught_preserves_cause() -> None:
    original = KeyError("token_endpoint")
    with pytest.raises(SmartTokenException) as excinfo:
        raise SmartTokenException("resposta invalida", original)
    assert excinfo.value.__cause__ is original

from __future__ import annotations

import pytest

from hubsaude_client.exceptions import SigningError, SmartTokenError


def test_smart_token_error_message_only() -> None:
    exc = SmartTokenError("falha ao processar PEM")
    assert str(exc) == "falha ao processar PEM"
    assert exc.__cause__ is None


def test_smart_token_error_message_with_cause_sets_cause_and_suppresses_context() -> None:
    original = ValueError("bytes invalidos")
    exc = SmartTokenError("falha ao assinar", original)
    assert exc.__cause__ is original
    assert exc.__suppress_context__ is True


def test_smart_token_error_is_runtime_error() -> None:
    assert isinstance(SmartTokenError("x"), RuntimeError)


def test_smart_token_error_raised_and_caught_preserves_cause() -> None:
    original = KeyError("token_endpoint")
    with pytest.raises(SmartTokenError) as excinfo:
        raise SmartTokenError("resposta invalida", original)
    assert excinfo.value.__cause__ is original


def test_signing_error_message_only() -> None:
    exc = SigningError("falha ao assinar dados")
    assert str(exc) == "falha ao assinar dados"
    assert exc.__cause__ is None


def test_signing_error_message_with_cause() -> None:
    original = ValueError("chave invalida")
    exc = SigningError("falha criptografica", original)
    assert exc.__cause__ is original


def test_signing_error_is_runtime_error() -> None:
    assert isinstance(SigningError("x"), RuntimeError)


def test_signing_error_is_distinct_from_smart_token_error() -> None:
    assert not issubclass(SigningError, SmartTokenError)
    assert not issubclass(SmartTokenError, SigningError)

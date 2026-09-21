from __future__ import annotations

import logging
import ssl

import httpx
import pytest

from hubsaude_client.error_classifier import (
    HTTP_TOO_MANY_REQUESTS,
    CertRejectionConfidence,
    ErrorClassifier,
    is_likely_client_certificate_rejection,
    is_transient_network_failure,
    sanitize_error_response,
)
from hubsaude_client.exceptions import SmartTokenError
from hubsaude_client.trace import TraceContext

CLIENT_ID = "cliente-teste"
ENDPOINT = "https://auth.example/token"


@pytest.fixture
def classifier() -> ErrorClassifier:
    return ErrorClassifier(CLIENT_ID, ENDPOINT)


@pytest.fixture
def trace() -> TraceContext:
    return TraceContext.generate()


def _fake_response(status_code: int, body: str, headers: dict[str, str] | None = None) -> httpx.Response:
    return httpx.Response(
        status_code=status_code,
        headers=headers or {},
        content=body.encode("utf-8"),
        request=httpx.Request("POST", ENDPOINT),
    )


# ---------------------------------------------------------------------------
# is_transient_network_failure
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "exc",
    [
        httpx.ConnectTimeout("timed out connecting"),
        httpx.ReadTimeout("timed out reading"),
        httpx.WriteTimeout("timed out writing"),
        httpx.PoolTimeout("timed out waiting for a connection from the pool"),
        httpx.ConnectError("connection refused"),
        httpx.ReadError("connection reset"),
        httpx.WriteError("connection reset"),
    ],
)
def test_transient_transport_failures_are_retriable(exc: httpx.RequestError) -> None:
    assert is_transient_network_failure(exc) is True


def test_premature_eof_message_is_retriable() -> None:
    exc = httpx.RemoteProtocolError("Server disconnected without sending a response.")
    assert is_transient_network_failure(exc) is True


def test_generic_io_like_failure_is_not_retriable() -> None:
    assert is_transient_network_failure(RuntimeError("disco cheio")) is False


def test_tls_failure_is_never_retriable_even_if_wrapped_in_connect_error() -> None:
    """httpx envolve falha de handshake mTLS num ConnectError; a falha TLS
    na cadeia de causas deve prevalecer sobre o tipo externo transitório."""
    tls_failure = ssl.SSLError("[SSL: SSLV3_ALERT_HANDSHAKE_FAILURE] handshake failure")
    wrapped = httpx.ConnectError("connection failed")
    wrapped.__cause__ = tls_failure
    assert is_transient_network_failure(wrapped) is False


def test_bare_ssl_error_is_not_retriable() -> None:
    assert is_transient_network_failure(ssl.SSLError("bad handshake")) is False


# ---------------------------------------------------------------------------
# is_likely_client_certificate_rejection
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "message",
    [
        "[SSL: SSLV3_ALERT_HANDSHAKE_FAILURE] sslv3 alert handshake failure",
        "[SSL: TLSV1_ALERT_CERTIFICATE_REVOKED] tlsv1 alert certificate revoked",
        "[SSL: TLSV13_ALERT_CERTIFICATE_EXPIRED] tlsv1.3 alert certificate expired",
        "[SSL: SSLV3_ALERT_CERTIFICATE_UNKNOWN] certificate unknown",
        "[SSL: SSLV3_ALERT_BAD_RECORD_MAC] decryption failed or bad record mac",
        "[SSL: TLSV1_ALERT_DECRYPT_ERROR] decrypt error",
        "[SSL: TLSV1_ALERT_ACCESS_DENIED] access denied",
    ],
)
def test_recognizes_client_certificate_rejection_alerts(message: str) -> None:
    assert is_likely_client_certificate_rejection(ssl.SSLError(message)) is CertRejectionConfidence.CONFIRMED


def test_recognizes_alert_wrapped_in_httpx_connect_error() -> None:
    tls_failure = ssl.SSLError("[SSL: TLSV1_ALERT_CERTIFICATE_REVOKED] certificate revoked")
    wrapped = httpx.ConnectError("connection failed")
    wrapped.__cause__ = tls_failure
    assert is_likely_client_certificate_rejection(wrapped) is CertRejectionConfidence.CONFIRMED


def test_does_not_confuse_with_server_certificate_verification_failure() -> None:
    """ssl.SSLCertVerificationError: o CLIENTE rejeitou o certificado do
    SERVIDOR (trust anchor local ausente/incorreto) -- não é o servidor
    rejeitando o certificado do cliente."""
    cert_verification_failure = ssl.SSLCertVerificationError(
        1, "certificate verify failed: unable to get local issuer certificate"
    )
    assert is_likely_client_certificate_rejection(cert_verification_failure) is CertRejectionConfidence.NONE


def test_server_cert_verification_failure_excludes_even_with_alert_text_elsewhere() -> None:
    """Se a cadeia contiver SSLCertVerificationError em qualquer ponto, a
    heurística de rejeição do certificado de CLIENTE não se aplica --
    mesmo que outro no da cadeia mencione um alerta típico."""
    cert_verification_failure = ssl.SSLCertVerificationError(1, "certificate verify failed")
    outer = ssl.SSLError("[SSL: SSLV3_ALERT_HANDSHAKE_FAILURE] handshake failure")
    outer.__cause__ = cert_verification_failure
    assert is_likely_client_certificate_rejection(outer) is CertRejectionConfidence.NONE


def test_recognizes_tls13_eof_after_handshake_variant_as_probable() -> None:
    """Sob TLS 1.3, alguns builds de OpenSSL encerram a conexão sem alerta
    textual reconhecível quando o servidor rejeita o certificado de
    cliente após o ``Finished`` (ver nota no topo de
    ``error_classifier.py``). Sinal AMBÍGUO (PROBABLE, não CONFIRMED):
    também pode ser apenas instabilidade de rede comum."""
    exc = ssl.SSLEOFError("EOF occurred in violation of protocol (_ssl.c:1006)")
    assert is_likely_client_certificate_rejection(exc) is CertRejectionConfidence.PROBABLE


def test_recognizes_tls13_eof_variant_wrapped_in_httpx_connect_error_as_probable() -> None:
    eof_failure = ssl.SSLEOFError("EOF occurred in violation of protocol (_ssl.c:1006)")
    wrapped = httpx.ConnectError("connection failed")
    wrapped.__cause__ = eof_failure
    assert is_likely_client_certificate_rejection(wrapped) is CertRejectionConfidence.PROBABLE


def test_ssl_eof_error_with_generic_message_is_not_a_client_certificate_rejection() -> None:
    """Só o texto exato da variante conhecida deve ser reconhecido -- um
    ``ssl.SSLEOFError`` genérico (ex.: queda de conexão TCP antes do
    handshake completar) não deve virar falso positivo."""
    exc = ssl.SSLEOFError("some other EOF condition")
    assert is_likely_client_certificate_rejection(exc) is CertRejectionConfidence.NONE


def test_ssl_error_with_eof_message_but_wrong_type_is_not_recognized() -> None:
    """A checagem exige o tipo exato ``ssl.SSLEOFError``: um ``ssl.SSLError``
    genérico com o mesmo texto (cenário que não deveria ocorrer na prática,
    mas não pode ser tratado como a variante específica) não é reconhecido
    por esse fragmento -- e nenhum dos fragmentos de alerta bate com esse
    texto, então o resultado é ``NONE``."""
    exc = ssl.SSLError("EOF occurred in violation of protocol (_ssl.c:1006)")
    assert is_likely_client_certificate_rejection(exc) is CertRejectionConfidence.NONE


def test_unrelated_ssl_error_is_not_a_client_certificate_rejection() -> None:
    assert is_likely_client_certificate_rejection(ssl.SSLError("unrecognized_name")) is CertRejectionConfidence.NONE


def test_non_ssl_failure_is_not_a_client_certificate_rejection() -> None:
    assert is_likely_client_certificate_rejection(httpx.ConnectTimeout("timed out")) is CertRejectionConfidence.NONE


def test_none_is_not_a_client_certificate_rejection() -> None:
    assert is_likely_client_certificate_rejection(None) is CertRejectionConfidence.NONE


# ---------------------------------------------------------------------------
# sanitize_error_response
# ---------------------------------------------------------------------------


def test_sanitize_none_body() -> None:
    assert sanitize_error_response(None) == "<empty>"


def test_sanitize_redacts_json_access_token() -> None:
    result = sanitize_error_response('{"access_token":"segredo"}')
    assert "[REDACTED]" in result
    assert "segredo" not in result


def test_sanitize_redacts_json_token_field() -> None:
    result = sanitize_error_response('{"token":"segredo-tambem"}')
    assert "[REDACTED]" in result
    assert "segredo-tambem" not in result


def test_sanitize_redacts_form_encoded_token() -> None:
    result = sanitize_error_response("error=slow_down&access_token=segredo123&scope=x")
    assert "[REDACTED]" in result
    assert "segredo123" not in result


def test_sanitize_truncates_long_body_after_redaction() -> None:
    long_body = '{"access_token":"' + ("x" * 600) + '","error":"' + ("y" * 600) + '"}'
    result = sanitize_error_response(long_body)
    assert result.endswith("...")
    assert "[REDACTED]" in result
    assert "y" * 600 not in result
    assert len(result) == 503  # 500 + "..."


def test_sanitize_preserves_short_body_without_tokens() -> None:
    assert sanitize_error_response('{"error":"invalid_client"}') == '{"error":"invalid_client"}'


# ---------------------------------------------------------------------------
# ErrorClassifier.retriable_or_reraise
# ---------------------------------------------------------------------------


def test_returns_the_exception_when_transient(classifier: ErrorClassifier, trace: TraceContext) -> None:
    timeout = httpx.ConnectTimeout("timed out")
    assert classifier.retriable_or_reraise(timeout, trace) is timeout


def test_reraises_when_not_transient(classifier: ErrorClassifier, trace: TraceContext) -> None:
    not_transient = httpx.RequestError("disco cheio")
    with pytest.raises(httpx.RequestError) as excinfo:
        classifier.retriable_or_reraise(not_transient, trace)
    assert excinfo.value is not_transient


def test_converts_mtls_rejection_into_smart_token_error_with_guidance(
    classifier: ErrorClassifier, trace: TraceContext
) -> None:
    tls_failure = ssl.SSLError("[SSL: TLSV1_ALERT_CERTIFICATE_REVOKED] certificate revoked")
    mtls_failure = httpx.ConnectError("connection failed")
    mtls_failure.__cause__ = tls_failure

    with pytest.raises(SmartTokenError) as excinfo:
        classifier.retriable_or_reraise(mtls_failure, trace)

    message = str(excinfo.value)
    assert ENDPOINT in message
    assert "certificado de cliente rejeitado" in message
    assert excinfo.value.__cause__ is mtls_failure


def test_logs_error_on_mtls_rejection(
    classifier: ErrorClassifier, trace: TraceContext, caplog: pytest.LogCaptureFixture
) -> None:
    tls_failure = ssl.SSLError("[SSL: TLSV1_ALERT_CERTIFICATE_REVOKED] certificate revoked")
    mtls_failure = httpx.ConnectError("connection failed")
    mtls_failure.__cause__ = tls_failure

    with caplog.at_level(logging.ERROR, logger="hubsaude_client.SmartTokenClient"):
        with pytest.raises(SmartTokenError):
            classifier.retriable_or_reraise(mtls_failure, trace)

    assert any(record.levelno == logging.ERROR for record in caplog.records)
    assert any(CLIENT_ID in record.getMessage() for record in caplog.records)


def test_probable_cert_rejection_is_retriable_unlike_confirmed(
    classifier: ErrorClassifier, trace: TraceContext
) -> None:
    """Sinal AMBÍGUO (PROBABLE, ssl.SSLEOFError sem alerta textual) não
    deve interromper o retry -- diferente do sinal CONFIRMED, que
    interrompe imediatamente (ver test_converts_mtls_rejection_into_smart_token_error_with_guidance).
    Pode ser rejeição de certificado, mas também pode ser só
    instabilidade de rede; a exceção deve ser devolvida para o chamador
    tentar de novo."""
    probable_failure = ssl.SSLEOFError("EOF occurred in violation of protocol (_ssl.c:1006)")
    wrapped = httpx.ConnectError("connection failed")
    wrapped.__cause__ = probable_failure

    assert classifier.retriable_or_reraise(wrapped, trace) is wrapped


# ---------------------------------------------------------------------------
# ErrorClassifier.exhaustion_hint
# ---------------------------------------------------------------------------


def test_exhaustion_hint_empty_for_confirmed_rejection(classifier: ErrorClassifier) -> None:
    """CONFIRMED nunca chega a esgotar o retry (interrompe antes, ver
    retriable_or_reraise) -- mas o método em si deve devolver string vazia
    pra esse sinal, por clareza de contrato."""
    tls_failure = ssl.SSLError("[SSL: TLSV1_ALERT_CERTIFICATE_REVOKED] certificate revoked")
    assert classifier.exhaustion_hint(tls_failure) == ""


def test_exhaustion_hint_empty_for_no_signal(classifier: ErrorClassifier) -> None:
    assert classifier.exhaustion_hint(httpx.ConnectTimeout("timed out")) == ""


def test_exhaustion_hint_non_empty_for_probable_rejection(classifier: ErrorClassifier) -> None:
    probable_failure = ssl.SSLEOFError("EOF occurred in violation of protocol (_ssl.c:1006)")
    hint = classifier.exhaustion_hint(probable_failure)
    assert hint != ""
    assert "certificado" in hint


# ---------------------------------------------------------------------------
# ErrorClassifier.http_failure
# ---------------------------------------------------------------------------


def test_builds_message_with_status_and_trace_id(classifier: ErrorClassifier, trace: TraceContext) -> None:
    exc = classifier.http_failure(_fake_response(401, '{"error":"invalid_client"}'), trace)

    message = str(exc)
    assert "HTTP 401" in message
    assert f"traceId={trace.trace_id}" in message
    assert "invalid_client" in message


def test_redacts_access_token_from_body(classifier: ErrorClassifier, trace: TraceContext) -> None:
    exc = classifier.http_failure(_fake_response(400, '{"access_token":"segredo"}'), trace)

    message = str(exc)
    assert "[REDACTED]" in message
    assert "segredo" not in message


def test_includes_retry_after_and_guidance_on_429(classifier: ErrorClassifier, trace: TraceContext) -> None:
    exc = classifier.http_failure(_fake_response(429, '{"error":"slow_down"}', headers={"Retry-After": "30"}), trace)

    message = str(exc)
    assert "HTTP 429" in message
    assert "(Retry-After: 30)" in message
    assert "a decisão de aguardar e reenviar é do chamador" in message


def test_omits_retry_after_when_absent(classifier: ErrorClassifier, trace: TraceContext) -> None:
    exc = classifier.http_failure(_fake_response(500, '{"error":"server_error"}'), trace)

    assert "Retry-After" not in str(exc)


def test_returns_smart_token_error_instance(classifier: ErrorClassifier, trace: TraceContext) -> None:
    exc = classifier.http_failure(_fake_response(500, "boom"), trace)
    assert isinstance(exc, SmartTokenError)


def test_logs_warning_on_429(
    classifier: ErrorClassifier, trace: TraceContext, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.WARNING, logger="hubsaude_client.SmartTokenClient"):
        classifier.http_failure(_fake_response(429, "{}"), trace)

    assert any(record.levelno == logging.WARNING for record in caplog.records)


def test_logs_error_on_non_429_http_failure(
    classifier: ErrorClassifier, trace: TraceContext, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.ERROR, logger="hubsaude_client.SmartTokenClient"):
        classifier.http_failure(_fake_response(401, "{}"), trace)

    assert any(record.levelno == logging.ERROR for record in caplog.records)


def test_http_too_many_requests_constant() -> None:
    assert HTTP_TOO_MANY_REQUESTS == 429

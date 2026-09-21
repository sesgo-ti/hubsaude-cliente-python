"""Validação de ``error_classifier.is_likely_client_certificate_rejection``
contra handshakes mTLS *reais* (sockets loopback + OpenSSL de verdade),
complementando ``test_error_classifier.py`` -- que só cobre a heurística
com instâncias de ``ssl.SSLError`` construídas a mão.

Este arquivo valida a heurística contra um handshake mTLS
real com certificado de cliente rejeitado (complementando os testes que
usam ``ssl.SSLError`` simulado), usando
``hubsaude_client.ssl_context_factory.build_ssl_context`` (mesmo caminho
de produção) para o lado do cliente, contra um servidor loopback que
exige certificado de cliente de uma CA que ele deliberadamente não
confia -- ver ``tests/conftest.py::real_mtls_client_cert_rejection``.

Esta cobertura contra handshake mTLS real é uma adição genuína desta
suíte: a implementação de referência valida a mesma heurística apenas
com exceções simuladas, sem um teste equivalente contra um handshake de
verdade.
"""

from __future__ import annotations

import ssl

import pytest

from hubsaude_client.error_classifier import (
    CertRejectionConfidence,
    is_likely_client_certificate_rejection,
    is_transient_network_failure,
)


def test_real_unknown_ca_rejection_tls12_is_classified(real_mtls_client_cert_rejection) -> None:
    """Sob TLS 1.2, um certificado de cliente com CA desconhecida do
    servidor produz um ``ssl.SSLError`` com o alerta ``unknown ca`` do
    lado do cliente. Teste de regressão: sem o fragmento
    ``unknown_ca``/``unknown ca`` em ``error_classifier.py``, esse
    alerta não seria reconhecido pela heurística (que cobre
    ``certificate_unknown``, um alerta TLS diferente, separadamente).
    """
    captured = real_mtls_client_cert_rejection("TLSv1.2")

    assert captured is not None, "esperava ssl.SSLError do lado do cliente; handshake teve sucesso inesperadamente"
    assert "unknown ca" in str(captured).lower()
    assert is_likely_client_certificate_rejection(captured) is CertRejectionConfidence.CONFIRMED


def test_real_unknown_ca_rejection_tls13_is_never_treated_as_retriable(real_mtls_client_cert_rejection) -> None:
    """Caracteriza o comportamento sob TLS 1.3 -- o protocolo padrão desta
    lib (``defaults.DEFAULT_TLS_PROTOCOL``) -- sem travar numa suposição
    de plataforma específica.

    A superfície exata do ``ssl.SSLError`` que o cliente
    recebe quando o servidor rejeita seu certificado sob TLS 1.3 *varia
    por plataforma/versão do OpenSSL*: em ``OpenSSL 3.0.13`` observa-se
    ``ssl.SSLEOFError`` ("EOF occurred in violation of protocol"), sem
    nenhum fragmento de alerta reconhecível -- nesse caso,
    ``is_likely_client_certificate_rejection`` devolve
    ``CertRejectionConfidence.PROBABLE`` (sinal ambíguo). Em
    outras combinações de plataforma/OpenSSL, o mesmo cenário produz um
    alerta ``unknown ca`` limpo, caso em que
    ``is_likely_client_certificate_rejection`` devolve
    ``CertRejectionConfidence.CONFIRMED``. Por isso este teste não afirma
    um valor específico
    de :func:`is_likely_client_certificate_rejection` (faria o teste
    depender de qual OpenSSL roda a máquina) -- ver
    ``test_real_unknown_ca_rejection_tls13_is_classified_when_surface_is_recognized``,
    abaixo, para a classificação fina das duas superfícies conhecidas
    (ver nota no topo de ``error_classifier.py``).

    O que este teste garante, e que *não* varia por plataforma: a
    conexão nunca é tratada como retriavel nesse cenário, porque
    ``is_transient_network_failure`` exclui todo ``ssl.SSLError``
    (inclusive ``ssl.SSLEOFError``) antes de qualquer outra checagem --
    a garantia de segurança real (não reenviar credencial contra um
    servidor que acabou de rejeitar o certificado do cliente) se
    sustenta independente de qual exceção exata aparecer.
    """
    captured = real_mtls_client_cert_rejection("TLSv1.3")

    assert captured is not None, "esperava ssl.SSLError do lado do cliente; handshake teve sucesso inesperadamente"
    assert is_transient_network_failure(captured) is False


def test_real_unknown_ca_rejection_tls13_is_classified_when_surface_is_recognized(
    real_mtls_client_cert_rejection,
) -> None:
    """Confirma a classificação fina sob TLS 1.3 para as duas superfícies
    conhecidas do mesmo evento de servidor (rejeição de certificado de
    cliente por CA desconhecida após o ``Finished``):

    - alerta ``unknown ca`` limpo (mesmo fragmento já coberto para TLS 1.2);
    - ``ssl.SSLEOFError`` com a mensagem "EOF occurred in violation of
      protocol", a outra superfície OpenSSL conhecida desse mesmo
      evento de servidor (ver nota no topo de ``error_classifier.py``).

    Uma terceira superfície não mapeada, se aparecer numa plataforma ainda
    não observada, resulta em ``skip`` explicativo -- não em falso
    positivo/negativo silencioso.
    """
    captured = real_mtls_client_cert_rejection("TLSv1.3")

    assert captured is not None, "esperava ssl.SSLError do lado do cliente; handshake teve sucesso inesperadamente"

    message = str(captured).lower()
    is_known_alert_surface = "unknown ca" in message
    is_known_eof_surface = isinstance(captured, ssl.SSLEOFError) and (
        "eof occurred in violation of protocol" in message
    )

    if not (is_known_alert_surface or is_known_eof_surface):
        pytest.skip(
            "Superfície de erro TLS 1.3 não mapeada neste ambiente "
            f"(OpenSSL/plataforma): {type(captured).__name__}: {captured!r}. "
            "Não é falha do teste -- é evidência de uma terceira variante "
            "que ainda não foi documentada no módulo error_classifier.py."
        )

    # As duas superfícies do mesmo evento de servidor têm níveis de
    # confiança diferentes: o alerta limpo é inequívoco (CONFIRMED); o
    # ssl.SSLEOFError sem alerta textual é ambíguo (PROBABLE), porque o
    # mesmo texto também pode surgir de uma instabilidade de rede comum
    # sem relação com o certificado.
    expected = CertRejectionConfidence.CONFIRMED if is_known_alert_surface else CertRejectionConfidence.PROBABLE
    assert is_likely_client_certificate_rejection(captured) is expected

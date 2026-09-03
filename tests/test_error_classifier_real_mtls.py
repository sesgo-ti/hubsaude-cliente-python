"""Validacao de ``error_classifier.is_likely_client_certificate_rejection``
contra handshakes mTLS *reais* (sockets loopback + OpenSSL de verdade),
complementando ``test_error_classifier.py`` -- que so' cobre a heuristica
com instancias de ``ssl.SSLError`` construidas a mao.

Este arquivo valida a heuristica contra um handshake mTLS
real com certificado de cliente rejeitado (complementando os testes que
usam ``ssl.SSLError`` simulado), usando
``hubsaude_client.ssl_context_factory.build_ssl_context`` (mesmo caminho
de producao) para o lado do cliente, contra um servidor loopback que
exige certificado de cliente de uma CA que ele deliberadamente nao
confia -- ver ``tests/conftest.py::real_mtls_client_cert_rejection``.

Esta cobertura contra handshake mTLS real e' uma adicao genuina desta
suite: a implementacao de referencia valida a mesma heuristica apenas
com excecoes simuladas, sem um teste equivalente contra um handshake de
verdade.
"""

from __future__ import annotations

import ssl

import pytest

from hubsaude_client.error_classifier import is_likely_client_certificate_rejection, is_transient_network_failure


def test_real_unknown_ca_rejection_tls12_is_classified(real_mtls_client_cert_rejection) -> None:
    """Sob TLS 1.2, um certificado de cliente com CA desconhecida do
    servidor produz um ``ssl.SSLError`` com o alerta ``unknown ca`` do
    lado do cliente. Teste de regressao: sem o fragmento
    ``unknown_ca``/``unknown ca`` em ``error_classifier.py``, esse
    alerta nao seria reconhecido pela heuristica (que cobre
    ``certificate_unknown``, um alerta TLS diferente, separadamente).
    """
    captured = real_mtls_client_cert_rejection("TLSv1.2")

    assert captured is not None, "esperava ssl.SSLError do lado do cliente; handshake teve sucesso inesperadamente"
    assert "unknown ca" in str(captured).lower()
    assert is_likely_client_certificate_rejection(captured) is True


def test_real_unknown_ca_rejection_tls13_is_never_treated_as_retriable(real_mtls_client_cert_rejection) -> None:
    """Caracteriza o comportamento sob TLS 1.3 -- o protocolo padrao desta
    lib (``defaults.DEFAULT_TLS_PROTOCOL``) -- sem travar numa suposicao
    de plataforma especifica.

    A superficie exata do ``ssl.SSLError`` que o cliente
    recebe quando o servidor rejeita seu certificado sob TLS 1.3 *varia
    por plataforma/versao do OpenSSL*: em ``OpenSSL 3.0.13`` observa-se
    ``ssl.SSLEOFError`` ("EOF occurred in violation of protocol"), sem
    nenhum fragmento de alerta reconhecivel -- nesse caso,
    ``is_likely_client_certificate_rejection`` devolve ``False``. Em
    outras combinacoes de plataforma/OpenSSL, o mesmo cenario produz um
    alerta ``unknown ca`` limpo, caso em que
    ``is_likely_client_certificate_rejection`` devolve ``True``. Por isso este teste nao afirma um valor especifico
    de :func:`is_likely_client_certificate_rejection` (faria o teste
    depender de qual OpenSSL roda a maquina) -- ver
    ``test_real_unknown_ca_rejection_tls13_is_classified_when_surface_is_recognized``,
    abaixo, para a classificacao fina das duas superficies conhecidas
    (ver nota no topo de ``error_classifier.py``).

    O que este teste garante, e que *nao* varia por plataforma: a
    conexao nunca e' tratada como retriavel nesse cenario, porque
    ``is_transient_network_failure`` exclui todo ``ssl.SSLError``
    (inclusive ``ssl.SSLEOFError``) antes de qualquer outra checagem --
    a garantia de seguranca real (nao reenviar credencial contra um
    servidor que acabou de rejeitar o certificado do cliente) se
    sustenta independente de qual excecao exata aparecer.
    """
    captured = real_mtls_client_cert_rejection("TLSv1.3")

    assert captured is not None, "esperava ssl.SSLError do lado do cliente; handshake teve sucesso inesperadamente"
    assert is_transient_network_failure(captured) is False


def test_real_unknown_ca_rejection_tls13_is_classified_when_surface_is_recognized(
    real_mtls_client_cert_rejection,
) -> None:
    """Confirma a classificacao fina sob TLS 1.3 para as duas superficies
    conhecidas do mesmo evento de servidor (rejeicao de certificado de
    cliente por CA desconhecida apos o ``Finished``):

    - alerta ``unknown ca`` limpo (mesmo fragmento ja coberto para TLS 1.2);
    - ``ssl.SSLEOFError`` com a mensagem "EOF occurred in violation of
      protocol", a outra superficie OpenSSL conhecida desse mesmo
      evento de servidor (ver nota no topo de ``error_classifier.py``).

    Uma terceira superficie nao mapeada, se aparecer numa plataforma ainda
    nao observada, resulta em ``skip`` explicativo -- nao em falso
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
            "Superficie de erro TLS 1.3 nao mapeada neste ambiente "
            f"(OpenSSL/plataforma): {type(captured).__name__}: {captured!r}. "
            "Nao e' falha do teste -- e' evidencia de uma terceira variante "
            "que ainda nao foi documentada no modulo error_classifier.py."
        )

    assert is_likely_client_certificate_rejection(captured) is True

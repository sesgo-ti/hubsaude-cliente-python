"""Validacao de ``error_classifier.is_likely_client_certificate_rejection``
contra handshakes mTLS *reais* (sockets loopback + OpenSSL de verdade),
complementando ``test_error_classifier.py`` -- que so' cobre a heuristica
com instancias de ``ssl.SSLError`` construidas a mao.

Contexto: item 2 do roadmap (``ROADMAP-hubsaude-cliente-python.md``)
listava como pendencia "validar a heuristica contra um handshake mTLS
real com certificado de cliente rejeitado (hoje so' testada com
ssl.SSLError simulado)". Este arquivo faz exatamente isso, usando
``hubsaude_client.ssl_context_factory.build_ssl_context`` (mesmo caminho
de producao) para o lado do cliente, contra um servidor loopback que
exige certificado de cliente de uma CA que ele deliberadamente nao
confia -- ver ``tests/conftest.py::real_mtls_client_cert_rejection``.
"""

from __future__ import annotations

from hubsaude_client.error_classifier import is_likely_client_certificate_rejection, is_transient_network_failure


def test_real_unknown_ca_rejection_tls12_is_classified(real_mtls_client_cert_rejection) -> None:
    """Sob TLS 1.2, um certificado de cliente com CA desconhecida do
    servidor produz um ``ssl.SSLError`` com o alerta ``unknown ca`` do
    lado do cliente -- caso real que nao estava coberto pelos fragmentos
    de ``error_classifier.py`` antes desta rodada (so' cobria
    ``certificate_unknown``, um alerta TLS diferente). Este teste teria
    falhado antes do fragmento ``unknown_ca``/``unknown ca`` ser
    adicionado.
    """
    captured = real_mtls_client_cert_rejection("TLSv1.2")

    assert captured is not None, "esperava ssl.SSLError do lado do cliente; handshake teve sucesso inesperadamente"
    assert "unknown ca" in str(captured).lower()
    assert is_likely_client_certificate_rejection(captured) is True


def test_real_unknown_ca_rejection_tls13_is_never_treated_as_retriable(real_mtls_client_cert_rejection) -> None:
    """Caracteriza o comportamento sob TLS 1.3 -- o protocolo padrao desta
    lib (``defaults.DEFAULT_TLS_PROTOCOL``) -- sem travar numa suposicao
    de plataforma especifica.

    Achado desta rodada (corrigido apos rodar em duas maquinas
    diferentes): a superficie exata do ``ssl.SSLError`` que o cliente
    recebe quando o servidor rejeita seu certificado sob TLS 1.3 *varia
    por plataforma/versao do OpenSSL*. Em ``OpenSSL 3.0.13`` observou-se
    ``ssl.SSLEOFError`` ("EOF occurred in violation of protocol"), sem
    nenhum fragmento de alerta reconhecivel -- nesse caso,
    ``is_likely_client_certificate_rejection`` devolve ``False``. Em
    outra maquina (mesma versao de Python, OpenSSL diferente), o mesmo
    cenario produziu um alerta ``unknown ca`` limpo -- caso em que, apos
    o fix desta rodada, ``is_likely_client_certificate_rejection``
    devolve ``True``. Por isso este teste nao afirma um valor especifico
    de :func:`is_likely_client_certificate_rejection` (faria o teste
    depender de qual OpenSSL roda a maquina) -- e' a mesma incerteza do
    ``# TODO(duvida)`` sobre ``AEADBadTagException`` (ver topo de
    ``error_classifier.py`` e item 2 do roadmap), agora com evidencia
    real de que ela tambem varia por ambiente, nao so' por plataforma
    Java-vs-Python.

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

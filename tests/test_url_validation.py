from __future__ import annotations

import pytest

from hubsaude_client.exceptions import SmartTokenError
from hubsaude_client.url_validation import require_https_scheme


def test_require_https_scheme_accepts_https() -> None:
    require_https_scheme("https://auth.exemplo.com/token", "token_endpoint")  # nao deve lancar


@pytest.mark.parametrize(
    "url",
    [
        "http://localhost/token",
        "http://localhost:8080/token",
        "http://127.0.0.1/token",
        "http://127.0.0.1:8080/token",
        "http://[::1]/token",
        "http://[::1]:8080/token",
        "http://LOCALHOST/token",
        "http://127.0.0.1:8080/TOKEN?x=1",
    ],
)
def test_require_https_scheme_allows_local_hosts_over_http(url: str) -> None:
    """RF-18: excecao explicita para hosts locais em http, util em
    desenvolvimento e testes com servidor local -- mesma allowlist do lado
    Java (`SmartConfigurationDiscovery.requireHttps`)."""
    require_https_scheme(url, "token_endpoint")  # nao deve lancar


def test_require_https_scheme_rejects_http_for_non_local_host() -> None:
    with pytest.raises(SmartTokenError, match="deve usar o esquema https"):
        require_https_scheme("http://auth.exemplo.com/token", "token_endpoint")


def test_require_https_scheme_rejects_http_for_similar_but_non_local_host() -> None:
    """Garante que a allowlist de hosts locais nao vaza para hosts
    parecidos (ex.: um subdominio malicioso contendo "localhost")."""
    with pytest.raises(SmartTokenError, match="deve usar o esquema https"):
        require_https_scheme("http://localhost.evil.example.com/token", "token_endpoint")


def test_require_https_scheme_rejects_non_http_non_https_scheme() -> None:
    with pytest.raises(SmartTokenError, match="deve usar o esquema https"):
        require_https_scheme("ftp://auth.exemplo.com/token", "token_endpoint")


def test_require_https_scheme_error_message_includes_field_name_and_url() -> None:
    with pytest.raises(SmartTokenError, match="fhir_base.*http://auth.exemplo.com/token"):
        require_https_scheme("http://auth.exemplo.com/token", "fhir_base")


@pytest.mark.parametrize(
    "malformed_url",
    [
        "http://[::1",
        "http://[::1/token",
        "https://[2001:db8::1/token",
    ],
)
def test_require_https_scheme_converts_malformed_url_to_smart_token_error(malformed_url: str) -> None:
    """``urlsplit`` lanca ``ValueError`` crua para literais IPv6 malformados
    (ex.: colchete de abertura sem fechamento); ``require_https_scheme``
    deve converter isso em ``SmartTokenError``, nao deixar o ``ValueError``
    vazar para quem chama (fronteira publica de excecao de dominio unica)."""
    with pytest.raises(SmartTokenError, match="URL malformada") as exc_info:
        require_https_scheme(malformed_url, "token_endpoint")
    assert isinstance(exc_info.value.__cause__, ValueError)


def test_require_https_scheme_case_insensitive_scheme_and_host() -> None:
    """Esquema e host sao comparados sem diferenciar maiusculas/minusculas
    (RF-18): ``HTTPS`` e equivalente a ``https``; ``HTTP`` + host local em
    qualquer caixa continua na allowlist."""
    require_https_scheme("HTTPS://auth.exemplo.com/token", "token_endpoint")  # nao deve lancar
    require_https_scheme("HTTP://LOCALHOST:8080/token", "token_endpoint")  # nao deve lancar

"""Validação compartilhada de esquema https para URLs (RF-10, RF-18).

Exige que uma URL use o esquema ``https``, com exceção explícita para
hosts locais (``localhost``, ``127.0.0.1``, ``::1``) em ``http`` -- útil em
desenvolvimento e testes com servidor local, nunca em produção.

Compartilhado por ``builder.py`` (URLs de ``token_endpoint``/``fhir_base``
informadas explicitamente por quem constrói o cliente) e ``discovery.py``
(URL de ``token_endpoint`` retornada pelo servidor de descoberta SMART):
extraído para um módulo próprio para que os
dois lados reutilizem a mesma lógica e a mesma lista de hosts locais, sem
duplicação nem dependência de um módulo sobre o outro.

Não faz parte da API pública da biblioteca (não exportado em
``__init__.py``).
"""

from __future__ import annotations

from typing import Final
from urllib.parse import urlsplit

from hubsaude_client.exceptions import SmartTokenError

_REQUIRED_URL_SCHEME: Final[str] = "https"

#: Hosts tratados como locais para fins da exceção de esquema http
#: (RF-18) -- úteis em desenvolvimento e testes com servidor local, nunca
#: em produção. ``urlsplit(...).hostname`` já normaliza IPv6 sem
#: colchetes e em minúsculas, então uma única entrada "::1" cobre tanto
#: ``http://[::1]`` quanto ``http://::1``.
_LOCAL_HOSTS: Final[frozenset[str]] = frozenset({"localhost", "127.0.0.1", "::1"})


def require_https_scheme(url: str, field_name: str) -> None:
    """Exige que ``url`` use o esquema ``https`` (RF-10, RF-18).

    Exceção explícita: ``http://localhost``, ``http://127.0.0.1`` e
    ``http://[::1]``/``http://::1`` são aceitos, para não quebrar o
    desenvolvimento local contra um authorization server de teste sem
    TLS.

    Args:
        url: URL a validar (já normalizada/sem espaços laterais).
        field_name: nome do campo, para a mensagem de erro.

    Raises:
        SmartTokenError: se o esquema não for ``https`` (case-insensitive)
            e o host não for um dos hosts locais permitidos em ``http``, ou
            se ``url`` for malformada a ponto de não poder ser decomposta
            (ex.: literal IPv6 sem colchete de fechamento) -- ``urlsplit``
            lança ``ValueError`` crua nesses casos, convertida aqui para
            manter um único tipo de exceção de domínio na fronteira pública
            desta função.
    """
    try:
        parts = urlsplit(url)
    except ValueError as exc:
        raise SmartTokenError(f"{field_name} e uma URL malformada: {url!r}", exc)
    scheme = parts.scheme.lower()
    if scheme == _REQUIRED_URL_SCHEME:
        return
    host = parts.hostname
    if scheme == "http" and host is not None and host.lower() in _LOCAL_HOSTS:
        return
    raise SmartTokenError(
        f"{field_name} deve usar o esquema https, recebido: {url!r}"
        " (credenciais e client_assertion não podem trafegar fora de TLS;"
        " o esquema http é permitido apenas para localhost/127.0.0.1/::1,"
        " em desenvolvimento e testes locais)"
    )

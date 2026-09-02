"""Validacao compartilhada de esquema https para URLs (RF-10, RF-18).

Exige que uma URL use o esquema ``https``, com excecao explicita para
hosts locais (``localhost``, ``127.0.0.1``, ``::1``) em ``http`` -- util em
desenvolvimento e testes com servidor local, nunca em producao.

Compartilhado por ``builder.py`` (URLs de ``token_endpoint``/``fhir_base``
informadas explicitamente por quem constroi o cliente) e ``discovery.py``
(URL de ``token_endpoint`` retornada pelo servidor de descoberta SMART):
extraido para um modulo proprio para que os
dois lados reutilizem a mesma logica e a mesma lista de hosts locais, sem
duplicacao nem dependencia de um modulo sobre o outro.

Nao faz parte da API publica da biblioteca (nao exportado em
``__init__.py``).
"""

from __future__ import annotations

from typing import Final
from urllib.parse import urlsplit

from hubsaude_client.exceptions import SmartTokenError

_REQUIRED_URL_SCHEME: Final[str] = "https"

#: Hosts tratados como locais para fins da excecao de esquema http
#: (RF-18) -- uteis em desenvolvimento e testes com servidor local, nunca
#: em producao. ``urlsplit(...).hostname`` ja normaliza IPv6 sem
#: colchetes e em minusculas, entao uma unica entrada "::1" cobre tanto
#: ``http://[::1]`` quanto ``http://::1``.
_LOCAL_HOSTS: Final[frozenset[str]] = frozenset({"localhost", "127.0.0.1", "::1"})


def require_https_scheme(url: str, field_name: str) -> None:
    """Exige que ``url`` use o esquema ``https`` (RF-10, RF-18).

    Excecao explicita: ``http://localhost``, ``http://127.0.0.1`` e
    ``http://[::1]``/``http://::1`` sao aceitos, para nao quebrar o
    desenvolvimento local contra um authorization server de teste sem
    TLS.

    Args:
        url: URL a validar (ja normalizada/sem espacos laterais).
        field_name: nome do campo, para a mensagem de erro.

    Raises:
        SmartTokenError: se o esquema nao for ``https`` (case-insensitive)
            e o host nao for um dos hosts locais permitidos em ``http``, ou
            se ``url`` for malformada a ponto de nao poder ser decomposta
            (ex.: literal IPv6 sem colchete de fechamento) -- ``urlsplit``
            lanca ``ValueError`` crua nesses casos, convertida aqui para
            manter um unico tipo de excecao de dominio na fronteira publica
            desta funcao.
    """
    try:
        parts = urlsplit(url)
    except ValueError as exc:
        raise SmartTokenError(f"{field_name} e uma URL malformada: {url!r}", exc) from exc
    scheme = parts.scheme.lower()
    if scheme == _REQUIRED_URL_SCHEME:
        return
    host = parts.hostname
    if scheme == "http" and host is not None and host.lower() in _LOCAL_HOSTS:
        return
    raise SmartTokenError(
        f"{field_name} deve usar o esquema https, recebido: {url!r}"
        " (credenciais e client_assertion nao podem trafegar fora de TLS;"
        " o esquema http e permitido apenas para localhost/127.0.0.1/::1,"
        " em desenvolvimento e testes locais)"
    )

"""Helper de baixo nível para montar um ``client_assertion`` JWT "na mão"
(sem passar pela API pública ``SmartTokenClient``/``builder.py``) e
inspecionar o protocolo bruto (header JOSE, JWKS) — usado pelos testes
de caracterização do elemento ``kid`` (issue #408) em
``tests/test_smart_token_client_integration.py``.

Construído com ``cryptography`` (já dependência de runtime do projeto —
ver ``pem_loader.py``/``ssl_context_factory.py``), sem introduzir
nenhuma dependência nova só para teste: uma lib de JWT dedicada, tipo
``pyjwt``, resolveria pouco a mais do que estas ~poucas dezenas de
linhas de base64/JSON/assinatura RSA, ao custo de mais uma dependência
a manter.
"""

from __future__ import annotations

import base64
import json
import ssl
import time
import uuid
from typing import Final

import httpx
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

#: Algoritmo fixo usado pelos testes de kid (mesmo RS384 usado pelo
#: restante da suíte).
_JWT_ALG: Final[str] = "RS384"
_JWT_TYPE: Final[str] = "JWT"

#: TTL fixo do client_assertion cru montado por estes testes -- não é o
#: TTL configurável do builder, já que estes testes contornam o builder
#: de propósito.
_ASSERTION_TTL_SECONDS: Final[int] = 60

_CLIENT_ASSERTION_TYPE: Final[str] = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"


def build_client_assertion(
    *,
    client_id: str,
    token_endpoint: str,
    private_key: rsa.RSAPrivateKey,
    kid: str | None,
) -> str:
    """Monta um ``client_assertion`` JWT compacto, assinado com RS384,
    com ou sem o elemento ``kid`` no header JOSE.

    Args:
        client_id: usado como ``iss``/``sub`` do JWT.
        token_endpoint: usado como ``aud`` do JWT.
        private_key: chave privada RSA usada para assinar (RS384 ==
            RSASSA-PKCS1-v1_5 com SHA-384).
        kid: identificador de chave a incluir no header; ``None`` omite
            o elemento (para caracterizar o comportamento do simulador
            nos dois cenários -- ver testes 12/13).

    Returns:
        O JWT compacto (``header.payload.assinatura``), em Base64URL
        sem padding em cada parte (RFC 7515 Sec2).
    """
    now = int(time.time())
    header: dict[str, object] = {"alg": _JWT_ALG, "typ": _JWT_TYPE}
    if kid is not None:
        header["kid"] = kid

    payload: dict[str, object] = {
        "iss": client_id,
        "sub": client_id,
        "aud": token_endpoint,
        "iat": now,
        "exp": now + _ASSERTION_TTL_SECONDS,
        "jti": str(uuid.uuid4()),
    }

    signing_input = f"{_b64url_json(header)}.{_b64url_json(payload)}"
    signature = private_key.sign(signing_input.encode("ascii"), padding.PKCS1v15(), hashes.SHA384())
    return f"{signing_input}.{_b64url_bytes(signature)}"


def request_token_directo(
    *,
    token_endpoint: str,
    assertion: str,
    ssl_context: ssl.SSLContext,
    scope: str = "system/Patient.rs",
    timeout: float = 30.0,
) -> httpx.Response:
    """Envia o ``client_assertion`` diretamente ao token endpoint do
    simulador (``POST application/x-www-form-urlencoded``), com mTLS.

    Contorna a classe ``SmartTokenClient`` de propósito, para inspecionar
    o protocolo bruto (JWT/JWKS) em vez de apenas o comportamento do
    cliente.

    Args:
        token_endpoint: URL do token endpoint do simulador.
        assertion: ``client_assertion`` já montado (ver
            :func:`build_client_assertion`).
        ssl_context: contexto TLS/mTLS já configurado com o certificado
            do simulador como trust anchor e o certificado/chave do
            cliente de teste (ex.: via
            ``hubsaude_client.ssl_context_factory.build_ssl_context``).
        scope: scope solicitado.
        timeout: timeout de conexão/leitura, em segundos.

    Returns:
        A resposta HTTP crua do token endpoint.
    """
    data = {
        "grant_type": "client_credentials",
        "client_assertion_type": _CLIENT_ASSERTION_TYPE,
        "client_assertion": assertion,
        "scope": scope,
    }
    with httpx.Client(verify=ssl_context, timeout=timeout) as client:
        return client.post(token_endpoint, data=data)


def extract_kid_from_jwt_header(jwt: str) -> str | None:
    """Decodifica o header JOSE (primeiro segmento) de um JWT compacto e
    retorna o valor de ``kid``, ou ``None`` se ausente.
    """
    header_segment = jwt.split(".", 1)[0]
    header = json.loads(_b64url_decode(header_segment))
    kid = header.get("kid")
    return kid if isinstance(kid, str) else None


def extract_kid_from_jwks(certs_endpoint: str, ssl_context: ssl.SSLContext, timeout: float = 30.0) -> str | None:
    """Obtém o ``kid`` da primeira chave publicada no JWKS do simulador
    (``GET /certs``). Inspeciona apenas a primeira chave publicada, não
    itera todas.

    Raises:
        RuntimeError: se o JWKS não estiver disponível (status != 200)
            ou não contiver nenhuma chave.
    """
    with httpx.Client(verify=ssl_context, timeout=timeout) as client:
        response = client.get(certs_endpoint)
    if response.status_code != 200:
        raise RuntimeError(f"JWKS deveria estar disponivel em {certs_endpoint}: HTTP {response.status_code}")

    keys = response.json().get("keys")
    if not keys:
        raise RuntimeError(f"JWKS em {certs_endpoint} deveria conter ao menos uma chave")

    kid = keys[0].get("kid")
    return kid if isinstance(kid, str) else None


def _b64url_json(value: dict[str, object]) -> str:
    return _b64url_bytes(json.dumps(value, separators=(",", ":")).encode("utf-8"))


def _b64url_bytes(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(segment: str) -> bytes:
    padding_needed = -len(segment) % 4
    return base64.urlsafe_b64decode(segment + ("=" * padding_needed))

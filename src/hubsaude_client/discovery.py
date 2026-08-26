"""Descoberta do token endpoint via ``.well-known/smart-configuration``
(SMART App Launch — Backend Services, RF-09).

Porte de ``SmartConfigurationDiscovery.java`` (colaborador interno de
``SmartTokenClient``): resolve o ``token_endpoint`` a partir de uma URL
base FHIR, para os consumidores que preferem informar ``fhir_base`` em
vez de um ``token_endpoint`` explicito. A exclusividade mutua entre
``token_endpoint``/``fhir_base`` e a decisao de *quando* chamar esta
classe (uma unica vez, na construcao do cliente — RF-09 item 5) sao
responsabilidade do builder/orquestrador (``builder.py``/``client.py``),
nao deste modulo: aqui so existe a mecanica de uma resolucao isolada.
Nao faz parte da API publica da biblioteca (nao exportado em
``__init__.py``).

O ``httpx.Client`` e recebido por injecao, nunca criado internamente —
garante que a descoberta reutiliza a mesma configuracao de TLS/mTLS e os
mesmos timeouts do cliente principal (RF-09 item 3), sem duplicar essa
configuracao aqui. Cada chamada gera seu proprio :class:`TraceContext`
e envia o header ``traceparent`` (mesmo contrato de correlacao usado
pelo restante da lib — ver ``trace.py``); corpos de resposta de erro
sao sanitizados com :func:`hubsaude_client.error_classifier.sanitize_error_response`
antes de compor a mensagem de excecao, para nao vazar eventuais tokens
presentes num corpo de erro inesperado.
"""

from __future__ import annotations

from typing import Any, Final

import httpx

from hubsaude_client._log import get_logger
from hubsaude_client.error_classifier import sanitize_error_response
from hubsaude_client.exceptions import SmartTokenError
from hubsaude_client.trace import TraceContext

#: Caminho fixo do documento de descoberta (SMART App Launch — Backend
#: Services). Sempre relativo a raiz da URL base FHIR informada.
_SMART_CONFIGURATION_PATH: Final[str] = "/.well-known/smart-configuration"

#: Campo do documento de descoberta que contem o token endpoint.
_TOKEN_ENDPOINT_FIELD: Final[str] = "token_endpoint"

#: Logger compartilhado com o restante da lib (ver _log.py): este
#: colaborador e' detalhe interno de implementacao e o contrato de
#: observabilidade (filtros de log por nome da classe publica) deve
#: permanecer estavel independente de como a implementacao interna e'
#: dividida em modulos.
_LOG = get_logger()


class SmartConfigurationDiscovery:
    """Resolve o ``token_endpoint`` a partir de uma URL base FHIR,
    consultando ``GET <fhir_base>/.well-known/smart-configuration``.

    Colaborador interno de ``SmartTokenClient``/``SmartTokenClientBuilder``;
    nao faz parte da API publica da biblioteca. Nao mantem estado entre
    chamadas: cada :meth:`discover_token_endpoint` e uma resolucao
    independente, com seu proprio ``TraceContext``.
    """

    __slots__ = ("_http_client",)

    def __init__(self, http_client: httpx.Client) -> None:
        """Cria a descoberta sobre um ``httpx.Client`` ja configurado.

        Args:
            http_client: cliente HTTP injetado pelo chamador, ja
                configurado com o ``ssl_context`` (TLS/mTLS) e os
                timeouts que o cliente principal usara — esta classe
                nao cria nem configura seu proprio ``httpx.Client``.
        """
        self._http_client = http_client

    def discover_token_endpoint(self, fhir_base: str) -> str:
        """Descobre o ``token_endpoint`` para a URL base FHIR informada.

        Args:
            fhir_base: URL base do servidor FHIR (sem o sufixo
                ``/.well-known/smart-configuration``, que e adicionado
                por este metodo). Barra final e tolerada.

        Returns:
            O ``token_endpoint`` resolvido.

        Raises:
            SmartTokenError: se a requisicao falhar por erro de rede,
                se a resposta nao tiver status ``200``, se o corpo nao
                for JSON valido, ou se o campo ``token_endpoint``
                estiver ausente, vazio ou nao for uma string.
        """
        well_known_url = _build_well_known_url(fhir_base)
        trace = TraceContext.generate()
        _LOG.debug(
            "Iniciando descoberta SMART em %s traceId=%s",
            well_known_url,
            trace.trace_id,
        )

        response = self._fetch(well_known_url, trace)

        if response.status_code != 200:
            _LOG.error(
                "Falha na descoberta SMART: HTTP %s em %s traceId=%s",
                response.status_code,
                well_known_url,
                trace.trace_id,
            )
            raise SmartTokenError(
                f"Falha na descoberta de configuracao SMART: HTTP {response.status_code}"
                f" em {well_known_url} (traceId={trace.trace_id})"
                f" — {sanitize_error_response(response.text)}"
            )

        payload = self._parse_json(response, well_known_url, trace)
        token_endpoint = _extract_token_endpoint(payload)
        if token_endpoint is None:
            _LOG.error(
                "Descoberta SMART sem token_endpoint em %s traceId=%s",
                well_known_url,
                trace.trace_id,
            )
            raise SmartTokenError(
                f"Documento de descoberta SMART em {well_known_url} nao contem"
                f" '{_TOKEN_ENDPOINT_FIELD}' valido (traceId={trace.trace_id})"
            )

        _LOG.debug(
            "Descoberta SMART concluida: token_endpoint=%s traceId=%s",
            token_endpoint,
            trace.trace_id,
        )
        return token_endpoint

    def _fetch(self, well_known_url: str, trace: TraceContext) -> httpx.Response:
        """Executa a requisicao GET, convertendo falha de transporte em
        ``SmartTokenError``.

        Nota de escopo: ao contrario do fluxo de obtencao de token
        (``client.py``), a descoberta nao classifica a falha como
        retriavel/nao-retriavel nem tenta novamente — RF-09 trata a
        descoberta como uma resolucao unica na construcao do cliente;
        decidir se vale reconstruir o cliente apos uma falha aqui e do
        chamador.

        Args:
            well_known_url: URL completa do documento de descoberta.
            trace: contexto de trace gerado para esta chamada.

        Returns:
            Resposta HTTP recebida.

        Raises:
            SmartTokenError: se a requisicao falhar por erro de rede.
        """
        try:
            return self._http_client.get(
                well_known_url,
                headers={TraceContext.TRACEPARENT_HEADER: trace.traceparent()},
            )
        except httpx.RequestError as exc:
            _LOG.error(
                "Falha de rede na descoberta SMART em %s traceId=%s: %s",
                well_known_url,
                trace.trace_id,
                exc,
            )
            raise SmartTokenError(
                f"Falha de rede ao descobrir configuracao SMART em {well_known_url}" f" (traceId={trace.trace_id})",
                exc,
            ) from exc

    def _parse_json(self, response: httpx.Response, well_known_url: str, trace: TraceContext) -> Any:
        """Decodifica o corpo da resposta como JSON, convertendo falha
        de parsing em ``SmartTokenError``.

        Args:
            response: resposta HTTP com status ``200``.
            well_known_url: URL completa do documento de descoberta
                (para a mensagem de erro).
            trace: contexto de trace desta chamada (para a mensagem de
                erro).

        Returns:
            Corpo decodificado (tipo dependente do JSON recebido).

        Raises:
            SmartTokenError: se o corpo nao for JSON valido.
        """
        try:
            return response.json()
        except ValueError as exc:
            _LOG.error(
                "Resposta de descoberta SMART nao e JSON valido em %s traceId=%s",
                well_known_url,
                trace.trace_id,
            )
            raise SmartTokenError(
                f"Resposta de descoberta SMART em {well_known_url} nao e JSON valido" f" (traceId={trace.trace_id})",
                exc,
            ) from exc


def _build_well_known_url(fhir_base: str) -> str:
    """Monta a URL do documento de descoberta a partir da URL base FHIR.

    Args:
        fhir_base: URL base do servidor FHIR, com ou sem barra final.

    Returns:
        ``<fhir_base sem barra final><_SMART_CONFIGURATION_PATH>``.
    """
    return fhir_base.rstrip("/") + _SMART_CONFIGURATION_PATH


def _extract_token_endpoint(payload: Any) -> str | None:
    """Extrai o campo ``token_endpoint`` de um documento de descoberta
    ja decodificado.

    Args:
        payload: corpo JSON decodificado da resposta (tipo arbitrario —
            um documento de descoberta malformado pode nao ser sequer
            um objeto).

    Returns:
        O valor de ``token_endpoint`` quando presente, nao vazio e do
        tipo ``str``; ``None`` caso contrario.
    """
    if not isinstance(payload, dict):
        return None
    token_endpoint = payload.get(_TOKEN_ENDPOINT_FIELD)
    if not isinstance(token_endpoint, str) or not token_endpoint.strip():
        return None
    return token_endpoint

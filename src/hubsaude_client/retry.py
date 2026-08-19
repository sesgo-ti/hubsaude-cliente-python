"""Calculo do delay de backoff exponencial entre tentativas de retry.

Regras aplicadas pelo cliente HTTP da biblioteca:

- apenas falhas transitorias de rede/transporte sao retriaveis — timeout
  de conexao, timeout de requisicao HTTP e recusa/queda de conexao TCP;
- respostas HTTP efetivamente recebidas (qualquer status, inclusive
  ``429`` e ``5xx``) **nunca** sofrem retry automatico: resultam em erro
  imediato para o chamador, e decidir se/quando reenviar e
  responsabilidade da camada de orquestracao do consumidor — fora do
  escopo desta funcao e desta lib;
- o delay antes da tentativa ``n+1`` e ``1s x 2^(n-1)`` (1s, 2s, 4s,
  8s...), sem *jitter* e sem *cap* (backoff exponencial puro).

Nota de escopo desta funcao: ``compute_retry_delay_seconds`` so calcula
o delay a partir do numero da tentativa que falhou. Ela nao decide *se*
deve haver retry — isso e responsabilidade de ``client.py``, que so a
invoca depois de classificar a falha como transitoria (via
``ErrorClassifier``) — nem valida ``max_retries``.

Nota: a normalizacao de ``max_retries <= 0`` para o default nao vive
aqui, e sim em ``fault_tolerance.py`` (``FaultToleranceConfig``), que e
quem recebe e normaliza esse parametro; esta funcao apenas calcula o
delay a partir da tentativa e nem recebe ``max_retries``.
"""

from __future__ import annotations

#: Delay base do backoff exponencial, em segundos (equivale a 1000 ms).
#: Expresso diretamente em segundos porque o consumidor natural em
#: Python e ``time.sleep(float)``, que recebe segundos.
_RETRY_BASE_DELAY_SECONDS: float = 1.0


def compute_retry_delay_seconds(attempt: int) -> float:
    """Calcula o delay de backoff exponencial antes da proxima tentativa.

    Formula: ``1s x 2^(attempt - 1)`` — 1s, 2s, 4s, 8s, 16s... Sem
    *jitter* e sem *cap* superior. O retorno e ``float`` em segundos,
    unidade idiomatica para ``time.sleep`` em Python.

    Args:
        attempt: numero da tentativa que acabou de falhar (1-based, ou
            seja, a *primeira* tentativa e ``1``). Deve ser >= 1.

    Returns:
        Delay em segundos a aguardar antes da proxima tentativa.

    Raises:
        ValueError: se ``attempt`` for menor que 1. Um ``attempt`` nao
            positivo produziria um deslocamento de bits
            (``1 << (attempt - 1)``) com resultado indefinido para o
            dominio do problema; validar aqui falha rapido em vez de
            propagar um delay sem sentido.
    """
    if attempt < 1:
        raise ValueError(f"attempt deve ser >= 1 (1-based, tentativa que falhou), recebido: {attempt}")
    return _RETRY_BASE_DELAY_SECONDS * (2.0 ** (attempt - 1))

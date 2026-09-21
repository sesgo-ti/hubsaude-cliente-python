"""Cálculo do delay de backoff exponencial entre tentativas de retry.

Regras aplicadas pelo cliente HTTP da biblioteca:

- apenas falhas transitórias de rede/transporte são retriáveis — timeout
  de conexão, timeout de requisição HTTP e recusa/queda de conexão TCP;
- respostas HTTP efetivamente recebidas (qualquer status, inclusive
  ``429`` e ``5xx``) **nunca** sofrem retry automático: resultam em erro
  imediato para o chamador, e decidir se/quando reenviar é
  responsabilidade da camada de orquestração do consumidor — fora do
  escopo desta função e desta lib;
- o delay antes da tentativa ``n+1`` é ``1s x 2^(n-1)`` (1s, 2s, 4s,
  8s...), sem *jitter* e sem *cap* (backoff exponencial puro).

Nota de escopo desta função: ``compute_retry_delay_seconds`` só calcula
o delay a partir do número da tentativa que falhou. Ela não decide *se*
deve haver retry — isso é responsabilidade de ``client.py``, que só a
invoca depois de classificar a falha como transitória (via
``ErrorClassifier``) — nem valida ``max_retries``.

Nota: a normalização de ``max_retries <= 0`` para o default não vive
aqui, e sim em ``fault_tolerance.py`` (``FaultToleranceConfig``), que é
quem recebe e normaliza esse parâmetro; esta função apenas calcula o
delay a partir da tentativa e nem recebe ``max_retries``.
"""

from __future__ import annotations

#: Delay base do backoff exponencial, em segundos (equivale a 1000 ms).
#: Expresso diretamente em segundos porque o consumidor natural em
#: Python é ``time.sleep(float)``, que recebe segundos.
_RETRY_BASE_DELAY_SECONDS: float = 1.0


def compute_retry_delay_seconds(attempt: int) -> float:
    """Calcula o delay de backoff exponencial antes da próxima tentativa.

    Fórmula: ``1s x 2^(attempt - 1)`` — 1s, 2s, 4s, 8s, 16s... Sem
    *jitter* e sem *cap* superior. O retorno é ``float`` em segundos,
    unidade idiomática para ``time.sleep`` em Python.

    Args:
        attempt: número da tentativa que acabou de falhar (1-based, ou
            seja, a *primeira* tentativa é ``1``). Deve ser >= 1.

    Returns:
        Delay em segundos a aguardar antes da próxima tentativa.

    Raises:
        ValueError: se ``attempt`` for menor que 1. Um ``attempt`` não
            positivo produziria um expoente negativo em
            ``2.0 ** (attempt - 1)``, resultando num delay fracionário
            sem sentido para o domínio do problema (backoff que diminui
            em vez de crescer); validar aqui falha rápido em vez de
            propagar um delay sem sentido.
    """
    if attempt < 1:
        raise ValueError(f"attempt deve ser >= 1 (1-based, tentativa que falhou), recebido: {attempt}")
    return _RETRY_BASE_DELAY_SECONDS * (2.0 ** (attempt - 1))

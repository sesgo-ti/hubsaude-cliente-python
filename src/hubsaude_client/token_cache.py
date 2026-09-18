"""Cache thread-safe de tokens por scope, com margem de expiração e janela LRU.

Colaborador interno (não faz parte da API pública da biblioteca) que
concentra a política de cache: validade com margem de renovação,
invalidação e uma janela LRU de tamanho fixo. Como em ``defaults.py`` /
``fault_tolerance.py``, os scopes recebidos por esta classe devem estar
**normalizados** (``strip()``; ``None`` -> string vazia) -- responsabilidade
do chamador (``client.py``).

Nota de escopo: o *lock striping* (locks fixos selecionados por
``hash(scope) % N``) usado para garantir *single-flight* de renovação --
no máximo uma requisição HTTP em voo por scope -- fica fora deste módulo
e e responsabilidade de ``client.py`` (``SmartTokenClient``): e la que a decisão de
"fazer ou não a chamada de rede" de fato acontece, e mantê-la fora deste
módulo preserva ``token_cache.py`` como um colaborador puro de cache
(cache-aside), sem qualquer conhecimento de rede/HTTP ou de política de
retry. O single-flight será garantido de ponta a ponta pela combinação
dos dois colaboradores: o lock por scope em ``client.py`` serializa as
renovações, e o cache-aside aqui evita que uma thread que esperou o lock
refaça uma chamada de rede ja resolvida por outra (double-checked
locking). O único lock definido *neste* módulo (``threading.Lock``,
abaixo) e um mecanismo diferente: protege apenas a estrutura de dados
interna do cache contra corrupção em acesso concorrente -- não decide
quem faz a requisição HTTP.
"""

from __future__ import annotations

import threading
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from hubsaude_client.defaults import (
    DEFAULT_TOKEN_CACHE_MARGIN_SECONDS,
    DEFAULT_TOKEN_CACHE_MAX_ENTRIES,
)

#: Fonte de tempo padrão (relógio UTC do sistema).
_DEFAULT_CLOCK: Callable[[], datetime] = lambda: datetime.now(timezone.utc)  # noqa: E731


@dataclass(frozen=True)
class CachedToken:
    """Token de acesso em cache, com o instante de expiração original.

    Attributes:
        access_token: token de acesso cacheado.
        expires_at: instante (timezone-aware, UTC) de expiração do token,
            sem a margem de renovação aplicada.
    """

    access_token: str
    expires_at: datetime

    def is_valid(self, margin_seconds: int, now: datetime) -> bool:
        """Verifica se o token ainda e válido considerando a margem.

        Args:
            margin_seconds: segundos de margem antes da expiração; uma
                entrada que expira dentro dessa margem e tratada como
                inválida, forçando renovação antecipada.
            now: instante corrente (timezone-aware).

        Returns:
            ``True`` se ``now + margin_seconds`` ainda for anterior a
            ``expires_at``.
        """
        return now + timedelta(seconds=margin_seconds) < self.expires_at

    def __repr__(self) -> str:
        """Representação textual com o token mascarado.

        Evita exposição acidental do access token em logs/repr.
        """
        return f"CachedToken(access_token=[REDACTED], expires_at={self.expires_at!r})"


@dataclass(frozen=True)
class CachedTokenResponse:
    """Resposta servida a partir do cache, pronta para o chamador.

    Reconstrói a resposta a partir da entrada em cache, com ``expires_in``
    recalculado como o tempo *restante* no momento da leitura (não o valor
    original armazenado em ``store``).

    Attributes:
        access_token: token de acesso.
        expires_in: segundos restantes de validade a partir de agora,
            nunca negativo.
    """

    access_token: str
    expires_in: int


class TokenCacheStrategy:
    """Cache de tokens por scope, com margem de expiração e janela LRU.

    Restrito a política de cache (ver nota de escopo no docstring do
    módulo).

    Estrutura interna: um único ``collections.OrderedDict`` (chave =
    scope) protegido por um único ``threading.Lock`` de instância. A ordem
    do ``OrderedDict`` *e* a política LRU -- um hit válido chama
    ``move_to_end(scope)``, e a eviction por limite de entradas chama
    ``popitem(last=False)`` para descartar o item usado há mais tempo.
    Esse lock cobre **todo** acesso de leitura e escrita ao dict (get, put,
    invalidate, invalidate_all e a checagem de tamanho para eviction) --
    cada método público adquire o lock no início do bloco crítico e libera
    ao sair (``with self._lock:``). E um lock diferente e independente do
    lock por-scope de single-flight de ``client.py`` (ver docstring do
    módulo).

    Instâncias são thread-safe para chamadas concorrentes aos seus
    métodos públicos.
    """

    def __init__(
        self,
        enabled: bool,
        margin_seconds: int = DEFAULT_TOKEN_CACHE_MARGIN_SECONDS,
        max_entries: int = DEFAULT_TOKEN_CACHE_MAX_ENTRIES,
        clock: Callable[[], datetime] = _DEFAULT_CLOCK,
    ) -> None:
        """Cria a estratégia de cache.

        Args:
            enabled: se ``True``, tokens são cacheados por scope; se
                ``False``, ``cached_if_valid`` sempre retorna ``None`` e
                ``store`` e no-op (cache totalmente desligado).
            margin_seconds: margem em segundos para considerar o token
                próximo da expiração e forçar renovação antecipada.
                Normalização de valores inválidos e responsabilidade do
                chamador (``fault_tolerance.py``/``client.py``).
            max_entries: quantidade máxima de scopes retidos
                simultaneamente no cache (janela LRU). Deve ser positivo.
            clock: fonte de tempo, substituível para testes
                determinísticos. Deve retornar ``datetime`` timezone-aware
                (o padrão usa UTC).

        Raises:
            ValueError: se ``max_entries`` não for positivo.
        """
        if max_entries <= 0:
            raise ValueError(f"max_entries deve ser positivo, recebido: {max_entries}")
        self._enabled = enabled
        self._margin_seconds = margin_seconds
        self._max_entries = max_entries
        self._clock = clock
        self._lock = threading.Lock()
        self._entries: OrderedDict[str, CachedToken] = OrderedDict()

    def cached_if_valid(self, normalized_scope: str) -> CachedTokenResponse | None:
        """Retorna o token em cache para o scope, se habilitado e válido.

        Quando a entrada existe mas já está inválida (expirada ou dentro da margem
        de renovação), ela e removida do cache nesta mesma chamada
        (eviction antecipada), evitando reter entradas mortas.

        Args:
            normalized_scope: scope ja normalizado pelo chamador (``strip()``;
                ``""`` para "sem scope").

        Returns:
            A resposta reconstruída a partir do cache, ou ``None`` quando o
            cache está desabilitado, não há entrada para o scope, ou a
            entrada existente não é mais válida.
        """
        if not self._enabled:
            return None
        with self._lock:
            cached = self._entries.get(normalized_scope)
            if cached is None:
                return None
            now = self._clock()
            if cached.is_valid(self._margin_seconds, now):
                self._entries.move_to_end(normalized_scope)
                remaining = int((cached.expires_at - now).total_seconds())
                return CachedTokenResponse(cached.access_token, max(0, remaining))
            del self._entries[normalized_scope]
            return None

    def store(self, normalized_scope: str, access_token: str, expires_in: int) -> None:
        """Armazena o token no cache quando habilitado; caso contrário, no-op.

        Se, após a inserção, o número de entradas exceder ``max_entries``, a entrada usada há mais
        tempo (menos recentemente acessada) e descartada (eviction LRU).

        Args:
            normalized_scope: scope ja normalizado pelo chamador.
            access_token: token de acesso recém-obtido do token endpoint.
            expires_in: validade do token em segundos, a partir de agora.
        """
        if not self._enabled:
            return
        now = self._clock()
        expires_at = now + timedelta(seconds=expires_in)
        with self._lock:
            self._entries[normalized_scope] = CachedToken(access_token, expires_at)
            self._entries.move_to_end(normalized_scope)
            if len(self._entries) > self._max_entries:
                self._entries.popitem(last=False)

    def invalidate(self, normalized_scope: str) -> None:
        """Invalida o cache para um scope específico (no-op se ausente).

        Args:
            normalized_scope: scope ja normalizado cujo token deve ser
                invalidado.
        """
        with self._lock:
            self._entries.pop(normalized_scope, None)

    def invalidate_all(self) -> None:
        """Invalida o cache de tokens de todos os scopes."""
        with self._lock:
            self._entries.clear()

    def size(self) -> int:
        """Retorna a quantidade de entradas retidas no momento.

        Exposto sobretudo para testes do teto da janela LRU.

        Returns:
            Tamanho atual do cache.
        """
        with self._lock:
            return len(self._entries)

    def __len__(self) -> int:
        """Permite ``len(cache)`` como sinônimo de :meth:`size`."""
        return self.size()

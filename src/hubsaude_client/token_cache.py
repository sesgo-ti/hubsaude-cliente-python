"""Cache thread-safe de tokens por scope, com margem de expiracao e janela LRU.

Portado de ``TokenCacheStrategy.java``.

Colaborador interno (nao faz parte da API publica da biblioteca) que
concentra a politica de cache: validade com margem de renovacao,
invalidacao e uma janela LRU de tamanho fixo. Como em ``defaults.py`` /
``fault_tolerance.py``, os scopes recebidos por esta classe devem estar
**normalizados** (``strip()``; ``None`` -> string vazia) -- responsabilidade
do chamador (``client.py``).

Nota de escopo (roadmap de port, tarefa B7): no ``.java`` de origem,
``TokenCacheStrategy`` tambem concentra o *lock striping* (32
``ReentrantLock`` fixos, selecionados por ``hash(scope) % 32``) usado para
garantir *single-flight* de renovacao -- no maximo uma requisicao HTTP em
voo por scope. Neste port, esse striping foi deliberadamente movido para
``client.py`` (``SmartTokenClient``, tarefa B8): e la que a decisao de
"fazer ou nao a chamada de rede" de fato acontece, e mante-la fora deste
modulo preserva ``token_cache.py`` como um colaborador puro de cache
(cache-aside), sem qualquer conhecimento de rede/HTTP ou de politica de
retry. O single-flight continua garantido de ponta a ponta pela combinacao
dos dois colaboradores: o lock por scope em ``client.py`` serializa as
renovacoes, e o cache-aside aqui evita que uma thread que esperou o lock
refaca uma chamada de rede ja resolvida por outra (double-checked
locking). O unico lock definido *neste* modulo (``threading.Lock``,
abaixo) e um mecanismo diferente: protege apenas a estrutura de dados
interna do cache contra corrupcao em acesso concorrente -- nao decide
quem faz a requisicao HTTP.
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

#: Fonte de tempo padrao (equivalente a Clock.systemUTC() do Java).
_DEFAULT_CLOCK: Callable[[], datetime] = lambda: datetime.now(timezone.utc)  # noqa: E731


@dataclass(frozen=True)
class CachedToken:
    """Token de acesso em cache, com o instante de expiracao original.

    Equivalente Python do record aninhado ``TokenCacheStrategy.CachedToken``
    (Java).

    Attributes:
        access_token: token de acesso cacheado.
        expires_at: instante (timezone-aware, UTC) de expiracao do token,
            sem a margem de renovacao aplicada.
    """

    access_token: str
    expires_at: datetime

    def is_valid(self, margin_seconds: int, now: datetime) -> bool:
        """Verifica se o token ainda e valido considerando a margem.

        Equivalente Python de ``CachedToken.isValid(int, Instant)`` (Java).

        Args:
            margin_seconds: segundos de margem antes da expiracao; uma
                entrada que expira dentro dessa margem e tratada como
                invalida, forcando renovacao antecipada.
            now: instante corrente (timezone-aware).

        Returns:
            ``True`` se ``now + margin_seconds`` ainda for anterior a
            ``expires_at``.
        """
        return now + timedelta(seconds=margin_seconds) < self.expires_at

    def __repr__(self) -> str:
        """Representacao textual com o token mascarado.

        Evita exposicao acidental do access token em logs/repr, equivalente
        ao ``toString()`` sobrescrito de ``CachedToken`` (Java).
        """
        return f"CachedToken(access_token=[REDACTED], expires_at={self.expires_at!r})"


@dataclass(frozen=True)
class CachedTokenResponse:
    """Resposta servida a partir do cache, pronta para o chamador.

    Equivalente Python ao valor retornado por
    ``TokenCacheStrategy.cachedResponseIfValid`` (Java): reconstroi a
    resposta a partir da entrada em cache, com ``expires_in`` recalculado
    como o tempo *restante* no momento da leitura (nao o valor original
    armazenado em ``store``).

    Attributes:
        access_token: token de acesso.
        expires_in: segundos restantes de validade a partir de agora,
            nunca negativo.
    """

    access_token: str
    expires_in: int


class TokenCacheStrategy:
    """Cache de tokens por scope, com margem de expiracao e janela LRU.

    Equivalente Python de ``TokenCacheStrategy`` (Java), restrito a
    politica de cache (ver nota de escopo no docstring do modulo).

    Estrutura interna: um unico ``collections.OrderedDict`` (chave =
    scope) protegido por um unico ``threading.Lock`` de instancia. A ordem
    do ``OrderedDict`` *e* a politica LRU -- um hit valido chama
    ``move_to_end(scope)``, e a eviction por limite de entradas chama
    ``popitem(last=False)`` para descartar o item usado ha mais tempo.
    Esse lock cobre **todo** acesso de leitura e escrita ao dict (get, put,
    invalidate, invalidate_all e a checagem de tamanho para eviction) --
    cada metodo publico adquire o lock no inicio do bloco critico e libera
    ao sair (``with self._lock:``). E um lock diferente e independente do
    lock por-scope de single-flight de ``client.py`` (ver docstring do
    modulo).

    Instancias sao thread-safe para chamadas concorrentes aos seus
    metodos publicos.
    """

    def __init__(
        self,
        enabled: bool,
        margin_seconds: int = DEFAULT_TOKEN_CACHE_MARGIN_SECONDS,
        max_entries: int = DEFAULT_TOKEN_CACHE_MAX_ENTRIES,
        clock: Callable[[], datetime] = _DEFAULT_CLOCK,
    ) -> None:
        """Cria a estrategia de cache.

        Args:
            enabled: se ``True``, tokens sao cacheados por scope; se
                ``False``, ``cached_if_valid`` sempre retorna ``None`` e
                ``store`` e no-op (cache totalmente desligado).
            margin_seconds: margem em segundos para considerar o token
                proximo da expiracao e forcar renovacao antecipada.
                Normalizacao de valores invalidos e responsabilidade do
                chamador (``fault_tolerance.py``/``client.py``), assim
                como no ``.java`` de origem.
            max_entries: quantidade maxima de scopes retidos
                simultaneamente no cache (janela LRU). Deve ser positivo.
            clock: fonte de tempo, substituivel para testes
                deterministicos. Deve retornar ``datetime`` timezone-aware
                (o padrao usa UTC).

        Raises:
            ValueError: se ``max_entries`` nao for positivo.
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
        """Retorna o token em cache para o scope, se habilitado e valido.

        Equivalente Python de ``cachedResponseIfValid`` (Java). Quando a
        entrada existe mas ja esta invalida (expirada ou dentro da margem
        de renovacao), ela e removida do cache nesta mesma chamada
        (eviction antecipada), evitando reter entradas mortas.

        Args:
            normalized_scope: scope ja normalizado pelo chamador (``strip()``;
                ``""`` para "sem scope").

        Returns:
            A resposta reconstruida a partir do cache, ou ``None`` quando o
            cache esta desabilitado, nao ha entrada para o scope, ou a
            entrada existente nao e mais valida.
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
        """Armazena o token no cache quando habilitado; caso contrario, no-op.

        Equivalente Python de ``store`` (Java). Se, apos a insercao, o
        numero de entradas exceder ``max_entries``, a entrada usada ha mais
        tempo (menos recentemente acessada) e descartada (eviction LRU).

        Args:
            normalized_scope: scope ja normalizado pelo chamador.
            access_token: token de acesso recem-obtido do token endpoint.
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
        """Invalida o cache para um scope especifico (no-op se ausente).

        Equivalente Python de ``invalidate`` (Java).

        Args:
            normalized_scope: scope ja normalizado cujo token deve ser
                invalidado.
        """
        with self._lock:
            self._entries.pop(normalized_scope, None)

    def invalidate_all(self) -> None:
        """Invalida o cache de tokens de todos os scopes.

        Equivalente Python de ``invalidateAll`` (Java).
        """
        with self._lock:
            self._entries.clear()

    def size(self) -> int:
        """Retorna a quantidade de entradas retidas no momento.

        Equivalente Python de ``size`` (Java); exposto sobretudo para
        testes do teto da janela LRU.

        Returns:
            Tamanho atual do cache.
        """
        with self._lock:
            return len(self._entries)

    def __len__(self) -> int:
        """Permite ``len(cache)`` como sinonimo de :meth:`size`."""
        return self.size()

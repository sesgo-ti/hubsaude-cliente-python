from __future__ import annotations

import threading
from datetime import datetime, timedelta, timezone

import pytest

from hubsaude_client.token_cache import CachedToken, CachedTokenResponse, TokenCacheStrategy

_SCOPE = "system/Patient.rs"
_MARGIN_SECONDS = 30


def _fixed_clock(instant: datetime):
    return lambda: instant


class TestCacheHabilitado:
    def _cache(self, **kwargs: object) -> TokenCacheStrategy:
        return TokenCacheStrategy(enabled=True, margin_seconds=_MARGIN_SECONDS, **kwargs)  # type: ignore[arg-type]

    def test_retorna_none_sem_entrada(self) -> None:
        cache = self._cache()
        assert cache.cached_if_valid(_SCOPE) is None

    def test_serve_token_armazenado(self) -> None:
        cache = self._cache()
        cache.store(_SCOPE, "tok-1", 3600)

        cached = cache.cached_if_valid(_SCOPE)

        assert cached is not None
        assert isinstance(cached, CachedTokenResponse)
        assert cached.access_token == "tok-1"
        assert 3500 <= cached.expires_in <= 3600

    def test_nao_serve_token_dentro_da_margem(self) -> None:
        # Expira em 10s < margem de 30s: deve forcar renovacao.
        cache = self._cache()
        cache.store(_SCOPE, "tok-quase-expirado", 10)

        assert cache.cached_if_valid(_SCOPE) is None

    def test_invalidate_remove_somente_o_scope_informado(self) -> None:
        cache = self._cache()
        cache.store(_SCOPE, "tok-1", 3600)
        cache.store("outro/scope", "tok-2", 3600)

        cache.invalidate(_SCOPE)

        assert cache.cached_if_valid(_SCOPE) is None
        assert cache.cached_if_valid("outro/scope") is not None

    def test_invalidate_all_remove_tudo(self) -> None:
        cache = self._cache()
        cache.store(_SCOPE, "tok-1", 3600)
        cache.store("outro/scope", "tok-2", 3600)

        cache.invalidate_all()

        assert cache.cached_if_valid(_SCOPE) is None
        assert cache.cached_if_valid("outro/scope") is None

    def test_remove_entrada_expirada_ao_ler(self) -> None:
        now = datetime(2026, 8, 1, 12, 0, 0, tzinfo=timezone.utc)
        expiring = TokenCacheStrategy(
            enabled=True,
            margin_seconds=_MARGIN_SECONDS,
            max_entries=2,
            clock=_fixed_clock(now),
        )
        expiring.store(_SCOPE, "tok-expirado", 10)

        assert expiring.cached_if_valid(_SCOPE) is None
        assert expiring.size() == 0

    def test_limita_cache_por_lru(self) -> None:
        bounded = self._cache(max_entries=2)
        bounded.store("scope-1", "tok-1", 3600)
        bounded.store("scope-2", "tok-2", 3600)
        bounded.cached_if_valid("scope-1")  # marca scope-1 como recentemente usado

        bounded.store("scope-3", "tok-3", 3600)  # deve evictar scope-2 (LRU)

        assert bounded.size() == 2
        assert bounded.cached_if_valid("scope-1") is not None
        assert bounded.cached_if_valid("scope-2") is None
        assert bounded.cached_if_valid("scope-3") is not None

    def test_mantem_teto_sob_operacoes_concorrentes(self) -> None:
        """Teste de concorrencia real (obrigatorio pelo roadmap, tarefa B7):
        N threads chamando get/put/invalidate simultaneamente sobre os
        mesmos scopes, confirmando ausencia de excecao/corrupcao de estado.
        """
        capacity = 32
        num_threads = 8
        ops_per_thread = 100
        bounded = self._cache(max_entries=capacity)
        start = threading.Event()
        errors: list[BaseException] = []
        errors_lock = threading.Lock()
        size_violations: list[int] = []

        def worker(offset: int) -> None:
            start.wait()
            try:
                for i in range(ops_per_thread):
                    scope = f"scope-{offset + i}"
                    bounded.store(scope, "tok", 3600)
                    bounded.cached_if_valid(scope)
                    if i % 10 == 0:
                        bounded.invalidate(scope)
                    if bounded.size() > capacity:
                        size_violations.append(bounded.size())
            except BaseException as exc:  # noqa: BLE001 - captura para assert fora da thread
                with errors_lock:
                    errors.append(exc)

        threads = [threading.Thread(target=worker, args=(thread_idx * 1000,)) for thread_idx in range(num_threads)]
        for t in threads:
            t.start()
        start.set()
        for t in threads:
            t.join(timeout=10)

        assert not errors, f"excecoes inesperadas durante acesso concorrente: {errors}"
        assert not size_violations, "cache excedeu max_entries durante acesso concorrente"
        assert bounded.size() <= capacity

        # Apos a concorrencia, confirma que o teto continua respeitado
        # com operacoes sequenciais adicionais.
        for i in range(capacity):
            bounded.store(f"scope-final-{i}", "tok", 3600)
        assert bounded.size() == capacity

    def test_rejeita_teto_nao_positivo(self) -> None:
        with pytest.raises(ValueError, match="max_entries"):
            TokenCacheStrategy(enabled=True, margin_seconds=_MARGIN_SECONDS, max_entries=0)


class TestCacheDesabilitado:
    def test_store_e_no_op(self) -> None:
        cache = TokenCacheStrategy(enabled=False, margin_seconds=_MARGIN_SECONDS)
        cache.store(_SCOPE, "tok-1", 3600)

        assert cache.cached_if_valid(_SCOPE) is None
        assert cache.size() == 0


class TestCachedToken:
    def test_is_valid_respeita_margem(self) -> None:
        now = datetime(2026, 8, 1, 12, 0, 0, tzinfo=timezone.utc)
        token = CachedToken(access_token="tok", expires_at=now + timedelta(seconds=40))

        assert token.is_valid(margin_seconds=30, now=now) is True
        assert token.is_valid(margin_seconds=41, now=now) is False

    def test_repr_nao_expoe_o_access_token(self) -> None:
        token = CachedToken(
            access_token="super-secreto",
            expires_at=datetime.now(timezone.utc) + timedelta(seconds=60),
        )

        text = repr(token)

        assert "[REDACTED]" in text
        assert "super-secreto" not in text

    def test_is_frozen_dataclass(self) -> None:
        token = CachedToken(access_token="tok", expires_at=datetime.now(timezone.utc))
        with pytest.raises(AttributeError):
            token.access_token = "outro"  # type: ignore[misc]


class TestCachedTokenResponse:
    def test_is_frozen_dataclass(self) -> None:
        response = CachedTokenResponse(access_token="tok", expires_in=100)
        with pytest.raises(AttributeError):
            response.access_token = "outro"  # type: ignore[misc]


def test_len_e_sinonimo_de_size() -> None:
    cache = TokenCacheStrategy(enabled=True, margin_seconds=_MARGIN_SECONDS)
    cache.store(_SCOPE, "tok-1", 3600)

    assert len(cache) == cache.size() == 1

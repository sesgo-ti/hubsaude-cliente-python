"""Testes unitários (sem subir o simulador de verdade, sem precisar de
JDK) para ``tests/hubsaude_simulator_helper.py`` — cobrem a resolução do
caminho do JAR (variável de ambiente vs. fallback de conveniência
``.simulator/hubsaude-simulador.jar``) e a alocação de porta livre.

Os testes que efetivamente sobem o simulador via ``subprocess`` e falam
mTLS real vivem em ``tests/test_smart_token_client_integration.py``
(marcados ``@pytest.mark.integration``, pulados sem JDK/JAR). Este
módulo, em contraste, roda sempre na suíte padrão — a lógica de
resolução de caminho não depende de nenhum pré-requisito externo.
"""

from __future__ import annotations

import socket
from pathlib import Path

import pytest

from . import hubsaude_simulator_helper as helper


@pytest.fixture(autouse=True)
def _isolated_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Garante que nenhum ``HUBSAUDE_SIMULADOR_JAR`` real do ambiente de
    execução vaze para dentro destes testes."""
    monkeypatch.delenv(helper.ENV_VAR_SIMULATOR_JAR, raising=False)


def test_simulator_jar_path_none_without_env_var_or_fallback(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(helper, "_LOCAL_JAR_FALLBACK", tmp_path / "nao-existe.jar")

    assert helper.simulator_jar_path() is None


def test_simulator_jar_path_uses_env_var_when_set(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    jar = tmp_path / "hubsaude-simulador.jar"
    jar.write_bytes(b"")
    monkeypatch.setenv(helper.ENV_VAR_SIMULATOR_JAR, str(jar))

    assert helper.simulator_jar_path() == jar


def test_simulator_jar_path_falls_back_to_local_convenience_path(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fallback = tmp_path / ".simulator" / "hubsaude-simulador.jar"
    fallback.parent.mkdir()
    fallback.write_bytes(b"")
    monkeypatch.setattr(helper, "_LOCAL_JAR_FALLBACK", fallback)

    assert helper.simulator_jar_path() == fallback


def test_simulator_jar_path_env_var_takes_precedence_over_fallback(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    env_jar = tmp_path / "env" / "hubsaude-simulador.jar"
    env_jar.parent.mkdir()
    env_jar.write_bytes(b"")
    fallback_jar = tmp_path / ".simulator" / "hubsaude-simulador.jar"
    fallback_jar.parent.mkdir()
    fallback_jar.write_bytes(b"")
    monkeypatch.setenv(helper.ENV_VAR_SIMULATOR_JAR, str(env_jar))
    monkeypatch.setattr(helper, "_LOCAL_JAR_FALLBACK", fallback_jar)

    assert helper.simulator_jar_path() == env_jar


def test_simulator_jar_path_env_var_pointing_to_missing_file_does_not_fall_back(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Uma env var mal configurada (caminho inexistente, ex.: typo) não
    deve ser mascarada silenciosamente pelo fallback -- fica visível
    como ``None`` (o chamador reporta o erro), mesmo que o caminho de
    conveniência exista."""
    fallback_jar = tmp_path / ".simulator" / "hubsaude-simulador.jar"
    fallback_jar.parent.mkdir()
    fallback_jar.write_bytes(b"")
    monkeypatch.setenv(helper.ENV_VAR_SIMULATOR_JAR, str(tmp_path / "caminho-errado.jar"))
    monkeypatch.setattr(helper, "_LOCAL_JAR_FALLBACK", fallback_jar)

    assert helper.simulator_jar_path() is None


def test_simulator_available_false_without_jar(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(helper, "_LOCAL_JAR_FALLBACK", tmp_path / "nao-existe.jar")

    assert helper.simulator_available() is False


def test_simulator_available_requires_java_even_with_jar_resolved(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    jar = tmp_path / "hubsaude-simulador.jar"
    jar.write_bytes(b"")
    monkeypatch.setenv(helper.ENV_VAR_SIMULATOR_JAR, str(jar))
    monkeypatch.setattr(helper, "java_available", lambda: False)

    assert helper.simulator_available() is False


def test_allocate_free_port_returns_bindable_ephemeral_port() -> None:
    port = helper.allocate_free_port()

    assert 0 < port < 65536
    # A porta deve estar livre logo em seguida -- confirma que o socket
    # de sondagem foi fechado corretamente (context manager em
    # allocate_free_port).
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", port))

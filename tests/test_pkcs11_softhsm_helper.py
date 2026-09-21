"""Testes unitários (sem precisar de SoftHSM2 instalado) para a
resolução do caminho do módulo PKCS#11 em
``tests/pkcs11_softhsm_helper.py`` -- variável ``SOFTHSM_LIB`` vs. a
lista de candidatos por distribuição. Os testes que falam com um token
SoftHSM2 real vivem em ``tests/test_pkcs11_strategy_factory.py`` e
``tests/test_builder.py``, pulados quando ele não está disponível.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from . import pkcs11_softhsm_helper as helper


@pytest.fixture(autouse=True)
def _isolated_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Garante que nenhum ``SOFTHSM_LIB`` real do ambiente de execução
    (ex.: exportado pelo CI) vaze para dentro destes testes."""
    monkeypatch.delenv(helper.ENV_VAR_SOFTHSM_LIB, raising=False)


def test_find_softhsm2_lib_none_without_env_var_or_candidates(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(helper, "SOFTHSM2_LIB_CANDIDATES", (str(tmp_path / "nao-existe.so"),))

    assert helper.find_softhsm2_lib() is None


def test_find_softhsm2_lib_uses_env_var_when_set(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    lib = tmp_path / "libsofthsm2.so"
    lib.write_bytes(b"")
    monkeypatch.setenv(helper.ENV_VAR_SOFTHSM_LIB, str(lib))

    assert helper.find_softhsm2_lib() == str(lib)


def test_find_softhsm2_lib_falls_back_to_candidates(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    candidate = tmp_path / "libsofthsm2.so"
    candidate.write_bytes(b"")
    monkeypatch.setattr(
        helper,
        "SOFTHSM2_LIB_CANDIDATES",
        (str(tmp_path / "nao-existe.so"), str(candidate)),
    )

    assert helper.find_softhsm2_lib() == str(candidate)


def test_find_softhsm2_lib_env_var_takes_precedence_over_candidates(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    env_lib = tmp_path / "env" / "libsofthsm2.so"
    env_lib.parent.mkdir()
    env_lib.write_bytes(b"")
    candidate = tmp_path / "candidato" / "libsofthsm2.so"
    candidate.parent.mkdir()
    candidate.write_bytes(b"")
    monkeypatch.setenv(helper.ENV_VAR_SOFTHSM_LIB, str(env_lib))
    monkeypatch.setattr(helper, "SOFTHSM2_LIB_CANDIDATES", (str(candidate),))

    assert helper.find_softhsm2_lib() == str(env_lib)


def test_find_softhsm2_lib_env_var_pointing_to_missing_file_does_not_fall_back(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Uma env var mal configurada (caminho inexistente, ex.: typo) não
    deve ser mascarada silenciosamente pelos candidatos."""
    candidate = tmp_path / "libsofthsm2.so"
    candidate.write_bytes(b"")
    monkeypatch.setenv(helper.ENV_VAR_SOFTHSM_LIB, str(tmp_path / "caminho-errado.so"))
    monkeypatch.setattr(helper, "SOFTHSM2_LIB_CANDIDATES", (str(candidate),))

    assert helper.find_softhsm2_lib() is None


def test_find_softhsm2_lib_env_var_pointing_to_directory_is_ignored(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Diretório não é módulo carregável: aceitá-lo faria
    ``softhsm2_available()`` devolver ``True`` e a falha só apareceria
    lá na frente, dentro do ``pkcs11.lib()``."""
    directory = tmp_path / "libsofthsm2.so"
    directory.mkdir()
    monkeypatch.setenv(helper.ENV_VAR_SOFTHSM_LIB, str(directory))

    assert helper.find_softhsm2_lib() is None


def test_softhsm2_available_false_without_lib(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(helper, "SOFTHSM2_LIB_CANDIDATES", (str(tmp_path / "nao-existe.so"),))

    assert helper.softhsm2_available() is False

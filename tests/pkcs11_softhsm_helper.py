"""Helper de setup/teardown de um slot SoftHSM2 efemero para os testes de
strategy_factory.from_pkcs11. Usa softhsm2-util (instalado no ambiente) para
criar um token isolado por execucao de teste, em um diretorio temporario.

O caminho PKCS#11/HSM desta biblioteca e' exercitado contra um token
SoftHSM2 real (nao apenas mocks) -- cobertura que nao existe na
implementacao de referencia para este ponto especifico."""

from __future__ import annotations

import os
import shutil
import subprocess
from collections.abc import Iterator
from pathlib import Path

import pytest

SOFTHSM2_LIB_CANDIDATES = (
    "/usr/lib/softhsm/libsofthsm2.so",
    "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
    "/usr/local/lib/softhsm/libsofthsm2.so",
)


def find_softhsm2_lib() -> str | None:
    for candidate in SOFTHSM2_LIB_CANDIDATES:
        if Path(candidate).exists():
            return candidate
    return None


def softhsm2_available() -> bool:
    return shutil.which("softhsm2-util") is not None and find_softhsm2_lib() is not None


@pytest.fixture(scope="session")
def _pkcs11_lib(tmp_path_factory: pytest.TempPathFactory) -> Iterator[object]:
    """Objeto ``pkcs11.lib(...)`` unico, compartilhado por toda a sessao de
    testes.

    A biblioteca PKCS#11 subjacente (``libsofthsm2.so``) so' le
    ``SOFTHSM2_CONF`` e enumera tokens na primeira chamada de
    ``C_Initialize`` dentro do processo -- esse estado e' global ao
    *processo*, nao a instancia Python de ``pkcs11.lib``. Criar um novo
    ``pkcs11.lib(mesmo_caminho)`` a cada teste nao reseta esse estado:
    testes subsequentes enxergariam o token do *primeiro* teste (mesmo
    apontando para um ``SOFTHSM2_CONF`` novo), causando ``NoSuchToken`` ou
    ``UserAlreadyLoggedIn`` (sessao do teste anterior, nunca fechada por
    design -- ``Pkcs11SigningStrategy`` mantem a sessao viva pelo seu
    tempo de vida). A correcao e' reciclar a *mesma* instancia de ``lib``
    via ``finalize()`` + ``reinitialize()`` a cada teste, o que forca a
    biblioteca a reler o ``SOFTHSM2_CONF`` corrente -- inclusive quando
    uma sessao anterior ficou aberta (cenario real do
    ``Pkcs11SigningStrategy``).

    A *primeira* ``C_Initialize`` -- a que acontece aqui, antes de
    qualquer teste rodar -- le qualquer ``SOFTHSM2_CONF`` que ja estiver
    no ambiente do processo pytest ou, na ausencia dele, a config padrao
    do sistema instalada pelo pacote (``/etc/softhsm2.conf``), cujo
    ``directories.tokendir`` (geralmente ``/var/lib/softhsm2/tokens/``)
    costuma so' ser gravavel pelo usuario ``root``/grupo ``softhsm``. Num
    usuario comum sem esse grupo, isso faz ``pkcs11.lib(module_path)``
    falhar com ``pkcs11.exceptions.GeneralError`` na fixture de sessao,
    antes mesmo do primeiro teste comecar -- nao e' um problema de
    instalacao do SoftHSM2 em si, e' a primeira inicializacao apontando
    pra um diretorio que este usuario nao pode acessar. A correcao e'
    apontar ``SOFTHSM2_CONF`` para um diretorio proprio, gravavel e
    efemero (``tmp_path_factory``, escopo de sessao) *antes* dessa
    primeira inicializacao, restaurando a variavel de ambiente logo em
    seguida -- o diretorio real usado por cada teste continua sendo o de
    :func:`softhsm2_token`, que troca essa variavel de novo e recicla
    esta mesma instancia via ``finalize()``/``reinitialize()``.
    """
    module_path = find_softhsm2_lib()
    assert module_path is not None

    bootstrap_dir = tmp_path_factory.mktemp("softhsm2-bootstrap")
    bootstrap_tokendir = bootstrap_dir / "tokens"
    bootstrap_tokendir.mkdir()
    bootstrap_conf = bootstrap_dir / "softhsm2.conf"
    bootstrap_conf.write_text(f"directories.tokendir = {bootstrap_tokendir}\nobjectstore.backend = file\n")

    previous_conf = os.environ.get("SOFTHSM2_CONF")
    os.environ["SOFTHSM2_CONF"] = str(bootstrap_conf)

    import pkcs11

    try:
        lib = pkcs11.lib(module_path)
    finally:
        # A config real de cada teste vem de softhsm2_token (via
        # monkeypatch, desfeito automaticamente ao fim de cada teste) --
        # esta variavel de bootstrap so' precisa existir durante a
        # C_Initialize acima, nao depois.
        if previous_conf is None:
            os.environ.pop("SOFTHSM2_CONF", None)
        else:
            os.environ["SOFTHSM2_CONF"] = previous_conf

    yield lib
    try:
        lib.finalize()
    except pkcs11.PKCS11Error:
        pass


@pytest.fixture
def softhsm2_token(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, _pkcs11_lib: object) -> Iterator[dict[str, str]]:
    """Cria um token SoftHSM2 efemero com um par de chaves RSA 2048, e o
    remove ao final. Retorna module_path, token_label, key_label, user_pin."""
    token_dir = tmp_path / "softhsm2-tokens"
    token_dir.mkdir()
    config_path = tmp_path / "softhsm2.conf"
    config_path.write_text(f"directories.tokendir = {token_dir}\nobjectstore.backend = file\n")

    env = os.environ.copy()
    env["SOFTHSM2_CONF"] = str(config_path)
    # A biblioteca pkcs11 (usada logo abaixo, dentro deste mesmo processo
    # Python) le SOFTHSM2_CONF do os.environ do processo atual, nao do env
    # passado ao subprocess do softhsm2-util -- por isso tambem precisa ser
    # setada aqui via monkeypatch (confirmado rodando os testes nesta
    # maquina: sem isso, lib.get_token() nao encontra o token recem-criado).
    monkeypatch.setenv("SOFTHSM2_CONF", str(config_path))

    token_label = "hubsaude-test-token"
    key_label = "hubsaude-test-key"
    so_pin = "1234"
    user_pin = "5678"

    subprocess.run(
        ["softhsm2-util", "--init-token", "--free", "--label", token_label, "--so-pin", so_pin, "--pin", user_pin],
        env=env,
        check=True,
        capture_output=True,
    )

    module_path = find_softhsm2_lib()
    assert module_path is not None

    import pkcs11

    # Ver docstring de _pkcs11_lib: forca a biblioteca (estado global ao
    # processo) a esquecer o SOFTHSM2_CONF/token da execucao de teste
    # anterior e reler a config atual, senao lib.get_token() abaixo
    # enxergaria o token de um teste anterior (ou nenhum token).
    _pkcs11_lib.finalize()  # type: ignore[attr-defined]
    _pkcs11_lib.reinitialize()  # type: ignore[attr-defined]

    token = _pkcs11_lib.get_token(token_label=token_label)  # type: ignore[attr-defined]
    with token.open(rw=True, user_pin=user_pin) as session:
        session.generate_keypair(pkcs11.KeyType.RSA, 2048, label=key_label, store=True)

    yield {"module_path": module_path, "token_label": token_label, "key_label": key_label, "user_pin": user_pin}

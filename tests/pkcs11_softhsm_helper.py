"""Helper de setup/teardown de um slot SoftHSM2 efêmero para os testes de
strategy_factory.from_pkcs11. Usa softhsm2-útil (instalado no ambiente) para
criar um token isolado por execução de teste, em um diretório temporário.

O caminho PKCS#11/HSM desta biblioteca é exercitado contra um token
SoftHSM2 real (não apenas mocks) -- cobertura que não existe na
implementação de referência para este ponto específico."""

from __future__ import annotations

import os
import shutil
import subprocess
from collections.abc import Iterator
from pathlib import Path
from typing import Final

import pytest

#: Variável de ambiente que aponta direto para o módulo PKCS#11 do
#: SoftHSM2 (``libsofthsm2.so``), com precedência sobre
#: :data:`SOFTHSM2_LIB_CANDIDATES` -- o caminho varia por distribuição,
#: então o CI descobre o real e o exporta.
ENV_VAR_SOFTHSM_LIB: Final[str] = "SOFTHSM_LIB"

SOFTHSM2_LIB_CANDIDATES = (
    "/usr/lib/softhsm/libsofthsm2.so",
    "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
    "/usr/local/lib/softhsm/libsofthsm2.so",
)


def find_softhsm2_lib() -> str | None:
    """Retorna o caminho do módulo PKCS#11 do SoftHSM2: ``SOFTHSM_LIB``,
    se definida, senão o primeiro de :data:`SOFTHSM2_LIB_CANDIDATES` que
    existir. ``None`` se nenhum resolver -- inclusive quando a variável
    aponta para algo que não é arquivo, caso em que os candidatos **não**
    são tentados, para o erro de configuração não ficar mascarado (mesma
    política de ``hubsaude_simulator_helper.simulator_jar_path``).
    """
    override = os.environ.get(ENV_VAR_SOFTHSM_LIB)
    if override:
        return override if Path(override).is_file() else None
    for candidate in SOFTHSM2_LIB_CANDIDATES:
        if Path(candidate).is_file():
            return candidate
    return None


def softhsm2_available() -> bool:
    return shutil.which("softhsm2-util") is not None and find_softhsm2_lib() is not None


@pytest.fixture(scope="session")
def _pkcs11_lib(tmp_path_factory: pytest.TempPathFactory) -> Iterator[object]:
    """Objeto ``pkcs11.lib(...)`` único, compartilhado por toda a sessão de
    testes.

    A biblioteca PKCS#11 subjacente (``libsofthsm2.so``) só lê
    ``SOFTHSM2_CONF`` e enumera tokens na primeira chamada de
    ``C_Initialize`` dentro do processo -- esse estado é global ao
    *processo*, não a instância Python de ``pkcs11.lib``. Criar um novo
    ``pkcs11.lib(mesmo_caminho)`` a cada teste não reseta esse estado:
    testes subsequentes enxergariam o token do *primeiro* teste (mesmo
    apontando para um ``SOFTHSM2_CONF`` novo), causando ``NoSuchToken`` ou
    ``UserAlreadyLoggedIn`` (sessão do teste anterior, nunca fechada por
    design -- ``Pkcs11SigningStrategy`` mantém a sessão viva pelo seu
    tempo de vida). A correção é reciclar a *mesma* instância de ``lib``
    via ``finalize()`` + ``reinitialize()`` a cada teste, o que força a
    biblioteca a reler o ``SOFTHSM2_CONF`` corrente -- inclusive quando
    uma sessão anterior ficou aberta (cenário real do
    ``Pkcs11SigningStrategy``).

    A *primeira* ``C_Initialize`` -- a que acontece aqui, antes de
    qualquer teste rodar -- lê qualquer ``SOFTHSM2_CONF`` que já estiver
    no ambiente do processo pytest ou, na ausência dele, a config padrão
    do sistema instalada pelo pacote (``/etc/softhsm2.conf``), cujo
    ``directories.tokendir`` (geralmente ``/var/lib/softhsm2/tokens/``)
    costuma só ser gravável pelo usuário ``root``/grupo ``softhsm``. Num
    usuário comum sem esse grupo, isso faz ``pkcs11.lib(module_path)``
    falhar com ``pkcs11.exceptions.GeneralError`` na fixture de sessão,
    antes mesmo do primeiro teste começar -- não é um problema de
    instalação do SoftHSM2 em si, é a primeira inicialização apontando
    pra um diretório que este usuário não pode acessar. A correção é
    apontar ``SOFTHSM2_CONF`` para um diretório próprio, gravável e
    efêmero (``tmp_path_factory``, escopo de sessão) *antes* dessa
    primeira inicialização, restaurando a variável de ambiente logo em
    seguida -- o diretório real usado por cada teste continua sendo o de
    :func:`softhsm2_token`, que troca essa variável de novo e recicla
    esta mesma instância via ``finalize()``/``reinitialize()``.
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
        # esta variável de bootstrap só precisa existir durante a
        # C_Initialize acima, não depois.
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
    """Cria um token SoftHSM2 efêmero com um par de chaves RSA 2048, e o
    remove ao final. Retorna module_path, token_label, key_label, user_pin."""
    token_dir = tmp_path / "softhsm2-tokens"
    token_dir.mkdir()
    config_path = tmp_path / "softhsm2.conf"
    config_path.write_text(f"directories.tokendir = {token_dir}\nobjectstore.backend = file\n")

    env = os.environ.copy()
    env["SOFTHSM2_CONF"] = str(config_path)
    # A biblioteca pkcs11 (usada logo abaixo, dentro deste mesmo processo
    # Python) lê SOFTHSM2_CONF do os.environ do processo atual, não do env
    # passado ao subprocess do softhsm2-útil -- por isso também precisa ser
    # setada aqui via monkeypatch (confirmado rodando os testes nesta
    # máquina: sem isso, lib.get_token() não encontra o token recém-criado).
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

    # Ver docstring de _pkcs11_lib: força a biblioteca (estado global ao
    # processo) a esquecer o SOFTHSM2_CONF/token da execução de teste
    # anterior e reler a config atual, senão lib.get_token() abaixo
    # enxergaria o token de um teste anterior (ou nenhum token).
    _pkcs11_lib.finalize()  # type: ignore[attr-defined]
    _pkcs11_lib.reinitialize()  # type: ignore[attr-defined]

    token = _pkcs11_lib.get_token(token_label=token_label)  # type: ignore[attr-defined]
    with token.open(rw=True, user_pin=user_pin) as session:
        session.generate_keypair(pkcs11.KeyType.RSA, 2048, label=key_label, store=True)

    yield {"module_path": module_path, "token_label": token_label, "key_label": key_label, "user_pin": user_pin}

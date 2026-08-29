from __future__ import annotations

import pytest

from hubsaude_client import strategy_factory
from hubsaude_client.exceptions import SigningError, SmartTokenError
from hubsaude_client.ports import SigningStrategy
from tests.pkcs11_softhsm_helper import (
    _pkcs11_lib,  # noqa: F401  (fixture, used transitively by softhsm2_token)
    softhsm2_available,
    softhsm2_token,  # noqa: F401  (fixture)
)

pytestmark = pytest.mark.skipif(not softhsm2_available(), reason="SoftHSM2 nao disponivel no ambiente")


def test_from_pkcs11_signs_with_hardware_backed_key(softhsm2_token) -> None:  # noqa: F811
    strategy = strategy_factory.from_pkcs11(
        pkcs11_module_path=softhsm2_token["module_path"],
        token_label=softhsm2_token["token_label"],
        key_label=softhsm2_token["key_label"],
        user_pin=softhsm2_token["user_pin"],
        jwt_algorithm="RS256",
    )
    assert isinstance(strategy, SigningStrategy)
    signature = strategy.sign(b"header.payload")
    assert len(signature) > 0


def test_from_pkcs11_unknown_key_label_raises(softhsm2_token) -> None:  # noqa: F811
    with pytest.raises(SmartTokenError, match="nao encontrada"):
        strategy_factory.from_pkcs11(
            pkcs11_module_path=softhsm2_token["module_path"],
            token_label=softhsm2_token["token_label"],
            key_label="chave-que-nao-existe",
            user_pin=softhsm2_token["user_pin"],
        )


def test_from_pkcs11_wrong_pin_raises(softhsm2_token) -> None:  # noqa: F811
    with pytest.raises(SmartTokenError):
        strategy_factory.from_pkcs11(
            pkcs11_module_path=softhsm2_token["module_path"],
            token_label=softhsm2_token["token_label"],
            key_label=softhsm2_token["key_label"],
            user_pin="0000",
        )


def test_pkcs11_signing_strategy_exposes_jwt_algorithm(softhsm2_token) -> None:  # noqa: F811
    strategy = strategy_factory.from_pkcs11(
        pkcs11_module_path=softhsm2_token["module_path"],
        token_label=softhsm2_token["token_label"],
        key_label=softhsm2_token["key_label"],
        user_pin=softhsm2_token["user_pin"],
        jwt_algorithm="RS384",
    )
    assert strategy.jwt_algorithm == "RS384"


def test_from_pkcs11_generic_key_access_error_raises(softhsm2_token) -> None:  # noqa: F811
    """Cobre o branch ``except Exception`` (nao ``NoSuchKey``) de
    ``from_pkcs11`` ao acessar a chave, com um erro real de hardware: dois
    pares de chave com o mesmo rotulo no token fazem ``session.get_key``
    levantar ``pkcs11.exceptions.MultipleObjectsReturned`` (confirmado
    nesta maquina via SoftHSM2 real, sem qualquer monkeypatch)."""
    import pkcs11

    lib = pkcs11.lib(softhsm2_token["module_path"])
    token = lib.get_token(token_label=softhsm2_token["token_label"])
    with token.open(rw=True, user_pin=softhsm2_token["user_pin"]) as session:
        session.generate_keypair(pkcs11.KeyType.RSA, 2048, label=softhsm2_token["key_label"], store=True)

    with pytest.raises(SmartTokenError, match="Falha ao acessar chave"):
        strategy_factory.from_pkcs11(
            pkcs11_module_path=softhsm2_token["module_path"],
            token_label=softhsm2_token["token_label"],
            key_label=softhsm2_token["key_label"],
            user_pin=softhsm2_token["user_pin"],
        )


def test_pkcs11_signing_strategy_sign_wraps_hardware_error(
    softhsm2_token, monkeypatch: pytest.MonkeyPatch  # noqa: F811
) -> None:
    """Cobre o branch ``except Exception`` de ``Pkcs11SigningStrategy.sign``.

    Diferente dos outros testes deste arquivo, aqui a chave PKCS#11 real e
    usada para construir a estrategia, mas o metodo ``sign`` do objeto de
    chave retornado pela biblioteca (uma instancia comum, nao a classe
    Cython em si) e substituido via ``monkeypatch`` para simular uma falha
    de hardware -- confirmado nesta maquina que atribuir um atributo de
    instancia em ``pkcs11.PrivateKey`` funciona (ao contrario de
    monkeypatch na *classe* de alguns outros objetos da biblioteca)."""
    strategy = strategy_factory.from_pkcs11(
        pkcs11_module_path=softhsm2_token["module_path"],
        token_label=softhsm2_token["token_label"],
        key_label=softhsm2_token["key_label"],
        user_pin=softhsm2_token["user_pin"],
    )

    def _raise_hardware_error(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("falha simulada de hardware")

    monkeypatch.setattr(strategy._key, "sign", _raise_hardware_error)  # type: ignore[attr-defined]

    with pytest.raises(SigningError, match="Falha ao assinar via PKCS#11"):
        strategy.sign(b"header.payload")

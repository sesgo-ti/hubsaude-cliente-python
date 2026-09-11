"""Estrategia de assinatura que delega ao hardware via PKCS#11 (HSM/smart
token). A chave privada NUNCA sai do dispositivo -- este objeto guarda
apenas um handle de sessao e a referencia a chave no token.

Divergencia de plataforma: a mecanica CKM_*_RSA_PKCS/CKM_ECDSA do PKCS#11 ja
produz a assinatura no formato exigido (RSA PKCS#1v1.5/PSS identico ao
software; ECDSA como R||S bruto, NAO DER) -- diferente de
private_key_signing_strategy.py, aqui NAO ha conversao DER->P1363 a fazer.

ECDSA usa sempre o mecanismo puro ``CKM_ECDSA`` (assinatura sobre um resumo
ja calculado pelo chamador), nunca os mecanismos combinados
``CKM_ECDSA_SHA*`` (hash + assinatura numa unica operacao do dispositivo):
nem todo hardware/software de token PKCS#11 implementa as variantes
combinadas, enquanto o mecanismo puro tem suporte praticamente universal
entre fabricantes (confirmado em reproducao real contra SoftHSM2 -- ver
achados tecnicos). O resumo (SHA-256/384/512) e calculado aqui, do lado do
cliente, via ``hashlib`` da biblioteca padrao, antes de enviar ao
dispositivo. RSA (PKCS#1v1.5 e PSS) continua usando os mecanismos
combinados ``CKM_SHA*_RSA_PKCS[_PSS]``, que nao tem o mesmo problema de
suporte.
"""

from __future__ import annotations

import hashlib
from typing import Callable

from hubsaude_client.algorithms import resolve
from hubsaude_client.exceptions import SigningError

_MECHANISM_BY_ALGORITHM: dict[str, str] = {
    "RS256": "SHA256_RSA_PKCS",
    "RS384": "SHA384_RSA_PKCS",
    "RS512": "SHA512_RSA_PKCS",
    "PS256": "SHA256_RSA_PKCS_PSS",
    "PS384": "SHA384_RSA_PKCS_PSS",
    "PS512": "SHA512_RSA_PKCS_PSS",
    # Mecanismo puro (nao combinado) -- ver nota no docstring do modulo.
    "ES256": "ECDSA",
    "ES384": "ECDSA",
    "ES512": "ECDSA",
}

#: Funcao de resumo (digest) a aplicar do lado do cliente antes de assinar,
#: por algoritmo ECDSA. Algoritmos RSA nao aparecem aqui: seus mecanismos
#: PKCS#11 permanecem combinados (hash + assinatura no dispositivo).
_ECDSA_DIGEST_BY_ALGORITHM: dict[str, Callable[[bytes], bytes]] = {
    "ES256": lambda data: hashlib.sha256(data).digest(),
    "ES384": lambda data: hashlib.sha384(data).digest(),
    "ES512": lambda data: hashlib.sha512(data).digest(),
}


class Pkcs11SigningStrategy:
    """Estrategia de assinatura via chave em hardware (HSM/smart token)."""

    def __init__(self, session: object, key: object, jwt_algorithm: str) -> None:
        """Cria a estrategia associada a uma sessao e chave PKCS#11 abertas.

        Args:
            session: sessao PKCS#11 aberta (``pkcs11.Session``), mantida viva
                pelo tempo de vida desta estrategia.
            key: objeto de chave privada no token (``pkcs11.PrivateKey``).
            jwt_algorithm: algoritmo JWT (JWA) a usar na assinatura.
        """
        resolve(jwt_algorithm)  # valida o algoritmo cedo (fail-fast)
        self._session = session
        self._key = key
        self._jwt_algorithm = jwt_algorithm

    @property
    def jwt_algorithm(self) -> str:
        """Algoritmo JWT (JWA) configurado para esta estrategia."""
        return self._jwt_algorithm

    def sign(self, data: bytes) -> bytes:
        """Assina os dados delegando a operacao ao hardware PKCS#11.

        Args:
            data: bytes a serem assinados.

        Returns:
            A assinatura digital em formato raw.

        Raises:
            SigningError: se ocorrer erro na operacao do hardware.
        """
        # Import local pelo mesmo motivo do import em strategy_factory.py:
        # python-pkcs11 e opcional (extra "hsm"). Este modulo e importado no
        # topo de strategy_factory.py -- se o import fosse no topo daqui, o
        # problema so migraria um nivel acima, quebrando o mesmo jeito para
        # quem nao instalou o extra.
        import pkcs11

        mechanism_name = _MECHANISM_BY_ALGORITHM[self._jwt_algorithm]
        mechanism = getattr(pkcs11.Mechanism, mechanism_name)
        # Para ECDSA (mecanismo puro CKM_ECDSA), o resumo precisa ser
        # calculado aqui, do lado do cliente -- o dispositivo espera receber
        # o hash pronto, nao os dados originais. Para RSA (mecanismos
        # combinados), os dados originais sao enviados como estao.
        digest_fn = _ECDSA_DIGEST_BY_ALGORITHM.get(self._jwt_algorithm)
        payload = digest_fn(data) if digest_fn is not None else data
        try:
            # self._key e tipado como "object" no construtor (handle opaco, sem
            # acoplar a assinatura publica da classe ao tipo concreto de
            # python-pkcs11) -- o atributo "sign" existe em tempo de execucao
            # em pkcs11.PrivateKey, mas nao e visivel estaticamente para mypy.
            signature = self._key.sign(payload, mechanism=mechanism)  # type: ignore[attr-defined]
        except Exception as exc:
            raise SigningError(f"Falha ao assinar via PKCS#11 com algoritmo {self._jwt_algorithm}", exc)
        return bytes(signature)

    def close(self) -> None:
        """Fecha a sessao PKCS#11 subjacente (best-effort, idempotente).

        HSMs e smart cards costumam ter um limite rigido de sessoes
        simultaneas; sem este fechamento explicito, a sessao permanece
        aberta ate o processo inteiro terminar (o objeto de sessao da
        biblioteca ``python-pkcs11`` nao define ``__del__``). Nao faz
        parte do Protocol ``ports.SigningStrategy`` (que so exige
        ``sign()``) -- e um metodo adicional, especifico desta
        implementacao, descoberto e chamado via duck typing (``getattr``)
        por quem mantiver o ciclo de vida desta estrategia (ver
        ``SmartTokenClient.close()``).
        """
        try:
            self._session.close()  # type: ignore[attr-defined]
        except Exception:  # pragma: no cover -- best-effort, nao deve propagar
            pass

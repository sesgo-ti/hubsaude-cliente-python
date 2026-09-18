"""Estratégia de assinatura que delega ao hardware via PKCS#11 (HSM/smart
token). A chave privada NUNCA sai do dispositivo -- este objeto guarda
apenas um handle de sessão e a referência a chave no token.

Divergência de plataforma: a mecânica CKM_*_RSA_PKCS/CKM_ECDSA do PKCS#11 ja
produz a assinatura no formato exigido (RSA PKCS#1v1.5/PSS idêntico ao
software; ECDSA como R||S bruto, NÃO DER) -- diferente de
private_key_signing_strategy.py, aqui NÃO há conversão DER->P1363 a fazer.

ECDSA usa sempre o mecanismo puro ``CKM_ECDSA`` (assinatura sobre um resumo
ja calculado pelo chamador), nunca os mecanismos combinados
``CKM_ECDSA_SHA*`` (hash + assinatura numa única operação do dispositivo):
nem todo hardware/software de token PKCS#11 implementa as variantes
combinadas, enquanto o mecanismo puro tem suporte praticamente universal
entre fabricantes (confirmado em reprodução real contra SoftHSM2 -- ver
achados técnicos). O resumo (SHA-256/384/512) e calculado aqui, do lado do
cliente, via ``hashlib`` da biblioteca padrão, antes de enviar ao
dispositivo. RSA (PKCS#1v1.5 e PSS) continua usando os mecanismos
combinados ``CKM_SHA*_RSA_PKCS[_PSS]``, que não tem o mesmo problema de
suporte.
"""

from __future__ import annotations

import hashlib
from typing import Callable

from hubsaude_client._log import get_logger
from hubsaude_client.algorithms import resolve
from hubsaude_client.exceptions import SigningError

# Logger compartilhado com o restante da lib (ver _log.py) -- este módulo
# não deve usar logging.getLogger(__name__) diretamente (ver contrato de
# observabilidade documentado em _log.py).
_LOG = get_logger()

_MECHANISM_BY_ALGORITHM: dict[str, str] = {
    "RS256": "SHA256_RSA_PKCS",
    "RS384": "SHA384_RSA_PKCS",
    "RS512": "SHA512_RSA_PKCS",
    "PS256": "SHA256_RSA_PKCS_PSS",
    "PS384": "SHA384_RSA_PKCS_PSS",
    "PS512": "SHA512_RSA_PKCS_PSS",
    # Mecanismo puro (não combinado) -- ver nota no docstring do módulo.
    "ES256": "ECDSA",
    "ES384": "ECDSA",
    "ES512": "ECDSA",
}

#: Função de resumo (digest) a aplicar do lado do cliente antes de assinar,
#: por algoritmo ECDSA. Algoritmos RSA não aparecem aqui: seus mecanismos
#: PKCS#11 permanecem combinados (hash + assinatura no dispositivo).
_ECDSA_DIGEST_BY_ALGORITHM: dict[str, Callable[[bytes], bytes]] = {
    "ES256": lambda data: hashlib.sha256(data).digest(),
    "ES384": lambda data: hashlib.sha384(data).digest(),
    "ES512": lambda data: hashlib.sha512(data).digest(),
}


class Pkcs11SigningStrategy:
    """Estratégia de assinatura via chave em hardware (HSM/smart token)."""

    def __init__(self, session: object, key: object, jwt_algorithm: str) -> None:
        """Cria a estratégia associada a uma sessão e chave PKCS#11 abertas.

        Args:
            session: sessão PKCS#11 aberta (``pkcs11.Session``), mantida viva
                pelo tempo de vida desta estratégia.
            key: objeto de chave privada no token (``pkcs11.PrivateKey``).
            jwt_algorithm: algoritmo JWT (JWA) a usar na assinatura.
        """
        resolve(jwt_algorithm)  # valida o algoritmo cedo (fail-fast)
        self._session = session
        self._key = key
        self._jwt_algorithm = jwt_algorithm

    @property
    def jwt_algorithm(self) -> str:
        """Algoritmo JWT (JWA) configurado para esta estratégia."""
        return self._jwt_algorithm

    def sign(self, data: bytes) -> bytes:
        """Assina os dados delegando a operação ao hardware PKCS#11.

        Args:
            data: bytes a serem assinados.

        Returns:
            A assinatura digital em formato raw.

        Raises:
            SigningError: se ocorrer erro na operação do hardware.
        """
        # Import local pelo mesmo motivo do import em strategy_factory.py:
        # python-pkcs11 e opcional (extra "hsm"). Este módulo e importado no
        # topo de strategy_factory.py -- se o import fosse no topo daqui, o
        # problema só migraria um nível acima, quebrando o mesmo jeito para
        # quem não instalou o extra.
        import pkcs11

        mechanism_name = _MECHANISM_BY_ALGORITHM[self._jwt_algorithm]
        mechanism = getattr(pkcs11.Mechanism, mechanism_name)
        # Para ECDSA (mecanismo puro CKM_ECDSA), o resumo precisa ser
        # calculado aqui, do lado do cliente -- o dispositivo espera receber
        # o hash pronto, não os dados originais. Para RSA (mecanismos
        # combinados), os dados originais são enviados como estão.
        digest_fn = _ECDSA_DIGEST_BY_ALGORITHM.get(self._jwt_algorithm)
        payload = digest_fn(data) if digest_fn is not None else data
        try:
            # self._key e tipado como "object" no construtor (handle opaco, sem
            # acoplar a assinatura pública da classe ao tipo concreto de
            # python-pkcs11) -- o atributo "sign" existe em tempo de execução
            # em pkcs11.PrivateKey, mas não e visível estaticamente para mypy.
            signature = self._key.sign(payload, mechanism=mechanism)  # type: ignore[attr-defined]
        except Exception as exc:
            raise SigningError(f"Falha ao assinar via PKCS#11 com algoritmo {self._jwt_algorithm}", exc)
        return bytes(signature)

    def close(self) -> None:
        """Fecha a sessão PKCS#11 subjacente (best-effort, idempotente).

        HSMs e smart cards costumam ter um limite rígido de sessões
        simultâneas; sem este fechamento explícito, a sessão permanece
        aberta até o processo inteiro terminar (o objeto de sessão da
        biblioteca ``python-pkcs11`` não define ``__del__``). Não faz
        parte do Protocol ``ports.SigningStrategy`` (que só exige
        ``sign()``) -- e um método adicional, específico desta
        implementação, descoberto e chamado via duck typing (``getattr``)
        por quem mantiver o ciclo de vida desta estratégia (ver
        ``SmartTokenClient.close()``).

        Falhas ao fechar são apenas logadas (best-effort, não propagam) --
        ver mesmo padrão em ``SmartTokenClient._close_signing_strategy_if_supported``.
        """
        try:
            self._session.close()  # type: ignore[attr-defined]
        except Exception as exc:  # nosec B110 -- best-effort, logado abaixo, não propaga
            _LOG.warning("Falha ao fechar sessão PKCS#11: %s", exc)

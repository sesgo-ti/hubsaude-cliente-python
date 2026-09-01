"""Agregacao da configuracao de assinatura do client_assertion JWT, e
resolucao da SigningStrategy efetiva a partir dela.

Nao lida com o claim ``hub_ctx`` (ver Global Constraints do plano de
execucao) -- isso e responsabilidade da orquestracao do cliente HTTP,
fora do escopo deste modulo. As fontes de assinatura sao mutuamente
exclusivas: uma SigningStrategy propria (HSM, cofre de segredos) ou uma
chave privada em arquivo PEM, da qual a estrategia e derivada conforme o
algoritmo JWT configurado.

Ponto de entrada consumido pelo cliente HTTP/orquestracao, junto
com TlsSettings.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes

from hubsaude_client import pem_loader, strategy_factory
from hubsaude_client.defaults import DEFAULT_JWT_ALGORITHM
from hubsaude_client.ports import SigningStrategy


@dataclass(frozen=True)
class ResolvedSigning:
    """Resultado da resolucao da configuracao de assinatura.

    Attributes:
        strategy: estrategia de assinatura efetiva do client_assertion.
        client_key: chave privada carregada do PEM, disponivel para uso em
            mTLS; ``None`` quando a estrategia foi fornecida diretamente
            (HSM, cofre de segredos).
    """

    strategy: SigningStrategy
    client_key: PrivateKeyTypes | None


@dataclass
class SigningSettings:
    """Configuracao de assinatura do client_assertion JWT.

    Attributes:
        private_key_pem: caminho da chave privada PEM; exclusivo com
            ``signing_strategy``.
        private_key_password: senha da chave privada PEM (``None`` se nao
            criptografada). E consumida: repassada a ``pem_loader``, que
            zera o array ao final de ``resolve()``, em sucesso ou erro. O
            chamador nao deve reutiliza-la.
        signing_strategy: estrategia de assinatura propria (HSM, cofre de
            segredos); exclusiva com ``private_key_pem``.
        jwt_algorithm: algoritmo JWT do client_assertion.
        key_id: identificador da chave (``kid``) no header do JWT; opcional.
    """

    private_key_pem: Path | None = None
    private_key_password: bytearray | None = None
    signing_strategy: SigningStrategy | None = None
    jwt_algorithm: str = DEFAULT_JWT_ALGORITHM
    key_id: str | None = None

    def resolve(self) -> ResolvedSigning:
        """Resolve a estrategia de assinatura efetiva.

        Quando a chave vem de arquivo PEM, a estrategia e criada a partir do
        algoritmo JWT configurado e a chave carregada fica disponivel para
        uso em mTLS.

        Returns:
            A estrategia efetiva e, quando aplicavel, a chave privada
            carregada do PEM.

        Raises:
            ValueError: se ambas ou nenhuma das fontes de assinatura forem
                definidas.
            SmartTokenError: se o arquivo PEM nao puder ser carregado.
        """
        if self.signing_strategy is not None:
            if self.private_key_pem is not None:
                raise ValueError("Defina signing_strategy OU private_key_pem, nao ambos")
            return ResolvedSigning(self.signing_strategy, None)
        if self.private_key_pem is None:
            raise ValueError("E obrigatorio definir signing_strategy ou private_key_pem")
        client_key = pem_loader.load_private_key(self.private_key_pem, self.private_key_password)
        strategy = strategy_factory.from_private_key(client_key, self.jwt_algorithm)
        return ResolvedSigning(strategy, client_key)

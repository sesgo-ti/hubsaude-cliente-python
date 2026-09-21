"""Agregação da configuração de assinatura do client_assertion JWT, e
resolução da SigningStrategy efetiva a partir dela.

Não lida com o claim ``hub_ctx`` (ver Global Constraints do plano de
execução) -- isso é responsabilidade da orquestração do cliente HTTP,
fora do escopo deste módulo. As fontes de assinatura são mutuamente
exclusivas: uma SigningStrategy própria (HSM, cofre de segredos) ou uma
chave privada em arquivo PEM, da qual a estratégia é derivada conforme o
algoritmo JWT configurado.

Ponto de entrada consumido pelo cliente HTTP/orquestração, junto
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
    """Resultado da resolução da configuração de assinatura.

    Attributes:
        strategy: estratégia de assinatura efetiva do client_assertion.
        client_key: chave privada carregada do PEM, disponível para uso em
            mTLS; ``None`` quando a estratégia foi fornecida diretamente
            (HSM, cofre de segredos).
    """

    strategy: SigningStrategy
    client_key: PrivateKeyTypes | None


@dataclass
class SigningSettings:
    """Configuração de assinatura do client_assertion JWT.

    Attributes:
        private_key_pem: caminho da chave privada PEM; exclusivo com
            ``signing_strategy``.
        private_key_password: senha da chave privada PEM (``None`` se não
            criptografada). É consumida: repassada a ``pem_loader``, que
            zera o array ao final de ``resolve()``, em sucesso ou erro. O
            chamador não deve reutiliza-la.
        signing_strategy: estratégia de assinatura própria (HSM, cofre de
            segredos); exclusiva com ``private_key_pem``.
        jwt_algorithm: algoritmo JWT do client_assertion.

    Nota: esta classe NÃO tem um campo ``key_id``. O identificador de chave
    (``kid``) do header do JWT e configurado exclusivamente via
    ``SmartTokenClientBuilder.key_id()`` -- é o builder quem mantém esse
    valor vivo até a construção do ``SmartTokenClient``. Uma versão anterior
    desta classe expunha um campo ``key_id`` que nunca produzia efeito
    algum (``resolve()`` nunca o lia, e o builder nunca o repassava para
    cá); foi removido para não sugerir, de forma enganosa, que configurar
    ``SigningSettings(key_id=...)`` diretamente teria algum efeito.
    """

    private_key_pem: Path | None = None
    private_key_password: bytearray | None = None
    signing_strategy: SigningStrategy | None = None
    jwt_algorithm: str = DEFAULT_JWT_ALGORITHM

    def resolve(self) -> ResolvedSigning:
        """Resolve a estratégia de assinatura efetiva.

        Quando a chave vem de arquivo PEM, a estratégia é criada a partir do
        algoritmo JWT configurado e a chave carregada fica disponível para
        uso em mTLS.

        Returns:
            A estratégia efetiva e, quando aplicável, a chave privada
            carregada do PEM.

        Raises:
            ValueError: se ambas ou nenhuma das fontes de assinatura forem
                definidas.
            SmartTokenError: se o arquivo PEM não puder ser carregado.
        """
        if self.signing_strategy is not None:
            if self.private_key_pem is not None:
                raise ValueError("Defina signing_strategy OU private_key_pem, não ambos")
            return ResolvedSigning(self.signing_strategy, None)
        if self.private_key_pem is None:
            raise ValueError("E obrigatório definir signing_strategy ou private_key_pem")
        client_key = pem_loader.load_private_key(self.private_key_pem, self.private_key_password)
        strategy = strategy_factory.from_private_key(client_key, self.jwt_algorithm)
        return ResolvedSigning(strategy, client_key)

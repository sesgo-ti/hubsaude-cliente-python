"""Excecoes de dominio do hubsaude_client.

Portado de SmartTokenException.java e SigningException.java.
"""

from __future__ import annotations


class SmartTokenError(RuntimeError):
    """Excecao de dominio para operacoes utilitarias do cliente SMART.

    Sinaliza falhas de parsing de PEM/JSON ou respostas inesperadas do
    servidor de autorizacao, preservando a causa original (``__cause__``)
    para facilitar o diagnostico.

    Equivalente Python de ``SmartTokenException`` (Java), que estende
    ``RuntimeException``. Em Python, o equivalente mais proximo de uma
    excecao nao-verificada e ``RuntimeError``; o sufixo ``Error`` segue a
    convencao da stdlib (``ValueError``, ``KeyError``).
    """

    def __init__(self, message: str, cause: BaseException | None = None) -> None:
        """Cria a excecao, preservando a causa original quando houver.

        Args:
            message: descricao da falha.
            cause: excecao original que motivou esta; ``None`` quando nao
                ha causa a preservar. Quando fornecida, fica disponivel em
                ``__cause__`` (equivalente ao construtor com ``Throwable
                cause`` do Java).
        """
        super().__init__(message)
        if cause is not None:
            self.__cause__ = cause


class SigningError(RuntimeError):
    """Excecao de dominio para falhas durante operacao de assinatura digital.

    Usada por implementacoes de ``SigningStrategy`` para encapsular erros
    criptograficos de forma consistente, independente da fonte da chave
    (memoria, HSM, cofre de segredos).

    Equivalente Python de ``SigningException`` (Java).
    """

    def __init__(self, message: str, cause: BaseException | None = None) -> None:
        """Cria a excecao, preservando a causa original quando houver.

        Args:
            message: descricao da falha.
            cause: excecao original que motivou esta; ``None`` quando nao
                ha causa a preservar.
        """
        super().__init__(message)
        if cause is not None:
            self.__cause__ = cause

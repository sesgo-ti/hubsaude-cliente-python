"""Excecoes de dominio do hubsaude_client.

Portado de SmartTokenException.java.
"""

from __future__ import annotations


class SmartTokenException(RuntimeError):
    """Excecao de dominio para operacoes utilitarias do cliente SMART.

    Sinaliza falhas de parsing de PEM/JSON ou respostas inesperadas do
    servidor de autorizacao, preservando a causa original (``__cause__``)
    para facilitar o diagnostico.

    Equivalente Python de ``SmartTokenException`` (Java), que estende
    ``RuntimeException``. Em Python, o equivalente mais proximo de uma
    excecao nao-verificada e ``RuntimeError``.
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

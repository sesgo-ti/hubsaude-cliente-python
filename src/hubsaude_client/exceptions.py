"""Exceções de domínio do hubsaude_client.

O nome oficial da exceção-base e ``SmartTokenError``, NÃO
``SmartTokenException``, seguindo a convenção Python de sufixo ``Error``
(análoga a ``ValueError``/``KeyError``). E usada por ``algorithms.py``
e pelos demais módulos da biblioteca.
"""

from __future__ import annotations


class SmartTokenError(RuntimeError):
    """Exceção de domínio para operações utilitárias do cliente SMART.

    Sinaliza falhas de parsing de PEM/JSON ou respostas inesperadas do
    servidor de autorização, preservando a causa original (``__cause__``)
    para facilitar o diagnóstico. Segue a convenção da stdlib para
    exceções de domínio (sufixo ``Error``, como ``ValueError``/``KeyError``).
    """

    def __init__(self, message: str, cause: BaseException | None = None) -> None:
        """Cria a exceção, preservando a causa original quando houver.

        Args:
            message: descrição da falha.
            cause: exceção original que motivou esta; ``None`` quando não
                há causa a preservar. Quando fornecida, fica disponível em
                ``__cause__`` para facilitar o diagnóstico.
        """
        super().__init__(message)
        if cause is not None:
            self.__cause__ = cause


class SigningError(RuntimeError):
    """Exceção de domínio para falhas durante operação de assinatura digital.

    Usada por implementações de ``SigningStrategy`` para encapsular erros
    criptográficos de forma consistente, independente da fonte da chave
    (memória, HSM, cofre de segredos).
    """

    def __init__(self, message: str, cause: BaseException | None = None) -> None:
        """Cria a exceção, preservando a causa original quando houver.

        Args:
            message: descrição da falha.
            cause: exceção original que motivou esta; ``None`` quando não
                há causa a preservar.
        """
        super().__init__(message)
        if cause is not None:
            self.__cause__ = cause

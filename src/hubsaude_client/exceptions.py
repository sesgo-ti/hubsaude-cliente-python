"""Excecoes de dominio do hubsaude_client.

Nota de decisao (QA intermediario do roadmap de port Java -> Python):
o nome oficial da excecao-base e ``SmartTokenError``, NAO
``SmartTokenException``. A F3 original do roadmap previa
``SmartTokenException``, mas a implementacao real -- ja consumida por
``algorithms.py`` e pelos testes da Fatia A -- usa ``SmartTokenError``,
seguindo a convencao Python de sufixo ``Error`` (analoga a
``ValueError``/``KeyError``). Renomear geraria retrabalho cruzado
desnecessario entre as Fatias A e B; a decisao foi formalizada sem
mudanca de codigo. Nao "corrigir" o nome de volta para
``SmartTokenException``.
"""

from __future__ import annotations


class SmartTokenError(RuntimeError):
    """Excecao de dominio para operacoes utilitarias do cliente SMART.

    Sinaliza falhas de parsing de PEM/JSON ou respostas inesperadas do
    servidor de autorizacao, preservando a causa original (``__cause__``)
    para facilitar o diagnostico. Segue a convencao da stdlib para
    excecoes de dominio (sufixo ``Error``, como ``ValueError``/``KeyError``).
    """

    def __init__(self, message: str, cause: BaseException | None = None) -> None:
        """Cria a excecao, preservando a causa original quando houver.

        Args:
            message: descricao da falha.
            cause: excecao original que motivou esta; ``None`` quando nao
                ha causa a preservar. Quando fornecida, fica disponivel em
                ``__cause__`` para facilitar o diagnostico.
        """
        super().__init__(message)
        if cause is not None:
            self.__cause__ = cause


class SigningError(RuntimeError):
    """Excecao de dominio para falhas durante operacao de assinatura digital.

    Usada por implementacoes de ``SigningStrategy`` para encapsular erros
    criptograficos de forma consistente, independente da fonte da chave
    (memoria, HSM, cofre de segredos).
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

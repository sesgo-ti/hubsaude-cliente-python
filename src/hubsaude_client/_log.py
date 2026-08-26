"""Logger compartilhado por todos os colaboradores internos da lib.

Contrato de observabilidade: quem filtra logs de fora filtra por
"hubsaude_client.SmartTokenClient", nao por modulo interno individual
(error_classifier, response_guard, discovery, etc). Isso preserva o
mesmo comportamento do .java original, onde os colaboradores internos
usam o logger compartilhado da classe publica em vez de logger proprio
por classe:

    /**
     * Logger compartilhado com {@link SmartTokenClient}: este colaborador e
     * detalhe interno de implementacao e o contrato de observabilidade
     * (filtros de log por nome da classe publica) deve permanecer estavel.
     */

Nenhum modulo desta biblioteca deve chamar ``logging.getLogger(__name__)``
diretamente -- todos importam ``get_logger()`` daqui.
"""

from __future__ import annotations

import logging

#: Nome fixo do logger compartilhado -- estavel independente de como a
#: implementacao interna e dividida em modulos.
LOGGER_NAME = "hubsaude_client.SmartTokenClient"


def get_logger() -> logging.Logger:
    """Retorna o logger compartilhado. Nao criar loggers com __name__."""
    return logging.getLogger(LOGGER_NAME)

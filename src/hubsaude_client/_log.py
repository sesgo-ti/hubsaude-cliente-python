"""Logger compartilhado por todos os colaboradores internos da lib.

Contrato de observabilidade: quem filtra logs de fora filtra por
"hubsaude_client.SmartTokenClient", não por módulo interno individual
(error_classifier, response_guard, discovery, etc). Um logger por módulo
interno vazaria um detalhe de implementação (em qual módulo o log foi
emitido) para um contrato que deve permanecer estável mesmo que a
implementação interna seja reorganizada entre módulos.

Nenhum módulo desta biblioteca deve chamar ``logging.getLogger(__name__)``
diretamente -- todos importam ``get_logger()`` daqui.
"""

from __future__ import annotations

import logging

#: Nome fixo do logger compartilhado -- estável independente de como a
#: implementação interna e dividida em módulos.
LOGGER_NAME = "hubsaude_client.SmartTokenClient"


def get_logger() -> logging.Logger:
    """Retorna o logger compartilhado. Não criar loggers com __name__."""
    return logging.getLogger(LOGGER_NAME)

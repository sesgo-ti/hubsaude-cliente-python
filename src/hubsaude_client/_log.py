"""Logger compartilhado por todos os colaboradores internos da lib.

Contrato de observabilidade: quem filtra logs de fora filtra por
"hubsaude_client.SmartTokenClient", nao por modulo interno individual
(error_classifier, response_guard, discovery, etc). Um logger por modulo
interno vazaria um detalhe de implementacao (em qual modulo o log foi
emitido) para um contrato que deve permanecer estavel mesmo que a
implementacao interna seja reorganizada entre modulos.

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

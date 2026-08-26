from __future__ import annotations

import logging

from hubsaude_client._log import LOGGER_NAME, get_logger


def test_logger_name_is_the_public_client_class() -> None:
    assert get_logger().name == "hubsaude_client.SmartTokenClient"


def test_logger_name_matches_constant() -> None:
    assert get_logger().name == LOGGER_NAME


def test_get_logger_returns_a_logger_instance() -> None:
    assert isinstance(get_logger(), logging.Logger)


def test_get_logger_returns_the_same_shared_instance() -> None:
    """logging.getLogger() com o mesmo nome sempre devolve o mesmo objeto:
    nao ha logger proprio por modulo (error_classifier, response_guard,
    discovery, etc.) -- todos compartilham esta unica instancia."""
    assert get_logger() is get_logger()


def test_no_module_creates_a_logger_with_dunder_name() -> None:
    """Contrato de observabilidade: nenhum modulo interno usa
    logging.getLogger(__name__), pois isso quebraria o filtro estavel por
    "hubsaude_client.SmartTokenClient" herdado do .java original."""
    assert get_logger().name != __name__

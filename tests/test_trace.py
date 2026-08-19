from __future__ import annotations

import re

import pytest

from hubsaude_client.trace import TraceContext

_HEX32 = re.compile(r"^[0-9a-f]{32}$")
_HEX16 = re.compile(r"^[0-9a-f]{16}$")


def test_traceparent_header_name() -> None:
    assert TraceContext.TRACEPARENT_HEADER == "traceparent"


def test_generate_produces_well_formed_ids() -> None:
    ctx = TraceContext.generate()
    assert _HEX32.match(ctx.trace_id)
    assert _HEX16.match(ctx.span_id)


def test_generate_never_all_zeros() -> None:
    for _ in range(200):
        ctx = TraceContext.generate()
        assert ctx.trace_id != "0" * 32
        assert ctx.span_id != "0" * 16


def test_generate_is_unique_across_calls() -> None:
    contexts = {(TraceContext.generate().trace_id, TraceContext.generate().span_id) for _ in range(50)}
    # Cada chamada gera um par novo; nao deve haver colisao em 50 amostras.
    assert len(contexts) == 50


def test_traceparent_format() -> None:
    ctx = TraceContext(trace_id="a" * 32, span_id="b" * 16)
    assert ctx.traceparent() == f"00-{'a' * 32}-{'b' * 16}-00"


def test_traceparent_matches_w3c_pattern() -> None:
    ctx = TraceContext.generate()
    pattern = re.compile(r"^00-[0-9a-f]{32}-[0-9a-f]{16}-00$")
    assert pattern.match(ctx.traceparent())


@pytest.mark.parametrize(
    "trace_id",
    [
        "0" * 32,  # todo-zeros: invalido
        "a" * 31,  # curto demais
        "a" * 33,  # longo demais
        "A" * 32,  # maiusculo: invalido
        "g" * 32,  # caractere fora do alfabeto hex
    ],
)
def test_invalid_trace_id_raises(trace_id: str) -> None:
    with pytest.raises(ValueError, match="trace-id inv"):
        TraceContext(trace_id=trace_id, span_id="b" * 16)


@pytest.mark.parametrize(
    "span_id",
    [
        "0" * 16,  # todo-zeros: invalido
        "b" * 15,  # curto demais
        "b" * 17,  # longo demais
        "B" * 16,  # maiusculo: invalido
        "g" * 16,  # caractere fora do alfabeto hex
    ],
)
def test_invalid_span_id_raises(span_id: str) -> None:
    with pytest.raises(ValueError, match="span-id inv"):
        TraceContext(trace_id="a" * 32, span_id=span_id)


def test_is_frozen_dataclass() -> None:
    ctx = TraceContext.generate()
    with pytest.raises(AttributeError):
        ctx.trace_id = "x" * 32  # type: ignore[misc]

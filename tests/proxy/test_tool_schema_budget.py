"""A tight context window must cost toolset breadth, never the whole run.

airecon always sent all 35 tool schemas (ranking reorders but never prunes), so
the mandatory payload alone (~76KB) overflowed small windows and raised
ContextBudgetError before any compression could run. fit_tools_to_budget sheds
the lowest-ranked OPTIONAL schemas while keeping the core set.
"""
from __future__ import annotations

import json

import pytest

from airecon.proxy.context_budget import (
    CORE_TOOL_NAMES,
    ContextBudgetError,
    fit_tools_to_budget,
    request_chars,
)


def _tool(name: str, pad: int = 0) -> dict:
    return {
        "type": "function",
        "function": {
            "name": name,
            "description": "x" * pad,
            "parameters": {"type": "object", "properties": {}},
        },
    }


def _names(tools: list[dict]) -> list[str]:
    return [t["function"]["name"] for t in tools]


@pytest.fixture
def messages():
    return [
        {"role": "system", "content": "S" * 2000},
        {"role": "user", "content": "start deep recon on target example.com"},
    ]


def test_returns_all_tools_when_already_fitting(messages):
    tools = [_tool("execute"), _tool("opt_a"), _tool("opt_b")]
    assert fit_tools_to_budget(messages, tools, 10_000_000) == tools


def test_prunes_lowest_ranked_tail_first(messages):
    # Rank order: most relevant first. Tail must go first.
    tools = [_tool("execute"), _tool("rank_hi", 400), _tool("rank_lo", 400)]
    budget = request_chars(messages, [_tool("execute"), _tool("rank_hi", 400)])
    kept = _names(fit_tools_to_budget(messages, tools, budget))
    assert kept == ["execute", "rank_hi"]


def test_core_tools_are_never_pruned(messages):
    tools = [_tool(n, 300) for n in CORE_TOOL_NAMES] + [
        _tool("optional_x", 3000),
        _tool("optional_y", 3000),
    ]
    # Budget far below even the core set.
    kept = _names(fit_tools_to_budget(messages, tools, 1))
    assert kept == list(CORE_TOOL_NAMES)
    assert "optional_x" not in kept and "optional_y" not in kept


def test_optional_tools_dropped_before_core_regardless_of_position(messages):
    # An optional tool sitting BEFORE core tools is still the one dropped.
    tools = [_tool("optional_big", 4000), _tool("execute", 100), _tool("read_file", 100)]
    kept = _names(fit_tools_to_budget(messages, tools, 3000))
    assert "optional_big" not in kept
    assert kept == ["execute", "read_file"]


def test_result_actually_fits_the_budget(messages):
    tools = [_tool("execute", 100)] + [_tool(f"opt_{i}", 900) for i in range(20)]
    budget = request_chars(messages, [_tool("execute", 100)]) + 2500
    kept = fit_tools_to_budget(messages, tools, budget)
    assert request_chars(messages, kept) <= budget
    assert "execute" in _names(kept)


def test_no_budget_in_force_is_a_passthrough(messages):
    tools = [_tool("execute"), _tool("opt_a")]
    assert fit_tools_to_budget(messages, tools, 0) == tools
    assert fit_tools_to_budget(messages, tools, -1) == tools


def test_empty_tools_is_safe(messages):
    assert fit_tools_to_budget(messages, [], 500) == []
    assert fit_tools_to_budget(messages, None, 500) == []


def test_tool_result_messages_are_not_mandatory(messages):
    # Tool results are compressible, so they must not inflate the mandatory set
    # and must not trigger pruning on their own.
    tools = [_tool("execute"), _tool("opt_a", 200)]
    base = request_chars(messages, tools)
    noisy = messages + [
        {"role": "tool", "tool_call_id": "c1", "content": "Z" * 50_000},
        {"role": "user", "content": "Y" * 50_000, "_tool_result": True},
    ]
    assert fit_tools_to_budget(noisy, tools, base) == tools


def test_real_toolset_fits_a_small_window_after_pruning(messages):
    """The regression that mattered: 35 real schemas in a tight budget."""
    from airecon.proxy.agent.tool_defs import get_tool_definitions

    tools = get_tool_definitions()
    full = request_chars(messages, tools)
    budget = full // 2
    kept = fit_tools_to_budget(messages, tools, budget)
    assert request_chars(messages, kept) <= budget
    assert len(kept) < len(tools)
    # Core survives, so the agent can still run commands and report findings.
    for core in ("execute", "create_vulnerability_report"):
        assert core in _names(kept)


def test_pack_history_no_longer_raises_once_tools_are_fitted(messages, tmp_path):
    from airecon.proxy.context_budget import ArtifactCompressor, pack_history
    from airecon.proxy.agent.tool_defs import get_tool_definitions

    tools = get_tool_definitions()
    budget = request_chars(messages, tools) // 2
    compressor = ArtifactCompressor(tmp_path, "s")

    with pytest.raises(ContextBudgetError):
        pack_history(messages, tools, budget, compressor)

    fitted = fit_tools_to_budget(messages, tools, budget)
    packed = pack_history(messages, fitted, budget, compressor)
    assert request_chars(packed, fitted) <= budget


def test_never_prunes_to_an_empty_toolset(messages):
    """An agent with zero tools answers from imagination — fail loudly instead."""
    huge = [_tool("not_core", 70_000)]
    kept = fit_tools_to_budget(messages, huge, 10)
    assert kept == huge, "irreducible schema must survive so pack_history raises"


def test_pruning_does_not_mutate_the_caller_registry(messages):
    tools = [_tool("execute"), _tool("opt_a", 4000), _tool("opt_b", 4000)]
    snapshot = json.dumps(tools, sort_keys=True)
    fit_tools_to_budget(messages, tools, 2000)
    assert json.dumps(tools, sort_keys=True) == snapshot

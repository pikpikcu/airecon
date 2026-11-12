"""The live token estimate must measure the request that is actually sent."""
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from airecon.proxy.config import DEFAULT_CONFIG
from airecon.proxy.context_budget import CORE_TOOL_NAMES, estimate_request_tokens


@pytest.fixture
def agent(monkeypatch, tmp_path):
    from airecon.proxy.agent.loop import AgentLoop

    cfg = SimpleNamespace(**DEFAULT_CONFIG)
    for module in ("loop", "loop_context", "models"):
        monkeypatch.setattr(f"airecon.proxy.agent.{module}.get_config", lambda: cfg)
    monkeypatch.setattr("airecon.proxy.config._workspace_root_cache", tmp_path)
    loop = AgentLoop(llm=MagicMock(), engine=MagicMock())
    loop.state.active_target = "fixture.test"
    loop.state.conversation = [
        {"role": "system", "content": "Only authorized fixture scope."},
        {"role": "user", "content": "Summarize the local fixture."},
        {"role": "assistant", "content": "Fixture summary."},
    ]
    return loop


def test_live_estimate_uses_the_budgeted_schema_list(agent):
    from airecon.proxy.agent.tool_defs import get_tool_definitions

    tools = get_tool_definitions()
    core = [tool for tool in tools if tool["function"]["name"] in CORE_TOOL_NAMES]
    assert len(core) < len(tools)
    agent._tools_llm = tools
    agent._tools_budgeted = core

    used = agent._recompute_used_tokens_from_conversation()

    assert used == estimate_request_tokens(agent._messages_for_llm(), core)
    assert used < estimate_request_tokens(agent.state.conversation, tools)


def test_live_estimate_falls_back_to_the_full_registry_before_budgeting(agent):
    from airecon.proxy.agent.tool_defs import get_tool_definitions

    agent._tools_llm = get_tool_definitions()
    agent._tools_budgeted = None

    used = agent._recompute_used_tokens_from_conversation()

    assert used == estimate_request_tokens(agent._messages_for_llm(), agent._tools_llm)

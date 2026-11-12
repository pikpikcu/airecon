"""Budget the exact latest group as well as instructions and tool schemas."""
from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from airecon.proxy.config import DEFAULT_CONFIG
from airecon.proxy.context_budget import request_chars


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
        {"role": "user", "content": "Read the local fixture exactly."},
    ]
    return loop


@pytest.mark.asyncio
async def test_optional_schemas_leave_headroom_for_exact_latest_read(agent):
    from airecon.proxy.agent.tool_defs import get_tool_definitions

    agent._tools_llm = get_tool_definitions()
    registry_before = json.dumps(agent._tools_llm, sort_keys=True)
    floor = request_chars(agent.state.conversation, agent._tools_llm)
    context = (floor + 1502) // 3 + 1024 + 256
    exact = "fixture bytes " * 450
    agent.state.conversation.extend([
        {"role": "assistant", "content": "", "tool_calls": [{
            "id": "read_1", "function": {"name": "read_file", "arguments": {"path": "fixture.txt"}},
        }]},
        {"role": "tool", "name": "read_file", "tool_call_id": "read_1", "content": exact},
    ])

    await agent._enforce_char_budget(context, 1024)

    assert request_chars(agent.state.conversation, agent._tools_budgeted) <= (context - 1280) * 3
    assert len(agent._tools_budgeted) < len(agent._tools_llm)
    assert agent.state.conversation[-1]["content"] == exact
    assert json.dumps(agent._tools_llm, sort_keys=True) == registry_before


def test_backend_recovery_can_shed_optional_schemas(agent):
    from airecon.proxy.agent.tool_defs import get_tool_definitions

    agent._tools_llm = get_tool_definitions()
    exact = "fixture bytes " * 450
    agent.state.conversation.extend([
        {"role": "assistant", "content": "", "tool_calls": [{
            "id": "read_1", "function": {"name": "read_file", "arguments": {"path": "fixture.txt"}},
        }]},
        {"role": "tool", "name": "read_file", "tool_call_id": "read_1", "content": exact},
    ])
    before = request_chars(agent._messages_for_llm(), agent._tools_llm)

    assert agent._recover_context_budget(1024)

    assert request_chars(agent.state.conversation, agent._tools_budgeted) < before
    assert len(agent._tools_budgeted) < len(agent._tools_llm)
    assert any(message.get("content") == exact for message in agent.state.conversation)


def test_recovery_output_cap_never_drops_below_fit_floor(agent):
    """The learned cap must be a value _fit_num_predict_to_ctx can honour.

    The fitter floors every request at 256 output tokens, so a smaller cap is
    sent to the provider while 256 is what the byte budget actually reserves.
    """
    agent._tools_llm = []
    agent.state.conversation.extend([
        {"role": "assistant", "content": "", "tool_calls": [{
            "id": "exec_1", "function": {"name": "execute", "arguments": {"command": "fixture"}},
        }]},
        {"role": "tool", "name": "execute", "tool_call_id": "exec_1", "content": "row " * 5000},
    ])

    assert agent._recover_context_budget(256)

    cap = agent._adaptive_num_predict_cap
    assert cap == agent._fit_num_predict_to_ctx(cap, 8192)


def _wire(agent):
    from airecon.proxy.llm import _to_openai_messages

    return _to_openai_messages(agent._messages_for_llm())


@pytest.mark.parametrize("role", ["tool", "user"])
@pytest.mark.asyncio
async def test_appended_exact_read_survives_budget_in_both_result_roles(agent, role):
    """read_file identity must survive the user-role fallback, not only role=tool."""
    from airecon.proxy.agent import loop_context
    from airecon.proxy.agent.tool_defs import get_tool_definitions

    loop_context.get_config().tool_response_role = role
    agent._tools_llm = get_tool_definitions()
    floor = request_chars(agent.state.conversation, agent._tools_llm)
    context = (floor + 1502) // 3 + 1024 + 256
    exact = "fixture bytes " * 450
    call = {"role": "assistant", "content": "Reading fixture.txt"}
    if role == "tool":
        call = {"role": "assistant", "content": "", "tool_calls": [{
            "id": "read_1", "function": {"name": "read_file", "arguments": {"path": "fixture.txt"}},
        }]}
    agent.state.conversation.append(call)
    agent._append_tool_result("read_file", exact, True, "read_1")
    appended = agent.state.conversation[-1]["content"]
    assert exact in appended

    await agent._enforce_char_budget(context, 1024)

    result = agent.state.conversation[-1]
    assert result.get("name") == "read_file"
    assert result["content"] == appended
    assert not result.get("_context_ref")
    assert request_chars(agent._messages_for_llm(), agent._tools_budgeted) <= (context - 1280) * 3
    wire = _wire(agent)
    assert exact in wire[-1]["content"]
    assert all("name" not in message for message in wire if message["role"] == "user")

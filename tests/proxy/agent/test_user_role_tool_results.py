from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from airecon.proxy.config import DEFAULT_CONFIG
from airecon.proxy.context_budget import request_chars


@pytest.fixture
def agent(monkeypatch, tmp_path):
    from airecon.proxy.agent.loop import AgentLoop

    cfg = SimpleNamespace(**DEFAULT_CONFIG)
    cfg.tool_response_role = "user"
    for module in ("loop", "loop_context", "models"):
        monkeypatch.setattr(f"airecon.proxy.agent.{module}.get_config", lambda: cfg)
    monkeypatch.setattr("airecon.proxy.config._workspace_root_cache", tmp_path)
    loop = AgentLoop(llm=MagicMock(), engine=MagicMock())
    loop._tools_llm = []
    loop.state.active_target = "fixture.test"
    loop.state.conversation = [
        {"role": "system", "content": "Only authorized fixture scope."},
        {"role": "user", "content": "Audit fixture.test only."},
    ]
    return loop


def _call(cid: str, name: str = "nmap") -> dict:
    return {
        "role": "assistant",
        "content": "",
        "tool_calls": [{"id": cid, "function": {"name": name, "arguments": {}}}],
    }


def _num_ctx_for_budget(budget: int, num_predict: int = 1024) -> int:
    return (budget + num_predict + 256 + 2) // 3 + num_predict + 256


def test_user_role_result_stub_points_at_following_message(agent):
    agent.state.conversation.append(_call("call_u1"))
    agent._append_tool_result("nmap", "22/tcp open ssh", True, "call_u1")

    msgs = agent._messages_for_llm()

    stubs = [m for m in msgs if m.get("role") == "tool" and m.get("tool_call_id") == "call_u1"]
    assert stubs, "a role=tool message must still follow the assistant tool_call"
    assert "unavailable" not in str(stubs[0]["content"]).lower(), (
        "the result exists in the next message; the stub must not claim it is unavailable"
    )
    assert "next message" in str(stubs[0]["content"]).lower()
    idx = msgs.index(stubs[0])
    following = msgs[idx + 1]
    assert following.get("_tool_result") and "22/tcp open ssh" in following["content"]


def test_genuinely_missing_result_keeps_unavailable_stub(agent):
    agent.state.conversation.append(_call("call_missing"))

    msgs = agent._messages_for_llm()

    stubs = [
        m for m in msgs
        if m.get("role") == "tool" and m.get("tool_call_id") == "call_missing"
    ]
    assert stubs and "unavailable" in str(stubs[0]["content"]).lower()


def test_multiple_calls_pair_with_user_results_by_order(agent):
    agent.state.conversation.append({
        "role": "assistant", "content": "",
        "tool_calls": [
            {"id": "call_a", "function": {"name": "nmap", "arguments": {}}},
            {"id": "call_b", "function": {"name": "httpx", "arguments": {}}},
        ],
    })
    agent._append_tool_result("nmap", "result A", True, "call_a")
    agent._append_tool_result("httpx", "result B", True, "call_b")

    msgs = agent._messages_for_llm()
    for cid in ("call_a", "call_b"):
        stub = next(m for m in msgs if m.get("role") == "tool" and m.get("tool_call_id") == cid)
        assert "unavailable" not in str(stub["content"]).lower()


def test_default_tool_role_behavior_unchanged(agent):
    from airecon.proxy.agent import loop_context

    loop_context.get_config().tool_response_role = "tool"

    agent.state.conversation.append(_call("call_t1"))
    agent._append_tool_result("nmap", "80/tcp open http", True, "call_t1")

    msgs = agent._messages_for_llm()

    tools = [m for m in msgs if m.get("role") == "tool" and m.get("tool_call_id") == "call_t1"]
    assert len(tools) == 1
    assert "80/tcp open http" in tools[0]["content"]
    assert "unavailable" not in str(tools[0]["content"]).lower()


@pytest.mark.asyncio
async def test_enforced_budget_holds_for_projected_request(agent):
    agent.state.conversation.append(_call("call_u1"))
    agent._append_tool_result("nmap", "user-role evidence page " * 600, True, "call_u1")

    tools = agent._tools_llm
    stored = request_chars(agent.state.conversation, tools)
    projected = request_chars(agent._messages_for_llm(), tools)
    assert projected > stored, "fixture must exercise the projection overhead"

    budget = stored + 20
    assert stored <= budget < projected
    agent._context_char_budget = budget
    await agent._enforce_char_budget(num_ctx=65536, num_predict=1024)

    sent_tools = getattr(agent, "_tools_budgeted", None) or tools
    actual = request_chars(agent._messages_for_llm(), sent_tools)
    assert actual <= budget, (
        f"projected request {actual} exceeds budget {budget}: "
        "budgeting must account for bytes _messages_for_llm() adds"
    )


@pytest.mark.asyncio
async def test_second_budget_pass_is_fixed_point(agent):
    from airecon.proxy.context_budget import _minimum_request_messages

    tools = [
        {
            "type": "function",
            "function": {
                "name": "execute" if i == 0 else f"opt_tool_{i:02d}",
                "description": "opt padding " * 4,
                "parameters": {"type": "object", "properties": {}},
            },
        }
        for i in range(40)
    ]
    agent._tools_llm = tools

    for i in range(30):
        agent.state.conversation.append(_call(f"call_old_{i}", "nmap"))
        agent._append_tool_result(
            "nmap", f"older scan evidence {i} " * 250, True, f"call_old_{i}"
        )
    agent.state.conversation.append(_call("call_latest", "read_file"))
    agent._append_tool_result(
        "read_file", "exact latest file page\n" * 60, True, "call_latest"
    )

    minimum = _minimum_request_messages(agent.state.conversation)
    repaired_minimum = type(agent.state)._repair_tool_pairs(list(minimum))
    stable_overhead = max(
        0, request_chars(repaired_minimum, tools) - request_chars(minimum, tools)
    )

    budget = request_chars(minimum, tools[:25]) + stable_overhead + 400
    agent._context_char_budget = budget

    await agent._enforce_char_budget(num_ctx=65536, num_predict=1024)

    conversation_1 = [dict(m) for m in agent.state.conversation]
    schemas_1 = list(agent._tools_budgeted)
    assert len(schemas_1) < len(tools), "fixture must force optional schemas out"
    surviving_calls = {
        call.get("id")
        for m in conversation_1
        for call in (m.get("tool_calls") or [])
    }
    assert surviving_calls == {"call_latest"}, (
        "fixture must force eviction of every older group"
    )
    assert request_chars(agent._messages_for_llm(), schemas_1) <= budget

    await agent._enforce_char_budget(num_ctx=65536, num_predict=1024)

    assert agent.state.conversation == conversation_1, (
        "a second budget pass on an already-packed history must change nothing"
    )
    assert agent._tools_budgeted == schemas_1, (
        "a second budget pass must not re-admit evicted optional schemas "
        f"({len(agent._tools_budgeted)} vs {len(schemas_1)})"
    )
    assert request_chars(agent._messages_for_llm(), agent._tools_budgeted) <= budget


@pytest.mark.asyncio
async def test_recovered_budget_shrinks_projected_request(agent):
    for i in range(4):
        agent.state.conversation.append(_call(f"call_{i}"))
        agent._append_tool_result("nmap", f"user-role evidence page {i} " * 400, True, f"call_{i}")

    sent_tools = getattr(agent, "_tools_budgeted", None) or agent._tools_llm
    before = request_chars(agent._messages_for_llm(), sent_tools)

    assert agent._recover_context_budget(1024)

    after = request_chars(agent._messages_for_llm(), sent_tools)
    assert after < before, "recovery must shrink what is actually sent"

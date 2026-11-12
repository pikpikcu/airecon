"""The agent's request budget must measure with the ACTIVE client's replay
policy (its own model + host), exactly like ``LLMClient._wire_payload`` does,
so budget == wire by construction even when the client differs from the
global config (finding X3). Also covers the projected-request guarantee after
packing: pair-repair stubs surviving inside the reserved slack must not push
the projected request over the budget.
"""
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
    cfg.llm_provider = "openai"
    cfg.llm_reasoning_replay = "auto"
    cfg.openai_base_url = "https://gateway.example/v1"
    cfg.openai_model = "gpt-fixture"
    for module in ("loop", "loop_context", "models"):
        monkeypatch.setattr(f"airecon.proxy.agent.{module}.get_config", lambda: cfg)
    monkeypatch.setattr("airecon.proxy.llm.get_config", lambda: cfg)
    monkeypatch.setattr("airecon.proxy.config._workspace_root_cache", tmp_path)
    loop = AgentLoop(llm=MagicMock(), engine=MagicMock())
    loop.state.active_target = "fixture.test"
    loop.state.conversation = [
        {"role": "system", "content": "Only authorized fixture scope."},
        {"role": "user", "content": "Read the local fixture exactly."},
    ]
    return loop


def _group(call_id: str, content: str) -> list[dict]:
    return [
        {"role": "assistant", "content": "", "tool_calls": [{
            "id": call_id, "function": {"name": "read_file", "arguments": {"path": "fixture.txt"}},
        }]},
        {"role": "tool", "name": "read_file", "tool_call_id": call_id, "content": content},
    ]


# ---------------------------------------------------------------------------
# X3 — budget must use the active client's replay policy, not the config's.


@pytest.mark.asyncio
async def test_enforce_budget_measures_with_client_replay_policy(agent):
    agent.llm = SimpleNamespace(model="deepseek/chat", _host="https://api.deepseek.com")
    agent._tools_llm = []
    reasoning = "stored chain-of-thought evidence " * 200  # replayed on the wire
    older = _group("read_0", "older evidence page")
    older[0]["reasoning_content"] = reasoning
    latest = _group("read_1", "latest evidence page")
    agent.state.conversation.extend(older + latest)

    # Sanity: the two policies disagree on this conversation.
    without_replay = request_chars(agent.state.conversation, [], replay_reasoning=False)
    with_replay = request_chars(agent.state.conversation, [], replay_reasoning=True)
    assert with_replay > without_replay
    # Config (gpt-fixture @ gateway.example) resolves replay OFF; the client
    # (deepseek/chat @ api.deepseek.com) resolves it ON, like _wire_payload.
    # The budget exactly fits the config-policy measurement, so only the
    # client-policy measurement forces the eviction.
    budget = without_replay
    agent._context_char_budget = budget

    await agent._enforce_char_budget(65536, 1024)

    # Budget == wire: the request the client would send must fit the budget.
    projected = request_chars(agent._messages_for_llm(), agent._tools_budgeted,
                              replay_reasoning=True)
    assert projected <= budget, f"projected {projected} exceeds budget {budget}"
    assert not any(m.get("tool_call_id") == "read_0" for m in agent.state.conversation), (
        "the replay-heavy older group must be evicted under the client's policy"
    )
    # Fixed point: a second pass on the packed conversation changes nothing.
    snapshot = json.dumps(agent.state.conversation, sort_keys=True, default=str)
    await agent._enforce_char_budget(65536, 1024)
    assert json.dumps(agent.state.conversation, sort_keys=True, default=str) == snapshot


@pytest.mark.asyncio
async def test_recover_context_budget_measures_with_client_replay_policy(agent):
    agent.llm = SimpleNamespace(model="deepseek/chat", _host="https://api.deepseek.com")
    agent._tools_llm = []
    older = _group("read_0", "older evidence page " * 100)
    older[0]["reasoning_content"] = "stored chain-of-thought evidence " * 100
    latest = _group("read_1", "latest evidence page")
    agent.state.conversation.extend(older + latest)

    assert agent._recover_context_budget(2048) is True

    projected = request_chars(agent._messages_for_llm(), agent._tools_budgeted,
                              replay_reasoning=True)
    before = request_chars(
        older + latest + agent.state.conversation[:2], [], replay_reasoning=True,
    )
    assert projected < before, "recovery must shrink the wire request under the client policy"


def test_used_tokens_estimate_uses_client_replay_policy(agent):
    agent.llm = SimpleNamespace(model="deepseek/chat", _host="https://api.deepseek.com")
    agent._tools_llm = []
    agent.state.conversation.append({
        "role": "assistant", "content": "plan",
        "reasoning_content": "stored chain-of-thought evidence " * 50,
    })

    used = agent._recompute_used_tokens_from_conversation()

    projected = request_chars(agent._messages_for_llm(), [], replay_reasoning=True)
    assert used == (projected + 2) // 3


# ---------------------------------------------------------------------------
# Projected-request guarantee: pair-repair stubs surviving inside the packing
# slack must not push the projected request over the budget.


@pytest.mark.asyncio
async def test_packed_slack_with_stubs_cannot_exceed_budget(agent):
    from airecon.proxy.agent import loop_context
    from airecon.proxy.context_budget import _minimum_request_messages

    loop_context.get_config().tool_response_role = "user"
    agent.llm = SimpleNamespace(model="gpt-fixture", _host="https://gateway.example/v1")
    agent._tools_llm = []
    for i in range(6):
        agent.state.conversation.append({
            "role": "assistant", "content": "", "tool_calls": [{
                "id": f"exec_{i}",
                "function": {"name": "execute", "arguments": {"command": "echo fixture"}},
            }],
        })
        agent._append_tool_result("execute", f"older fixture output {i} " * 3, True, f"exec_{i}")
    agent.state.conversation.append({
        "role": "assistant", "content": "", "tool_calls": [{
            "id": "exec_latest",
            "function": {"name": "execute", "arguments": {"command": "scan fixture"}},
        }],
    })
    # Just over the preview stand-in threshold: the reservation holds 2400
    # wire bytes for it while the packed form stays small, leaving slack the
    # older groups (and their pair-repair stubs) can survive inside.
    agent._append_tool_result("execute", "latest scan line ok\n" * 25, True, "exec_latest")

    minimum = _minimum_request_messages(agent.state.conversation)
    reserved = request_chars(minimum, [])
    repaired = type(agent.state)._repair_tool_pairs(list(minimum))
    stable_overhead = max(0, request_chars(repaired, []) - reserved)
    budget = reserved + stable_overhead
    agent._context_char_budget = budget

    await agent._enforce_char_budget(65536, 1024)

    projected = request_chars(agent._messages_for_llm(), agent._tools_budgeted)
    assert projected <= budget, (
        f"projected {projected} exceeds budget {budget}: surviving stubs in slack"
    )
    snapshot = json.dumps(agent.state.conversation, sort_keys=True, default=str)
    await agent._enforce_char_budget(65536, 1024)
    assert json.dumps(agent.state.conversation, sort_keys=True, default=str) == snapshot

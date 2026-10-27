"""Provider-independent context contracts: retain instructions, budget the wire, recover evidence."""
from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from airecon.proxy.config import DEFAULT_CONFIG
from airecon.proxy.llm import _to_openai_messages


def pair(index, text):
    cid = f"call_{index}"
    return [
        {"role": "assistant", "content": "", "tool_calls": [{
            "id": cid, "function": {"name": "execute", "arguments": {"command": "fixture"}},
        }]},
        {"role": "tool", "name": "execute", "tool_call_id": cid, "content": text},
    ]


@pytest.fixture
def loop(monkeypatch, tmp_path):
    from airecon.proxy.agent.loop import AgentLoop
    cfg = SimpleNamespace(**DEFAULT_CONFIG)
    for module in ("loop", "loop_context", "models"):
        monkeypatch.setattr(f"airecon.proxy.agent.{module}.get_config", lambda: cfg)
    monkeypatch.setattr("airecon.proxy.config._workspace_root_cache", tmp_path)
    agent = AgentLoop(llm=MagicMock(), engine=MagicMock())
    agent._tools_llm = []
    agent.state.active_target = "example.test"
    agent.state.conversation = [
        {"role": "system", "content": "Only authorized scope; preserve exact evidence."},
        {"role": "user", "content": "Audit example.test only."},
    ]
    return agent


@pytest.mark.asyncio
async def test_recent_large_result_fits_budget_and_original_is_recoverable(loop, tmp_path):
    raw = "synthetic row " * 4000 + "\n[critical] CVE-2026-0001 https://example.test/api\n" + "tail row " * 1000
    loop.state.conversation += pair(0, raw)
    await loop._enforce_char_budget(num_ctx=8192, num_predict=1024)
    messages = _to_openai_messages(loop._messages_for_llm())
    assert len(json.dumps({"messages": messages, "tools": []}, ensure_ascii=False)) <= (8192 - 1024 - 256) * 3
    result = next(m for m in loop.state.conversation if m.get("role") == "tool")
    assert result.get("_context_ref"), "Compaction must expose a durable retrieval reference"
    assert (tmp_path / "example.test" / result["_context_ref"]).read_text() == raw
    assert "CVE-2026-0001" in result["content"]


@pytest.mark.asyncio
async def test_all_user_constraints_and_scope_survive_repeated_compaction(loop):
    followup = "Do NOT access /payments, even on example.test."
    loop.state.conversation.append({"role": "user", "content": followup})
    for i in range(12):
        loop.state.conversation.extend(pair(i, "scan noise " * 1000))
    for ctx in (16384, 8192, 4096):
        await loop._enforce_char_budget(num_ctx=ctx, num_predict=512)
        assert any(m.get("content") == followup for m in loop.state.conversation)
        assert loop.state.conversation[0]["content"] == "Only authorized scope; preserve exact evidence."
        calls = {t["id"] for m in loop.state.conversation for t in m.get("tool_calls", [])}
        results = {m["tool_call_id"] for m in loop.state.conversation if m.get("role") == "tool"}
        assert calls == results


def test_token_accounting_includes_schemas_and_call_arguments(loop):
    before = loop._recompute_used_tokens_from_conversation()
    loop._tools_llm = [{"type": "function", "function": {"name": "fixture", "description": "schema " * 2000}}]
    assert loop._recompute_used_tokens_from_conversation() > before
    before = loop._recompute_used_tokens_from_conversation()
    loop.state.conversation += pair(0, "done")
    loop.state.conversation[-2]["tool_calls"][0]["function"]["arguments"] = {"payload": "arg " * 2000}
    assert loop._recompute_used_tokens_from_conversation() > before


@pytest.mark.asyncio
async def test_irreducible_schema_stops_without_deleting_user_instructions(loop):
    original = list(loop.state.conversation)
    loop._tools_llm = [{"type": "function", "function": {"name": "fixture", "description": "schema " * 10000}}]
    with pytest.raises(RuntimeError, match="(?i)context.*budget|budget.*context"):
        await loop._enforce_char_budget(num_ctx=4096, num_predict=512)
    assert loop.state.conversation == original


@pytest.mark.asyncio
async def test_learned_budget_applies_to_future_iterations(loop):
    loop._context_char_budget = 3000
    loop.state.conversation += pair(0, "large latest result " * 2000)
    await loop._enforce_char_budget(num_ctx=65536, num_predict=512)
    wire = json.dumps({"messages": _to_openai_messages(loop._messages_for_llm()), "tools": []}, ensure_ascii=False)
    assert len(wire) <= 3000


def test_message_count_truncation_preserves_later_instructions(loop):
    constraint = {"role": "user", "content": "Never request /payments."}
    loop.state.conversation.append(constraint)
    for i in range(40):
        loop.state.conversation.extend(pair(i, "done"))
    loop.state.truncate_conversation(max_messages=12)
    assert constraint in loop.state.conversation


@pytest.mark.asyncio
async def test_llm_summary_preserves_later_instructions(loop):
    from unittest.mock import AsyncMock
    constraint = {"role": "user", "content": "Never request /payments."}
    loop.state.conversation.append(constraint)
    for i in range(20):
        loop.state.conversation.extend(pair(i, "done"))
    loop.llm.complete = AsyncMock(return_value="Older tool results summarized.")
    await loop.state.compress_with_llm(loop.llm, keep_recent=6)
    assert constraint in loop.state.conversation


def test_output_is_archived_before_entering_history(loop, tmp_path):
    raw = "progress\n" * 1000 + "[high] finding in the middle\n" + "progress\n" * 1000
    loop._append_tool_result("execute", raw, True, "call_1")
    message = loop.state.conversation[-1]
    assert "finding in the middle" in message["content"]
    assert message.get("_context_ref")
    assert (tmp_path / "example.test" / message["_context_ref"]).read_text() == raw


def test_context_recovery_shrinks_actual_payload_not_configured_window(loop):
    from airecon.proxy.context_budget import request_chars
    loop.state.conversation.extend(pair(0, "large result " * 5000))
    before = request_chars(loop._messages_for_llm(), loop._tools_llm)
    assert loop._recover_context_budget(1024)
    after = request_chars(loop._messages_for_llm(), loop._tools_llm)
    assert after < before
    assert loop._context_char_budget <= before // 2
    assert loop._adaptive_num_predict_cap <= 512


def test_learned_budget_is_part_of_saved_session(loop):
    from dataclasses import asdict
    from airecon.proxy.agent.session import SessionData
    loop._session = SessionData(target="example.test")
    loop.state.conversation.extend(pair(0, "large result " * 5000))
    assert loop._recover_context_budget(1024)
    assert asdict(loop._session)["context_char_budget"] == loop._context_char_budget


@pytest.mark.asyncio
async def test_generated_user_role_tool_output_is_not_a_user_instruction(loop):
    loop.state.conversation.append({"role": "user", "content": "tool output " * 5000, "_tool_result": True})
    await loop._enforce_char_budget(num_ctx=8192, num_predict=512)
    assert any(m.get("content") == "Audit example.test only." for m in loop.state.conversation)
    assert len(json.dumps(loop.state.conversation)) < 10000


@pytest.mark.parametrize("method", ["phase", "old", "stale"])
def test_legacy_compaction_archives_before_replacing_output(loop, method):
    raw = "INFO progress\n" * 1000 + "[critical] exact-middle-finding\n" + "INFO progress\n" * 1000
    for i in range(12):
        loop.state.conversation.extend(pair(i, raw))
    if method == "phase":
        loop._compact_phase_context("RECON")
    elif method == "old":
        loop._compress_old_tool_outputs(aggressive=True)
    else:
        loop._drop_stale_tool_results()
    changed = [m for m in loop.state.conversation if m.get("role") == "tool" and m["content"] != raw]
    assert changed
    compressor = loop._get_artifact_compressor()
    for message in changed:
        assert compressor.load(message["_context_ref"]) == raw
        assert "exact-middle-finding" in message["content"]


def test_small_output_is_archived_before_future_summary_or_message_eviction(loop):
    raw = "[high] short but important finding"
    loop._append_tool_result("execute", raw, True, "short_1")
    message = loop.state.conversation[-1]
    assert loop._get_artifact_compressor().load(message["_context_ref"]) == raw


def test_count_truncation_keeps_exact_reads_and_explicitly_protected_content():
    from unittest.mock import patch
    from airecon.proxy.agent.models import AgentState
    state = AgentState()
    raw = "Exact read content  \n" * 100
    protected = "Important protected content " * 100
    state.conversation = [{"role": "user", "content": "Scope example.test only."}]
    state.conversation.extend(pair(0, raw))
    state.conversation[-1]["name"] = "read_file"
    state.conversation[-1]["_protected"] = True
    state.conversation[-2]["_protected"] = True
    state.conversation.append({"role": "assistant", "content": protected, "_protected": True})
    for i in range(1, 201):
        state.conversation.extend(pair(i, "small result"))
    with patch("airecon.proxy.agent.models._get_context_limits", return_value={"uncompressed_keep_count": 2}):
        state.truncate_conversation(max_messages=400)
    assert any(m.get("content") == raw for m in state.conversation)
    assert any(m.get("content") == protected for m in state.conversation)


@pytest.mark.asyncio
async def test_summary_keeps_protected_context_without_duplicating_system_instructions():
    from unittest.mock import AsyncMock
    from airecon.proxy.agent.models import AgentState
    state = AgentState()
    system = {"role": "system", "content": "Protected fixture instruction.", "_protected": True}
    protected = {"role": "assistant", "content": "Important evidence.", "_protected": True}
    state.conversation = [system, {"role": "user", "content": "Never access /payments."}, protected]
    for i in range(6):
        state.conversation.extend(pair(i, "fixture output"))
    llm = AsyncMock()
    llm.model = "fixture-model"
    llm.complete.return_value = "Synthetic summary retains endpoint and confirmed evidence. " * 8
    await state.compress_with_llm(llm, keep_recent=2)
    assert sum(m == system for m in state.conversation) == 1
    assert sum(m == protected for m in state.conversation) == 1
    assert any(m.get("content") == "Never access /payments." for m in state.conversation)

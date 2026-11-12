"""Provider state must survive message conversion and tool-call replay."""
from __future__ import annotations

from airecon.proxy.llm_protocol import anthropic_messages


def test_native_anthropic_keeps_trailing_retry_as_user_turn():
    history = [
        {"role": "system", "content": "Authorized fixture only."},
        {"role": "user", "content": "Read the fixture."},
        {"role": "assistant", "content": "I will read the fixture."},
        {"role": "system", "content": "[SYSTEM: RETRY REQUIRED — TOOL CALL MISSING]"},
    ]
    system, wire = anthropic_messages(history)

    assert system == "Authorized fixture only."
    assert [message["role"] for message in wire] == ["user", "assistant", "user"]
    assert "RETRY REQUIRED" in wire[-1]["content"][0]["text"]
    assert history[-1]["role"] == "system"


def test_native_tool_use_is_not_mistaken_for_a_plain_assistant_turn():
    blocks = [
        {"type": "thinking", "thinking": "fixture", "signature": "fixture-signature"},
        {"type": "tool_use", "id": "call_native", "name": "fixture_status", "input": {}},
    ]
    system, wire = anthropic_messages([
        {"role": "user", "content": "Check fixture."},
        {"role": "assistant", "content": "", "_provider_blocks": blocks},
        {"role": "system", "content": "Keep the pending tool-use turn intact."},
    ])
    assert system == "Keep the pending tool-use turn intact."
    assert [message["role"] for message in wire] == ["user", "assistant"]
    assert wire[-1]["content"] == blocks


def test_openai_serializer_preserves_opaque_tool_metadata():
    from airecon.proxy.llm import _to_openai_messages

    extra = {"google": {"thought_signature": "fixture-signature"}, "vendor": {"opaque": [1, 2]}}
    history = [
        {"role": "user", "content": "Check fixture."},
        {"role": "assistant", "content": "", "tool_calls": [{
            "id": "call_fixture", "type": "function", "extra_content": extra,
            "function": {"name": "fixture_status", "arguments": {}},
        }]},
        {"role": "tool", "tool_call_id": "call_fixture", "content": "ok"},
    ]
    wire = _to_openai_messages(history)
    assert wire[1]["tool_calls"][0]["extra_content"] == extra
    wire[1]["tool_calls"][0]["extra_content"]["google"]["thought_signature"] = "changed"
    assert extra["google"]["thought_signature"] == "fixture-signature"


def test_explicit_reasoning_survives_history_filter_and_session_roundtrip(monkeypatch, tmp_path):
    from types import SimpleNamespace
    from typing import cast
    from airecon.proxy.agent.loop_context import _ContextMixin
    from airecon.proxy.agent.models import AgentState
    from airecon.proxy.agent.session import SessionData, load_session, save_session
    from airecon.proxy.llm import _to_openai_messages

    state = AgentState()
    state.conversation = [
        {"role": "user", "content": "Fixture only."},
        {"role": "assistant", "content": "", "thinking": "UI-only reasoning",
         "reasoning_content": "Original provider state", "tool_calls": [{
             "id": "call_fixture", "function": {"name": "fixture_status", "arguments": {}}}]},
        {"role": "tool", "tool_call_id": "call_fixture", "content": "ok"},
        {"role": "assistant", "content": "Next fixture step."},
    ]
    filtered = _ContextMixin._messages_for_llm(cast(_ContextMixin, SimpleNamespace(state=state)))
    assert "thinking" not in filtered[1]
    assert filtered[1]["reasoning_content"] == "Original provider state"
    monkeypatch.setattr("airecon.proxy.agent.session.SESSIONS_DIR", tmp_path)
    saved = SessionData(target="fixture.test", conversation=filtered)
    save_session(saved)
    restored = load_session(saved.session_id)
    assert restored is not None
    wire = _to_openai_messages(restored.conversation, replay_reasoning=True)
    assert wire[1]["reasoning_content"] == "Original provider state"


def test_plain_thinking_is_not_invented_as_provider_reasoning():
    from airecon.proxy.llm import _to_openai_messages

    wire = _to_openai_messages([{"role": "assistant", "content": "Fixture response", "thinking": "UI only"}])
    assert "thinking" not in wire[0]
    assert "reasoning_content" not in wire[0]


def test_empty_explicit_reasoning_field_is_preserved():
    from airecon.proxy.llm import _to_openai_messages

    wire = _to_openai_messages(
        [{"role": "assistant", "content": "Fixture response", "reasoning_content": ""}],
        replay_reasoning=True,
    )
    assert wire[0]["reasoning_content"] == ""


def test_missing_reasoning_history_is_not_an_unsupported_reasoning_parameter():
    from airecon.proxy.llm import LLMClient

    assert not LLMClient._is_unsupported_reasoning_error(
        400, "Invalid request: reasoning_content must be passed back on assistant tool-call turns",
    )

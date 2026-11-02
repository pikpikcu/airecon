"""Regression tests for trailing system text at the wire boundary.

The reflector appends its retry prompt with role ``system`` after a
text-only assistant turn. Hoisting that text into the leading system block
left the request ending on the assistant's own turn, which current Claude
models reject with a 400 (prefilled-assistant rejection) and the agent
treats as non-retryable, ending the run. Trailing system text after a
plain assistant turn must instead ride at the end as a user turn.
"""

from __future__ import annotations

from airecon.proxy.llm import _to_openai_messages


def test_trailing_system_after_assistant_becomes_final_user_turn():
    # The issue's reproduction: a text-only turn, then the reflector's
    # retry prompt appended as a system message.
    convo = [
        {"role": "system", "content": "You are AIRecon."},
        {"role": "user", "content": "assess example.test"},
        {"role": "assistant", "content": "I will start with the login page next."},
        {"role": "system", "content": "[SYSTEM: RETRY REQUIRED — TOOL CALL MISSING]"},
    ]
    out = _to_openai_messages(convo)
    assert [m["role"] for m in out] == ["system", "user", "assistant", "user"]
    # The leading system prompt is untouched and the retry prompt is not in it.
    assert out[0]["content"] == "You are AIRecon."
    assert "RETRY REQUIRED" in out[-1]["content"]


def test_multiple_trailing_system_parts_join_into_one_user_turn():
    convo = [
        {"role": "user", "content": "go"},
        {"role": "assistant", "content": "thinking out loud"},
        {"role": "system", "content": "first note"},
        {"role": "system", "content": "second note"},
    ]
    out = _to_openai_messages(convo)
    assert [m["role"] for m in out] == ["user", "assistant", "user"]
    assert out[-1]["content"] == "first note\n\nsecond note"


def test_trailing_system_without_leading_system_still_ends_on_user():
    convo = [
        {"role": "user", "content": "go"},
        {"role": "assistant", "content": "no tools this time"},
        {"role": "system", "content": "[SYSTEM: RETRY REQUIRED — TOOL CALL MISSING]"},
    ]
    out = _to_openai_messages(convo)
    assert [m["role"] for m in out] == ["user", "assistant", "user"]
    assert "RETRY REQUIRED" in out[-1]["content"]


def test_trailing_system_after_user_turn_is_hoisted_as_before():
    # No assistant turn at the end, so nothing can be stranded: the
    # trailing system text joins the system prompt exactly as before.
    convo = [
        {"role": "system", "content": "You are AIRecon."},
        {"role": "user", "content": "assess example.test"},
        {"role": "system", "content": "extra instruction"},
    ]
    out = _to_openai_messages(convo)
    assert [m["role"] for m in out] == ["system", "user"]
    assert out[0]["content"] == "You are AIRecon.\n\nextra instruction"


def test_trailing_system_after_tool_result_is_hoisted_as_before():
    call = {
        "id": "call_1",
        "type": "function",
        "function": {"name": "execute", "arguments": '{"command": "id"}'},
    }
    convo = [
        {"role": "user", "content": "go"},
        {"role": "assistant", "content": "", "tool_calls": [call]},
        {"role": "tool", "tool_call_id": "call_1", "content": "uid=0"},
        {"role": "system", "content": "extra instruction"},
    ]
    out = _to_openai_messages(convo)
    assert [m["role"] for m in out] == ["system", "user", "assistant", "tool"]
    assert out[0]["content"] == "extra instruction"


def test_mid_conversation_system_is_still_hoisted():
    convo = [
        {"role": "user", "content": "go"},
        {"role": "system", "content": "mid instruction"},
        {"role": "assistant", "content": "working"},
        {"role": "user", "content": "next"},
    ]
    out = _to_openai_messages(convo)
    assert [m["role"] for m in out] == ["system", "user", "assistant", "user"]
    assert out[0]["content"] == "mid instruction"


def test_single_leading_system_is_returned_unchanged():
    convo = [
        {"role": "system", "content": "You are AIRecon."},
        {"role": "user", "content": "go"},
        {"role": "assistant", "content": "done"},
    ]
    out = _to_openai_messages(convo)
    assert out == convo

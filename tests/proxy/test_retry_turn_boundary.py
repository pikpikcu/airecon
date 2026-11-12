"""Regression tests for a mid-conversation retry instruction as a turn boundary.

The reflector's retry prompt arrives as a ``system`` message right after a
text-only assistant turn. While it is the *last* message it is kept at the
end as a user turn (see test_trailing_system_message.py). But once a real
assistant reply (signed thinking + tool_use) follows, the retry instruction
sits *between two assistant turns*. Hoisting it into the system prompt made
``_coalesce_system_messages`` produce two adjacent assistant messages, which
``anthropic_messages`` then merges into one turn with blocks
``[text, thinking, tool_use]`` — Anthropic requires the signed thinking
block first, so the request is rejected. The retry instruction must keep its
chronological place as a user-turn boundary in every conversion, so the two
assistant turns never merge.
"""

from __future__ import annotations

from airecon.proxy.llm import _to_openai_messages
from airecon.proxy.llm_protocol import anthropic_messages


THINKING = {"type": "thinking", "thinking": "plan the check", "signature": "sig-abc123"}
TOOL_USE = {"type": "tool_use", "id": "toolu_01", "name": "execute", "input": {"command": "id"}}


def _retry_convo() -> list[dict]:
    return [
        {"role": "system", "content": "You are AIRecon."},
        {"role": "user", "content": "assess example.test"},
        {"role": "assistant", "content": "I will start with the login page next."},
        {"role": "system", "content": "[SYSTEM: RETRY REQUIRED — TOOL CALL MISSING]"},
        {"role": "assistant", "content": "", "_provider_blocks": [dict(THINKING), dict(TOOL_USE)]},
        {"role": "tool", "tool_call_id": "toolu_01", "content": "uid=0"},
    ]


def test_openai_retry_between_assistant_turns_keeps_user_boundary():
    out = _to_openai_messages(_retry_convo())
    roles = [m["role"] for m in out]
    # The signed native assistant turn carries no text and no OpenAI
    # tool_calls, so OpenAI-side conversion drops it (pre-existing); the
    # retry instruction must still NOT be hoisted — it stays a user turn.
    assert roles == ["system", "user", "assistant", "user"]
    assert "RETRY REQUIRED" in out[3]["content"]
    assert out[0]["content"] == "You are AIRecon."


def test_openai_retry_boundary_survives_a_later_turn():
    # Same retry instruction, now with a further turn after it: the
    # boundary must be identical, not reordered by later history.
    convo = _retry_convo() + [
        {"role": "assistant", "content": "result analysed"},
    ]
    out = _to_openai_messages(convo)
    roles = [m["role"] for m in out]
    assert roles == ["system", "user", "assistant", "user", "assistant"]
    assert "RETRY REQUIRED" in out[3]["content"]
    assert out[0]["content"] == "You are AIRecon."


def test_anthropic_retry_between_assistant_turns_does_not_merge():
    system, turns = anthropic_messages(_retry_convo())
    assert system == "You are AIRecon."
    roles = [t["role"] for t in turns]
    assert roles == ["user", "assistant", "user", "assistant", "user"]
    # The first assistant turn is only its text; the retry prompt is a user turn.
    assert turns[1]["content"] == [{"type": "text", "text": "I will start with the login page next."}]
    assert "RETRY REQUIRED" in turns[2]["content"][0]["text"]


def test_anthropic_signed_thinking_stays_first_and_byte_exact():
    _, turns = anthropic_messages(_retry_convo())
    signed_turn = turns[3]
    assert signed_turn["role"] == "assistant"
    assert signed_turn["content"][0]["type"] == "thinking"
    # Byte-exact replay of the signed provider blocks, no text hoisted before them.
    assert signed_turn["content"] == [THINKING, TOOL_USE]
    # tool_result pairing is untouched.
    assert turns[4]["content"] == [
        {"type": "tool_result", "tool_use_id": "toolu_01", "content": "uid=0"}
    ]


def test_anthropic_multiple_retry_systems_join_into_one_boundary():
    convo = _retry_convo()
    convo.insert(4, {"role": "system", "content": "second retry note"})
    _, turns = anthropic_messages(convo)
    roles = [t["role"] for t in turns]
    assert roles == ["user", "assistant", "user", "assistant", "user"]
    texts = [b["text"] for b in turns[2]["content"] if b.get("type") == "text"]
    assert "RETRY REQUIRED" in texts[0]
    assert "second retry note" in texts[0]


def test_openai_two_notes_after_text_reply_join_into_one_boundary():
    convo = _retry_convo()
    convo.insert(4, {"role": "system", "content": "second retry note"})
    out = _to_openai_messages(convo)
    roles = [m["role"] for m in out]
    assert roles == ["system", "user", "assistant", "user"]
    assert "RETRY REQUIRED" in out[3]["content"]
    assert "second retry note" in out[3]["content"]


def _phase_note_convo() -> list[dict]:
    call = {
        "id": "call_1",
        "type": "function",
        "function": {"name": "execute", "arguments": '{"command": "id"}'},
    }
    return [
        {"role": "system", "content": "You are AIRecon."},
        {"role": "user", "content": "assess example.test"},
        {"role": "assistant", "content": "", "tool_calls": [call]},
        {"role": "system", "content": "[SYSTEM: phase note]"},
        {"role": "tool", "tool_call_id": "call_1", "content": "uid=0"},
    ]


def test_openai_phase_note_between_tool_call_and_result_is_hoisted():
    # Regression: an inline user boundary between an assistant tool_calls
    # message and its tool result is rejected by OpenAI-compatible servers.
    out = _to_openai_messages(_phase_note_convo())
    roles = [m["role"] for m in out]
    assert roles == ["system", "user", "assistant", "tool"]
    assert "phase note" in out[0]["content"]
    assert out[3]["tool_call_id"] == "call_1"


def test_anthropic_phase_note_between_tool_call_and_result_is_hoisted():
    system, turns = anthropic_messages(_phase_note_convo())
    assert "phase note" in system and "You are AIRecon." in system
    roles = [t["role"] for t in turns]
    assert roles == ["user", "assistant", "user"]
    # tool_result pairing untouched, no user text block before it.
    assert turns[2]["content"] == [
        {"type": "tool_result", "tool_use_id": "call_1", "content": "uid=0"}
    ]


def test_note_after_last_tool_result_of_group_is_hoisted():
    call = {
        "id": "call_1",
        "type": "function",
        "function": {"name": "execute", "arguments": '{"command": "id"}'},
    }
    convo = [
        {"role": "system", "content": "You are AIRecon."},
        {"role": "user", "content": "go"},
        {"role": "assistant", "content": "", "tool_calls": [call]},
        {"role": "tool", "tool_call_id": "call_1", "content": "uid=0"},
        {"role": "system", "content": "[archive] older turns were archived"},
        {"role": "assistant", "content": "done analysing"},
    ]
    out = _to_openai_messages(convo)
    assert [m["role"] for m in out] == ["system", "user", "assistant", "tool", "assistant"]
    assert "[archive]" in out[0]["content"]

    system, turns = anthropic_messages(convo)
    assert "[archive]" in system
    assert [t["role"] for t in turns] == ["user", "assistant", "user", "assistant"]


def test_archive_notice_before_latest_turn_is_still_hoisted():
    # context_budget drops an archive notice as a system message placed
    # before the latest real assistant turn (after a tool result, not
    # between two assistant turns): it must keep joining the system prompt.
    call = {
        "id": "call_1",
        "type": "function",
        "function": {"name": "execute", "arguments": '{"command": "id"}'},
    }
    convo = [
        {"role": "system", "content": "You are AIRecon."},
        {"role": "user", "content": "go"},
        {"role": "assistant", "content": "", "tool_calls": [call]},
        {"role": "tool", "tool_call_id": "call_1", "content": "uid=0"},
        {"role": "system", "content": "[archive] older turns were archived"},
        {"role": "assistant", "content": "", "_provider_blocks": [dict(THINKING), dict(TOOL_USE)]},
        {"role": "user", "content": [
            {"type": "tool_result", "tool_use_id": "toolu_01", "content": "uid=0"},
        ]},
    ]
    system, turns = anthropic_messages(convo)
    assert "[archive]" in system and "You are AIRecon." in system
    roles = [t["role"] for t in turns]
    assert roles == ["user", "assistant", "user", "assistant", "user"]
    # The signed turn is untouched: thinking first, byte-exact.
    assert turns[3]["content"] == [THINKING, TOOL_USE]

    out = _to_openai_messages(convo)
    assert "[archive]" in out[0]["content"]
    # The signed native turn is dropped by OpenAI-side conversion
    # (pre-existing); the archive notice stays hoisted, tool pairing intact.
    assert [m["role"] for m in out] == ["system", "user", "assistant", "tool", "user"]

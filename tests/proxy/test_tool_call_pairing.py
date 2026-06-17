"""Regression tests for tool_call/tool_result pairing at the wire boundary.

Strict OpenAI-compatible gateways (e.g. the Responses backend) reject a tool
result whose call_id has no matching tool_call:
    "No tool call found for function call output with call_id ..."
These tests lock in that AIRecon never emits such an orphan.
"""

from __future__ import annotations

from airecon.proxy.llm import _to_openai_messages


def _ids(messages):
    out = set()
    for m in messages:
        for tc in m.get("tool_calls") or []:
            out.add(tc["id"])
    return out


def test_orphaned_tool_result_is_dropped_not_fabricated():
    # tool result with no preceding assistant tool_call
    convo = [
        {"role": "user", "content": "go"},
        {"role": "tool", "tool_call_id": "call_orphan", "content": "stale output"},
    ]
    out = _to_openai_messages(convo)
    assert all(m["role"] != "tool" for m in out), "orphan tool result must be dropped"
    # and no fabricated call_ id leaks through
    assert not any(m.get("tool_call_id", "").startswith("call_") for m in out)


def test_valid_pair_is_preserved_and_bound():
    convo = [
        {"role": "user", "content": "go"},
        {
            "role": "assistant",
            "content": "",
            "tool_calls": [
                {"id": "call_A", "function": {"name": "execute", "arguments": {"cmd": "id"}}}
            ],
        },
        {"role": "tool", "tool_call_id": "call_A", "content": "uid=0"},
    ]
    out = _to_openai_messages(convo)
    tool_msgs = [m for m in out if m["role"] == "tool"]
    assert len(tool_msgs) == 1
    assert tool_msgs[0]["tool_call_id"] == "call_A"
    assert "call_A" in _ids(out)


def test_idless_tool_result_binds_to_preceding_call_by_order():
    convo = [
        {
            "role": "assistant",
            "content": "",
            "tool_calls": [
                {"id": "call_X", "function": {"name": "web_search", "arguments": {}}}
            ],
        },
        {"role": "tool", "content": "results"},  # no explicit tool_call_id
    ]
    out = _to_openai_messages(convo)
    tool_msgs = [m for m in out if m["role"] == "tool"]
    assert len(tool_msgs) == 1
    assert tool_msgs[0]["tool_call_id"] == "call_X"


def test_result_referencing_wrong_id_is_dropped():
    convo = [
        {
            "role": "assistant",
            "content": "",
            "tool_calls": [
                {"id": "call_real", "function": {"name": "execute", "arguments": {}}}
            ],
        },
        {"role": "tool", "tool_call_id": "call_real", "content": "ok"},
        # a second result pointing at a non-existent call
        {"role": "tool", "tool_call_id": "call_ghost", "content": "ghost"},
    ]
    out = _to_openai_messages(convo)
    tool_ids = [m["tool_call_id"] for m in out if m["role"] == "tool"]
    assert tool_ids == ["call_real"]

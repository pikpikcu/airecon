"""Tests for the persistent raw-turn buffer that enriches resume history."""

from __future__ import annotations

import types

from airecon.proxy.agent.loop_state import _StateMixin
from airecon.proxy.agent.session import SessionData


def _stub(conversation):
    s = types.SimpleNamespace()
    s._session = SessionData(session_id="s1", target="acme.test")
    s.state = types.SimpleNamespace(conversation=conversation)
    # Bind the staticmethod the accumulator relies on (AgentLoop has it via mixin).
    s._turn_signature = _StateMixin._turn_signature
    return s


def test_accumulates_chat_turns_skips_system_and_empty():
    convo = [
        {"role": "system", "content": "[SYSTEM: X]"},
        {"role": "user", "content": "recon acme.test"},
        {"role": "assistant", "content": "", "tool_calls": [{"function": {"name": "execute"}}]},
        {"role": "assistant", "content": ""},  # empty, no tool_calls -> skipped
        {"role": "tool", "content": "nmap output"},
    ]
    s = _stub(convo)
    _StateMixin._accumulate_recent_turns(s)
    rt = s._session.recent_turns
    roles = [t["role"] for t in rt]
    assert roles == ["user", "assistant", "tool"]
    assert any(t.get("tool_calls") for t in rt)


def test_accumulation_is_deduped_across_calls():
    convo = [{"role": "user", "content": "step one"}]
    s = _stub(convo)
    _StateMixin._accumulate_recent_turns(s)
    _StateMixin._accumulate_recent_turns(s)  # same turn again
    assert len(s._session.recent_turns) == 1


def test_survives_when_conversation_later_compacted():
    # Turns captured, then the live conversation is wiped (compaction).
    s = _stub([{"role": "user", "content": "u1"}, {"role": "tool", "content": "t1"}])
    _StateMixin._accumulate_recent_turns(s)
    s.state.conversation = [{"role": "system", "content": "[SYSTEM: COMPRESSION SUMMARY] ..."}]
    _StateMixin._accumulate_recent_turns(s)
    # The earlier raw turns are still in the persistent buffer.
    assert len(s._session.recent_turns) == 2


def test_session_roundtrip_persists_recent_turns(tmp_path, monkeypatch):
    import airecon.proxy.agent.session as session_mod

    monkeypatch.setattr(session_mod, "SESSIONS_DIR", tmp_path)
    s = SessionData(session_id="s_rt", target="acme.test")
    s.recent_turns = [
        {"role": "user", "content": "recon"},
        {"role": "assistant", "content": "", "tool_calls": [{"function": {"name": "execute"}}]},
    ]
    session_mod.save_session(s)
    loaded = session_mod.load_session("s_rt")
    assert loaded is not None
    assert len(loaded.recent_turns) == 2
    assert any(t.get("tool_calls") for t in loaded.recent_turns)

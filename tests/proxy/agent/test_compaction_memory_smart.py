"""Tests for the smarter compaction/memory preservation.

- protected system messages are kept BY TYPE (freshest of each) so scope,
  pinned findings, recovery state and the compression summary all survive even
  when many messages accumulate and truncation runs.
- the first user message (original task) is always preserved.
"""

from __future__ import annotations

from airecon.proxy.agent.models import AgentState


def _sys(content: str) -> dict:
    return {"role": "system", "content": content}


def test_all_protected_types_survive_truncation():
    state = AgentState()
    convo = [
        _sys("You are AIRecon."),  # core system
        {"role": "user", "content": "scan target acme.test (ORIGINAL TASK)"},
    ]
    # Many protected messages of DIFFERENT types, interleaved with filler.
    protected = {
        "[SYSTEM: STRICT_SCOPE_MODE] scope=acme.test",
        "[SYSTEM: PINNED CONTEXT — confirmed findings] sqli at /login",
        "[SYSTEM: RECOVERY STATE] iteration=42",
        "[SYSTEM: COMPRESSION SUMMARY] goal/progress/findings",
        "[SYSTEM: MEMORY BRAIN] target_findings=3",
    }
    for p in protected:
        convo.append(_sys(p))
    # Lots of filler tool/assistant/user messages to force truncation.
    for i in range(80):
        convo.append({"role": "assistant", "content": f"step {i}", "tool_calls": []})
        convo.append({"role": "tool", "content": f"output {i} " + "x" * 300})

    state.conversation = list(convo)
    state.truncate_conversation(max_messages=30)

    kept = "\n".join(str(m.get("content", "")) for m in state.conversation)
    # Every protected TYPE must still be present.
    for p in protected:
        prefix = p.split("]")[0] + "]"
        assert prefix in kept, f"protected type dropped: {prefix}"
    # Original task (first user) preserved.
    assert "ORIGINAL TASK" in kept


def test_freshest_of_each_protected_type_wins():
    state = AgentState()
    convo = [
        _sys("core"),
        {"role": "user", "content": "task"},
        _sys("[SYSTEM: PINNED CONTEXT — confirmed findings] OLD pin"),
    ]
    for i in range(60):
        convo.append({"role": "assistant", "content": f"s{i}"})
    convo.append(_sys("[SYSTEM: PINNED CONTEXT — confirmed findings] NEW pin"))
    state.conversation = convo
    state.truncate_conversation(max_messages=20)
    kept = "\n".join(str(m.get("content", "")) for m in state.conversation)
    assert "NEW pin" in kept
    assert "OLD pin" not in kept  # only the freshest of the type is kept

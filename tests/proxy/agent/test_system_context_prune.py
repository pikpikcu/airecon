"""Dedup of re-injected ephemeral system messages.

Sessions showed the context flooded with duplicate system boilerplate
(HANDOFF SUMMARY ×15, VISIONARY ×5, ...) — ~38k tokens crowding out the
agent's actual recon data. These tests lock in that singletons collapse to the
latest one, distinct skills survive, and snapshot families keep the latest two.
"""

from __future__ import annotations

import types

from airecon.proxy.agent.loop_cycle_post import _CyclePostMixin


def _prune(conversation):
    obj = _CyclePostMixin.__new__(_CyclePostMixin)
    obj.state = types.SimpleNamespace(conversation=list(conversation), iteration=7)
    _CyclePostMixin._prune_stale_system_context(obj)
    return obj.state.conversation


def _count(conv, prefix):
    return sum(
        1
        for m in conv
        if m.get("role") == "system" and str(m.get("content", "")).startswith(prefix)
    )


def test_singletons_collapse_to_latest_one():
    conv = [{"role": "system", "content": "MAIN PROMPT"}]
    for i in range(15):
        conv.append({"role": "system", "content": f"[SYSTEM: HANDOFF SUMMARY] v{i}"})
    conv.append({"role": "user", "content": "go"})
    out = _prune(conv)
    assert _count(out, "[SYSTEM: HANDOFF SUMMARY") == 1
    # the LATEST copy is the one retained
    kept = [m for m in out if str(m.get("content", "")).startswith("[SYSTEM: HANDOFF")]
    assert kept[0]["content"].endswith("v14")
    # core prompt + user message untouched
    assert any(m.get("content") == "MAIN PROMPT" for m in out)
    assert any(m.get("role") == "user" for m in out)


def test_distinct_skills_are_preserved():
    conv = [
        {"role": "system", "content": "[SKILL LOADED: recon/full_recon.md]\nbody"},
        {"role": "system", "content": "[SKILL LOADED: vulns/idor.md]\nbody"},
        {"role": "system", "content": "[SKILL LOADED: recon/full_recon.md]\nbody-reload"},
    ]
    out = _prune(conv)
    skills = [m for m in out if str(m.get("content", "")).startswith("[SKILL LOADED")]
    # one per distinct skill (full_recon collapsed, idor kept)
    assert len(skills) == 2
    headers = {m["content"].split(chr(10))[0] for m in skills}
    assert "[SKILL LOADED: recon/full_recon.md]" in headers
    assert "[SKILL LOADED: vulns/idor.md]" in headers


def test_snapshot_families_keep_latest_two():
    conv = [
        {"role": "system", "content": f"[NEW EVIDENCE — {i}] x"} for i in range(5)
    ]
    out = _prune(conv)
    assert _count(out, "[NEW EVIDENCE —") == 2


def test_unmatched_system_messages_never_pruned():
    conv = [
        {"role": "system", "content": "[SYSTEM: REGISTERED TOOLS] a,b,c"},
        {"role": "system", "content": "[SYSTEM: EXECUTE_COMMAND_AVAILABLE=yes]"},
    ]
    out = _prune(conv)
    assert len(out) == 2

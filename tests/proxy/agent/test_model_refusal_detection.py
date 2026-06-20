"""Tests for LLM-side refusal detection (labels a model refusal, not an AIRecon bug)."""

from __future__ import annotations

from airecon.proxy.agent.loop_tool_cycle import _ToolCycleMixin
from airecon.proxy.data_loader import (
    load_awaiting_input_markers,
    load_refusal_markers,
)

_detect = _ToolCycleMixin._looks_like_model_refusal
_awaiting = _ToolCycleMixin._looks_like_awaiting_input


def test_refusal_markers_load_nonempty():
    markers = load_refusal_markers()
    assert markers, "refusal markers should load from data/refusal_markers.json"
    assert all(m == m.lower() for m in markers), "markers must be lowercase"


def test_detects_real_world_refusal():
    text = (
        "I cannot perform reconnaissance or security testing against "
        "`example.com` or any other real-world third-party systems. I can, "
        "however, explain the methodologies from a defensive or educational "
        "perspective."
    )
    assert _detect(text) is True


def test_detects_decline_phrasings():
    for text in [
        "I'm unable to assist with that request.",
        "I must decline to conduct offensive security testing.",
        "I do not have permission to scan that host.",
    ]:
        assert _detect(text) is True, text


def test_normal_action_text_not_flagged():
    text = (
        "Running subfinder against the target to enumerate subdomains, then "
        "httpx to probe live hosts."
    )
    assert _detect(text) is False


def test_finding_writeup_with_unauthorized_not_flagged():
    # 'unauthorized' appears in legitimate findings; must not trip the detector.
    text = "Confirmed IDOR: /api/users/2 returned unauthorized data for another account."
    assert _detect(text) is False


def test_empty_text_not_flagged():
    assert _detect("") is False
    assert _detect(None) is False  # type: ignore[arg-type]


# ── awaiting-input detection (graceful text-only stop) ───────────────────────


def test_awaiting_input_markers_load_nonempty():
    markers = load_awaiting_input_markers()
    assert markers, "awaiting-input markers should load from data file"
    assert all(m == m.lower() for m in markers)


def test_detects_awaiting_input_phrasings():
    # the exact degenerate phrasing from the real stuck run
    for text in [
        "Need target/task. Existing workspace: `example.com`.",
        "Ready. Send scope/objective.",
        "Ready. Target + objective?",
        "Awaiting your next instruction.",
    ]:
        assert _awaiting(text) is True, text


def test_action_text_not_flagged_as_awaiting():
    text = "Pivoting to high-value APIs; probing auth on the admin endpoint next."
    assert _awaiting(text) is False


def test_awaiting_empty_text_not_flagged():
    assert _awaiting("") is False
    assert _awaiting(None) is False  # type: ignore[arg-type]

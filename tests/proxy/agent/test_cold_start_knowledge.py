"""Tests for cold-start dataset knowledge + memory recall cadence config.

When cross-session memory has learned nothing yet, the agent should still get
real domain knowledge from the static tech_correlations dataset so datasets are
actively used as the brain from iteration 1.
"""

from __future__ import annotations

from airecon.proxy.agent.loop_cycle_prelude import (
    _build_cold_start_knowledge,
    _load_tech_correlations,
)


def test_tech_dataset_loads():
    tc = _load_tech_correlations()
    assert isinstance(tc, dict) and len(tc) > 10
    assert "wordpress" in tc


def test_cold_start_knowledge_for_known_tech():
    kb = _build_cold_start_knowledge(["WordPress", "nginx"])
    assert kb.startswith("[SYSTEM: KNOWLEDGE BASE")
    # Real dataset content surfaced (case-insensitive match on tech name).
    assert "wordpress" in kb.lower()
    assert "known issues:" in kb or "check paths:" in kb or "tools:" in kb


def test_cold_start_empty_for_unknown_tech():
    assert _build_cold_start_knowledge(["totally-unknown-stack-xyz"]) == ""


def test_cold_start_empty_for_no_tech():
    assert _build_cold_start_knowledge([]) == ""


def test_recall_and_correlation_intervals_config_driven():
    import os

    os.environ.pop("AIRECON_OPENAI_MODEL", None)
    from airecon.proxy.config import Config

    c = Config.load_with_defaults({"openai_model": "m"})
    # Faster defaults so memory/datasets are used more actively as the brain.
    assert c.intelligence_memory_recall_interval == 4
    assert c.intelligence_correlation_interval == 6
    assert c.intelligence_adaptive_min_observations == 2

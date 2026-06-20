"""Tests for LLM cycle tool-intelligence wiring."""

from __future__ import annotations

from types import SimpleNamespace

from airecon.proxy.agent.loop_cycle_llm import _CycleLlmMixin
from airecon.proxy.agent.models import AgentState, ToolExecution
from airecon.proxy.agent.pipeline import PipelinePhase
from airecon.proxy.agent.session import SessionData


class _PipelineStub:
    def get_current_phase(self):
        return PipelinePhase.ANALYSIS


class _AdaptiveEngineStub:
    def recommend_tools(self, **kwargs):
        return [("ffuf", 0.91), ("httpx", 0.73)]

    def recommend_strategy(self, conditions):
        return SimpleNamespace(
            description="Use ffuf before httpx",
            tool_sequence=["ffuf", "httpx"],
            reliability=0.88,
        )


class _DummyLoop(_CycleLlmMixin):
    def __init__(self):
        self.state = AgentState()
        self.state.evidence_log = [
            {
                "summary": "Workflow signal: tenant checkout state transition bypass",
                "tags": ["workflow", "tenant", "authorization"],
            }
        ]
        self.state.tool_history = [
            ToolExecution(
                tool_name="nmap",
                arguments={},
                result={},
                duration=0.1,
                status="success",
            ),
            ToolExecution(
                tool_name="httpx",
                arguments={},
                result={},
                duration=0.1,
                status="success",
            ),
        ]
        self.state.conversation = []
        self.state.exploit_chains = []
        self.pipeline = _PipelineStub()
        self._tools_llm = [
            {"function": {"name": "ffuf", "description": "Fast content discovery"}},
            {"function": {"name": "httpx", "description": "HTTP probing"}},
        ]
        self._consecutive_failures = 0
        self._blocked_tools = set()
        self._session = SessionData(target="example.com")
        self._session.tool_counts = {"ffuf": 1, "httpx": 2}
        self._session.technologies = {"fastapi": "0.111"}
        self._session.vulnerabilities = [
            {"finding": "SQL injection in /orders endpoint", "endpoint": "/orders"}
        ]

    def _ensure_adaptive_learning_engine(self):
        return _AdaptiveEngineStub()

    def _inject_target_memory(self) -> None:
        return

    def _inject_learned_insights(self, current_phase: str) -> None:
        return

    def _inject_adaptive_recommendations(self, current_phase: str) -> None:
        return

    def _inject_meta_reflection_context(self, current_phase: str) -> None:
        return


class TestCycleLlmMixin:
    def test_inject_tool_intelligence_passes_adaptive_ranking_inputs(self, monkeypatch):
        loop = _DummyLoop()
        captured = {}

        def fake_rank_tools_for_phase(tools, **kwargs):
            captured.update(kwargs)
            return tools

        monkeypatch.setattr(
            "airecon.proxy.agent.loop_cycle_llm.rank_tools_for_phase",
            fake_rank_tools_for_phase,
        )

        loop._inject_tool_intelligence()

        assert captured["recent_tool_names"] == ["nmap", "httpx"]
        assert captured["adaptive_tool_scores"]["ffuf"] == 0.91
        assert captured["strategy_tool_sequence"] == ["ffuf", "httpx"]
        assert {"SQL_INJECTION", "INJECTION"} & captured["tested_vuln_classes"]
        assert any(
            msg["content"].startswith("<system_tool_intelligence>")
            for msg in loop.state.conversation
        )

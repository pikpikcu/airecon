"""Tests for loop_supervision.py — watchdog, quality scores, mentor analysis."""

from __future__ import annotations


from airecon.proxy.agent.loop_supervision import _SupervisionMixin
from airecon.proxy.agent.models import AgentState
from airecon.proxy.agent.pipeline import PipelinePhase


def _make_agent():
    class DummyAgent(_SupervisionMixin):
        def __init__(self):
            self.state = AgentState()
            self._tools_llm = []
            import re

            self._FAKE_CMD_BLOCK_RE = re.compile(
                r"```(?:bash|sh|shell)?\s*\n(.*?)```", re.DOTALL
            )

    return DummyAgent()


class TestExtractShellCommandCandidate:
    def test_extracts_command_from_code_block(self):
        agent = _make_agent()
        content = "Let me run:\n```bash\nnmap -sV example.com\n```\nDone."
        result = agent._extract_shell_command_candidate(content)
        assert result is not None
        assert "nmap" in result

    def test_rejects_dangerous_commands(self):
        agent = _make_agent()
        content = "```bash\nrm -rf /\n```"
        result = agent._extract_shell_command_candidate(content)
        assert result is None

    def test_rejects_too_long_commands(self):
        agent = _make_agent()
        content = f"```bash\n{'a' * 9000}\n```"
        result = agent._extract_shell_command_candidate(content)
        assert result is None

    def test_returns_none_for_no_command(self):
        agent = _make_agent()
        content = "Just some analysis text without commands."
        result = agent._extract_shell_command_candidate(content)
        assert result is None


class TestReflectorInferToolHint:
    def test_infers_tool_from_content(self):
        from airecon.proxy.agent.loop_supervision import _SupervisionMixin

        class A(_SupervisionMixin):
            def __init__(self):
                self._tools_llm = [
                    {"function": {"name": "execute", "description": "run"}},
                    {"function": {"name": "web_search", "description": "search"}},
                ]

        agent = A()
        hint = agent._reflector_infer_tool_hint("let me use web_search for information")
        assert "web_search" in hint

    def test_defaults_to_execute(self):
        from airecon.proxy.agent.loop_supervision import _SupervisionMixin

        class A(_SupervisionMixin):
            def __init__(self):
                self._tools_llm = [
                    {"function": {"name": "execute", "description": "run"}},
                ]

        agent = A()
        hint = agent._reflector_infer_tool_hint("let me analyze this")
        assert "execute" in hint


class TestBuildWatchdogToolCall:
    def test_returns_tool_call_when_command_found(self):
        agent = _make_agent()
        agent.state.iteration = 5
        content = "```bash\nnmap -sV example.com\n```"
        result = agent._build_watchdog_tool_call(content, "", PipelinePhase.RECON)
        assert result is not None
        assert result["function"]["name"] == "execute"
        assert "nmap" in result["function"]["arguments"]["command"]

    def test_returns_none_when_no_command_found(self):
        agent = _make_agent()
        agent.state.iteration = 5
        result = agent._build_watchdog_tool_call(
            "Just text analysis", "", PipelinePhase.RECON
        )
        assert result is None


class TestComputeQualityScores:
    def test_returns_score_dict(self):
        from airecon.proxy.agent.loop_supervision import _SupervisionMixin
        from unittest.mock import MagicMock

        class A(_SupervisionMixin):
            def __init__(self):
                self.state = AgentState()
                self.state.evidence_log = [
                    {
                        "tags": ["artifact", "execution"],
                        "confidence": 0.8,
                        "severity": 4,
                        "summary": "Found XSS",
                        "source_tool": "execute",
                    },
                ]
                self._session = MagicMock()
                self._session.vulnerabilities = []

        agent = A()
        scores = agent._compute_quality_scores()
        assert "evidence" in scores
        assert "overall" in scores
        assert 0.0 <= scores["evidence"] <= 1.0

    def test_empty_state_returns_zero_scores(self):
        from airecon.proxy.agent.loop_supervision import _SupervisionMixin
        from unittest.mock import MagicMock

        class A(_SupervisionMixin):
            def __init__(self):
                self.state = AgentState()
                self.state.evidence_log = []
                self._session = MagicMock()
                self._session.vulnerabilities = []

        agent = A()
        scores = agent._compute_quality_scores()
        assert scores["evidence"] == 0.0
        assert scores["overall"] == 0.0


class TestMentorAnalysisSeverityNormalization:
    def test_build_mentor_analysis_handles_string_severity(self):
        agent = _make_agent()
        agent.state.evidence_log = [
            {
                "phase": "ANALYSIS",
                "severity": "HIGH",
                "summary": "JWT alg:none accepted by API",
                "confidence": 0.9,
                "source_tool": "execute",
            }
        ]

        analysis = agent._build_mentor_analysis(
            PipelinePhase.ANALYSIS,
            tool_name="execute",
            evidence_added=True,
        )

        assert "HIGH/CRITICAL finding(s) confirmed" in analysis
        assert "Latest: [HIGH]" in analysis


class TestPruneStaleSkills:
    def test_returns_zero_when_conversation_too_short(self):
        from airecon.proxy.agent.loop_supervision import _SupervisionMixin

        class A(_SupervisionMixin):
            def __init__(self):
                self.state = AgentState()
                self.state.iteration = 5
                self.state.conversation = [
                    {"role": "user", "content": "short"},
                ]

            def _get_current_phase(self):
                return PipelinePhase.RECON

        agent = A()
        assert agent._prune_stale_skills() == 0

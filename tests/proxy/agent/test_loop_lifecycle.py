"""Tests for loop_lifecycle.py — initialize, reset, context management."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from airecon.proxy.agent.models import AgentState


class TestInitialize:
    @pytest.fixture
    def agent(self):
        from airecon.proxy.agent.loop_lifecycle import _LifecycleMixin

        class DummyAgent(_LifecycleMixin):
            def __init__(self):
                self.state = AgentState()
                self._tools_llm = []
                self._blocked_tools = set()
                self._ctf_mode = False
                self._override_max_iterations = None
                self._CTF_MAX_ITERATIONS = 50
                self._adaptive_num_ctx = 0
                self._session = None
                self._is_subagent = False
                self.pipeline = None
                self.engine = MagicMock()
                self._initial_messages = []
                self._token_snapshot_task = None
                self._token_snapshot_resave_requested = False
                self._executed_tool_counts = {}
                self._executed_cmd_hashes = set()
                self._executed_cmd_order = []
                self._last_output_file = None
                self._stagnation_iterations = 0
                self._recent_tool_names = []
                self._last_evidence_count = 0
                self._watchdog_forced_calls = 0
                self._vram_crash_count = 0
                self._adaptive_num_predict_cap = 0
                self._fatal_llm_error = ""

            async def refresh_tool_registry(self):
                self._tools_llm = [
                    {"function": {"name": "execute", "description": "run"}},
                ]

            def _sync_recovery_state_from_session(self):
                pass

            def _sync_token_usage_from_session(self):
                pass

        return DummyAgent()

    @pytest.mark.asyncio
    async def test_initialization_sets_system_prompt(self, agent):
        with (
            patch("airecon.proxy.agent.loop_lifecycle.get_config") as mock_cfg,
            patch(
                "airecon.proxy.agent.loop_lifecycle._is_ctf_target", return_value=False
            ),
            patch(
                "airecon.proxy.caido_client.CaidoClient._get_token", return_value=None
            ),
        ):
            cfg = MagicMock()
            cfg.llm_context_window_small = 8192
            cfg.agent_max_tool_iterations = 20
            mock_cfg.return_value = cfg

            await agent.initialize(target="example.com")

        system_msgs = [m for m in agent.state.conversation if m.get("role") == "system"]
        assert len(system_msgs) > 0

    @pytest.mark.asyncio
    async def test_ctf_mode_activation(self, agent):
        with (
            patch("airecon.proxy.agent.loop_lifecycle.get_config") as mock_cfg,
            patch(
                "airecon.proxy.agent.loop_lifecycle._is_ctf_target", return_value=True
            ),
            patch(
                "airecon.proxy.caido_client.CaidoClient._get_token", return_value=None
            ),
        ):
            cfg = MagicMock()
            cfg.llm_context_window_small = 8192
            cfg.agent_max_tool_iterations = 20
            mock_cfg.return_value = cfg

            await agent.initialize(target="127.0.0.1")

        assert agent._ctf_mode is True
        assert agent._override_max_iterations == 50

    @pytest.mark.asyncio
    async def test_caido_available_message(self, agent):
        with (
            patch("airecon.proxy.agent.loop_lifecycle.get_config") as mock_cfg,
            patch(
                "airecon.proxy.agent.loop_lifecycle._is_ctf_target", return_value=False
            ),
            patch(
                "airecon.proxy.caido_client.CaidoClient._get_token",
                return_value="valid_token",
            ),
        ):
            cfg = MagicMock()
            cfg.llm_context_window_small = 8192
            cfg.agent_max_tool_iterations = 20
            mock_cfg.return_value = cfg

            await agent.initialize(target="example.com")

        assert agent._caido_available is True
        system_contents = " ".join(
            m.get("content", "") for m in agent.state.conversation
        )
        assert "CAIDO_PROXY=available" in system_contents

    @pytest.mark.asyncio
    async def test_caido_unavailable_message(self, agent):
        with (
            patch("airecon.proxy.agent.loop_lifecycle.get_config") as mock_cfg,
            patch(
                "airecon.proxy.agent.loop_lifecycle._is_ctf_target", return_value=False
            ),
            patch(
                "airecon.proxy.caido_client.CaidoClient._get_token", return_value=None
            ),
        ):
            cfg = MagicMock()
            cfg.llm_context_window_small = 8192
            cfg.agent_max_tool_iterations = 20
            mock_cfg.return_value = cfg

            await agent.initialize(target="example.com")

        assert agent._caido_available is False
        system_contents = " ".join(
            m.get("content", "") for m in agent.state.conversation
        )
        assert "CAIDO_PROXY=unavailable" in system_contents

    @pytest.mark.asyncio
    async def test_creates_new_session(self, agent):
        with (
            patch("airecon.proxy.agent.loop_lifecycle.get_config") as mock_cfg,
            patch(
                "airecon.proxy.agent.loop_lifecycle._is_ctf_target", return_value=False
            ),
            patch(
                "airecon.proxy.caido_client.CaidoClient._get_token", return_value=None
            ),
        ):
            cfg = MagicMock()
            cfg.llm_context_window_small = 8192
            cfg.agent_max_tool_iterations = 20
            mock_cfg.return_value = cfg

            await agent.initialize(target="example.com")

        assert agent._session is not None
        assert agent.pipeline is not None


class TestReset:
    @pytest.fixture
    def agent(self):
        from airecon.proxy.agent.loop_lifecycle import _LifecycleMixin

        class DummyAgent(_LifecycleMixin):
            def __init__(self):
                self.state = AgentState()
                self.state.iteration = 10
                self._tools_llm = [{"function": {"name": "execute"}}]
                self._ctf_mode = True
                self._initial_messages = [{"role": "system", "content": "init"}]
                self._token_snapshot_task = None
                self._token_snapshot_resave_requested = True
                self._executed_tool_counts = {"nmap": 5}
                self._executed_cmd_hashes = {"hash1", "hash2"}
                self._executed_cmd_order = ["nmap", "subfinder"]
                self._last_output_file = "output/nmap.txt"
                self._stagnation_iterations = 3
                self._recent_tool_names = ["nmap"]
                self._last_evidence_count = 5
                self._watchdog_forced_calls = 2
                self._adaptive_num_ctx = 4096
                self._vram_crash_count = 3
                self._adaptive_num_predict_cap = 1024
                self._fatal_llm_error = "some error"
                self._session = MagicMock()
                self.pipeline = MagicMock()

        return DummyAgent()

    def test_reset_clears_state(self, agent):
        agent.reset()

        assert agent.state.iteration == 0
        assert agent._executed_tool_counts == {}
        assert agent._executed_cmd_hashes == set()
        assert agent._stagnation_iterations == 0
        assert agent._watchdog_forced_calls == 0
        assert agent._adaptive_num_ctx == 0
        assert agent._vram_crash_count == 0
        assert agent._fatal_llm_error == ""

    def test_reset_preserves_initial_messages(self, agent):
        agent.reset()

        assert len(agent.state.conversation) == 1
        assert agent.state.conversation[0]["role"] == "system"

    def test_reset_creates_fresh_session(self, agent):
        old_session = agent._session
        agent.reset()

        assert agent._session is not None
        assert agent._session is not old_session

    def test_reset_preserves_ctf_mode(self, agent):
        agent.reset()
        assert agent._ctf_mode is True


class TestResetLLMContext:
    @pytest.fixture
    def agent(self):
        from airecon.proxy.agent.loop_lifecycle import _LifecycleMixin

        class DummyAgent(_LifecycleMixin):
            def __init__(self):
                self.state = AgentState()
                self._session = MagicMock()
                self._session.target = "example.com"
                self._session.subdomains = ["sub.example.com"]
                self._session.live_hosts = ["http://example.com"]
                self._session.open_ports = {"80": "http"}
                self._session.urls = ["http://example.com/login"]
                self._session.vulnerabilities = []
                self._session.tools_run = ["nmap"]
                self._session.current_phase = "RECON"
                self.state.evidence_log = []
                self.state.iteration = 5
                self.state.max_iterations = 20
                self._ctf_mode = False
                self.llm = MagicMock()
                self.pipeline = MagicMock()
                self.pipeline.get_current_phase.return_value = MagicMock(value="RECON")

            def _get_current_phase(self):
                return MagicMock(value="RECON")

            def _build_system_prompt_for_reset(self):
                return "[SYSTEM: reset]"

            def _apply_local_context_fallback(self, reason=""):
                pass

        return DummyAgent()

    @pytest.mark.asyncio
    async def test_reset_context_succeeds(self, agent):
        agent.llm.reset_context = AsyncMock(return_value=True)

        result = await agent._reset_llm_context()
        assert result is True

    @pytest.mark.asyncio
    async def test_reset_context_retries_on_failure(self, agent):
        agent.llm.reset_context = AsyncMock(side_effect=RuntimeError("failed"))

        result = await agent._reset_llm_context()
        assert result is False
        assert agent.llm.reset_context.call_count == 3

    @pytest.mark.asyncio
    async def test_reset_context_detects_fatal_llm_error(self, agent):
        agent.llm.reset_context = AsyncMock(
            side_effect=RuntimeError("runner has unexpectedly stopped")
        )

        result = await agent._reset_llm_context()
        assert result is False
        assert agent._fatal_llm_error != ""

    @pytest.mark.asyncio
    async def test_reset_context_returns_false_without_llm(self, agent):
        agent.llm = None
        result = await agent._reset_llm_context()
        assert result is False


class TestBuildReconSummary:
    @pytest.fixture
    def agent(self):
        from airecon.proxy.agent.loop_lifecycle import _LifecycleMixin

        class DummyAgent(_LifecycleMixin):
            def __init__(self):
                self.state = AgentState()
                self.state.iteration = 5
                self.state.max_iterations = 20
                self.state.evidence_log = [
                    {"summary": "Found open port 80"},
                    {"summary": "Found subdomain"},
                ]
                self._session = MagicMock()
                self._session.target = "example.com"
                self._session.subdomains = ["sub1.example.com", "sub2.example.com"]
                self._session.live_hosts = ["http://example.com"]
                self._session.open_ports = {"80": "http", "443": "https"}
                self._session.urls = ["http://example.com/login"]
                self._session.vulnerabilities = [{"title": "XSS"}]
                self._session.tools_run = ["nmap", "subfinder"]
                self._session.current_phase = "RECON"
                self.pipeline = MagicMock()
                self.pipeline.get_current_phase.return_value = MagicMock(value="RECON")

            def _get_current_phase(self):
                return MagicMock(value="RECON")

        return DummyAgent()

    def test_builds_summary_with_data(self, agent):
        summary = agent._build_recon_summary()
        assert "RECON PROGRESS SUMMARY" in summary
        assert "example.com" in summary
        assert "Subdomains: 2 found" in summary
        assert "Open Ports:" in summary
        assert "Vulnerabilities: 1 confirmed" in summary

    def test_returns_no_progress_without_session(self, agent):
        agent._session = None
        summary = agent._build_recon_summary()
        assert "No recon progress yet" in summary


class TestApplyLocalContextFallback:
    @pytest.fixture
    def agent(self):
        from airecon.proxy.agent.loop_lifecycle import _LifecycleMixin

        class DummyAgent(_LifecycleMixin):
            def __init__(self):
                self.state = AgentState()
                self.state.conversation = [
                    {"role": "system", "content": "system"},
                ] + [{"role": "user", "content": f"msg {i}"} for i in range(50)]
                self.state.token_usage = {"used": 10000}
                self._ctf_mode = False

            def _build_critical_findings_context(self):
                return "critical findings"

            def _build_handoff_summary(self):
                return "handoff summary"

        return DummyAgent()

    def test_truncates_conversation(self, agent):
        before = len(agent.state.conversation)
        agent._apply_local_context_fallback(reason="test")
        after = len(agent.state.conversation)
        assert after < before

    def test_reduces_token_usage(self, agent):
        before_used = agent.state.token_usage["used"]
        agent._apply_local_context_fallback(reason="test")
        after_used = agent.state.token_usage["used"]
        assert after_used < before_used

    def test_does_nothing_on_empty_conversation(self, agent):
        agent.state.conversation = []
        agent._apply_local_context_fallback(reason="test")
        assert len(agent.state.conversation) == 0


class TestCheckLLMContextPressure:
    @pytest.fixture
    def agent(self):
        from airecon.proxy.agent.loop_lifecycle import _LifecycleMixin

        class DummyAgent(_LifecycleMixin):
            def __init__(self):
                self.state = AgentState()
                self.llm = MagicMock()
                self._ctf_mode = False
                self._last_context_check = 0.0

            async def _check_and_reset_context(self):
                pass

        return DummyAgent()

    @pytest.mark.asyncio
    async def test_creates_task_when_llm_exists(self, agent):
        agent._check_llm_context_pressure()

    def test_does_nothing_without_llm(self, agent):
        agent.llm = None
        agent._check_llm_context_pressure()


class TestRefreshToolRegistry:
    @pytest.fixture
    def agent(self):
        from airecon.proxy.agent.loop_lifecycle import _LifecycleMixin

        class DummyAgent(_LifecycleMixin):
            def __init__(self):
                self._tools_llm = []
                self._blocked_tools = set()
                self.engine = MagicMock()

        return DummyAgent()

    @pytest.mark.asyncio
    async def test_refreshes_tool_registry(self, agent):
        agent.engine.discover_tools = AsyncMock(
            return_value=[{"function": {"name": "nmap", "description": "scan"}}]
        )
        agent.engine.tools_to_llm_format = MagicMock(
            return_value=[{"function": {"name": "nmap", "description": "scan"}}]
        )

        await agent.refresh_tool_registry()

        assert len(agent._tools_llm) > 0
        names = [t["function"]["name"] for t in agent._tools_llm]
        assert "nmap" in names
        assert "execute" in names

    @pytest.mark.asyncio
    async def test_excludes_blocked_tools(self, agent):
        agent.engine.discover_tools = AsyncMock(return_value=[])
        agent.engine.tools_to_llm_format = MagicMock(
            return_value=[
                {"function": {"name": "execute", "description": "run"}},
                {"function": {"name": "blocked_tool", "description": "blocked"}},
            ]
        )
        agent._blocked_tools = {"blocked_tool"}

        await agent.refresh_tool_registry()

        names = [t["function"]["name"] for t in agent._tools_llm]
        assert "blocked_tool" not in names
        assert "execute" in names

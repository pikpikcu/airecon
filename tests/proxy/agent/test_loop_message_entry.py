"""Tests for loop_message_entry.py — message context preparation."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest


class TestPrepareMessageContext:
    @pytest.fixture
    def agent(self):
        from airecon.proxy.agent.loop_message_entry import _MessageEntryMixin
        from airecon.proxy.agent.models import AgentState

        class DummyAgent(_MessageEntryMixin):
            def __init__(self):
                self.state = AgentState()
                self._tools_llm = None  # Not yet initialized
                self._ctf_mode = False
                self._override_max_iterations = None
                self._CTF_MAX_ITERATIONS = 50
                self._session = None
                self._scope_anchor_target = None
                self._scope_lock_active = False
                self._scope_lock_brief = ""
                self._adaptive_num_ctx = 0
                self.pipeline = None
                self._memory_manager = None
                self._loaded_tech_skill_paths = set()

            def _extract_targets_from_text(self, text):
                import re

                targets = re.findall(
                    r"\b(?:\d{1,3}\.){3}\d{1,3}\b|"
                    r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b",
                    text.lower(),
                )
                filtered = [
                    t
                    for t in targets
                    if not t.endswith((".txt", ".py", ".md", ".json", ".yaml", ".log"))
                ]
                return filtered

            async def initialize(self, target=None, user_message=None):
                self._tools_llm = [
                    {"function": {"name": "execute", "description": "run"}},
                ]

            def _scan_workspace_state(self, target):
                return f"[SYSTEM: WORKSPACE={target}]"

            def _skill_phase_for_message_start(self):
                return "RECON"

            def _sync_token_usage_from_session(self):
                pass

            def _sync_phase_objectives(self, phase):
                pass

            def _update_objectives_from_session(self, phase):
                pass

            def _check_llm_context_pressure(self):
                pass

            def _recompute_used_tokens_from_conversation(self):
                return 100

        return DummyAgent()

    @pytest.mark.asyncio
    async def test_preparse_file_refs(self, agent):
        msg = "Scan target.com"
        await agent._prepare_message_context(msg)

        user_msgs = [m for m in agent.state.conversation if m.get("role") == "user"]
        assert len(user_msgs) == 1
        assert "target.com" in user_msgs[0]["content"]

    @pytest.mark.asyncio
    async def test_extract_target_from_message(self, agent):
        msg = "Scan example.com for vulnerabilities"
        await agent._prepare_message_context(msg)

        assert agent.state.active_target == "example.com"

    @pytest.mark.asyncio
    async def test_initializes_when_tools_not_loaded(self, agent):
        msg = "Scan target.com"
        await agent._prepare_message_context(msg)

        assert agent._tools_llm is not None

    @pytest.mark.asyncio
    async def test_ctf_mode_activation(self, agent):
        agent._ctf_mode = True
        agent._override_max_iterations = None
        msg = "Scan 127.0.0.1"
        await agent._prepare_message_context(msg)
        assert agent._ctf_mode is True

    @pytest.mark.asyncio
    async def test_resets_iteration_counters(self, agent):
        agent.state.iteration = 10
        agent.state.warnings_sent = True
        agent._consecutive_failures = 5
        agent._no_tool_iterations = 3

        await agent._prepare_message_context("Scan test.com")

        assert agent.state.iteration == 0
        assert agent.state.warnings_sent is False
        assert agent._consecutive_failures == 0
        assert agent._no_tool_iterations == 0

    @pytest.mark.asyncio
    async def test_clears_ephemeral_messages(self, agent):
        agent._tools_llm = [{"function": {"name": "execute"}}]
        agent.state.conversation = [
            {"role": "system", "content": "[SYSTEM: WORKSPACE=old]"},
            {"role": "system", "content": "[SYSTEM: OBJECTIVE FOCUS=test]"},
            {"role": "user", "content": "scan test.com"},
        ]

        await agent._prepare_message_context("scan test.com")

        system_contents = [
            m.get("content", "")
            for m in agent.state.conversation
            if m.get("role") == "system"
        ]
        # Old ephemeral messages should be cleared
        for c in system_contents:
            assert not c.startswith("[SYSTEM: OBJECTIVE FOCUS")
        # New workspace message should exist
        assert any("[SYSTEM: WORKSPACE=" in c for c in system_contents)

    @pytest.mark.asyncio
    async def test_sets_trace_id(self, agent):
        await agent._prepare_message_context("scan test.com")

        assert hasattr(agent, "_current_trace_id")
        assert len(agent._current_trace_id) == 12

    @pytest.mark.asyncio
    async def test_phase_reset_after_complete(self, agent):
        agent._tools_llm = [{"function": {"name": "execute"}}]
        agent._session = MagicMock()
        agent._session.current_phase = "COMPLETE"
        agent._session.target = "test.com"
        agent._session.scan_count = 0
        agent._session.subdomains = []
        agent._session.live_hosts = []
        agent._session.open_ports = {}
        agent._session.urls = []
        agent._session.vulnerabilities = []
        agent._session.injection_points = []
        agent._session.technologies = {}
        agent._session.waf_profiles = {}
        agent._session.tested_endpoints = set()
        agent._session.loaded_skills = []
        agent.state.active_target = "test.com"
        agent.state.evidence_log = [
            {"confidence": 0.9, "summary": "found vuln"},
            {"confidence": 0.3, "summary": "low signal"},
        ]
        agent.pipeline = MagicMock()

        await agent._prepare_message_context("continue scanning test.com")

        agent.pipeline.set_phase.assert_called()

    @pytest.mark.asyncio
    async def test_scope_lock_in_standard_mode(self, agent):
        with patch("airecon.proxy.agent.loop_message_entry.get_config") as mock_cfg:
            cfg = MagicMock()
            cfg.agent_recon_mode = "standard"
            cfg.llm_context_window = 8192
            cfg.agent_max_tool_iterations = 20
            mock_cfg.return_value = cfg

            await agent._prepare_message_context("scan test.com")

        assert agent._scope_lock_active is False


class TestContextPressureTruncation:
    @pytest.fixture
    def agent(self):
        from airecon.proxy.agent.loop_message_entry import _MessageEntryMixin
        from airecon.proxy.agent.models import AgentState

        class DummyAgent(_MessageEntryMixin):
            def __init__(self):
                self.state = AgentState()
                self._tools_llm = [{"function": {"name": "execute"}}]
                self._ctf_mode = False
                self._override_max_iterations = None
                self._session = None
                self._scope_anchor_target = None
                self._scope_lock_active = False
                self._scope_lock_brief = ""
                self._adaptive_num_ctx = 8192
                self.pipeline = None
                self._memory_manager = None
                self._loaded_tech_skill_paths = set()

            def _extract_targets_from_text(self, text):
                return ["test.com"]

            def _scan_workspace_state(self, target):
                return f"[SYSTEM: WORKSPACE={target}]"

            def _skill_phase_for_message_start(self):
                return "RECON"

            def _sync_token_usage_from_session(self):
                pass

            def _sync_phase_objectives(self, phase):
                pass

            def _update_objectives_from_session(self, phase):
                pass

            def _check_llm_context_pressure(self):
                pass

            def _recompute_used_tokens_from_conversation(self):
                return 7000  # High usage to trigger truncation

        return DummyAgent()

    @pytest.mark.asyncio
    async def test_emergency_truncation_on_hard_cap(self, agent):
        agent.state.conversation = [
            {"role": "system", "content": "system prompt"},
        ] + [{"role": "user", "content": f"message {i}"} for i in range(50)]

        await agent._prepare_message_context("scan test.com")

        # Conversation should have been truncated
        assert len(agent.state.conversation) < 51

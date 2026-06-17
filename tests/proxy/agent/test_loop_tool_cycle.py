"""Tests for loop_tool_cycle.py — the core agent iteration loop."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from airecon.proxy.agent.models import AgentState


class TestCollectKnownShellBinaries:
    def test_returns_frozenset(self):
        from airecon.proxy.agent.loop_tool_cycle import _collect_known_shell_binaries

        result = _collect_known_shell_binaries()
        assert isinstance(result, frozenset)
        assert len(result) > 0

    def test_contains_common_binaries(self):
        from airecon.proxy.agent.loop_tool_cycle import _collect_known_shell_binaries

        result = _collect_known_shell_binaries()
        assert "nmap" in result
        assert "subfinder" in result

    def test_excludes_execute(self):
        from airecon.proxy.agent.loop_tool_cycle import _collect_known_shell_binaries

        result = _collect_known_shell_binaries()
        assert "execute" not in result


class TestRewriteShellBinaryToolCall:
    @pytest.fixture
    def agent(self):
        from airecon.proxy.agent.loop_tool_cycle import _ToolCycleMixin

        class DummyAgent(_ToolCycleMixin):
            def __init__(self):
                self._tools_llm = [
                    {"function": {"name": "execute", "description": "run cmd"}},
                    {"function": {"name": "read_file", "description": "read"}},
                ]
                self.state = AgentState()

        return DummyAgent()

    def test_registered_tool_not_rewritten(self, agent):
        tn, args, rewritten = agent._rewrite_shell_binary_tool_call(
            "execute", {"command": "ls"}
        )
        assert rewritten is False
        assert tn == "execute"

    def test_unknown_binary_not_rewritten(self, agent):
        tn, args, rewritten = agent._rewrite_shell_binary_tool_call(
            "unknown_tool", {"command": "something"}
        )
        assert rewritten is False

    def test_known_binary_without_command_argument(self, agent):
        tn, args, rewritten = agent._rewrite_shell_binary_tool_call(
            "nmap", {"target": "example.com", "ports": "80,443"}
        )
        assert rewritten is True
        assert tn == "execute"
        assert "nmap" in args.get("command", "")

    def test_known_binary_with_command_string(self, agent):
        tn, args, rewritten = agent._rewrite_shell_binary_tool_call(
            "nmap", {"command": "-sV example.com"}
        )
        assert rewritten is True
        assert tn == "execute"
        assert "nmap" in args.get("command", "")

    def test_known_binary_with_empty_command(self, agent):
        tn, args, rewritten = agent._rewrite_shell_binary_tool_call(
            "subfinder", {"command": ""}
        )
        assert rewritten is True
        assert tn == "execute"
        assert args.get("command") == "subfinder"

    def test_empty_tool_name_returns_unchanged(self, agent):
        tn, args, rewritten = agent._rewrite_shell_binary_tool_call(
            "", {"command": "test"}
        )
        assert rewritten is False
        assert tn == ""


class TestRunIterationLoop:
    @pytest.fixture
    def agent(self):
        from airecon.proxy.agent.loop_tool_cycle import _ToolCycleMixin
        from airecon.proxy.agent.pipeline import PipelinePhase

        class DummyAgent(_ToolCycleMixin):
            def __init__(self):
                self.state = AgentState()
                self.state.max_iterations = 2
                self._tools_llm = [
                    {"function": {"name": "execute", "description": "run"}},
                ]
                self._stop_requested = False
                self._fatal_llm_error = ""
                self._current_trace_id = None
                self._ctf_mode = False
                self._session = None
                self._adaptive_num_ctx = 0
                self._adaptive_num_predict_cap = 0
                self._vram_crash_count = 0
                self._recovery_force_tool_calls = 0
                self._no_tool_iterations = 0
                self._watchdog_forced_calls = 0
                self._consecutive_thinking_iterations = 0
                self._stagnation_iterations = 0
                self._empty_response_retry_count = 0
                self.llm = MagicMock()
                self.pipeline = MagicMock()
                self.pipeline.get_current_phase.return_value = PipelinePhase.RECON

            def _get_current_phase(self):
                return PipelinePhase.RECON

            async def _run_iteration_housekeeping(self, cfg, phase):
                pass

            async def _fit_num_predict_to_ctx(self, num_predict, num_ctx):
                return min(num_predict or 8192, num_ctx)

            def _get_iteration_num_predict(self, cfg, phase, ctx):
                return 8192

            def _get_iteration_temperature(self, cfg, phase):
                return 0.7

            def _cfg_int(self, cfg, key, default):
                return default

            def _cfg_float(self, cfg, key, default):
                return default

            def _should_use_thinking(self, cfg, phase):
                return False

            def _fit_num_keep_to_ctx(self, requested, ctx, predict):
                return requested

            async def _check_and_reset_context(self):
                pass

            def _messages_for_llm(self):
                return [{"role": "user", "content": "test"}]

            def _recompute_used_tokens_from_conversation(self):
                return 100

            async def _enforce_char_budget(self, num_ctx, num_predict):
                pass

            def _record_token_usage(self, prompt_tokens, completion_tokens):
                pass

            async def _reset_llm_context(self):
                return True

            def _build_critical_findings_context(self):
                return "summary"

            def _build_handoff_summary(self):
                return "handoff"

            def _analyze_llm_output(
                self, current_phase, content_acc, thinking_acc, tool_calls_acc
            ):
                return content_acc, thinking_acc, tool_calls_acc, False

            def _has_scan_work(self):
                return False

            def _normalize_tool_args(self, tn, args, session):
                return args or {}

            def _is_duplicate_command(self, tn, args):
                return False, ""

            def _validate_tool_args(self, tn, args):
                return True, None

            def _check_output_dedup(self, args):
                pass

            async def _execute_tool_and_record(self, tn, args):
                return True, 0.1, {"success": True, "result": "ok"}, None

            def _apply_output_merge(self, args, success):
                pass

            def _truncate_result(self, result):
                return str(result)[:100]

        return DummyAgent()

    @pytest.mark.asyncio
    async def test_loop_yields_done_when_stop_requested(self, agent):
        agent._stop_requested = True
        cfg = MagicMock()
        cfg.llm_context_window = 8192

        events = []
        async for event in agent._run_iteration_loop(cfg):
            events.append(event)

        assert any(e.type == "error" for e in events)
        assert any(e.type == "done" for e in events)

    @pytest.mark.asyncio
    async def test_loop_yields_error_on_fatal_llm(self, agent):
        agent._fatal_llm_error = "runner died"
        cfg = MagicMock()
        cfg.llm_context_window = 8192

        events = []
        async for event in agent._run_iteration_loop(cfg):
            events.append(event)

        assert any(e.type == "error" for e in events)
        assert any(e.type == "done" for e in events)

    @pytest.mark.asyncio
    async def test_loop_respects_max_iterations(self, agent):
        agent.state.max_iterations = 0
        cfg = MagicMock()
        cfg.llm_context_window = 8192

        events = []
        async for event in agent._run_iteration_loop(cfg):
            events.append(event)

        # Should exit immediately with done
        assert any(e.type == "done" for e in events)

    @pytest.mark.asyncio
    async def test_loop_sets_adaptive_num_ctx_from_config(self, agent):
        agent._adaptive_num_ctx = 0
        cfg = MagicMock()
        cfg.llm_context_window = 32768

        # Mock llm to return empty stream immediately
        async def empty_stream(**kwargs):
            return
            yield

        agent.llm.chat_stream = empty_stream

        events = []
        async for event in agent._run_iteration_loop(cfg):
            events.append(event)
            if len(events) > 20:
                break

        # Should have set token_usage limit
        assert agent.state.token_usage["limit"] == 32768

    @pytest.mark.asyncio
    async def test_loop_clamps_num_ctx_below_minimum(self, agent):
        agent._adaptive_num_ctx = 0
        cfg = MagicMock()
        cfg.llm_context_window = 4096  # below 8192 minimum

        async def empty_stream(**kwargs):
            return
            yield

        agent.llm.chat_stream = empty_stream

        events = []
        async for event in agent._run_iteration_loop(cfg):
            events.append(event)
            if len(events) > 20:
                break

        # Should have been clamped to 8192
        assert agent.state.token_usage["limit"] == 8192

    @pytest.mark.asyncio
    async def test_loop_handles_unlimited_context(self, agent):
        agent._adaptive_num_ctx = -1
        cfg = MagicMock()
        cfg.llm_context_window = -1

        async def empty_stream(**kwargs):
            return
            yield

        agent.llm.chat_stream = empty_stream

        events = []
        async for event in agent._run_iteration_loop(cfg):
            events.append(event)
            if len(events) > 20:
                break

        assert agent.state.token_usage["limit"] == -1

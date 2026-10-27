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

    @pytest.mark.asyncio
    async def test_context_error_stops_without_auto_recovery(self, agent, monkeypatch):
        from types import SimpleNamespace
        from unittest.mock import AsyncMock

        from airecon.proxy.config import DEFAULT_CONFIG
        from airecon.proxy.llm import LLMBackendHTTPError

        cfg = SimpleNamespace(**DEFAULT_CONFIG)
        agent.state.max_iterations = 1
        agent._consecutive_failures = 0
        agent._fit_num_predict_to_ctx = lambda predict, ctx: min(predict, ctx)
        original_conversation = [{"role": "user", "content": "Read the fixture."}]
        agent.state.conversation = list(original_conversation)
        attempts = []
        sleep = AsyncMock()
        monkeypatch.setattr("airecon.proxy.agent.loop_tool_cycle.asyncio.sleep", sleep)

        async def failed_stream(**kwargs):
            attempts.append(kwargs)
            raise LLMBackendHTTPError(
                500,
                'OpenAI-compatible returned HTTP 500: '
                '{"error":{"message":"no user query found in messages"}}',
            )
            yield  # pragma: no cover — preserve the async-generator interface

        agent.llm.chat_stream = failed_stream
        events = [event async for event in agent._run_iteration_loop(cfg)]

        assert len(attempts) == 1
        sleep.assert_not_awaited()
        assert not any("AUTO-RECOVERY" in str(event.data) for event in events)
        errors = [event.data for event in events if event.type == "error"]
        assert len(errors) == 1
        assert errors[0]["reason"] == "llm_context_error"
        assert "OLLAMA_CONTEXT_LENGTH" in errors[0]["message"]
        assert events[-1].type == "done"
        assert agent._vram_crash_count == 0
        assert any(m == original_conversation[0] for m in agent.state.conversation)

    @pytest.mark.asyncio
    async def test_context_recovery_retries_only_smaller_payloads_and_is_bounded(self, agent, monkeypatch, tmp_path):
        from types import MethodType, SimpleNamespace
        from unittest.mock import AsyncMock
        from airecon.proxy.agent.loop_context import _ContextMixin
        from airecon.proxy.context_budget import ArtifactCompressor, request_chars
        from airecon.proxy.config import DEFAULT_CONFIG
        from airecon.proxy.llm import LLMBackendHTTPError

        agent._fit_num_predict_to_ctx = lambda predict, ctx: min(predict, ctx)
        agent._consecutive_failures = 0
        agent.state.conversation = [
            {"role": "user", "content": "Stay in example.test only."},
            {"role": "assistant", "content": "", "tool_calls": [{"id": "call_1", "function": {"name": "execute", "arguments": {}}}]},
            {"role": "tool", "tool_call_id": "call_1", "content": "noise " * 10000},
        ]
        agent._messages_for_llm = lambda: agent.state.conversation
        agent._get_artifact_compressor = lambda: ArtifactCompressor(tmp_path, rtk="", caveman="")
        agent._recover_context_budget = MethodType(_ContextMixin._recover_context_budget, agent)
        sizes = []
        sleep = AsyncMock()
        monkeypatch.setattr("airecon.proxy.agent.loop_tool_cycle.asyncio.sleep", sleep)

        async def reject(**kwargs):
            sizes.append(request_chars(kwargs["messages"], kwargs["tools"]))
            raise LLMBackendHTTPError(500, "no user query found in messages")
            yield  # pragma: no cover

        agent.llm.chat_stream = reject
        events = [e async for e in agent._run_iteration_loop(SimpleNamespace(**DEFAULT_CONFIG))]
        assert 1 < len(sizes) <= 4
        assert all(after < before for before, after in zip(sizes, sizes[1:]))
        sleep.assert_not_awaited()
        assert events[-1].type == "done"
        assert any(e.type == "error" and e.data["reason"] == "llm_context_error" for e in events)

    @pytest.mark.asyncio
    async def test_oversized_mandatory_context_stops_before_repeated_local_compaction(self, agent, tmp_path):
        from types import MethodType, SimpleNamespace
        from airecon.proxy.agent.loop_context import _ContextMixin
        from airecon.proxy.context_budget import ArtifactCompressor
        from airecon.proxy.config import DEFAULT_CONFIG
        agent._fit_num_predict_to_ctx = lambda predict, ctx: min(predict, ctx)
        agent.state.conversation = [{"role": "user", "content": "Never leave example.test. " * 5000}]
        agent._recompute_used_tokens_from_conversation = lambda: 100_000
        agent._compress_old_tool_outputs = lambda **kwargs: None
        agent._build_compressed_findings_summary = lambda: ""
        agent._calc_keep_recent = lambda *args, **kwargs: 35
        agent._apply_local_context_fallback = lambda **kwargs: None
        agent._get_artifact_compressor = lambda: ArtifactCompressor(tmp_path, rtk="", caveman="")
        agent._enforce_char_budget = MethodType(_ContextMixin._enforce_char_budget, agent)
        cfg = SimpleNamespace(**DEFAULT_CONFIG)
        cfg.llm_context_window = 8192
        events = []
        async for event in agent._run_iteration_loop(cfg):
            events.append(event)
            if len(events) > 5:
                break
        assert events[-1].type == "done"
        assert any(e.type == "error" and e.data["reason"] == "context_budget" for e in events)
        agent.llm.chat_stream.assert_not_called()

    @pytest.mark.asyncio
    async def test_invalid_tool_arguments_get_bounded_correction_not_connection_backoff(self, agent, monkeypatch):
        from types import SimpleNamespace
        from unittest.mock import AsyncMock
        from airecon.proxy.config import DEFAULT_CONFIG
        from airecon.proxy.llm import LLMToolCallError
        agent._fit_num_predict_to_ctx = lambda predict, ctx: min(predict, ctx)
        agent._consecutive_failures = 0
        agent.state.conversation = [{"role": "user", "content": "Do not access /payments."}]
        agent._messages_for_llm = lambda: agent.state.conversation
        agent._tools_llm = [{"type": "function", "function": {"name": "execute", "parameters": {
            "type": "object", "properties": {"command": {"type": "string"}}, "required": ["command"],
        }}}]
        requests = []
        async def invalid(**kwargs):
            import copy
            requests.append(copy.deepcopy(kwargs["messages"]))
            raise LLMToolCallError("execute", "missing required argument 'command'")
            yield  # pragma: no cover
        sleep = AsyncMock()
        monkeypatch.setattr("airecon.proxy.agent.loop_tool_cycle.asyncio.sleep", sleep)
        agent.llm.chat_stream = invalid
        events = [e async for e in agent._run_iteration_loop(SimpleNamespace(**DEFAULT_CONFIG))]
        assert len(requests) == 3  # original + two repair requests, never a scan/tool call
        assert requests[1] != requests[0]
        assert any("command" in m.get("content", "") and "TOOL CALL REPAIR" in m.get("content", "") for m in requests[1])
        assert all(any(m.get("content") == "Do not access /payments." for m in request) for request in requests)
        sleep.assert_not_awaited()
        assert not any(e.type == "tool_start" for e in events)
        assert events[-1].type == "done"
        assert any(e.type == "error" and e.data.get("reason") == "invalid_tool_arguments" for e in events)

    @pytest.mark.asyncio
    async def test_repaired_tool_call_reaches_existing_validation_with_exact_command(self, agent, monkeypatch):
        from types import SimpleNamespace
        from unittest.mock import AsyncMock
        from airecon.proxy.config import DEFAULT_CONFIG
        from airecon.proxy.llm import LLMToolCallError
        agent._fit_num_predict_to_ctx = lambda predict, ctx: min(predict, ctx)
        agent._consecutive_failures = 0
        seen = []
        async def repair(**kwargs):
            seen.append(kwargs["messages"])
            if len(seen) == 1:
                raise LLMToolCallError("execute", "missing required argument 'command'")
            yield {"message": {"tool_calls": [{"id": "repaired", "function": {
                "name": "execute", "arguments": {"command": "printf synthetic_fixture"},
            }}]}, "done": True}
        admitted = []
        def validate(name, arguments):
            admitted.append((name, arguments))
            agent._stop_requested = True
            return False, "fixture stops here; no command execution"
        agent.llm.chat_stream = repair
        agent._validate_tool_args = validate
        agent._append_tool_result = lambda *args: None
        sleep = AsyncMock()
        monkeypatch.setattr("airecon.proxy.agent.loop_tool_cycle.asyncio.sleep", sleep)
        events = [e async for e in agent._run_iteration_loop(SimpleNamespace(**DEFAULT_CONFIG))]
        assert len(seen) == 2
        assert admitted == [("execute", {"command": "printf synthetic_fixture"})]
        assert any(e.type == "llm_status" and e.data.get("recovered") is True for e in events)
        sleep.assert_not_awaited()
        assert events[-1].type == "done"

    @pytest.mark.asyncio
    @pytest.mark.parametrize("failure", [RuntimeError("fixture parser fault"), ValueError("fixture bad input"), AttributeError("fixture missing field")])
    async def test_local_faults_do_not_enter_connection_retry(self, agent, monkeypatch, failure):
        from types import SimpleNamespace
        from unittest.mock import AsyncMock
        from airecon.proxy.config import DEFAULT_CONFIG
        agent._fit_num_predict_to_ctx = lambda predict, ctx: min(predict, ctx)
        agent._consecutive_failures = 0
        attempts = []
        async def fail(**kwargs):
            attempts.append(kwargs)
            raise failure
            yield
        agent.llm.chat_stream = fail
        sleep = AsyncMock()
        monkeypatch.setattr("airecon.proxy.agent.loop_tool_cycle.asyncio.sleep", sleep)
        events = [e async for e in agent._run_iteration_loop(SimpleNamespace(**DEFAULT_CONFIG))]
        assert len(attempts) == 1
        sleep.assert_not_awaited()
        assert not any("AUTO-RECOVERY" in str(e.data) for e in events)
        assert any(e.type == "error" and e.data.get("reason") == "llm_stream_error" for e in events)

    @pytest.mark.asyncio
    @pytest.mark.parametrize("status", [429, 503])
    async def test_transient_http_has_one_retry_owner_and_no_fake_vram_recovery(self, agent, monkeypatch, status):
        from types import SimpleNamespace
        from unittest.mock import AsyncMock
        from airecon.proxy.config import DEFAULT_CONFIG
        from airecon.proxy.llm import LLMBackendHTTPError
        agent._fit_num_predict_to_ctx = lambda predict, ctx: min(predict, ctx)
        agent._consecutive_failures = 0
        attempts = []
        async def fail(**kwargs):
            attempts.append(kwargs)
            raise LLMBackendHTTPError(status, f"OpenAI-compatible returned HTTP {status}: fixture unavailable")
            yield
        agent.llm.chat_stream = fail
        sleep = AsyncMock()
        monkeypatch.setattr("airecon.proxy.agent.loop_tool_cycle.asyncio.sleep", sleep)
        events = [e async for e in agent._run_iteration_loop(SimpleNamespace(**DEFAULT_CONFIG))]
        assert len(attempts) == 5
        assert all(a.get("max_retries") == 0 for a in attempts)
        assert agent._vram_crash_count == 0
        assert all(f"HTTP {status}" in e.data["content"] for e in events if e.type == "text" and "Retrying in" in e.data.get("content", ""))
        assert not any(e.type == "tool_start" for e in events)

    @pytest.mark.asyncio
    async def test_empty_response_recovery_preserves_earlier_user_constraints(self, agent, monkeypatch):
        from types import SimpleNamespace
        from unittest.mock import AsyncMock
        from airecon.proxy.config import DEFAULT_CONFIG
        agent._fit_num_predict_to_ctx = lambda predict, ctx: min(predict, ctx)
        agent.state.max_iterations = 1
        agent._empty_response_retry_count = 2
        constraint = {"role": "user", "content": "Never request /payments."}
        agent.state.conversation = [constraint] + [{"role": "assistant", "content": f"fixture {i}"} for i in range(35)]
        async def empty(**kwargs):
            return
            yield
        agent.llm.chat_stream = empty
        monkeypatch.setattr("airecon.proxy.agent.loop_tool_cycle.asyncio.sleep", AsyncMock())
        _ = [e async for e in agent._run_iteration_loop(SimpleNamespace(**DEFAULT_CONFIG))]
        assert constraint in agent.state.conversation

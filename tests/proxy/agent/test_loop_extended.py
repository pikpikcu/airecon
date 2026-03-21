"""Extended AgentLoop tests: VRAM crash patterns, dedup logic, session init,
tool call parsing, and mocked end-to-end streaming."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from airecon.proxy.agent.loop import AgentLoop
from airecon.proxy.agent.pipeline import PipelinePhase


# ── Fixture ───────────────────────────────────────────────────────────────────

@pytest.fixture
def loop(mocker):
    ollama_mock = MagicMock()
    ollama_mock.chat_stream = AsyncMock()

    engine_mock = MagicMock()
    engine_mock.discover_tools = AsyncMock(return_value=[])
    engine_mock.tools_to_ollama_format = MagicMock(return_value=[])

    with patch("airecon.proxy.agent.loop.get_config") as mock_cfg:
        cfg = MagicMock()
        cfg.agent_max_tool_iterations = 10
        cfg.ollama_num_ctx_small = 16384
        mock_cfg.return_value = cfg
        agent = AgentLoop(ollama=ollama_mock, engine=engine_mock)
        return agent


# ── VRAM crash detection patterns ─────────────────────────────────────────────

class TestVRAMCrashPatterns:
    """Verify that the _is_vram_crash detection heuristics in loop.py
    correctly identify OOM/crash errors from Ollama.

    These patterns must stay in sync with loop.py lines 846-856.
    We test them via a whitebox check on the set of strings.
    """

    # Patterns that SHOULD trigger VRAM crash recovery
    CRASH_ERRORS = [
        "invalid character '<' looking for beginning of value",
        "failed to parse JSON response from Ollama",
        "HTML error page returned by Ollama",
        "unexpected end of json input",
        "<!doctype html>",
        "<html><body>Error</body></html>",
        "CUDA out of memory. Tried to allocate 2.00 GiB",
        "out of memory",
        "llm runner process no longer alive",
        "signal: killed",
    ]

    # Errors that should NOT trigger VRAM recovery
    NON_CRASH_ERRORS = [
        "connection refused",
        "model not found: llama3",
        "request timed out",
        "context length exceeded",
    ]

    @staticmethod
    def _is_vram_crash(err_str: str) -> bool:
        """Mirror of the detection logic in loop.py."""
        err_lower = err_str.lower()
        return (
            "invalid character '<'" in err_str
            or "failed to parse JSON" in err_str
            or "HTML error page" in err_str
            or "unexpected end of json" in err_lower
            or "<!doctype" in err_lower
            or "<html" in err_lower
            or "out of memory" in err_lower
            or "cuda out of memory" in err_lower
            or "llm runner process no longer alive" in err_lower
            or "signal: killed" in err_lower
        )

    @pytest.mark.parametrize("err", CRASH_ERRORS)
    def test_vram_crash_pattern_detected(self, err):
        assert self._is_vram_crash(err) is True, f"Expected crash for: {err!r}"

    @pytest.mark.parametrize("err", NON_CRASH_ERRORS)
    def test_non_crash_not_flagged(self, err):
        assert self._is_vram_crash(err) is False, f"Expected no crash for: {err!r}"


# ── Deduplication logic ───────────────────────────────────────────────────────

class TestDuplicateCommandDetection:
    def test_same_execute_command_is_duplicate(self, loop):
        loop._is_duplicate_command("execute", {"command": "nmap -sV 10.0.0.1"})
        is_dup, msg = loop._is_duplicate_command("execute", {"command": "nmap -sV 10.0.0.1"})
        assert is_dup
        assert "[ANTI-REPEAT]" in msg

    def test_different_commands_not_duplicate(self, loop):
        loop._is_duplicate_command("execute", {"command": "nmap -sV 10.0.0.1"})
        is_dup, _ = loop._is_duplicate_command("execute", {"command": "nmap -p 443 10.0.0.1"})
        assert not is_dup

    def test_create_file_always_allowed(self, loop):
        """create_file is in DEDUP_EXEMPT_TOOLS and must never be blocked."""
        loop._is_duplicate_command("create_file", {"path": "test.txt", "content": "a"})
        is_dup, _ = loop._is_duplicate_command("create_file", {"path": "test.txt", "content": "a"})
        assert not is_dup

    def test_create_vulnerability_report_exempt(self, loop):
        loop._is_duplicate_command("create_vulnerability_report", {"title": "SQLi"})
        is_dup, _ = loop._is_duplicate_command("create_vulnerability_report", {"title": "SQLi"})
        assert not is_dup

    def test_browser_click_is_exempt(self, loop):
        """Browser interactive actions must always be allowed."""
        args = {"action": "click", "coordinate": "500,300"}
        loop._is_duplicate_command("browser_action", args)
        is_dup, _ = loop._is_duplicate_command("browser_action", args)
        assert not is_dup

    def test_browser_goto_can_be_deduped(self, loop):
        """Non-interactive browser actions (goto) should be deduped."""
        args = {"action": "goto", "url": "http://example.com"}
        loop._is_duplicate_command("browser_action", args)
        is_dup, _ = loop._is_duplicate_command("browser_action", args)
        assert is_dup


# ── Session initialisation ────────────────────────────────────────────────────

class TestAgentLoopInitialisation:
    @pytest.mark.asyncio
    async def test_initialize_creates_session(self, loop, mocker):
        mocker.patch("airecon.proxy.agent.loop.get_system_prompt", return_value="SYS")
        await loop.initialize(target="scanme.com", user_message="start recon")

        # initialize() creates a fresh session with empty target — the target is
        # only extracted and set inside process_message() on the first user turn.
        assert loop._session is not None
        assert loop._session.session_id != ""

    @pytest.mark.asyncio
    async def test_initialize_sets_pipeline(self, loop, mocker):
        mocker.patch("airecon.proxy.agent.loop.get_system_prompt", return_value="SYS")
        await loop.initialize(target="test.com", user_message="go")

        assert loop.pipeline is not None
        from airecon.proxy.agent.pipeline import PipelinePhase
        assert loop.pipeline.get_current_phase() == PipelinePhase.RECON

    @pytest.mark.asyncio
    async def test_initialize_adds_system_prompt_to_conversation(self, loop, mocker):
        mocker.patch("airecon.proxy.agent.loop.get_system_prompt", return_value="CUSTOM SYS PROMPT")
        await loop.initialize(target="test.com", user_message="run scan")

        messages = loop.state.conversation
        assert any("CUSTOM SYS PROMPT" in str(m.get("content", "")) for m in messages)

    @pytest.mark.asyncio
    async def test_initialize_registers_tools_in_conversation(self, loop, mocker):
        mocker.patch("airecon.proxy.agent.loop.get_system_prompt", return_value="SYS")
        await loop.initialize(target="test.com", user_message="scan all ports")

        # After initialize(), the conversation should have system messages listing
        # registered tools (added by the REGISTERED TOOLS system message).
        all_content = " ".join(
            str(m.get("content", "")) for m in loop.state.conversation
        )
        assert "REGISTERED TOOLS" in all_content or "EXECUTE_COMMAND" in all_content


# ── Reset ─────────────────────────────────────────────────────────────────────

class TestAgentLoopReset:
    def test_reset_clears_iteration_count(self, loop):
        loop.state.iteration = 42
        loop.reset()
        assert loop.state.iteration == 0

    def test_reset_clears_executed_tool_counts(self, loop):
        loop._executed_tool_counts = {("execute", "nmap"): 3}
        loop.reset()
        assert loop._executed_tool_counts == {}

    def test_reset_clears_conversation(self, loop):
        loop.state.conversation = [{"role": "user", "content": "test"}]
        loop.reset()
        assert loop.state.conversation == []


# ── Mocked streaming: text response ──────────────────────────────────────────

class TestLoopStreamingWithMockedOllama:
    """Test that the loop correctly yields AgentEvents from a mocked streaming
    Ollama response that returns plain text (no tool calls)."""

    @pytest.mark.asyncio
    async def test_plain_text_response_yields_text_events(self, loop, mocker):
        mocker.patch("airecon.proxy.agent.loop.get_system_prompt", return_value="SYS")
        await loop.initialize(target="test.com", user_message="hello")

        # Build a mock streaming response: 3 chunks + done chunk
        async def _stream(*args, **kwargs):
            chunks = [
                {"message": {"content": "Hello "}, "done": False},
                {"message": {"content": "world!"}, "done": False},
                {"message": {"content": ""}, "done": True,
                 "eval_count": 5, "prompt_eval_count": 20},
            ]
            for chunk in chunks:
                yield chunk

        loop.ollama.chat_stream = _stream

        events = []
        async for event in loop.process_message("hello world"):
            events.append(event)
            if event.type == "done":
                break

        text_events = [e for e in events if e.type == "text"]
        assert len(text_events) > 0
        full_text = "".join(e.data.get("content", "") for e in text_events)
        assert "Hello" in full_text or "world" in full_text

    @pytest.mark.asyncio
    async def test_error_event_on_connection_refused(self, loop, mocker):
        mocker.patch("airecon.proxy.agent.loop.get_system_prompt", return_value="SYS")
        mocker.patch("airecon.proxy.agent.loop.asyncio.sleep")  # prevent 10+30+60+120s retry waits
        await loop.initialize(target="test.com", user_message="go")

        async def _failing_stream(*args, **kwargs):
            raise Exception("connection refused")
            yield  # make it an async generator

        loop.ollama.chat_stream = _failing_stream

        events = []
        async for event in loop.process_message("scan target"):
            events.append(event)
            if event.type in ("error", "done"):
                break

        error_events = [e for e in events if e.type == "error"]
        assert len(error_events) >= 1
        assert "Ollama" in error_events[0].data.get("message", "") or \
               "connect" in error_events[0].data.get("message", "").lower()

    @pytest.mark.asyncio
    async def test_recovery_does_not_stop_on_text_only_hallucination(self, loop, mocker):
        """When active recon target exists, a text-only hallucinated response
        must trigger retry, not immediate done.
        """
        mocker.patch("airecon.proxy.agent.loop.get_system_prompt", return_value="SYS")
        mocker.patch.object(loop, "_scan_workspace_state", return_value="")
        await loop.initialize(target="test.com", user_message="start recon test.com")
        loop.state.active_target = "test.com"

        stream_calls = 0

        async def _stream(*args, **kwargs):
            nonlocal stream_calls
            stream_calls += 1
            if stream_calls == 1:
                yield {
                    "message": {
                        "content": (
                            "Let me run WPScan first.\n"
                            "```bash\n"
                            "wpscan --url https://test.com\n"
                            "```"
                        )
                    },
                    "done": True,
                }
            else:
                yield {
                    "message": {
                        "tool_calls": [
                            {
                                "id": "call_1",
                                "type": "function",
                                "function": {
                                    "name": "execute",
                                    "arguments": "{\"command\":\"echo recovered\"}",
                                },
                            }
                        ]
                    },
                    "done": True,
                }

        loop.ollama.chat_stream = _stream

        events = []
        async for event in loop.process_message("continue recon test.com"):
            events.append(event)
            if event.type == "tool_start":
                break

        assert stream_calls >= 2
        assert not any(e.type == "done" for e in events)
        tool_start = next(e for e in events if e.type == "tool_start")
        assert tool_start.data.get("tool") == "execute"

    @pytest.mark.asyncio
    async def test_watchdog_injects_nudge_then_aborts_after_text_only_retries(self, loop, mocker):
        """After repeated text-only bash-block responses, watchdog injects recovery nudges
        and eventually aborts with an error event (no longer forces a specific tool call)."""
        mocker.patch("airecon.proxy.agent.loop.get_system_prompt", return_value="SYS")
        mocker.patch.object(loop, "_scan_workspace_state", return_value="")
        await loop.initialize(target="test.com", user_message="start recon test.com")
        loop.state.active_target = "test.com"

        stream_calls = 0

        async def _stream(*args, **kwargs):
            nonlocal stream_calls
            stream_calls += 1
            yield {
                "message": {
                    "content": (
                        "I'll run scan now.\n"
                        "```bash\n"
                        "wpscan --url https://test.com\n"
                        "```"
                    )
                },
                "done": True,
            }

        loop.ollama.chat_stream = _stream

        events = []
        async for event in loop.process_message("continue recon test.com"):
            events.append(event)

        # Multiple stream calls should have happened (retry + nudge cycles)
        assert stream_calls >= 3
        # The loop should have aborted with an error after exhausting watchdog attempts
        error_events = [e for e in events if e.type == "error"]
        assert error_events, "Expected watchdog to abort with an error event"
        assert "stuck" in error_events[0].data.get("message", "").lower() or \
               "text-only" in error_events[0].data.get("message", "").lower() or \
               "watchdog" in error_events[0].data.get("message", "").lower()
        # Loop emits error then done — verify error comes before final done
        event_types = [e.type for e in events]
        assert "error" in event_types, "watchdog abort must emit an error event"
        error_idx = next(i for i, e in enumerate(events) if e.type == "error")
        remaining = [e.type for e in events[error_idx + 1:]]
        assert remaining in ([], ["done"]), f"unexpected events after error: {remaining}"


class TestAdvancedStateOrchestration:
    def test_sync_phase_objectives_injects_defaults(self, loop):
        loop._sync_phase_objectives(PipelinePhase.RECON)
        recon_objs = [
            o for o in loop.state.objective_queue
            if o.get("phase") == "RECON"
        ]
        assert len(recon_objs) >= 3

    def test_record_evidence_extracts_key_signals(self, loop):
        loop._record_evidence_from_result(
            phase="EXPLOIT",
            tool_name="execute",
            arguments={"command": "cat output/final.txt"},
            result={
                "stdout": (
                    "Found FLAG{demo-proof}\n"
                    "Potential issue CVE-2024-1234\n"
                    "Endpoint: https://target.local/api/users\n"
                    "Service 443/tcp open\n"
                    "Possible SQLi in id parameter"
                )
            },
            success=True,
            output_file="output/final.txt",
        )
        all_summaries = " ".join(
            str(e.get("summary", "")) for e in loop.state.evidence_log
        )
        assert "FLAG{demo-proof}" in all_summaries
        assert "CVE-2024-1234" in all_summaries
        assert "https://target.local/api/users" in all_summaries
        assert "output/final.txt" in all_summaries

    def test_phase_gate_warns_on_early_exploit_without_evidence(self, loop):
        note = loop._build_phase_gate_note("quick_fuzz", success=True)
        assert "PHASE GATE" in note

    def test_exploration_directive_triggers_on_stagnation(self, loop, mocker):
        mocker.patch("airecon.proxy.agent.loop.get_config", return_value=mocker.MagicMock(
            agent_exploration_mode=True,
            agent_exploration_intensity=0.9,
            agent_stagnation_threshold=1,
            agent_max_same_tool_streak=3,
            agent_tool_diversity_window=8,
            ollama_temperature=0.1,
            agent_exploration_temperature=0.4,
        ))
        loop._stagnation_iterations = 2
        directive = loop._build_exploration_directive(PipelinePhase.RECON)
        assert "AGGRESSIVE EXPLORATION MODE" in directive
        assert "novel" in directive.lower()

    def test_iteration_temperature_raises_when_stagnant(self, loop, mocker):
        cfg = mocker.MagicMock(
            agent_exploration_mode=True,
            ollama_temperature=0.1,
            agent_exploration_temperature=0.4,
            agent_stagnation_threshold=1,
        )
        loop._stagnation_iterations = 2
        temp = loop._get_iteration_temperature(cfg)
        assert temp >= 0.4

    def test_extract_shell_command_candidate_from_code_block(self, loop):
        candidate = loop._extract_shell_command_candidate(
            content_acc=(
                "Let me run this.\n"
                "```bash\n"
                "# enumerate target\n"
                "nmap -sV test.com\n"
                "```"
            ),
            thinking_acc="",
        )
        assert candidate == "nmap -sV test.com"

    def test_quality_scores_have_expected_shape(self, loop):
        loop.state.add_evidence(
            phase="EXPLOIT",
            source_tool="execute",
            summary="Executed exploit command",
            confidence=0.9,
            artifact="output/exploit.txt",
            tags=["artifact", "execution", "trace", "signal"],
        )
        if loop._session:
            loop._session.vulnerabilities.append(
                {"title": "SQL Injection", "report_generated": True}
            )
        scores = loop._compute_quality_scores()
        assert set(scores.keys()) == {
            "evidence", "reproducibility", "impact", "overall", "counts"
        }
        assert 0.0 <= scores["overall"] <= 1.0
        assert scores["counts"]["evidence"] >= 1

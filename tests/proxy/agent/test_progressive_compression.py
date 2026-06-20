"""Tests for Progressive Context Summarization in AgentLoop."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from airecon.proxy.agent.models import AgentState


# ---------------------------------------------------------------------------
# _build_compressed_findings_summary (static helper — test via AgentLoop)
# ---------------------------------------------------------------------------


def _make_loop() -> "AgentLoop":  # type: ignore[name-defined]  # noqa: F821
    """Create a minimal AgentLoop with mocked engine and llm."""
    from airecon.proxy.agent.loop import AgentLoop

    loop = AgentLoop.__new__(AgentLoop)
    loop.state = AgentState()
    loop.llm = AsyncMock()
    loop.engine = MagicMock()
    loop._session = None
    loop._ctf_mode = False
    loop._scope_anchor_target = ""
    loop._scope_lock_active = False
    loop._memory_health_status = {}
    return loop


class TestBuildCompressedFindingsSummary:
    def test_returns_empty_when_nothing_to_pin(self) -> None:
        loop = _make_loop()
        result = loop._build_compressed_findings_summary()
        assert result == ""

    def test_includes_vulnerabilities(self) -> None:
        loop = _make_loop()
        session = MagicMock()
        session.vulnerabilities = [
            {"finding": "SQL injection found in login username parameter"}
        ]
        session.technologies = []
        loop._session = session

        result = loop._build_compressed_findings_summary()
        assert "CONFIRMED VULNS" in result
        assert "SQL injection" in result

    def test_includes_active_hypotheses(self) -> None:
        loop = _make_loop()
        loop.state.add_hypothesis(
            "IDOR via user_id parameter in /api/profile",
            "Send GET /api/profile with different user_id values",
        )

        result = loop._build_compressed_findings_summary()
        assert "ACTIVE HYPOTHESES" in result
        assert "IDOR via user_id" in result

    def test_includes_high_value_evidence(self) -> None:
        loop = _make_loop()
        loop.state.add_evidence(
            phase="EXPLOIT",
            source_tool="sqlmap",
            summary="SQLi confirmed in login endpoint username param via boolean-based",
            confidence=0.95,
            severity=5,
        )

        result = loop._build_compressed_findings_summary()
        assert "HIGH-VALUE EVIDENCE" in result
        assert "sqlmap" in result

    def test_excludes_low_severity_evidence(self) -> None:
        loop = _make_loop()
        loop.state.add_evidence(
            phase="RECON",
            source_tool="nmap",
            summary="Port 80 open on target host",
            confidence=0.90,
            severity=2,  # LOW — should not appear in pinned
        )

        result = loop._build_compressed_findings_summary()
        # No high-value evidence → no "HIGH-VALUE EVIDENCE" section
        assert "HIGH-VALUE EVIDENCE" not in result

    def test_pinned_context_prefix(self) -> None:
        loop = _make_loop()
        loop.state.add_hypothesis("XSS in search form parameter", "send <script>")

        result = loop._build_compressed_findings_summary()
        assert result.startswith("[SYSTEM: PINNED CONTEXT")

    def test_pinned_summary_includes_scope_context(self) -> None:
        loop = _make_loop()
        loop.state.active_target = "example.com"
        loop._scope_anchor_target = "example.com"
        loop._scope_lock_active = True

        result = loop._build_compressed_findings_summary()
        assert "SCOPE TARGET: example.com" in result
        assert "SCOPE ANCHOR: example.com" in result
        assert "SCOPE LOCK: ACTIVE" in result

    def test_pinned_summary_includes_memory_health(self) -> None:
        loop = _make_loop()
        loop.state.active_target = "example.com"
        loop._memory_health_status = {
            "ok": True,
            "target_sessions": 2,
            "target_findings": 7,
            "patterns_total": 9,
            "high_quality_patterns": 3,
        }

        result = loop._build_compressed_findings_summary()
        assert "MEMORY BRAIN: OK" in result
        assert "target_sessions=2" in result

    def test_pinned_summary_includes_failure_and_execution_memory(self) -> None:
        loop = _make_loop()
        loop._compression_summary = "[ANALYSIS_COMP] Investigated /checkout and saw tenant-state anomaly."
        loop.state.failure_log = [
            {
                "name": "ffuf",
                "error_type": "auth",
                "target": "/admin",
                "suggested_action": "Retry with authenticated role context.",
            }
        ]
        loop.state.tool_history = [
            MagicMock(
                tool_name="execute",
                arguments={"command": "ffuf -u https://example.com/FUZZ"},
                status="error",
            ),
            MagicMock(
                tool_name="browser_action",
                arguments={"action": "goto", "url": "https://example.com/checkout"},
                status="success",
            ),
        ]
        loop.state.add_evidence(
            phase="ANALYSIS",
            source_tool="browser_action",
            summary="Workflow signal: tenant checkout approved refund without owner role",
            confidence=0.92,
            tags=["workflow", "tenant", "authorization"],
            severity=4,
        )

        result = loop._build_compressed_findings_summary()
        assert "ITERATIVE MEMORY HANDOFF" in result
        assert "FAILURE MEMORY (DO NOT REPEAT)" in result
        assert "RECENT EXECUTION MEMORY" in result
        assert "UNUSUAL SIGNALS / ANOMALIES" in result


class TestAgentStateCompressionMemory:
    @pytest.mark.asyncio
    async def test_compress_with_llm_carries_prior_summary_and_updates_state(self) -> None:
        state = AgentState()
        state.compression_summary = "[RECON_COMP] api.example.com discovered; /admin pending auth validation."
        state.add_hypothesis(
            "Tenant isolation may fail on /checkout",
            "Replay checkout as member vs owner",
        )
        state.add_failure(
            "ffuf",
            "403 Forbidden on /admin",
            target="/admin",
            error_type="auth",
        )
        state.conversation = [
            {"role": "user", "content": "scan example.com"},
            {"role": "assistant", "content": "Running recon."},
            {"role": "user", "content": "Found /admin and /checkout."},
            {"role": "assistant", "content": "Need to compare tenant behavior."},
            {"role": "user", "content": "Try authenticated path next."},
            {"role": "assistant", "content": "ffuf failed due to auth; browser path looks better."},
            {"role": "user", "content": "The refund workflow looks stateful."},
            {"role": "assistant", "content": "Need to verify owner vs member behavior on refund approval."},
            {"role": "user", "content": "Continue."},
        ]

        llm = AsyncMock()
        llm.model = "qwen3.5:122b"
        llm.complete = AsyncMock(
            return_value="Preserved api.example.com, /admin auth gate, pending tenant checkout comparison, ffuf auth failure noted."
        )

        await state.compress_with_llm(
            llm,
            keep_recent=2,
            phase="ANALYSIS",
        )

        call = llm.complete.await_args.kwargs
        user_prompt = call["messages"][1]["content"]
        assert "PREVIOUS SUMMARY TO PRESERVE" in user_prompt
        assert "RECENT MISTAKES / FAILURES TO REMEMBER" in user_prompt
        assert "OPEN HYPOTHESES / WORK IN PROGRESS" in user_prompt
        assert state.compression_summary.startswith("[ANALYSIS_COMP]")


class TestCompressOldToolOutputs:
    def test_compresses_old_tool_messages(self) -> None:
        loop = _make_loop()
        # Add 25 non-system messages (5 old + 20 recent)
        for i in range(25):
            role = "tool" if i % 2 == 0 else "assistant"
            loop.state.conversation.append(
                {
                    "role": role,
                    "content": "A" * 500 + f" result number {i}",
                }
            )

        loop._compress_old_tool_outputs()

        # Old tool messages (first 5) should be compressed
        tool_msgs = [m for m in loop.state.conversation if m.get("role") == "tool"]
        compressed = [m for m in tool_msgs if m["content"].startswith("[COMPRESSED]")]
        assert len(compressed) > 0

    def test_does_not_compress_recent_8(self) -> None:
        loop = _make_loop()
        # Add exactly 8 non-system messages (all tool)
        for i in range(8):
            loop.state.conversation.append(
                {
                    "role": "tool",
                    "content": "B" * 500,
                }
            )

        loop._compress_old_tool_outputs()

        # All 8 are within the keep-recent window → none compressed
        compressed = [
            m
            for m in loop.state.conversation
            if m.get("role") == "tool" and m["content"].startswith("[COMPRESSED]")
        ]
        assert len(compressed) == 0

    def test_preserves_short_tool_outputs(self) -> None:
        loop = _make_loop()
        # 25 messages, all tool, but short content
        for i in range(25):
            loop.state.conversation.append({"role": "tool", "content": "short"})

        loop._compress_old_tool_outputs()

        # Short messages should NOT be compressed
        compressed = [
            m
            for m in loop.state.conversation
            if m.get("role") == "tool" and m["content"].startswith("[COMPRESSED]")
        ]
        assert len(compressed) == 0

    def test_does_not_compress_system_messages(self) -> None:
        loop = _make_loop()
        for i in range(25):
            loop.state.conversation.append(
                {
                    "role": "system",
                    "content": "D" * 500,
                }
            )

        loop._compress_old_tool_outputs()

        compressed = [
            m
            for m in loop.state.conversation
            if m.get("role") == "system" and m["content"].startswith("[COMPRESSED]")
        ]
        assert len(compressed) == 0

    def test_skips_already_compressed_messages(self) -> None:
        loop = _make_loop()
        # Add 25 messages where some are pre-compressed
        for i in range(25):
            content = "[COMPRESSED] already done" if i < 3 else "E" * 500
            loop.state.conversation.append({"role": "tool", "content": content})

        loop._compress_old_tool_outputs()

        # Pre-compressed messages should not have double-[COMPRESSED]
        for msg in loop.state.conversation:
            assert not msg["content"].startswith("[COMPRESSED] [COMPRESSED]")

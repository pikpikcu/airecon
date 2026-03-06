"""Tests for _FormatterMixin in airecon/proxy/agent/formatters.py.

These tests use a minimal DummyFormatter that extends _FormatterMixin
directly so we can test each method without spinning up a full AgentLoop.
"""

import pytest
from unittest.mock import MagicMock, AsyncMock, patch
from dataclasses import dataclass, field
from typing import Any
from airecon.proxy.agent.formatters import _FormatterMixin, _help_cache


# ── Helpers ──────────────────────────────────────────────────────────────────

@dataclass
class FakeToolExecution:
    tool_name: str
    status: str
    arguments: dict = field(default_factory=dict)
    duration: float = 1.0
    result: dict | None = None


class FakeState:
    def __init__(self, history: list | None = None):
        self.tool_history = history or []


class DummyFormatter(_FormatterMixin):
    """Minimal concrete class that satisfies _FormatterMixin's self.state / self.engine deps."""

    def __init__(self, history=None, engine=None):
        self.state = FakeState(history)
        self.engine = engine


# ── _smart_format_tool_result: failure branch ────────────────────────────────

class TestSmartFormatFailure:
    def setup_method(self):
        self.fmt = DummyFormatter()

    def _fail(self, command="nmap -sV target", error="", stderr="", stdout="", exit_code=1):
        return self.fmt._smart_format_tool_result(
            "execute",
            {"error": error, "stderr": stderr, "stdout": stdout, "exit_code": exit_code},
            success=False,
            command=command,
        )

    def test_command_not_found_shows_tip(self):
        out = self._fail(command="gobuster dir -u http://t.com", error="gobuster: command not found")
        assert "TIP" in out
        assert "gobuster" in out
        assert "apt" in out or "pip" in out

    def test_permission_denied_suggests_sudo(self):
        out = self._fail(command="nmap -sS target", error="permission denied")
        assert "sudo" in out.lower()

    def test_connection_refused_tip(self):
        out = self._fail(error="connection refused to 10.0.0.1")
        assert "TIP" in out
        assert "down" in out.lower() or "filter" in out.lower()

    def test_no_route_to_host_tip(self):
        out = self._fail(error="no route to host")
        assert "Docker" in out or "network" in out.lower()

    def test_invalid_flag_without_engine(self):
        # Engine is None → falls back to "run --help" suggestion
        out = self._fail(command="ffuf -X INVALID", error="unknown flag: -X INVALID")
        assert "TIP" in out or "Flag" in out or "ffuf" in out

    def test_invalid_flag_with_engine_calls_help(self):
        """When engine is present, _auto_help_lookup is attempted."""
        # Clear cache to ensure the lookup runs
        _help_cache.pop("ffuf", None)

        mock_engine = MagicMock()
        mock_engine.execute_tool = AsyncMock(return_value={
            "stdout": "Usage: ffuf [options]\n  -u URL\n  -w WORDLIST\n  -X METHOD"
        })
        fmt = DummyFormatter(engine=mock_engine)
        out = fmt._smart_format_tool_result(
            "execute",
            {"error": "unknown flag -X", "stderr": "", "stdout": "", "exit_code": 2},
            success=False,
            command="ffuf -X INVALID",
        )
        # Either we got the cached help text or a generic TIP
        assert "ffuf" in out or "TIP" in out

    def test_generic_error_action_required(self):
        out = self._fail(error="some unexpected error happened")
        assert "ACTION REQUIRED" in out or "Analyze" in out

    def test_exit_code_present_in_output(self):
        out = self._fail(exit_code=127)
        assert "127" in out

    def test_stderr_included_when_different_from_error(self):
        out = self._fail(
            error="Exit status 1",
            stderr="FATAL: cannot open config file"
        )
        assert "FATAL" in out

    def test_sudo_command_not_suggested_again(self):
        """Already running with sudo — should not suggest sudo again."""
        out = self._fail(command="sudo nmap -sS target", error="permission denied")
        # The TIP for sudo should not appear (already using sudo)
        assert "Retry with elevated" not in out


# ── _smart_format_tool_result: success/execute branch ────────────────────────

class TestSmartFormatSuccess:
    def setup_method(self):
        self.fmt = DummyFormatter()

    def _succeed(self, stdout="", tool="execute", result=None):
        if result is None:
            result = {"stdout": stdout, "success": True}
        return self.fmt._smart_format_tool_result(tool, result, success=True)

    def test_empty_stdout_returns_warning(self):
        out = self._succeed(stdout="")
        assert "NO OUTPUT" in out
        assert "DO NOT invent" in out

    def test_whitespace_only_stdout_is_empty(self):
        out = self._succeed(stdout="   \n   \t  ")
        assert "NO OUTPUT" in out

    def test_small_stdout_returned_as_is(self):
        out = self._succeed(stdout="sub1.example.com\nsub2.example.com")
        assert "sub1.example.com" in out

    def test_large_stdout_truncated(self):
        lines = [f"line-{i}" for i in range(200)]
        out = self._succeed(stdout="\n".join(lines))
        # Generic parser kicks in and returns structured output with first 25 items
        # OR raw fallback with head/tail. Either way: truncation indicator must appear.
        assert "line-0" in out
        has_truncation = (
            "more" in out.lower()
            or "truncated" in out.lower()
            or "TOTAL" in out
        )
        assert has_truncation

    def test_nmap_stdout_structured_format(self):
        nmap_out = (
            "Starting Nmap\n"
            "Host is up (0.01s latency).\n"
            "80/tcp  open  http   Apache httpd 2.4\n"
            "443/tcp open  https  nginx 1.18\n"
        )
        out = self._succeed(stdout=nmap_out)
        # Should show structured summary
        assert "80/tcp" in out or "Nmap" in out

    def test_output_never_exceeds_max_total(self):
        big_stdout = "x" * 15000
        out = self._succeed(stdout=big_stdout)
        assert len(out) <= 12100  # MAX_TOTAL=12000 + small buffer for suffix

    def test_browser_action_hides_screenshot(self):
        result = {
            "success": True,
            "url": "http://example.com",
            "screenshot": "data:image/png;base64,AABBCC==VERY_LONG_BASE64"
        }
        out = self.fmt._smart_format_tool_result("browser_action", result, success=True)
        assert "VERY_LONG_BASE64" not in out
        assert "base64_image_hidden" in out

    def test_browser_action_keeps_other_fields(self):
        result = {"success": True, "url": "http://example.com", "title": "Test Page"}
        out = self.fmt._smart_format_tool_result("browser_action", result, success=True)
        assert "example.com" in out

    def test_result_with_string_result_field(self):
        result = {"success": True, "result": "plain text content"}
        out = self.fmt._smart_format_tool_result("read_file", result, success=True)
        assert "plain text content" in out


# ── _build_recent_history_context ────────────────────────────────────────────

class TestBuildRecentHistoryContext:
    def test_empty_history_returns_empty(self):
        fmt = DummyFormatter(history=[])
        assert fmt._build_recent_history_context() == ""

    def test_execute_entry_shows_command(self):
        entries = [
            FakeToolExecution("execute", "success", {"command": "nmap -sV 10.0.0.1"}, 3.5),
        ]
        fmt = DummyFormatter(history=entries)
        out = fmt._build_recent_history_context()
        assert "nmap" in out
        assert "OK" in out
        assert "3.5s" in out

    def test_execute_strips_cd_prefix(self):
        entries = [
            FakeToolExecution(
                "execute", "success",
                {"command": "cd /workspace/session_abc && nmap -sV target"},
                1.0
            ),
        ]
        fmt = DummyFormatter(history=entries)
        out = fmt._build_recent_history_context()
        assert "cd /workspace" not in out
        assert "nmap" in out

    def test_failed_entry_shows_fail(self):
        entries = [
            FakeToolExecution("execute", "error", {"command": "sqlmap -u http://test"}, 0.5),
        ]
        fmt = DummyFormatter(history=entries)
        out = fmt._build_recent_history_context()
        assert "FAIL" in out

    def test_browser_action_shows_action_and_url(self):
        entries = [
            FakeToolExecution(
                "browser_action", "success",
                {"action": "goto", "url": "http://example.com"},
                2.1
            ),
        ]
        fmt = DummyFormatter(history=entries)
        out = fmt._build_recent_history_context()
        assert "goto" in out
        assert "example.com" in out

    def test_web_search_shows_query(self):
        entries = [
            FakeToolExecution(
                "web_search", "success",
                {"query": "SQLi bypass techniques"},
                0.8
            ),
        ]
        fmt = DummyFormatter(history=entries)
        out = fmt._build_recent_history_context()
        assert "SQLi bypass" in out

    def test_last_n_limit(self):
        entries = [
            FakeToolExecution("execute", "success", {"command": f"cmd-{i}"}, 1.0)
            for i in range(20)
        ]
        fmt = DummyFormatter(history=entries)
        out = fmt._build_recent_history_context(last_n=5)
        assert "cmd-15" in out  # one of the last 5
        assert "cmd-0" not in out  # early entries excluded

    def test_system_header_present(self):
        entries = [FakeToolExecution("execute", "success", {"command": "ls"}, 0.1)]
        fmt = DummyFormatter(history=entries)
        out = fmt._build_recent_history_context()
        assert "RECENT EXECUTIONS" in out


# ── _truncate_result ──────────────────────────────────────────────────────────

class TestTruncateResult:
    def setup_method(self):
        self.fmt = DummyFormatter()

    def test_failed_result_starts_with_error(self):
        out = self.fmt._truncate_result(
            {"success": False, "error": "Something broke"})
        assert out.startswith("ERROR:")
        assert "Something broke" in out

    def test_failed_result_uses_stderr_fallback(self):
        out = self.fmt._truncate_result(
            {"success": False, "error": "", "stderr": "FATAL: panic"})
        assert "FATAL" in out

    def test_failed_no_detail_shows_exit_code(self):
        out = self.fmt._truncate_result(
            {"success": False, "error": "", "stderr": "", "exit_code": 2})
        assert "exit code" in out

    def test_success_with_stdout(self):
        result = {"success": True, "result": {"stdout": "line1\nline2\nline3"}}
        out = self.fmt._truncate_result(result)
        assert "Success" in out
        assert "line1" in out

    def test_success_large_stdout_summarised(self):
        big_stdout = "\n".join([f"sub{i}.example.com" for i in range(300)])
        result = {"success": True, "result": {"stdout": big_stdout}}
        out = self.fmt._truncate_result(result, max_len=500)
        assert "too large" in out or "found" in out.lower()

    def test_success_no_stdout(self):
        result = {"success": True, "result": ""}
        out = self.fmt._truncate_result(result)
        assert "no output" in out.lower() or "executed" in out.lower()

    def test_truncation_limit_applied(self):
        long_error = "E" * 2000
        out = self.fmt._truncate_result(
            {"success": False, "error": long_error}, max_len=100)
        assert "truncated" in out
        assert len(out) < 500

    def test_list_result_shows_preview(self):
        lines = [f"sub{i}.example.com" for i in range(15)]
        stdout = "\n".join(lines)
        result = {"success": True, "result": {"stdout": stdout}}
        out = self.fmt._truncate_result(result)
        assert "Found" in out or "Success" in out

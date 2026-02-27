"""Tests for AgentLoop core logic — target extraction, validation, truncation, dedup, formatting."""

import json
import os
import pytest
import tempfile
from unittest.mock import AsyncMock, MagicMock, patch

# We import the class and instantiate with mocks to test pure logic methods
from airecon.proxy.agent import AgentLoop, AgentState


# ═══════════════════════════════════════════════════════════════
# Fixtures
# ═══════════════════════════════════════════════════════════════

@pytest.fixture
def agent():
    """Create an AgentLoop with mocked dependencies for pure logic testing."""
    ollama = MagicMock()
    engine = MagicMock()
    engine.has_tool = MagicMock(return_value=False)
    loop = AgentLoop(ollama, engine)
    loop._tools_ollama = [
        {"function": {"name": "execute"}},
        {"function": {"name": "browser_action"}},
        {"function": {"name": "web_search"}},
        {"function": {"name": "create_file"}},
        {"function": {"name": "read_file"}},
        {"function": {"name": "create_vulnerability_report"}},
    ]
    return loop


# ═══════════════════════════════════════════════════════════════
# Target Extraction
# ═══════════════════════════════════════════════════════════════

class TestTargetExtraction:
    """Tests for _extract_target_from_text and _extract_targets_from_text."""

    def test_simple_domain(self, agent):
        assert agent._extract_target_from_text("scan example.org") == "example.org"

    def test_subdomain(self, agent):
        assert agent._extract_target_from_text("scan api.example.org") == "api.example.org"

    def test_url_with_scheme(self, agent):
        # Regex matches domain part, scheme is just text before it
        result = agent._extract_target_from_text("scan https://target.com/login")
        assert result == "target.com"

    def test_rejects_file_extensions(self, agent):
        """Bug 2 fix: file names like config.json should NOT be treated as domains."""
        assert agent._extract_target_from_text("read config.json") is None
        assert agent._extract_target_from_text("parse output.txt") is None
        assert agent._extract_target_from_text("open nmap.xml") is None
        assert agent._extract_target_from_text("edit script.py") is None
        assert agent._extract_target_from_text("view report.html") is None
        assert agent._extract_target_from_text("check data.csv") is None
        assert agent._extract_target_from_text("load config.yaml") is None

    def test_rejects_placeholder_targets(self, agent):
        assert agent._extract_target_from_text("scan example.com") is None
        assert agent._extract_target_from_text("scan test.com") is None
        assert agent._extract_target_from_text("scan sub.example.com") is None

    def test_multi_target_extraction(self, agent):
        """Multi-target improvement: finds all domains in text."""
        targets = agent._extract_targets_from_text(
            "scan api.target.com and admin.target.com and mail.target.com"
        )
        assert targets == ["api.target.com", "admin.target.com", "mail.target.com"]

    def test_multi_target_dedup(self, agent):
        """Duplicate domains are removed, order preserved."""
        targets = agent._extract_targets_from_text(
            "scan target.com then scan target.com again"
        )
        assert targets == ["target.com"]

    def test_multi_target_filters_files(self, agent):
        """File extensions rejected even in multi-target mode."""
        targets = agent._extract_targets_from_text(
            "scan target.com and read output.txt and check data.json"
        )
        assert targets == ["target.com"]

    def test_empty_input(self, agent):
        assert agent._extract_target_from_text("") is None
        assert agent._extract_target_from_text(None) is None
        assert agent._extract_targets_from_text("") == []

    def test_no_domain(self, agent):
        assert agent._extract_target_from_text("hello world") is None
        assert agent._extract_target_from_text("run nmap") is None


# ═══════════════════════════════════════════════════════════════
# Tool Argument Validation
# ═══════════════════════════════════════════════════════════════

class TestValidateToolArgs:
    """Tests for _validate_tool_args pre-execution validation."""

    def test_execute_valid(self, agent):
        valid, err = agent._validate_tool_args("execute", {"command": "nmap -sV target.com"})
        assert valid is True
        assert err is None

    def test_execute_empty_command(self, agent):
        valid, err = agent._validate_tool_args("execute", {"command": ""})
        assert valid is False
        assert "non-empty" in err

    def test_execute_missing_command(self, agent):
        valid, err = agent._validate_tool_args("execute", {})
        assert valid is False

    def test_execute_too_long_command(self, agent):
        valid, err = agent._validate_tool_args("execute", {"command": "x" * 25000})
        assert valid is False
        assert "too long" in err

    def test_browser_valid_goto(self, agent):
        valid, err = agent._validate_tool_args("browser_action", {
            "action": "goto", "url": "https://target.com"
        })
        assert valid is True

    def test_browser_invalid_action(self, agent):
        valid, err = agent._validate_tool_args("browser_action", {"action": "fly"})
        assert valid is False
        assert "Invalid browser action" in err

    def test_browser_goto_missing_url(self, agent):
        valid, err = agent._validate_tool_args("browser_action", {"action": "goto", "url": ""})
        assert valid is False
        assert "url" in err.lower()

    def test_browser_click_missing_coordinate(self, agent):
        valid, err = agent._validate_tool_args("browser_action", {"action": "click"})
        assert valid is False
        assert "coordinate" in err.lower()

    def test_browser_type_missing_text(self, agent):
        valid, err = agent._validate_tool_args("browser_action", {"action": "type"})
        assert valid is False

    def test_web_search_valid(self, agent):
        valid, err = agent._validate_tool_args("web_search", {"query": "CVE-2024-1234"})
        assert valid is True

    def test_web_search_empty_query(self, agent):
        valid, err = agent._validate_tool_args("web_search", {"query": ""})
        assert valid is False

    def test_create_file_valid(self, agent):
        valid, err = agent._validate_tool_args("create_file", {
            "path": "report.md", "content": "# Report"
        })
        assert valid is True

    def test_create_file_missing_content(self, agent):
        valid, err = agent._validate_tool_args("create_file", {"path": "report.md"})
        assert valid is False

    def test_read_file_empty_path(self, agent):
        valid, err = agent._validate_tool_args("read_file", {"path": ""})
        assert valid is False

    def test_unknown_tool_passes(self, agent):
        """Unknown tools pass validation (handled elsewhere)."""
        valid, err = agent._validate_tool_args("unknown_tool", {"foo": "bar"})
        assert valid is True


# ═══════════════════════════════════════════════════════════════
# Conversation Truncation
# ═══════════════════════════════════════════════════════════════

class TestTruncateConversation:
    """Tests for AgentState.truncate_conversation sandwich strategy."""

    def test_no_truncation_under_limit(self):
        state = AgentState()
        state.conversation = [{"role": "user", "content": f"msg {i}"} for i in range(30)]
        state.truncate_conversation(max_messages=50)
        assert len(state.conversation) == 30  # unchanged

    def test_truncation_preserves_system(self):
        state = AgentState()
        state.conversation = [
            {"role": "system", "content": "You are AIRecon"},
        ] + [{"role": "user", "content": f"msg {i}"} for i in range(60)]
        state.truncate_conversation(max_messages=20)
        # System message always preserved
        assert state.conversation[0]["content"] == "You are AIRecon"

    def test_truncation_sandwich_structure(self):
        """HEAD_KEEP=4 messages preserved at start, rest from tail."""
        state = AgentState()
        msgs = [{"role": "user", "content": f"msg_{i}"} for i in range(100)]
        state.conversation = msgs
        state.truncate_conversation(max_messages=20)
        # Should have: HEAD(4) + separator(1) + TAIL(16) = 21
        # Find the separator
        separator = [m for m in state.conversation if "messages removed" in m.get("content", "")]
        assert len(separator) == 1
        # First 4 non-system messages preserved
        assert state.conversation[0]["content"] == "msg_0"
        assert state.conversation[3]["content"] == "msg_3"
        # Last message is the most recent
        assert state.conversation[-1]["content"] == "msg_99"

    def test_ephemeral_collapsed(self):
        """Ephemeral system messages collapsed to most recent only."""
        state = AgentState()
        state.conversation = [
            {"role": "system", "content": "Main prompt"},
            {"role": "system", "content": "[SYSTEM: WORKSPACE for old]"},
            {"role": "system", "content": "[SYSTEM: WORKSPACE for new]"},
        ] + [{"role": "user", "content": f"msg {i}"} for i in range(60)]
        state.truncate_conversation(max_messages=20)
        workspace_msgs = [m for m in state.conversation
                         if m.get("content", "").startswith("[SYSTEM: WORKSPACE")]
        assert len(workspace_msgs) == 1
        assert "new" in workspace_msgs[0]["content"]


# ═══════════════════════════════════════════════════════════════
# Tool Deduplication
# ═══════════════════════════════════════════════════════════════

class TestToolDedup:
    """Tests for _executed_tool_counts dedup mechanism."""

    def test_dedup_counter_cleared_on_init(self, agent):
        assert agent._executed_tool_counts == {}

    def test_dedup_key_structure(self, agent):
        """Key is (tool_name, json_serialized_args)."""
        args = {"command": "nmap -sV target.com"}
        key = ("execute", json.dumps(args, sort_keys=True, default=str))
        agent._executed_tool_counts[key] = 1
        assert agent._executed_tool_counts[key] == 1

    def test_dedup_counts_increment(self, agent):
        key = ("execute", json.dumps({"command": "test"}, sort_keys=True))
        agent._executed_tool_counts[key] = 0
        agent._executed_tool_counts[key] += 1
        assert agent._executed_tool_counts[key] == 1
        agent._executed_tool_counts[key] += 1
        assert agent._executed_tool_counts[key] == 2

    def test_clear_resets(self, agent):
        agent._executed_tool_counts[("x", "y")] = 5
        agent._executed_tool_counts.clear()
        assert agent._executed_tool_counts == {}


# ═══════════════════════════════════════════════════════════════
# Normalize Tool Args
# ═══════════════════════════════════════════════════════════════

class TestNormalizeToolArgs:
    """Tests for _normalize_tool_args."""

    def test_dict_passthrough(self, agent):
        args = {"command": "nmap target.com"}
        result = agent._normalize_tool_args("execute", args)
        assert result == {"command": "nmap target.com"}

    def test_string_json_parsed(self, agent):
        args = '{"command": "nmap target.com"}'
        result = agent._normalize_tool_args("execute", args)
        assert result == {"command": "nmap target.com"}

    def test_invalid_json_string_returns_empty(self, agent):
        result = agent._normalize_tool_args("execute", "not json")
        assert result == {}

    def test_non_dict_returns_empty(self, agent):
        assert agent._normalize_tool_args("execute", 42) == {}
        assert agent._normalize_tool_args("execute", [1, 2]) == {}

    def test_placeholder_replacement(self, agent):
        agent.state.active_target = "real-target.com"
        args = {"command": "nmap example.com"}
        result = agent._normalize_tool_args("execute", args)
        assert result["command"] == "nmap real-target.com"

    def test_no_replacement_without_target(self, agent):
        agent.state.active_target = None
        args = {"command": "nmap example.com"}
        result = agent._normalize_tool_args("execute", args)
        assert result["command"] == "nmap example.com"


# ═══════════════════════════════════════════════════════════════
# Smart Format Tool Result
# ═══════════════════════════════════════════════════════════════

class TestSmartFormatToolResult:
    """Tests for _smart_format_tool_result error tips and success formatting."""

    def test_command_not_found_tip(self, agent):
        result = {"error": "bash: gobuster: command not found", "exit_code": 127}
        output = agent._smart_format_tool_result("execute", result, success=False, command="gobuster dir -u ...")
        assert "COMMAND FAILED" in output
        assert "not be installed" in output
        assert "gobuster" in output

    def test_permission_denied_tip(self, agent):
        result = {"error": "Permission denied", "exit_code": 1, "stderr": "Permission denied"}
        output = agent._smart_format_tool_result("execute", result, success=False, command="nmap -sS target.com")
        assert "sudo" in output

    def test_invalid_flag_tip(self, agent):
        result = {"error": "unknown flag: --bogus", "exit_code": 1}
        output = agent._smart_format_tool_result("execute", result, success=False, command="nmap --bogus")
        assert "--help" in output

    def test_connection_refused_tip(self, agent):
        result = {"error": "connection refused", "exit_code": 1}
        output = agent._smart_format_tool_result("execute", result, success=False, command="curl target.com")
        assert "reachability" in output.lower() or "down" in output.lower()

    def test_success_with_output(self, agent):
        result = {"stdout": "found.example.com\nsub.example.com", "exit_code": 0}
        output = agent._smart_format_tool_result("execute", result, success=True)
        assert "found.example.com" in output
        assert "sub.example.com" in output

    def test_success_empty_output(self, agent):
        result = {"stdout": "", "exit_code": 0}
        output = agent._smart_format_tool_result("execute", result, success=True)
        assert "NO OUTPUT" in output
        assert "DO NOT invent" in output

    def test_success_large_output_truncated(self, agent):
        lines = [f"line_{i}" for i in range(200)]
        result = {"stdout": "\n".join(lines), "exit_code": 0}
        output = agent._smart_format_tool_result("execute", result, success=True)
        assert "more lines" in output
        assert "line_0" in output  # Head preserved
        assert "line_199" in output  # Tail preserved

    def test_non_execute_success(self, agent):
        result = {"result": "Search results: CVE-2024-1234"}
        output = agent._smart_format_tool_result("web_search", result, success=True)
        assert "CVE-2024-1234" in output


# ═══════════════════════════════════════════════════════════════
# Reporting (CVSS + Validation)
# ═══════════════════════════════════════════════════════════════

class TestReporting:
    """Tests for reporting.py — CVSS, validation, file dedup."""

    def test_required_field_validation(self):
        from airecon.proxy.reporting import _validate_required_fields
        errors = _validate_required_fields(
            title="", description="test", impact="test",
            target="test", technical_analysis="test",
            poc_description="test", poc_script_code="",
            remediation_steps="test",
        )
        assert any("Title" in e for e in errors)
        assert any("PoC" in e for e in errors)

    def test_cvss_parameter_validation(self):
        from airecon.proxy.reporting import _validate_cvss_parameters
        # Valid
        errors = _validate_cvss_parameters(
            attack_vector="N", attack_complexity="L",
            privileges_required="N", user_interaction="N",
            scope="U", confidentiality="H",
            integrity="H", availability="H",
        )
        assert errors == []

    def test_cvss_invalid_parameter(self):
        from airecon.proxy.reporting import _validate_cvss_parameters
        errors = _validate_cvss_parameters(
            attack_vector="X",  # Invalid
            attack_complexity="L",
            privileges_required="N", user_interaction="N",
            scope="U", confidentiality="H",
            integrity="H", availability="H",
        )
        assert len(errors) >= 1
        assert "attack_vector" in errors[0]

    def test_cvss_calculation(self):
        from airecon.proxy.reporting import calculate_cvss_and_severity
        score, severity, vector = calculate_cvss_and_severity(
            "N", "L", "N", "N", "U", "H", "H", "H"
        )
        assert score > 0
        assert severity in ("critical", "high", "medium", "low", "none", "unknown")
        assert vector.startswith("CVSS:3.1/")

    def test_report_creation(self):
        from airecon.proxy.reporting import create_vulnerability_report
        with tempfile.TemporaryDirectory() as tmpdir:
            result = create_vulnerability_report(
                title="Test XSS in Login",
                description="Reflected XSS found",
                impact="Account takeover",
                target="https://target.com",
                technical_analysis="User input reflected without encoding",
                poc_description="Steps to reproduce",
                poc_script_code="alert(1)",
                remediation_steps="Encode output",
                attack_vector="N", attack_complexity="L",
                privileges_required="N", user_interaction="R",
                scope="C", confidentiality="L",
                integrity="L", availability="N",
                _workspace_root=tmpdir,
            )
            assert result["success"] is True
            assert os.path.exists(result["report_path"])

    def test_report_duplicate_rejected(self):
        from airecon.proxy.reporting import create_vulnerability_report
        with tempfile.TemporaryDirectory() as tmpdir:
            common_args = dict(
                title="Duplicate Finding",
                description="d", impact="i", target="https://t.com",
                technical_analysis="t", poc_description="p",
                poc_script_code="code", remediation_steps="r",
                attack_vector="N", attack_complexity="L",
                privileges_required="N", user_interaction="N",
                scope="U", confidentiality="L",
                integrity="N", availability="N",
                _workspace_root=tmpdir,
            )
            r1 = create_vulnerability_report(**common_args)
            assert r1["success"] is True
            r2 = create_vulnerability_report(**common_args)
            assert r2["success"] is False
            assert "already exists" in r2["message"]


# ═══════════════════════════════════════════════════════════════
# Config
# ═══════════════════════════════════════════════════════════════

class TestConfig:
    """Tests for Config loading and defaults."""

    def test_default_config_values(self):
        from airecon.proxy.config import Config, DEFAULT_CONFIG
        cfg = Config(**DEFAULT_CONFIG)
        assert cfg.ollama_enable_thinking is True
        assert cfg.browser_page_load_delay == 1.0
        assert cfg.agent_max_tool_iterations == 500
        assert cfg.agent_repeat_tool_call_limit == 2
        assert cfg.agent_missing_tool_retry_limit == 2

    def test_config_load_from_file(self):
        from airecon.proxy.config import Config
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"ollama_model": "test-model", "ollama_temperature": 0.1}, f)
            f.flush()
            try:
                cfg = Config.load(config_path=f.name)
                assert cfg.ollama_model == "test-model"
                assert cfg.ollama_temperature == 0.1
                # Defaults still applied
                assert cfg.ollama_enable_thinking is True
            finally:
                os.unlink(f.name)

    def test_config_env_override(self):
        from airecon.proxy.config import Config
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({}, f)
            f.flush()
            try:
                with patch.dict(os.environ, {"AIRECON_OLLAMA_TEMPERATURE": "0.99"}):
                    cfg = Config.load(config_path=f.name)
                    assert cfg.ollama_temperature == 0.99
            finally:
                os.unlink(f.name)


# ═══════════════════════════════════════════════════════════════
# Placeholder Handling
# ═══════════════════════════════════════════════════════════════

class TestPlaceholderHandling:
    """Tests for placeholder detection and replacement."""

    def test_placeholder_detection(self, agent):
        assert agent._is_placeholder_target("example.com") is True
        assert agent._is_placeholder_target("test.com") is True
        assert agent._is_placeholder_target("sub.example.com") is True
        assert agent._is_placeholder_target("real-target.com") is False

    def test_placeholder_replacement_in_args(self, agent):
        agent.state.active_target = "real.com"
        result = agent._replace_placeholder_targets({
            "command": "nmap example.com",
            "targets": ["example.com", "test.com"],
        })
        assert result["command"] == "nmap real.com"
        assert result["targets"] == ["real.com", "real.com"]

    def test_nested_replacement(self, agent):
        agent.state.active_target = "target.io"
        result = agent._replace_placeholder_targets({
            "data": {"url": "https://example.com/api"},
            "list": ["test.com", "other.com"],
        })
        assert result["data"]["url"] == "https://target.io/api"
        assert result["list"][0] == "target.io"
        assert result["list"][1] == "other.com"  # not a placeholder


# ═══════════════════════════════════════════════════════════════
# AgentState
# ═══════════════════════════════════════════════════════════════

class TestAgentState:
    """Tests for AgentState management."""

    def test_add_message(self):
        state = AgentState()
        state.add_message("user", "hello")
        assert len(state.conversation) == 1
        assert state.conversation[0] == {"role": "user", "content": "hello"}

    def test_add_message_with_tool_calls(self):
        state = AgentState()
        tc = [{"function": {"name": "execute", "arguments": {}}}]
        state.add_message("assistant", "text", tool_calls=tc)
        assert state.conversation[0]["tool_calls"] == tc

    def test_add_message_with_thinking(self):
        state = AgentState()
        state.add_message("assistant", "answer", thinking="let me think...")
        assert state.conversation[0]["thinking"] == "let me think..."

    def test_is_approaching_limit(self):
        state = AgentState()
        state.max_iterations = 10
        state.iteration = 7
        assert state.is_approaching_limit() is True
        state.iteration = 5
        assert state.is_approaching_limit() is False

    def test_increment_iteration(self):
        state = AgentState()
        state.increment_iteration()
        assert state.iteration == 1
        state.increment_iteration()
        assert state.iteration == 2


# ═══════════════════════════════════════════════════════════════
# Stop Mechanism
# ═══════════════════════════════════════════════════════════════

class TestStopMechanism:
    """Tests for _stop_requested flag."""

    def test_stop_flag_default_false(self, agent):
        assert agent._stop_requested is False

    def test_consecutive_failure_default(self, agent):
        assert agent._consecutive_failures == 0

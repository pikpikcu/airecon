"""P3 Comprehensive Tests for airecon.proxy.semgrep module.

Tests cover:
- Command building with various options (rules, languages, max findings)
- Output parsing of Semgrep JSON results
- Error handling and edge cases
- Integration with DockerEngine executor
"""

from __future__ import annotations

import json
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

# Module under test
from airecon.proxy import semgrep


class TestGetDefaultRules:
    """Test get_default_rules() function."""

    def test_returns_list(self):
        """Default rules should return a list."""
        rules = semgrep.get_default_rules()
        assert isinstance(rules, list)
        assert len(rules) > 0

    def test_contains_security_audit(self):
        """Default rules should include security-audit."""
        rules = semgrep.get_default_rules()
        assert "p/security-audit" in rules

    def test_contains_owasp_top_ten(self):
        """Default rules should include OWASP Top Ten."""
        rules = semgrep.get_default_rules()
        assert "p/owasp-top-ten" in rules

    def test_does_not_modify_original(self):
        """Calling multiple times should not modify internal state."""
        rules1 = semgrep.get_default_rules()
        rules2 = semgrep.get_default_rules()
        assert rules1 == rules2
        # Verify it's a copy, not the same list
        rules1.append("p/test")
        assert "p/test" not in semgrep.get_default_rules()


class TestBuildSemgrepCommand:
    """Test build_semgrep_command() function."""

    def test_minimal_command(self):
        """Should build command with target path only."""
        cmd = semgrep.build_semgrep_command("/workspace/src")
        assert "semgrep" in cmd
        assert "/workspace/src" in cmd
        assert "--json" in cmd

    def test_with_default_rules(self):
        """Command should use default rules when none provided."""
        cmd = semgrep.build_semgrep_command("/workspace/src")
        assert "--config p/security-audit" in cmd
        assert "--config p/owasp-top-ten" in cmd

    def test_with_custom_rules(self):
        """Command should use custom rules when provided."""
        custom_rules = ["p/custom-rule", "p/another-rule"]
        cmd = semgrep.build_semgrep_command(
            "/workspace/src",
            rules=custom_rules
        )
        assert "--config p/custom-rule" in cmd
        assert "--config p/another-rule" in cmd
        # Default rules should not be present when custom provided
        assert "--config p/security-audit" not in cmd

    def test_with_languages(self):
        """Command should include language filters when provided."""
        cmd = semgrep.build_semgrep_command(
            "/workspace/src",
            languages=["python", "javascript"]
        )
        assert "--lang python,javascript" in cmd

    def test_with_single_language(self):
        """Command should handle single language."""
        cmd = semgrep.build_semgrep_command(
            "/workspace/src",
            languages=["python"]
        )
        assert "--lang python" in cmd

    def test_with_max_findings(self):
        """Command should handle max_findings parameter."""
        cmd = semgrep.build_semgrep_command(
            "/workspace/src",
            max_findings=50
        )
        # The command contains head with max_findings * 5000
        assert "head -c 250000" in cmd  # 50 * 5000

    def test_no_git_ignore_flag(self):
        """Command should include --no-git-ignore flag."""
        cmd = semgrep.build_semgrep_command("/workspace/src")
        assert "--no-git-ignore" in cmd

    def test_timeout_flag(self):
        """Command should include timeout setting."""
        cmd = semgrep.build_semgrep_command("/workspace/src")
        assert "--timeout 120" in cmd

    def test_memory_flag(self):
        """Command should include memory limit."""
        cmd = semgrep.build_semgrep_command("/workspace/src")
        assert "--max-memory 2048" in cmd

    def test_metrics_off(self):
        """Command should disable metrics."""
        cmd = semgrep.build_semgrep_command("/workspace/src")
        assert "--metrics off" in cmd

    def test_json_output_flag(self):
        """Command should specify JSON output format."""
        cmd = semgrep.build_semgrep_command("/workspace/src")
        assert "--json" in cmd


class TestParseSemgrepResults:
    """Test parse_semgrep_results() function."""

    def test_empty_results(self):
        """Should handle empty results JSON."""
        raw_json = json.dumps({"results": [], "errors": []})
        result = semgrep.parse_semgrep_results(raw_json)
        
        assert result["findings"] == []
        assert result["errors"] == []
        assert "No issues found" in result["summary"]
        assert result["total"] == 0

    def test_single_finding(self):
        """Should parse single finding correctly."""
        raw_json = json.dumps({
            "results": [{
                "check_id": "python.lang.security.insecure-hash-function",
                "path": "src/auth.py",
                "start": {"line": 10},
                "end": {"line": 12},
                "extra": {
                    "message": "Use of md5 for password hashing is insecure",
                    "severity": "ERROR",
                    "lines": "hash = md5(password)",
                    "metadata": {
                        "cwe": ["CWE-303"],
                        "owasp": ["A2:2021 – Cryptographic Failures"],
                        "confidence": "HIGH",
                    },
                },
            }],
            "errors": [],
        })
        result = semgrep.parse_semgrep_results(raw_json)
        
        assert len(result["findings"]) == 1
        finding = result["findings"][0]
        assert finding["rule_id"] == "python.lang.security.insecure-hash-function"
        assert finding["file"] == "src/auth.py"
        assert finding["severity"] == "ERROR"
        assert finding["start_line"] == 10
        assert finding["end_line"] == 12
        assert "CWE-303" in finding["cwe"]

    def test_multiple_findings_with_different_severities(self):
        """Should handle multiple findings with different severities."""
        raw_json = json.dumps({
            "results": [
                {
                    "check_id": "rule1",
                    "path": "file1.py",
                    "start": {"line": 1},
                    "end": {"line": 1},
                    "extra": {
                        "message": "Error finding",
                        "severity": "ERROR",
                        "metadata": {},
                    },
                },
                {
                    "check_id": "rule2",
                    "path": "file2.py",
                    "start": {"line": 2},
                    "end": {"line": 2},
                    "extra": {
                        "message": "Warning finding",
                        "severity": "WARNING",
                        "metadata": {},
                    },
                },
                {
                    "check_id": "rule3",
                    "path": "file3.py",
                    "start": {"line": 3},
                    "end": {"line": 3},
                    "extra": {
                        "message": "Info finding",
                        "severity": "INFO",
                        "metadata": {},
                    },
                },
            ],
            "errors": [],
        })
        result = semgrep.parse_semgrep_results(raw_json)
        
        assert len(result["findings"]) == 3
        assert result["total"] == 3
        assert "ERROR: 1" in result["summary"]
        assert "WARNING: 1" in result["summary"]
        assert "INFO: 1" in result["summary"]

    def test_invalid_json(self):
        """Should handle invalid JSON gracefully."""
        raw_json = "not valid json {"
        result = semgrep.parse_semgrep_results(raw_json)
        
        assert result["findings"] == []
        assert len(result["errors"]) > 0
        assert "Parse error" in result["summary"] or "Failed to parse" in result["summary"]

    def test_errors_in_output(self):
        """Should extract errors from Semgrep output."""
        raw_json = json.dumps({
            "results": [],
            "errors": [
                {"type": "timeout", "message": "Scan timed out"},
                {"type": "file_error", "message": "Permission denied"},
            ],
        })
        result = semgrep.parse_semgrep_results(raw_json)
        
        assert len(result["errors"]) == 2
        assert result["errors"][0]["type"] == "timeout"

    def test_metadata_extraction(self):
        """Should extract all metadata fields from results."""
        raw_json = json.dumps({
            "results": [{
                "check_id": "test-rule",
                "path": "test.py",
                "start": {"line": 1},
                "end": {"line": 1},
                "extra": {
                    "message": "Test message",
                    "severity": "WARNING",
                    "lines": "vulnerable_code()",
                    "metadata": {
                        "cwe": ["CWE-89", "CWE-90"],
                        "owasp": ["A03:2021"],
                        "confidence": "MEDIUM",
                        "references": ["https://example.com"],
                    },
                },
            }],
            "errors": [],
        })
        result = semgrep.parse_semgrep_results(raw_json)
        
        finding = result["findings"][0]
        assert finding["cwe"] == ["CWE-89", "CWE-90"]
        assert finding["owasp"] == ["A03:2021"]
        assert finding["confidence"] == "MEDIUM"
        assert len(finding["references"]) == 1

    def test_missing_optional_fields(self):
        """Should handle results with missing optional fields."""
        raw_json = json.dumps({
            "results": [{
                "check_id": "rule",
                "path": "file.py",
                "start": {"line": 5},
                "end": {"line": 5},
                "extra": {
                    "message": "Issue found",
                    "severity": "ERROR",
                },
            }],
            "errors": [],
        })
        result = semgrep.parse_semgrep_results(raw_json)
        
        finding = result["findings"][0]
        assert finding["cwe"] == []
        assert finding["owasp"] == []
        assert finding["references"] == []

    def test_summary_format(self):
        """Summary should be properly formatted."""
        raw_json = json.dumps({
            "results": [
                {
                    "check_id": "r1",
                    "path": "f1.py",
                    "start": {"line": 1},
                    "end": {"line": 1},
                    "extra": {"message": "m1", "severity": "CRITICAL", "metadata": {}},
                },
                {
                    "check_id": "r2",
                    "path": "f2.py",
                    "start": {"line": 2},
                    "end": {"line": 2},
                    "extra": {"message": "m2", "severity": "HIGH", "metadata": {}},
                },
            ],
            "errors": [],
        })
        result = semgrep.parse_semgrep_results(raw_json)
        
        assert "Found 2 issues" in result["summary"]


class TestRunCodeAnalysis:
    """Test run_code_analysis() async function."""

    @pytest.mark.asyncio
    async def test_successful_scan(self):
        """Should run successful scan and return parsed results."""
        mock_engine = AsyncMock()
        mock_engine.execute_tool = AsyncMock()
        
        # First call: which semgrep check
        # Second call: actual semgrep scan
        semgrep_output = json.dumps({
            "results": [{
                "check_id": "test-rule",
                "path": "src/main.py",
                "start": {"line": 1},
                "end": {"line": 1},
                "extra": {
                    "message": "Security issue",
                    "severity": "HIGH",
                    "metadata": {},
                },
            }],
            "errors": [],
        })
        
        mock_engine.execute_tool.side_effect = [
            {"success": True},  # which semgrep
            {"success": True, "result": semgrep_output},  # semgrep scan
        ]
        
        result = await semgrep.run_code_analysis(mock_engine, "/workspace/src")
        
        assert result["total"] == 1
        assert len(result["findings"]) == 1
        assert result["findings"][0]["rule_id"] == "test-rule"

    @pytest.mark.asyncio
    async def test_semgrep_not_installed(self):
        """Should handle semgrep installation check."""
        mock_engine = AsyncMock()
        mock_engine.execute_tool = AsyncMock()
        
        semgrep_output = json.dumps({"results": [], "errors": []})
        mock_engine.execute_tool.side_effect = [
            {"success": False},  # which semgrep fails
            {"success": True, "result": semgrep_output},  # but scan proceeds
        ]
        
        result = await semgrep.run_code_analysis(mock_engine, "/workspace/src")
        
        # Should still attempt to run even if install check failed
        assert isinstance(result, dict)
        assert "findings" in result

    @pytest.mark.asyncio
    async def test_scan_execution_failure(self):
        """Should handle scan execution failure gracefully."""
        mock_engine = AsyncMock()
        mock_engine.execute_tool = AsyncMock()
        
        mock_engine.execute_tool.side_effect = [
            {"success": True},  # which semgrep
            {"success": False, "error": "Command failed"},  # semgrep fails
        ]
        
        result = await semgrep.run_code_analysis(mock_engine, "/workspace/src")
        
        assert result["total"] == 0
        assert len(result["findings"]) == 0
        assert len(result["errors"]) > 0
        assert "Semgrep execution failed" in result["errors"][0]

    @pytest.mark.asyncio
    async def test_no_output_from_semgrep(self):
        """Should handle empty output from Semgrep."""
        mock_engine = AsyncMock()
        mock_engine.execute_tool = AsyncMock()
        
        mock_engine.execute_tool.side_effect = [
            {"success": True},
            {"success": True, "result": ""},  # Empty output
        ]
        
        result = await semgrep.run_code_analysis(mock_engine, "/workspace/src")
        
        assert result["total"] == 0
        assert len(result["findings"]) == 0
        assert "No output from Semgrep" in result["summary"]

    @pytest.mark.asyncio
    async def test_with_custom_rules(self):
        """Should pass custom rules to command builder."""
        mock_engine = AsyncMock()
        mock_engine.execute_tool = AsyncMock()
        
        semgrep_output = json.dumps({"results": [], "errors": []})
        mock_engine.execute_tool.side_effect = [
            {"success": True},
            {"success": True, "result": semgrep_output},
        ]
        
        custom_rules = ["p/custom-rule"]
        result = await semgrep.run_code_analysis(
            mock_engine,
            "/workspace/src",
            rules=custom_rules
        )
        
        # Verify the command builder was called (via execute_tool)
        assert mock_engine.execute_tool.call_count == 2

    @pytest.mark.asyncio
    async def test_with_language_filter(self):
        """Should pass language filter to command builder."""
        mock_engine = AsyncMock()
        mock_engine.execute_tool = AsyncMock()
        
        semgrep_output = json.dumps({"results": [], "errors": []})
        mock_engine.execute_tool.side_effect = [
            {"success": True},
            {"success": True, "result": semgrep_output},
        ]
        
        languages = ["python", "javascript"]
        result = await semgrep.run_code_analysis(
            mock_engine,
            "/workspace/src",
            languages=languages
        )
        
        assert isinstance(result, dict)
        assert "findings" in result


class TestIntegrationScenarios:
    """Integration tests for semgrep module."""

    def test_command_to_parsing_flow(self):
        """Full flow: build command, mock execution, parse results."""
        # Build command
        cmd = semgrep.build_semgrep_command(
            "/workspace/src",
            rules=["p/security-audit"],
            languages=["python"],
            max_findings=100
        )
        
        assert "semgrep" in cmd
        assert "--config p/security-audit" in cmd
        assert "--lang python" in cmd
        assert "/workspace/src" in cmd
        
        # Mock execution result
        mock_output = json.dumps({
            "results": [
                {
                    "check_id": "rule1",
                    "path": "src/auth.py",
                    "start": {"line": 10},
                    "end": {"line": 12},
                    "extra": {
                        "message": "Insecure crypto",
                        "severity": "CRITICAL",
                        "metadata": {"cwe": ["CWE-303"]},
                    },
                }
            ],
            "errors": [],
        })
        
        # Parse output
        result = semgrep.parse_semgrep_results(mock_output)
        
        assert len(result["findings"]) == 1
        assert result["findings"][0]["severity"] == "CRITICAL"
        assert result["total"] == 1

    @pytest.mark.asyncio
    async def test_end_to_end_analysis(self):
        """Test complete analysis flow from init to result."""
        mock_engine = AsyncMock()
        mock_engine.execute_tool = AsyncMock()
        
        semgrep_output = json.dumps({
            "results": [
                {
                    "check_id": "security-rule",
                    "path": "app/main.py",
                    "start": {"line": 42},
                    "end": {"line": 43},
                    "extra": {
                        "message": "SQL injection vulnerability",
                        "severity": "CRITICAL",
                        "lines": 'query = f"SELECT * FROM users WHERE id = {user_id}"',
                        "metadata": {
                            "cwe": ["CWE-89"],
                            "owasp": ["A03:2021 – Injection"],
                            "confidence": "HIGH",
                        },
                    },
                }
            ],
            "errors": [],
        })
        
        mock_engine.execute_tool.side_effect = [
            {"success": True},
            {"success": True, "result": semgrep_output},
        ]
        
        result = await semgrep.run_code_analysis(
            mock_engine,
            "/workspace/src",
            rules=["p/security-audit"],
        )
        
        assert result["total"] == 1
        finding = result["findings"][0]
        assert "SQL injection" in finding["message"].lower() or "SQL injection" in finding["message"]
        assert finding["severity"] == "CRITICAL"
        assert "CWE-89" in finding["cwe"]

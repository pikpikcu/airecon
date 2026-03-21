"""Tests for extract_primary_binary in command_parse.py."""

from __future__ import annotations

from airecon.proxy.agent.command_parse import extract_primary_binary


class TestExtractPrimaryBinaryBasic:
    def test_empty_string(self):
        assert extract_primary_binary("") == ""

    def test_none_like_empty(self):
        assert extract_primary_binary("   ") == ""

    def test_simple_binary(self):
        assert extract_primary_binary("nmap -sV 192.168.1.1") == "nmap"

    def test_full_path_binary(self):
        assert extract_primary_binary("/usr/bin/nmap -sV target") == "nmap"

    def test_lowercase_output(self):
        assert extract_primary_binary("NMAP -sV target") == "nmap"

    def test_flag_only_no_binary(self):
        assert extract_primary_binary("-v -x") == ""


class TestExtractPrimaryBinaryWorkspacePrefix:
    def test_strips_cd_workspace_prefix(self):
        assert extract_primary_binary("cd /workspace/target && nmap -sV 10.0.0.1") == "nmap"

    def test_strips_cd_workspace_with_domain(self):
        assert extract_primary_binary("cd /workspace/example.com && gobuster dir -u http://example.com") == "gobuster"

    def test_strips_cd_workspace_no_subdir(self):
        """cd /workspace && (without subdirectory) must be stripped (regression fix)."""
        assert extract_primary_binary("cd /workspace && nmap -sV target") == "nmap"

    def test_strips_cd_workspace_no_subdir_subfinder(self):
        assert extract_primary_binary("cd /workspace && subfinder -d target.com -o subs.txt") == "subfinder"


class TestExtractPrimaryBinarySudo:
    def test_sudo_simple(self):
        assert extract_primary_binary("sudo nmap -sS target") == "nmap"

    def test_sudo_full_path(self):
        assert extract_primary_binary("sudo /usr/bin/nmap -sS target") == "nmap"

    def test_sudo_with_flags(self):
        assert extract_primary_binary("sudo -n nmap -sS target") == "nmap"


class TestExtractPrimaryBinaryTimeout:
    def test_timeout_seconds(self):
        assert extract_primary_binary("timeout 30 nmap -sV target") == "nmap"

    def test_timeout_with_unit(self):
        assert extract_primary_binary("timeout 5m gobuster dir -u http://target") == "gobuster"

    def test_timeout_with_double_dash(self):
        assert extract_primary_binary("timeout 10 -- nmap target") == "nmap"


class TestExtractPrimaryBinaryStdbuf:
    def test_stdbuf_oL(self):
        assert extract_primary_binary("stdbuf -oL nmap -sV target") == "nmap"

    def test_stdbuf_multiple_flags(self):
        assert extract_primary_binary("stdbuf -oL -eL ffuf -w wordlist -u URL") == "ffuf"


class TestExtractPrimaryBinaryEnv:
    def test_env_key_value(self):
        assert extract_primary_binary("env TERM=xterm nmap target") == "nmap"

    def test_env_multiple_assignments(self):
        assert extract_primary_binary("env FOO=bar BAZ=qux nuclei -u target") == "nuclei"

    def test_env_dash_i(self):
        assert extract_primary_binary("env -i nmap target") == "nmap"

    def test_env_double_dash(self):
        assert extract_primary_binary("env -- nmap target") == "nmap"


class TestExtractPrimaryBinaryShellTrampoline:
    def test_bash_c(self):
        assert extract_primary_binary("bash -c 'nmap -sV target'") == "nmap"

    def test_sh_c(self):
        assert extract_primary_binary("sh -c 'gobuster dir -u http://target'") == "gobuster"

    def test_bash_lc(self):
        assert extract_primary_binary("bash -lc 'nuclei -u target'") == "nuclei"

    def test_full_path_bash(self):
        assert extract_primary_binary("/bin/bash -c 'ffuf -w wl -u URL'") == "ffuf"

    def test_shell_only_no_nested(self):
        # No nested command after flags → returns the shell itself
        result = extract_primary_binary("bash -v")
        assert result == "bash"


class TestExtractPrimaryBinaryNohupNice:
    def test_nohup(self):
        assert extract_primary_binary("nohup nmap -sV target") == "nmap"

    def test_nice(self):
        assert extract_primary_binary("nice nmap -sV target") == "nmap"


class TestExtractPrimaryBinaryEdgeCases:
    def test_unbalanced_quotes_fallback(self):
        # shlex.split fails → falls back to split(), still extracts first token
        result = extract_primary_binary("nmap 'unbalanced")
        assert result == "nmap"

    def test_chained_wrappers(self):
        assert extract_primary_binary("sudo timeout 30 nmap -sV target") == "nmap"

    def test_tool_with_version_flag(self):
        assert extract_primary_binary("nmap --version") == "nmap"

    def test_binary_with_hyphen(self):
        assert extract_primary_binary("sqlmap -u http://target --dbs") == "sqlmap"

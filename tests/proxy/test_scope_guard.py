"""Tests for the config-driven scope guard + audit log."""

from __future__ import annotations

import json

import pytest

from airecon.proxy.scope import (
    ScopeGuard,
    audit_log,
    extract_hosts,
    host_matches,
)


def test_extract_hosts_from_command():
    hosts = extract_hosts("nmap -sV https://app.example.com:443/login then 10.0.0.5")
    assert "app.example.com" in hosts
    assert "10.0.0.5" in hosts


def test_host_matches_apex_and_subdomains():
    assert host_matches("example.com", "example.com")
    assert host_matches("api.example.com", "example.com")
    assert not host_matches("notexample.com", "example.com")
    # wildcard matches subdomains only, not the apex
    assert host_matches("api.example.com", "*.example.com")
    assert not host_matches("example.com", "*.example.com")


def test_denylist_takes_precedence():
    g = ScopeGuard(allowlist=["example.com"], denylist=["admin.example.com"], mode="block")
    ok, reason, host = g.check_command("curl https://admin.example.com/x")
    assert ok is False and host == "admin.example.com" and "denylist" in reason


def test_allowlist_blocks_out_of_scope():
    g = ScopeGuard(allowlist=["example.com"], denylist=[], mode="block")
    assert g.check_command("curl https://api.example.com")[0] is True
    ok, reason, host = g.check_command("curl https://evil.org")
    assert ok is False and host == "evil.org" and "allowlist" in reason


def test_mode_off_and_warn_never_block():
    for mode in ("off", "warn"):
        g = ScopeGuard(allowlist=["example.com"], denylist=["evil.org"], mode=mode)
        # off => no checks at all
        if mode == "off":
            assert g.check_command("curl https://evil.org") == (True, "", "")


def test_empty_allowlist_allows_everything():
    g = ScopeGuard(allowlist=[], denylist=[], mode="block")
    assert g.check_command("nmap https://anything.test")[0] is True


@pytest.mark.parametrize("command", [
    "cat output/scan.txt",
    "python3 tools/filter.py",
    "cat /workspace/example.com/output/hosts.json",
    "curl https://api.example.com/export/error.json -o output/response.json",
])
def test_scope_does_not_treat_path_components_as_hosts(command):
    guard = ScopeGuard(allowlist=["example.com"], denylist=[], mode="block")
    assert guard.check_command(command)[0] is True


@pytest.mark.parametrize("command", [
    "curl outside.example.org/path/file.json",
    "curl https://outside.example.org/path/file.json",
    "curl ftp://outside.example.org/path/file.json",
    "curl http:/outside.example.org/path/file.json",
    "curl http:///outside.example.org/path/file.json",
    "curl //outside.example.org/path/file.json",
    r"curl https:\/\/outside.example.org/path/file.json",
])
def test_scope_still_checks_network_authorities_with_paths(command):
    guard = ScopeGuard(allowlist=["example.com"], denylist=[], mode="block")
    assert guard.check_command(command)[0] is False


def test_audit_log_writes_jsonl(tmp_path, monkeypatch):
    import airecon.proxy.scope as scope_mod

    monkeypatch.setattr(scope_mod, "_audit_path", lambda: tmp_path / "audit.jsonl")

    class _Cfg:
        audit_log_enabled = True

    monkeypatch.setattr(scope_mod, "get_config", lambda: _Cfg())
    audit_log({"type": "execute", "command": "nmap x", "in_scope": True})
    audit_log({"type": "execute", "command": "curl y", "in_scope": False})
    lines = (tmp_path / "audit.jsonl").read_text().strip().splitlines()
    assert len(lines) == 2
    rec = json.loads(lines[0])
    assert rec["type"] == "execute" and "ts" in rec


def test_audit_log_disabled(tmp_path, monkeypatch):
    import airecon.proxy.scope as scope_mod

    monkeypatch.setattr(scope_mod, "_audit_path", lambda: tmp_path / "audit.jsonl")

    class _Cfg:
        audit_log_enabled = False

    monkeypatch.setattr(scope_mod, "get_config", lambda: _Cfg())
    audit_log({"type": "execute"})
    assert not (tmp_path / "audit.jsonl").exists()

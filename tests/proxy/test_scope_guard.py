"""Tests for the config-driven scope guard + audit log."""

from __future__ import annotations

import json

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

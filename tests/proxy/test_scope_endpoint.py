"""Tests for the /api/scope endpoint (TUI /scope command backend)."""

from __future__ import annotations

from types import SimpleNamespace

import httpx
import pytest

import airecon.proxy.server as srv


@pytest.fixture
def _fake_cfg(monkeypatch):
    cfg = SimpleNamespace(
        scope_enforcement="warn",
        scope_allowlist="",
        scope_denylist="",
        audit_log_enabled=True,
    )
    monkeypatch.setattr(srv, "get_config", lambda: cfg)

    def _fake_update(updates):
        for k, v in updates.items():
            setattr(cfg, k, v)
        return cfg

    monkeypatch.setattr("airecon.proxy.config.update_config_values", _fake_update)
    return cfg


async def _post(path, json):
    transport = httpx.ASGITransport(app=srv.app, raise_app_exceptions=True)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        return await c.post(path, json=json)


@pytest.mark.asyncio
async def test_scope_allow_adds_hosts(_fake_cfg):
    r = await _post("/api/scope", {"action": "allow", "hosts": ["1.example.com", "2.example.com"]})
    assert r.status_code == 200
    data = r.json()
    assert data["success"] is True
    assert data["allowlist"] == ["1.example.com", "2.example.com"]


@pytest.mark.asyncio
async def test_scope_deny_adds_hosts(_fake_cfg):
    r = await _post("/api/scope", {"action": "deny", "hosts": ["evil.com"]})
    assert r.json()["denylist"] == ["evil.com"]


@pytest.mark.asyncio
async def test_scope_mode_validation(_fake_cfg):
    ok = await _post("/api/scope", {"action": "mode", "mode": "block"})
    assert ok.json()["mode"] == "block"
    bad = await _post("/api/scope", {"action": "mode", "mode": "bogus"})
    assert bad.status_code == 400


@pytest.mark.asyncio
async def test_scope_show_and_clear(_fake_cfg):
    _fake_cfg.scope_allowlist = "a.com,b.com"
    show = await _post("/api/scope", {"action": "show"})
    assert show.json()["allowlist"] == ["a.com", "b.com"]
    clr = await _post("/api/scope", {"action": "clear"})
    assert clr.json()["allowlist"] == [] and clr.json()["denylist"] == []


@pytest.mark.asyncio
async def test_scope_unknown_action(_fake_cfg):
    r = await _post("/api/scope", {"action": "frobnicate"})
    assert r.status_code == 400


@pytest.mark.asyncio
async def test_scope_allow_dedups(_fake_cfg):
    _fake_cfg.scope_allowlist = "1.example.com"
    r = await _post("/api/scope", {"action": "allow", "hosts": ["1.example.com", "3.example.com"]})
    assert r.json()["allowlist"] == ["1.example.com", "3.example.com"]

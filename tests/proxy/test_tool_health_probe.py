"""Tests for real sandbox tool-health probing."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

import airecon.proxy.server as srv


@pytest.mark.asyncio
async def test_probe_reports_present_and_missing(monkeypatch):
    srv._tool_probe_cache["ts"] = 0.0
    srv._tool_probe_cache["result"] = {}

    class _Cfg:
        tool_health_probe_binaries = "nuclei,nmap,ffuf"
        tool_health_probe_ttl = 300.0

    monkeypatch.setattr(srv, "get_config", lambda: _Cfg())
    fake_engine = type("E", (), {})()
    # Sandbox has nuclei + nmap but not ffuf.
    fake_engine.execute_tool = AsyncMock(return_value={"stdout": "nuclei\nnmap\n"})
    monkeypatch.setattr(srv, "engine", fake_engine)

    result = await srv._probe_sandbox_tools()
    assert result == {"nuclei": True, "nmap": True, "ffuf": False}


@pytest.mark.asyncio
async def test_probe_empty_when_no_engine(monkeypatch):
    srv._tool_probe_cache["ts"] = 0.0
    srv._tool_probe_cache["result"] = {}

    class _Cfg:
        tool_health_probe_binaries = "nuclei"
        tool_health_probe_ttl = 300.0

    monkeypatch.setattr(srv, "get_config", lambda: _Cfg())
    monkeypatch.setattr(srv, "engine", None)
    assert await srv._probe_sandbox_tools() == {}


@pytest.mark.asyncio
async def test_probe_uses_cache(monkeypatch):
    import time

    srv._tool_probe_cache["ts"] = time.time()
    srv._tool_probe_cache["result"] = {"nuclei": True}

    class _Cfg:
        tool_health_probe_binaries = "nuclei"
        tool_health_probe_ttl = 300.0

    monkeypatch.setattr(srv, "get_config", lambda: _Cfg())
    fake_engine = type("E", (), {})()
    fake_engine.execute_tool = AsyncMock(side_effect=AssertionError("should use cache"))
    monkeypatch.setattr(srv, "engine", fake_engine)
    assert await srv._probe_sandbox_tools() == {"nuclei": True}

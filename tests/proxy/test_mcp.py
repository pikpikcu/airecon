from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

import json
from pathlib import Path

from airecon.proxy import mcp
from airecon.proxy.agent.tool_defs import get_tool_definitions


@pytest.mark.asyncio
async def test_mcp_list_tools_command_transport_uses_stdio():
    with (
        patch("airecon.proxy.mcp.list_mcp_servers", return_value={
            "hexstrike": {
                "command": "python3",
                "args": ["/usr/share/hexstrike-ai/hexstrike_mcp.py"],
                "env": {"PYTHONUNBUFFERED": "1"},
            }
        }),
        patch("airecon.proxy.mcp._mcp_stdio_request", new=AsyncMock(return_value=(True, {"tools": [{"name": "ping"}]}))) as stdio_mock,
    ):
        ok, payload = await mcp.mcp_list_tools("hexstrike")

    assert ok is True
    assert payload.get("tools") == [{"name": "ping"}]
    stdio_mock.assert_awaited_once()


@pytest.mark.asyncio
async def test_mcp_call_tool_command_transport_uses_stdio():
    with (
        patch("airecon.proxy.mcp.list_mcp_servers", return_value={
            "hexstrike": {
                "command": "python3",
                "args": ["/usr/share/hexstrike-ai/hexstrike_mcp.py"],
            }
        }),
        patch("airecon.proxy.mcp._mcp_stdio_request", new=AsyncMock(return_value=(True, {"content": [{"type": "text", "text": "ok"}]}))) as stdio_mock,
    ):
        ok, payload = await mcp.mcp_call_tool("hexstrike", "whoami", {"target": "example.com"})

    assert ok is True
    assert "result" in payload
    stdio_mock.assert_awaited_once()


@pytest.mark.asyncio
async def test_mcp_list_tools_http_transport_uses_http_request():
    with (
        patch("airecon.proxy.mcp.list_mcp_servers", return_value={
            "remote": {
                "transport": "sse",
                "url": "http://127.0.0.1:7777/sse",
            }
        }),
        patch("airecon.proxy.mcp._mcp_http_request", new=AsyncMock(return_value=(True, {"tools": [{"name": "a"}, {"name": "b"}]}))) as http_mock,
    ):
        ok, payload = await mcp.mcp_list_tools("remote")

    assert ok is True
    assert len(payload.get("tools", [])) == 2
    http_mock.assert_awaited_once()


@pytest.mark.asyncio
async def test_mcp_list_tools_rejects_disabled_server():
    with patch("airecon.proxy.mcp.list_mcp_servers", return_value={
        "hexstrike": {
            "command": "python3",
            "args": ["/tmp/x.py"],
            "enabled": False,
        }
    }):
        ok, payload = await mcp.mcp_list_tools("hexstrike")

    assert ok is False
    assert "disabled" in str(payload.get("error", "")).lower()


def test_build_auth_headers_basic_and_bearer():
    h1 = mcp._build_auth_headers("user/demo:pass123")
    assert h1.get("Authorization", "").startswith("Basic ")

    h2 = mcp._build_auth_headers("apikey:secret-token")
    assert h2.get("Authorization") == "Bearer secret-token"


def test_tools_json_has_no_hardcoded_mcp_tools():
    tools_path = Path("airecon/proxy/data/tools.json")
    data = json.loads(tools_path.read_text(encoding="utf-8"))
    names = [t.get("function", {}).get("name", "") for t in data]
    assert not any(str(name).startswith("mcp_") for name in names)


def test_mcp_llm_tools_only_exposes_enabled_servers():
    with patch(
        "airecon.proxy.mcp.list_mcp_servers",
        return_value={
            "hexstrike": {"command": "python3", "enabled": True},
            "disabledsrv": {"url": "http://127.0.0.1:7777/sse", "enabled": False},
        },
    ):
        dynamic = mcp.mcp_llm_tools()

    names = [t.get("function", {}).get("name") for t in dynamic]
    assert "mcp_hexstrike" in names
    assert "mcp_disabledsrv" not in names
    action_enum = dynamic[0]["function"]["parameters"]["properties"]["action"]["enum"]
    assert "list_tools" in action_enum
    assert "call_tool" in dynamic[0]["function"]["description"]


def test_get_tool_definitions_includes_dynamic_mcp_tools_when_enabled():
    with patch(
        "airecon.proxy.mcp.list_mcp_servers",
        return_value={"hexstrike": {"command": "python3", "enabled": True}},
    ):
        tools = get_tool_definitions()

    names = [t.get("function", {}).get("name") for t in tools]
    assert "execute" in names
    assert "mcp_hexstrike" in names


@pytest.mark.asyncio
async def test_mcp_stdio_request_performs_initialize_handshake_before_tools_list():
    writes: list[str] = []
    read_buf = [
        b'{"jsonrpc":"2.0","id":1,"result":{"serverInfo":{"name":"hex"}}}\n',
        b'{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"scan"}]}}\n',
    ]

    class _FakeStdin:
        def write(self, data: bytes) -> None:
            writes.append(data.decode("utf-8"))

        async def drain(self) -> None:
            return None

        def close(self) -> None:
            return None

    class _FakeStdout:
        def __init__(self) -> None:
            self._buf = b""

        async def read(self, n: int) -> bytes:
            if not read_buf:
                return b""
            chunk = read_buf.pop(0)
            self._buf += chunk
            return self._buf[:n] if len(self._buf) >= n else self._buf

        async def readline(self) -> bytes:
            # Fallback for tests that still use readline
            if not read_buf:
                return b""
            line = read_buf.pop(0)
            return line

    class _FakeProc:
        def __init__(self) -> None:
            self.stdin = _FakeStdin()
            self.stdout = _FakeStdout()
            self.stderr = None

        async def wait(self) -> int:
            return 0

        def kill(self) -> None:
            return None

    with patch("asyncio.create_subprocess_exec", new=AsyncMock(return_value=_FakeProc())):
        ok, payload = await mcp._mcp_stdio_request(
            {"command": "python3", "args": ["mcp_server.py"]},
            "tools/list",
            {},
        )

    assert ok is True
    assert payload.get("tools") == [{"name": "scan"}]

    sent = "".join(writes)
    assert '"method": "initialize"' in sent
    assert '"method": "notifications/initialized"' in sent
    assert '"method": "tools/list"' in sent


@pytest.mark.asyncio
async def test_mcp_list_tools_truncates_large_toolset_for_context_stability():
    big_tools = [{"name": f"t{i}"} for i in range(60)]
    with patch(
        "airecon.proxy.mcp.list_mcp_servers",
        return_value={"hexstrike": {"command": "python3", "enabled": True}},
    ), patch(
        "airecon.proxy.mcp._mcp_stdio_request",
        new=AsyncMock(return_value=(True, {"tools": big_tools})),
    ):
        ok, payload = await mcp.mcp_list_tools("hexstrike")

    assert ok is True
    assert payload.get("truncated") is True
    assert payload.get("total_tools") == 60
    assert payload.get("omitted") == 10
    assert len(payload.get("tools", [])) == 50


def test_mcp_search_tools_payload_filters_and_limits_results():
    payload = {
        "tools": [
            {"name": "status", "description": "Check current status"},
            {"name": "scan_host", "description": "Scan host quickly"},
            {"name": "scan_deep", "description": "Deep scanner"},
        ]
    }

    out = mcp.mcp_search_tools_payload(payload, query="scan", limit=1)
    assert out["count"] == 1
    assert out["total_matches"] == 2
    assert out["tools"][0]["name"].startswith("scan")


def test_mcp_search_tools_payload_requires_query():
    out = mcp.mcp_search_tools_payload({"tools": []}, query="", limit=10)
    assert out.get("error")


@pytest.mark.asyncio
async def test_mcp_stdio_request_includes_stderr_when_server_exits_early():
    class _FakeStdin:
        def write(self, data: bytes) -> None:
            return None

        async def drain(self) -> None:
            return None

        def close(self) -> None:
            return None

    class _FakeStdout:
        async def read(self, n: int) -> bytes:
            return b""

    class _FakeStderr:
        async def read(self) -> bytes:
            return b"startup failure on port 8888"

    class _FakeProc:
        def __init__(self) -> None:
            self.stdin = _FakeStdin()
            self.stdout = _FakeStdout()
            self.stderr = _FakeStderr()
            self.returncode = None

        async def wait(self) -> int:
            self.returncode = 1
            return 1

        def kill(self) -> None:
            self.returncode = 1

    with patch("asyncio.create_subprocess_exec", new=AsyncMock(return_value=_FakeProc())):
        ok, payload = await mcp._mcp_stdio_request(
            {"command": "python3", "args": ["mcp_server.py"]},
            "tools/list",
            {},
        )

    assert ok is False
    assert "stderr" in str(payload.get("error", "")).lower()
    assert "startup failure" in str(payload.get("error", "")).lower()

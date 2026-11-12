import json
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from airecon.proxy import mcp
from airecon.proxy.config import DEFAULT_CONFIG


@pytest.mark.asyncio
@pytest.mark.parametrize("stdio", [False, True])
@pytest.mark.parametrize("mode,host,allowed", [
    ("block", "outside.example.org", False),
    ("block", "api.example.com", True),
    ("warn", "outside.example.org", True),
    ("off", "outside.example.org", True),
])
async def test_mcp_call_enforces_scope_before_transport(monkeypatch, stdio, mode, host, allowed):
    cfg = SimpleNamespace(**(DEFAULT_CONFIG | {
        "scope_enforcement": mode,
        "scope_allowlist": "example.com",
        "scope_denylist": "",
        "audit_log_enabled": False,
    }))
    monkeypatch.setattr("airecon.proxy.scope.get_config", lambda: cfg)
    monkeypatch.setattr(mcp, "list_mcp_servers", lambda: {
        "fixture": {"command": "fixture"} if stdio else {"url": "http://127.0.0.1"},
    })
    transport = AsyncMock(return_value=(True, {"content": []}))
    monkeypatch.setattr(mcp, "_mcp_stdio_request", transport)
    monkeypatch.setattr(mcp, "_mcp_http_request", transport)
    ok, payload = await mcp.mcp_call_tool(
        "fixture", "status", {"request": {"url": f"https://{host}/"}},
    )
    assert ok is allowed
    if allowed:
        transport.assert_awaited_once()
    else:
        assert "scope" in payload["error"].lower()
        transport.assert_not_awaited()


@pytest.mark.parametrize("arguments,denylist,allowed", [
    ({"targets": "example.com\n203.0.113.9"}, [], False),
    ({"targets": "example.com\t203.0.113.9"}, [], False),
    ({"hosts": "a.example.com\noutside.example.org"}, ["outside.example.org"], False),
    ({"hosts": "a.example.com\toutside.example.org"}, ["outside.example.org"], False),
    ({"targets": "fixture\nexample.com"}, [], True),
    ({"nested": [{"target": "fixture\texample.com"}]}, [], True),
    ({"nested": [{"target": "example.com\n203.0.113.9"}]}, [], False),
    ({"outside.example.org": "fixture"}, ["outside.example.org"], False),
])
def test_mcp_scope_checks_raw_nested_strings(arguments, denylist, allowed):
    from airecon.proxy.scope import ScopeGuard

    guard = ScopeGuard(
        allowlist=[] if denylist else ["example.com"], denylist=denylist, mode="block",
    )
    ok, _, _ = guard.check_tool("mcp_fixture", {"action": "call_tool", "arguments": arguments})
    assert ok is allowed


@pytest.mark.parametrize("host,allowed", [("example.com", True), ("203.0.113.9", False)])
def test_mcp_scope_decodes_supported_json_argument_strings(host, allowed):
    from airecon.proxy.scope import ScopeGuard

    guard = ScopeGuard(allowlist=["example.com"], denylist=[], mode="block")
    arguments = json.dumps({"targets": f"fixture\n{host}"})
    assert guard.check_tool("mcp_fixture", {"action": "call_tool", "arguments": arguments})[0] is allowed

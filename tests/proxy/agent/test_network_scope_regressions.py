"""Scope policy must run before network handlers, not only shell commands."""
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from airecon.proxy.agent.executors import _ExecutorMixin
from airecon.proxy.config import DEFAULT_CONFIG


class Agent(_ExecutorMixin):
    def __init__(self):
        self.state = SimpleNamespace(active_target="example.com", tool_history=[], tool_counts={"exec": 0, "total": 0})
        self._executed_tool_counts = {}


@pytest.fixture
def policy(monkeypatch):
    cfg = SimpleNamespace(**(DEFAULT_CONFIG | {
        "scope_allowlist": "example.com",
        "scope_denylist": "admin.example.com",
        "scope_enforcement": "block",
        "audit_log_enabled": False,
    }))
    monkeypatch.setattr("airecon.proxy.scope.get_config", lambda: cfg)
    monkeypatch.setattr("airecon.proxy.agent.executors_dispatch.get_config", lambda: cfg)
    return cfg


@pytest.mark.asyncio
@pytest.mark.parametrize("tool,args", [
    ("schemathesis_fuzz", {"schema_url": "https://outside.test/openapi.json"}),
    ("schemathesis_fuzz", {"schema_url": " HTTPS://outside.test/openapi.json "}),
    ("schemathesis_fuzz", {"schema_url": "schema.json", "base_url": "https://outside.test"}),
    ("advanced_fuzz", {"target": "https://outside.test"}),
    ("quick_fuzz", {"target": "https://admin.example.com"}),
    ("deep_fuzz", {"target": "https://example.com", "graphql_endpoints": ["https://outside.test/graphql"]}),
    ("caido_send_request", {"host": "outside.test"}),
    ("caido_automate", {"host": "outside.test"}),
    ("http_observe", {"url": "https://outside.test"}),
    ("spawn_agent", {"target": "outside.test"}),
    ("run_parallel_agents", {"targets": ["example.com", "outside.test"]}),
    ("advanced_fuzz", {"target": "https://example.com", "auth_login_url": "https://outside.test/login"}),
])
async def test_network_dispatch_blocks_before_handler(policy, tool, args):
    agent = Agent()
    method, _ = agent._TOOL_DISPATCH_MAP[tool]
    handler = AsyncMock(return_value=(True, 0.0, {"success": True}, None))
    setattr(agent, method, handler)
    outcome = await agent._execute_tool_and_record(tool, args)
    assert outcome[0] is False
    assert "scope" in outcome[2]["error"].lower()
    handler.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("mode,url", [
    ("block", "https://api.example.com/openapi.json"),
    ("warn", "https://outside.test/openapi.json"),
    ("off", "https://outside.test/openapi.json"),
])
async def test_network_dispatch_preserves_allowed_modes(policy, mode, url):
    policy.scope_enforcement = mode
    agent = Agent()
    agent._execute_schemathesis_tool = AsyncMock(return_value=(True, 0.0, {}, None))
    assert (await agent._execute_tool_and_record("schemathesis_fuzz", {"schema_url": url}))[0]
    agent._execute_schemathesis_tool.assert_awaited_once()


@pytest.mark.asyncio
async def test_local_notes_are_not_network_targets(policy):
    agent = Agent()
    agent._execute_create_note_tool = AsyncMock(return_value=(True, 0.0, {}, None))
    assert (await agent._execute_tool_and_record("create_note", {"content": "https://outside.test"}))[0]


@pytest.mark.asyncio
async def test_browser_navigation_enforces_config_scope(policy, monkeypatch):
    browser = MagicMock(return_value={"success": True})
    monkeypatch.setattr("airecon.proxy.agent.executors.browser_action", browser)
    monkeypatch.setattr("airecon.proxy.agent.executors.get_config", lambda: policy)
    agent = Agent()
    result = await agent._execute_local_browser_tool("browser_action", {"action": "goto", "url": "https://outside.test"})
    assert result[0] is False
    assert "scope" in result[2]["error"].lower()
    browser.assert_not_called()

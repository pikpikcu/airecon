import shlex
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from airecon.proxy.agent.executors_observe import _ObserveExecutorMixin
from airecon.proxy.config import DEFAULT_CONFIG


class Agent(_ObserveExecutorMixin):
    def __init__(self, responses):
        self.engine = MagicMock(execute_tool=AsyncMock(side_effect=responses))
        self.state = SimpleNamespace(
            active_target="example.com", http_sessions={}, http_baselines={},
            tool_history=[], tool_counts={"total": 0}, iteration=0,
        )
        self._session = None

    @staticmethod
    def _str_arg(arguments, key):
        value = arguments.get(key)
        return value.strip() if isinstance(value, str) else ""


def reply(status=200, location="", body="fixture"):
    header = f"Location: {location}\r\n" if location else ""
    return {"success": True, "stdout": f"HTTP/1.1 {status} Fixture\r\n{header}\r\n{body}"}


@pytest.fixture(autouse=True)
def policy(monkeypatch, tmp_path):
    config = SimpleNamespace(**(DEFAULT_CONFIG | {
        "scope_enforcement": "block", "scope_allowlist": "example.com", "scope_denylist": "",
        "audit_log_enabled": False,
    }))
    monkeypatch.setattr("airecon.proxy.scope.get_config", lambda: config)
    monkeypatch.setattr("airecon.proxy.agent.executors_observe.get_workspace_root", lambda: tmp_path)


@pytest.mark.asyncio
async def test_http_observe_follows_relative_redirect_and_saves_final_response():
    agent = Agent([reply(302, "/next"), reply(body="final fixture")])
    ok, _, result, _ = await agent._execute_http_observe_tool("http_observe", {
        "url": "https://example.com/start", "follow_redirects": True, "save_as": "final",
    })
    assert ok and result["status_code"] == 200
    assert result["url"] == "https://example.com/next"
    assert agent.state.http_baselines["final"]["body"] == "final fixture"
    assert agent.engine.execute_tool.await_count == 2
    assert agent.state.tool_history[0].arguments["url"] == "https://example.com/start"
    for call in agent.engine.execute_tool.call_args_list:
        assert "--no-location" in shlex.split(call.args[1]["command"])


@pytest.mark.asyncio
async def test_http_observe_blocks_out_of_scope_redirect_before_second_request():
    agent = Agent([reply(302, "https://outside.example.org/next"), reply()])
    ok, _, result, _ = await agent._execute_http_observe_tool("http_observe", {
        "url": "https://example.com/start", "follow_redirects": True,
    })
    assert not ok and "scope" in result["error"].lower()
    assert agent.engine.execute_tool.await_count == 1


@pytest.mark.asyncio
async def test_http_observe_drops_headers_on_cross_origin_redirect():
    agent = Agent([reply(302, "https://api.example.com/next"), reply()])
    ok, _, _, _ = await agent._execute_http_observe_tool("http_observe", {
        "url": "https://example.com/start", "follow_redirects": True,
        "headers": {"Authorization": "fixture credential", "X-Fixture": "private fixture"},
    })
    assert ok and agent.engine.execute_tool.await_count == 2
    command = agent.engine.execute_tool.call_args_list[1].args[1]["command"]
    assert "fixture credential" not in command and "private fixture" not in command


@pytest.mark.asyncio
@pytest.mark.parametrize("location", ["file:///fixture", "https://example.com/start", "http://["])
async def test_http_observe_stops_unsupported_or_looping_redirect(location):
    agent = Agent([reply(302, location), reply()])
    ok, _, result, _ = await agent._execute_http_observe_tool("http_observe", {
        "url": "https://example.com/start", "follow_redirects": True,
    })
    assert not ok and result["error"]
    assert agent.engine.execute_tool.await_count == 1


@pytest.mark.asyncio
async def test_http_observe_keeps_redirect_response_when_follow_is_disabled():
    agent = Agent([reply(302, "/next")])
    ok, _, result, _ = await agent._execute_http_observe_tool("http_observe", {
        "url": "https://example.com/start", "follow_redirects": False,
    })
    assert ok and result["status_code"] == 302
    assert agent.engine.execute_tool.await_count == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("status,method,body,expected_method,expected_body", [
    (301, "POST", "fixture body", "GET", ""),
    (303, "PUT", "fixture body", "GET", ""),
    (307, "POST", "fixture body", "POST", "fixture body"),
    (308, "PUT", "fixture body", "PUT", "fixture body"),
])
async def test_http_observe_preserves_redirect_method_contract(status, method, body, expected_method, expected_body):
    agent = Agent([reply(status, "/next"), reply()])
    ok, _, _, _ = await agent._execute_http_observe_tool("http_observe", {
        "url": "https://example.com/start", "follow_redirects": True,
        "method": method, "body": body, "headers": ["invalid header shape"],
    })
    assert ok
    command = shlex.split(agent.engine.execute_tool.call_args_list[1].args[1]["command"])
    assert command[command.index("-X") + 1] == expected_method
    if expected_body:
        assert command[command.index("--data-raw") + 1] == expected_body
    else:
        assert "--data-raw" not in command


@pytest.mark.asyncio
async def test_http_observe_does_not_forward_body_to_another_origin():
    agent = Agent([reply(307, "https://api.example.com/next"), reply()])
    ok, _, result, _ = await agent._execute_http_observe_tool("http_observe", {
        "url": "https://example.com/start", "follow_redirects": True,
        "method": "POST", "body": "private fixture body",
    })
    assert not ok and "across origins" in result["error"]
    assert agent.engine.execute_tool.await_count == 1


@pytest.mark.asyncio
async def test_http_observe_refuses_https_downgrade_before_sending_cookies():
    agent = Agent([reply(302, "http://example.com/next"), reply()])
    agent.state.http_sessions["example.com"] = {"cookies": {"sid": "fixture cookie"}}
    ok, _, result, _ = await agent._execute_http_observe_tool("http_observe", {
        "url": "https://example.com/start", "follow_redirects": True,
    })
    assert not ok and "downgrade" in result["error"].lower()
    assert agent.engine.execute_tool.await_count == 1


@pytest.mark.asyncio
async def test_http_observe_bounds_a_non_repeating_redirect_chain():
    agent = Agent([reply(302, f"/hop{index}") for index in range(10)])
    ok, _, result, _ = await agent._execute_http_observe_tool("http_observe", {
        "url": "https://example.com/start", "follow_redirects": True,
    })
    assert not ok and "limit" in result["error"]
    assert agent.engine.execute_tool.await_count == 6

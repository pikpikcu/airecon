import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from airecon.proxy.agent.executors import _ExecutorMixin
from airecon.proxy.agent.validators import _ValidatorMixin


class DummyState:
    def __init__(self):
        self.active_target = "example.com"
        self.tool_history = []
        self.tool_counts = {"exec": 0, "total": 0}


class DummyAgent(_ExecutorMixin, _ValidatorMixin):
    def __init__(self):
        self.state = DummyState()
        self._executed_tool_counts = {}
        self._last_output_file = None
        self._session = None

    def _normalize_args_for_dedup(self, tool_name, args):
        return tool_name, str(args)

    def _save_tool_output(self, tool_name, arguments, result):
        pass


@pytest.fixture
def agent():
    return DummyAgent()


@pytest.mark.asyncio
async def test_execute_local_browser_tool(agent, mocker):
    mocker.patch('airecon.proxy.agent.executors.browser_action',
                 return_value={"title": "Test Page"})

    success, duration, result, out_file = await agent._execute_local_browser_tool("browser_action", {"action": "goto", "url": "http://test.com"})

    assert success
    assert result["result"]["title"] == "Test Page"
    assert len(agent.state.tool_history) == 1
    assert agent.state.tool_history[0].tool_name == "browser_action"


@pytest.mark.asyncio
async def test_execute_filesystem_tool_read(agent, mocker):
    mocker.patch('airecon.proxy.agent.executors.read_file', return_value={
                 "success": True, "result": "file content"})

    success, duration, result, out_file = await agent._execute_filesystem_tool("read_file", {"path": "test.txt"})

    assert success
    assert result["result"] == "file content"
    assert "test.txt" in agent.state.tool_history[0].arguments["path"]


@pytest.mark.asyncio
async def test_execute_web_search_tool(agent, mocker):
    async def mock_search(*args, **kwargs):
        return {"success": True, "result": "Search Results String"}

    mocker.patch('airecon.proxy.agent.executors.web_search',
                 side_effect=mock_search)

    with patch('airecon.proxy.agent.executors.get_workspace_root', return_value=MagicMock()):
        with patch('builtins.open', mocker.mock_open()):
            success, duration, result, saved_path = await agent._execute_web_search_tool({"query": "test query"})

            assert success
            assert "Search Results String" in result["result"]
            assert saved_path is not None


@pytest.mark.asyncio
async def test_execute_report_tool(agent, mocker):
    mocker.patch('airecon.proxy.agent.executors.create_vulnerability_report',
                 return_value={"success": True, "finding_id": "VULN-1"})

    success, duration, result, out_file = await agent._execute_report_tool("create_vulnerability_report", {"title": "Test Vuln"})

    assert success
    assert result["finding_id"] == "VULN-1"


# ── schemathesis behavioral tests ─────────────────────────────────────────────

@pytest.mark.asyncio
async def test_schemathesis_malformed_schema_url_dict(agent, mocker):
    """schema_url=dict must not crash — _str_arg coerces to '' → early return."""
    success, duration, result, _ = await agent._execute_schemathesis_tool(
        "schemathesis_fuzz", {"schema_url": {"url": "http://evil"}}
    )
    assert success is False
    assert "schema_url" in result.get("error", "")


@pytest.mark.asyncio
async def test_schemathesis_malformed_max_examples(agent, mocker):
    """max_examples='abc' must fall back to 30, not raise ValueError."""
    mock_exec = AsyncMock(return_value={
        "success": True, "stdout": "1 PASSED", "result": "1 PASSED",
        "error": "", "stderr": "",
    })
    agent.engine = mocker.MagicMock()
    agent.engine.execute_tool = mock_exec

    success, duration, result, _ = await agent._execute_schemathesis_tool(
        "schemathesis_fuzz",
        {"schema_url": "http://target/openapi.json", "max_examples": "abc"},
    )
    assert success is True
    called_cmd = mock_exec.call_args[0][1]["command"]
    assert "--hypothesis-max-examples 30" in called_cmd


@pytest.mark.asyncio
async def test_schemathesis_engine_failure_not_masked(agent, mocker):
    """engine_ok=False must make success=False even when stdout is non-empty."""
    mock_exec = AsyncMock(return_value={
        "success": False,
        "stdout": "some partial output",
        "result": "some partial output",
        "error": "Docker exec failed",
        "stderr": "",
    })
    agent.engine = mocker.MagicMock()
    agent.engine.execute_tool = mock_exec

    success, duration, result, _ = await agent._execute_schemathesis_tool(
        "schemathesis_fuzz", {"schema_url": "http://target/openapi.json"}
    )
    assert success is False
    assert "error" in result


@pytest.mark.asyncio
async def test_schemathesis_happy_path(agent, mocker):
    """Normal successful run reports passes and violations."""
    output = "PASSED\nPASSED\nFAILED\n"
    mock_exec = AsyncMock(return_value={
        "success": True, "stdout": output, "result": output,
        "error": "", "stderr": "",
    })
    agent.engine = mocker.MagicMock()
    agent.engine.execute_tool = mock_exec

    success, duration, result, _ = await agent._execute_schemathesis_tool(
        "schemathesis_fuzz", {"schema_url": "http://target/openapi.json"}
    )
    assert success is True
    assert result["violations"] == 1
    assert result["summary"].startswith("Schemathesis completed: 2 passed")


# ── browser_action_timeout from config fix ────────────────────────────────────

def test_browser_action_timeout_reads_config():
    """browser timeout must come from get_config().browser_action_timeout."""
    src = Path(__file__).parents[3] / "airecon/proxy/agent/executors.py"
    text = src.read_text()
    assert "get_config().browser_action_timeout" in text


def test_browser_action_timeout_not_hardcoded():
    """timeout=120.0 must no longer appear in _execute_local_browser_tool."""
    src = Path(__file__).parents[3] / "airecon/proxy/agent/executors.py"
    text = src.read_text()
    start = text.find("async def _execute_local_browser_tool")
    end = text.find("\n    async def ", start + 1)
    assert "timeout=120.0" not in text[start:end]


# ── tools.json browser_action auth actions fix ────────────────────────────────

def _browser_tool_fn() -> dict:
    tools_path = Path(__file__).parents[3] / "airecon/proxy/data/tools.json"
    for t in json.loads(tools_path.read_text()):
        if t.get("function", {}).get("name") == "browser_action":
            return t["function"]
    raise AssertionError("browser_action not in tools.json")


def test_browser_action_enum_has_auth_actions():
    enum_vals = _browser_tool_fn()["parameters"]["properties"]["action"]["enum"]
    for action in ("login_form", "handle_totp", "save_auth_state", "inject_cookies", "oauth_authorize"):
        assert action in enum_vals, f"browser_action enum missing: {action}"


def test_browser_action_has_auth_param_descriptions():
    props = _browser_tool_fn()["parameters"]["properties"]
    for param in ("username", "password", "totp_secret", "cookies", "oauth_url"):
        assert param in props, f"browser_action missing param description: {param}"

import json
import shlex
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from airecon.proxy.agent.executors import _ExecutorMixin
from airecon.proxy.agent.session import SessionData
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
async def test_execute_allows_caido_setup_for_first_bootstrap(agent, mocker):
    from airecon.proxy.caido_client import CaidoClient

    mocker.patch.object(CaidoClient, "_token", None)
    agent.engine = MagicMock()
    agent.engine.execute_tool = AsyncMock(
        return_value={
            "success": True,
            "stdout": "🔑 Access Token: test-bootstrap-token\n",
            "stderr": "",
        }
    )

    success, _, result, _ = await agent._execute_tool_and_record(
        "execute", {"command": "caido-setup"}
    )

    assert success is True
    assert "next_action" in result
    assert CaidoClient._token == "test-bootstrap-token"


@pytest.mark.asyncio
async def test_execute_rejects_caido_setup_when_token_exists(agent, mocker):
    from airecon.proxy.caido_client import CaidoClient

    mocker.patch.object(CaidoClient, "_token", "already-token")
    success, _, result, _ = await agent._execute_tool_and_record(
        "execute", {"command": "caido-setup"}
    )
    assert success is False
    assert "token already exists" in (result.get("error") or "")


@pytest.mark.asyncio
async def test_execute_rejects_direct_caido_graphql_login(agent):
    cmd = (
        "curl -sL -X POST -H \"Content-Type: application/json\" "
        "-d '{\"query\":\"mutation { loginAsGuest { token { accessToken } } }\"}' "
        "http://127.0.0.1:48080/graphql"
    )
    success, _, result, _ = await agent._execute_tool_and_record(
        "execute", {"command": cmd}
    )
    assert success is False
    err = result.get("error") or ""
    assert "Caido" in err and "caido_list_requests" in err


@pytest.mark.asyncio
async def test_caido_list_requests_applies_filter_and_limit(agent, mocker):
    from airecon.proxy.caido_client import CaidoClient

    mocker.patch.object(
        CaidoClient,
        "gql",
        new=AsyncMock(
            return_value={
                "data": {
                    "requests": {
                        "edges": [
                            {
                                "node": {
                                    "id": "1",
                                    "method": "GET",
                                    "host": "example.com",
                                    "path": "/",
                                    "response": {"statusCode": 200},
                                }
                            },
                            {
                                "node": {
                                    "id": "2",
                                    "method": "POST",
                                    "host": "example.com",
                                    "path": "/login",
                                    "response": {"statusCode": 302},
                                }
                            },
                        ]
                    }
                }
            }
        ),
    )

    success, _, result, _ = await agent._execute_caido_list_requests_tool(
        "caido_list_requests", {"filter": "post", "limit": 1}
    )

    assert success is True
    assert result["total"] == 1
    assert result["requests"][0]["method"] == "POST"


@pytest.mark.asyncio
async def test_caido_sitemap_children_uses_parent_id_variable(agent, mocker):
    from airecon.proxy.caido_client import CaidoClient

    gql_mock = mocker.patch.object(
        CaidoClient,
        "gql",
        new=AsyncMock(return_value={"data": {"sitemapDescendantEntries": {"edges": []}}}),
    )

    success, _, result, _ = await agent._execute_caido_sitemap_tool(
        "caido_sitemap", {"parent_id": "abc123"}
    )

    assert success is True
    assert result["level"] == "children"
    assert gql_mock.await_count == 1
    args, kwargs = gql_mock.await_args
    assert "$parentId" in args[0]
    assert args[1] == {"parentId": "abc123"}


@pytest.mark.asyncio
async def test_caido_set_scope_updates_existing_scope(agent, mocker):
    from airecon.proxy.caido_client import CaidoClient

    gql_mock = mocker.patch.object(
        CaidoClient,
        "gql",
        new=AsyncMock(
            side_effect=[
                {"data": {"scopes": [{"id": "scope-1", "name": "airecon-example.com"}]}},
                {
                    "data": {
                        "updateScope": {
                            "scope": {"id": "scope-1", "name": "airecon-example.com"}
                        }
                    }
                },
            ]
        ),
    )

    success, _, result, _ = await agent._execute_caido_set_scope_tool(
        "caido_set_scope", {"allowlist": ["example.com"], "denylist": []}
    )

    assert success is True
    assert result["action"] == "updated"
    assert gql_mock.await_count == 2


@pytest.mark.asyncio
async def test_caido_automate_rejects_invalid_payload_shape(agent):
    success, _, result, _ = await agent._execute_caido_automate_tool(
        "caido_automate",
        {
            "raw_http": "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
            "host": "example.com",
            "payloads": "not-a-list",
        },
    )

    assert success is False
    assert "payloads must be a list" in (result.get("error") or "")


@pytest.mark.asyncio
async def test_execute_local_browser_tool(agent, mocker):
    mocker.patch(
        "airecon.proxy.agent.executors.browser_action",
        return_value={"title": "Test Page"},
    )

    success, duration, result, out_file = await agent._execute_local_browser_tool(
        "browser_action", {"action": "goto", "url": "http://test.com"}
    )

    assert success
    assert result["result"]["title"] == "Test Page"
    assert len(agent.state.tool_history) == 1
    assert agent.state.tool_history[0].tool_name == "browser_action"


@pytest.mark.asyncio
async def test_execute_filesystem_tool_read(agent, mocker):
    mocker.patch(
        "airecon.proxy.agent.executors.read_file",
        return_value={"success": True, "result": "file content"},
    )

    success, duration, result, out_file = await agent._execute_filesystem_tool(
        "read_file", {"path": "test.txt"}
    )

    assert success
    assert result["result"] == "file content"
    assert "test.txt" in agent.state.tool_history[0].arguments["path"]


@pytest.mark.asyncio
async def test_execute_filesystem_tool_keeps_upload_paths_target_relative(agent, mocker):
    read_mock = mocker.patch(
        "airecon.proxy.agent.executors.read_file",
        return_value={"success": True, "result": "file content"},
    )

    success, _, result, _ = await agent._execute_filesystem_tool(
        "read_file", {"path": "uploads/core/main.py"}
    )

    assert success
    assert result["result"] == "file content"
    assert agent.state.tool_history[0].arguments["path"] == "uploads/core/main.py"
    read_mock.assert_called_once_with(
        path="example.com/uploads/core/main.py",
        offset=0,
        limit=500,
    )


@pytest.mark.asyncio
async def test_execute_web_search_tool(agent, mocker):
    async def mock_search(*args, **kwargs):
        return {"success": True, "result": "Search Results String"}

    mocker.patch("airecon.proxy.agent.executors.web_search", side_effect=mock_search)

    with patch(
        "airecon.proxy.agent.executors.get_workspace_root", return_value=MagicMock()
    ):
        with patch("builtins.open", mocker.mock_open()):
            (
                success,
                duration,
                result,
                saved_path,
            ) = await agent._execute_web_search_tool({"query": "test query"})

            assert success
            assert "Search Results String" in result["result"]
            assert saved_path is not None


@pytest.mark.asyncio
async def test_execute_report_tool(agent, mocker):
    mocker.patch(
        "airecon.proxy.agent.executors.create_vulnerability_report",
        return_value={"success": True, "finding_id": "VULN-1"},
    )

    success, duration, result, out_file = await agent._execute_report_tool(
        "create_vulnerability_report", {
            "title": "Test Vuln",
            "description": "Test XSS found",
            "target": "http://test.local",
            "poc_description": "GET /?q=%3Cscript%3Ealert(1)%3C/script%3E returned 200 with body reflection",
            "poc_script_code": "print(result)",
        }
    )

    assert success
    assert result["finding_id"] == "VULN-1"


@pytest.mark.asyncio
async def test_execute_report_tool_marks_existing_vulnerability(agent, mocker):
    mocker.patch(
        "airecon.proxy.agent.executors.create_vulnerability_report",
        return_value={"success": True, "finding_id": "VULN-2"},
    )
    agent._session = SessionData(target="example.com")
    agent._session.vulnerabilities.append(
        {
            "finding": "SQL injection in /login endpoint",
            "endpoint": "/login",
            "verified": True,
        }
    )

    success, _, _, _ = await agent._execute_report_tool(
        "create_vulnerability_report",
        {
            "title": "SQL injection in /login endpoint",
            "endpoint": "/login",
            "description": "SQLi at /login",
            "target": "http://example.com",
            "poc_description": "POST /login username=' OR 1=1 -- returned admin profile",
            "poc_script_code": "print(result)",
        },
    )

    assert success
    assert agent._session.vulnerabilities[0].get("report_generated") is True


@pytest.mark.asyncio
async def test_execute_report_tool_blocks_weak_unverified_claim(agent, mocker):
    report_mock = mocker.patch(
        "airecon.proxy.agent.executors.create_vulnerability_report",
        return_value={"success": True, "finding_id": "VULN-BLOCK"},
    )
    agent._session = SessionData(target="example.com")
    agent._session.vulnerabilities.append(
        {"finding": "SQL injection in /login endpoint", "endpoint": "/login"}
    )

    success, _, result, _ = await agent._execute_report_tool(
        "create_vulnerability_report",
        {
            "title": "SQL injection in /login endpoint",
            "endpoint": "/login",
            "description": "Login response looked suspicious",
            "target": "http://example.com",
            "poc_description": "POST /login returned admin profile",
            "poc_script_code": "print(result)",
        },
    )

    assert success is False
    assert result["blocked_by_verifier"] is True
    report_mock.assert_not_called()


@pytest.mark.asyncio
async def test_execute_report_tool_does_not_append_unmatched_title(agent, mocker):
    mocker.patch(
        "airecon.proxy.agent.executors.create_vulnerability_report",
        return_value={"success": True, "finding_id": "VULN-3"},
    )
    agent._session = SessionData(target="example.com")
    agent._session.vulnerabilities.append(
        {"finding": "Reflected XSS in search", "endpoint": "/search"}
    )

    success, _, _, _ = await agent._execute_report_tool(
        "create_vulnerability_report",
        {
            "title": "Remote code execution in admin panel",
            "endpoint": "/admin",
            "description": "RCE in admin panel",
            "target": "http://example.com",
            "poc_description": "POST /admin returned root shell",
            "poc_script_code": "print(result)",
        },
    )

    assert success is False
    assert len(agent._session.vulnerabilities) == 1
    assert agent._session.vulnerabilities[0].get("report_generated") is not True


@pytest.mark.asyncio
async def test_execute_code_analysis_tool_profiles_target_and_expands_rules(
    agent, mocker, tmp_path
):
    project_dir = tmp_path / "example.com"
    project_dir.mkdir()
    (project_dir / "auth_checkout.py").write_text("print('ok')\n")
    (project_dir / "Dockerfile").write_text("FROM python:3.12\n")

    run_mock = mocker.patch(
        "airecon.proxy.semgrep.run_code_analysis",
        new=AsyncMock(
            return_value={
                "summary": "1 finding",
                "total": 1,
                "findings": [
                    {
                        "severity": "HIGH",
                        "rule_id": "test-rule",
                        "message": "Issue",
                        "file": "auth_checkout.py",
                        "start_line": 1,
                        "code_snippet": "print('ok')",
                    }
                ],
                "errors": [],
            }
        ),
    )
    mocker.patch("airecon.proxy.semgrep.get_default_rules", return_value=["p/default"])
    mocker.patch(
        "airecon.proxy.agent.executors_observe.get_workspace_root",
        return_value=tmp_path,
    )
    agent.engine = MagicMock()

    success, _, result, _ = await agent._execute_code_analysis_tool(
        "code_analysis",
        {"target_path": "."},
    )

    assert success is True
    assert "python" in result["target_profile"]["languages"]
    assert "p/docker" in result["target_profile"]["rules"]
    assert isinstance(result["target_profile"]["signals"], list)
    assert result["summary"] == "1 finding"
    called = run_mock.await_args.kwargs
    assert "python" in called["languages"]
    assert "p/default" in called["rules"]
    assert "p/python" in called["rules"]


# ── schemathesis behavioral tests ─────────────────────────────────────────────


@pytest.fixture
def schemathesis_report_writer(tmp_path, monkeypatch):
    monkeypatch.setattr("airecon.proxy.agent.executors_observe.get_workspace_root", lambda: tmp_path)

    async def execute(tool, arguments):
        parts = shlex.split(arguments["command"])
        report_path = parts[parts.index("--report-json-path") + 1]
        host_path = tmp_path / report_path.removeprefix("/workspace/")
        host_path.parent.mkdir(parents=True, exist_ok=True)
        host_path.write_text(json.dumps({
            "complete": True, "exit_code": 1, "operations": {"tested": 1},
            "test_cases": {"generated": 3, "with_failures": 1, "unique_failures": 1, "without_checks": 0},
            "failures": [{"type": "ServerError", "count": 1}], "errors": [],
        }))
        return {"success": True, "exit_code": 1, "stdout": "❌ 1 failed", "stderr": ""}

    return execute


@pytest.mark.asyncio
async def test_schemathesis_malformed_schema_url_dict(agent, mocker):
    """schema_url=dict must not crash — _str_arg coerces to '' → early return."""
    success, duration, result, _ = await agent._execute_schemathesis_tool(
        "schemathesis_fuzz", {"schema_url": {"url": "http://evil"}}
    )
    assert success is False
    assert "schema_url" in result.get("error", "")


@pytest.mark.asyncio
async def test_schemathesis_malformed_max_examples(agent, mocker, schemathesis_report_writer):
    """max_examples='abc' must fall back to 30, not raise ValueError."""
    mock_exec = AsyncMock(side_effect=schemathesis_report_writer)
    agent.engine = mocker.MagicMock()
    agent.engine.execute_tool = mock_exec

    success, duration, result, _ = await agent._execute_schemathesis_tool(
        "schemathesis_fuzz",
        {"schema_url": "http://target/openapi.json", "max_examples": "abc"},
    )
    assert success is True
    called_cmd = mock_exec.call_args[0][1]["command"]
    assert "--max-examples 30" in called_cmd


@pytest.mark.asyncio
async def test_schemathesis_engine_failure_not_masked(agent, mocker):
    """engine_ok=False must make success=False even when stdout is non-empty."""
    mock_exec = AsyncMock(
        return_value={
            "success": False,
            "stdout": "some partial output",
            "result": "some partial output",
            "error": "Docker exec failed",
            "stderr": "",
        }
    )
    agent.engine = mocker.MagicMock()
    agent.engine.execute_tool = mock_exec

    success, duration, result, _ = await agent._execute_schemathesis_tool(
        "schemathesis_fuzz", {"schema_url": "http://target/openapi.json"}
    )
    assert success is False
    assert "error" in result


@pytest.mark.asyncio
async def test_schemathesis_happy_path(agent, mocker, schemathesis_report_writer):
    """Normal successful run reports passes and violations."""
    mock_exec = AsyncMock(side_effect=schemathesis_report_writer)
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
    for action in (
        "login_form",
        "handle_totp",
        "save_auth_state",
        "inject_cookies",
        "oauth_authorize",
    ):
        assert action in enum_vals, f"browser_action enum missing: {action}"


def test_browser_action_has_auth_param_descriptions():
    props = _browser_tool_fn()["parameters"]["properties"]
    for param in ("username", "password", "totp_secret", "cookies", "oauth_url"):
        assert param in props, f"browser_action missing param description: {param}"


# ── http_observe tool tests ───────────────────────────────────────────────────


class DummyStateWithBaselines(DummyState):
    def __init__(self):
        super().__init__()
        self.http_baselines: dict = {}
        self.http_sessions: dict = {}
        self.iteration: int = 0


class AgentWithBaselines(DummyAgent):
    def __init__(self):
        super().__init__()
        self.state = DummyStateWithBaselines()


@pytest.fixture
def agent_with_baselines():
    return AgentWithBaselines()


@pytest.mark.asyncio
async def test_http_observe_missing_url(agent_with_baselines):
    (
        success,
        duration,
        result,
        _,
    ) = await agent_with_baselines._execute_http_observe_tool("http_observe", {})
    assert success is False
    assert "url" in result["error"]


@pytest.mark.asyncio
async def test_http_observe_basic_get(agent_with_baselines, mocker):
    raw_response = (
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/html\r\n"
        "Server: nginx\r\n"
        "\r\n"
        "<html>hello</html>"
    )
    mock_exec = AsyncMock(
        return_value={
            "success": True,
            "stdout": raw_response,
            "error": "",
            "stderr": "",
        }
    )
    agent_with_baselines.engine = mocker.MagicMock()
    agent_with_baselines.engine.execute_tool = mock_exec

    (
        success,
        duration,
        result,
        _,
    ) = await agent_with_baselines._execute_http_observe_tool(
        "http_observe", {"url": "https://example.com/"}
    )
    assert success is True
    assert result["status_code"] == 200
    assert result["headers"].get("content-type") == "text/html"
    assert result["headers"].get("server") == "nginx"
    assert "<html>hello</html>" in result["body"]


@pytest.mark.asyncio
async def test_http_observe_save_as_stores_baseline(agent_with_baselines, mocker):
    raw_response = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\nhello"
    mock_exec = AsyncMock(
        return_value={
            "success": True,
            "stdout": raw_response,
            "error": "",
            "stderr": "",
        }
    )
    agent_with_baselines.engine = mocker.MagicMock()
    agent_with_baselines.engine.execute_tool = mock_exec

    _, _, result, _ = await agent_with_baselines._execute_http_observe_tool(
        "http_observe", {"url": "https://example.com/", "save_as": "my_baseline"}
    )
    assert result.get("saved_as") == "my_baseline"
    assert "my_baseline" in agent_with_baselines.state.http_baselines
    assert (
        agent_with_baselines.state.http_baselines["my_baseline"]["status_code"] == 200
    )


@pytest.mark.asyncio
async def test_http_observe_compare_to_missing_baseline(agent_with_baselines, mocker):
    raw_response = "HTTP/1.1 200 OK\r\n\r\nbody"
    mock_exec = AsyncMock(
        return_value={
            "success": True,
            "stdout": raw_response,
            "error": "",
            "stderr": "",
        }
    )
    agent_with_baselines.engine = mocker.MagicMock()
    agent_with_baselines.engine.execute_tool = mock_exec

    _, _, result, _ = await agent_with_baselines._execute_http_observe_tool(
        "http_observe", {"url": "https://example.com/", "compare_to": "nonexistent"}
    )
    assert "diff_error" in result
    assert "nonexistent" in result["diff_error"]


@pytest.mark.asyncio
async def test_http_observe_diff_detects_status_change(agent_with_baselines, mocker):
    # First: establish baseline (200)
    raw_200 = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\nnormal body"
    # Second: probe returns 302
    raw_302 = "HTTP/1.1 302 Found\r\nLocation: javascript:alert(1)\r\n\r\n"
    mock_exec = AsyncMock(
        side_effect=[
            {"success": True, "stdout": raw_200, "error": "", "stderr": ""},
            {"success": True, "stdout": raw_302, "error": "", "stderr": ""},
        ]
    )
    agent_with_baselines.engine = mocker.MagicMock()
    agent_with_baselines.engine.execute_tool = mock_exec

    await agent_with_baselines._execute_http_observe_tool(
        "http_observe", {"url": "https://t.com/", "save_as": "base"}
    )
    _, _, result, _ = await agent_with_baselines._execute_http_observe_tool(
        "http_observe",
        {"url": "https://t.com/?next=javascript:alert(1)", "compare_to": "base"},
    )
    diff = result["diff"]
    assert diff["status_code_changed"]["from"] == 200
    assert diff["status_code_changed"]["to"] == 302
    assert diff["significant_change"] is True
    assert "location" in diff.get("security_headers_present", {})
    assert diff["security_headers_present"]["location"] == "javascript:alert(1)"


def test_parse_http_response_basic():
    raw = 'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"key":"val"}'
    parsed = AgentWithBaselines._parse_http_response(raw)
    assert parsed["status_code"] == 200
    assert parsed["headers"]["content-type"] == "application/json"
    assert '{"key":"val"}' in parsed["body"]


def test_parse_http_response_empty():
    parsed = AgentWithBaselines._parse_http_response("")
    assert parsed["status_code"] == 0
    assert parsed["body"] == ""


def test_parse_http_response_last_block_wins():
    """curl -i with a redirect shows 301 then 200 — we want the final 200."""
    raw = (
        "HTTP/1.1 301 Moved Permanently\r\nLocation: /new\r\n\r\n"
        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\nfinal body"
    )
    parsed = AgentWithBaselines._parse_http_response(raw)
    assert parsed["status_code"] == 200
    assert "final body" in parsed["body"]


def test_diff_http_responses_no_change():
    baseline = {
        "status_code": 200,
        "headers": {"x-foo": "bar"},
        "body": "hello",
        "body_size_bytes": 5,
    }
    current = {
        "status_code": 200,
        "headers": {"x-foo": "bar"},
        "body": "hello",
        "body_size_bytes": 5,
    }
    diff = AgentWithBaselines._diff_http_responses(baseline, current)
    assert diff["significant_change"] is False
    assert "status_code_changed" not in diff


def test_http_observe_in_tools_json():
    """http_observe must be present in tools.json with correct structure."""
    tools_path = Path(__file__).parents[3] / "airecon/proxy/data/tools.json"
    tools = json.loads(tools_path.read_text())
    names = [t.get("function", {}).get("name") for t in tools]
    assert "http_observe" in names
    tool = next(t for t in tools if t.get("function", {}).get("name") == "http_observe")
    assert tool["type"] == "function"
    assert "url" in tool["function"]["parameters"]["properties"]
    assert "url" in tool["function"]["parameters"]["required"]

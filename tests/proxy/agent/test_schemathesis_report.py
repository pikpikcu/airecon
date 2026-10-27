"""Schemathesis 4.26 JSON contract, independent of console formatting."""
import copy
import json
import shlex
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from airecon.proxy.agent.executors_observe import _ObserveExecutorMixin
from airecon.proxy.agent.validators import _ValidatorMixin

# Shape and counts captured from a real 4.26.1 run against a loopback 500 fixture.
FAILURE_REPORT = {
    "schemathesis_version": "4.26.1", "complete": True, "exit_code": 1,
    "operations": {"tested": 1, "errored": 0},
    "test_cases": {"generated": 2, "with_failures": 2, "unique_failures": 4, "without_checks": 0},
    "failures": [
        {"type": "ServerError", "title": "Server error", "count": 2, "operations": ["GET /ping", "TRACE /ping"]},
        {"type": "UndefinedStatusCode", "count": 1, "operations": ["GET /ping"]},
        {"type": "UnsupportedMethodResponse", "count": 1, "operations": ["TRACE /ping"]},
    ],
    "errors": [],
}


class Agent(_ObserveExecutorMixin, _ValidatorMixin):
    def __init__(self):
        self.state = SimpleNamespace(active_target="example.com", tool_history=[], tool_counts={"total": 0})
        self._save_tool_output = lambda *args: None


@pytest.fixture
def scan(tmp_path, monkeypatch):
    monkeypatch.setattr("airecon.proxy.agent.executors_observe.get_workspace_root", lambda: tmp_path)
    agent = Agent()

    async def run(report, code=1, stdout="❌ 1 failed", engine_ok=True):
        async def execute(tool, args):
            tokens = shlex.split(args["command"])
            if "--report-json-path" in tokens and report is not None:
                container_path = tokens[tokens.index("--report-json-path") + 1]
                host_path = tmp_path / container_path.removeprefix("/workspace/")
                host_path.parent.mkdir(parents=True, exist_ok=True)
                host_path.write_text(report if isinstance(report, str) else json.dumps(report))
            return {"success": engine_ok, "exit_code": code, "stdout": stdout, "stderr": ""}
        agent.engine = SimpleNamespace(execute_tool=AsyncMock(side_effect=execute))
        return await agent._execute_schemathesis_tool("schemathesis_fuzz", {"schema_url": "https://example.com/openapi.json"})

    return agent, run


@pytest.mark.asyncio
async def test_report_counts_real_failures_without_console_keywords(scan):
    agent, run = scan
    ok, _, result, _ = await run(FAILURE_REPORT)
    assert ok
    assert result["violations"] == 4
    assert result["passed"] == 0
    assert result["test_cases"]["with_failures"] == 2
    assert len(result["failures"]) == 3
    assert result["exit_code"] == 1
    assert agent.state.tool_history[-1].status == "success"


@pytest.mark.asyncio
async def test_clean_report_counts_passed_cases(scan):
    _, run = scan
    report = copy.deepcopy(FAILURE_REPORT)
    report.update(exit_code=0, failures=[])
    report["test_cases"].update(generated=3, with_failures=0, unique_failures=0)
    ok, _, result, _ = await run(report, code=0)
    assert ok and result["passed"] == 3 and result["violations"] == 0


@pytest.mark.asyncio
async def test_schema_loading_failure_report_with_null_operations(scan):
    _, run = scan
    report = {"complete": False, "exit_code": 0, "operations": None,
              "test_cases": {"generated": 0}, "failures": [], "errors": []}
    ok, _, result, _ = await run(report, code=1)
    assert not ok
    assert result["complete"] is False
    assert result["exit_code"] == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("report,code", [
    (None, 127),
    ("not json", 0),
    ({**FAILURE_REPORT, "complete": False, "exit_code": 0}, 1),
    ({**FAILURE_REPORT, "errors": [{"message": "schema error"}]}, 1),
    (FAILURE_REPORT, 2),
    ({**FAILURE_REPORT, "operations": {"tested": 0}}, 0),
    ({"complete": True, "exit_code": 0}, 0),
])
async def test_invalid_or_incomplete_runs_are_not_clean_scans(scan, report, code):
    _, run = scan
    ok, _, result, _ = await run(report, code=code, stdout="Failed to load specification")
    assert not ok
    assert result["error"]
    assert "completed:" not in result.get("summary", "")


@pytest.mark.asyncio
async def test_fresh_report_paths_prevent_reusing_previous_run(scan):
    agent, run = scan
    assert (await run(FAILURE_REPORT))[0]
    first = agent.engine.execute_tool.await_args.args[1]["command"]
    assert not (await run(None, code=1))[0]
    second = agent.engine.execute_tool.await_args.args[1]["command"]
    assert first != second
    assert "| tee" not in first

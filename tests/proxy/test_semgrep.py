"""Tests for airecon/proxy/semgrep.py — pure logic and async run_code_analysis."""

import json
import pytest
from unittest.mock import AsyncMock, MagicMock
from airecon.proxy.semgrep import (
    get_default_rules,
    build_semgrep_command,
    parse_semgrep_results,
    run_code_analysis,
)


# ── get_default_rules ─────────────────────────────────────────────────────────

def test_get_default_rules_returns_list():
    rules = get_default_rules()
    assert isinstance(rules, list)
    assert len(rules) >= 3


def test_get_default_rules_contains_security_audit():
    rules = get_default_rules()
    assert "p/security-audit" in rules


def test_get_default_rules_returns_copy():
    r1 = get_default_rules()
    r2 = get_default_rules()
    r1.append("extra")
    assert "extra" not in r2  # modifying one copy must not affect the other


# ── build_semgrep_command ─────────────────────────────────────────────────────

def test_build_semgrep_command_default_rules():
    cmd = build_semgrep_command("/workspace/repo")
    assert "semgrep" in cmd
    assert "p/security-audit" in cmd
    assert "p/owasp-top-ten" in cmd
    assert "/workspace/repo" in cmd
    assert "--json" in cmd


def test_build_semgrep_command_custom_rules():
    cmd = build_semgrep_command("/workspace/app", rules=["p/python", "p/django"])
    assert "p/python" in cmd
    assert "p/django" in cmd
    assert "p/security-audit" not in cmd


def test_build_semgrep_command_with_languages():
    cmd = build_semgrep_command("/workspace/app", languages=["python", "javascript"])
    assert "--lang" in cmd
    assert "python" in cmd
    assert "javascript" in cmd


def test_build_semgrep_command_max_findings_affects_head():
    cmd50 = build_semgrep_command("/workspace", max_findings=50)
    cmd200 = build_semgrep_command("/workspace", max_findings=200)
    # head -c limit should differ
    assert "250000" in cmd50   # 50 * 5000
    assert "1000000" in cmd200  # 200 * 5000


def test_build_semgrep_command_has_safety_flags():
    cmd = build_semgrep_command("/workspace/app")
    assert "--max-target-bytes" in cmd
    assert "--timeout" in cmd
    assert "--max-memory" in cmd
    assert "--metrics off" in cmd


# ── parse_semgrep_results ─────────────────────────────────────────────────────

def _make_result(rule_id="test.rule", severity="WARNING", message="Test issue",
                 path="app.py", start_line=10, end_line=15,
                 cwe=None, owasp=None, confidence="HIGH"):
    return {
        "check_id": rule_id,
        "path": path,
        "start": {"line": start_line},
        "end": {"line": end_line},
        "extra": {
            "message": message,
            "severity": severity,
            "lines": "dangerous_code()",
            "metadata": {
                "cwe": cwe or ["CWE-79"],
                "owasp": owasp or ["A03:2021"],
                "confidence": confidence,
                "references": ["https://owasp.org/"],
            }
        }
    }


def test_parse_semgrep_results_basic():
    raw = json.dumps({
        "results": [_make_result()],
        "errors": [],
    })
    result = parse_semgrep_results(raw)
    assert result["total"] == 1
    assert len(result["findings"]) == 1
    f = result["findings"][0]
    assert f["rule_id"] == "test.rule"
    assert f["severity"] == "WARNING"
    assert f["file"] == "app.py"
    assert f["start_line"] == 10
    assert f["cwe"] == ["CWE-79"]


def test_parse_semgrep_results_multiple_severities():
    raw = json.dumps({
        "results": [
            _make_result("r1", "ERROR"),
            _make_result("r2", "WARNING"),
            _make_result("r3", "ERROR"),
        ],
        "errors": [],
    })
    result = parse_semgrep_results(raw)
    assert result["total"] == 3
    assert "ERROR: 2" in result["summary"]
    assert "WARNING: 1" in result["summary"]


def test_parse_semgrep_results_empty():
    raw = json.dumps({"results": [], "errors": []})
    result = parse_semgrep_results(raw)
    assert result["total"] == 0
    assert result["findings"] == []
    assert "No issues" in result["summary"]


def test_parse_semgrep_results_with_errors():
    raw = json.dumps({
        "results": [],
        "errors": [{"type": "ParseError", "message": "Syntax error in file"}]
    })
    result = parse_semgrep_results(raw)
    assert len(result["errors"]) == 1
    assert result["errors"][0]["type"] == "ParseError"


def test_parse_semgrep_results_bad_json():
    result = parse_semgrep_results("NOT VALID JSON {{{")
    assert result["findings"] == []
    assert len(result["errors"]) == 1
    assert "Failed to parse" in result["errors"][0]


def test_parse_semgrep_results_code_snippet_extracted():
    raw = json.dumps({
        "results": [_make_result()],
        "errors": [],
    })
    result = parse_semgrep_results(raw)
    assert result["findings"][0]["code_snippet"] == "dangerous_code()"


# ── run_code_analysis (async, mocked engine) ──────────────────────────────────

@pytest.fixture
def mock_engine():
    engine = MagicMock()
    engine.execute_tool = AsyncMock()
    return engine


@pytest.mark.asyncio
async def test_run_code_analysis_success(mock_engine):
    good_json = json.dumps({
        "results": [_make_result("xss.reflect", "ERROR", "Reflected XSS")],
        "errors": [],
    })
    # First call: which semgrep (install check)
    # Second call: actual scan
    mock_engine.execute_tool.side_effect = [
        {"success": True, "result": "/usr/bin/semgrep"},
        {"success": True, "result": good_json},
    ]

    result = await run_code_analysis(mock_engine, "/workspace/app")
    assert result["total"] == 1
    assert result["findings"][0]["rule_id"] == "xss.reflect"


@pytest.mark.asyncio
async def test_run_code_analysis_empty_output(mock_engine):
    mock_engine.execute_tool.side_effect = [
        {"success": True, "result": "/usr/bin/semgrep"},
        {"success": True, "result": ""},
    ]
    result = await run_code_analysis(mock_engine, "/workspace/app")
    assert result["total"] == 0
    assert "no scannable files" in result["summary"].lower() or result["total"] == 0


@pytest.mark.asyncio
async def test_run_code_analysis_execution_failure(mock_engine):
    mock_engine.execute_tool.side_effect = [
        {"success": True, "result": "/usr/bin/semgrep"},
        {"success": False, "error": "Container not running"},
    ]
    result = await run_code_analysis(mock_engine, "/workspace/app")
    assert result["total"] == 0
    assert len(result["errors"]) > 0
    assert "failed" in result["summary"].lower()


@pytest.mark.asyncio
async def test_run_code_analysis_with_custom_rules(mock_engine):
    mock_engine.execute_tool.side_effect = [
        {"success": True},
        {"success": True, "result": json.dumps({"results": [], "errors": []})},
    ]
    await run_code_analysis(
        mock_engine, "/workspace/app",
        rules=["p/python"], languages=["python"]
    )
    # Verify the scan command contains our custom rules
    scan_call = mock_engine.execute_tool.call_args_list[1]
    cmd = scan_call[0][1]["command"]
    assert "p/python" in cmd
    assert "--lang" in cmd

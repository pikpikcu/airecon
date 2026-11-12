"""Safety regression: python_session must NEVER execute model code on the host.

The legacy python_session handler ran model-generated Python via in-process
exec()/eval() on the proxy host (host filesystem, subprocess, host network).
It has been removed. These tests pin the fail-closed contract:

- the handler (and both dispatch entry paths) reject any attempted call with
  a structured error BEFORE any code execution or utility-state side effect;
- no in-process exec/eval session machinery exists in executors_utils;
- the advertised tool catalog/metadata no longer offers a Python REPL;
- no environment switch can re-enable host execution.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from airecon.proxy.agent import executors_utils
from airecon.proxy.agent.executors_utils import _UtilsExecutorMixin

_TOOLS_JSON = (
    Path(__file__).parents[3] / "airecon" / "proxy" / "data" / "tools.json"
)
_TOOLS_META_JSON = (
    Path(__file__).parents[3] / "airecon" / "proxy" / "data" / "tools_meta.json"
)
_SKILLS_JSON = (
    Path(__file__).parents[3] / "airecon" / "proxy" / "data" / "skills.json"
)
_TOOLS_DOC = Path(__file__).parents[3] / "docs" / "tools.md"


class _BareUtils(_UtilsExecutorMixin):
    pass


def _make_utils() -> _BareUtils:
    # Bypass __init__ (which needs a workspace); the handler must reject
    # without ever touching runtime state anyway.
    return object.__new__(_BareUtils)


def _marker_code(marker: Path) -> str:
    return (
        f"with open({str(marker)!r}, 'w') as f:\n"
        f"    f.write('host write via python_session')\n"
    )


# --- 1. Handler is fail-closed: no code executes, no host write happens ---
@pytest.mark.asyncio
async def test_handler_rejects_code_without_executing(tmp_path: Path):
    marker = tmp_path / "host_marker.txt"
    utils = _make_utils()

    success, duration, result, output_file = await utils._execute_python_session_tool(
        "python_session", {"code": _marker_code(marker), "session_id": "s1"}
    )

    assert isinstance(success, bool) and success is False
    assert isinstance(duration, float)
    assert output_file is None
    assert isinstance(result, dict)
    assert result["success"] is False
    assert "error" in result and result["error"]
    err = result["error"].lower()
    assert "python" in err
    assert "execute" in err  # points the model at the sandboxed execute tool
    # The core safety property: model code never ran on the host.
    assert not marker.exists()


# --- 2. Rejection happens BEFORE any utility-state side effect ---
@pytest.mark.asyncio
async def test_handler_rejects_before_any_state_side_effect():
    utils = _make_utils()

    success, _, result, _ = await utils._execute_python_session_tool(
        "python_session", {"code": "x = 1", "session_id": "default"}
    )

    assert success is False
    assert result["success"] is False
    # No session bookkeeping was created for the rejected call.
    assert not hasattr(utils, "_python_sessions") or utils._python_sessions == {}


# --- 3. Empty/missing code is rejected too (structured, not crash) ---
@pytest.mark.asyncio
async def test_handler_rejects_empty_arguments_structurally():
    utils = _make_utils()

    success, _, result, _ = await utils._execute_python_session_tool(
        "python_session", {}
    )

    assert success is False
    assert result["success"] is False
    assert result.get("error")


# --- 4. No config/env switch re-enables host execution ---
@pytest.mark.asyncio
async def test_no_env_switch_enables_host_execution(tmp_path: Path):
    marker = tmp_path / "host_marker.txt"
    utils = _make_utils()

    env_overrides = {
        "AIRECON_PYTHON_SESSION": "1",
        "AIRECON_ENABLE_PYTHON_SESSION": "true",
        "AIRECON_PYTHON_SESSION_SANDBOX": "enabled",
        "AIRECON_ALLOW_HOST_PYTHON": "1",
    }
    with patch.dict(os.environ, env_overrides):
        success, _, result, _ = await utils._execute_python_session_tool(
            "python_session", {"code": _marker_code(marker), "session_id": "s"}
        )

    assert success is False
    assert result["success"] is False
    assert not marker.exists()


# --- 5. In-process exec/eval machinery is gone from the module ---
def test_inprocess_exec_machinery_removed():
    assert not hasattr(executors_utils, "_PythonSession")
    source = Path(executors_utils.__file__).read_text(encoding="utf-8")
    assert "exec(code" not in source
    assert "eval(code" not in source
    assert 'compile(code, "<python_session>"' not in source


# --- 6. Dispatch entry path 1: _dispatch_tool rejects (persisted registry) ---
@pytest.mark.asyncio
async def test_dispatch_tool_entry_path_rejects(tmp_path: Path):
    from airecon.proxy.agent.executors_dispatch import _DispatchExecutorMixin

    class _Stub(_DispatchExecutorMixin, _UtilsExecutorMixin):
        pass

    marker = tmp_path / "host_marker.txt"
    stub = object.__new__(_Stub)

    success, _, result, _ = await stub._dispatch_tool(
        "python_session", {"code": _marker_code(marker), "session_id": "s"}
    )

    assert success is False
    assert result["success"] is False
    assert result.get("error")
    assert not marker.exists()


# --- 7. Dispatch entry path 2: _execute_tool_and_record rejects ---
@pytest.mark.asyncio
async def test_execute_tool_and_record_entry_path_rejects(tmp_path: Path):
    from airecon.proxy.agent.executors_dispatch import _DispatchExecutorMixin

    class _Stub(_DispatchExecutorMixin, _UtilsExecutorMixin):
        def _is_recon_phase_repeat_blocked(self, *a, **k):
            return False

    marker = tmp_path / "host_marker.txt"
    with patch(
        "airecon.proxy.agent.executors_dispatch.get_config"
    ) as mock_cfg:
        mock_cfg.return_value = SimpleNamespace(agent_repeat_tool_call_limit=1)
        stub = object.__new__(_Stub)
        stub._last_output_file = None
        stub._executed_tool_counts = {}
        stub.state = SimpleNamespace(
            tool_history=[], tool_counts={"exec": 0, "total": 0}
        )

        success, _, result, _ = await stub._execute_tool_and_record(
            "python_session", {"code": _marker_code(marker), "session_id": "s"}
        )

        assert success is False
        assert result["success"] is False
        assert result.get("error")
        assert not marker.exists()


# --- 8. Advertised catalog and metadata no longer offer a Python REPL ---
def test_tool_catalog_no_python_session():
    catalog = json.loads(_TOOLS_JSON.read_text(encoding="utf-8"))
    names = {t["function"]["name"] for t in catalog}
    assert "python_session" not in names
    # No stale mentions anywhere in the advertised schema text.
    assert "python_session" not in _TOOLS_JSON.read_text(encoding="utf-8")


def test_tools_meta_no_python_session():
    raw = _TOOLS_META_JSON.read_text(encoding="utf-8")
    meta = json.loads(raw)
    assert "python_session" not in meta.get("callable_core_tools", [])
    assert "python_session" not in raw


# --- 9. Skill aliases and the tool guide agree with the disabled tool ---
def test_skill_aliases_and_tool_guide_do_not_advertise_python_session():
    raw_skills = _SKILLS_JSON.read_text(encoding="utf-8")
    keywords = json.loads(raw_skills)["skill_keywords"]
    assert "python_session" not in raw_skills
    # Removing the obsolete alias must not take the live scripting aliases.
    for alias in (
        "execute",
        "http_observe",
        "edit_file",
        "create_file",
        "read_file",
        "list_files",
    ):
        assert keywords[alias] == "tools/scripting.md"

    guide = _TOOLS_DOC.read_text(encoding="utf-8")
    # The old callable schema and persistent-interpreter promise are gone.
    assert '"name": "python_session"' not in guide
    assert "persistent python interpreter" not in guide.lower()
    assert "(#82-python_session)" not in guide

    # The table of contents entry and the summary table row are both marked.
    listed = [
        line
        for line in guide.splitlines()
        if "python_session" in line and line.lstrip().startswith(("- [", "|"))
    ]
    assert len(listed) == 2
    for line in listed:
        assert "disabled" in line.lower()

    # Section 8.2 is a removal notice that points at execute inside Docker.
    section = guide.split("\n### 8.2 ", 1)[1].split("\n### ", 1)[0].lower()
    assert "python_session" in section
    assert "disabled" in section
    assert "host" in section
    assert "not advertised" in section
    assert "`execute`" in section
    assert "docker" in section
    assert "no persistent python repl" in section
    assert "no configuration switch" in section
    assert "session_id" not in section

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from airecon.proxy.agent.executors_utils import _UtilsExecutorMixin


class _BareUtils(_UtilsExecutorMixin):
    pass


@pytest.mark.asyncio
async def test_python_session_tool_self_heals_missing_runtime_state():
    utils = object.__new__(_BareUtils)

    success, _, result, _ = await utils._execute_python_session_tool(
        "python_session",
        {"code": "value = 7", "session_id": "tmp"},
    )

    assert success is True
    assert result["session_id"] == "tmp"
    assert hasattr(utils, "_python_sessions")
    assert "value" in result["session_state"]


def test_agent_loop_initializes_utils_runtime_state():
    from airecon.proxy.agent.loop import AgentLoop

    llm_mock = MagicMock()
    engine_mock = MagicMock()

    with patch("airecon.proxy.agent.loop.get_config") as mock_cfg:
        cfg = MagicMock()
        cfg.agent_max_browser_visits_per_domain = 5
        mock_cfg.return_value = cfg
        loop = AgentLoop(llm=llm_mock, engine=engine_mock)

    assert isinstance(loop._python_sessions, dict)
    assert loop._notes_manager is None
    assert isinstance(loop._thoughts_log, list)


@pytest.mark.asyncio
async def test_notes_do_not_create_global_workspace_dir_without_target(tmp_path: Path):
    with patch(
        "airecon.proxy.agent.executors_utils.get_workspace_root",
        return_value=tmp_path,
    ):
        utils = _BareUtils()
        utils.state = SimpleNamespace(active_target="")
        utils._session = SimpleNamespace(target="")
        utils._ensure_utils_runtime_state()

        success, _, result, _ = await utils._execute_create_note_tool(
            "create_note",
            {
                "category": "finding",
                "title": "Needs target",
                "content": "Should not write before target exists",
            },
        )

        assert success is False
        assert "active target" in result["error"].lower()
        assert not (tmp_path / "notes").exists()


@pytest.mark.asyncio
async def test_notes_use_target_workspace_directory(tmp_path: Path):
    with patch(
        "airecon.proxy.agent.executors_utils.get_workspace_root",
        return_value=tmp_path,
    ):
        utils = _BareUtils()
        utils.state = SimpleNamespace(active_target="example.com")
        utils._session = SimpleNamespace(target="example.com")
        utils._ensure_utils_runtime_state()

        success, _, result, _ = await utils._execute_create_note_tool(
            "create_note",
            {
                "category": "finding",
                "title": "SQLi candidate",
                "content": "Potential SQL injection on /login",
                "tags": ["sqli"],
            },
        )

        assert success is True
        assert result["success"] is True
        assert result["artifact_type"] == "working_note"
        assert result["report_generated"] is False
        assert utils._notes_manager.storage_dir == tmp_path / "example.com" / "notes"
        assert (tmp_path / "example.com" / "notes" / "notes_index.json").exists()


@pytest.mark.asyncio
async def test_export_notes_wiki_defaults_to_target_notes_dir(tmp_path: Path):
    with patch(
        "airecon.proxy.agent.executors_utils.get_workspace_root",
        return_value=tmp_path,
    ):
        utils = _BareUtils()
        utils.state = SimpleNamespace(active_target="example.com")
        utils._session = SimpleNamespace(target="example.com")
        utils._ensure_utils_runtime_state()

        await utils._execute_create_note_tool(
            "create_note",
            {
                "category": "observation",
                "title": "Header leak",
                "content": "X-Powered-By exposed",
                "tags": ["info"],
            },
        )

        success, _, result, _ = await utils._execute_export_notes_wiki_tool(
            "export_notes_wiki",
            {},
        )

        assert success is True
        assert result["path"] == str(tmp_path / "example.com" / "notes" / "wiki.md")
        assert (tmp_path / "example.com" / "notes" / "wiki.md").exists()

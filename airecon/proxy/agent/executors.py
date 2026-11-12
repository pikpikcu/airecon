from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any

from ..browser import browser_action
from ..config import get_config, get_workspace_root
from ..filesystem import create_file, list_files, read_file
from ..reporting import create_vulnerability_report
from ..web_search import web_search
from .command_parse import extract_primary_binary
from .executors_browser import _BrowserExecutorMixin
from .executors_caido import _CaidoExecutorMixin
from .executors_catalog import _AIRECON_TOOL_NAMES  # noqa: F401
from .executors_catalog import _TOOL_FLAG_CONFLICTS  # noqa: F401
from .executors_catalog import (
    _READ_FILE_CONTENT_TRUNCATION_THRESHOLD,
    _RECON_CONTENT_DISCOVERY_BINS,
    _RECON_LIVE_HOST_BINS,
    _RECON_PORT_SCAN_BINS,
    _RECON_SUBDOMAIN_BINS,
)
from .executors_dispatch import _DispatchExecutorMixin
from .executors_filesystem import _FilesystemExecutorMixin
from .executors_fuzzing import _FuzzingExecutorMixin
from .executors_interactive import _InteractiveExecutorMixin
from .executors_observe import _ObserveExecutorMixin
from .executors_utils import _UtilsExecutorMixin
from .executors_reporting import _ReportingExecutorMixin
from .models import ToolExecution, _truncate_tool_result

if TYPE_CHECKING:
    from ..docker import DockerEngine
    from .models import AgentState
    from .session import SessionData

logger = logging.getLogger("airecon.agent")

__all__ = [
    "_ExecutorMixin",
    "_RECON_SUBDOMAIN_BINS",
    "_RECON_PORT_SCAN_BINS",
    "_RECON_CONTENT_DISCOVERY_BINS",
    "_RECON_LIVE_HOST_BINS",
]


def _load_recon_bins(category: str, fallback: frozenset[str]) -> frozenset[str]:
    try:
        path = Path(__file__).resolve().parent.parent / "data" / "tools_meta.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        bins = data.get("categories", {}).get("reconnaissance", {}).get(category, [])
        return frozenset(str(x).strip().lower() for x in bins if str(x).strip())
    except Exception as exc:
        logger.warning(
            "Could not load recon bins (category=%r) from tools_meta.json: %s — "
            "falling back to built-in list.",
            category,
            exc,
        )
        return fallback


class _ExecutorMixin(
    _BrowserExecutorMixin,
    _FilesystemExecutorMixin,
    _ReportingExecutorMixin,
    _CaidoExecutorMixin,
    _FuzzingExecutorMixin,
    _ObserveExecutorMixin,
    _InteractiveExecutorMixin,
    _DispatchExecutorMixin,
    _UtilsExecutorMixin,
):
    if TYPE_CHECKING:
        engine: DockerEngine
        state: AgentState
        _session: SessionData | None
        _last_output_file: str | None
        _executed_tool_counts: dict[tuple[str, str], int]

    def _get_executor_providers(self) -> dict[str, dict[str, Any]]:
        try:
            self._executor_providers
        except AttributeError:
            self._executor_providers: dict[str, dict[str, Any]] = {
                "browser": {
                    "browser_action": browser_action,
                    "get_config": get_config,
                    "get_workspace_root": get_workspace_root,
                    "ToolExecution": ToolExecution,
                },
                "filesystem": {
                    "create_file": create_file,
                    "read_file": read_file,
                    "list_files": list_files,
                    "get_workspace_root": get_workspace_root,
                    "ToolExecution": ToolExecution,
                    "_READ_FILE_CONTENT_TRUNCATION_THRESHOLD": (
                        _READ_FILE_CONTENT_TRUNCATION_THRESHOLD
                    ),
                },
                "web_search": {
                    "web_search": web_search,
                    "get_workspace_root": get_workspace_root,
                    "ToolExecution": ToolExecution,
                },
                "report": {
                    "create_vulnerability_report": create_vulnerability_report,
                    "ToolExecution": ToolExecution,
                },
            }
        return self._executor_providers

    def _append_tool_history(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        result: dict[str, Any],
        duration: float,
        status: str,
    ) -> None:
        truncated_result = _truncate_tool_result(result)
        self.state.tool_history.append(
            ToolExecution(
                tool_name=tool_name,
                arguments=arguments,
                result=truncated_result,
                duration=duration,
                status=status,
            )
        )
        self.state.tool_counts["exec"] += 1
        self.state.tool_counts["total"] += 1

    def _extract_command_binary(self, command: str) -> str:
        return extract_primary_binary(command)

    def _is_recon_phase_repeat_blocked(
        self, tool_name: str, arguments: dict[str, Any], count: int
    ) -> bool:
        if tool_name != "execute" or count < 1:
            return False

        phase_name = ""
        try:
            if hasattr(self, "_get_current_phase"):
                phase_name = str(self._get_current_phase().value).upper()
        except Exception as exc:
            logger.debug(
                "Could not determine current phase for recon repeat check: %s", exc
            )
            phase_name = ""

        if phase_name != "RECON":
            return False

        binary = self._extract_command_binary(arguments.get("command", ""))
        return binary in _RECON_SUBDOMAIN_BINS or binary in _RECON_PORT_SCAN_BINS

    async def _execute_local_browser_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> tuple[bool, float, dict[str, Any], str | None]:
        _ = get_config().browser_action_timeout
        from . import executors_browser as _browser_mod

        _browser_mod.browser_action = browser_action
        _browser_mod.get_config = get_config
        _browser_mod.get_workspace_root = get_workspace_root
        _browser_mod.ToolExecution = ToolExecution
        return await _BrowserExecutorMixin._execute_local_browser_tool(
            self, tool_name, arguments
        )

    async def _execute_filesystem_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> tuple[bool, float, dict[str, Any], str | None]:
        from . import executors_filesystem as _fs_mod

        _fs_mod.create_file = create_file
        _fs_mod.read_file = read_file
        _fs_mod.list_files = list_files
        _fs_mod.get_workspace_root = get_workspace_root
        _fs_mod.ToolExecution = ToolExecution
        _fs_mod._READ_FILE_CONTENT_TRUNCATION_THRESHOLD = (
            _READ_FILE_CONTENT_TRUNCATION_THRESHOLD
        )
        return await _FilesystemExecutorMixin._execute_filesystem_tool(
            self, tool_name, arguments
        )

    async def _execute_web_search_tool(
        self,
        arguments: dict[str, Any],
    ) -> tuple[bool, float, dict[str, Any], str | None]:
        from . import executors_filesystem as _fs_mod

        _fs_mod.web_search = web_search
        _fs_mod.get_workspace_root = get_workspace_root
        _fs_mod.ToolExecution = ToolExecution
        return await _FilesystemExecutorMixin._execute_web_search_tool(self, arguments)

    async def _execute_report_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> tuple[bool, float, dict[str, Any], str | None]:
        from . import executors_reporting as _report_mod

        _report_mod.create_vulnerability_report = create_vulnerability_report
        _report_mod.ToolExecution = ToolExecution
        return await _ReportingExecutorMixin._execute_report_tool(
            self, tool_name, arguments
        )

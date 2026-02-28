from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import time
from typing import Any

from ..browser import browser_action
from ..config import get_config, get_workspace_root
from ..filesystem import create_file, read_file
from ..reporting import create_vulnerability_report
from ..web_search import web_search
from .models import ToolExecution

logger = logging.getLogger("airecon.agent")


class _ExecutorMixin:

    async def _execute_local_browser_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> tuple[bool, float, dict[str, Any], str | None]:
        self._last_output_file = None  # type: ignore[attr-defined]

        args_key = (tool_name, json.dumps(arguments, sort_keys=True, default=str))
        allow_repeat = arguments.get("action") in [
            "wait", "scroll_down", "scroll_up", "get_console_logs", "execute_js"
        ]
        if not allow_repeat:
            count = self._executed_tool_counts.get(args_key, 0)  # type: ignore[attr-defined]
            limit = get_config().agent_repeat_tool_call_limit
            if count >= limit:
                return False, 0.0, {"success": False, "error": f"Duplicate tool execution prevented (already ran {count}x)."}, None

        start_time = time.time()
        try:
            result = await asyncio.to_thread(browser_action, **arguments)
            success = not (isinstance(result, dict) and "error" in result)
            if "success" not in result:
                result = {"success": success, "result": result}
            try:
                self._save_tool_output(tool_name, arguments, result)  # type: ignore[attr-defined]
            except Exception:
                pass
        except Exception as e:
            success = False
            result = {"success": False, "error": str(e)}
            logger.error(f"Browser tool exec error: {e}")

        duration = time.time() - start_time

        history_result = result
        if success and self._last_output_file and len(str(result)) > 10000:  # type: ignore[attr-defined]
            history_result = {
                "success": True,
                "result": f"<Result truncated. Full output in {self._last_output_file}>",  # type: ignore[attr-defined]
                "truncated": True,
            }

        self.state.tool_history.append(  # type: ignore[attr-defined]
            ToolExecution(
                tool_name=tool_name, arguments=arguments,
                result=history_result, duration=duration,
                status="success" if success else "error",
            )
        )
        self.state.tool_counts["exec"] += 1  # type: ignore[attr-defined]
        self.state.tool_counts["total"] += 1  # type: ignore[attr-defined]

        if success:
            self._executed_tool_counts[args_key] = self._executed_tool_counts.get(args_key, 0) + 1  # type: ignore[attr-defined]

        return success, duration, result, self._last_output_file  # type: ignore[attr-defined]

    async def _execute_filesystem_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> tuple[bool, float, dict[str, Any], str | None]:
        self._last_output_file = None  # type: ignore[attr-defined]
        start_time = time.time()

        try:
            path_arg = arguments.get("path", "")
            if path_arg.startswith("workspace/"):
                path_arg = path_arg[10:]
            elif path_arg.startswith("/workspace/"):
                path_arg = path_arg[11:]

            if self.state.active_target:  # type: ignore[attr-defined]
                if not path_arg.startswith(self.state.active_target) and not os.path.isabs(path_arg):  # type: ignore[attr-defined]
                    path_arg = os.path.join(self.state.active_target, path_arg)  # type: ignore[attr-defined]

            arguments["path"] = path_arg

            if tool_name == "create_file":
                result = await asyncio.to_thread(create_file, **arguments)
            elif tool_name == "read_file":
                result = await asyncio.to_thread(read_file, **arguments)
            else:
                result = {"success": False, "error": f"Unknown filesystem tool: {tool_name}"}

            success = result.get("success", False)
            try:
                self._save_tool_output(tool_name, arguments, result)  # type: ignore[attr-defined]
            except Exception:
                pass
        except Exception as e:
            success = False
            result = {"success": False, "error": str(e)}
            logger.error(f"Filesystem tool exec error: {e}")

        duration = time.time() - start_time

        history_result = result
        if tool_name == "read_file" and success:
            content = result.get("result", "")
            if len(content) > 2000:
                history_result = {
                    "success": True,
                    "result": f"<File content loaded ({len(content)} chars). Truncated in history.>",
                    "truncated": True,
                }

        self.state.tool_history.append(  # type: ignore[attr-defined]
            ToolExecution(
                tool_name=tool_name, arguments=arguments,
                result=history_result, duration=duration,
                status="success" if success else "error",
            )
        )
        self.state.tool_counts["exec"] += 1  # type: ignore[attr-defined]
        self.state.tool_counts["total"] += 1  # type: ignore[attr-defined]

        return success, duration, result, self._last_output_file  # type: ignore[attr-defined]

    async def _execute_web_search_tool(
        self,
        arguments: dict[str, Any],
    ) -> tuple[bool, float, dict[str, Any], str | None]:
        start_time = time.time()
        try:
            result = await web_search(
                query=arguments.get("query", ""),
                max_results=arguments.get("max_results", 5),
            )
            success = result.get("success", False)
        except Exception as e:
            success = False
            result = {"success": False, "error": str(e)}
            logger.error(f"Web search tool error: {e}")

        duration = time.time() - start_time
        self.state.tool_history.append(  # type: ignore[attr-defined]
            ToolExecution(
                tool_name="web_search", arguments=arguments,
                result=result, duration=duration,
                status="success" if success else "error",
            )
        )
        self.state.tool_counts["exec"] += 1  # type: ignore[attr-defined]
        self.state.tool_counts["total"] += 1  # type: ignore[attr-defined]
        return success, duration, result, None

    async def _execute_report_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> tuple[bool, float, dict[str, Any], str | None]:
        self._last_output_file = None  # type: ignore[attr-defined]
        start_time = time.time()

        try:
            result = await asyncio.to_thread(create_vulnerability_report, **arguments)
            success = result.get("success", False)
            try:
                self._save_tool_output(tool_name, arguments, result)  # type: ignore[attr-defined]
            except Exception:
                pass
        except Exception as e:
            success = False
            result = {"success": False, "error": str(e)}
            logger.error(f"Reporting tool exec error: {e}")

        duration = time.time() - start_time
        self.state.tool_history.append(  # type: ignore[attr-defined]
            ToolExecution(
                tool_name=tool_name, arguments=arguments,
                result=result, duration=duration,
                status="success" if success else "error",
            )
        )
        self.state.tool_counts["exec"] += 1  # type: ignore[attr-defined]
        self.state.tool_counts["total"] += 1  # type: ignore[attr-defined]

        return success, duration, result, self._last_output_file  # type: ignore[attr-defined]

    async def _execute_tool_and_record(
        self,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> tuple[bool, float, dict[str, Any], str | None]:
        self._last_output_file = None  # type: ignore[attr-defined]

        args_key = (tool_name, json.dumps(arguments, sort_keys=True, default=str))
        count = self._executed_tool_counts.get(args_key, 0)  # type: ignore[attr-defined]
        limit = get_config().agent_repeat_tool_call_limit
        if count >= limit:
            return False, 0.0, {"success": False, "error": f"Duplicate tool execution prevented (already ran {count}x)."}, None

        if tool_name == "execute":
            cmd_lower = arguments.get("command", "").lower()
            if "nuclei" in cmd_lower and self.state.active_target:  # type: ignore[attr-defined]
                missing = self._check_nuclei_gate()  # type: ignore[attr-defined]
                if missing:
                    gate_error = (
                        "NUCLEI GATE BLOCKED: nuclei is forbidden before Phases 1 & 2 are evidenced by output files.\n"
                        + "\n".join(f"  - {m}" for m in missing)
                        + "\nProduce the missing output files first, then retry nuclei."
                    )
                    return False, 0.0, {"success": False, "error": gate_error}, None

        if tool_name == "execute":
            cmd = arguments.get("command", "")
            if self.state.active_target and cmd and not cmd.strip().startswith("cd "):  # type: ignore[attr-defined]
                workspace_dir = f"/workspace/{self.state.active_target}"  # type: ignore[attr-defined]
                host_workspace = get_workspace_root() / self.state.active_target  # type: ignore[attr-defined]
                try:
                    host_workspace.mkdir(parents=True, exist_ok=True)
                except Exception:
                    pass
                for subdir in ["output", "command", "tools", "vulnerabilities"]:
                    try:
                        (host_workspace / subdir).mkdir(parents=True, exist_ok=True)
                    except Exception:
                        pass
                cmd = re.sub(r"(?<!\S)/?workspace/[^/\s]+/", "", cmd)
                arguments["command"] = f"cd {workspace_dir} && {cmd}"
                logger.info(f"Enforced workspace context: {arguments['command']}")

        start_time = time.time()
        try:
            result = await self.engine.execute_tool(tool_name, arguments)  # type: ignore[attr-defined]
            success = result.get("success", False)
            try:
                self._save_tool_output(tool_name, arguments, result)  # type: ignore[attr-defined]
            except Exception:
                pass
        except Exception as e:
            success = False
            result = {"success": False, "error": str(e)}
            logger.error(f"Tool exec error: {e}")

        duration = time.time() - start_time

        history_result = result
        if success and self._last_output_file and len(str(result)) > 10000:  # type: ignore[attr-defined]
            history_result = {
                "success": True,
                "result": f"<Result truncated. Full output in {self._last_output_file}>",  # type: ignore[attr-defined]
                "truncated": True,
            }

        self.state.tool_history.append(  # type: ignore[attr-defined]
            ToolExecution(
                tool_name=tool_name, arguments=arguments,
                result=history_result, duration=duration,
                status="success" if success else "error",
            )
        )
        self.state.tool_counts["exec"] += 1  # type: ignore[attr-defined]
        self.state.tool_counts["total"] += 1  # type: ignore[attr-defined]

        if success:
            self._executed_tool_counts[args_key] = self._executed_tool_counts.get(args_key, 0) + 1  # type: ignore[attr-defined]

        return success, duration, result, self._last_output_file  # type: ignore[attr-defined]

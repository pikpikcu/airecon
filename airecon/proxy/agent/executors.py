from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import shlex
import time
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable
from urllib.parse import urlparse

from ..browser import browser_action
from ..config import get_config, get_workspace_root
from ..filesystem import create_file, list_files, read_file
from ..reporting import create_vulnerability_report
from ..web_search import web_search
from .command_parse import extract_primary_binary
from .models import ToolExecution
from .session import _is_duplicate_vulnerability

if TYPE_CHECKING:
    from ..docker import DockerEngine
    from .models import AgentState
    from .session import SessionData

logger = logging.getLogger("airecon.agent")

# ---------------------------------------------------------------------------
# Specialist prompts — loaded from data/tools_meta.json["specialist_prompts"].
# Tool names live in JSON, not in Python code.
# ---------------------------------------------------------------------------
def _load_specialist_prefixes() -> dict[str, str]:
    try:
        path = Path(__file__).resolve().parent.parent / "data" / "tools_meta.json"
        return json.loads(path.read_text(encoding="utf-8")).get("specialist_prompts", {})
    except Exception as exc:
        logger.warning("Could not load specialist_prompts from tools_meta.json: %s", exc)
        return {}


_SPECIALIST_PREFIXES: dict[str, str] = _load_specialist_prefixes()

# ---------------------------------------------------------------------------
# Magic numbers extracted to constants for maintainability
# ---------------------------------------------------------------------------
_RESULT_TRUNCATION_THRESHOLD = 10000
_READ_FILE_CONTENT_TRUNCATION_THRESHOLD = 2000
_MAX_COMMAND_LENGTH = 20_000
# Report file name patterns to block in create_file (matched against basename only)
_REPORT_FILE_PATTERNS = (
    "final_report", "report", "vuln", "vulnerability", "finding",
    "assessment", "security_report", "pentest_report", "summary_report",
)


def _safe_non_negative_int(value: Any) -> int:
    """Coerce value to non-negative int; returns 0 on failure or negative input."""
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return 0
    return parsed if parsed >= 0 else 0


def _load_recon_bins(category: str, fallback: frozenset[str]) -> frozenset[str]:
    """Load a recon binary list from data/tools_meta.json by category name.

    Single loader used by all RECON_*_BINS constants to keep tools_meta.json
    as the single source of truth for tool names.
    """
    try:
        path = Path(__file__).resolve().parent.parent / "data" / "tools_meta.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        bins = (
            data.get("categories", {})
            .get("reconnaissance", {})
            .get(category, [])
        )
        return frozenset(str(x).strip().lower() for x in bins if str(x).strip())
    except Exception as exc:
        logger.warning(
            "Could not load recon bins (category=%r) from tools_meta.json: %s — "
            "falling back to built-in list. Check that data/tools_meta.json exists.",
            category,
            exc,
        )
        return fallback


_RECON_SUBDOMAIN_BINS: frozenset[str] = _load_recon_bins(
    "subdomain_enum",
    frozenset({"subfinder", "amass", "assetfinder", "findomain", "dnsx"}),
)

_RECON_PORT_SCAN_BINS: frozenset[str] = _load_recon_bins(
    "port_scan",
    frozenset({"nmap", "masscan", "naabu", "rustscan"}),
)

def _load_tool_flag_conflicts() -> dict[str, tuple[list[str], str]]:
    """Load tool flag conflict rules from data/tools_meta.json.

    Keeps tool metadata in the JSON file as the single source of truth,
    avoiding hardcoded tool names and flags in Python code.
    """
    try:
        path = Path(__file__).resolve().parent.parent / "data" / "tools_meta.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        raw = data.get("tool_flag_conflicts", {})
        return {
            tool: (entry["flags"], entry["correct_tool"])
            for tool, entry in raw.items()
            if isinstance(entry.get("flags"), list) and entry.get("correct_tool")
        }
    except Exception as exc:
        logger.warning(
            "Could not load tool_flag_conflicts from tools_meta.json: %s — "
            "flag conflict detection disabled. Check that data/tools_meta.json exists.",
            exc,
        )
        return {}


# Flags that belong to a specific tool but are sometimes written by LLMs
# on the wrong binary. Loaded from tools_meta.json (single source of truth).
# Key: binary that received wrong flags → (wrong_flags, correct_binary)
_TOOL_FLAG_CONFLICTS: dict[str, tuple[list[str], str]] = _load_tool_flag_conflicts()


class _ExecutorMixin:
    # Attributes provided by AgentLoop — declared here for type checkers only.
    # Only include attrs that come from AgentLoop.__init__, not methods defined
    # in this class or sibling mixins (_WorkspaceMixin._save_tool_output, etc.).
    if TYPE_CHECKING:
        engine: DockerEngine
        state: AgentState
        _session: SessionData | None
        _last_output_file: str | None
        _executed_tool_counts: dict[tuple[str, str], int]

    def _extract_command_binary(self, command: str) -> str:
        """Extract executable binary from command, stripping wrappers."""
        return extract_primary_binary(command)

    def _is_recon_phase_repeat_blocked(self, tool_name: str, arguments: dict[str, Any], count: int) -> bool:
        """Return True if a repeated recon execute command should be blocked.

        Recon enumeration binaries (subfinder, nmap…) are blocked after the
        first successful run in RECON phase only. Template scanners are
        unrestricted — tool selection is left to the LLM via prompt guidance.
        """
        if tool_name != "execute" or count < 1:
            return False

        phase_name = ""
        try:
            if hasattr(self, "_get_current_phase"):
                phase_name = str(self._get_current_phase().value).upper()  # type: ignore[misc]
        except Exception:
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
        self._last_output_file = None

        args_key = self._normalize_args_for_dedup(tool_name, arguments)
        # browser_action is inherently stateful — the same action (launch, goto, screenshot,
        # close, etc.) produces different results at different points in the test workflow.
        # Dedup does not apply; loop prevention is handled by MAX_TOOL_ITERATIONS.
        allow_repeat = True  # noqa: SIM210

        if not allow_repeat:  # pragma: no cover — kept for future per-action opt-in
            count = self._executed_tool_counts.get(
                args_key, 0)
            limit = get_config().agent_repeat_tool_call_limit
            if count >= limit:
                return False, 0.0, {
                    "success": False,
                    "error": f"Duplicate tool execution prevented (already ran {count}x)."
                }, None

        _browser_timeout = float(get_config().browser_action_timeout)
        start_time = time.time()
        try:
            try:
                result = await asyncio.wait_for(
                    asyncio.to_thread(browser_action, **arguments),
                    timeout=_browser_timeout,
                )
            except asyncio.TimeoutError:
                # The underlying sync Playwright thread cannot be force-killed
                # from asyncio. Schedule a best-effort close to release the
                # browser process before we return the error.
                asyncio.get_running_loop().run_in_executor(
                    None,
                    lambda: browser_action(action="close"),
                )
                return False, _browser_timeout, {
                    "success": False,
                    "error": f"Browser action timed out after {_browser_timeout:.0f}s. Browser close requested.",
                }, None

            # Auto-inject session cookies immediately after launch
            if arguments.get("action") == "launch" and hasattr(self, "_session"):
                cookies = getattr(self._session, "auth_cookies", [])
                if cookies:
                    try:
                        await asyncio.to_thread(
                            browser_action,
                            action="inject_cookies",
                            cookies=cookies
                        )
                        if "url" in arguments:
                            # Reload to apply cookies
                            await asyncio.to_thread(
                                browser_action,
                                action="goto",
                                url=arguments["url"]
                            )
                    except Exception as e:
                        logger.warning("Failed to auto-inject session cookies: %s", e)

            success = not (isinstance(result, dict) and "error" in result)
            if not success and isinstance(result, dict) and "error" in result:
                result = {"success": False, "error": result["error"]}
            elif "success" not in result:
                result = {"success": success, "result": result}

            # Auto-save view_source / get_console_logs / get_network_logs to
            # workspace
            if success and self.state.active_target:
                action = arguments.get("action")
                if action in ("view_source", "get_console_logs",
                              "get_network_logs"):
                    try:
                        inner = result.get("result", {})
                        if not isinstance(inner, dict):
                            inner = {}
                        page_url = inner.get("url", "")
                        netloc = urlparse(page_url).netloc.replace(
                            ":", "_") if page_url else "unknown"
                        domain = netloc or "unknown"
                        host_output = (
                            get_workspace_root()
                            / self.state.active_target
                            / "output"
                        )
                        host_output.mkdir(parents=True, exist_ok=True)

                        if action == "view_source":
                            # Use full_page_source for file (untruncated), fall
                            # back to page_source
                            source_full = inner.get(
                                "full_page_source") or inner.get("page_source", "")
                            source_file = host_output / f"source_{domain}.txt"
                            with open(source_file, "w", encoding="utf-8") as f:
                                f.write(f"URL: {page_url}\n{'=' * 60}\n{source_full}")
                            saved_path = f"output/source_{domain}.txt"
                            # Extract JS file URLs from full HTML source
                            js_src = re.findall(
                                r'src=["\']([^"\']*\.js[^"\']*)["\']', source_full)
                            js_abs = re.findall(
                                r'https?://[^\s"\'<>]+\.js(?:\?[^\s"\'<>]*)?', source_full)
                            all_js = list(dict.fromkeys(js_src + js_abs))
                            js_note = ""
                            if all_js:
                                js_file = host_output / "js_files.txt"
                                with open(js_file, "a", encoding="utf-8") as f:
                                    f.write(
                                        f"\n{'=' * 60}\nSOURCE: {page_url}\n{'=' * 60}\n"
                                    )
                                    for js_url in all_js:
                                        f.write(js_url + "\n")
                                js_note = f" {len(all_js)} JS files extracted to output/js_files.txt."
                            inner = dict(inner)
                            # strip from LLM context
                            inner.pop("full_page_source", None)
                            inner["auto_saved"] = saved_path
                            inner["note"] = (
                                f"[Auto-saved full page source ({len(source_full)} chars) to {saved_path}.{js_note}"
                                " Analyze JS files for API endpoints, secrets, and vulnerabilities.]"
                            )
                            result = {"success": True, "result": inner}
                            self._last_output_file = saved_path

                        elif action == "get_console_logs":
                            logs = inner.get("console_logs", [])
                            console_file = host_output / \
                                f"console_{domain}.txt"
                            with open(console_file, "w", encoding="utf-8") as f:
                                f.write(
                                    f"URL: {page_url}\nLogs captured: {len(logs)}\n{'=' * 60}\n"
                                )
                                for log in logs:
                                    f.write(
                                        f"[{log.get('type', 'log')}] {log.get('text', '')}\n")
                            saved_path = f"output/console_{domain}.txt"
                            inner = dict(inner)
                            inner["auto_saved"] = saved_path
                            inner["note"] = (
                                f"[Auto-saved {len(logs)} console logs to {saved_path}."
                                " Check for errors, debug info, and leaked sensitive data.]"
                            )
                            result = {"success": True, "result": inner}
                            self._last_output_file = saved_path

                        elif action == "get_network_logs":
                            reqs = inner.get("network_requests", [])
                            net_file = host_output / f"network_{domain}.txt"
                            with open(net_file, "w", encoding="utf-8") as f:
                                f.write(
                                    f"URL: {page_url}\nTotal entries: {len(reqs)}\n{'=' * 60}\n\n"
                                )
                                for entry in reqs:
                                    etype = entry.get("type", "?")
                                    url = entry.get("url", "")
                                    if etype == "request":
                                        method = entry.get("method", "GET")
                                        resource_type = entry.get("resource_type", "")
                                        f.write(
                                            f">> {method} [{resource_type}] {url}\n"
                                        )
                                        if entry.get("post_data"):
                                            f.write(f"   BODY: {entry['post_data']}\n")
                                    elif etype == "response":
                                        status = entry.get("status", "")
                                        content_type = entry.get("content_type", "")
                                        f.write(
                                            f"<< {status} {url}  [{content_type}]\n"
                                        )
                                        if entry.get("body"):
                                            f.write(f"   RESPONSE: {entry['body']}\n")
                                    f.write("\n")
                            saved_path = f"output/network_{domain}.txt"
                            summary = inner.get("network_summary", {})
                            api_calls = summary.get("api_calls", [])
                            inner = dict(inner)
                            # strip raw list from LLM context
                            inner.pop("network_requests", None)
                            inner["auto_saved"] = saved_path
                            inner["note"] = (
                                f"[Auto-saved {len(reqs)} network entries to {saved_path}."
                                f" {len(api_calls)} XHR/Fetch API calls detected."
                                " Review for API endpoints, auth tokens, and sensitive data in responses.]"
                            )
                            result = {"success": True, "result": inner}
                            self._last_output_file = saved_path

                    except Exception as _e:
                        logger.warning("Failed to auto-save browser result: %s", _e)

            try:
                self._save_tool_output(tool_name, arguments, result)
            except Exception as _e:
                logger.debug("Could not save tool output: %s", _e)
        except Exception as e:
            success = False
            result = {"success": False, "error": str(e)}
            logger.error("Browser tool exec error: %s", e)

        duration = time.time() - start_time

        history_result = result
        if success and self._last_output_file and len(
                str(result)) > _RESULT_TRUNCATION_THRESHOLD:
            history_result = {
                "success": True,
                "result": f"<Result truncated. Full output in {self._last_output_file}>",
                "truncated": True,
            }

        self.state.tool_history.append(
            ToolExecution(
                tool_name=tool_name, arguments=arguments,
                result=history_result, duration=duration,
                status="success" if success else "error",
            )
        )
        self.state.tool_counts["exec"] += 1
        self.state.tool_counts["total"] += 1

        if success:
            self._executed_tool_counts[args_key] = self._executed_tool_counts.get(
                args_key, 0) + 1
        return success, duration, result, self._last_output_file

    async def _execute_filesystem_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> tuple[bool, float, dict[str, Any], str | None]:
        self._last_output_file = None
        start_time = time.time()

        try:
            path_arg = arguments.get("path", "")
            if path_arg.startswith("workspace/"):
                path_arg = path_arg[10:]
            elif path_arg.startswith("/workspace/"):
                path_arg = path_arg[11:]

            if self.state.active_target:
                if not path_arg.startswith(self.state.active_target) and not os.path.isabs(
                        path_arg):
                    path_arg = os.path.join(
                        self.state.active_target,
                        path_arg)

            # Path traversal protection: resolve and verify path is within workspace
            workspace_root = get_workspace_root()
            resolved = (workspace_root / path_arg).resolve()
            try:
                resolved.relative_to(workspace_root.resolve())
            except ValueError:
                return False, 0.0, {
                    "success": False,
                    "error": f"Path traversal attempt blocked: '{path_arg}' resolves outside workspace.",
                }, None

            arguments["path"] = path_arg

            if tool_name == "create_file":
                # Match against the basename only to avoid false positives on
                # parent directory names like "reports/notes.md".
                # Exempt skill files (path contains "skills/") since those are
                # instruction documents, not vulnerability reports.
                _raw_path = str(arguments.get("path", "")).strip()
                _is_skill_file = "skills/" in _raw_path.replace("\\", "/")
                basename_lower = Path(_raw_path).name.lower()
                if (
                    not _is_skill_file
                    and basename_lower.endswith(".md")
                    and any(token in basename_lower for token in _REPORT_FILE_PATTERNS)
                ):
                    return False, 0.0, {
                        "success": False,
                        "error": (
                            "BLOCKED: Writing vulnerability findings to markdown is forbidden. "
                            "Use create_vulnerability_report for confirmed findings."
                        ),
                    }, None
                result = await asyncio.to_thread(create_file, **arguments)
            elif tool_name == "read_file":
                path_arg_clean = arguments.get("path", "")
                if "skills/" in path_arg_clean and path_arg_clean.endswith(".md"):
                    skill_name = os.path.basename(
                        path_arg_clean).replace(".md", "")
                    if skill_name not in self.state.skills_used:
                        self.state.skills_used.append(skill_name)
                result = await asyncio.to_thread(
                    read_file,
                    path=path_arg_clean,
                    offset=int(arguments.get("offset", 0)),
                    limit=int(arguments.get("limit", 500)),
                )
            elif tool_name == "list_files":
                result = await asyncio.to_thread(
                    list_files,
                    path=arguments.get("path", ""),
                )
            else:
                result = {
                    "success": False,
                    "error": f"Unknown filesystem tool: {tool_name}"}

            success = result.get("success", False)
            try:
                self._save_tool_output(tool_name, arguments, result)
            except Exception as _e:
                logger.debug("Could not save tool output: %s", _e)
        except Exception as e:
            success = False
            result = {"success": False, "error": str(e)}
            logger.error("Filesystem tool exec error: %s", e)

        duration = time.time() - start_time

        history_result = result
        if tool_name == "read_file" and success:
            content = result.get("result", "")
            if len(content) > _READ_FILE_CONTENT_TRUNCATION_THRESHOLD:
                history_result = {
                    "success": True,
                    "result": f"<File content loaded ({len(content)} chars). Truncated in history.>",
                    "truncated": True,
                }

        self.state.tool_history.append(
            ToolExecution(
                tool_name=tool_name, arguments=arguments,
                result=history_result, duration=duration,
                status="success" if success else "error",
            )
        )
        self.state.tool_counts["exec"] += 1
        self.state.tool_counts["total"] += 1
        return success, duration, result, self._last_output_file

    async def _execute_web_search_tool(
        self,
        arguments: dict[str, Any],
    ) -> tuple[bool, float, dict[str, Any], str | None]:
        start_time = time.time()
        try:
            result = await web_search(
                query=arguments.get("query", ""),
                max_results=arguments.get("max_results", 10),
            )
            success = result.get("success", False)
        except Exception as e:
            success = False
            result = {"success": False, "error": str(e)}
            logger.error("Web search tool error: %s", e)

        duration = time.time() - start_time

        # Auto-save results to output/dork_results.txt so Phase 1 evidence
        # is persisted even if the model forgets to call create_file.
        saved_path: str | None = None
        if success and self.state.active_target:
            try:
                host_output = (
                    get_workspace_root()
                    / self.state.active_target
                    / "output"
                )
                host_output.mkdir(parents=True, exist_ok=True)
                dork_file = host_output / "dork_results.txt"
                query = arguments.get("query", "")
                entry = (
                    f"\n{'=' * 60}\n"
                    f"QUERY: {query}\n"
                    f"{'=' * 60}\n"
                    f"{result.get('result', '')}\n"
                )
                with open(dork_file, "a", encoding="utf-8") as f:
                    f.write(entry)
                saved_path = "output/dork_results.txt"
                # Tell the model where the data was saved
                result = dict(result)
                result["saved_to"] = saved_path
                result["result"] = (
                    result.get("result", "")
                    + f"\n\n[Auto-saved to {saved_path}]"
                )
            except Exception as e:
                logger.warning("Failed to auto-save dork results: %s", e)

        self.state.tool_history.append(
            ToolExecution(
                tool_name="web_search", arguments=arguments,
                result=result, duration=duration,
                status="success" if success else "error",
            )
        )
        self.state.tool_counts["exec"] += 1
        self.state.tool_counts["total"] += 1
        return success, duration, result, saved_path

    async def _execute_report_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> tuple[bool, float, dict[str, Any], str | None]:
        self._last_output_file = None
        start_time = time.time()

        try:
            result = await asyncio.to_thread(
                create_vulnerability_report,
                **arguments,
                _active_target=self.state.active_target,
            )
            success = result.get("success", False)
            try:
                self._save_tool_output(tool_name, arguments, result)
            except Exception as _e:
                logger.debug("Could not save tool output: %s", _e)

            # Mark matching vulnerability as reported so REPORT phase can
            # transition
            if success and self._session:
                report_title = arguments.get("title", "")
                flag = arguments.get("flag", "")
                matched = False
                for vuln in self._session.vulnerabilities:
                    v_title = vuln.get("title", vuln.get("finding", ""))
                    if report_title and v_title and v_title.lower() in report_title.lower():
                        vuln["report_generated"] = True
                        if flag:
                            vuln["flag"] = flag
                        matched = True
                if not matched and report_title:
                    self._session.vulnerabilities.append({
                        "title": report_title,
                        "finding": report_title,
                        "report_generated": True,
                        "flag": flag,
                        "source": "create_vulnerability_report",
                        "timestamp": datetime.now().isoformat(),
                    })
        except Exception as e:
            success = False
            result = {"success": False, "error": str(e)}
            logger.error("Reporting tool exec error: %s", e)

        duration = time.time() - start_time
        self.state.tool_history.append(
            ToolExecution(
                tool_name=tool_name, arguments=arguments,
                result=result, duration=duration,
                status="success" if success else "error",
            )
        )
        self.state.tool_counts["exec"] += 1
        self.state.tool_counts["total"] += 1
        return success, duration, result, self._last_output_file

    async def _execute_advanced_fuzz_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> tuple[bool, float, dict[str, Any], str | None]:
        from ..fuzzer import Fuzzer
        self._last_output_file = None
        start_time = time.time()

        target = arguments.get("target", "")
        params = arguments.get("parameters", [])
        method = arguments.get("method", "GET")
        vuln_types = arguments.get("vuln_types",
                                   ["sql_injection",
                                    "xss",
                                    "idor",
                                    "ssti",
                                    "command_injection",
                                    "path_traversal",
                                    "xxe",
                                    "race_condition",
                                    "parameter_pollution",
                                    "mass_assignment"])

        try:
            fuzzer = Fuzzer(target=target, method=method, headers=self._build_fuzz_headers())
            results = await fuzzer.fuzz_parameters(params, vuln_types)

            if not results:
                res_dict = {
                    "success": True,
                    "result": "No vulnerabilities found with confidence > 0.60."}
            else:
                findings_list = []
                for r in results:
                    findings_list.append(
                        f"Param: {r.parameter} | Vuln: {r.vuln_type} | "
                        f"Severity: {r.severity} | Conf: {r.confidence:.2f} | "
                        f"Evidence: {r.evidence}"
                    )
                res_dict = {"success": True, "findings": findings_list}

            try:
                self._save_tool_output(tool_name, arguments, res_dict)
            except Exception as _e:
                logger.debug("Could not save tool output: %s", _e)
            success = True
        except Exception as e:
            logger.error("Fuzzer error: %s", e)
            res_dict = {"success": False, "error": str(e)}
            success = False

        duration = time.time() - start_time

        self.state.tool_history.append(
            ToolExecution(
                tool_name=tool_name, arguments=arguments,
                result=res_dict, duration=duration,
                status="success" if success else "error",
            )
        )
        self.state.tool_counts["total"] += 1

        return success, duration, res_dict, None

    async def _execute_quick_fuzz_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> tuple[bool, float, dict[str, Any], str | None]:
        from ..fuzzer import quick_fuzz_url
        self._last_output_file = None
        start_time = time.time()

        target = arguments.get("target", "")
        params = arguments.get("params") or None

        try:
            results = await quick_fuzz_url(
                url=target, params=params,
                headers=self._build_fuzz_headers(),
            )

            if not results:
                res_dict = {
                    "success": True,
                    "result": "No vulnerabilities found with confidence > 0.60."}
            else:
                findings_list = [
                    f"Param: {r.parameter} | Vuln: {r.vuln_type} | "
                    f"Severity: {r.severity} | Conf: {r.confidence:.2f} | "
                    f"Evidence: {r.evidence}"
                    for r in results
                ]
                # Build stdout with [SEVERITY] prefix so session extractor
                # can capture findings into session.vulnerabilities.
                stdout_lines = []
                for r in results:
                    sev = r.severity.upper()
                    stdout_lines.append(
                        f"[{sev}] {r.vuln_type.upper()} on param '{r.parameter}'"
                        f" at {r.target}"
                    )
                    stdout_lines.append(
                        f"Payload: {r.payload} | Conf: {r.confidence:.2f}"
                    )
                    stdout_lines.append(f"Evidence: {r.evidence}")
                res_dict = {
                    "success": True,
                    "stdout": "\n".join(stdout_lines),
                    "findings": findings_list,
                    "total": len(findings_list)}

            try:
                self._save_tool_output(tool_name, arguments, res_dict)
            except Exception as _e:
                logger.debug("Could not save tool output: %s", _e)
            success = True
        except Exception as e:
            logger.error("quick_fuzz error: %s", e)
            res_dict = {"success": False, "error": str(e)}
            success = False

        duration = time.time() - start_time
        self.state.tool_history.append(
            ToolExecution(
                tool_name=tool_name, arguments=arguments,
                result=res_dict, duration=duration,
                status="success" if success else "error",
            )
        )
        self.state.tool_counts["total"] += 1
        return success, duration, res_dict, None

    async def _execute_deep_fuzz_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> tuple[bool, float, dict[str, Any], str | None]:
        self._last_output_file = None
        start_time = time.time()

        target = arguments.get("target", "")
        params = arguments.get("params") or None
        vuln_types = arguments.get("vuln_types") or None

        try:
            from ..fuzzer import InteractiveRealTimeTester
            tester = InteractiveRealTimeTester(
                target, threads=10, timeout=20,
                headers=self._build_fuzz_headers(),
            )
            async for event in tester.stream_fuzz(params=params, vuln_types=vuln_types):
                pass
            summary = tester.get_summary()

            findings_list = []
            for f in getattr(tester, "_findings", []):
                findings_list.append(
                    f"Param: {f.parameter} | Vuln: {f.vuln_type} | "
                    f"Severity: {f.severity} | Conf: {f.confidence:.2f} | "
                    f"Evidence: {f.evidence}"
                )

            res_dict = {
                "success": True,
                "summary": summary,
                "findings": findings_list,
            }

            try:
                self._save_tool_output(tool_name, arguments, res_dict)
            except Exception as _e:
                logger.debug("Could not save tool output: %s", _e)
            success = True
        except Exception as e:
            logger.error("deep_fuzz error: %s", e)
            res_dict = {"success": False, "error": str(e)}
            success = False

        duration = time.time() - start_time
        self.state.tool_history.append(
            ToolExecution(
                tool_name=tool_name, arguments=arguments,
                result=res_dict, duration=duration,
                status="success" if success else "error",
            )
        )
        self.state.tool_counts["total"] += 1
        return success, duration, res_dict, None

    async def _execute_generate_wordlist_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> tuple[bool, float, dict[str, Any], str | None]:
        from ..fuzzer import generate_fuzz_wordlist
        self._last_output_file = None
        start_time = time.time()

        # Strip any directory components — only allow plain filenames to
        # prevent path traversal (e.g. output_file="../../etc/cron.d/x").
        raw_output_file = arguments.get("output_file", "wordlist.txt")
        output_file = Path(raw_output_file).name or "wordlist.txt"
        max_combinations = min(
            int(arguments.get("max_combinations", 300)), 1000)
        vuln_types = arguments.get("vuln_types") or None

        try:
            wordlist = generate_fuzz_wordlist(
                max_combinations=max_combinations,
                vuln_types=vuln_types,
            )

            # Save to workspace output/
            target = self.state.active_target or "unknown"
            host_output = get_workspace_root() / target / "output"
            host_output.mkdir(parents=True, exist_ok=True)
            out_path = host_output / output_file
            with open(out_path, "w", encoding="utf-8") as f:
                f.write("\n".join(wordlist))

            saved_path = f"output/{output_file}"
            res_dict = {
                "success": True,
                "result": f"Generated {len(wordlist)} entries saved to {saved_path}.",
                "saved_to": saved_path,
                "total_entries": len(wordlist),
            }
            self._last_output_file = saved_path

            try:
                self._save_tool_output(tool_name, arguments, res_dict)
            except Exception as _e:
                logger.debug("Could not save tool output: %s", _e)
            success = True
        except Exception as e:
            logger.error("generate_wordlist error: %s", e)
            res_dict = {"success": False, "error": str(e)}
            success = False

        duration = time.time() - start_time
        self.state.tool_history.append(
            ToolExecution(
                tool_name=tool_name, arguments=arguments,
                result=res_dict, duration=duration,
                status="success" if success else "error",
            )
        )
        self.state.tool_counts["total"] += 1
        return success, duration, res_dict, self._last_output_file

    async def _execute_run_parallel_agents_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> tuple[bool, float, dict[str, Any], str | None]:
        from .subagent import ParallelAgentRunner
        self._last_output_file = None
        start_time = time.time()

        targets = arguments.get("targets", [])
        prompt = arguments.get("prompt", "")

        try:
            runner = ParallelAgentRunner(
                engine=self.engine)
            results = await runner.run_parallel(targets, prompt)

            # Summarize the vulnerabilities found per target
            res_dict = {
                "success": True,
                "results": {
                    t: len(
                        s.vulnerabilities) for t,
                    s in results.items()}}

            try:
                self._save_tool_output(tool_name, arguments, res_dict)
            except Exception as _e:
                logger.debug("Could not save tool output: %s", _e)
            success = True
        except Exception as e:
            logger.error("Subagent runner error: %s", e)
            res_dict = {"success": False, "error": str(e)}
            success = False

        duration = time.time() - start_time

        self.state.tool_history.append(
            ToolExecution(
                tool_name=tool_name, arguments=arguments,
                result=res_dict, duration=duration,
                status="success" if success else "error",
            )
        )
        self.state.tool_counts["total"] += 1

        return success, duration, res_dict, None

    # ------------------------------------------------------------------
    # Native Caido Tools
    # ------------------------------------------------------------------

    async def _execute_caido_list_requests_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> tuple[bool, float, dict[str, Any], str | None]:
        from ..caido_client import CaidoClient
        self._last_output_file = None
        start_time = time.time()

        httpql = arguments.get("filter", "")
        limit = min(int(arguments.get("limit", 50)), 200)

        query = """
        query ListRequests($filter: RequestsFilter, $first: Int) {
            requests(filter: $filter, first: $first) {
                edges {
                    node {
                        id
                        method
                        host
                        path
                        response { statusCode }
                    }
                }
            }
        }
        """
        variables = {"filter": {"httpql": httpql}, "first": limit}

        try:
            data = await CaidoClient.gql(query, variables)
            if "errors" in data:
                res_dict = {
                    "success": False,
                    "error": data["errors"][0]["message"]}
                success = False
            else:
                edges = data.get(
                    "data",
                    {}).get(
                    "requests",
                    {}).get(
                    "edges",
                    [])
                requests = [
                    {
                        "id": e["node"]["id"],
                        "method": e["node"]["method"],
                        "host": e["node"]["host"],
                        "path": e["node"]["path"],
                        "status": (e["node"].get("response") or {}).get("statusCode"),
                    }
                    for e in edges
                ]
                res_dict = {
                    "success": True,
                    "requests": requests,
                    "total": len(requests)}
                success = True
        except Exception as e:
            logger.error("caido_list_requests error: %s", e)
            res_dict = {"success": False, "error": str(e)}
            success = False

        duration = time.time() - start_time
        self.state.tool_history.append(
            ToolExecution(tool_name=tool_name, arguments=arguments,
                          result=res_dict, duration=duration,
                          status="success" if success else "error")
        )
        self.state.tool_counts["total"] += 1
        return success, duration, res_dict, None

    async def _execute_caido_send_request_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> tuple[bool, float, dict[str, Any], str | None]:
        from ..caido_client import CaidoClient
        self._last_output_file = None
        start_time = time.time()

        request_id = self._str_arg(arguments, "request_id")
        raw_http = self._str_arg(arguments, "raw_http")
        # Strip protocol prefix if LLM passes full URL instead of bare host
        host = self._str_arg(arguments, "host").removeprefix("https://").removeprefix("http://").rstrip("/")
        # is_tls: handle both real bool and string "false"/"true" from LLM
        _is_tls_raw = arguments.get("is_tls", True)
        if isinstance(_is_tls_raw, str):
            is_tls = _is_tls_raw.lower() not in ("false", "0", "no", "")
        else:
            is_tls = bool(_is_tls_raw)
        # Default port: 443 for TLS, 80 for plain — respect explicit override
        _port_raw = arguments.get("port")
        try:
            port = int(_port_raw) if _port_raw is not None else (443 if is_tls else 80)
        except (TypeError, ValueError):
            port = 443 if is_tls else 80

        try:
            async with asyncio.timeout(60):
                # Step 1: Create replay session
                create_q = """
                mutation CreateReplay($input: CreateReplaySessionInput!) {
                    createReplaySession(input: $input) {
                        session { id }
                    }
                }
                """
                source: dict[str, Any] = {}
                if request_id:
                    source = {"id": request_id}
                create_vars: dict[str, Any] = {"input": {}}
                if source:
                    create_vars["input"]["requestSource"] = source

                create_data = await CaidoClient.gql(create_q, create_vars)
                if "errors" in create_data:
                    raise RuntimeError(create_data["errors"][0]["message"])
                session_id = create_data["data"]["createReplaySession"]["session"]["id"]

                # Step 2: Send (start replay task)
                start_q = """
                mutation StartReplay($sessionId: ID!, $input: StartReplayTaskInput!) {
                    startReplayTask(sessionId: $sessionId, input: $input) {
                        task { id }
                    }
                }
                """
                task_input: dict[str, Any] = {
                    "connection": {"host": host, "port": port, "isTLS": is_tls},
                    "settings": {"connectionClose": False, "updateContentLength": True, "placeholders": []},
                }
                if raw_http:
                    task_input["raw"] = CaidoClient.encode_raw_http(raw_http)

                start_data = await CaidoClient.gql(start_q, {"sessionId": session_id, "input": task_input})
                if "errors" in start_data:
                    raise RuntimeError(start_data["errors"][0]["message"])

                task_id = start_data["data"]["startReplayTask"]["task"]["id"]
            res_dict = {"success": True, "session_id": session_id, "task_id": task_id,
                        "host": host, "port": port}
            success = True
        except asyncio.TimeoutError:
            logger.error("caido_send_request timeout (60s)")
            res_dict = {
                "success": False,
                "error": "Caido did not respond within 60 seconds"}
            success = False
        except Exception as e:
            logger.error("caido_send_request error: %s", e)
            res_dict = {"success": False, "error": str(e)}
            success = False

        duration = time.time() - start_time
        self.state.tool_history.append(
            ToolExecution(tool_name=tool_name, arguments=arguments,
                          result=res_dict, duration=duration,
                          status="success" if success else "error")
        )
        self.state.tool_counts["total"] += 1
        return success, duration, res_dict, None

    async def _execute_caido_automate_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> tuple[bool, float, dict[str, Any], str | None]:
        from ..caido_client import CaidoClient
        self._last_output_file = None
        start_time = time.time()

        raw_http = self._str_arg(arguments, "raw_http")
        host = self._str_arg(arguments, "host").removeprefix("https://").removeprefix("http://").rstrip("/")
        _is_tls_raw = arguments.get("is_tls", True)
        if isinstance(_is_tls_raw, str):
            is_tls = _is_tls_raw.lower() not in ("false", "0", "no", "")
        else:
            is_tls = bool(_is_tls_raw)
        _port_raw = arguments.get("port")
        try:
            port = int(_port_raw) if _port_raw is not None else (443 if is_tls else 80)
        except (TypeError, ValueError):
            port = 443 if is_tls else 80
        payloads = arguments.get("payloads", [])
        workers = min(int(arguments.get("workers", 10)), 50)

        # Calculate §FUZZ§ placeholders BEFORE stripping markers.
        # find_fuzz_offsets() works on the original string and returns positions
        # in the clean (marker-stripped) bytes — so order matters.
        placeholders = CaidoClient.find_fuzz_offsets(raw_http)
        clean_http = raw_http.replace("§FUZZ§", "")
        encoded_raw = CaidoClient.encode_raw_http(clean_http)

        # Track created session so we can clean up on failure before recording task_id
        auto_id: str | None = None
        task_id: str | None = None

        async def _cleanup_orphan_session() -> None:
            """Best-effort delete of a Caido session that was created but never tracked."""
            if not auto_id:
                return
            try:
                delete_q = """
                mutation DeleteSession($id: ID!) {
                    deleteAutomateSession(id: $id) { deletedId }
                }
                """
                await asyncio.wait_for(
                    CaidoClient.gql(delete_q, {"id": auto_id}), timeout=5.0
                )
                logger.info("Cleaned up orphaned Caido automate session %s", auto_id)
            except Exception as cleanup_err:
                logger.debug(
                    "Could not clean up Caido session %s (manual cleanup may be needed): %s",
                    auto_id, cleanup_err,
                )

        try:
            async with asyncio.timeout(90):
                # Step 1: Create automate session
                create_q = "mutation { createAutomateSession(input: {}) { session { id } } }"
                create_data = await CaidoClient.gql(create_q)
                if "errors" in create_data:
                    raise RuntimeError(create_data["errors"][0]["message"])
                auto_id = create_data["data"]["createAutomateSession"]["session"]["id"]

                # Step 2: Configure session with request, placeholders, and
                # payloads
                update_q = """
                mutation UpdateAutomate($id: ID!, $input: UpdateAutomateSessionInput!) {
                    updateAutomateSession(id: $id, input: $input) {
                        session { id }
                    }
                }
                """
                update_input: dict[str, Any] = {
                    "connection": {"host": host, "port": port, "isTLS": is_tls},
                    "raw": encoded_raw,
                    "settings": {
                        "closeConnection": False,
                        "updateContentLength": True,
                        "strategy": "SEQUENTIAL",
                        "concurrency": {"workers": workers, "delay": 0},
                        "placeholders": placeholders,
                        "payloads": [{"preprocessors": [], "options": {"simpleList": {"list": payloads}}}],
                    },
                }
                update_data = await CaidoClient.gql(update_q, {"id": auto_id, "input": update_input})
                if "errors" in update_data:
                    raise RuntimeError(update_data["errors"][0]["message"])

                # Step 3: Start automate task
                start_q = """
                mutation StartAutomate($id: ID!) {
                    startAutomateTask(automateSessionId: $id) {
                        automateTask { id paused }
                    }
                }
                """
                start_data = await CaidoClient.gql(start_q, {"id": auto_id})
                if "errors" in start_data:
                    raise RuntimeError(start_data["errors"][0]["message"])

                task_id = start_data["data"]["startAutomateTask"]["automateTask"]["id"]
            res_dict = {
                "success": True,
                "automate_session_id": auto_id,
                "task_id": task_id,
                "payloads_count": len(payloads),
                "placeholders": len(placeholders),
                "workers": workers,
            }
            success = True
        except asyncio.TimeoutError:
            logger.error("caido_automate timeout (90s)")
            # task_id was never captured — session may be orphaned in Caido
            if task_id is None:
                await _cleanup_orphan_session()
            res_dict = {
                "success": False,
                "error": "Caido did not respond within 90 seconds"}
            success = False
        except Exception as e:
            logger.error("caido_automate error: %s", e)
            # Clean up session if task was never started
            if task_id is None:
                await _cleanup_orphan_session()
            res_dict = {"success": False, "error": str(e)}
            success = False

        duration = time.time() - start_time
        self.state.tool_history.append(
            ToolExecution(tool_name=tool_name, arguments=arguments,
                          result=res_dict, duration=duration,
                          status="success" if success else "error")
        )
        self.state.tool_counts["total"] += 1
        return success, duration, res_dict, None

    async def _execute_caido_get_findings_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> tuple[bool, float, dict[str, Any], str | None]:
        from ..caido_client import CaidoClient
        self._last_output_file = None
        start_time = time.time()

        limit = min(int(arguments.get("limit", 50)), 200)

        query = """
        query GetFindings($first: Int) {
            findings(first: $first) {
                edges {
                    node {
                        id
                        title
                        description
                        reporter
                        request {
                            id method host path
                            response { statusCode }
                        }
                    }
                }
            }
        }
        """
        try:
            data = await CaidoClient.gql(query, {"first": limit})
            if "errors" in data:
                res_dict = {
                    "success": False,
                    "error": data["errors"][0]["message"]}
                success = False
            else:
                edges = data.get(
                    "data",
                    {}).get(
                    "findings",
                    {}).get(
                    "edges",
                    [])
                findings = [
                    {
                        "id": e["node"]["id"],
                        "title": e["node"]["title"],
                        "description": e["node"].get("description", ""),
                        "reporter": e["node"].get("reporter", ""),
                        "request": {
                            "id": (e["node"].get("request") or {}).get("id"),
                            "method": (e["node"].get("request") or {}).get("method"),
                            "host": (e["node"].get("request") or {}).get("host"),
                            "path": (e["node"].get("request") or {}).get("path"),
                            "status": ((e["node"].get("request") or {}).get("response") or {}).get("statusCode"),
                        },
                    }
                    for e in edges
                ]
                res_dict = {
                    "success": True,
                    "findings": findings,
                    "total": len(findings)}
                success = True
        except Exception as e:
            logger.error("caido_get_findings error: %s", e)
            res_dict = {"success": False, "error": str(e)}
            success = False

        duration = time.time() - start_time
        self.state.tool_history.append(
            ToolExecution(tool_name=tool_name, arguments=arguments,
                          result=res_dict, duration=duration,
                          status="success" if success else "error")
        )
        self.state.tool_counts["total"] += 1
        return success, duration, res_dict, None

    async def _execute_caido_set_scope_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> tuple[bool, float, dict[str, Any], str | None]:
        from ..caido_client import CaidoClient
        self._last_output_file = None
        start_time = time.time()

        # tools.json uses snake_case field names; Caido GraphQL uses camelCase.
        allowlist = arguments.get("allowlist", [])
        denylist = arguments.get("denylist", [])
        scope_name = f"airecon-{self.state.active_target or 'scope'}"

        try:
            # Step 1: Check if a scope with the same name already exists so we
            # can update it instead of accumulating duplicate scopes on every
            # call.
            # Caido scopes query returns a direct array, not a connection (no edges/node).
            list_q = """
            query ListScopes {
                scopes { id name }
            }
            """
            existing_id: str | None = None
            try:
                list_data = await CaidoClient.gql(list_q)
                scopes_list = (
                    list_data.get("data", {})
                    .get("scopes", [])
                )
                for scope in scopes_list:
                    if scope.get("name") == scope_name:
                        existing_id = scope["id"]
                        break
            except Exception as _list_err:
                logger.debug("Could not list Caido scopes: %s — will create new", _list_err)

            if existing_id:
                # Update the existing scope (avoids duplicate accumulation).
                # Caido GraphQL uses snake_case (allowlist/denylist) not camelCase.
                update_q = """
                mutation UpdateScope($id: ID!, $input: UpdateScopeInput!) {
                    updateScope(id: $id, input: $input) {
                        scope { id name }
                    }
                }
                """
                variables: dict[str, Any] = {
                    "id": existing_id,
                    "input": {
                        "name": scope_name,  # UpdateScopeInput also requires name
                        "allowlist": allowlist,
                        "denylist": denylist,
                    },
                }
                data = await CaidoClient.gql(update_q, variables)
                scope_key = "updateScope"
            else:
                # Create a fresh scope.
                create_q = """
                mutation CreateScope($input: CreateScopeInput!) {
                    createScope(input: $input) {
                        scope { id name }
                    }
                }
                """
                variables = {
                    "input": {
                        "name": scope_name,
                        "allowlist": allowlist,
                        "denylist": denylist,
                    },
                }
                data = await CaidoClient.gql(create_q, variables)
                scope_key = "createScope"

            if "errors" in data:
                res_dict = {
                    "success": False,
                    "error": data["errors"][0]["message"],
                }
                success = False
            else:
                scope = (
                    data.get("data", {})
                    .get(scope_key, {})
                    .get("scope", {})
                )
                res_dict = {
                    "success": True,
                    "scope_id": scope.get("id"),
                    "scope_name": scope.get("name"),
                    "action": "updated" if existing_id else "created",
                    "allowlist": allowlist,
                    "denylist": denylist,
                }
                success = True
        except Exception as e:
            logger.error("caido_set_scope error: %s", e)
            res_dict = {"success": False, "error": str(e)}
            success = False

        duration = time.time() - start_time
        self.state.tool_history.append(
            ToolExecution(tool_name=tool_name, arguments=arguments,
                          result=res_dict, duration=duration,
                          status="success" if success else "error")
        )
        self.state.tool_counts["total"] += 1
        return success, duration, res_dict, None

    # ------------------------------------------------------------------
    # Caido Intercept Control
    # ------------------------------------------------------------------

    async def _execute_caido_intercept_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> tuple[bool, float, dict[str, Any], str | None]:
        from ..caido_client import CaidoClient
        self._last_output_file = None
        start_time = time.time()

        action = arguments.get("action", "status")
        message_id = arguments.get("message_id")
        raw_http = arguments.get("raw_http")

        try:
            if action == "status":
                data = await CaidoClient.gql("{ interceptStatus }")
                if "errors" in data:
                    res_dict = {"success": False, "error": data["errors"][0]["message"]}
                    success = False
                else:
                    status = data.get("data", {}).get("interceptStatus", "UNKNOWN")
                    res_dict = {"success": True, "status": status}
                    success = True

            elif action == "pause":
                data = await CaidoClient.gql(
                    "mutation { pauseIntercept { status } }"
                )
                if "errors" in data:
                    res_dict = {"success": False, "error": data["errors"][0]["message"]}
                    success = False
                else:
                    status = (
                        data.get("data", {})
                        .get("pauseIntercept", {})
                        .get("status", "UNKNOWN")
                    )
                    res_dict = {"success": True, "status": status}
                    success = True

            elif action == "resume":
                data = await CaidoClient.gql(
                    "mutation { resumeIntercept { status } }"
                )
                if "errors" in data:
                    res_dict = {"success": False, "error": data["errors"][0]["message"]}
                    success = False
                else:
                    status = (
                        data.get("data", {})
                        .get("resumeIntercept", {})
                        .get("status", "UNKNOWN")
                    )
                    res_dict = {"success": True, "status": status}
                    success = True

            elif action == "list":
                query = """
                query {
                    interceptMessages(first: 20, kind: REQUEST) {
                        edges {
                            node {
                                id
                                ... on InterceptRequestMessage {
                                    request {
                                        method
                                        host
                                        path
                                    }
                                }
                            }
                        }
                    }
                }
                """
                data = await CaidoClient.gql(query)
                if "errors" in data:
                    res_dict = {"success": False, "error": data["errors"][0]["message"]}
                    success = False
                else:
                    edges = (
                        data.get("data", {})
                        .get("interceptMessages", {})
                        .get("edges", [])
                    )
                    messages = [
                        {
                            "id": e["node"]["id"],
                            "method": e["node"].get("request", {}).get("method"),
                            "host": e["node"].get("request", {}).get("host"),
                            "path": e["node"].get("request", {}).get("path"),
                        }
                        for e in edges
                    ]
                    res_dict = {"success": True, "queued": len(messages), "messages": messages}
                    success = True

            elif action == "forward":
                if not message_id:
                    res_dict = {"success": False, "error": "message_id required for forward"}
                    success = False
                else:
                    variables: dict[str, Any] = {"id": message_id}
                    if raw_http:
                        encoded = CaidoClient.encode_raw_http(raw_http)
                        variables["input"] = {
                            "request": {"updateRaw": encoded, "updateContentLength": True}
                        }
                    else:
                        variables["input"] = {}
                    mutation = """
                    mutation ForwardMessage($id: ID!, $input: ForwardInterceptMessageInput!) {
                        forwardInterceptMessage(id: $id, input: $input) {
                            ... on ForwardInterceptMessageSuccess { deletedId }
                            ... on Error { code message }
                        }
                    }
                    """
                    data = await CaidoClient.gql(mutation, variables)
                    if "errors" in data:
                        res_dict = {"success": False, "error": data["errors"][0]["message"]}
                        success = False
                    else:
                        payload = data.get("data", {}).get("forwardInterceptMessage", {})
                        if "code" in payload:
                            res_dict = {"success": False, "error": payload.get("message")}
                            success = False
                        else:
                            res_dict = {
                                "success": True,
                                "action": "forwarded",
                                "deleted_id": payload.get("deletedId"),
                            }
                            success = True

            elif action == "drop":
                if not message_id:
                    res_dict = {"success": False, "error": "message_id required for drop"}
                    success = False
                else:
                    mutation = """
                    mutation DropMessage($id: ID!) {
                        dropInterceptMessage(id: $id) {
                            ... on DropInterceptMessageSuccess { deletedId }
                            ... on Error { code message }
                        }
                    }
                    """
                    data = await CaidoClient.gql(mutation, {"id": message_id})
                    if "errors" in data:
                        res_dict = {"success": False, "error": data["errors"][0]["message"]}
                        success = False
                    else:
                        payload = data.get("data", {}).get("dropInterceptMessage", {})
                        if "code" in payload:
                            res_dict = {"success": False, "error": payload.get("message")}
                            success = False
                        else:
                            res_dict = {
                                "success": True,
                                "action": "dropped",
                                "deleted_id": payload.get("deletedId"),
                            }
                            success = True

            else:
                res_dict = {
                    "success": False,
                    "error": f"Unknown action: {action}. Use status/pause/resume/list/forward/drop",
                }
                success = False

        except Exception as e:
            logger.error("caido_intercept error: %s", e)
            res_dict = {"success": False, "error": str(e)}
            success = False

        duration = time.time() - start_time
        self.state.tool_history.append(
            ToolExecution(tool_name=tool_name, arguments=arguments,
                          result=res_dict, duration=duration,
                          status="success" if success else "error")
        )
        self.state.tool_counts["total"] += 1
        return success, duration, res_dict, None

    # ------------------------------------------------------------------
    # Caido Sitemap Browser
    # ------------------------------------------------------------------

    async def _execute_caido_sitemap_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> tuple[bool, float, dict[str, Any], str | None]:
        from ..caido_client import CaidoClient
        self._last_output_file = None
        start_time = time.time()

        parent_id = arguments.get("parent_id")  # None = list roots

        try:
            if parent_id is None:
                # List root entries (top-level domains/hosts)
                query = """
                {
                    sitemapRootEntries {
                        edges {
                            node {
                                id
                                label
                                kind
                                hasDescendants
                            }
                        }
                    }
                }
                """
                data = await CaidoClient.gql(query)
                if "errors" in data:
                    res_dict = {"success": False, "error": data["errors"][0]["message"]}
                    success = False
                else:
                    edges = (
                        data.get("data", {})
                        .get("sitemapRootEntries", {})
                        .get("edges", [])
                    )
                    entries = [
                        {
                            "id": e["node"]["id"],
                            "label": e["node"]["label"],
                            "kind": e["node"]["kind"],
                            "has_children": e["node"]["hasDescendants"],
                        }
                        for e in edges
                    ]
                    res_dict = {
                        "success": True,
                        "level": "root",
                        "count": len(entries),
                        "entries": entries,
                    }
                    success = True
            else:
                # List direct children of a given node
                query = """
                query SitemapChildren($parentId: ID!) {
                    sitemapDescendantEntries(parentId: $parentId, depth: DIRECT) {
                        edges {
                            node {
                                id
                                label
                                kind
                                hasDescendants
                            }
                        }
                    }
                }
                """
                data = await CaidoClient.gql(query, {"parentId": str(parent_id)})
                if "errors" in data:
                    res_dict = {"success": False, "error": data["errors"][0]["message"]}
                    success = False
                else:
                    edges = (
                        data.get("data", {})
                        .get("sitemapDescendantEntries", {})
                        .get("edges", [])
                    )
                    entries = [
                        {
                            "id": e["node"]["id"],
                            "label": e["node"]["label"],
                            "kind": e["node"]["kind"],
                            "has_children": e["node"]["hasDescendants"],
                        }
                        for e in edges
                    ]
                    res_dict = {
                        "success": True,
                        "level": "children",
                        "parent_id": parent_id,
                        "count": len(entries),
                        "entries": entries,
                    }
                    success = True

        except Exception as e:
            logger.error("caido_sitemap error: %s", e)
            res_dict = {"success": False, "error": str(e)}
            success = False

        duration = time.time() - start_time
        self.state.tool_history.append(
            ToolExecution(tool_name=tool_name, arguments=arguments,
                          result=res_dict, duration=duration,
                          status="success" if success else "error")
        )
        self.state.tool_counts["total"] += 1
        return success, duration, res_dict, None

    # ------------------------------------------------------------------
    # Source Code Analysis (Semgrep)
    # ------------------------------------------------------------------

    async def _execute_code_analysis_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> tuple[bool, float, dict[str, Any], str | None]:
        from ..semgrep import run_code_analysis
        self._last_output_file = None
        start_time = time.time()

        target_path = self._str_arg(arguments, "target_path") or "."
        rules = arguments.get("rules") or None
        languages = arguments.get("languages") or None

        # Resolve and validate path — guard against ../traversal escaping /workspace
        active_target = self.state.active_target or "unknown"
        from .validators import validate_target_path  # local import — no circular dep
        _base = "/workspace" if target_path.startswith("/") else f"/workspace/{active_target}"
        _ok, _resolved = validate_target_path(target_path, _base)
        if not _ok:
            return False, 0.0, {"success": False, "error": f"Invalid target_path: {_resolved}"}, None
        target_path = str(_resolved)

        try:
            result = await run_code_analysis(
                engine=self.engine,
                target_path=target_path,
                rules=rules,
                languages=languages,
            )

            findings_capped = result.get("findings", [])[:50]
            # Build stdout with [SEVERITY] prefix so session extractor
            # can capture findings into session.vulnerabilities.
            _stdout_lines: list[str] = []
            for _f in findings_capped:
                _sev = str(_f.get("severity", "MEDIUM")).upper()
                _rule = _f.get("rule_id", "unknown")
                _msg = _f.get("message", "")
                _file = _f.get("file", "")
                _line = _f.get("start_line", "?")
                _code = _f.get("code_snippet", "")
                _stdout_lines.append(f"[{_sev}] {_rule}: {_msg}")
                if _file:
                    _stdout_lines.append(f"  File: {_file}:{_line}")
                if _code:
                    _stdout_lines.append(f"  Code: {_code}")
            res_dict = {
                "success": True,
                "summary": result.get("summary", ""),
                "total": result.get("total", 0),
                "findings": findings_capped,
                "errors": result.get("errors", []),
                "stdout": "\n".join(_stdout_lines),
            }

            # Save output
            try:
                self._save_tool_output(tool_name, arguments, res_dict)
            except Exception as _e:
                logger.debug("Could not save tool output: %s", _e)
            success = True
        except Exception as e:
            logger.error("code_analysis error: %s", e)
            res_dict = {"success": False, "error": str(e)}
            success = False

        duration = time.time() - start_time
        self.state.tool_history.append(
            ToolExecution(
                tool_name=tool_name, arguments=arguments,
                result=res_dict, duration=duration,
                status="success" if success else "error",
            )
        )
        self.state.tool_counts["total"] += 1
        return success, duration, res_dict, None

    # ------------------------------------------------------------------
    # API Schema Fuzzing (Schemathesis)
    # ------------------------------------------------------------------

    async def _execute_schemathesis_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> tuple[bool, float, dict[str, Any], str | None]:
        """Run Schemathesis API schema fuzzing inside the Docker sandbox."""
        self._last_output_file = None
        start_time = time.time()

        schema_url = self._str_arg(arguments, "schema_url").strip()
        base_url = self._str_arg(arguments, "base_url").strip()
        auth_header = self._str_arg(arguments, "auth_header").strip()
        checks = arguments.get("checks") or []
        try:
            max_examples = int(arguments.get("max_examples") or 30)
        except (TypeError, ValueError):
            max_examples = 30

        if not schema_url:
            return False, 0.0, {"success": False,
                                "error": "'schema_url' is required."}, None

        # Build schemathesis CLI command — all user-supplied values shell-quoted
        import shlex
        cmd_parts = [
            "python3 -m schemathesis run",
            shlex.quote(schema_url),
        ]
        if base_url:
            cmd_parts.extend(["--base-url", shlex.quote(base_url)])
        if auth_header:
            cmd_parts.extend(
                ["--header", shlex.quote(f"Authorization: {auth_header}")])
        if checks:
            cmd_parts.extend(["--checks", shlex.quote(",".join(checks))])
        cmd_parts.append(f"--hypothesis-max-examples {int(max_examples)}")
        cmd_parts.append("--request-timeout 15")
        cmd_parts.append("--output-truncate false")
        cmd_parts.append("--code-sample-style python")
        active_target = self.state.active_target or "unknown"
        workspace_dir = shlex.quote(f"/workspace/{active_target}")
        output_file = shlex.quote(f"/workspace/{active_target}/output/schemathesis_results.txt")
        joined_cmd = " ".join(cmd_parts)
        full_cmd = (
            f"cd {workspace_dir} && "
            f"{joined_cmd} 2>&1 | tee {output_file}"
        )

        try:
            exec_result = await self.engine.execute_tool(
                "execute",
                {"command": full_cmd, "timeout": 300},
            )
            stdout = exec_result.get(
                "stdout", "") or exec_result.get(
                "result", "") or ""
            # Treat as failure only on hard execution errors (no output at all,
            # or explicit exec error). Schemathesis normally prints "ERROR:"
            # level lines for individual test cases — those are NOT failures.
            exec_error = exec_result.get("error") or exec_result.get("stderr") or ""
            engine_ok = bool(exec_result.get("success", True))
            success = engine_ok and (bool(stdout.strip()) or not bool(exec_error))

            # Parse summary line counts
            violations = stdout.count("FAILED") + \
                stdout.count("not_a_server_error")
            passed = stdout.count("PASSED")

            res_dict = {
                "success": success,
                "summary": f"Schemathesis completed: {passed} passed, {violations} potential violations.",
                "violations": violations,
                "output_file": output_file,
                "raw_output": stdout[:3000],
            }
            if not success:
                res_dict["error"] = exec_error[:500] if exec_error else "No output produced"
            try:
                self._save_tool_output(tool_name, arguments, res_dict)
            except Exception as _e:
                logger.debug("Could not save tool output: %s", _e)
        except Exception as e:
            logger.error("schemathesis_fuzz error: %s", e)
            res_dict = {"success": False, "error": str(e)}
            success = False

        duration = time.time() - start_time
        self.state.tool_history.append(
            ToolExecution(
                tool_name=tool_name, arguments=arguments,
                result=res_dict, duration=duration,
                status="success" if success else "error",
            )
        )
        self.state.tool_counts["total"] += 1
        return success, duration, res_dict, self._last_output_file

    # ------------------------------------------------------------------
    # Dynamic Subagent Spawn
    # ------------------------------------------------------------------

    async def _execute_spawn_agent_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> tuple[bool, float, dict[str, Any], str | None]:
        self._last_output_file = None
        start_time = time.time()

        task = arguments.get("task", "")
        target = arguments.get("target", self.state.active_target or "")
        # Validate and sanitize specialist — only allow known role names
        _RAW_SPECIALIST = str(arguments.get("specialist", "exploit"))
        _VALID_SPECIALISTS = {
            "sqli", "xss", "ssrf", "lfi", "recon", "exploit", "analyzer", "reporter"
        }
        specialist = _RAW_SPECIALIST.lower().strip() if _RAW_SPECIALIST.lower(
        ).strip() in _VALID_SPECIALISTS else "exploit"

        # Specialist prompts loaded from prompts/specialists/*.txt at module level.
        # Tool names belong in text files, not in Python code — see _SPECIALIST_PREFIXES.

        prompt = (
            f"[SUBAGENT — Specialist: {specialist.upper()}]\n"
            f"[Target: {target}]\n\n"
            f"{_SPECIALIST_PREFIXES.get(specialist, '')}\n\n"
            f"Task assigned by parent agent:\n{task}\n\n"
            "Run focused tests. Use create_vulnerability_report for each confirmed finding. "
            "Output [TASK_COMPLETE] when done."
        )

        try:
            from .loop import AgentLoop

            # Reuse parent's OllamaClient — avoids a redundant blocking
            # `ollama show` network call on every spawn_agent invocation.
            parent_ollama = getattr(self, "ollama", None)
            if parent_ollama is None:
                from ..config import get_config
                from ..ollama import OllamaClient
                parent_ollama = OllamaClient(model=get_config().ollama_model)

            # Subagent uses same engine as parent
            agent = AgentLoop(ollama=parent_ollama, engine=self.engine)
            # Subagent always gets a fresh session — never touches parent's.
            agent._is_subagent = True
            # Limit subagent iterations — focused task, not full recon
            agent._override_max_iterations = 100
            # Subagents must NOT be able to spawn further subagents (depth=1)
            agent._blocked_tools = {"spawn_agent", "run_parallel_agents"}

            # Drain subagent events, counting iterations for the result summary.
            _sub_iters = 0
            async for _ in agent.process_message(prompt):
                _sub_iters += 1

            _raw_sub_usage = getattr(getattr(agent, "state", None), "token_usage", {})
            sub_token_usage = dict(_raw_sub_usage) if isinstance(_raw_sub_usage, dict) else {}
            sub_total = _safe_non_negative_int(
                sub_token_usage.get("cumulative", sub_token_usage.get("used", 0))
            )
            sub_prompt_total = _safe_non_negative_int(
                sub_token_usage.get("cumulative_prompt", sub_token_usage.get("last_prompt", 0))
            )
            sub_completion_total = _safe_non_negative_int(
                sub_token_usage.get("cumulative_completion", sub_token_usage.get("last_completion", 0))
            )
            if sub_total > 0:
                state_token_usage = getattr(self.state, "token_usage", None)
                if not isinstance(state_token_usage, dict):
                    state_token_usage = {}
                    try:
                        self.state.token_usage = state_token_usage
                    except Exception:
                        pass
                state_token_usage["cumulative"] = _safe_non_negative_int(
                    state_token_usage.get("cumulative", 0)
                ) + sub_total
                state_token_usage["cumulative_prompt"] = _safe_non_negative_int(
                    state_token_usage.get("cumulative_prompt", 0)
                ) + sub_prompt_total
                state_token_usage["cumulative_completion"] = _safe_non_negative_int(
                    state_token_usage.get("cumulative_completion", 0)
                ) + sub_completion_total
                parent_session = getattr(self, "_session", None)
                if parent_session is not None:
                    parent_session.token_total = _safe_non_negative_int(
                        state_token_usage.get("cumulative", 0)
                    )
                    parent_session.token_prompt_total = _safe_non_negative_int(
                        state_token_usage.get("cumulative_prompt", 0)
                    )
                    parent_session.token_completion_total = _safe_non_negative_int(
                        state_token_usage.get("cumulative_completion", 0)
                    )
                    parent_session.token_last_used = _safe_non_negative_int(
                        state_token_usage.get("used", 0)
                    )

            findings: list[str] = []
            if agent._session:
                findings = [
                    v.get("finding", str(v))
                    for v in agent._session.vulnerabilities[:10]
                ]
                # Merge findings into parent session using proper deduplication
                parent_session = getattr(self, "_session", None)
                if parent_session is not None:
                    for vuln in agent._session.vulnerabilities:
                        if not _is_duplicate_vulnerability(
                                vuln, parent_session.vulnerabilities):
                            parent_session.vulnerabilities.append(vuln)

            res_dict = {
                "success": True,
                "specialist": specialist,
                "target": target,
                "findings": findings,
                "total": len(findings),
                "iterations": _sub_iters,
                "token_usage": sub_token_usage,
            }
            success = True
        except Exception as e:
            logger.error("spawn_agent error: %s", e)
            res_dict = {"success": False, "error": str(e)}
            success = False

        duration = time.time() - start_time
        self.state.tool_history.append(
            ToolExecution(tool_name=tool_name, arguments=arguments,
                          result=res_dict, duration=duration,
                          status="success" if success else "error")
        )
        self.state.tool_counts["total"] += 1
        self.state.tool_counts["subagents"] = self.state.tool_counts.get(
            "subagents", 0) + 1
        return success, duration, res_dict, None

    def _build_fuzz_headers(self) -> dict[str, str] | None:
        """Build auth headers dict from session cookies/headers for fuzzer auth context."""
        headers: dict[str, str] = {}
        session = getattr(self, "_session", None)
        if session is None:
            return None
        auth_cookies: list[dict[str, Any]] = getattr(session, "auth_cookies", []) or []
        if auth_cookies:
            cookie_str = "; ".join(
                f"{c.get('name', '')}={c.get('value', '')}"
                for c in auth_cookies if c.get("name")
            )
            if cookie_str:
                headers["Cookie"] = cookie_str
        auth_hdrs: dict[str, str] = getattr(session, "auth_headers", {}) or {}
        headers.update(auth_hdrs)
        return headers or None

    def _normalize_args_for_dedup(
            self, tool_name: str, arguments: dict[str, Any]) -> tuple[str, str]:
        """Normalize arguments to prevent bypass of duplicate execution checks."""
        args_copy = dict(arguments)
        if tool_name == "execute" and "command" in args_copy:
            cmd = args_copy["command"]
            # Strip common variations that don't change the core command
            # Remove output file directives (-o, --output, > file)
            cmd = re.sub(r'(\s+-(oA|oN|oX|oG|oJ|o)\s+[^\s]+)', '', cmd)
            cmd = re.sub(r'(\s+--output\s*=?\s*[^\s]+)', '', cmd)
            cmd = re.sub(r'(\s*>\s*[^\s]+(\s+2>&1)?)', '', cmd)
            # Remove cookie files since they are standard
            cmd = re.sub(r'(\s+-[bc]\s+output/cookies\.txt)', '', cmd)
            cmd = re.sub(r'(\s+--cookie(?:-jar)?\s+[^\s]+)', '', cmd)
            # Remove timestamp patterns commonly used in typical output files
            cmd = re.sub(r'_[0-9]{8}_[0-9]{6}\.', '.', cmd)
            args_copy["command"] = cmd.strip()

        return tool_name, json.dumps(args_copy, sort_keys=True, default=str)

    async def _execute_tool_and_record(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        on_output: Callable[[str], None] | None = None,
    ) -> tuple[bool, float, dict[str, Any], str | None]:
        self._last_output_file = None

        args_key = self._normalize_args_for_dedup(tool_name, arguments)
        count = self._executed_tool_counts.get(
            args_key, 0)
        limit = get_config().agent_repeat_tool_call_limit

        if self._is_recon_phase_repeat_blocked(tool_name, arguments, count):
            binary = self._extract_command_binary(arguments.get("command", ""))
            return False, 0.0, {
                "success": False,
                "error": (
                    f"Duplicate recon execution blocked for '{binary}'. "
                    "Use previous results and pivot to a new recon vector."
                ),
            }, None

        if count >= limit:
            return False, 0.0, {
                "success": False, "error": f"Duplicate tool execution prevented (already ran {count}x)."}, None

        if tool_name == "advanced_fuzz":
            return await self._execute_advanced_fuzz_tool(tool_name, arguments)

        if tool_name == "quick_fuzz":
            return await self._execute_quick_fuzz_tool(tool_name, arguments)

        if tool_name == "deep_fuzz":
            return await self._execute_deep_fuzz_tool(tool_name, arguments)

        if tool_name == "generate_wordlist":
            return await self._execute_generate_wordlist_tool(tool_name, arguments)

        if tool_name == "run_parallel_agents":
            return await self._execute_run_parallel_agents_tool(tool_name, arguments)

        if tool_name == "caido_list_requests":
            return await self._execute_caido_list_requests_tool(tool_name, arguments)

        if tool_name == "caido_send_request":
            return await self._execute_caido_send_request_tool(tool_name, arguments)

        if tool_name == "caido_automate":
            return await self._execute_caido_automate_tool(tool_name, arguments)

        if tool_name == "caido_get_findings":
            return await self._execute_caido_get_findings_tool(tool_name, arguments)

        if tool_name == "caido_set_scope":
            return await self._execute_caido_set_scope_tool(tool_name, arguments)

        if tool_name == "caido_intercept":
            return await self._execute_caido_intercept_tool(tool_name, arguments)

        if tool_name == "caido_sitemap":
            return await self._execute_caido_sitemap_tool(tool_name, arguments)

        if tool_name == "spawn_agent":
            return await self._execute_spawn_agent_tool(tool_name, arguments)

        if tool_name == "code_analysis":
            return await self._execute_code_analysis_tool(tool_name, arguments)

        if tool_name == "schemathesis_fuzz":
            return await self._execute_schemathesis_tool(tool_name, arguments)

        if tool_name == "execute":
            cmd = arguments.get("command", "")
            if not cmd or not cmd.strip():
                return False, 0.0, {
                    "success": False,
                    "error": (
                        "Tool call error: 'command' argument is required and cannot be empty. "
                        "Example: {\"name\": \"execute\", \"arguments\": {\"command\": \"ls -la /workspace\"}}"
                    ),
                }, None
            if len(cmd) > _MAX_COMMAND_LENGTH:
                return False, 0.0, {
                    "success": False,
                    "error": (
                        f"Command rejected: length {len(cmd)} exceeds "
                        f"maximum {_MAX_COMMAND_LENGTH} characters."
                    ),
                }, None
            # Detect common tool-mixing hallucinations before executing.
            # Example: LLM writes "curl -sc -title -tech-detect ..." (httpx flags on curl).
            # Catch and reject with a correction hint instead of running a broken command.
            cmd_stripped = cmd.strip()
            _first_token = cmd_stripped.split()[0] if cmd_stripped.split() else ""
            if _first_token in _TOOL_FLAG_CONFLICTS:
                _conflict_flags, _correct_tool = _TOOL_FLAG_CONFLICTS[_first_token]
                # Use token-based matching (not substring) to avoid false positives
                # from URLs or data values that happen to contain flag-like strings.
                # e.g. `curl "https://api.example.com?status-code=200"` must NOT trigger.
                try:
                    _cmd_tokens = set(shlex.split(cmd_stripped))
                except ValueError:
                    _cmd_tokens = set(cmd_stripped.split())
                _found = [f for f in _conflict_flags if f in _cmd_tokens]
                if _found:
                    return False, 0.0, {
                        "success": False,
                        "error": (
                            f"Command rejected: '{_first_token}' was used with flags that "
                            f"belong to '{_correct_tool}': {_found}. "
                            f"Replace '{_first_token}' with '{_correct_tool}' and retry. "
                            f"Example: {cmd_stripped.replace(_first_token, _correct_tool, 1)}"
                        ),
                    }, None
            if self.state.active_target and cmd and not cmd.strip(
            ).startswith("cd "):
                workspace_dir = f"/workspace/{self.state.active_target}"
                host_workspace = get_workspace_root() / self.state.active_target
                try:
                    host_workspace.mkdir(parents=True, exist_ok=True)
                except Exception as _e:
                    logger.debug("Could not create workspace dir: %s", _e)
                for subdir in ["output", "command",
                               "tools", "vulnerabilities"]:
                    try:
                        (host_workspace / subdir).mkdir(parents=True, exist_ok=True)
                    except Exception as _e:
                        logger.debug("Could not create subdir %s: %s", subdir, _e)
                # Do NOT strip workspace paths from the command — absolute paths
                # inside the container are valid and stripping them breaks
                # multi-path commands.
                arguments["command"] = f"cd {workspace_dir} && {cmd}"
                logger.info("Enforced workspace context: %s", arguments["command"])

        start_time = time.time()
        output_file: str | None = None
        try:
            result = await self.engine.execute_tool(tool_name, arguments)
            success = result.get("success", False)
            try:
                # Capture returned path as local variable to avoid race
                # condition when multiple tools run concurrently via gather().
                output_file = self._save_tool_output(tool_name, arguments, result)
            except Exception as _e:
                logger.debug("Could not save tool output: %s", _e)
        except Exception as e:
            success = False
            result = {"success": False, "error": str(e)}
            logger.error("Tool exec error: %s", e)

        # Inject a helpful hint for common bash escaping errors (single quotes
        # inside single quotes)
        if not success:
            err_msg = str(result.get("error") or result.get("stderr") or "")
            if "unexpected EOF while looking for matching `''" in err_msg:
                hint = (
                    "\n\n[SYSTEM HINT]: Bash syntax error! You cannot escape a single quote inside a single-quoted string "
                    "(e.g., 'don\\'t' is invalid). To use a single quote inside a single-quoted string, close the quote, "
                    "insert an escaped quote, and reopen it: 'don'\\''t'. Alternatively, wrap your entire command/regex in double "
                    "quotes if it contains single quotes."
                )
                if "error" in result and result["error"]:
                    result["error"] = str(result["error"]) + hint
                if "stderr" in result and result["stderr"]:
                    result["stderr"] = str(result["stderr"]) + hint

            # Inject hint for type errors — LLM passed wrong argument type
            elif "int() argument" in err_msg or "invalid literal for int" in err_msg:
                result["error"] = (
                    err_msg
                    + "\n[SYSTEM HINT]: A numeric argument was given a non-numeric value. "
                    "Check that integer fields (e.g. port, limit, count) are actual numbers, not strings."
                )
            # Hint for missing required keys
            elif "required" in err_msg.lower() and "argument" in err_msg.lower():
                result["error"] = (
                    err_msg
                    + f"\n[SYSTEM HINT]: The tool '{tool_name}' is missing a required argument. "
                    "Re-read the tool definition and include all required fields."
                )
            # Hint for NoneType / attribute errors — usually wrong arg type or missing value
            elif "NoneType" in err_msg or "'NoneType' object has no attribute" in err_msg:
                result["error"] = (
                    err_msg
                    + f"\n[SYSTEM HINT]: A None value was passed where a string/dict was expected for tool '{tool_name}'. "
                    "Check that all arguments are non-null and the correct type."
                )

        duration = time.time() - start_time

        history_result = result
        if success and output_file and len(str(result)) > _RESULT_TRUNCATION_THRESHOLD:
            history_result = {
                "success": True,
                "result": f"<Result truncated. Full output in {output_file}>",
                "truncated": True,
            }

        self.state.tool_history.append(
            ToolExecution(
                tool_name=tool_name, arguments=arguments,
                result=history_result, duration=duration,
                status="success" if success else "error",
            )
        )
        self.state.tool_counts["exec"] += 1
        self.state.tool_counts["total"] += 1

        if success:
            self._executed_tool_counts[args_key] = self._executed_tool_counts.get(
                args_key, 0) + 1
        return success, duration, result, output_file

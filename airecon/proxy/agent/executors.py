from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import time
from datetime import datetime
from typing import Any, Callable
from urllib.parse import urlparse

from ..browser import browser_action
from ..config import get_config, get_workspace_root
from ..filesystem import create_file, list_files, read_file
from ..reporting import create_vulnerability_report
from ..web_search import web_search
from .models import ToolExecution
from .session import _is_duplicate_vulnerability

logger = logging.getLogger("airecon.agent")


class _ExecutorMixin:

    async def _execute_local_browser_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> tuple[bool, float, dict[str, Any], str | None]:
        self._last_output_file = None  # type: ignore[attr-defined]

        args_key = self._normalize_args_for_dedup(tool_name, arguments)
        allow_repeat = arguments.get("action") in [
            "wait", "scroll_down", "scroll_up", "get_console_logs", "get_network_logs", "execute_js",
            "goto", "click", "type", "press"
        ]

        if not allow_repeat:
            count = self._executed_tool_counts.get(
                args_key, 0)  # type: ignore[attr-defined]
            limit = get_config().agent_repeat_tool_call_limit
            if count >= limit:
                return False, 0.0, {
                    "success": False,
                    "error": f"Duplicate tool execution prevented (already ran {count}x)."
                }, None

        start_time = time.time()
        try:
            try:
                result = await asyncio.wait_for(
                    asyncio.to_thread(browser_action, **arguments),
                    timeout=120.0,
                )
            except asyncio.TimeoutError:
                return False, 120.0, {
                    "success": False,
                    "error": "Browser action timed out after 120s. The page may be hanging.",
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
                        logger.warning(
                            f"Failed to auto-inject session cookies: {e}")

            success = not (isinstance(result, dict) and "error" in result)
            if not success and isinstance(result, dict) and "error" in result:
                result = {"success": False, "error": result["error"]}
            elif "success" not in result:
                result = {"success": success, "result": result}

            # Auto-save view_source / get_console_logs / get_network_logs to
            # workspace
            # type: ignore[attr-defined]
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
                            # type: ignore[attr-defined]
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
                                f.write(
                                    f"URL: {page_url}\n{
                                        '=' * 60}\n{source_full}")
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
                                        f"\n{
                                            '=' *
                                            60}\nSOURCE: {page_url}\n{
                                            '=' *
                                            60}\n")
                                    for js_url in all_js:
                                        f.write(js_url + "\n")
                                js_note = f" {
                                    len(all_js)} JS files extracted to output/js_files.txt."
                            inner = dict(inner)
                            # strip from LLM context
                            inner.pop("full_page_source", None)
                            inner["auto_saved"] = saved_path
                            inner["note"] = (
                                f"[Auto-saved full page source ({
                                    len(source_full)} chars) to {saved_path}.{js_note}"
                                " Analyze JS files for API endpoints, secrets, and vulnerabilities.]"
                            )
                            result = {"success": True, "result": inner}
                            # type: ignore[attr-defined]
                            self._last_output_file = saved_path

                        elif action == "get_console_logs":
                            logs = inner.get("console_logs", [])
                            console_file = host_output / \
                                f"console_{domain}.txt"
                            with open(console_file, "w", encoding="utf-8") as f:
                                f.write(
                                    f"URL: {page_url}\nLogs captured: {
                                        len(logs)}\n{
                                        '=' * 60}\n")
                                for log in logs:
                                    f.write(
                                        f"[{log.get('type', 'log')}] {log.get('text', '')}\n")
                            saved_path = f"output/console_{domain}.txt"
                            inner = dict(inner)
                            inner["auto_saved"] = saved_path
                            inner["note"] = (
                                f"[Auto-saved {
                                    len(logs)} console logs to {saved_path}."
                                " Check for errors, debug info, and leaked sensitive data.]"
                            )
                            result = {"success": True, "result": inner}
                            # type: ignore[attr-defined]
                            self._last_output_file = saved_path

                        elif action == "get_network_logs":
                            reqs = inner.get("network_requests", [])
                            net_file = host_output / f"network_{domain}.txt"
                            with open(net_file, "w", encoding="utf-8") as f:
                                f.write(
                                    f"URL: {page_url}\nTotal entries: {
                                        len(reqs)}\n{
                                        '=' * 60}\n\n")
                                for entry in reqs:
                                    etype = entry.get("type", "?")
                                    url = entry.get("url", "")
                                    if etype == "request":
                                        f.write(
                                            f">> {
                                                entry.get(
                                                    'method',
                                                    'GET')} [{
                                                entry.get(
                                                    'resource_type',
                                                    '')}] {url}\n")
                                        if entry.get("post_data"):
                                            f.write(
                                                f"   BODY: {
                                                    entry['post_data']}\n")
                                    elif etype == "response":
                                        f.write(
                                            f"<< {
                                                entry.get(
                                                    'status',
                                                    '')} {url}  [{
                                                entry.get(
                                                    'content_type',
                                                    '')}]\n")
                                        if entry.get("body"):
                                            f.write(
                                                f"   RESPONSE: {
                                                    entry['body']}\n")
                                    f.write("\n")
                            saved_path = f"output/network_{domain}.txt"
                            summary = inner.get("network_summary", {})
                            api_calls = summary.get("api_calls", [])
                            inner = dict(inner)
                            # strip raw list from LLM context
                            inner.pop("network_requests", None)
                            inner["auto_saved"] = saved_path
                            inner["note"] = (
                                f"[Auto-saved {
                                    len(reqs)} network entries to {saved_path}."
                                f" {len(api_calls)} XHR/Fetch API calls detected."
                                " Review for API endpoints, auth tokens, and sensitive data in responses.]"
                            )
                            result = {"success": True, "result": inner}
                            # type: ignore[attr-defined]
                            self._last_output_file = saved_path

                    except Exception as _e:
                        logger.warning(
                            f"Failed to auto-save browser result: {_e}")

            try:
                # type: ignore[attr-defined]
                self._save_tool_output(tool_name, arguments, result)
            except Exception as _e:
                logger.debug("Could not save tool output: %s", _e)
        except Exception as e:
            success = False
            result = {"success": False, "error": str(e)}
            logger.error(f"Browser tool exec error: {e}")

        duration = time.time() - start_time

        history_result = result
        if success and self._last_output_file and len(
                str(result)) > 10000:  # type: ignore[attr-defined]
            history_result = {
                "success": True,
                # type: ignore[attr-defined]
                "result": f"<Result truncated. Full output in {self._last_output_file}>",
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
            self._executed_tool_counts[args_key] = self._executed_tool_counts.get(
                args_key, 0) + 1  # type: ignore[attr-defined]

        # type: ignore[attr-defined]
        return success, duration, result, self._last_output_file

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
                if not path_arg.startswith(self.state.active_target) and not os.path.isabs(
                        path_arg):  # type: ignore[attr-defined]
                    path_arg = os.path.join(
                        self.state.active_target,
                        path_arg)  # type: ignore[attr-defined]

            # Path traversal protection: resolve and verify path is within workspace
            workspace_root = get_workspace_root()
            resolved = (workspace_root / path_arg).resolve()
            if not str(resolved).startswith(str(workspace_root.resolve())):
                return False, 0.0, {
                    "success": False,
                    "error": f"Path traversal attempt blocked: '{path_arg}' resolves outside workspace.",
                }, None

            arguments["path"] = path_arg

            if tool_name == "create_file":
                result = await asyncio.to_thread(create_file, **arguments)
            elif tool_name == "read_file":
                path_arg_clean = arguments.get("path", "")
                if "skills/" in path_arg_clean and path_arg_clean.endswith(".md"):
                    skill_name = os.path.basename(
                        path_arg_clean).replace(".md", "")
                    # type: ignore[attr-defined]
                    if skill_name not in self.state.skills_used:
                        # type: ignore[attr-defined]
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
                # type: ignore[attr-defined]
                self._save_tool_output(tool_name, arguments, result)
            except Exception as _e:
                logger.debug("Could not save tool output: %s", _e)
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

        # type: ignore[attr-defined]
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
            logger.error(f"Web search tool error: {e}")

        duration = time.time() - start_time

        # Auto-save results to output/dork_results.txt so Phase 1 evidence
        # is persisted even if the model forgets to call create_file.
        saved_path: str | None = None
        if success and self.state.active_target:  # type: ignore[attr-defined]
            try:
                host_output = (
                    get_workspace_root()
                    / self.state.active_target  # type: ignore[attr-defined]
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
                logger.warning(f"Failed to auto-save dork results: {e}")

        self.state.tool_history.append(  # type: ignore[attr-defined]
            ToolExecution(
                tool_name="web_search", arguments=arguments,
                result=result, duration=duration,
                status="success" if success else "error",
            )
        )
        self.state.tool_counts["exec"] += 1  # type: ignore[attr-defined]
        self.state.tool_counts["total"] += 1  # type: ignore[attr-defined]
        return success, duration, result, saved_path

    async def _execute_report_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> tuple[bool, float, dict[str, Any], str | None]:
        self._last_output_file = None  # type: ignore[attr-defined]
        start_time = time.time()

        try:
            result = await asyncio.to_thread(
                create_vulnerability_report,
                **arguments,
                # type: ignore[attr-defined]
                _active_target=self.state.active_target,
            )
            success = result.get("success", False)
            try:
                # type: ignore[attr-defined]
                self._save_tool_output(tool_name, arguments, result)
            except Exception as _e:
                logger.debug("Could not save tool output: %s", _e)

            # Mark matching vulnerability as reported so REPORT phase can
            # transition
            if success and self._session:  # type: ignore[attr-defined]
                report_title = arguments.get("title", "")
                flag = arguments.get("flag", "")
                matched = False
                # type: ignore[attr-defined]
                for vuln in self._session.vulnerabilities:
                    v_title = vuln.get("title", vuln.get("finding", ""))
                    if report_title and v_title and v_title.lower() in report_title.lower():
                        vuln["report_generated"] = True
                        if flag:
                            vuln["flag"] = flag
                        matched = True
                if not matched and report_title:
                    self._session.vulnerabilities.append({  # type: ignore[attr-defined]
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

        # type: ignore[attr-defined]
        return success, duration, result, self._last_output_file

    async def _execute_advanced_fuzz_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> tuple[bool, float, dict[str, Any], str | None]:
        from ..fuzzer import Fuzzer
        self._last_output_file = None  # type: ignore[attr-defined]
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
            fuzzer = Fuzzer(target=target, method=method)
            results = await fuzzer.fuzz_parameters(params, vuln_types)

            if not results:
                res_dict = {
                    "success": True,
                    "result": "No vulnerabilities found with confidence > 0.60."}
            else:
                findings_list = []
                for r in results:
                    findings_list.append(
                        f"Param: {
                            r.parameter} | Vuln: {
                            r.vuln_type} | Severity: {
                            r.severity} | Conf: {
                            r.confidence:.2f} | Evidence: {
                            r.evidence}")
                res_dict = {"success": True, "findings": findings_list}

            try:
                # type: ignore[attr-defined]
                self._save_tool_output(tool_name, arguments, res_dict)
            except Exception as _e:
                logger.debug("Could not save tool output: %s", _e)
            success = True
        except Exception as e:
            logger.error(f"Fuzzer error: {e}")
            res_dict = {"success": False, "error": str(e)}
            success = False

        duration = time.time() - start_time

        self.state.tool_history.append(  # type: ignore[attr-defined]
            ToolExecution(
                tool_name=tool_name, arguments=arguments,
                result=res_dict, duration=duration,
                status="success" if success else "error",
            )
        )
        self.state.tool_counts["total"] += 1  # type: ignore[attr-defined]

        return success, duration, res_dict, None

    async def _execute_quick_fuzz_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> tuple[bool, float, dict[str, Any], str | None]:
        from ..fuzzer import quick_fuzz_url
        self._last_output_file = None  # type: ignore[attr-defined]
        start_time = time.time()

        target = arguments.get("target", "")
        params = arguments.get("params") or None

        try:
            results = await quick_fuzz_url(url=target, params=params)

            if not results:
                res_dict = {
                    "success": True,
                    "result": "No vulnerabilities found with confidence > 0.60."}
            else:
                findings_list = [
                    f"Param: {
                        r.parameter} | Vuln: {
                        r.vuln_type} | Severity: {
                        r.severity} | Conf: {
                        r.confidence:.2f} | Evidence: {
                        r.evidence}"
                    for r in results
                ]
                res_dict = {
                    "success": True,
                    "findings": findings_list,
                    "total": len(findings_list)}

            try:
                # type: ignore[attr-defined]
                self._save_tool_output(tool_name, arguments, res_dict)
            except Exception as _e:
                logger.debug("Could not save tool output: %s", _e)
            success = True
        except Exception as e:
            logger.error(f"quick_fuzz error: {e}")
            res_dict = {"success": False, "error": str(e)}
            success = False

        duration = time.time() - start_time
        self.state.tool_history.append(  # type: ignore[attr-defined]
            ToolExecution(
                tool_name=tool_name, arguments=arguments,
                result=res_dict, duration=duration,
                status="success" if success else "error",
            )
        )
        self.state.tool_counts["total"] += 1  # type: ignore[attr-defined]
        return success, duration, res_dict, None

    async def _execute_deep_fuzz_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> tuple[bool, float, dict[str, Any], str | None]:
        self._last_output_file = None  # type: ignore[attr-defined]
        start_time = time.time()

        target = arguments.get("target", "")
        params = arguments.get("params") or None
        vuln_types = arguments.get("vuln_types") or None

        try:
            from ..fuzzer import InteractiveRealTimeTester
            tester = InteractiveRealTimeTester(target, threads=10, timeout=20)
            async for event in tester.stream_fuzz(params=params, vuln_types=vuln_types):
                pass
            summary = tester.get_summary()

            findings_list = []
            for f in getattr(tester, "_findings", []):
                findings_list.append(
                    f"Param: {
                        f.parameter} | Vuln: {
                        f.vuln_type} | Severity: {
                        f.severity} | Conf: {
                        f.confidence:.2f} | Evidence: {
                        f.evidence}"
                )

            res_dict = {
                "success": True,
                "summary": summary,
                "findings": findings_list,
            }

            try:
                # type: ignore[attr-defined]
                self._save_tool_output(tool_name, arguments, res_dict)
            except Exception as _e:
                logger.debug("Could not save tool output: %s", _e)
            success = True
        except Exception as e:
            logger.error(f"deep_fuzz error: {e}")
            res_dict = {"success": False, "error": str(e)}
            success = False

        duration = time.time() - start_time
        self.state.tool_history.append(  # type: ignore[attr-defined]
            ToolExecution(
                tool_name=tool_name, arguments=arguments,
                result=res_dict, duration=duration,
                status="success" if success else "error",
            )
        )
        self.state.tool_counts["total"] += 1  # type: ignore[attr-defined]
        return success, duration, res_dict, None

    async def _execute_generate_wordlist_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> tuple[bool, float, dict[str, Any], str | None]:
        from ..fuzzer import generate_fuzz_wordlist
        self._last_output_file = None  # type: ignore[attr-defined]
        start_time = time.time()

        output_file = arguments.get("output_file", "wordlist.txt")
        max_combinations = min(
            int(arguments.get("max_combinations", 300)), 1000)
        vuln_types = arguments.get("vuln_types") or None

        try:
            wordlist = generate_fuzz_wordlist(
                max_combinations=max_combinations,
                vuln_types=vuln_types,
            )

            # Save to workspace output/
            # type: ignore[attr-defined]
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
            self._last_output_file = saved_path  # type: ignore[attr-defined]

            try:
                # type: ignore[attr-defined]
                self._save_tool_output(tool_name, arguments, res_dict)
            except Exception as _e:
                logger.debug("Could not save tool output: %s", _e)
            success = True
        except Exception as e:
            logger.error(f"generate_wordlist error: {e}")
            res_dict = {"success": False, "error": str(e)}
            success = False

        duration = time.time() - start_time
        self.state.tool_history.append(  # type: ignore[attr-defined]
            ToolExecution(
                tool_name=tool_name, arguments=arguments,
                result=res_dict, duration=duration,
                status="success" if success else "error",
            )
        )
        self.state.tool_counts["total"] += 1  # type: ignore[attr-defined]
        # type: ignore[attr-defined]
        return success, duration, res_dict, self._last_output_file

    async def _execute_run_parallel_agents_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> tuple[bool, float, dict[str, Any], str | None]:
        from ..subagent import ParallelAgentRunner
        self._last_output_file = None  # type: ignore[attr-defined]
        start_time = time.time()

        targets = arguments.get("targets", [])
        prompt = arguments.get("prompt", "")

        try:
            runner = ParallelAgentRunner(
                engine=self.engine)  # type: ignore[attr-defined]
            results = await runner.run_parallel(targets, prompt)

            # Summarize the vulnerabilities found per target
            res_dict = {
                "success": True,
                "results": {
                    t: len(
                        s.vulnerabilities) for t,
                    s in results.items()}}

            try:
                # type: ignore[attr-defined]
                self._save_tool_output(tool_name, arguments, res_dict)
            except Exception as _e:
                logger.debug("Could not save tool output: %s", _e)
            success = True
        except Exception as e:
            logger.error(f"Subagent runner error: {e}")
            res_dict = {"success": False, "error": str(e)}
            success = False

        duration = time.time() - start_time

        self.state.tool_history.append(  # type: ignore[attr-defined]
            ToolExecution(
                tool_name=tool_name, arguments=arguments,
                result=res_dict, duration=duration,
                status="success" if success else "error",
            )
        )
        self.state.tool_counts["total"] += 1  # type: ignore[attr-defined]

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
        self._last_output_file = None  # type: ignore[attr-defined]
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
            logger.error(f"caido_list_requests error: {e}")
            res_dict = {"success": False, "error": str(e)}
            success = False

        duration = time.time() - start_time
        self.state.tool_history.append(  # type: ignore[attr-defined]
            ToolExecution(tool_name=tool_name, arguments=arguments,
                          result=res_dict, duration=duration,
                          status="success" if success else "error")
        )
        self.state.tool_counts["total"] += 1  # type: ignore[attr-defined]
        return success, duration, res_dict, None

    async def _execute_caido_send_request_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> tuple[bool, float, dict[str, Any], str | None]:
        from ..caido_client import CaidoClient
        self._last_output_file = None  # type: ignore[attr-defined]
        start_time = time.time()

        request_id = arguments.get("request_id", "")
        raw_http = arguments.get("raw_http", "")
        host = arguments.get("host", "")
        port = int(arguments.get("port", 443))
        is_tls = bool(arguments.get("is_tls", True))

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
            logger.error(f"caido_send_request error: {e}")
            res_dict = {"success": False, "error": str(e)}
            success = False

        duration = time.time() - start_time
        self.state.tool_history.append(  # type: ignore[attr-defined]
            ToolExecution(tool_name=tool_name, arguments=arguments,
                          result=res_dict, duration=duration,
                          status="success" if success else "error")
        )
        self.state.tool_counts["total"] += 1  # type: ignore[attr-defined]
        return success, duration, res_dict, None

    async def _execute_caido_automate_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> tuple[bool, float, dict[str, Any], str | None]:
        from ..caido_client import CaidoClient
        self._last_output_file = None  # type: ignore[attr-defined]
        start_time = time.time()

        raw_http = arguments.get("raw_http", "")
        host = arguments.get("host", "")
        port = int(arguments.get("port", 443))
        is_tls = bool(arguments.get("is_tls", True))
        payloads = arguments.get("payloads", [])
        workers = min(int(arguments.get("workers", 10)), 50)

        # Calculate §FUZZ§ placeholders BEFORE stripping markers.
        # find_fuzz_offsets() works on the original string and returns positions
        # in the clean (marker-stripped) bytes — so order matters.
        placeholders = CaidoClient.find_fuzz_offsets(raw_http)
        clean_http = raw_http.replace("§FUZZ§", "")
        encoded_raw = CaidoClient.encode_raw_http(clean_http)

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
            res_dict = {
                "success": False,
                "error": "Caido did not respond within 90 seconds"}
            success = False
        except Exception as e:
            logger.error(f"caido_automate error: {e}")
            res_dict = {"success": False, "error": str(e)}
            success = False

        duration = time.time() - start_time
        self.state.tool_history.append(  # type: ignore[attr-defined]
            ToolExecution(tool_name=tool_name, arguments=arguments,
                          result=res_dict, duration=duration,
                          status="success" if success else "error")
        )
        self.state.tool_counts["total"] += 1  # type: ignore[attr-defined]
        return success, duration, res_dict, None

    async def _execute_caido_get_findings_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> tuple[bool, float, dict[str, Any], str | None]:
        from ..caido_client import CaidoClient
        self._last_output_file = None  # type: ignore[attr-defined]
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
            logger.error(f"caido_get_findings error: {e}")
            res_dict = {"success": False, "error": str(e)}
            success = False

        duration = time.time() - start_time
        self.state.tool_history.append(  # type: ignore[attr-defined]
            ToolExecution(tool_name=tool_name, arguments=arguments,
                          result=res_dict, duration=duration,
                          status="success" if success else "error")
        )
        self.state.tool_counts["total"] += 1  # type: ignore[attr-defined]
        return success, duration, res_dict, None

    async def _execute_caido_set_scope_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> tuple[bool, float, dict[str, Any], str | None]:
        from ..caido_client import CaidoClient
        self._last_output_file = None  # type: ignore[attr-defined]
        start_time = time.time()

        allowlist = arguments.get("allowlist", [])
        denylist = arguments.get("denylist", [])

        query = """
        mutation CreateScope($input: CreateScopeInput!) {
            createScope(input: $input) {
                scope { id name }
            }
        }
        """
        scope_name = f"airecon-{
            self.state.active_target or 'scope'}"  # type: ignore[attr-defined]
        variables = {
            "input": {
                "name": scope_name,
                "allowlist": allowlist,
                "denylist": denylist}}

        try:
            data = await CaidoClient.gql(query, variables)
            if "errors" in data:
                res_dict = {
                    "success": False,
                    "error": data["errors"][0]["message"]}
                success = False
            else:
                scope = data.get(
                    "data",
                    {}).get(
                    "createScope",
                    {}).get(
                    "scope",
                    {})
                res_dict = {"success": True, "scope_id": scope.get("id"),
                            "scope_name": scope.get("name"),
                            "allowlist": allowlist, "denylist": denylist}
                success = True
        except Exception as e:
            logger.error(f"caido_set_scope error: {e}")
            res_dict = {"success": False, "error": str(e)}
            success = False

        duration = time.time() - start_time
        self.state.tool_history.append(  # type: ignore[attr-defined]
            ToolExecution(tool_name=tool_name, arguments=arguments,
                          result=res_dict, duration=duration,
                          status="success" if success else "error")
        )
        self.state.tool_counts["total"] += 1  # type: ignore[attr-defined]
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
        self._last_output_file = None  # type: ignore[attr-defined]
        start_time = time.time()

        target_path = arguments.get("target_path", ".")
        rules = arguments.get("rules") or None
        languages = arguments.get("languages") or None

        # Resolve path relative to target workspace
        # type: ignore[attr-defined]
        active_target = self.state.active_target or "unknown"
        if not target_path.startswith("/"):
            target_path = f"/workspace/{active_target}/{target_path}"

        try:
            result = await run_code_analysis(
                engine=self.engine,  # type: ignore[attr-defined]
                target_path=target_path,
                rules=rules,
                languages=languages,
            )

            res_dict = {
                "success": True,
                "summary": result.get("summary", ""),
                "total": result.get("total", 0),
                # Cap at 50 findings
                "findings": result.get("findings", [])[:50],
                "errors": result.get("errors", []),
            }

            # Save output
            try:
                # type: ignore[attr-defined]
                self._save_tool_output(tool_name, arguments, res_dict)
            except Exception as _e:
                logger.debug("Could not save tool output: %s", _e)
            success = True
        except Exception as e:
            logger.error(f"code_analysis error: {e}")
            res_dict = {"success": False, "error": str(e)}
            success = False

        duration = time.time() - start_time
        self.state.tool_history.append(  # type: ignore[attr-defined]
            ToolExecution(
                tool_name=tool_name, arguments=arguments,
                result=res_dict, duration=duration,
                status="success" if success else "error",
            )
        )
        self.state.tool_counts["total"] += 1  # type: ignore[attr-defined]
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
        self._last_output_file = None  # type: ignore[attr-defined]
        start_time = time.time()

        schema_url = arguments.get("schema_url", "").strip()
        base_url = arguments.get("base_url", "").strip()
        auth_header = arguments.get("auth_header", "").strip()
        checks = arguments.get("checks") or []
        max_examples = int(arguments.get("max_examples") or 30)

        if not schema_url:
            return False, 0.0, {"success": False,
                                "error": "'schema_url' is required."}, None

        # Build schemathesis CLI command
        cmd_parts = [
            "python3 -m schemathesis run",
            f'"{schema_url}"',
        ]
        if base_url:
            cmd_parts.append(f'--base-url "{base_url}"')
        if auth_header:
            import shlex
            cmd_parts.append(
                f"--header {shlex.quote(f'Authorization: {auth_header}')}")
        if checks:
            cmd_parts.append(f'--checks {",".join(checks)}')
        cmd_parts.append(f"--hypothesis-max-examples {max_examples}")
        cmd_parts.append("--request-timeout 15")
        cmd_parts.append("--output-truncate false")
        cmd_parts.append("--code-sample-style python")

        # type: ignore[attr-defined]
        active_target = self.state.active_target or "unknown"
        workspace_dir = f"/workspace/{active_target}"
        output_file = f"{workspace_dir}/output/schemathesis_results.txt"
        full_cmd = f"cd {workspace_dir} && pip install -q schemathesis 2>/dev/null; {
            ' '.join(cmd_parts)} 2>&1 | tee {output_file}"

        try:
            exec_result = await self.engine.execute_tool(  # type: ignore[attr-defined]
                "execute",
                {"command": full_cmd, "timeout": 300},
            )
            stdout = exec_result.get(
                "stdout", "") or exec_result.get(
                "result", "") or ""
            success = bool(stdout) and "Error" not in stdout[:200]

            # Parse summary line counts
            violations = stdout.count("FAILED") + \
                stdout.count("not_a_server_error")
            passed = stdout.count("PASSED")

            res_dict = {
                "success": True,
                "summary": f"Schemathesis completed: {passed} passed, {violations} potential violations.",
                "violations": violations,
                "output_file": output_file,
                "raw_output": stdout[:3000],
            }
            try:
                # type: ignore[attr-defined]
                self._save_tool_output(tool_name, arguments, res_dict)
            except Exception as _e:
                logger.debug("Could not save tool output: %s", _e)
        except Exception as e:
            logger.error(f"schemathesis_fuzz error: {e}")
            res_dict = {"success": False, "error": str(e)}
            success = False

        duration = time.time() - start_time
        self.state.tool_history.append(  # type: ignore[attr-defined]
            ToolExecution(
                tool_name=tool_name, arguments=arguments,
                result=res_dict, duration=duration,
                status="success" if success else "error",
            )
        )
        self.state.tool_counts["total"] += 1  # type: ignore[attr-defined]
        # type: ignore[attr-defined]
        return success, duration, res_dict, self._last_output_file

    # ------------------------------------------------------------------
    # Dynamic Subagent Spawn
    # ------------------------------------------------------------------

    async def _execute_spawn_agent_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> tuple[bool, float, dict[str, Any], str | None]:
        self._last_output_file = None  # type: ignore[attr-defined]
        start_time = time.time()

        task = arguments.get("task", "")
        # type: ignore[attr-defined]
        target = arguments.get("target", self.state.active_target or "")
        # Validate and sanitize specialist — only allow known role names
        _RAW_SPECIALIST = str(arguments.get("specialist", "exploit"))
        _VALID_SPECIALISTS = {
            "sqli", "xss", "ssrf", "lfi", "recon", "exploit", "analyzer", "reporter"
        }
        specialist = _RAW_SPECIALIST.lower().strip() if _RAW_SPECIALIST.lower(
        ).strip() in _VALID_SPECIALISTS else "exploit"

        _SPECIALIST_PREFIXES: dict[str, str] = {
            "sqli": (
                "Focus EXCLUSIVELY on SQL injection. Test all input parameters for "
                "error-based, blind time-based, and UNION-based SQLi. "
                "Use manual payloads first, then sqlmap to confirm."
            ),
            "xss": (
                "Focus EXCLUSIVELY on Cross-Site Scripting (XSS). Test all input "
                "reflection points for stored, reflected, and DOM-based XSS. "
                "Use dalfox for automated scanning after manual confirmation."
            ),
            "ssrf": (
                "Focus EXCLUSIVELY on SSRF. Test all URL/redirect/callback parameters. "
                "Try AWS metadata (169.254.169.254), internal hosts (127.0.0.1, localhost), "
                "and protocol wrappers (file://, gopher://, dict://)."
            ),
            "lfi": (
                "Focus EXCLUSIVELY on LFI and Path Traversal. Test all file/path/include "
                "parameters with traversal sequences (../), null bytes, and encoding variants."
            ),
            "recon": (
                "Perform deep reconnaissance ONLY. Enumerate subdomains, open ports, "
                "directories, and JavaScript files. Map all endpoints and parameters. "
                "Do NOT attempt exploitation."
            ),
            "exploit": (
                "Test and exploit all discovered input parameters. Use all available "
                "fuzzing and scanning tools. Focus on achieving impact."
            ),
            "analyzer": (
                "Focus EXCLUSIVELY on source code and configuration analysis. "
                "Use code_analysis tool to run Semgrep scans. Review application "
                "logic, authentication flows, and data handling patterns. "
                "Look for hardcoded secrets, insecure crypto, and logic flaws."
            ),
            "reporter": (
                "Focus EXCLUSIVELY on generating comprehensive vulnerability reports. "
                "Review all findings from the session and create detailed "
                "create_vulnerability_report entries for each confirmed issue. "
                "Include proper CVSS scores, PoC scripts, and remediation steps."
            ),
        }

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
            from ..ollama import OllamaClient
            from ..config import get_config

            cfg = get_config()
            ollama = OllamaClient(model=cfg.ollama_model)
            # Subagent uses same engine as parent
            # type: ignore[attr-defined]
            agent = AgentLoop(ollama=ollama, engine=self.engine)
            # Limit subagent iterations — focused task, not full recon
            # process_message respects this over config
            agent._override_max_iterations = 200
            # Subagents must NOT be able to spawn further subagents (depth=1)
            agent._blocked_tools = {"spawn_agent", "run_parallel_agents"}

            async for _ in agent.process_message(prompt):
                pass  # drain all events

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
            }
            success = True
        except Exception as e:
            logger.error(f"spawn_agent error: {e}")
            res_dict = {"success": False, "error": str(e)}
            success = False

        duration = time.time() - start_time
        self.state.tool_history.append(  # type: ignore[attr-defined]
            ToolExecution(tool_name=tool_name, arguments=arguments,
                          result=res_dict, duration=duration,
                          status="success" if success else "error")
        )
        self.state.tool_counts["total"] += 1  # type: ignore[attr-defined]
        self.state.tool_counts["subagents"] = self.state.tool_counts.get(
            "subagents", 0) + 1  # type: ignore[attr-defined]
        return success, duration, res_dict, None

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
        self._last_output_file = None  # type: ignore[attr-defined]

        args_key = self._normalize_args_for_dedup(tool_name, arguments)
        count = self._executed_tool_counts.get(
            args_key, 0)  # type: ignore[attr-defined]
        limit = get_config().agent_repeat_tool_call_limit
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

        if tool_name == "spawn_agent":
            return await self._execute_spawn_agent_tool(tool_name, arguments)

        if tool_name == "code_analysis":
            return await self._execute_code_analysis_tool(tool_name, arguments)

        if tool_name == "schemathesis_fuzz":
            return await self._execute_schemathesis_tool(tool_name, arguments)

        if tool_name == "execute":
            cmd = arguments.get("command", "")
            if self.state.active_target and cmd and not cmd.strip(
            ).startswith("cd "):  # type: ignore[attr-defined]
                # type: ignore[attr-defined]
                workspace_dir = f"/workspace/{self.state.active_target}"
                # type: ignore[attr-defined]
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
                logger.info(
                    f"Enforced workspace context: {
                        arguments['command']}")

        start_time = time.time()
        try:
            # type: ignore[attr-defined]
            result = await self.engine.execute_tool(tool_name, arguments)
            success = result.get("success", False)
            try:
                # type: ignore[attr-defined]
                self._save_tool_output(tool_name, arguments, result)
            except Exception as _e:
                logger.debug("Could not save tool output: %s", _e)
        except Exception as e:
            success = False
            result = {"success": False, "error": str(e)}
            logger.error(f"Tool exec error: {e}")

        # Inject a helpful hint for common bash escaping errors (single quotes
        # inside single quotes)
        if not success:
            err_msg = result.get("error") or result.get("stderr") or ""
            if "unexpected EOF while looking for matching `''" in str(err_msg):
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

        duration = time.time() - start_time

        history_result = result
        if success and self._last_output_file and len(
                str(result)) > 10000:  # type: ignore[attr-defined]
            history_result = {
                "success": True,
                # type: ignore[attr-defined]
                "result": f"<Result truncated. Full output in {self._last_output_file}>",
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
            self._executed_tool_counts[args_key] = self._executed_tool_counts.get(
                args_key, 0) + 1  # type: ignore[attr-defined]

        # type: ignore[attr-defined]
        return success, duration, result, self._last_output_file

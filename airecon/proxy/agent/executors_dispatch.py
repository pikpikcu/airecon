from __future__ import annotations

import asyncio
import json
import logging
import re
import shlex
import time
from pathlib import Path
from typing import Any, Callable

from ..caido_client import CaidoClient
from ..config import get_config, get_workspace_root
from ..mcp import mcp_call_tool, mcp_list_tools, mcp_search_tools_payload
from .executors_catalog import (
    _AIRECON_TOOL_NAMES,
    _MAX_COMMAND_LENGTH,
    _RESULT_TRUNCATION_THRESHOLD,
    _TOOL_FLAG_CONFLICTS,
)
from .models import ToolExecution

logger = logging.getLogger("airecon.agent")


class _DispatchExecutorMixin:
    # tool_name -> (method_name, needs_on_output)
    _TOOL_DISPATCH_MAP: dict[str, tuple[str, bool]] = {
        "advanced_fuzz": ("_execute_advanced_fuzz_tool", False),
        "quick_fuzz": ("_execute_quick_fuzz_tool", False),
        "deep_fuzz": ("_execute_deep_fuzz_tool", False),
        "generate_wordlist": ("_execute_generate_wordlist_tool", False),
        "run_parallel_agents": ("_execute_run_parallel_agents_tool", True),
        "caido_list_requests": ("_execute_caido_list_requests_tool", False),
        "caido_send_request": ("_execute_caido_send_request_tool", False),
        "caido_automate": ("_execute_caido_automate_tool", False),
        "caido_get_findings": ("_execute_caido_get_findings_tool", False),
        "caido_set_scope": ("_execute_caido_set_scope_tool", False),
        "caido_intercept": ("_execute_caido_intercept_tool", False),
        "caido_sitemap": ("_execute_caido_sitemap_tool", False),
        "spawn_agent": ("_execute_spawn_agent_tool", False),
        "code_analysis": ("_execute_code_analysis_tool", False),
        "http_observe": ("_execute_http_observe_tool", False),
        "record_hypothesis": ("_exec_record_hypothesis", False),
        "schemathesis_fuzz": ("_execute_schemathesis_tool", False),
        "request_user_input": ("_execute_request_user_input", False),
        "load_skill": ("_exec_load_skill", False),
        # Utility tools
        "python_session": ("_execute_python_session_tool", False),
        "edit_file": ("_execute_edit_file_tool", False),
        "think": ("_execute_think_tool", False),
        "create_note": ("_execute_create_note_tool", False),
        "list_notes": ("_execute_list_notes_tool", False),
        "search_notes": ("_execute_search_notes_tool", False),
        "read_note": ("_execute_read_note_tool", False),
        "export_notes_wiki": ("_execute_export_notes_wiki_tool", False),
        "dataset_search": ("_execute_dataset_search_tool", False),
    }

    async def _dispatch_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        on_output: Callable | None = None,
    ):
        entry = self._TOOL_DISPATCH_MAP.get(tool_name)
        if entry is None:
            return None  # not a dispatched tool
        method_name, needs_on_output = entry
        method = getattr(self, method_name)
        if needs_on_output:
            return await method(tool_name, arguments, on_output=on_output)
        return await method(tool_name, arguments)

    async def _execute_run_parallel_agents_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        on_output: Callable[[str], None] | None = None,
    ) -> tuple[bool, float, dict[str, Any], str | None]:
        from .subagent import ParallelAgentRunner

        self._last_output_file = None
        start_time = time.time()

        targets = arguments.get("targets", [])
        prompt = arguments.get("prompt", "")

        parent_context = ""
        if hasattr(self, "_session") and self._session is not None:
            try:
                from .session import session_to_context

                parent_context = session_to_context(self._session)
            except Exception as _e:
                logger.debug("Could not build parent context for subagents: %s", _e)

        # Block tools that subagents should not use — loaded from tools_meta.json
        _meta_path = Path(__file__).parent.parent / "data" / "tools_meta.json"
        _subagent_block = {"execute", "browser_action", "web_search", "http_observe"}
        try:
            if _meta_path.exists():
                import json as _json

                _meta = _json.loads(_meta_path.read_text(encoding="utf-8"))
                # Subagents should not use parent-level orchestration tools
                _subagent_block |= set(
                    _meta.get("categories", {})
                    .get("utilities", {})
                    .get("custom_scripting", [])
                )
        except Exception as exc:
            logger.debug(
                "Could not load subagent blocklist from tools_meta.json: %s", exc
            )
        tools_to_block = _subagent_block
        if hasattr(self, "_blocked_tools"):
            self._blocked_tools.update(tools_to_block)
            logger.info("Blocked tools during run_parallel_agents: %s", tools_to_block)

        progress_lines: list[str] = []
        _seen_progress: set[str] = set()

        def _progress_cb(target: str, message: str) -> None:
            if target == "orchestrator":
                logger.debug("Orchestrator progress (hidden): %s", message)
                return

            key = f"{target}:{message}"
            if key in _seen_progress:
                return
            _seen_progress.add(key)
            if message.startswith("✅") or message.startswith("❌"):
                _seen_progress.clear()  # Reset on completion

            line = f"[{target}] {message}"
            progress_lines.append(line)
            logger.info("Parallel agent progress: [%s] %s", target, message)
            if on_output:
                event_json = (
                    json.dumps(
                        {
                            "event_type": "subagent_text",
                            "target": target,
                            "content": message + "\n",
                        }
                    )
                    + "\n"
                )
                logger.debug("SubAgent _progress_cb: sending text for %s", target)
                on_output(event_json)

        def _event_cb(target: str, event: Any) -> None:
            if not on_output:
                logger.warning(
                    "SubAgent _event_cb: on_output is None, dropping event for target=%s",
                    target,
                )
                return

            evt_type = getattr(event, "type", "")
            evt_data = getattr(event, "data", {}) or {}
            tool_id = str(evt_data.get("tool_id", ""))

            logger.info(
                "SubAgent _event_cb: target=%s, evt_type=%s, tool_id=%s",
                target,
                evt_type,
                tool_id,
            )

            if evt_type == "tool_start":
                tn = evt_data.get("tool", "?")
                args = evt_data.get("arguments", {})
                logger.debug(
                    "SubAgent _event_cb: tool_start target=%s tool=%s", target, tn
                )
                event_json = (
                    json.dumps(
                        {
                            "event_type": "subagent_tool_start",
                            "target": target,
                            "tool_id": tool_id or f"{tn}_{id(event)}",
                            "tool": tn,
                            "arguments": args,
                        }
                    )
                    + "\n"
                )
                logger.info(
                    "SubAgent _event_cb: sending tool_start JSON for %s::%s", target, tn
                )
                on_output(event_json)

            elif evt_type == "tool_output":
                content = evt_data.get("content", "")
                if content:
                    on_output(
                        json.dumps(
                            {
                                "event_type": "subagent_tool_output",
                                "target": target,
                                "tool_id": tool_id,
                                "content": content,
                            }
                        )
                        + "\n"
                    )

            elif evt_type == "tool_end":
                tn = evt_data.get("tool", "?")
                success = evt_data.get("success", False)
                dur = evt_data.get("duration", 0)
                on_output(
                    json.dumps(
                        {
                            "event_type": "subagent_tool_end",
                            "target": target,
                            "tool_id": tool_id,
                            "tool": tn,
                            "success": success,
                            "duration": dur,
                        }
                    )
                    + "\n"
                )

            elif evt_type == "text":
                content = evt_data.get("content", "")
                if content:
                    on_output(
                        json.dumps(
                            {
                                "event_type": "subagent_text",
                                "target": target,
                                "content": content,
                            }
                        )
                        + "\n"
                    )

            elif evt_type == "task_complete":
                on_output(
                    json.dumps(
                        {
                            "event_type": "subagent_complete",
                            "target": target,
                        }
                    )
                    + "\n"
                )

        try:
            runner = ParallelAgentRunner(engine=self.engine)
            runner.set_progress_callback(_progress_cb)
            runner.set_event_callback(_event_cb)
            logger.info("SubAgent runner configured with progress and event callbacks")

            cfg = get_config()
            recon_mode = (
                str(getattr(cfg, "agent_recon_mode", "standard")).strip().lower()
            )
            if recon_mode not in {"standard", "full"}:
                recon_mode = "standard"
            logger.info(
                "Subagent recon_mode: %s (from agent_recon_mode config)", recon_mode
            )

            if on_output:
                logger.info("Sending initial status for %d targets", len(targets))

                for t in targets:
                    on_output(
                        json.dumps(
                            {
                                "event_type": "subagent_text",
                                "target": t,
                                "content": "⏳ Waiting for slot...\n",
                            }
                        )
                        + "\n"
                    )
                on_output("\n")

            results = await runner.run_parallel(
                targets, prompt, parent_context=parent_context, recon_mode=recon_mode
            )

            result_summary = {
                "success": True,
                "targets_scanned": len(results),
                "targets": {},
                "progress_log": progress_lines[-50:],
            }
            for t, s in results.items():
                result_summary["targets"][t] = {
                    "subdomains": len(s.subdomains),
                    "live_hosts": len(s.live_hosts),
                    "urls": len(s.urls),
                    "vulnerabilities": len(s.vulnerabilities),
                    "technologies": len(s.technologies),
                }

                if on_output:
                    on_output(
                        f"✅ {t}: {len(s.subdomains)} subdomains, "
                        f"{len(s.live_hosts)} live hosts, "
                        f"{len(s.urls)} URLs, "
                        f"{len(s.vulnerabilities)} vulnerabilities\n"
                    )

            res_dict = {
                "success": True,
                "results": result_summary,
            }

            try:
                self._save_tool_output(tool_name, arguments, res_dict)
            except Exception as _e:
                logger.debug("Could not save tool output: %s", _e)
            success = True
        except Exception as e:
            logger.error("Subagent runner error: %s", e)
            if on_output:
                on_output(f"❌ Error: {e}\n")
            res_dict = {
                "success": False,
                "error": str(e),
                "progress_log": progress_lines[-20:] if progress_lines else [],
            }
            success = False

        if hasattr(self, "_blocked_tools"):
            self._blocked_tools.difference_update(tools_to_block)
            logger.info("Unblocked tools after run_parallel_agents: %s", tools_to_block)

        duration = time.time() - start_time

        self.state.tool_history.append(
            ToolExecution(
                tool_name=tool_name,
                arguments=arguments,
                result=res_dict,
                duration=duration,
                status="success" if success else "error",
            )
        )
        self.state.tool_counts["total"] += 1

        return success, duration, res_dict, None

    def _normalize_args_for_dedup(
        self, tool_name: str, arguments: dict[str, Any]
    ) -> tuple[str, str]:
        args_copy = dict(arguments)
        if tool_name == "execute" and "command" in args_copy:
            cmd = args_copy["command"]
            cmd = re.sub(r"(\s+-(oA|oN|oX|oG|oJ|o)\s+[^\s]+)", "", cmd)
            cmd = re.sub(r"(\s+--output\s*=?\s*[^\s]+)", "", cmd)
            cmd = re.sub(r"(\s*>\s*[^\s]+(\s+2>&1)?)", "", cmd)
            cmd = re.sub(r"(\s+-[bc]\s+output/cookies\.txt)", "", cmd)
            cmd = re.sub(r"(\s+--cookie(?:-jar)?\s+[^\s]+)", "", cmd)
            cmd = re.sub(r"_[0-9]{8}_[0-9]{6}\.", ".", cmd)
            args_copy["command"] = cmd.strip()

        return tool_name, json.dumps(args_copy, sort_keys=True, default=str)

    @staticmethod
    def _normalize_workspace_paths(cmd: str, target: str) -> str:
        """Rewrite paths that would create nested workspace dirs.

        Since the agent already `cd`'d into /workspace/<target>,
        any path reference to <target> in output files should be relative.

        E.g. ``amass -o target.com/output/file.txt`` becomes ``amass -o output/file.txt``
        E.g. ``mkdir target.com/output`` becomes ``mkdir output``
        """
        if not cmd or not target:
            return cmd

        # Handle paths like "target/target/" -> "target/"
        double_target = f"{target}/{target}/"
        if double_target in cmd:
            cmd = cmd.replace(double_target, target + "/")

        # Handle paths where the command references the target from within
        # the workspace dir (which is already the target dir):
        #   "target.com/output" or "/workspace/target.com/output" -> "output"
        replacements = [
            f"/workspace/{target}/",
            f"/workspace/{target}",
        ]
        for old_path in replacements:
            if old_path in cmd:
                cmd = cmd.replace(old_path, "")

        # Also handle bare "target.com/" prefix in any path segment after the target itself.
        # Since we're already cd'd into /workspace/<target>, "target.com/anything" -> "anything"
        # This covers: -o target/output, mkdir target/output, cat target/file, etc.
        # We must be careful not to break: curl https://target.com/api, curl api.target.com
        target_prefix = f"{target}/"
        if target_prefix in cmd:
            # Match output flags: -o[NAGX], --output=, >
            output_flag_pattern = rf"(?:-o[NAGX]?\s+|--output(?:-directory)?\s*=?\s*|>\s*)(\S*{re.escape(target_prefix)}\S*)"
            for match in re.finditer(output_flag_pattern, cmd):
                full = match.group(1)
                if target_prefix in full:
                    replacement = full.replace(target_prefix, "", 1)
                    cmd = cmd.replace(full, replacement, 1)

            # Also handle standalone paths: mkdir, cat, echo > target/output
            bare_path_pattern = rf"(?:(?:mkdir|cp|mv|rm|touch|ls|cat|tee)\s+)(.*?{re.escape(target_prefix)}\S*)"
            for match in re.finditer(bare_path_pattern, cmd):
                full = match.group(1)
                if target_prefix in full:
                    replacement = full.replace(target_prefix, "", 1)
                    cmd = cmd.replace(full, replacement, 1)

        return cmd

    async def _execute_tool_and_record(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        on_output: Callable[[str], None] | None = None,
    ) -> tuple[bool, float, dict[str, Any], str | None]:
        self._last_output_file = None

        if not isinstance(arguments, dict):
            logger.warning(
                "Tool '%s' received non-dict arguments (type=%s) — rejecting",
                tool_name,
                type(arguments).__name__,
            )
            return (
                False,
                0.0,
                {
                    "success": False,
                    "error": (
                        f"Tool call rejected: arguments must be a JSON object (dict), "
                        f"got {type(arguments).__name__}. "
                        f'Example: {{"name": "{tool_name}", "arguments": {{"key": "value"}}}}'
                    ),
                },
                None,
            )

        args_key = self._normalize_args_for_dedup(tool_name, arguments)
        count = self._executed_tool_counts.get(args_key, 0)
        limit = get_config().agent_repeat_tool_call_limit

        # MCP meta-operations (list_tools, search_tools) are read-only discovery
        # calls — they must never be blocked by dedup. Only call_tool with the
        # same tool+args combination is subject to repeat limits.
        _mcp_meta_action = (
            tool_name.startswith("mcp_")
            and str(arguments.get("action", "")).strip().lower()
            in ("list_tools", "search_tools")
        )

        if not _mcp_meta_action:
            if self._is_recon_phase_repeat_blocked(tool_name, arguments, count):
                binary = self._extract_command_binary(arguments.get("command", ""))
                return (
                    False,
                    0.0,
                    {
                        "success": False,
                        "error": (
                            f"Duplicate recon execution blocked for '{binary}'. "
                            "Use previous results and pivot to a new recon vector."
                        ),
                    },
                    None,
                )

            if count >= limit:
                return (
                    False,
                    0.0,
                    {
                        "success": False,
                        "error": f"Duplicate tool execution prevented (already ran {count}x).",
                    },
                    None,
                )

        if tool_name.startswith("mcp_"):
            start_time = time.time()
            server_name = tool_name[4:]
            action = str(arguments.get("action", "")).strip().lower()
            if action == "list_tools":
                success, result = await mcp_list_tools(server_name)
            elif action == "search_tools":
                query = str(arguments.get("query", "")).strip()
                raw_limit = arguments.get("limit", 10)
                try:
                    limit = int(raw_limit)
                except (TypeError, ValueError):
                    limit = 10

                success, listed = await mcp_list_tools(server_name)
                if not success:
                    result = listed
                else:
                    result = mcp_search_tools_payload(
                        listed if isinstance(listed, dict) else {}, query, limit
                    )
                    success = "error" not in result
            elif action == "call_tool":
                tool = str(arguments.get("tool", "")).strip()
                raw_args = arguments.get("arguments", {})

                # {"action":"call_tool","arguments":{"tool":"x","arguments":{...}}}
                if not tool and isinstance(raw_args, dict):
                    tool = str(raw_args.get("tool", "")).strip()
                    nested_args = raw_args.get("arguments", {})
                    if isinstance(nested_args, dict):
                        raw_args = nested_args

                if not tool:
                    success, result = (
                        False,
                        {"error": "MCP call_tool requires a 'tool' field"},
                    )
                elif not isinstance(raw_args, dict):
                    success, result = (
                        False,
                        {"error": "MCP 'arguments' must be a JSON object"},
                    )
                else:
                    success, result = await mcp_call_tool(server_name, tool, raw_args)
            else:
                success, result = (
                    False,
                    {
                        "error": "Invalid MCP action. Use 'list_tools', 'search_tools', or 'call_tool'."
                    },
                )

            duration = time.time() - start_time
            self._append_tool_history(
                tool_name=tool_name,
                arguments=arguments,
                result=result,
                duration=duration,
                status="success" if success else "error",
            )
            self._executed_tool_counts[args_key] = count + 1
            return success, duration, result, None

        handler_entry = self._TOOL_DISPATCH_MAP.get(tool_name)
        if handler_entry is not None:
            method_name, needs_on_output = handler_entry
            method = getattr(self, method_name)
            if needs_on_output:
                return await method(tool_name, arguments, on_output=on_output)
            return await method(tool_name, arguments)

        if tool_name == "execute":
            cmd = arguments.get("command", "")
            if not cmd or not cmd.strip():
                return (
                    False,
                    0.0,
                    {
                        "success": False,
                        "error": (
                            "Tool call error: 'command' argument is required and cannot be empty. "
                            'Example: {"name": "execute", "arguments": {"command": "ls -la /workspace"}}'
                        ),
                    },
                    None,
                )
            if len(cmd) > _MAX_COMMAND_LENGTH:
                return (
                    False,
                    0.0,
                    {
                        "success": False,
                        "error": (
                            f"Command rejected: length {len(cmd)} exceeds "
                            f"maximum {_MAX_COMMAND_LENGTH} characters."
                        ),
                    },
                    None,
                )

            # Scope guard + audit trail (config-driven). Default mode "warn" is
            # non-blocking; only scope_enforcement=block refuses out-of-scope
            # hosts. Every command is recorded to the persistent audit log.
            try:
                from ..scope import audit_log, get_scope_guard

                _guard = get_scope_guard()
                _in_scope, _scope_reason, _scope_host = _guard.check_command(cmd)
                audit_log(
                    {
                        "type": "execute",
                        "command": cmd[:500],
                        "target": getattr(self.state, "active_target", "") or "",
                        "in_scope": _in_scope,
                        "host": _scope_host,
                        "reason": _scope_reason,
                        "mode": _guard.mode,
                    }
                )
                if not _in_scope and _guard.mode == "block":
                    return (
                        False,
                        0.0,
                        {
                            "success": False,
                            "error": (
                                f"Command blocked by scope guard: {_scope_reason}. "
                                "Adjust scope_allowlist/scope_denylist, or set "
                                "scope_enforcement=warn to allow with a warning."
                            ),
                        },
                        None,
                    )
                if not _in_scope:
                    logger.warning("Scope advisory (execute): %s", _scope_reason)
            except Exception as _scope_err:
                logger.debug("scope guard check skipped: %s", _scope_err)

            _cmd_stripped = cmd.strip().lower()
            _is_caido_setup = "caido-setup" in _cmd_stripped
            _has_graphql_url = (
                "127.0.0.1:48080/graphql" in _cmd_stripped
                or "localhost:48080/graphql" in _cmd_stripped
            )
            _has_loginasguest = "loginasguest" in _cmd_stripped

            if _has_graphql_url or _has_loginasguest:
                return (
                    False,
                    0.0,
                    {
                        "success": False,
                        "error": (
                            "Command rejected: GraphQL/auth API must not run via execute. "
                            "Use native Caido tools directly: caido_intercept (action=status), "
                            "caido_list_requests, caido_set_scope, caido_send_request, caido_automate, caido_get_findings. "
                            "Reason: execute runs inside Docker sandbox and cannot reach host Caido (127.0.0.1 inside != host)."
                        ),
                    },
                    None,
                )

            if _is_caido_setup:
                existing_token = CaidoClient._token
                if existing_token:
                    return (
                        False,
                        0.0,
                        {
                            "success": False,
                            "error": (
                                "Command rejected: caido-setup bootstrap not needed because Caido token already exists. "
                                "Use native Caido tools directly: caido_intercept (action=status), "
                                "caido_list_requests, caido_set_scope, caido_send_request, caido_automate, caido_get_findings."
                            ),
                        },
                        None,
                    )
                logger.info(
                    "Allowing caido-setup via execute for initial token bootstrap"
                )

            _cmd_stripped = cmd.strip()
            _first_token = _cmd_stripped.split()[0] if _cmd_stripped.split() else ""

            if _first_token in _AIRECON_TOOL_NAMES and _first_token != "execute":  # nosec B105
                return (
                    False,
                    0.0,
                    {
                        "success": False,
                        "error": (
                            f"Command rejected: '{_first_token}' is an AIRecon tool, "
                            "not a shell binary. Do NOT call AIRecon tools via execute — "
                            f"use the '{_first_token}' tool directly with its own arguments. "
                            f'Example: {{"name": "{_first_token}", "arguments": {{...}}}}'
                        ),
                    },
                    None,
                )

            _func_call_match = (
                re.search(
                    r"\b("
                    + "|".join(re.escape(t) for t in _AIRECON_TOOL_NAMES)
                    + r")\s*\(",
                    _cmd_stripped,
                )
                if _AIRECON_TOOL_NAMES
                else None
            )
            if _func_call_match:
                _bad_tool = _func_call_match.group(1)
                return (
                    False,
                    0.0,
                    {
                        "success": False,
                        "error": (
                            f"Command rejected: '{_bad_tool}(...)' is not valid bash syntax. "
                            f"'{_bad_tool}' is an AIRecon tool — call it as a separate tool "
                            f"with its own arguments, not as a shell function inside execute. "
                            f'Example: {{"name": "{_bad_tool}", "arguments": {{...}}}}'
                        ),
                    },
                    None,
                )

            if _first_token in _TOOL_FLAG_CONFLICTS:
                _conflict_flags, _correct_tool = _TOOL_FLAG_CONFLICTS[_first_token]

                try:
                    _cmd_tokens = set(shlex.split(_cmd_stripped))
                except ValueError:
                    _cmd_tokens = set(_cmd_stripped.split())
                _found = [f for f in _conflict_flags if f in _cmd_tokens]
                if _found:
                    return (
                        False,
                        0.0,
                        {
                            "success": False,
                            "error": (
                                f"Command rejected: '{_first_token}' was used with flags that "
                                f"belong to '{_correct_tool}': {_found}. "
                                f"Replace '{_first_token}' with '{_correct_tool}' and retry. "
                                f"Example: {_cmd_stripped.replace(_first_token, _correct_tool, 1)}"
                            ),
                        },
                        None,
                    )
            if self.state.active_target and cmd and not cmd.strip().startswith("cd "):
                workspace_dir = f"/workspace/{self.state.active_target}"
                host_workspace = get_workspace_root() / self.state.active_target
                try:
                    host_workspace.mkdir(parents=True, exist_ok=True)
                except Exception as _e:
                    logger.debug("Could not create workspace dir: %s", _e)
                for subdir in ["output", "command", "tools", "vulnerabilities"]:
                    try:
                        (host_workspace / subdir).mkdir(parents=True, exist_ok=True)
                    except Exception as _e:
                        logger.debug("Could not create subdir %s: %s", subdir, _e)

                # Sanitize: rewrite nested workspace paths to relative equivalents.
                # E.g. "target/target/output/file.txt" -> "output/file.txt"
                # E.g. "target/output/file.txt" -> "output/file.txt"
                target = self.state.active_target
                cmd = self._normalize_workspace_paths(cmd, target)

                arguments["command"] = f"cd {workspace_dir} && {cmd}"
                logger.info("Enforced workspace context: %s", arguments["command"])

        start_time = time.time()
        output_file: str | None = None
        try:
            if hasattr(self, "state") and getattr(self.state, "_stop_requested", False):
                logger.info("Tool execution cancelled before start: %s", tool_name)
                return (
                    False,
                    0.0,
                    {
                        "success": False,
                        "error": "Tool execution cancelled: agent is stopping.",
                        "cancelled": True,
                    },
                    None,
                )

            result = await self.engine.execute_tool(
                tool_name, arguments, on_output=on_output
            )
            success = result.get("success", False)
            try:
                output_file = self._save_tool_output(tool_name, arguments, result)
            except Exception as _e:
                logger.debug("Could not save tool output: %s", _e)
        except asyncio.CancelledError:
            logger.info("Tool execution cancelled by agent: %s", tool_name)
            return (
                False,
                0.0,
                {
                    "success": False,
                    "error": "Tool execution cancelled: agent is stopping.",
                    "cancelled": True,
                },
                None,
            )
        except KeyboardInterrupt:
            logger.warning("Tool execution interrupted by user: %s", tool_name)
            return (
                False,
                0.0,
                {
                    "success": False,
                    "error": "Tool execution interrupted by user.",
                    "interrupted": True,
                },
                None,
            )
        except Exception as e:
            success = False
            result = {"success": False, "error": str(e)}
            logger.error("Tool exec error: %s", e)

        if tool_name == "execute" and hasattr(self, "state"):
            cmd = arguments.get("command", "").lower()
            stdout = result.get("stdout", "") or ""
            stderr = result.get("stderr", "") or ""
            output = (stdout + stderr).lower()

            if "caido-setup" in cmd:
                full_output = stdout + stderr
                try:
                    if CaidoClient.extract_and_set_token_from_execute_output(
                        full_output
                    ):
                        logger.info(
                            "caido-setup token extracted and cached for future use"
                        )
                        if "next_action" not in result:
                            result["next_action"] = (
                                "Caido token extracted successfully. "
                                "Caido is now active and ready for use via native tools: "
                                "caido_intercept, caido_list_requests, etc."
                            )
                except Exception as _e:
                    logger.debug(
                        "Token extraction from caido-setup output failed: %s", _e
                    )

            _dead_markers = (
                "name_not_resolved",
                "err_name_not_resolved",
                "nodename nor servname",
                "no such host",
                "could not resolve host",
                "getaddrinfo failed",
                "temporary failure in name resolution",
                "failed to resolve",
                "unable to resolve",
                "nxdomain",
                "connection refused",
                "connection reset",
                "address unreachable",
                "failed to connect",
                "no address associated",
            )
            if any(m in output for m in _dead_markers):
                _host_match = re.search(
                    r"(?:https?://|ssh://)([a-zA-Z0-9][-a-zA-Z0-9]*(?:\.[a-zA-Z0-9][-a-zA-Z0-9]*)+)"
                    r"|(?:^|\s)([a-zA-Z0-9][-a-zA-Z0-9]*(?:\.[a-zA-Z]{2,})(?::\d+)?(?=/|\s|$))",
                    cmd,
                )
                _host = (
                    (_host_match.group(1) or _host_match.group(2) or "").split(":")[0]
                    if _host_match
                    else None
                )

                if _host:
                    added = self.state.add_dead_host(_host)
                    if added:
                        logger.info(
                            "Dead host detected from execute output: %s",
                            _host,
                        )

                        result["dead_host_detected"] = True
                        result["host"] = _host
                        if "next_action" not in result:
                            result["next_action"] = (
                                f"SKIP: {_host} is unreachable (DNS/connection error). "
                                "Remove from target list and proceed to next subdomain."
                            )

        _is_exec_failure = (
            not success
            and hasattr(self, "state")
            and tool_name in ("execute", "browser_action", "web_search", "list_files")
            and "Duplicate tool execution" not in (result.get("error") or "")
            and "Tool call rejected" not in (result.get("error") or "")
            and "Command rejected" not in (result.get("error") or "")
        )
        if _is_exec_failure and hasattr(self.state, "add_failure"):
            error_detail = (
                result.get("error", "") or result.get("stderr", "") or "Unknown error"
            )
            target = arguments.get("target") or arguments.get("url", "")
            failure_id = self.state.add_failure(
                name=tool_name,
                error_detail=error_detail,
                target=target,
                failure_category="tool",
            )
            logger.debug(
                "Failure recorded with ID: %s for tool %s", failure_id, tool_name
            )

            if "next_action" not in result and hasattr(
                self.state, "get_failure_summary"
            ):
                failure_summary = self.state.get_failure_summary()
                if failure_summary.get("most_common"):
                    result["next_action"] = (
                        f"Pattern detected: {failure_summary['most_common']} errors are most common. "
                        f"Review recent failures and adapt strategy."
                    )

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

            elif "int() argument" in err_msg or "invalid literal for int" in err_msg:
                result["error"] = (
                    err_msg
                    + "\n[SYSTEM HINT]: A numeric argument was given a non-numeric value. "
                    "Check that integer fields (e.g. port, limit, count) are actual numbers, not strings."
                )

            elif "required" in err_msg.lower() and "argument" in err_msg.lower():
                result["error"] = (
                    err_msg
                    + f"\n[SYSTEM HINT]: The tool '{tool_name}' is missing a required argument. "
                    "Re-read the tool definition and include all required fields."
                )

            elif (
                "NoneType" in err_msg or "'NoneType' object has no attribute" in err_msg
            ):
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
                tool_name=tool_name,
                arguments=arguments,
                result=history_result,
                duration=duration,
                status="success" if success else "error",
            )
        )
        self.state.tool_counts["exec"] += 1
        self.state.tool_counts["total"] += 1

        if success:
            self._executed_tool_counts[args_key] = (
                self._executed_tool_counts.get(args_key, 0) + 1
            )
        return success, duration, result, output_file

    async def _exec_load_skill(
        self, tool_name: str, arguments: dict[str, Any]
    ) -> tuple[bool, float, dict[str, Any], str | None]:
        """Execute load_skill tool — dynamically load skill files into session."""
        start_time = time.time()

        try:
            from .executors_skill_loader import load_skill

            current_target = self.state.active_target or (
                self._session.target if self._session else ""
            )
            current_phase = self._get_current_phase().value
            result = load_skill(
                self.state,
                arguments.get("skills", ""),
                arguments.get("replace_skills", False),
                memory_manager=getattr(self, "_memory_manager", None),
                current_target=current_target,
                current_phase=current_phase,
            )
            success = result.get("success", False)
            if success and self._session:
                for skill_rel in result.get("loaded_skills", []):
                    if skill_rel not in self._session.loaded_skills:
                        self._session.loaded_skills.append(skill_rel)
        except Exception as e:
            logger.error("load_skill error: %s", e)
            result = {"success": False, "error": str(e)}
            success = False

        duration = time.time() - start_time

        self.state.tool_history.append(
            ToolExecution(
                tool_name=tool_name,
                arguments=arguments,
                result=result,
                duration=duration,
                status="success" if success else "error",
            )
        )
        self.state.tool_counts["exec"] += 1
        self.state.tool_counts["total"] += 1

        return success, duration, result, None

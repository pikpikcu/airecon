from __future__ import annotations

import asyncio
import json
import logging
import re
from pathlib import Path
from typing import Any, AsyncIterator

from ..config import get_config, get_workspace_root
from ..docker import DockerEngine
from ..ollama import OllamaClient
from ..system import get_system_prompt, auto_load_skills_for_message
from .executors import _ExecutorMixin
from .formatters import _FormatterMixin
from .models import AgentEvent, AgentState, MAX_TOOL_ITERATIONS
from .output_parser import parse_tool_output
from .session import (
    SessionData, load_session, save_session,
    update_from_parsed_output, session_to_context,
)
from .tool_defs import get_tool_definitions
from .validators import _ValidatorMixin
from .workspace import _WorkspaceMixin

logger = logging.getLogger("airecon.agent")


class AgentLoop(_ValidatorMixin, _FormatterMixin, _WorkspaceMixin, _ExecutorMixin):

    # Extracts embedded <tool_call>…</tool_call> blocks from model text output
    _TOOL_CALL_RE = re.compile(
        r"<tool_call>\s*(\{.*?\})\s*</tool_call>",
        re.DOTALL | re.IGNORECASE,
    )

    def __init__(self, ollama: OllamaClient, engine: DockerEngine) -> None:
        self.ollama = ollama
        self.engine = engine
        self.state = AgentState()
        self._tools_ollama: list[dict[str, Any]] | None = None
        self._last_output_file: str | None = None
        self._executed_tool_counts: dict[tuple[str, str], int] = {}
        self._initial_messages: list[dict[str, Any]] = []
        self._stop_requested: bool = False
        self._consecutive_failures: int = 0
        self._session: SessionData | None = None

    async def stop(self) -> None:
        logger.warning("Stopping Agent Loop...")
        self._stop_requested = True
        if self.engine:
            await self.engine.force_stop()

    async def initialize(self) -> None:
        self.state.conversation = [{"role": "system", "content": get_system_prompt()}]
        engine_tools = await self.engine.discover_tools()
        self._tools_ollama = self.engine.tools_to_ollama_format(engine_tools)

        if self.engine:
            self.state.add_message("system", "[SYSTEM: EXECUTE_COMMAND_AVAILABLE=yes]")

        if self._tools_ollama is None:
            self._tools_ollama = []
        self._tools_ollama.extend(get_tool_definitions())

        # Deduplicate by tool name
        unique: dict[str, dict] = {}
        for t in self._tools_ollama:
            unique[t["function"]["name"]] = t
        self._tools_ollama = list(unique.values())

        logger.info(f"Agent initialized with {len(self._tools_ollama)} tools")

        tool_names = [t["function"]["name"] for t in self._tools_ollama]
        self.state.add_message("system", f"[SYSTEM: REGISTERED TOOLS]\n{', '.join(tool_names)}")

        self._initial_messages = list(self.state.conversation)

    def reset(self) -> None:
        self.state = AgentState()
        if self._initial_messages:
            self.state.conversation = list(self._initial_messages)
        self._executed_tool_counts.clear()
        self._last_output_file = None
        self._session = None

    async def process_message(self, user_message: str) -> AsyncIterator[AgentEvent]:
        try:
            if not self._tools_ollama:
                await self.initialize()

            all_targets = self._extract_targets_from_text(user_message)
            extracted_target = all_targets[0] if all_targets else None
            if extracted_target:
                self.state.active_target = extracted_target

            cfg = get_config()

            if cfg.deep_recon_autostart and extracted_target and user_message.strip() == extracted_target:
                logger.info(f"Auto-starting deep recon for {extracted_target}")
                user_message = (
                    f"Perform a comprehensive full deep recon and vulnerability scan on {extracted_target}. "
                    "Use all available tools."
                )

            EPHEMERAL_PREFIXES = (
                "[SYSTEM: WORKSPACE",
                "[SYSTEM: ACTIVE_TARGET",
                "[SYSTEM: ADDITIONAL_TARGETS",
            )
            self.state.conversation = [
                msg for msg in self.state.conversation
                if not (
                    msg.get("role") == "system"
                    and any(msg.get("content", "").startswith(p) for p in EPHEMERAL_PREFIXES)
                )
            ]

            if len(all_targets) > 1:
                extra = ", ".join(all_targets[1:])
                self.state.conversation.append({
                    "role": "system",
                    "content": (
                        f"[SYSTEM: ADDITIONAL_TARGETS={extra}] "
                        f"Primary workspace is '{extracted_target}'. "
                        f"Additional targets also mentioned: {extra}. "
                        "Handle each in sequence or as directed by the user."
                    ),
                })

            if self.state.active_target:
                workspace_context = await asyncio.to_thread(
                    self._scan_workspace_state, self.state.active_target
                )
                self.state.conversation.append({
                    "role": "system",
                    "content": workspace_context if workspace_context
                               else f"[SYSTEM: ACTIVE_TARGET={self.state.active_target}]",
                })

                # Load previous session for this target
                if not self._session or self._session.target != self.state.active_target:
                    self._session = load_session(self.state.active_target)
                    if not self._session:
                        self._session = SessionData(target=self.state.active_target)

                if self._session and self._session.scan_count > 0:
                    session_ctx = session_to_context(self._session)
                    self.state.conversation.append({
                        "role": "system",
                        "content": session_ctx,
                    })

            self.state.conversation.append({"role": "user", "content": user_message})

            # Auto-load relevant skills based on user message keywords
            skill_context = auto_load_skills_for_message(user_message)
            if skill_context:
                self.state.conversation.append({"role": "system", "content": skill_context})

            # Reset per-message state
            self.state.iteration = 0
            self.state.max_iterations = cfg.agent_max_tool_iterations or MAX_TOOL_ITERATIONS
            self.state.warnings_sent = False
            self._stop_requested = False
            self._consecutive_failures = 0
            # NOTE: Do NOT clear _executed_tool_counts here — dedup must persist
            # across messages within the same session. It is only cleared in reset().

            while self.state.iteration < self.state.max_iterations:
                if self._stop_requested:
                    yield AgentEvent(type="error", data={"message": "Agent stopped by user."})
                    yield AgentEvent(type="done", data={})
                    return

                self.state.increment_iteration()

                # --- PLANNING INJECTION (iteration 1 only) ---
                if self.state.iteration == 1:
                    self.state.conversation.append({
                        "role": "system",
                        "content": (
                            "[SYSTEM: MANDATORY PLANNING STEP]\n"
                            "Before executing ANY tool, you MUST output your plan:\n"
                            "1. OBJECTIVE: What is the goal of this engagement?\n"
                            "2. PHASES: List 3-5 phases you will execute (e.g., Recon → Enumeration → Scanning → Exploitation)\n"
                            "3. TOOLS PER PHASE: Which tools for each phase?\n"
                            "4. SUCCESS CRITERIA: What does a successful outcome look like?\n"
                            "Output your plan FIRST, then proceed with Phase 1."
                        ),
                    })

                # --- EVALUATION CHECKPOINT (every 15 iterations) ---
                if self.state.iteration > 1 and self.state.iteration % 15 == 0:
                    session_info = ""
                    if self._session:
                        s = self._session
                        session_info = (
                            f"\nCurrent findings: {len(s.subdomains)} subdomains, "
                            f"{len(s.live_hosts)} live hosts, "
                            f"{sum(len(p) for p in s.open_ports.values())} open ports, "
                            f"{len(s.urls)} URLs, "
                            f"{len(s.vulnerabilities)} vulnerabilities"
                        )
                    self.state.conversation.append({
                        "role": "system",
                        "content": (
                            f"[SYSTEM: EVALUATION CHECKPOINT — iteration {self.state.iteration}]{session_info}\n"
                            "MANDATORY: Review your progress before proceeding:\n"
                            "1. What phases are COMPLETE? What phases remain?\n"
                            "2. What are the most important findings so far?\n"
                            "3. Should you CONTINUE, PIVOT to a different approach, or STOP?\n"
                            "4. What is the single most valuable action to take next?\n"
                            "If recon is sufficient, begin exploitation or emit [TASK_COMPLETE].\n"
                            "Do NOT repeat scans that have already been run."
                        ),
                    })

                # --- CONTEXT MANAGEMENT (every 15 iterations) ---
                if self.state.iteration % 15 == 0:
                    self.state.truncate_conversation(max_messages=50)

                if self.state.iteration > 1 and self.state.iteration % 10 == 0:
                    # Inject session-aware summary instead of just tool history
                    if self._session and self._session.scan_count > 0:
                        session_summary = session_to_context(self._session)
                        self.state.conversation = [
                            msg for msg in self.state.conversation
                            if not msg.get("content", "").startswith("[SYSTEM: RECENT EXECUTIONS")
                            and not msg.get("content", "").startswith("[SYSTEM: PREVIOUS SESSION")
                        ]
                        self.state.conversation.append({"role": "system", "content": session_summary})
                    elif self.state.tool_history:
                        history_ctx = self._build_recent_history_context(last_n=10)
                        if history_ctx:
                            self.state.conversation = [
                                msg for msg in self.state.conversation
                                if not msg.get("content", "").startswith("[SYSTEM: RECENT EXECUTIONS")
                            ]
                            self.state.conversation.append({"role": "system", "content": history_ctx})

                if self.state.is_approaching_limit() and not self.state.warnings_sent:
                    self.state.warnings_sent = True
                    remaining = self.state.max_iterations - self.state.iteration
                    self.state.conversation.append({
                        "role": "system",
                        "content": f"[SYSTEM: {remaining} iterations remaining]",
                    })

                thinking_acc = ""
                content_acc = ""
                tool_calls_acc = []
                in_thinking_tag = False
                _carry = ""

                try:
                    async for chunk in self.ollama.chat_stream(
                        messages=self.state.conversation,
                        tools=self._tools_ollama,
                        options={
                            "num_ctx": cfg.ollama_num_ctx,
                            "temperature": cfg.ollama_temperature,
                            "num_predict": cfg.ollama_num_predict,
                        },
                        think=cfg.ollama_enable_thinking,
                    ):
                        if hasattr(chunk, "model_dump"):
                            chunk_data = chunk.model_dump()
                        elif isinstance(chunk, dict):
                            chunk_data = chunk
                        else:
                            chunk_data = dict(chunk)

                        message = chunk_data.get("message", {})
                        chunk_thinking = message.get("thinking")
                        chunk_tool_calls = message.get("tool_calls")
                        chunk_content = message.get("content", "")

                        if chunk_thinking:
                            thinking_acc += chunk_thinking
                            yield AgentEvent(type="thinking", data={"content": chunk_thinking})

                        if chunk_content:
                            text = _carry + chunk_content
                            _carry = ""
                            _OPEN_TAG = "<think>"
                            _CLOSE_TAG = "</think>"
                            # Buffer partial tag suffix to avoid splitting mid-tag
                            for partial_len in range(min(len(text), 8), 0, -1):
                                suffix = text[-partial_len:]
                                if _OPEN_TAG.startswith(suffix) or _CLOSE_TAG.startswith(suffix):
                                    _carry = suffix
                                    text = text[:-partial_len]
                                    break

                            while text:
                                if not in_thinking_tag:
                                    if _OPEN_TAG in text:
                                        idx = text.index(_OPEN_TAG)
                                        before = text[:idx]
                                        text = text[idx + len(_OPEN_TAG):]
                                        if before:
                                            content_acc += before
                                            yield AgentEvent(type="text", data={"content": before})
                                        in_thinking_tag = True
                                    else:
                                        content_acc += text
                                        yield AgentEvent(type="text", data={"content": text})
                                        text = ""
                                else:
                                    if _CLOSE_TAG in text:
                                        idx = text.index(_CLOSE_TAG)
                                        think_frag = text[:idx]
                                        text = text[idx + len(_CLOSE_TAG):]
                                        if think_frag:
                                            thinking_acc += think_frag
                                            yield AgentEvent(type="thinking", data={"content": think_frag})
                                        in_thinking_tag = False
                                    else:
                                        thinking_acc += text
                                        yield AgentEvent(type="thinking", data={"content": text})
                                        text = ""

                        if chunk_tool_calls:
                            tool_calls_acc.extend(chunk_tool_calls)

                    if _carry:
                        content_acc += _carry
                        yield AgentEvent(type="text", data={"content": _carry})
                        _carry = ""

                except Exception as stream_err:
                    err_str = str(stream_err)
                    err_lower = err_str.lower()
                    if "invalid character '<'" in err_str or "failed to parse JSON" in err_str or "HTML error page" in err_str:
                        error_msg = "Ollama returned an HTML error page — server crashed or ran out of VRAM.\nFix: run `systemctl restart ollama` or reduce `ollama_num_ctx` in config."
                    elif "connection refused" in err_lower:
                        error_msg = "Cannot connect to Ollama (connection refused).\nFix: start Ollama with `ollama serve`."
                    elif "model not found" in err_lower or "pull" in err_lower:
                        error_msg = f"Model not found: {cfg.ollama_model}\nFix: run `ollama pull {cfg.ollama_model}`."
                    elif "context length" in err_lower or "out of memory" in err_lower:
                        error_msg = "Model ran out of context or memory.\nFix: lower `ollama_num_ctx` in config (e.g. 32768)."
                    elif "timeout" in err_lower or "timed out" in err_lower:
                        error_msg = "Ollama request timed out.\nFix: increase `ollama_timeout` in config or use a faster model."
                    else:
                        error_msg = f"Model connection error: {err_str}"
                    logger.error(f"Ollama stream error: {stream_err}")
                    yield AgentEvent(type="error", data={"message": error_msg})
                    yield AgentEvent(type="done", data={})
                    return

                if not content_acc and not tool_calls_acc and not thinking_acc:
                    yield AgentEvent(type="error", data={"message": "Empty response from model."})
                    yield AgentEvent(type="done", data={})
                    return

                # Fallback: some models emit tool calls as text inside <tool_call> tags
                if not tool_calls_acc:
                    _registered = {t["function"]["name"] for t in (self._tools_ollama or [])}
                    _search_text = content_acc + "\n" + thinking_acc
                    extracted = self._extract_tool_calls_from_text(_search_text, _registered)
                    if extracted:
                        tool_calls_acc.extend(extracted)
                        content_acc = self._TOOL_CALL_RE.sub("", content_acc).strip()

                _has_task_complete = "[TASK_COMPLETE]" in content_acc
                content_acc = content_acc.replace("[TASK_COMPLETE]", "").strip()

                self.state.add_message("assistant", content_acc, tool_calls_acc, thinking_acc)

                if not tool_calls_acc:
                    if _has_task_complete:
                        logger.info("Agent emitted [TASK_COMPLETE] — stopping.")
                        # Save session on task complete
                        if self._session:
                            save_session(self._session)
                    yield AgentEvent(type="done", data={})
                    return

                if not content_acc.strip():
                    tool_names_str = ", ".join(tc["function"]["name"] for tc in tool_calls_acc)
                    yield AgentEvent(type="text", data={"content": f"Executing: {tool_names_str}..."})

                # Classify tools: parallelizable (execute) vs sequential (browser, fs, etc.)
                _SEQUENTIAL_TOOLS = {"browser_action", "create_file", "read_file", "create_vulnerability_report"}
                parallel_tasks: list[tuple[int, dict]] = []
                sequential_tasks: list[tuple[int, dict]] = []

                for idx, tc in enumerate(tool_calls_acc):
                    tn = tc["function"]["name"]
                    args = self._normalize_tool_args(tn, tc["function"]["arguments"], user_message)
                    # Yield tool start FIRST so UI spinner shows immediately
                    yield AgentEvent(type="tool_start", data={"tool_id": str(idx), "tool": tn, "arguments": args})
                    
                    if tn in _SEQUENTIAL_TOOLS or not self.engine.has_tool(tn):
                        sequential_tasks.append((idx, tc, args))
                    else:
                        parallel_tasks.append((idx, tc, args))

                # Execute parallel tasks concurrently if there are multiple
                all_results: dict[int, tuple] = {}  # idx -> (tc, tool_name, arguments, valid, ...)

                if len(parallel_tasks) > 1:
                    async def _run_parallel(idx: int, tc: dict, args_ready: dict) -> tuple:
                        tn = tc["function"]["name"]
                        args = args_ready
                        valid, arg_err = self._validate_tool_args(tn, args)
                        if not valid:
                            return (idx, tc, tn, args, False, 0.0, {"success": False, "error": arg_err}, None, False)
                        # Check output file dedup
                        dedup_warn = self._check_output_dedup(args) if tn == "execute" else None
                        if dedup_warn:
                            return (idx, tc, tn, args, False, 0.0, {"success": False, "error": dedup_warn}, None, False)
                        s, d, r, o = await self._execute_tool_and_record(tn, args)
                        self.state.missing_tool_count = 0
                        return (idx, tc, tn, args, True, d, r, o, s)

                    coros = [_run_parallel(i, t, a) for i, t, a in parallel_tasks]
                    results = await asyncio.gather(*coros, return_exceptions=True)
                    for res in results:
                        if isinstance(res, Exception):
                            logger.error(f"Parallel tool error: {res}")
                            continue
                        all_results[res[0]] = res
                else:
                    # Single parallel task or none → add to sequential
                    sequential_tasks.extend(parallel_tasks)
                    sequential_tasks.sort(key=lambda x: x[0])

                # Execute sequential tasks one by one
                for idx, tc, args in sequential_tasks:
                    tn = tc["function"]["name"]
                    valid, arg_err = self._validate_tool_args(tn, args)
                    if not valid:
                        all_results[idx] = (idx, tc, tn, args, False, 0.0, {"success": False, "error": arg_err}, None, False)
                        continue
                    # Check output file dedup for execute commands
                    if tn == "execute":
                        dedup_warn = self._check_output_dedup(args)
                        if dedup_warn:
                            all_results[idx] = (idx, tc, tn, args, False, 0.0, {"success": False, "error": dedup_warn}, None, False)
                            continue

                    if tn == "browser_action":
                        s, d, r, o = await self._execute_local_browser_tool(tn, args)
                        self.state.missing_tool_count = 0
                    elif tn == "create_vulnerability_report":
                        s, d, r, o = await self._execute_report_tool(tn, args)
                        self.state.missing_tool_count = 0
                    elif tn in ("create_file", "read_file"):
                        s, d, r, o = await self._execute_filesystem_tool(tn, args)
                        self.state.missing_tool_count = 0
                    elif tn == "web_search":
                        s, d, r, o = await self._execute_web_search_tool(args)
                        self.state.missing_tool_count = 0
                    elif self.engine.has_tool(tn):
                        s, d, r, o = await self._execute_tool_and_record(tn, args)
                        self.state.missing_tool_count = 0
                    else:
                        self.state.missing_tool_count += 1
                        tool_list = ", ".join(t["function"]["name"] for t in (self._tools_ollama or []))
                        error_msg = (
                            "CRITICAL ERROR: You just submitted an empty tool call (missing 'name'). "
                            f"Registered tools: {tool_list}."
                            if not tn
                            else f"Tool '{tn}' does not exist. "
                                 f"Registered tools: {tool_list}. "
                                 "Use 'execute' to run any shell command in the sandbox."
                        )
                        s, d, r, o = (False, 0.0, {"success": False, "error": error_msg}, None)
                        if self.state.missing_tool_count >= cfg.agent_missing_tool_retry_limit:
                            yield AgentEvent(
                                type="error",
                                data={"message": f"Agent called unknown tool '{tn}' {self.state.missing_tool_count}x. Stopping."},
                            )
                            yield AgentEvent(type="done", data={})
                            return
                    all_results[idx] = (idx, tc, tn, args, True, d, r, o, s)

                # Process all results in order and emit events
                for idx in sorted(all_results.keys()):
                    res = all_results[idx]
                    _, tc, tool_name, arguments, was_valid, duration, result, output_file, success = res

                    if not was_valid:
                        arg_error = result.get("error", "Unknown validation error")
                        yield AgentEvent(
                            type="tool_end",
                            data={"tool_id": str(idx), "tool": tool_name, "success": False, "duration": 0.0,
                                  "result_preview": f"VALIDATION ERROR: {arg_error}",
                                  "output_file": None, "tool_counts": self.state.tool_counts},
                        )
                        self._consecutive_failures += 1
                        self._append_tool_result(
                            tool_name,
                            f"ARGUMENT VALIDATION FAILED: {arg_error}\nFix the arguments and retry.",
                            False, tc.get("id"),
                        )
                        continue

                    yield AgentEvent(
                        type="tool_end",
                        data={
                            "tool_id": str(idx),
                            "tool": tool_name,
                            "success": success,
                            "duration": round(duration, 2),
                            "result_preview": self._truncate_result(result),
                            "output_file": output_file,
                            "tool_counts": self.state.tool_counts,
                        },
                    )

                    if success:
                        self._consecutive_failures = 0
                    else:
                        self._consecutive_failures += 1

                    raw_command = arguments.get("command", "") if tool_name == "execute" else ""
                    content_str = self._smart_format_tool_result(tool_name, result, success, raw_command)

                    # Update session with parsed tool output
                    if success and tool_name == "execute" and self._session:
                        stdout = result.get("stdout", "") or result.get("result", "") or ""
                        if isinstance(stdout, str) and stdout.strip():
                            parsed_out = parse_tool_output(raw_command, stdout)
                            if parsed_out and parsed_out.total_count > 0:
                                update_from_parsed_output(self._session, parsed_out, raw_command)

                    if not success and self._consecutive_failures >= 3:
                        alt_suggestion = self._suggest_alternative_tool(tool_name, raw_command)
                        content_str += (
                            f"\n\n[SYSTEM: {self._consecutive_failures} CONSECUTIVE FAILURES DETECTED] "
                            "MANDATORY: Stop using the current approach. "
                            "Switch to a completely different tool or strategy. "
                            + (f"SUGGESTED ALTERNATIVES: {alt_suggestion}\n" if alt_suggestion else "")
                            + "If all options are exhausted, document what was tried and emit [TASK_COMPLETE]."
                        )

                    if success and self.state.tool_counts["total"] >= 1:
                        content_str += (
                            "\n\n[SYSTEM: SELF-CHECK] Re-read the user's original request. "
                            "Ask yourself: 'Did the user explicitly ask for the NEXT step I'm about to run?' "
                            "If YES → continue. "
                            "If NO → report the current results and emit [TASK_COMPLETE] now."
                        )

                    self._append_tool_result(tool_name, content_str, success, tc.get("id"))

                if _has_task_complete:
                    logger.info("Agent emitted [TASK_COMPLETE] after tools — stopping.")
                    if self._session:
                        save_session(self._session)
                    yield AgentEvent(type="done", data={})
                    return

            yield AgentEvent(type="error", data={"message": "Max tool iterations reached."})
            yield AgentEvent(type="done", data={})

        except Exception as e:
            logger.exception("Fatal error in agent loop")
            yield AgentEvent(type="error", data={"message": f"Fatal Agent Error: {str(e)}"})
            yield AgentEvent(type="done", data={})

    def _append_tool_result(
        self,
        tool_name: str,
        content_str: str,
        success: bool,
        tool_call_id: str | None = None,
    ) -> None:
        cfg = get_config()
        if cfg.tool_response_role.lower() == "tool":
            tool_msg: dict[str, Any] = {"role": "tool", "name": tool_name, "content": content_str}
            if tool_call_id:
                tool_msg["tool_call_id"] = tool_call_id
            self.state.conversation.append(tool_msg)
        else:
            status = "successfully" if success else "with errors"
            self.state.conversation.append({
                "role": "user",
                "content": f"[SYSTEM: Tool '{tool_name}' executed {status}]\nOutput:\n{content_str}",
            })

    def get_stats(self) -> dict[str, Any]:
        return {
            "message_count": len(self.state.conversation),
            "tool_counts": self.state.tool_counts,
        }

    def _format_tool_calls_for_critic(
        self, tool_calls: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        formatted: list[dict[str, Any]] = []
        for tc in tool_calls:
            fn = tc.get("function", {})
            name = fn.get("name")
            args = fn.get("arguments")
            if isinstance(args, str):
                try:
                    args = json.loads(args)
                except Exception:
                    args = {}
            formatted.append({"name": name, "arguments": args})
        return formatted

    def _extract_tool_calls_from_text(
        self, text: str, registered_tools: set[str]
    ) -> list[dict[str, Any]]:
        """Extract tool calls from model text using fault-tolerant JSON parsing.

        Handles:
        - <tool_call>{...}</tool_call> tags
        - Bare JSON objects with 'name' and 'arguments' keys
        - Malformed JSON with trailing commas, comments, unbalanced brackets
        """
        tool_calls: list[dict[str, Any]] = []

        # Step 1: Try <tool_call> tag extraction
        for raw_json in self._TOOL_CALL_RE.findall(text):
            tc = self._parse_tool_call_json(raw_json, registered_tools)
            if tc:
                tool_calls.append(tc)

        if tool_calls:
            return tool_calls

        # Step 2: Try finding bare JSON objects that look like tool calls
        # Match any JSON-like object in the text
        brace_depth = 0
        start_idx = None
        for i, ch in enumerate(text):
            if ch == "{":
                if brace_depth == 0:
                    start_idx = i
                brace_depth += 1
            elif ch == "}":
                brace_depth -= 1
                if brace_depth == 0 and start_idx is not None:
                    candidate = text[start_idx:i + 1]
                    # Only try if it looks like a tool call (has "name" key)
                    if '"name"' in candidate or "'name'" in candidate:
                        tc = self._parse_tool_call_json(candidate, registered_tools)
                        if tc:
                            tool_calls.append(tc)
                    start_idx = None

        return tool_calls

    def _parse_tool_call_json(
        self, raw: str, registered_tools: set[str]
    ) -> dict[str, Any] | None:
        """Try to parse a JSON string as a tool call with auto-repair."""
        parsed = self._try_parse_json(raw)
        if parsed is None:
            return None

        # Extract tool name and arguments from various formats
        tc_name = (
            parsed.get("name")
            or parsed.get("function", {}).get("name", "")
        )
        tc_args = (
            parsed.get("arguments")
            or parsed.get("parameters")
            or parsed.get("function", {}).get("arguments", {})
            or {}
        )

        if tc_name and tc_name in registered_tools:
            logger.info(f"[fallback] Extracted tool_call: {tc_name}")
            return {"function": {"name": tc_name, "arguments": tc_args}}
        return None

    @staticmethod
    def _try_parse_json(raw: str) -> dict | None:
        """Try to parse JSON with auto-repair for common issues."""
        # Attempt 1: direct parse
        try:
            result = json.loads(raw)
            if isinstance(result, dict):
                return result
        except json.JSONDecodeError:
            pass

        # Attempt 2: strip // and /* */ comments
        cleaned = re.sub(r"//[^\n]*", "", raw)
        cleaned = re.sub(r"/\*.*?\*/", "", cleaned, flags=re.DOTALL)
        try:
            result = json.loads(cleaned)
            if isinstance(result, dict):
                return result
        except json.JSONDecodeError:
            pass

        # Attempt 3: fix trailing commas
        cleaned = re.sub(r",\s*([}\]])", r"\1", cleaned)
        try:
            result = json.loads(cleaned)
            if isinstance(result, dict):
                return result
        except json.JSONDecodeError:
            pass

        # Attempt 4: balance brackets
        open_count = cleaned.count("{")
        close_count = cleaned.count("}")
        if open_count > close_count:
            cleaned += "}" * (open_count - close_count)
        elif close_count > open_count:
            cleaned = "{" * (close_count - open_count) + cleaned
        try:
            result = json.loads(cleaned)
            if isinstance(result, dict):
                return result
        except json.JSONDecodeError:
            pass

        # Attempt 5: replace single quotes with double quotes
        cleaned = cleaned.replace("'", '"')
        try:
            result = json.loads(cleaned)
            if isinstance(result, dict):
                return result
        except json.JSONDecodeError:
            pass

        return None

    def _check_output_dedup(self, arguments: dict[str, Any]) -> str | None:
        """Check if a command writes to an output file that already has data.

        Returns a warning string if the scan should be skipped, None otherwise.
        """
        cmd = arguments.get("command", "")
        if not cmd or not self.state.active_target:
            return None

        # Detect -o / --output / -oX / -oN / -oG flags
        import shlex
        try:
            tokens = shlex.split(cmd)
        except ValueError:
            return None

        output_file = None
        for i, token in enumerate(tokens):
            if token in ("-o", "--output", "-oX", "-oN", "-oG", "-oA", "-oJ") and i + 1 < len(tokens):
                output_file = tokens[i + 1]
                break
            if token.startswith("-o") and len(token) > 2 and not token.startswith("-oX"):
                # -oFilename (no space)
                output_file = token[2:]
                break

        if not output_file:
            return None

        # Check if the file exists in workspace
        workspace = get_workspace_root() / self.state.active_target
        full_path = workspace / output_file if not output_file.startswith("/") else Path(output_file)

        if full_path.exists() and full_path.stat().st_size > 100:
            size_kb = full_path.stat().st_size / 1024
            return (
                f"OUTPUT FILE ALREADY EXISTS: {output_file} ({size_kb:.1f} KB)\n"
                f"This scan has likely been run before. To avoid duplicate work:\n"
                f"- Read the existing file: cat {output_file}\n"
                f"- If you need fresh data: delete it first, then re-run\n"
                f"- If the data is sufficient: move to the next phase"
            )
        return None

    # Tool alternative suggestions for smart retry
    _TOOL_ALTERNATIVES: dict[str, str] = {
        "nmap": "Try: masscan for fast port scan, or naabu for focused port scan",
        "subfinder": "Try: amass enum, assetfinder, findomain, or crt.sh via curl",
        "httpx": "Try: curl -s -o /dev/null -w '%{http_code}' <url>, or wget --spider",
        "nuclei": "Try: nikto, whatweb, or manual testing with curl",
        "ffuf": "Try: dirsearch, feroxbuster, gobuster, or wfuzz",
        "gobuster": "Try: ffuf, dirsearch, feroxbuster, or wfuzz",
        "dirsearch": "Try: ffuf, feroxbuster, gobuster, or wfuzz",
        "sqlmap": "Try: ghauri, or manual SQL injection testing with curl",
        "nikto": "Try: nuclei with web templates, or whatweb",
        "amass": "Try: subfinder, assetfinder, findomain, or dnsx",
        "katana": "Try: gospider, waybackurls, gau, or hakrawler",
        "curl": "Try: wget, httpx, or python3 requests",
        "dig": "Try: nslookup, host, or dnsx",
        "whatweb": "Try: httpx -tech-detect, or wappalyzer via browser",
        "testssl": "Try: sslscan, sslyze, or nmap --script ssl*",
        "masscan": "Try: nmap, naabu, or rustscan",
        "wpscan": "Try: nuclei -t wordpress/, or manual enumeration",
    }

    def _suggest_alternative_tool(self, tool_name: str, command: str = "") -> str:
        """Suggest alternative tools when the current one fails repeatedly."""
        # Try to find the actual binary name from the command
        cmd = command or ""
        cmd_clean = re.sub(r"^cd\s+/workspace/[^\s]+\s*&&\s*", "", cmd).strip()
        binary = cmd_clean.split()[0] if cmd_clean.split() else tool_name
        binary = binary.rsplit("/", 1)[-1]  # strip path
        if binary == "sudo" and len(cmd_clean.split()) > 1:
            binary = cmd_clean.split()[1]

        suggestion = self._TOOL_ALTERNATIVES.get(binary)
        if suggestion:
            return suggestion

        # Generic fallback
        return "Try using a completely different tool. Run 'which <tool>' to verify availability."

    def get_progress(self) -> dict[str, Any]:
        """Return progress data for the /api/progress endpoint."""
        session = self._session
        progress = {
            "target": self.state.active_target or "none",
            "iteration": self.state.iteration,
            "max_iterations": self.state.max_iterations,
            "tool_counts": self.state.tool_counts,
            "consecutive_failures": self._consecutive_failures,
            "session": None,
        }
        if session:
            progress["session"] = {
                "subdomains": len(session.subdomains),
                "live_hosts": len(session.live_hosts),
                "open_ports": sum(len(p) for p in session.open_ports.values()),
                "urls": len(session.urls),
                "vulnerabilities": len(session.vulnerabilities),
                "tools_run": session.tools_run,
                "scan_count": session.scan_count,
                "completed_phases": session.completed_phases,
            }
        return progress

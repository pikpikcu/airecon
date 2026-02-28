from __future__ import annotations

import asyncio
import json
import logging
import re
from typing import Any, AsyncIterator

from ..config import get_config, get_workspace_root
from ..docker import DockerEngine
from ..ollama import OllamaClient
from ..system import get_system_prompt
from .executors import _ExecutorMixin
from .formatters import _FormatterMixin
from .models import AgentEvent, AgentState, MAX_TOOL_ITERATIONS
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

            self.state.conversation.append({"role": "user", "content": user_message})

            # Reset per-message state
            self.state.iteration = 0
            self.state.max_iterations = cfg.agent_max_tool_iterations or MAX_TOOL_ITERATIONS
            self.state.warnings_sent = False
            self._stop_requested = False
            self._consecutive_failures = 0
            self._executed_tool_counts.clear()

            while self.state.iteration < self.state.max_iterations:
                if self._stop_requested:
                    yield AgentEvent(type="error", data={"message": "Agent stopped by user."})
                    yield AgentEvent(type="done", data={})
                    return

                self.state.increment_iteration()

                if self.state.iteration % 20 == 0:
                    self.state.truncate_conversation(max_messages=60)

                if self.state.iteration > 1 and self.state.iteration % 10 == 0 and self.state.tool_history:
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
                    for raw_json in self._TOOL_CALL_RE.findall(_search_text):
                        try:
                            parsed = json.loads(raw_json)
                            tc_name = parsed.get("name") or parsed.get("function", {}).get("name", "")
                            tc_args = (
                                parsed.get("arguments")
                                or parsed.get("parameters")
                                or parsed.get("function", {}).get("arguments", {})
                                or {}
                            )
                            if tc_name and tc_name in _registered:
                                tool_calls_acc.append({"function": {"name": tc_name, "arguments": tc_args}})
                                logger.info(f"[fallback] Extracted embedded tool_call: {tc_name}")
                        except json.JSONDecodeError:
                            logger.warning(f"[fallback] Could not parse embedded tool_call: {raw_json[:120]}")

                    if tool_calls_acc:
                        content_acc = self._TOOL_CALL_RE.sub("", content_acc).strip()

                _has_task_complete = "[TASK_COMPLETE]" in content_acc
                content_acc = content_acc.replace("[TASK_COMPLETE]", "").strip()

                self.state.add_message("assistant", content_acc, tool_calls_acc, thinking_acc)

                if not tool_calls_acc:
                    if _has_task_complete:
                        logger.info("Agent emitted [TASK_COMPLETE] — stopping.")
                    yield AgentEvent(type="done", data={})
                    return

                if not content_acc.strip():
                    tool_names_str = ", ".join(tc["function"]["name"] for tc in tool_calls_acc)
                    yield AgentEvent(type="text", data={"content": f"Executing: {tool_names_str}..."})

                for tc in tool_calls_acc:
                    tool_name = tc["function"]["name"]
                    arguments = self._normalize_tool_args(tool_name, tc["function"]["arguments"], user_message)

                    valid, arg_error = self._validate_tool_args(tool_name, arguments)
                    if not valid:
                        yield AgentEvent(type="tool_start", data={"tool": tool_name, "arguments": arguments})
                        yield AgentEvent(
                            type="tool_end",
                            data={"tool": tool_name, "success": False, "duration": 0.0,
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

                    yield AgentEvent(type="tool_start", data={"tool": tool_name, "arguments": arguments})

                    if tool_name == "browser_action":
                        success, duration, result, output_file = await self._execute_local_browser_tool(tool_name, arguments)
                        self.state.missing_tool_count = 0
                    elif tool_name == "create_vulnerability_report":
                        success, duration, result, output_file = await self._execute_report_tool(tool_name, arguments)
                        self.state.missing_tool_count = 0
                    elif tool_name in ("create_file", "read_file"):
                        success, duration, result, output_file = await self._execute_filesystem_tool(tool_name, arguments)
                        self.state.missing_tool_count = 0
                    elif tool_name == "web_search":
                        success, duration, result, output_file = await self._execute_web_search_tool(arguments)
                        self.state.missing_tool_count = 0
                    elif self.engine.has_tool(tool_name):
                        success, duration, result, output_file = await self._execute_tool_and_record(tool_name, arguments)
                        self.state.missing_tool_count = 0
                    else:
                        self.state.missing_tool_count += 1
                        tool_list = ", ".join(t["function"]["name"] for t in (self._tools_ollama or []))
                        error_msg = (
                            "CRITICAL ERROR: You just submitted an empty tool call (missing 'name'). "
                            f"Registered tools: {tool_list}."
                            if not tool_name
                            else f"Tool '{tool_name}' does not exist. "
                                 f"Registered tools: {tool_list}. "
                                 "Use 'execute' to run any shell command in the sandbox."
                        )
                        success, duration, result, output_file = (
                            False, 0.0, {"success": False, "error": error_msg}, None
                        )
                        if self.state.missing_tool_count >= cfg.agent_missing_tool_retry_limit:
                            yield AgentEvent(
                                type="error",
                                data={"message": f"Agent called unknown tool '{tool_name}' {self.state.missing_tool_count}x. Stopping."},
                            )
                            yield AgentEvent(type="done", data={})
                            return

                    yield AgentEvent(
                        type="tool_end",
                        data={
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

                    if not success and self._consecutive_failures >= 3:
                        content_str += (
                            f"\n\n[SYSTEM: {self._consecutive_failures} CONSECUTIVE FAILURES DETECTED] "
                            "MANDATORY: Stop using the current approach. "
                            "Switch to a completely different tool or strategy. "
                            "If all options are exhausted, document what was tried and emit [TASK_COMPLETE]."
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

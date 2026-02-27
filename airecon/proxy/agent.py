"""Agent: LLM ↔ tool execution cycle with streaming using Ollama SDK."""

from __future__ import annotations

import json
import logging
import time
import asyncio
import os
import re
from dataclasses import dataclass, field
from typing import Any, AsyncIterator

from .docker import DockerEngine
from .ollama import OllamaClient
from .system import get_system_prompt
from .config import get_config, get_workspace_root
from .browser import browser_action
from .reporting import create_vulnerability_report
from .filesystem import create_file, read_file
from .web_search import web_search

logger = logging.getLogger("airecon.agent")

MAX_TOOL_ITERATIONS = 2000


@dataclass
class ToolExecution:
    """Record of a single tool execution."""
    tool_name: str
    arguments: dict[str, Any]
    result: dict[str, Any] | None = None
    duration: float = 0.0
    status: str = "pending"


@dataclass
class AgentEvent:
    """Event streamed from the agent loop to the client."""
    type: str  # "text", "tool_start", "tool_end", "error", "done", "thinking"
    data: dict[str, Any] = field(default_factory=dict)

@dataclass
class AgentState:
    """Encapsulates the dynamic state of the agent during a task."""
    conversation: list[dict[str, Any]] = field(default_factory=list)
    tool_history: list[ToolExecution] = field(default_factory=list)
    tool_counts: dict[str, int] = field(default_factory=lambda: {"exec": 0, "total": 0})
    iteration: int = 0
    max_iterations: int = MAX_TOOL_ITERATIONS
    active_target: str | None = None
    warnings_sent: bool = False
    
    # Context management
    system_prompt: dict[str, Any] | None = None  # Store system prompt separately for truncation
    missing_tool_count: int = 0

    def add_message(self, role: str, content: str, tool_calls: list[dict[str, Any]] | None = None, thinking: str | None = None) -> None:
        msg = {"role": role, "content": content}
        if tool_calls:
            msg["tool_calls"] = tool_calls
        if thinking:
            msg["thinking"] = thinking
        self.conversation.append(msg)

    def is_approaching_limit(self) -> bool:
        return self.iteration >= (self.max_iterations - 3)

    def increment_iteration(self) -> None:
        self.iteration += 1
    
    def truncate_conversation(self, max_messages: int = 50) -> None:
        """
        Truncate conversation history to prevent token overflow.

        Strategy (sandwich):
        - All core system messages are always kept (prompt, tool catalog, etc.)
        - Ephemeral system messages (workspace, targets, history) collapsed to most recent
        - Non-system messages: keep first HEAD_KEEP + last (max_messages - HEAD_KEEP)
          This preserves the user's original request + early findings while keeping
          the freshest tool results. A separator note is injected at the cut point.
        """
        if len(self.conversation) <= max_messages:
            return

        EPHEMERAL_PREFIXES = (
            "[SYSTEM: WORKSPACE",
            "[SYSTEM: ACTIVE_TARGET",
            "[SYSTEM: ADDITIONAL_TARGETS",
            "[SYSTEM: RECENT EXECUTIONS",
        )

        core_system: list[dict] = []
        ephemeral_system: list[dict] = []
        other_messages: list[dict] = []

        for msg in self.conversation:
            if msg.get("role") == "system":
                content = msg.get("content", "")
                if any(content.startswith(p) for p in EPHEMERAL_PREFIXES):
                    ephemeral_system.append(msg)
                else:
                    core_system.append(msg)
            else:
                other_messages.append(msg)

        # Keep only the last ephemeral workspace/history message to avoid unbounded growth
        if ephemeral_system:
            ephemeral_system = [ephemeral_system[-1]]

        # Sandwich: head (initial context) + tail (recent context)
        # HEAD_KEEP = 4 preserves: first user message + first assistant reply + initial tool results
        HEAD_KEEP = 4
        if len(other_messages) > max_messages:
            dropped = len(other_messages) - max_messages
            head = other_messages[:HEAD_KEEP]
            tail = other_messages[-(max_messages - HEAD_KEEP):]
            separator = {
                "role": "system",
                "content": (
                    f"[SYSTEM: {dropped} intermediate messages removed to manage context. "
                    "Early task context preserved above; recent tool results below.]"
                ),
            }
            other_messages = head + [separator] + tail

        self.conversation = core_system + ephemeral_system + other_messages
        logger.info(f"Truncated conversation to {len(self.conversation)} messages (dropped {len(other_messages) - max_messages if len(other_messages) > max_messages else 0})")


class AgentLoop:
    """
    Core agent loop orchestrating LLM ↔ tool execution using Ollama SDK logic.
    Refactored for structural robustness and state management.
    """

    # Compiled once at class level — used to extract embedded <tool_call>…</tool_call> blocks
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
        self._executed_tool_counts: dict[tuple[str, str], int] = {}  # call-count dedup (O(1))
        self._initial_messages: list[dict[str, Any]] = []  # Snapshot after initialize()
        self._stop_requested: bool = False
        self._consecutive_failures: int = 0  # tracks back-to-back tool failures

    async def stop(self) -> None:
        """
        Force stop the agent loop and kill running tools.
        Called by /api/stop.
        """
        logger.warning("Stopping Agent Loop...")
        self._stop_requested = True
        # Kill running tools in container — this causes execute() to return,
        # which will unblock the while loop on the next iteration check.
        if self.engine:
            await self.engine.force_stop()


    async def initialize(self) -> None:
        """Initialize agent: load system prompt and discover tools."""
        self.state.conversation = [{"role": "system", "content": get_system_prompt()}]
        engine_tools = await self.engine.discover_tools()
        self._tools_ollama = self.engine.tools_to_ollama_format(engine_tools)
        
        if self.engine:
            self.state.add_message(
                "system",
                "[SYSTEM: EXECUTE_COMMAND_AVAILABLE=yes]"
            )

        # Inject browser_action tool definition
        browser_tool_def = {
            "type": "function",
            "function": {
                "name": "browser_action",
                "description": "Control a headless browser to navigate, interact, or extract data from websites.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "action": {
                            "type": "string",
                            "enum": ["launch", "goto", "click", "type", "scroll_down", "scroll_up", "back", "forward", "new_tab", "switch_tab", "close_tab", "wait", "execute_js", "double_click", "hover", "press_key", "save_pdf", "get_console_logs", "view_source", "close", "list_tabs"],
                            "description": "The action to perform."
                        },
                        "url": {"type": "string", "description": "URL for launch/goto/new_tab."},
                        "coordinate": {"type": "string", "description": "x,y coordinates for click/hover."},
                        "text": {"type": "string", "description": "Text to type."},
                        "tab_id": {"type": "string", "description": "Tab ID to target."},
                        "js_code": {"type": "string", "description": "JavaScript code to execute."},
                        "duration": {"type": "number", "description": "Duration to wait in seconds."},
                        "key": {"type": "string", "description": "Key to press."},
                        "file_path": {"type": "string", "description": "Path to save PDF."},
                        "clear": {"type": "boolean", "description": "Clear logs after fetching."}
                    },
                    "required": ["action"]
                }
            }
        }
        
        # Inject local filesystem tools
        create_file_def = {
            "type": "function",
            "function": {
                "name": "create_file",
                "description": "Create a new file in the workspace. Overwrites if exists.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "description": "File path (relative to workspace/ or absolute within workspace/)"},
                        "content": {"type": "string", "description": "Content to write to the file."}
                    },
                    "required": ["path", "content"]
                }
            }
        }

        read_file_def = {
            "type": "function",
            "function": {
                "name": "read_file",
                "description": "Read content of a file from the workspace.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "description": "File path to read."}
                    },
                    "required": ["path"]
                }
            }
        }

        web_search_def = {
            "type": "function",
            "function": {
                "name": "web_search",
                "description": (
                    "Search the web using DuckDuckGo. Use this to research payloads, "
                    "CVEs, exploit techniques, WAF bypasses, tool flags, or any "
                    "information needed during security testing."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "query": {
                            "type": "string",
                            "description": "Search query string.",
                        },
                        "max_results": {
                            "type": "integer",
                            "description": "Maximum results to return (default: 5, max: 10).",
                        },
                    },
                    "required": ["query"],
                },
            },
        }

        # Inject create_vulnerability_report tool definition
        vuln_tool_def = {
            "type": "function",
            "function": {
                "name": "create_vulnerability_report",
                "description": """Create a vulnerability report for a discovered security issue.

IMPORTANT: This tool checks for duplicate reports by title — a report with the same title as an existing one will be rejected. Do NOT attempt to re-submit a rejected report; move on to testing other areas.

Use this tool to document a specific fully verified security vulnerability.

DO NOT USE:
- For general security observations without specific vulnerabilities
- When you don't have concrete vulnerability details
- When you don't have a proof of concept, or still not 100% sure if it's a vulnerability
- For tracking multiple vulnerabilities (create separate reports)
- For reporting multiple vulnerabilities at once. Use a separate create_vulnerability_report for each vulnerability.
- To re-report a vulnerability that was already reported

DEDUPLICATION: If this tool returns with success=false and mentions a duplicate or existing title, DO NOT attempt to re-submit. Move on to testing other areas.

Professional, customer-facing report rules (PDF-ready):
- Do NOT include internal or system details: never mention local or absolute paths (e.g., "/workspace"), internal tools, agents, orchestrators, sandboxes, models, system prompts/instructions, connection issues, internal errors/logs/stack traces, or tester machine environment details.
- Tone and style: formal, objective, third-person, vendor-neutral, concise. No runbooks, checklists, or engineering notes. Avoid headings like "QUICK", "Approach", or "Techniques" that read like internal guidance.
- Use a standard penetration testing report structure per finding:
  1) Overview
  2) Severity and CVSS (vector only)
  3) Affected asset(s)
  4) Technical details
  5) Proof of concept (repro steps plus code)
  6) Impact
  7) Remediation
  8) Evidence (optional request/response excerpts, etc.) in the technical analysis field.
- Numbered steps are allowed ONLY within the proof of concept. Elsewhere, use clear, concise paragraphs suitable for customer-facing reports.
- Language must be precise and non-vague; avoid hedging.""",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "title": {
                            "type": "string",
                            "description": "Clear, specific title (e.g., \"SQL Injection in /api/users Login Parameter\"). But not too long. Don't mention CVE number in the title."
                        },
                        "description": {
                            "type": "string",
                            "description": "Comprehensive description of the vulnerability and how it was discovered"
                        },
                        "impact": {
                            "type": "string",
                            "description": "Impact assessment: what attacker can do, business risk, data at risk"
                        },
                        "target": {
                            "type": "string",
                            "description": "Affected target: URL, domain, or Git repository"
                        },
                        "technical_analysis": {
                            "type": "string",
                            "description": "Technical explanation of the vulnerability mechanism and root cause"
                        },
                        "poc_description": {
                            "type": "string",
                            "description": "Step-by-step instructions to reproduce the vulnerability"
                        },
                        "poc_script_code": {
                            "type": "string",
                            "description": "Actual proof of concept code, exploit, payload, or script that demonstrates the vulnerability. Python code."
                        },
                        "remediation_steps": {
                            "type": "string",
                            "description": "Specific, actionable steps to fix the vulnerability"
                        },
                        "attack_vector": {
                            "type": "string",
                            "enum": ["N", "A", "L", "P"],
                            "description": "CVSS Attack Vector - How the vulnerability is exploited:\nN = Network (remotely exploitable)\nA = Adjacent (same network segment)\nL = Local (local access required)\nP = Physical (physical access required)"
                        },
                        "attack_complexity": {
                            "type": "string",
                            "enum": ["L", "H"],
                            "description": "CVSS Attack Complexity - Conditions beyond attacker's control:\nL = Low (no special conditions)\nH = High (special conditions must exist)"
                        },
                        "privileges_required": {
                            "type": "string",
                            "enum": ["N", "L", "H"],
                            "description": "CVSS Privileges Required - Level of privileges needed:\nN = None (no privileges needed)\nL = Low (basic user privileges)\nH = High (admin privileges)"
                        },
                        "user_interaction": {
                            "type": "string",
                            "enum": ["N", "R"],
                            "description": "CVSS User Interaction - Does exploit require user action:\nN = None (no user interaction needed)\nR = Required (user must perform some action)"
                        },
                        "scope": {
                            "type": "string",
                            "enum": ["U", "C"],
                            "description": "CVSS Scope - Can the vulnerability affect resources beyond its security scope:\nU = Unchanged (only affects the vulnerable component)\nC = Changed (affects resources beyond vulnerable component)"
                        },
                        "confidentiality": {
                            "type": "string",
                            "enum": ["N", "L", "H"],
                            "description": "CVSS Confidentiality Impact - Impact to confidentiality:\nN = None (no impact)\nL = Low (some information disclosure)\nH = High (all information disclosed)"
                        },
                        "integrity": {
                            "type": "string",
                            "enum": ["N", "L", "H"],
                            "description": "CVSS Integrity Impact - Impact to integrity:\nN = None (no impact)\nL = Low (data can be modified but scope is limited)\nH = High (total loss of integrity)"
                        },
                        "availability": {
                            "type": "string",
                            "enum": ["N", "L", "H"],
                            "description": "CVSS Availability Impact - Impact to availability:\nN = None (no impact)\nL = Low (reduced performance or interruptions)\nH = High (total loss of availability)"
                        },
                        "endpoint": {
                            "type": "string",
                            "description": "API endpoint(s) or URL path(s) (e.g., \"/api/login\") - for web vulnerabilities, or Git repository path(s) - for code vulnerabilities"
                        },
                        "method": {
                            "type": "string",
                            "description": "HTTP method(s) (GET, POST, etc.) - for web vulnerabilities."
                        },
                        "cve": {
                            "type": "string",
                            "description": "CVE identifier (e.g., \"CVE-2024-1234\"). Make sure it's a valid CVE. Use web search or vulnerability databases to make sure it's a valid CVE number."
                        }
                    },
                    "required": ["title", "description", "impact", "target", "technical_analysis", "poc_description", "poc_script_code", "remediation_steps", "attack_vector", "attack_complexity", "privileges_required", "user_interaction", "scope", "confidentiality", "integrity", "availability"]
                }
            }
        }
        
        if self._tools_ollama is None:
            self._tools_ollama = []
        self._tools_ollama.append(browser_tool_def)
        self._tools_ollama.append(create_file_def)
        self._tools_ollama.append(read_file_def)
        self._tools_ollama.append(web_search_def)
        self._tools_ollama.append(vuln_tool_def)
            
        # DEDUPLICATION: Ensure no duplicate tool names
        unique_tools = {}
        for t in self._tools_ollama:
            t_name = t["function"]["name"]
            unique_tools[t_name] = t
        self._tools_ollama = list(unique_tools.values())
        
        logger.info(f"Agent initialized with {len(self._tools_ollama or [])} tools")

        # Inject minimal tool catalog (just names) so model knows what's registered
        tool_names = [t["function"]["name"] for t in self._tools_ollama]
        self.state.add_message(
            "system",
            f"[SYSTEM: REGISTERED TOOLS]\n{', '.join(tool_names)}"
        )

        # Save snapshot so reset() can restore core system messages
        self._initial_messages = list(self.state.conversation)


    def reset(self) -> None:
        """Reset conversation history, restoring all core system messages."""
        self.state = AgentState()
        # Restore full initial snapshot (main prompt + tool registration messages)
        # so the model still knows which tools are available after reset.
        if self._initial_messages:
            self.state.conversation = list(self._initial_messages)
        self._executed_tool_counts.clear()
        self._last_output_file = None

    async def process_message(self, user_message: str) -> AsyncIterator[AgentEvent]:
        """
        Process user message through agent loop using accumulated partial fields.
        """
        try:
            if not self._tools_ollama:
                await self.initialize()

            # Update or lock onto target — support multiple targets in one message
            all_targets = self._extract_targets_from_text(user_message)
            extracted_target = all_targets[0] if all_targets else None
            if extracted_target:
                self.state.active_target = extracted_target

            cfg = get_config()

            # Implement deep_recon_autostart
            if cfg.deep_recon_autostart and extracted_target and user_message.strip() == extracted_target:
                logger.info(f"Auto-starting deep recon for {extracted_target}")
                user_message = f"Perform a comprehensive full deep recon and vulnerability scan on {extracted_target}. Use all available tools."

            # Always inject workspace state if we have a target.
            # Remove stale ephemeral system messages first so they don't accumulate.
            EPHEMERAL_PREFIXES = (
                "[SYSTEM: WORKSPACE",
                "[SYSTEM: ACTIVE_TARGET",
                "[SYSTEM: ADDITIONAL_TARGETS",
            )
            self.state.conversation = [
                msg for msg in self.state.conversation
                if not (msg.get("role") == "system" and
                        any(msg.get("content", "").startswith(p) for p in EPHEMERAL_PREFIXES))
            ]

            # If multiple targets were specified, inject them so the model is aware
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
            self._stop_requested = False
            self._consecutive_failures = 0
            # Clear dedup counts per message so identical commands in follow-up
            # messages are not incorrectly blocked by previous runs.
            self._executed_tool_counts.clear()

            while self.state.iteration < self.state.max_iterations:
                if self._stop_requested:
                    yield AgentEvent(type="error", data={"message": "Agent stopped by user."})
                    yield AgentEvent(type="done", data={})
                    return

                self.state.increment_iteration()

                # ✅ OPTIMIZATION: Truncate conversation history every 20 iterations
                # This prevents token overflow and Ollama slowdown
                if self.state.iteration % 20 == 0:
                    self.state.truncate_conversation(max_messages=50)

                # Inject compact recent execution history every 10 iterations so the
                # model doesn't lose track of what it has already done.
                if self.state.iteration > 1 and self.state.iteration % 10 == 0 and self.state.tool_history:
                    history_ctx = self._build_recent_history_context(last_n=10)
                    if history_ctx:
                        self.state.conversation = [
                            msg for msg in self.state.conversation
                            if not msg.get("content", "").startswith("[SYSTEM: RECENT EXECUTIONS]")
                        ]
                        self.state.conversation.append({"role": "system", "content": history_ctx})
                
                # Iteration limit warning (functional, not a prompt)
                if self.state.is_approaching_limit() and not self.state.warnings_sent:
                    self.state.warnings_sent = True
                    remaining = self.state.max_iterations - self.state.iteration
                    self.state.conversation.append({
                        "role": "system",
                        "content": f"[SYSTEM: {remaining} iterations remaining]"
                    })

                # --- STEP EXECUTION ---
                # Accumulators for this turn
                thinking_acc = ""
                content_acc = ""
                tool_calls_acc = []
                in_thinking_tag = False
                # Carry buffer: holds partial tag fragments across chunk boundaries
                _carry = ""

                # Stream response from SDK
                try:
                    tools_for_llm = self._tools_ollama

                    async for chunk in self.ollama.chat_stream(
                        messages=self.state.conversation,
                        tools=tools_for_llm,
                        options={
                            "num_ctx": cfg.ollama_num_ctx,
                            "temperature": cfg.ollama_temperature,
                            "num_predict": cfg.ollama_num_predict,
                        },
                        think=cfg.ollama_enable_thinking,
                    ):
                        if hasattr(chunk, 'model_dump'): chunk_data = chunk.model_dump()
                        elif isinstance(chunk, dict): chunk_data = chunk
                        else: chunk_data = dict(chunk)

                        message = chunk_data.get("message", {})
                        chunk_thinking = message.get("thinking")
                        chunk_tool_calls = message.get("tool_calls")
                        chunk_content = message.get("content", "")

                        if chunk_thinking:
                            thinking_acc += chunk_thinking
                            yield AgentEvent(type="thinking", data={"content": chunk_thinking})

                        if chunk_content:
                            # Prepend any carry buffer from previous chunk
                            text = _carry + chunk_content
                            _carry = ""

                            # Detect partial tag at end of text to defer to next chunk.
                            # Check suffixes of length 1..8 (longest tag fragment we care about).
                            _OPEN_TAG = "<think>"
                            _CLOSE_TAG = "</think>"
                            for partial_len in range(min(len(text), 8), 0, -1):
                                suffix = text[-partial_len:]
                                if _OPEN_TAG.startswith(suffix) or _CLOSE_TAG.startswith(suffix):
                                    _carry = suffix
                                    text = text[:-partial_len]
                                    break

                            # Process the safe (complete) portion of text
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
                            for tc in chunk_tool_calls:
                                tool_calls_acc.append(tc)

                    # Flush any remaining carry buffer as content
                    if _carry:
                        content_acc += _carry
                        yield AgentEvent(type="text", data={"content": _carry})
                        _carry = ""

                except Exception as stream_err:
                    error_msg = f"Model connection error: {str(stream_err)}"
                    logger.error(f"Ollama stream error: {stream_err}")
                    # CRITICAL: Send actual error to UI so user knows WHY it failed (e.g. 400 Bad Request)
                    yield AgentEvent(type="error", data={"message": error_msg})
                    yield AgentEvent(type="done", data={})
                    return

                if not content_acc and not tool_calls_acc and not thinking_acc:
                    yield AgentEvent(type="error", data={"message": "Empty response from model."})
                    yield AgentEvent(type="done", data={})
                    return

                # ── Fallback: extract <tool_call>…</tool_call> from text/thinking ──
                # Some models (qwen, deepseek-r1) emit tool calls as XML text instead of
                # using the Ollama structured tool_calls field. We detect and promote them.
                if not tool_calls_acc:
                    # Scan both visible content and thinking for embedded tags.
                    # Only promote tool calls whose name is in the registered tool list —
                    # this prevents false positives from example code or explanatory text.
                    _registered_tool_names = {
                        t["function"]["name"] for t in (self._tools_ollama or [])
                    }
                    _search_text = content_acc + "\n" + thinking_acc
                    _matches = self._TOOL_CALL_RE.findall(_search_text)
                    for raw_json in _matches:
                        try:
                            parsed = json.loads(raw_json)
                            # Normalise to Ollama tool_calls format
                            tc_name = parsed.get("name") or parsed.get("function", {}).get("name", "")
                            tc_args = (
                                parsed.get("arguments")
                                or parsed.get("parameters")
                                or parsed.get("function", {}).get("arguments", {})
                                or {}
                            )
                            # Only promote if the tool is actually registered
                            if tc_name and tc_name in _registered_tool_names:
                                tool_calls_acc.append({
                                    "function": {"name": tc_name, "arguments": tc_args}
                                })
                                logger.info(f"[fallback] Extracted embedded tool_call: {tc_name}")
                            elif tc_name:
                                logger.debug(f"[fallback] Ignoring unknown tool in embedded tag: {tc_name}")
                        except json.JSONDecodeError:
                            logger.warning(f"[fallback] Could not parse embedded tool_call: {raw_json[:120]}")

                    if tool_calls_acc:
                        # Strip the raw <tool_call>…</tool_call> tags from visible content
                        content_acc = self._TOOL_CALL_RE.sub("", content_acc).strip()
                        # Re-emit a clean text event so UI doesn't show raw XML
                        if not content_acc:
                            content_acc = ""

                # Strip [TASK_COMPLETE] from visible text (it's a control signal)
                _has_task_complete = "[TASK_COMPLETE]" in content_acc
                content_acc = content_acc.replace("[TASK_COMPLETE]", "").strip()

                # Record Assistant Message (with possibly-promoted tool_calls)
                self.state.add_message("assistant", content_acc, tool_calls_acc, thinking_acc)

                # --- TOOL EXECUTION PHASE ---
                if not tool_calls_acc:
                    # Model finished with no tool calls — pure text response, we're done.
                    if _has_task_complete:
                        logger.info("Agent emitted [TASK_COMPLETE] — stopping execution loop.")
                    yield AgentEvent(type="done", data={})
                    return

                # Execute Tools FIRST, then honour [TASK_COMPLETE].
                # This ensures a final reporting/tool call emitted together with
                # [TASK_COMPLETE] is not silently dropped.
                if not content_acc.strip():
                    tool_names = [tc["function"]["name"] for tc in tool_calls_acc]
                    yield AgentEvent(type="text", data={"content": f"Executing: {', '.join(tool_names)}..."})

                for tc in tool_calls_acc:
                    tool_name = tc["function"]["name"]
                    arguments = self._normalize_tool_args(tool_name, tc["function"]["arguments"], user_message)

                    # Validate arguments before wasting a tool execution
                    valid, arg_error = self._validate_tool_args(tool_name, arguments)
                    if not valid:
                        yield AgentEvent(type="tool_start", data={"tool": tool_name, "arguments": arguments})
                        yield AgentEvent(
                            type="tool_end",
                            data={
                                "tool": tool_name,
                                "success": False,
                                "duration": 0.0,
                                "result_preview": f"VALIDATION ERROR: {arg_error}",
                                "output_file": None,
                                "tool_counts": self.state.tool_counts,
                            },
                        )
                        self._consecutive_failures += 1
                        self._append_tool_result(
                            tool_name,
                            f"ARGUMENT VALIDATION FAILED: {arg_error}\nFix the arguments and retry.",
                            False,
                            tc.get("id"),
                        )
                        continue

                    yield AgentEvent(type="tool_start", data={"tool": tool_name, "arguments": arguments})
                    
                    # Handle local tools
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
                        # Valid Docker/engine tool (currently only 'execute')
                        success, duration, result, output_file = await self._execute_tool_and_record(tool_name, arguments)
                        self.state.missing_tool_count = 0
                    else:
                        # Unknown / hallucinated tool — give corrective error to LLM
                        self.state.missing_tool_count += 1
                        tool_list = ", ".join(
                            t["function"]["name"] for t in (self._tools_ollama or [])
                        )
                        if not tool_name:
                            error_msg = (
                                "CRITICAL ERROR: You just submitted an empty tool call (missing 'name'). "
                                "You MUST specify a valid tool name. "
                                f"Registered tools: {tool_list}."
                            )
                        else:
                            error_msg = (
                                f"Tool '{tool_name}' does not exist. "
                                f"Registered tools: {tool_list}. "
                                f"Use 'execute' to run any shell command in the sandbox."
                            )
                        
                        success, duration, result, output_file = (
                            False, 0.0,
                            {"success": False, "error": error_msg},
                            None,
                        )
                        if self.state.missing_tool_count >= cfg.agent_missing_tool_retry_limit:
                            yield AgentEvent(
                                type="error",
                                data={"message": f"Agent called unknown tool '{tool_name}' {self.state.missing_tool_count}x in a row. Stopping to prevent infinite loop."},
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

                    # Track consecutive failures — helps inject pivot messages
                    if success:
                        self._consecutive_failures = 0
                    else:
                        self._consecutive_failures += 1

                    # Build smart content string to send back to LLM
                    raw_command = arguments.get("command", "") if tool_name == "execute" else ""
                    content_str = self._smart_format_tool_result(tool_name, result, success, raw_command)

                    # If stuck in a failure loop, append a strong pivot directive
                    if not success and self._consecutive_failures >= 3:
                        content_str += (
                            f"\n\n[SYSTEM: {self._consecutive_failures} CONSECUTIVE FAILURES DETECTED] "
                            "MANDATORY: Stop using the current approach. "
                            "Switch to a completely different tool or strategy. "
                            "If all options are exhausted, document what was tried and emit [TASK_COMPLETE]."
                        )

                    # ── Task completion self-check ───────────────────────────────
                    # After the first successful tool, prompt the model to re-read
                    # its task scope classification and decide if it is done.
                    # This fires on every success so chain-creep reasoning is
                    # challenged at each step, not just at the start.
                    if success and self.state.tool_counts["total"] >= 1:
                        content_str += (
                            "\n\n[SYSTEM: SELF-CHECK] Re-read the user's original request. "
                            "Ask yourself: 'Did the user explicitly ask for the NEXT step I'm about to run?' "
                            "If YES → continue. "
                            "If NO → report the current results and emit [TASK_COMPLETE] now."
                        )
                    # ── End self-check ───────────────────────────────────────────

                    self._append_tool_result(tool_name, content_str, success, tc.get("id"))

                # After all tool calls are executed, honour [TASK_COMPLETE] signal
                if _has_task_complete:
                    logger.info("Agent emitted [TASK_COMPLETE] after tools — stopping execution loop.")
                    yield AgentEvent(type="done", data={})
                    return

            # Loop limit reached
            yield AgentEvent(type="error", data={"message": "Max tool iterations reached."})
            yield AgentEvent(type="done", data={})

        except Exception as e:
            logger.exception("Fatal error in agent loop")
            yield AgentEvent(type="error", data={"message": f"Fatal Agent Error: {str(e)}"})
            yield AgentEvent(type="done", data={})

    # ── New helper methods ──────────────────────────────────────────────────────

    _VALID_BROWSER_ACTIONS = frozenset({
        "launch", "goto", "click", "type", "scroll_down", "scroll_up", "back",
        "forward", "new_tab", "switch_tab", "close_tab", "wait", "execute_js",
        "double_click", "hover", "press_key", "save_pdf", "get_console_logs",
        "view_source", "close", "list_tabs",
    })

    def _validate_tool_args(self, tool_name: str, arguments: dict[str, Any]) -> tuple[bool, str | None]:
        """Validate tool arguments before execution.

        Returns (valid, error_message). Fast-path rejection for obviously wrong calls
        avoids wasting tool execution quota and gives the model clear correction feedback.
        """
        if tool_name == "execute":
            cmd = arguments.get("command", "")
            if not isinstance(cmd, str) or not cmd.strip():
                return False, "'command' must be a non-empty string."
            if len(cmd) > 20_000:
                return False, f"'command' is too long ({len(cmd)} chars). Split into smaller calls."

        elif tool_name == "browser_action":
            action = arguments.get("action", "")
            if action not in self._VALID_BROWSER_ACTIONS:
                return False, (
                    f"Invalid browser action '{action}'. "
                    f"Valid actions: {sorted(self._VALID_BROWSER_ACTIONS)}"
                )
            if action in ("goto", "launch", "new_tab") and not arguments.get("url", "").strip():
                return False, f"browser_action '{action}' requires a non-empty 'url'."
            if action == "click" and not arguments.get("coordinate", "").strip():
                return False, "browser_action 'click' requires 'coordinate' (format: 'x,y')."
            if action == "type" and arguments.get("text") is None:
                return False, "browser_action 'type' requires a 'text' argument."
            if action == "switch_tab" and not arguments.get("tab_id", "").strip():
                return False, "browser_action 'switch_tab' requires 'tab_id'."
            if action == "press_key" and not arguments.get("key", "").strip():
                return False, "browser_action 'press_key' requires 'key'."

        elif tool_name == "web_search":
            if not arguments.get("query", "").strip():
                return False, "'query' must be a non-empty string."

        elif tool_name == "create_file":
            if not arguments.get("path", "").strip():
                return False, "'path' must be a non-empty string."
            if "content" not in arguments:
                return False, "'content' argument is required."

        elif tool_name == "read_file":
            if not arguments.get("path", "").strip():
                return False, "'path' must be a non-empty string."

        return True, None

    def _smart_format_tool_result(
        self,
        tool_name: str,
        result: dict[str, Any],
        success: bool,
        command: str = "",
    ) -> str:
        """Build a smart, model-friendly content string from a tool result.

        - Failures get targeted fix suggestions based on error pattern.
        - Empty execute output gets an explicit 'no results' message.
        - Large outputs get smart head+tail truncation with line counts.
        """
        MAX_TOTAL = 8000

        if not success:
            error_msg  = result.get("error",  "") or ""
            stderr_msg = result.get("stderr", "") or ""
            stdout_msg = result.get("stdout", "") or ""
            exit_code  = result.get("exit_code", "")

            parts = [f"COMMAND FAILED (exit code: {exit_code})"]
            if error_msg.strip():
                parts.append(f"ERROR: {error_msg.strip()}")
            if stderr_msg.strip() and stderr_msg.strip() != error_msg.strip():
                parts.append(f"STDERR: {stderr_msg.strip()[:2000]}")
            if stdout_msg.strip():
                parts.append(f"STDOUT: {stdout_msg.strip()[:2000]}")

            # Targeted tips based on common error patterns
            combined = (error_msg + stderr_msg + stdout_msg).lower()
            tool_bin  = command.strip().split()[0] if command.strip() else "tool"
            if "command not found" in combined or (
                "no such file" in combined and "or directory" in combined and tool_bin
            ):
                parts.append(
                    f"TIP: '{tool_bin}' may not be installed. "
                    f"Verify: which {tool_bin} | "
                    f"Install: sudo apt-get install -y {tool_bin} or pip3/go install equivalent."
                )
            elif "permission denied" in combined and not command.strip().startswith("sudo"):
                parts.append(f"TIP: Retry with elevated privileges: sudo {command.strip()[:80]}")
            elif "connection refused" in combined or "connection timed out" in combined:
                parts.append(
                    "TIP: Target may be down or filtering. "
                    "Verify reachability: curl -I --max-time 5 <url>"
                )
            elif any(k in combined for k in ("invalid option", "unknown flag", "unrecognized", "syntax error")):
                parts.append(f"TIP: Flag/syntax error. Check: {tool_bin} --help | head -40")
            elif "no route to host" in combined:
                parts.append("TIP: Network unreachable from container. Check Docker network settings.")
            else:
                parts.append(
                    "ACTION REQUIRED: Analyze the error. "
                    "Common causes: wrong flags (run `tool --help`), missing file, "
                    "permission denied, network timeout."
                )

            return "\n".join(parts)

        # ── Success path ────────────────────────────────────────────────────────

        if tool_name == "execute":
            # Prefer stdout; fallback to result string
            stdout = (
                result.get("stdout", "")
                or (result.get("result", "") if isinstance(result.get("result"), str) else "")
                or ""
            )

            if not stdout.strip():
                return (
                    "Command executed successfully with NO OUTPUT.\n"
                    "This means:\n"
                    "- The tool found 0 results (not an error)\n"
                    "- Output was written directly to a file (check: ls output/)\n"
                    "- Or the tool ran silently\n"
                    "DO NOT invent results. If a file was written, read it with: cat output/<file>"
                )

            lines = stdout.strip().split("\n")
            total = len(lines)

            if total > 100:
                head = "\n".join(lines[:60])
                tail = "\n".join(lines[-15:])
                body = (
                    f"{head}\n\n"
                    f"... [{total - 75} more lines] ...\n\n"
                    f"{tail}\n\n"
                    f"TOTAL OUTPUT: {total} lines. Full output saved to file."
                )
            else:
                body = stdout.strip()

            if len(body) > MAX_TOTAL:
                body = body[:MAX_TOTAL] + "\n... (truncated)"
            return body

        # Non-execute tool (browser, web_search, reporting, filesystem)
        if isinstance(result, dict) and "result" in result and isinstance(result["result"], str):
            content = result["result"]
        else:
            content = json.dumps(result, default=str)

        if len(content) > MAX_TOTAL:
            content = content[:MAX_TOTAL] + "\n... (truncated)"
        return content

    def _build_recent_history_context(self, last_n: int = 10) -> str:
        """Build a compact summary of the most recent tool executions.

        Injected periodically so the model doesn't forget what it has already
        done and doesn't repeat completed work.
        """
        recent = self.state.tool_history[-last_n:] if self.state.tool_history else []
        if not recent:
            return ""

        lines = [f"[SYSTEM: RECENT EXECUTIONS — last {len(recent)} calls]"]
        for i, rec in enumerate(recent, 1):
            status = "OK" if rec.status == "success" else "FAIL"
            detail = ""
            if rec.tool_name == "execute":
                cmd = rec.arguments.get("command", "")
                # Strip the cd /workspace/... prefix to save tokens
                cmd = re.sub(r"^cd\s+/workspace/[^\s]+\s*&&\s*", "", cmd).strip()
                detail = f": {cmd[:100]}"
            elif rec.tool_name == "browser_action":
                detail = f" action={rec.arguments.get('action','?')} url={rec.arguments.get('url','')}"
            elif rec.tool_name == "web_search":
                detail = f": {rec.arguments.get('query','')[:60]}"
            lines.append(f"  {i}. [{status}] {rec.tool_name}{detail} ({rec.duration:.1f}s)")

        return "\n".join(lines)

    # ── End new helpers ─────────────────────────────────────────────────────────

    def _truncate_result(self, result: dict[str, Any], max_len: int = 500) -> str:
        """Create a clean summary of the tool result for TUI display."""
        if not result.get("success", False):
            # Build informative error from all available fields
            error = result.get('error', '') or ''
            stderr = result.get('stderr', '') or ''
            stdout = result.get('stdout', '') or ''
            exit_code = result.get('exit_code', '')
            
            # Use the most informative source
            detail = error.strip() or stderr.strip() or stdout.strip()
            if not detail:
                detail = f"Command failed (exit code: {exit_code})"
            
            # Truncate if too long
            if len(detail) > max_len:
                detail = detail[:max_len] + '... (truncated)'
            
            return f"ERROR: {detail}"

        res_data = result.get("result", "")

        # Docker execute returns result as a plain string (stdout_str).
        # Some internal tools wrap in a dict with a "stdout" key — handle both.
        if isinstance(res_data, dict) and "stdout" in res_data:
            stdout = res_data["stdout"].strip()
        elif isinstance(res_data, str):
            stdout = res_data.strip()
        else:
            stdout = ""

        if stdout:
            if len(stdout) > max_len * 2:
                summary = ""
                if "subdomains found" in stdout.lower():
                    summary = "(Subdomain Scan Results) "
                elif "vulnerabilities found" in stdout.lower():
                    summary = "(Scan Results) "
                return f"Success {summary}-- Output too large ({len(stdout)} chars). Check output file."

            lines = [l for l in stdout.split("\n") if l.strip()]
            count = len(lines)
            is_list = all(len(l) < 100 for l in lines[:5]) if lines else False

            if count > 10:
                if is_list:
                    preview = "\n".join(f"  {line}" for line in lines[:8])
                    return f"Success -- Found {count} items.\n{preview}\n  ... ({count-8} more)"
                else:
                    preview = "\n".join(f"  {line}" for line in lines[:8])
                    return f"Success\n{preview}\n  ... ({count-8} more lines)"
            else:
                formatted_lines = "\n".join(f"  {line}" for line in lines)
                return f"Success\n{formatted_lines}"

        if not res_data:
            return "Command executed (no output)."
        
        try:
            text = json.dumps(result, default=str)
            if len(text) > max_len:
                return f"Result too large ({len(text)} chars). Check output file."
            return text
        except Exception:
             return "Result (unserializable). Check output file."

    def get_stats(self) -> dict[str, Any]:
        return {
            "message_count": len(self.state.conversation),
            "tool_counts": self.state.tool_counts,
        }

    def _format_tool_calls_for_critic(self, tool_calls: list[dict[str, Any]]) -> list[dict[str, Any]]:
        formatted: list[dict[str, Any]] = []
        for tc in tool_calls:
            fn = tc.get("function", {})
            name = fn.get("name")
            args = fn.get("arguments")
            if isinstance(args, str):
                try: args = json.loads(args)
                except: args = {}
            formatted.append({"name": name, "arguments": args})
        return formatted

    async def _execute_local_browser_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> tuple[bool, float, dict[str, Any], str | None]:
        """Execute the local browser tool, record history, and persist output."""
        self._last_output_file = None
        
        # Check for duplicates using call-count
        args_key = (tool_name, json.dumps(arguments, sort_keys=True, default=str))
        allow_repeat = arguments.get("action") in ["wait", "scroll_down", "scroll_up", "get_console_logs", "execute_js"]
        if not allow_repeat:
            count = self._executed_tool_counts.get(args_key, 0)
            limit = get_config().agent_repeat_tool_call_limit
            if count >= limit:
                return False, 0.0, {"success": False, "error": f"Duplicate tool execution prevented (already ran {count}x)."}, None

        start_time = time.time()
        try:
            # Execute local browser action
            # Arguments are already normalized
            result = await asyncio.to_thread(browser_action, **arguments)
            
            # Check for error in result dict
            if isinstance(result, dict) and "error" in result:
                success = False
            else:
                success = True
                
            # Wrap in standard result format if not already
            if "success" not in result:
                result = {"success": success, "result": result}
            
            try:
                self._save_tool_output(tool_name, arguments, result)
            except Exception:
                pass

        except Exception as e:
            success = False
            result = {"success": False, "error": str(e)}
            logger.error(f"Browser tool exec error: {e}")

        duration = time.time() - start_time

        # Optimize memory: Truncate large results in history if saved to file
        history_result = result
        if success and self._last_output_file:
             res_str = str(result)
             if len(res_str) > 10000:
                 history_result = {
                     "success": True, 
                     "result": f"<Result truncated due to size. Full output in {self._last_output_file}>",
                     "truncated": True
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
        self.state.tool_counts["exec"] += 1 # Count as exec for now, or total?
        self.state.tool_counts["total"] += 1

        # Increment call count on success
        if success:
            self._executed_tool_counts[args_key] = self._executed_tool_counts.get(args_key, 0) + 1

        return success, duration, result, self._last_output_file




    async def _execute_filesystem_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> tuple[bool, float, dict[str, Any], str | None]:
        """Execute local filesystem tools."""
        self._last_output_file = None
        start_time = time.time()
        
        try:
            # Context-aware path handling
            path_arg = arguments.get("path", "")
            
            # 1. Strip redundant workspace/ prefix if present (AI often adds it)
            if path_arg.startswith("workspace/"):
                path_arg = path_arg[10:]
            elif path_arg.startswith("/workspace/"):
                path_arg = path_arg[11:]
            
            # 2. Inject active target if available and not already in path
            if self.state.active_target:
                # Check if path already starts with target
                if not path_arg.startswith(self.state.active_target) and not os.path.isabs(path_arg):
                    path_arg = os.path.join(self.state.active_target, path_arg)
            
            arguments["path"] = path_arg

            if tool_name == "create_file":
                result = await asyncio.to_thread(create_file, **arguments)
            elif tool_name == "read_file":
                result = await asyncio.to_thread(read_file, **arguments)
            else:
                result = {"success": False, "error": f"Unknown filesystem tool: {tool_name}"}
                
            success = result.get("success", False)
            
            # Save output if needed
            try:
                self._save_tool_output(tool_name, arguments, result)
            except Exception:
                pass

        except Exception as e:
            success = False
            result = {"success": False, "error": str(e)}
            logger.error(f"Filesystem tool exec error: {e}")

        duration = time.time() - start_time
        
        # Optimize memory for read_file
        history_result = result
        if tool_name == "read_file" and success:
             content = result.get("result", "")
             if len(content) > 2000:
                 history_result = {
                     "success": True,
                     "result": f"<File content loaded ({len(content)} chars). Truncated in history.>",
                     "truncated": True
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

        return success, duration, result, self._last_output_file

    async def _execute_web_search_tool(
        self,
        arguments: dict[str, Any],
    ) -> tuple[bool, float, dict[str, Any], str | None]:
        """Execute the web_search tool via DuckDuckGo."""
        start_time = time.time()
        try:
            query = arguments.get("query", "")
            max_results = arguments.get("max_results", 5)
            result = await web_search(query=query, max_results=max_results)
            success = result.get("success", False)
        except Exception as e:
            success = False
            result = {"success": False, "error": str(e)}
            logger.error(f"Web search tool error: {e}")

        duration = time.time() - start_time
        self.state.tool_history.append(
            ToolExecution(
                tool_name="web_search",
                arguments=arguments,
                result=result,
                duration=duration,
                status="success" if success else "error",
            )
        )
        self.state.tool_counts["exec"] += 1
        self.state.tool_counts["total"] += 1
        return success, duration, result, None

    async def _execute_report_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> tuple[bool, float, dict[str, Any], str | None]:
        """Execute the vulnerability reporting tool."""
        self._last_output_file = None
        start_time = time.time()
        
        try:
            # Inject workspace root if needed, or let tool handle it
            # The tool uses os.getcwd()/workspace by default which matches our structure
            
            # Execute
            result = await asyncio.to_thread(create_vulnerability_report, **arguments)
            
            success = result.get("success", False)
            
            # We don't necessarily need to save the JSON output of the report tool 
            # because the tool ITSELF saves a Markdown file. 
            # But for history consistency, we can save the JSON receipt.
            try:
                self._save_tool_output(tool_name, arguments, result)
            except Exception:
                pass

        except Exception as e:
            success = False
            result = {"success": False, "error": str(e)}
            logger.error(f"Reporting tool exec error: {e}")

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

        return success, duration, result, self._last_output_file

    async def _execute_tool_and_record(
        self,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> tuple[bool, float, dict[str, Any], str | None]:
        """Execute a tool via Docker engine, record history, and persist output."""
        self._last_output_file = None
        # Duplicate check using call-count
        args_key = (tool_name, json.dumps(arguments, sort_keys=True, default=str))
        count = self._executed_tool_counts.get(args_key, 0)
        limit = get_config().agent_repeat_tool_call_limit
        if count >= limit:
            return False, 0.0, {"success": False, "error": f"Duplicate tool execution prevented (already ran {count}x)."}, None



        if tool_name == "execute":
            # 1. Enforce Workspace Execution inside Docker container
            # If we have an active target, prepend "cd /workspace/<target> && ..."
            # Docker mounts ./workspace → /workspace
            
            cmd = arguments.get("command", "")

            if self.state.active_target and cmd:
                # Check if already cd-ing
                if not cmd.strip().startswith("cd "):
                    workspace_dir = f"/workspace/{self.state.active_target}"
                    
                    # Create directory on host if it doesn't exist (Docker mounts it)
                    host_workspace = get_workspace_root() / self.state.active_target
                    try:
                        host_workspace.mkdir(parents=True, exist_ok=True)
                    except Exception:
                        pass

                    # Auto-create required subdirectories to prevent AI mkdir errors
                    for subdir in ["output", "command", "tools", "vulnerabilities"]:
                        try:
                            (host_workspace / subdir).mkdir(parents=True, exist_ok=True)
                        except Exception:
                            pass
                            
                    # Modify command
                    # Use '&&' to ensure we only run if cd succeeds
                    # Quote the path just in case
                    
                    # CRITICAL FIX: Strip redundant workspace/<target> from command
                    # because we are now INSIDE that directory.
                    # Example Regex strips: 'mkdir workspace/feedly/out' -> 'mkdir out'
                    # and '-o /workspace/feedly.com/out' -> '-o out'
                    import re
                    # Match optional leading slash, 'workspace/', and anything up to the next slash.
                    cmd = re.sub(r'(?<!\S)/?workspace/[^/\s]+/', '', cmd)
                    arguments["command"] = f"cd {workspace_dir} && {cmd}"
                    logger.info(f"Enforced workspace context: {arguments['command']}")

        start_time = time.time()
        try:
            result = await self.engine.execute_tool(tool_name, arguments)
            success = result.get("success", False)
            try:
                self._save_tool_output(tool_name, arguments, result)
            except Exception:
                pass

            # Errors are returned as-is — system_prompt handles error recovery guidance

        except Exception as e:
            success = False
            result = {"success": False, "error": str(e)}
            logger.error(f"Tool exec error: {e}")

        duration = time.time() - start_time

        # Optimize memory: Truncate large results in history if saved to file
        history_result = result
        if success and self._last_output_file:
             # Rough size check
             res_str = str(result)
             


             if len(res_str) > 10000: # 10KB limit for history
                 history_result = {
                     "success": True, 
                     "result": f"<Result truncated due to size. Full output in {self._last_output_file}>",
                     "truncated": True
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

        # Increment call count on success
        if success:
            self._executed_tool_counts[args_key] = self._executed_tool_counts.get(args_key, 0) + 1

        return success, duration, result, self._last_output_file

    def _append_tool_result(
        self,
        tool_name: str,
        content_str: str,
        success: bool,
        tool_call_id: str | None = None,
    ) -> None:
        """Append tool output to the conversation history."""
        cfg = get_config()
        # Default to tool role if supported, else user
        if cfg.tool_response_role.lower() == "tool":
            tool_msg = {
                "role": "tool",
                "name": tool_name,
                "content": content_str,
            }
            if tool_call_id:
                tool_msg["tool_call_id"] = tool_call_id
            self.state.conversation.append(tool_msg)
        else:
            status = "successfully" if success else "with errors"
            self.state.conversation.append(
                {
                    "role": "user",
                    "content": f"[SYSTEM: Tool '{tool_name}' executed {status}]\nOutput:\n{content_str}",
                }
            )

    # Removed: _handle_auto_recon, _build_auto_chain, _intercept_tool (MCP-era dead code)
    # Removed: _is_simple_task_completed, _check_supervisor_intervention
    # All behaviors now handled by system_prompt and Docker engine.

    # NOTE: _truncate_result is defined once at L727. Duplicate removed.

    # File extensions worth listing in workspace context
    _WORKSPACE_SCAN_EXTENSIONS = frozenset({
        ".txt", ".json", ".html", ".htm", ".csv", ".xml",
        ".out", ".md", ".log", ".nmap",
    })

    def _scan_workspace_state(self, target: str) -> str:
        """Scan workspace output/, tools/, and vulnerabilities/ to provide context."""
        try:
            base_dir = str(get_workspace_root() / target)

            if not os.path.exists(base_dir):
                return ""

            output_dir = os.path.join(base_dir, "output")
            tools_dir = os.path.join(base_dir, "tools")
            vuln_dir = os.path.join(base_dir, "vulnerabilities")

            files_info = []

            # Scan Output Files (inputs for tool chaining)
            if os.path.exists(output_dir):
                for f in sorted(os.listdir(output_dir)):
                    ext = os.path.splitext(f)[1].lower()
                    if ext not in self._WORKSPACE_SCAN_EXTENSIONS:
                        continue
                    path = os.path.join(output_dir, f)
                    size = os.path.getsize(path)
                    lines = 0
                    if ext in {".txt", ".csv", ".out", ".log", ".nmap"}:
                        try:
                            with open(path, "r", errors="ignore") as fh:
                                lines = sum(1 for _ in fh)
                        except Exception:
                            pass
                    info = f"- /workspace/{target}/output/{f} ({size} bytes"
                    if lines:
                        info += f", {lines} lines"
                    info += ")"
                    files_info.append(info)

            # Scan Custom Scripts
            if os.path.exists(tools_dir):
                for f in sorted(os.listdir(tools_dir)):
                    files_info.append(f"- [SCRIPT] /workspace/{target}/tools/{f}")

            # Scan Vulnerability Reports (so agent knows what has already been reported)
            if os.path.exists(vuln_dir):
                for f in sorted(os.listdir(vuln_dir)):
                    if f.endswith(".md"):
                        files_info.append(f"- [REPORTED] /workspace/{target}/vulnerabilities/{f}")

            if not files_info:
                return ""

            file_list = "\n".join(files_info)
            return (
                f"[SYSTEM: WORKSPACE for {target}]\n"
                f"{file_list}"
            )
        except Exception as e:
            logger.error(f"Error scanning workspace: {e}")
            return ""

    def _infer_domain_from_value(self, value: str, user_message: str | None = None) -> str:
        """Best-effort extraction of a domain from a value or user prompt."""
        if not value: return value
        raw = str(value).strip().replace("http://", "").replace("https://", "")
        if "workspace/" in raw:
             try: return raw.split("workspace/")[1].split("/")[0]
             except: pass
        if "/" in raw: return raw.split("/")[0]
        return raw

    # Common file/script/config extensions that should never be treated as a domain
    _FILE_EXTENSIONS = frozenset({
        "json", "txt", "xml", "html", "htm", "csv", "yaml", "yml", "md", "rst",
        "py", "js", "ts", "sh", "rb", "go", "php", "java", "c", "cpp", "h",
        "log", "conf", "cfg", "ini", "toml", "lock", "env",
        "pdf", "png", "jpg", "jpeg", "gif", "svg", "ico",
        "zip", "tar", "gz", "bz2", "xz", "whl", "deb", "rpm",
        "out", "bin", "exe", "so", "dylib",
    })

    def _extract_targets_from_text(self, text: str) -> list[str]:
        """Extract all valid, unique domain targets from text (ordered by appearance)."""
        if not text:
            return []
        seen: set[str] = set()
        targets: list[str] = []
        for m in re.finditer(r"\b[a-z0-9.-]+\.[a-z]{2,}\b", text, re.IGNORECASE):
            candidate = m.group(0).lower()
            ext = candidate.rsplit(".", 1)[-1]
            if ext in self._FILE_EXTENSIONS:
                continue
            if self._is_placeholder_target(candidate):
                continue
            if candidate not in seen:
                seen.add(candidate)
                targets.append(candidate)
        return targets

    def _extract_target_from_text(self, text: str) -> str | None:
        """Return the first valid domain found in text."""
        targets = self._extract_targets_from_text(text)
        return targets[0] if targets else None

    def _is_placeholder_target(self, value: str) -> bool:
        if not value: return False
        val = value.lower()
        return val in {"example.com", "test.com"} or val.endswith(".example.com")

    def _replace_placeholders_in_text(self, text: str) -> str:
        if not text or not self.state.active_target: return text
        return text.replace("example.com", self.state.active_target) # Simplified

    def _replace_placeholder_targets(self, data: Any) -> Any:
        if not self.state.active_target: return data
        if isinstance(data, str):
            res = data.replace("example.com", self.state.active_target)
            res = res.replace("test.com", self.state.active_target)
            return res
        if isinstance(data, list):
            return [self._replace_placeholder_targets(v) for v in data]
        if isinstance(data, dict):
            return {k: self._replace_placeholder_targets(v) for k, v in data.items()}
        return data

    def _validate_target_consistency(self, tool_name: str, args: dict[str, Any], user_message: str) -> str | None:
        if not self.state.active_target: return None
        return None # Simplified

    def _normalize_tool_args(
        self,
        tool_name: str,
        arguments: Any,
        user_message: str | None = None,
    ) -> dict[str, Any]:
        """Normalize and fix common tool argument mistakes."""
        if isinstance(arguments, str):
            try: arguments = json.loads(arguments)
            except: arguments = {}
        if not isinstance(arguments, dict): return {}

        args = dict(arguments)

        if self.state.active_target:
            args = self._replace_placeholder_targets(args)

        return args

    def _save_tool_output(self, tool_name: str, args: dict[str, Any], result: dict[str, Any]) -> None:
        try:
            from datetime import datetime
            target = self.state.active_target or "unknown"
            base_dir = str(get_workspace_root() / target)

            # Create subdirectories
            command_dir = os.path.join(base_dir, "command")
            output_dir = os.path.join(base_dir, "output")
            tools_dir = os.path.join(base_dir, "tools")
            vuln_dir = os.path.join(base_dir, "vulnerabilities")

            os.makedirs(command_dir, exist_ok=True)
            os.makedirs(output_dir, exist_ok=True)
            os.makedirs(tools_dir, exist_ok=True)
            os.makedirs(vuln_dir, exist_ok=True)

            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            succeeded = result.get("success", False)

            # 1. Always save JSON metadata so errors are still inspectable
            json_filename = f"{tool_name}_{timestamp}.json"
            json_filepath = os.path.join(command_dir, json_filename)

            meta_data = {
                "tool": tool_name,
                "args": args,
                "result": result,
                "timestamp": timestamp,
                "success": succeeded,
            }

            with open(json_filepath, "w") as f:
                json.dump(meta_data, f, indent=2)

            # 2. Only save a .txt output file for successful runs — failed commands
            #    already have their error captured in the JSON above, and cluttering
            #    command/ with error files adds noise without benefit.
            if not succeeded:
                self._last_output_file = json_filepath
                return

            txt_content = ""
            if isinstance(result, dict) and "result" in result:
                res_data = result["result"]
                if isinstance(res_data, dict) and "stdout" in res_data:
                    txt_content = res_data["stdout"]
                else:
                    txt_content = str(res_data)

            if txt_content:
                txt_filename = f"{tool_name}_{timestamp}.txt"
                # execute output → command/ (execution log); all other tools → output/
                if tool_name == "execute":
                    txt_filepath = os.path.join(command_dir, txt_filename)
                else:
                    txt_filepath = os.path.join(output_dir, txt_filename)

                with open(txt_filepath, "w") as f:
                    f.write(str(txt_content))

                self._last_output_file = txt_filepath
            else:
                self._last_output_file = json_filepath

        except Exception as e:
            logger.error(f"Error saving tool output: {e}")


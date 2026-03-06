from __future__ import annotations
from .workspace import _WorkspaceMixin
from .validators import _ValidatorMixin
from .tool_defs import get_tool_definitions
from .session import (
    SessionData,
    load_session,
    save_session,
    update_from_parsed_output,
    session_to_context,
)
from .pipeline import PipelineEngine, PipelinePhase
from .output_parser import parse_tool_output
from .models import AgentEvent, AgentState, MAX_TOOL_ITERATIONS
from .formatters import _FormatterMixin
from .executors import _ExecutorMixin
from ..system import auto_load_skills_for_message
from ..ollama import OllamaClient
from ..docker import DockerEngine
from ..config import get_config, get_workspace_root
from typing import Any, AsyncIterator
import re
import logging

import asyncio
import json
from pathlib import Path

_tools_meta_path = Path(__file__).parent.parent / "data" / "tools_meta.json"
with open(_tools_meta_path, "r") as f:
    _TOOLS_META = json.load(f)


# from ..correlation import run_correlation

logger = logging.getLogger("airecon.agent")


class AgentLoop(_ValidatorMixin, _FormatterMixin,
                _WorkspaceMixin, _ExecutorMixin):
    # Extracts embedded <tool_call>…</tool_call> blocks from model text output
    _TOOL_CALL_RE = re.compile(
        r"<tool_call>\s*(\{.*?\})\s*</tool_call>",
        re.DOTALL | re.IGNORECASE,
    )

    # Tools exempt from dedup (interactive / stateful operations that must be
    # re-runnable)
    _DEDUP_EXEMPT_TOOLS = frozenset({
        "create_file",
        "create_vulnerability_report",
        "spawn_agent",
    })
    # browser_action actions that are always interactive and must not be
    # deduped
    _DEDUP_EXEMPT_BROWSER_ACTIONS = frozenset({
        "click", "type", "press", "scroll_down", "scroll_up",
        "wait", "get_console_logs", "get_network_logs",
    })
    # Max number of times the same CTF-local challenge can be seen before CTF
    # mode kicks in
    _CTF_MAX_ITERATIONS = 150

    def __init__(self, ollama: OllamaClient, engine: DockerEngine) -> None:
        self.ollama = ollama
        self.engine = engine
        self.state = AgentState()
        self._tools_ollama: list[dict[str, Any]] | None = None
        self._last_output_file: str | None = None
        self._executed_tool_counts: dict[tuple[str, str], int] = {}
        # Hash-based dedup: stores MD5(tool_name+args) to block re-execution of
        # identical commands
        self._executed_cmd_hashes: set[str] = set()
        self._initial_messages: list[dict[str, Any]] = []
        self._stop_requested: bool = False
        self._consecutive_failures: int = 0
        self._session: SessionData | None = None
        self._pending_output_merges: dict[str, list[str]] = {}
        # Tools blocked for this agent (e.g. depth control)
        self._blocked_tools: set[str] = set()
        # If set, overrides config in process_message
        self._override_max_iterations: int | None = None
        self._ctf_mode: bool = False  # True when target is CTF/XBOW/localhost
        self.pipeline: PipelineEngine | None = None

    async def stop(self) -> None:
        logger.warning("Stopping Agent Loop...")
        self._stop_requested = True
        if self.engine:
            await self.engine.force_stop()

    # ------------------------------------------------------------------
    # Anti-repeat guard (Priority 2)
    # ------------------------------------------------------------------

    def _is_duplicate_command(
        self, tool_name: str, args: dict[str, Any]
    ) -> tuple[bool, str]:
        """Return (is_duplicate, explanation_message).

        Uses MD5 hash of (tool_name + canonical JSON args) to detect
        identical tool calls across all iterations.  Safe to call on every
        tool invocation; exempt tools and interactive browser actions bypass
        the check entirely.
        """
        import hashlib

        # Exempt: stateful / side-effect tools that must always run
        if tool_name in self._DEDUP_EXEMPT_TOOLS:
            return False, ""

        # Exempt: interactive browser actions
        if tool_name == "browser_action":
            action = args.get("action", "")
            if action in self._DEDUP_EXEMPT_BROWSER_ACTIONS:
                return False, ""

        # Normalise args: sort keys, strip leading/trailing whitespace from
        # string values
        def _normalise(v: Any) -> Any:
            if isinstance(v, str):
                return v.strip()
            return v

        try:
            canonical = json.dumps(
                {k: _normalise(v) for k, v in args.items()}, sort_keys=True
            )
        except (TypeError, ValueError):
            canonical = str(args)

        raw = f"{tool_name}:{canonical}"
        cmd_hash = hashlib.md5(  # nosec B324 - non-security dedup hash
            raw.encode(
                "utf-8",
                errors="replace"),
            usedforsecurity=False).hexdigest()

        if cmd_hash in self._executed_cmd_hashes:
            msg = (
                f"[ANTI-REPEAT] Command '{tool_name}' with identical arguments was already "
                "executed. The result is already in your tool history. "
                "Do NOT repeat it — use the existing result and proceed to the next step."
            )
            return True, msg

        self._executed_cmd_hashes.add(cmd_hash)
        return False, ""

    async def initialize(
        self,
        target: str | None = None,
        user_message: str | None = None,
    ) -> None:
        from ..system import get_system_prompt as _gsp, _is_ctf_target
        self.state.conversation = [
            {"role": "system", "content": _gsp(
                target=target, user_message=user_message)}
        ]
        # Detect CTF mode early so process_message can apply iteration cap
        if _is_ctf_target(target, user_message):
            self._ctf_mode = True
            if self._override_max_iterations is None:
                self._override_max_iterations = self._CTF_MAX_ITERATIONS
            logger.info(
                f"CTF mode activated for target={target!r} "
                f"— max iterations capped at {self._CTF_MAX_ITERATIONS}"
            )
        engine_tools = await self.engine.discover_tools()
        self._tools_ollama = self.engine.tools_to_ollama_format(engine_tools)

        if self.engine:
            self.state.add_message(
                "system", "[SYSTEM: EXECUTE_COMMAND_AVAILABLE=yes]")

        if self._tools_ollama is None:
            self._tools_ollama = []
        self._tools_ollama.extend(get_tool_definitions())

        # Deduplicate by tool name
        unique: dict[str, dict] = {}
        for t in self._tools_ollama:
            unique[t["function"]["name"]] = t
        self._tools_ollama = list(unique.values())

        # Remove blocked tools (e.g. spawn_agent blocked for subagents to
        # prevent recursion)
        if self._blocked_tools:
            self._tools_ollama = [
                t for t in self._tools_ollama
                if t["function"]["name"] not in self._blocked_tools
            ]

        logger.info(f"Agent initialized with {len(self._tools_ollama)} tools")

        tool_names = [t["function"]["name"] for t in self._tools_ollama]
        self.state.add_message(
            "system", f"[SYSTEM: REGISTERED TOOLS]\n{', '.join(tool_names)}"
        )

        self._initial_messages = list(self.state.conversation)

        # Initialize session: load from env var ID if provided, otherwise
        # create fresh
        import os as _os
        _session_id = _os.environ.get("AIRECON_SESSION_ID")
        if _session_id:
            self._session = load_session(_session_id) or SessionData(
                session_id=_session_id, target=""
            )
            logger.info(
                f"Loaded session {_session_id} (target={
                    self._session.target})")
        else:
            self._session = SessionData(target="")
            logger.info(f"Created new session {self._session.session_id}")

        self.pipeline = PipelineEngine(self._session)
        if self._ctf_mode and self.pipeline:
            self.pipeline.set_ctf_mode(True)

    def reset(self) -> None:
        self.state = AgentState()
        if self._initial_messages:
            self.state.conversation = list(self._initial_messages)
        self._executed_tool_counts.clear()
        self._last_output_file = None
        # Create a new session on reset (keeps the old one on disk)
        self._session = SessionData(target="")
        self.pipeline = PipelineEngine(self._session)

    async def process_message(
            self, user_message: str) -> AsyncIterator[AgentEvent]:
        try:
            all_targets = self._extract_targets_from_text(user_message)
            extracted_target = all_targets[0] if all_targets else None

            if not self._tools_ollama:
                # First call: initialise with target+message so CTF prompt is
                # selected
                await self.initialize(
                    target=extracted_target,
                    user_message=user_message,
                )
            else:
                # Subsequent messages: detect CTF target and activate mode if
                # not yet done
                if not self._ctf_mode and extracted_target:
                    from ..system import _is_ctf_target
                    if _is_ctf_target(extracted_target, user_message):
                        self._ctf_mode = True
                        if self._override_max_iterations is None:
                            self._override_max_iterations = self._CTF_MAX_ITERATIONS
                        if self.pipeline:
                            self.pipeline.set_ctf_mode(True)
                        logger.info(
                            "CTF mode activated mid-session for target=%r",
                            extracted_target,
                        )

            if extracted_target:
                self.state.active_target = extracted_target

            cfg = get_config()

            _COMPLEX_SIGNALS = (
                "how", "what", "why", "explain", "show me", "list", "help",
                "?", "can you", "could you", "please tell", "describe",
            )
            _msg_lower = user_message.strip().lower()
            _is_simple_target_msg = (
                extracted_target is not None
                and len(user_message.strip()) <= 120
                and not any(s in _msg_lower for s in _COMPLEX_SIGNALS)
                and extracted_target.lower() in _msg_lower
            )
            if cfg.deep_recon_autostart and _is_simple_target_msg:
                logger.info(f"Auto-starting deep recon for {extracted_target}")
                user_message = (
                    f"Perform a comprehensive full deep recon and "
                    f"vulnerability scan on {extracted_target}. "
                    "Use all available tools."
                )

            EPHEMERAL_PREFIXES = (
                "[SYSTEM: WORKSPACE",
                "[SYSTEM: ACTIVE_TARGET",
                "[SYSTEM: ADDITIONAL_TARGETS",
            )
            self.state.conversation = [
                msg
                for msg in self.state.conversation
                if not (
                    msg.get("role") == "system"
                    and any(
                        msg.get("content", "").startswith(p) for p in EPHEMERAL_PREFIXES
                    )
                )
            ]

            if len(all_targets) > 1:
                extra = ", ".join(all_targets[1:])
                self.state.conversation.append(
                    {
                        "role": "system",
                        "content": (
                            f"[SYSTEM: ADDITIONAL_TARGETS={extra}] "
                            f"Primary workspace is '{extracted_target}'. "
                            f"Additional targets also mentioned: {extra}. "
                            "Handle each in sequence or as directed by the user."
                        ),
                    }
                )

            if self.state.active_target:
                workspace_context = await asyncio.to_thread(
                    self._scan_workspace_state, self.state.active_target
                )
                self.state.conversation.append(
                    {
                        "role": "system",
                        "content": workspace_context
                        if workspace_context
                        else f"[SYSTEM: ACTIVE_TARGET={self.state.active_target}]",
                    }
                )

                # Update session target (session was pre-created in
                # initialize())
                if not self._session:
                    self._session = SessionData(
                        target=self.state.active_target)
                    self.pipeline = PipelineEngine(self._session)
                elif self._session.target != self.state.active_target:
                    self._session.target = self.state.active_target
                    if self.pipeline:
                        self.pipeline = PipelineEngine(self._session)

                if self._session and self._session.scan_count > 0:
                    session_ctx = session_to_context(self._session)
                    self.state.conversation.append(
                        {
                            "role": "system",
                            "content": session_ctx,
                        }
                    )

            self.state.conversation.append(
                {"role": "user", "content": user_message})

            # Auto-load relevant skills based on user message keywords
            skill_context, loaded_skills = auto_load_skills_for_message(
                user_message)
            if loaded_skills:
                for s in loaded_skills:
                    if s not in self.state.skills_used:
                        self.state.skills_used.append(s)

            if skill_context:
                self.state.conversation.append(
                    {"role": "system", "content": skill_context}
                )

            # Reset per-message state
            self.state.iteration = 0
            self.state.max_iterations = (
                self._override_max_iterations
                or cfg.agent_max_tool_iterations
                or MAX_TOOL_ITERATIONS
            )
            self.state.warnings_sent = False
            self._stop_requested = False
            self._consecutive_failures = 0
            # NOTE: Do NOT clear _executed_tool_counts here — dedup must persist
            # across messages within the same session. It is only cleared in
            # reset().
            last_iteration_had_tools = False

            while self.state.iteration < self.state.max_iterations:
                if self._stop_requested:
                    yield AgentEvent(
                        type="error", data={"message": "Agent stopped by user."}
                    )
                    yield AgentEvent(type="done", data={})
                    return

                self.state.increment_iteration()

                # --- PLANNING INJECTION (iteration 1 only) ---
                if self.state.iteration == 1:
                    self.state.conversation.append(
                        {
                            "role": "system",
                            "content": (
                                "[SYSTEM: MANDATORY PLANNING STEP]\n"
                                "Write a brief, goal-oriented plan for your engagement.\n"
                                "Immediately execute the first step of Phase 1 (Manual scripts, curl, OSINT) AFTER outputting your plan. Do not wait."
                            ),
                        }
                    )
                    # Clear planned tools at start
                    self.state.planned_tools.clear()

                # --- PLAN REVISION (every N iterations from config) ---
                revision_interval = cfg.agent_plan_revision_interval
                if (
                    revision_interval > 0
                    and self.state.iteration > 1
                    and self.state.iteration % revision_interval == 0
                ):
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
                    self.state.conversation.append(
                        {
                            "role": "system",
                            "content": (
                                f"[SYSTEM: MANDATORY PLAN REVISION — iteration {
                                    self.state.iteration}]{session_info}\n"
                                "Your original plan may be stale. REVISED PLANNING REQUIRED:\n"
                                "1. Compare original plan vs actual findings\n"
                                "2. What has WORKED? What has FAILED?\n"
                                "3. Adjust strategy: which phases to SKIP, which to PRIORITIZE?\n"
                                "4. What is the single most valuable next action?\n"
                                "Output revised plan, then continue."
                            ),
                        }
                    )

                # --- PIPELINE CHECKPOINT (every 5 iterations) ---
                # Lightweight: injects pipeline phase prompt + session summary.
                # Correlation/chaining/expert run at every 10 (see below).
                if self.state.iteration > 1 and self.state.iteration % 5 == 0:
                    session_info = ""
                    pipeline_prompt = ""

                    if self._session:
                        s = self._session

                        # Keep pipeline iteration counter in sync
                        if self.pipeline:
                            self.pipeline._current_iteration = self.state.iteration

                        # Check pipeline transitions
                        if self.pipeline and self.pipeline.should_transition():
                            new_phase = self.pipeline.transition()
                            if new_phase:
                                pipeline_prompt = self.pipeline.get_transition_prompt(
                                    new_phase)
                        elif self.pipeline:
                            pipeline_prompt = "\n" + self.pipeline.get_phase_prompt()

                        # Full session context injected to prevent "lost in the middle"
                        # context degradation in long runs. Includes actual finding data
                        # (subdomain list, host list, port map, tech stack, vuln titles)
                        # so the LLM doesn't need to recall from early
                        # conversation turns.
                        session_info = "\n" + session_to_context(s)

                    self.state.conversation.append(
                        {
                            "role": "system",
                            "content": (
                                f"[SYSTEM: EXECUTION CHECKPOINT — Itr {
                                    self.state.iteration}]"
                                f"{session_info}\n\n"
                                f"{pipeline_prompt}"
                                "MANDATORY ACTION: Do not just plan. Pick the absolute best next tool and execute it. If done, output [TASK_COMPLETE]."
                            ),
                        }
                    )

                # --- EVALUATION CHECKPOINT (every 10 iterations) ---
                # Heavier: adds correlation, vuln chaining, expert testing
                # hints.
                if self.state.iteration > 1 and self.state.iteration % 10 == 0:
                    vuln_chaining_prompt = ""
                    correlation_prompt = ""
                    expert_testing_prompt = ""

                    if self._session:
                        s = self._session

                        # OUTPUT CORRELATION ENGINE
                        if s.open_ports or s.technologies:
                            from ..correlation import run_correlation  # lazy – avoids circular import
                            correlations = run_correlation(s)
                            if correlations:
                                corr_lines = [
                                    "\n[OUTPUT CORRELATION - Attack Chains]"]
                                # Enhanced to show top 10 instead of 5
                                for corr in correlations[:10]:
                                    severity = corr.get("severity", "MEDIUM")
                                    vuln_type = corr.get("type", "correlation")

                                    if vuln_type == "port":
                                        port = corr.get("port", "?")
                                        service = corr.get("service", "?")
                                        vulns = corr.get("vulnerabilities", [])
                                        vuln_str = vulns[0] if vulns else "Multiple issues"
                                        corr_lines.append(
                                            f"- [{severity}] Port {port} ({service}): {vuln_str}")

                                    elif vuln_type == "technology":
                                        tech = corr.get("technology", "?")
                                        vulns = corr.get("vulnerabilities", [])
                                        vuln_str = vulns[0] if vulns else "Multiple issues"
                                        corr_lines.append(
                                            f"- [{severity}] Tech {tech}: {vuln_str}")

                                    elif vuln_type == "technology_cve":
                                        tech = corr.get("technology", "?")
                                        vulns = corr.get("vulnerabilities", [])
                                        vuln_str = vulns[0] if vulns else "Multiple issues"
                                        corr_lines.append(
                                            f"- [{severity}] {tech} CVE: {vuln_str}")

                                    elif vuln_type == "url_path":
                                        path = corr.get("path", "?")
                                        tech = corr.get("technology", "?")
                                        corr_lines.append(
                                            f"- [{severity}] Discovered Path '{path}' "
                                            f"mapped to {tech}"
                                        )

                                    elif vuln_type == "expert_test":
                                        pattern = corr.get("pattern", "?")
                                        desc = corr.get("description", "?")
                                        corr_lines.append(
                                            f"- [{severity}] EXPERT TEST ({pattern}): {desc}")

                                    elif vuln_type == "zeroday_potential":
                                        pattern = corr.get("pattern", "?")
                                        desc = corr.get("description", "?")
                                        corr_lines.append(
                                            f"- [{severity}] ZERO-DAY INDICATOR "
                                            f"({pattern}): {desc}"
                                        )

                                    elif vuln_type == "business_logic":
                                        pattern = corr.get("pattern", "?")
                                        desc = corr.get("description", "?")
                                        corr_lines.append(
                                            f"- [{severity}] BUSINESS LOGIC FLAW "
                                            f"({pattern}): {desc}"
                                        )

                                    elif vuln_type == "attack_chain":
                                        name = corr.get("name", "?")
                                        steps = corr.get("steps", [])
                                        steps_str = " -> ".join(steps)
                                        corr_lines.append(
                                            f"- [{severity}] ATTACK CHAIN DETECTED "
                                            f"({name}): {steps_str}"
                                        )

                                    else:
                                        # Generic fallback
                                        corr_lines.append(
                                            f"- [{severity}] Unknown Correlation: {corr}")

                                correlation_prompt = "\n".join(corr_lines)

                        # VULNERABILITY CHAINING ANALYSIS
                        if len(s.vulnerabilities) >= 2:
                            vuln_titles = [
                                v.get("title", v.get("finding", "?"))
                                for v in s.vulnerabilities[:10]
                            ]
                            vuln_chaining_prompt = (
                                f"\n\n[VULNERABILITY CHAINING ANALYSIS]\n"
                                f"You have {
                                    len(
                                        s.vulnerabilities)} vulnerabilities. Consider chaining:\n"
                                f"Current vulns: {'; '.join(vuln_titles)}\n"
                                f"Analyze if combining these can lead to greater impact:\n"
                                f"- Can XSS be combined with CSRF for session hijacking?\n"
                                f"- Can IDOR + broken auth lead to account takeover?\n"
                                f"- Can SSRF + cloud metadata = full cloud compromise?\n"
                                f"Document attack chains in output/attack_chains.txt"
                            )

                        # EXPERT TESTING & ZERO-DAY DISCOVERY GUIDANCE
                        if s.urls and len(s.urls) > 5:
                            url_str = " ".join(s.urls).lower()
                            expert_patterns = []

                            if "api" in url_str:
                                expert_patterns.append(
                                    "API endpoints detected - FUZZ all parameters with ffuf"
                                )
                            if any(x in url_str for x in [
                                   "user_id", "order_id", "id="]):
                                expert_patterns.append(
                                    "ID parameters found - TEST IDOR: change IDs 1,2,3,999"
                                )
                            if any(x in url_str for x in [
                                   "search", "query", "q="]):
                                expert_patterns.append(
                                    "Search params found - TEST XSS and SQL injection"
                                )
                            if any(x in url_str for x in [
                                   "price", "amount", "discount"]):
                                expert_patterns.append(
                                    "Price params found - TEST business logic manipulation"
                                )
                            if any(x in url_str for x in [
                                   "upload", "file", "image"]):
                                expert_patterns.append(
                                    "File upload found - TEST webshell upload, polyglots"
                                )

                            if expert_patterns:
                                try:
                                    prompt_path = Path(
                                        __file__).parent.parent / "prompts" / "testing.txt"
                                    with open(prompt_path, "r") as pf:
                                        expert_template = pf.read()
                                    patterns_str = "\n".join(
                                        f"- {p}" for p in expert_patterns)
                                    expert_testing_prompt = "\n\n" + \
                                        expert_template.replace(
                                            "{expert_patterns}", patterns_str)
                                except Exception as _tmpl_err:
                                    logger.debug(
                                        "Could not load testing.txt template: %s — using inline fallback",
                                        _tmpl_err,
                                    )
                                    expert_testing_prompt = "\n\n[EXPERT TESTING] " + ", ".join(
                                        expert_patterns)

                    if correlation_prompt or vuln_chaining_prompt or expert_testing_prompt:
                        self.state.conversation.append(
                            {
                                "role": "system",
                                "content": (
                                    f"[SYSTEM: ANALYSIS — Itr {
                                        self.state.iteration}]"
                                    f"{correlation_prompt}"
                                    f"{vuln_chaining_prompt}"
                                    f"{expert_testing_prompt}\n"
                                ),
                            }
                        )

                # --- CONTEXT MANAGEMENT (adaptive interval + progressive truncation) ---
                # Run more frequently in long sessions to prevent VRAM growth
                _ctx_interval = 10 if self.state.iteration > 150 else 15
                if self.state.iteration % _ctx_interval == 0:
                    # LLM-based compression first (summarizes old messages,
                    # preserves findings)
                    await self.state.compress_with_llm(self.ollama, keep_recent=30)
                    # PIN CRITICAL FINDINGS BEFORE TRUNCATION
                    critical_context = self._build_critical_findings_context()
                    # Progressive max_messages: more aggressive as session
                    # grows to limit KV cache
                    if self.state.iteration < 100:
                        _max_msgs = 150
                    elif self.state.iteration < 200:
                        _max_msgs = 120
                    elif self.state.iteration < 300:
                        _max_msgs = 100
                    else:
                        _max_msgs = 80
                    self.state.truncate_conversation(max_messages=_max_msgs)
                    # Re-inject critical findings after truncation
                    if critical_context:
                        self.state.conversation.append(
                            {"role": "system", "content": critical_context}
                        )

                if self.state.iteration > 1 and self.state.iteration % 10 == 0:
                    # Inject session-aware summary instead of just tool history
                    if self._session and self._session.scan_count > 0:
                        session_summary = session_to_context(self._session)
                        self.state.conversation = [
                            msg
                            for msg in self.state.conversation
                            if not msg.get("content", "").startswith(
                                "[SYSTEM: RECENT EXECUTIONS"
                            )
                            and not msg.get("content", "").startswith(
                                "[SYSTEM: PREVIOUS SESSION"
                            )
                        ]
                        self.state.conversation.append(
                            {"role": "system", "content": session_summary}
                        )
                    elif self.state.tool_history:
                        history_ctx = self._build_recent_history_context(
                            last_n=10)
                        if history_ctx:
                            self.state.conversation = [
                                msg
                                for msg in self.state.conversation
                                if not msg.get("content", "").startswith(
                                    "[SYSTEM: RECENT EXECUTIONS"
                                )
                            ]
                            self.state.conversation.append(
                                {"role": "system", "content": history_ctx}
                            )

                if self.state.is_approaching_limit() and not self.state.warnings_sent:
                    self.state.warnings_sent = True
                    remaining = self.state.max_iterations - self.state.iteration
                    self.state.conversation.append(
                        {
                            "role": "system",
                            "content": f"[SYSTEM: {remaining} iterations remaining]",
                        }
                    )

                thinking_acc = ""
                content_acc = ""
                tool_calls_acc = []
                in_thinking_tag = False
                _carry = ""

                # Context window — full size by default; reduced to small on
                # VRAM crash retry
                adaptive_num_ctx = cfg.ollama_num_ctx

                # --- VRAM-CRASH RECOVERY LOOP ---
                # Attempt the LLM stream up to 2 times.
                # On first failure with an HTML error page (Ollama OOM), we truncate
                # the conversation aggressively, switch to ollama_num_ctx_small, and retry.
                # On any other error (or if the retry also fails), we stop with
                # an error message.
                _last_chunk_data = {}  # Store last chunk to extract token info
                for _stream_attempt in range(2):
                    try:
                        async for chunk in self.ollama.chat_stream(
                            messages=self.state.conversation,
                            tools=self._tools_ollama,
                            options={
                                "num_ctx": adaptive_num_ctx,
                                "temperature": cfg.ollama_temperature,
                                "num_predict": cfg.ollama_num_predict,
                            },
                            think=cfg.ollama_enable_thinking
                            and self.ollama.supports_thinking,
                        ):
                            if hasattr(chunk, "model_dump"):
                                chunk_data = chunk.model_dump()
                            elif isinstance(chunk, dict):
                                chunk_data = chunk
                            else:
                                chunk_data = dict(chunk)

                            _last_chunk_data = chunk_data  # Keep track of last chunk for token info

                            message = chunk_data.get("message", {})
                            chunk_thinking = message.get("thinking")
                            chunk_tool_calls = message.get("tool_calls")
                            chunk_content = message.get("content", "")

                            if chunk_thinking:
                                thinking_acc += chunk_thinking
                                yield AgentEvent(
                                    type="thinking", data={"content": chunk_thinking}
                                )

                            if chunk_content:
                                text = _carry + chunk_content
                                _carry = ""
                                _OPEN_TAG = "<think>"
                                _CLOSE_TAG = "</think>"
                                # Buffer partial tag suffix to avoid splitting
                                # mid-tag
                                for partial_len in range(
                                        min(len(text), 8), 0, -1):
                                    suffix = text[-partial_len:]
                                    if _OPEN_TAG.startswith(
                                        suffix
                                    ) or _CLOSE_TAG.startswith(suffix):
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
                                                yield AgentEvent(
                                                    type="text", data={"content": before}
                                                )
                                            in_thinking_tag = True
                                        else:
                                            content_acc += text
                                            yield AgentEvent(
                                                type="text", data={"content": text}
                                            )
                                            text = ""
                                    else:
                                        if _CLOSE_TAG in text:
                                            idx = text.index(_CLOSE_TAG)
                                            think_frag = text[:idx]
                                            text = text[idx + len(_CLOSE_TAG):]
                                            if think_frag:
                                                thinking_acc += think_frag
                                                yield AgentEvent(
                                                    type="thinking",
                                                    data={
                                                        "content": think_frag},
                                                )
                                            in_thinking_tag = False
                                        else:
                                            thinking_acc += text
                                            yield AgentEvent(
                                                type="thinking", data={"content": text}
                                            )
                                            text = ""
                            if chunk_tool_calls:
                                tool_calls_acc.extend(chunk_tool_calls)

                        if _carry:
                            content_acc += _carry
                            yield AgentEvent(type="text", data={"content": _carry})
                            _carry = ""

                        # Extract token usage from last chunk
                        if _last_chunk_data:
                            # Ollama returns eval_count (tokens generated) and prompt_eval_count (tokens in prompt)
                            eval_count = _last_chunk_data.get(
                                "eval_count", 0)  # tokens generated
                            prompt_eval_count = _last_chunk_data.get(
                                "prompt_eval_count", 0)  # tokens in prompt
                            total_tokens = eval_count + prompt_eval_count
                            if total_tokens > 0:
                                self.state.token_usage["used"] = total_tokens
                                logger.debug(
                                    f"Token usage: prompt={prompt_eval_count}, generated={eval_count}, total={total_tokens}")

                        break  # stream completed — exit retry loop
                    except Exception as stream_err:
                        err_str = str(stream_err)
                        err_lower = err_str.lower()
                        _is_vram_crash = (
                            "invalid character '<'" in err_str
                            or "failed to parse JSON" in err_str
                            or "HTML error page" in err_str
                            or "unexpected end of json" in err_lower
                            or "<!doctype" in err_lower
                            or "<html" in err_lower
                            or "out of memory" in err_lower
                            or "cuda out of memory" in err_lower
                            or "llm runner process no longer alive" in err_lower
                            or "signal: killed" in err_lower
                        )
                        if _is_vram_crash and _stream_attempt == 0:
                            # First attempt: auto-recover and retry with
                            # smaller context
                            logger.warning(
                                "Ollama VRAM crash detected — auto-recovering "
                                "(aggressive truncation + reduced context window)"
                            )
                            yield AgentEvent(
                                type="text",
                                data={
                                    "content": (
                                        "\n[AUTO-RECOVERY] Ollama VRAM crash detected. "
                                        "Truncating context and retrying with reduced "
                                        f"context window ({
                                            cfg.ollama_num_ctx_small} tokens)...\n"
                                    )
                                },
                            )
                            self.state.truncate_conversation(max_messages=80)
                            adaptive_num_ctx = cfg.ollama_num_ctx_small
                            thinking_acc = ""
                            content_acc = ""
                            tool_calls_acc = []
                            in_thinking_tag = False
                            _carry = ""
                            continue  # retry the stream with smaller context
                        # Fatal error: not VRAM crash, or second attempt also
                        # failed
                        if _is_vram_crash:
                            error_msg = (
                                "Ollama crashed twice (VRAM exhausted). "
                                "Run `systemctl restart ollama` and reduce "
                                "`ollama_num_ctx` in config (e.g. 32768)."
                            )
                        elif "connection refused" in err_lower:
                            error_msg = "Cannot connect to Ollama (connection refused).\nFix: start Ollama with `ollama serve`."
                        elif "model not found" in err_lower or "pull" in err_lower:
                            error_msg = f"Model not found: {
                                cfg.ollama_model}\nFix: run `ollama pull {
                                cfg.ollama_model}`."
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
                    yield AgentEvent(
                        type="error", data={"message": "Empty response from model."}
                    )
                    yield AgentEvent(type="done", data={})
                    return

                # --- RESPONSE QUALITY GATE ---
                combined_response = content_acc + " " + thinking_acc
                # Signals that indicate the model is fabricating results instead of running tools.
                # These are tuned for local LLMs (Ollama/Mistral/Llama) which tend to narrate
                # findings confidently without calling tools.
                hallucination_signals = [
                    "i have found",          # Claims finding without tool output
                    "the scan shows",        # Claims scan result without running scan
                    "the results indicate",  # Claims results without tool evidence
                    "my analysis shows",     # Claims analysis without code_analysis tool
                    "it appears that",       # Speculative claim without evidence
                    "based on my knowledge",  # LLM knowledge, not live tool output
                    "without running",       # Explicitly admits no tool used
                    "i don't have access to",  # Model refusing instead of using tools
                ]
                has_hallucination_risk = any(
                    signal in combined_response.lower()
                    for signal in hallucination_signals
                )

                # Enhanced hallucination check: stricter in EXPLOIT phase or after vulnerability found
                has_prior_tool_runs = last_iteration_had_tools
                is_exploit_phase = self.pipeline and self.pipeline.get_current_phase(
                ) == PipelinePhase.EXPLOIT
                has_vulns = self._session and len(
                    self._session.vulnerabilities) > 0
                is_post_vuln_context = has_vulns and (
                    is_exploit_phase or self.state.iteration > 15)

                if has_hallucination_risk and not tool_calls_acc and not has_prior_tool_runs:
                    if is_post_vuln_context:
                        # STRICT MODE: After vulnerability found, tool calls are MANDATORY
                        logger.warning(
                            f"Post-vulnerability hallucination detected in EXPLOIT phase. "
                            f"Forcing tool call requirement (phase={is_exploit_phase}, vulns={len(self._session.vulnerabilities) if self._session else 0})"
                        )
                        self.state.conversation.append(
                            {
                                "role": "system",
                                "content": (
                                    "[SYSTEM: MANDATORY TOOL CALL - EXPLOIT PHASE]\n"
                                    "A vulnerability was found. You MUST now prove it works:\n"
                                    "1. Call execute, browser_action, or quick_fuzz\n"
                                    "2. Show the actual response/output as evidence\n"
                                    "3. DO NOT write analysis-only text\n"
                                    "TOOL EXECUTION IS MANDATORY. Do not skip this step."
                                ),
                            }
                        )
                    else:
                        # Normal mode: warn and let model self-correct
                        self.state.conversation.append(
                            {
                                "role": "system",
                                "content": (
                                    "[SYSTEM: HALLUCINATION WARNING]\n"
                                    "Your response contains claims without tool execution. "
                                    "You have NO data unless a tool actually returned it. "
                                    "You MUST call a tool to verify any findings. "
                                    "Do NOT fabricate results."
                                ),
                            }
                        )

                # Fallback: some models emit tool calls as text inside
                # <tool_call> tags
                if not tool_calls_acc:
                    _registered = {
                        t["function"]["name"] for t in (self._tools_ollama or [])
                    }
                    _search_text = content_acc + "\n" + thinking_acc
                    extracted = self._extract_tool_calls_from_text(
                        _search_text, _registered
                    )
                    if extracted:
                        tool_calls_acc.extend(extracted)
                        content_acc = self._TOOL_CALL_RE.sub(
                            "", content_acc).strip()

                # --- TEXT-ONLY RESPONSE DETECTION IN EXPLOIT PHASE ---
                # If we're in EXPLOIT phase and got text-only response (no tools),
                # detect if it's analysis-only hallucination
                is_exploit_phase = self.pipeline and self.pipeline.get_current_phase(
                ) == PipelinePhase.EXPLOIT
                if is_exploit_phase and not tool_calls_acc and content_acc.strip():
                    # Check if response is analysis-only (claims without verification)
                    analysis_keywords = [
                        "analysis", "shows", "found", "detected",
                        "i have", "based on", "my analysis", "the results",
                        "might", "could be", "appears", "potentially"
                    ]
                    is_analysis_text = any(
                        keyword in content_acc.lower() for keyword in analysis_keywords
                    )

                    # Short text = likely plan/analysis
                    if is_analysis_text and len(content_acc) < 500:
                        logger.warning(
                            "Text-only analysis response in EXPLOIT phase detected. "
                            "Forcing tool execution."
                        )
                        self.state.conversation.append({
                            "role": "system",
                            "content": (
                                "[SYSTEM: TEXT-ONLY NOT ALLOWED IN EXPLOIT]\n"
                                "You provided only analysis/planning text without executing tools.\n"
                                "In EXPLOIT phase, you MUST:\n"
                                "1. Execute a tool (execute, browser_action, quick_fuzz, etc.)\n"
                                "2. Show the actual output\n"
                                "3. Base your next steps on REAL evidence\n"
                                "DO NOT provide analysis-only responses. Call a tool NOW."
                            )
                        })
                        # Don't process this response - set flag to regenerate
                        tool_calls_acc = []
                        content_acc = ""
                        # Continue to next iteration without adding to message history

                _has_task_complete = "[TASK_COMPLETE]" in content_acc
                content_acc = content_acc.replace(
                    "[TASK_COMPLETE]", "").strip()

                self.state.add_message(
                    "assistant", content_acc, tool_calls_acc, thinking_acc
                )

                # --- AUTO-LOAD SKILLS FROM LLM OUTPUT (not just user message) ---
                _llm_output_for_skills = (
                    content_acc + " " + thinking_acc).strip()
                if _llm_output_for_skills:
                    _new_skill_ctx, _new_loaded_skills = auto_load_skills_for_message(
                        _llm_output_for_skills)

                    if _new_loaded_skills:
                        for s in _new_loaded_skills:
                            if s not in self.state.skills_used:
                                self.state.skills_used.append(s)

                    if _new_skill_ctx:
                        # Avoid injecting the same skill context twice in a
                        # session
                        _skill_key = hash(_new_skill_ctx[:200])
                        if not hasattr(self, "_loaded_skill_hashes"):
                            self._loaded_skill_hashes: set[int] = set()
                        if _skill_key not in self._loaded_skill_hashes:
                            self._loaded_skill_hashes.add(_skill_key)
                            self.state.conversation.append(
                                {"role": "system", "content": _new_skill_ctx}
                            )
                            logger.debug(
                                "Auto-loaded skill from LLM output keywords"
                            )

                # --- TRACK PLANNED TOOLS ---
                # Extract tools mentioned in assistant's text response and
                # track them
                if content_acc:
                    known_tools = []
                    _categories = _TOOLS_META.get("categories", {})
                    for cat_group in _categories.values():
                        if isinstance(cat_group, dict):
                            for sublist in cat_group.values():
                                if isinstance(sublist, list):
                                    known_tools.extend(sublist)
                        elif isinstance(cat_group, list):
                            known_tools.extend(cat_group)
                    content_lower = content_acc.lower()
                    for tool in known_tools:

                        if re.search(rf"\b{re.escape(tool)}\b", content_lower):
                            if tool not in self.state.planned_tools:
                                self.state.planned_tools.append(tool)

                if not tool_calls_acc:
                    if _has_task_complete:
                        logger.info(
                            "Agent emitted [TASK_COMPLETE] — stopping.")
                    # Save session on any early text-only exit (with or without
                    # TASK_COMPLETE)
                    if self._session:
                        save_session(self._session)
                    yield AgentEvent(type="done", data={})
                    return

                # Deduplicate tool calls (Ollama streaming sometimes emits
                # duplicates per chunk)
                seen_tools = set()
                deduped_tool_calls = []
                for tc in tool_calls_acc:
                    tc_str = json.dumps(tc, sort_keys=True)
                    if tc_str not in seen_tools:
                        seen_tools.add(tc_str)
                        deduped_tool_calls.append(tc)
                tool_calls_acc = deduped_tool_calls

                last_iteration_had_tools = bool(tool_calls_acc)

                if not content_acc.strip():
                    tool_names_str = ", ".join(
                        tc["function"]["name"] for tc in tool_calls_acc
                    )
                    yield AgentEvent(
                        type="text", data={"content": f"Executing: {tool_names_str}..."}
                    )

                # --- PARALLEL TOOL EXECUTION ---
                # Classify tools into parallelizable groups
                parallelizable_tools = _TOOLS_META.get(
                    "parallelizable_tools", [])

                # Check if tools can run in parallel (same category, different
                # targets)
                tool_groups: dict[str, list[tuple[int, dict, dict]]] = {}
                sequential_only: list[tuple[int, dict, dict]] = []

                for idx, tc in enumerate(tool_calls_acc):
                    tn = tc["function"]["name"]
                    args = self._normalize_tool_args(
                        tn, tc["function"]["arguments"], user_message
                    )

                    # Yield tool start FIRST so UI spinner shows immediately
                    yield AgentEvent(
                        type="tool_start",
                        data={
                            "tool_id": str(idx),
                            "tool": tn,
                            "arguments": args},
                    )

                    # Check if this is a parallelizable tool
                    is_parallel = False
                    if tn == "execute":
                        cmd = args.get("command", "")
                        cmd_bin = (
                            cmd.split()[1]
                            if cmd.startswith("cd ")
                            else cmd.split()[0]
                        )
                        cmd_bin = cmd_bin.rsplit("/", 1)[-1]
                        if cmd_bin in parallelizable_tools:
                            # Group all parallel tools under a single
                            # 'parallel' category
                            if "parallel" not in tool_groups:
                                tool_groups["parallel"] = []
                            tool_groups["parallel"].append((idx, tc, args))
                            is_parallel = True

                    if not is_parallel:
                        sequential_only.append((idx, tc, args))

                all_results: dict[
                    int, tuple
                ] = {}  # idx -> (tc, tool_name, arguments, valid, ...)

                # --- EXECUTE PARALLEL TOOLS ---
                async def execute_single_tool(
                        idx: int, tc: dict, args: dict) -> tuple:
                    """Execute a single tool and return results."""
                    tn = tc["function"]["name"]

                    # --- ANTI-REPEAT GUARD (Priority 2) ---
                    # Block identical commands before they even reach
                    # validation/execution.
                    is_dup, dup_msg = self._is_duplicate_command(tn, args)
                    if is_dup:
                        logger.info(
                            f"Anti-repeat guard blocked duplicate: {tn}")
                        return (
                            idx, tc, tn, args,
                            True,   # treat as "success" so it is included in context
                            0.0,
                            {"success": True, "result": dup_msg},
                            None,
                            True,
                        )

                    valid, arg_err = self._validate_tool_args(tn, args)
                    if not valid:
                        return (
                            idx,
                            tc,
                            tn,
                            args,
                            False,
                            0.0,
                            {"success": False, "error": arg_err},
                            None,
                            False,
                        )

                    if tn == "execute":
                        # save old content for post-run merge
                        self._check_output_dedup(args)

                    if tn == "browser_action":
                        s, d, r, o = await self._execute_local_browser_tool(tn, args)
                    elif tn == "create_vulnerability_report":
                        s, d, r, o = await self._execute_report_tool(tn, args)
                    elif tn in ("create_file", "read_file", "list_files"):
                        s, d, r, o = await self._execute_filesystem_tool(tn, args)
                    elif tn == "web_search":
                        s, d, r, o = await self._execute_web_search_tool(args)
                    elif any(tn == t["function"]["name"] for t in (self._tools_ollama or [])):
                        s, d, r, o = await self._execute_tool_and_record(tn, args)
                    else:
                        self.state.missing_tool_count += 1
                        return (
                            idx,
                            tc,
                            tn,
                            args,
                            False,
                            0.0,
                            {"success": False, "error": f"Unknown tool: {tn}"},
                            None,
                            False,
                        )

                    # Post-run: merge new output with pre-existing file content
                    # (if any)
                    if tn == "execute":
                        self._apply_output_merge(args, s)

                    return (idx, tc, tn, args, True, d, r, o, s)

                # Execute parallel groups concurrently
                for _, group_tasks in tool_groups.items():
                    if len(group_tasks) > 1:
                        # Execute tools in parallel
                        tasks = [
                            asyncio.create_task(
                                execute_single_tool(idx, tc, args))
                            for idx, tc, args in group_tasks
                        ]
                        results = await asyncio.gather(*tasks, return_exceptions=True)
                        for res in results:
                            if isinstance(res, Exception):
                                logger.error(f"Parallel tool error: {res}")
                            else:
                                all_results[res[0]] = res
                    else:
                        # Single tool in group - execute normally
                        idx, tc, args = group_tasks[0]
                        res = await execute_single_tool(idx, tc, args)
                        all_results[idx] = res

                # Execute sequential-only tasks
                for idx, tc, args in sequential_only:
                    # Get the result from already-executed parallel task if
                    # exists
                    if idx in all_results:
                        continue
                    tn = tc["function"]["name"]
                    valid, arg_err = self._validate_tool_args(tn, args)
                    if not valid:
                        all_results[idx] = (
                            idx,
                            tc,
                            tn,
                            args,
                            False,
                            0.0,
                            {"success": False, "error": arg_err},
                            None,
                            False,
                        )
                        continue
                    # Save old output content for post-run merge (never blocks)
                    if tn == "execute":
                        self._check_output_dedup(args)

                    if tn == "browser_action":
                        s, d, r, o = await self._execute_local_browser_tool(tn, args)
                        self.state.missing_tool_count = 0
                    elif tn == "create_vulnerability_report":
                        s, d, r, o = await self._execute_report_tool(tn, args)
                        self.state.missing_tool_count = 0
                    elif tn in ("create_file", "read_file", "list_files"):
                        s, d, r, o = await self._execute_filesystem_tool(tn, args)
                        self.state.missing_tool_count = 0
                    elif tn == "web_search":
                        s, d, r, o = await self._execute_web_search_tool(args)
                        self.state.missing_tool_count = 0
                    elif any(tn == t["function"]["name"] for t in (self._tools_ollama or [])):
                        out_queue: asyncio.Queue[str] = asyncio.Queue()

                        def _on_chunk(text: str) -> None:
                            out_queue.put_nowait(text)

                        # create task
                        t_task = asyncio.create_task(
                            self._execute_tool_and_record(
                                tn, args, on_output=_on_chunk)
                        )

                        # Wait for task while yielding chunks
                        while not t_task.done():
                            try:
                                chunk = await asyncio.wait_for(
                                    out_queue.get(), timeout=0.1
                                )
                                yield AgentEvent(
                                    type="tool_output",
                                    data={
                                        "tool_id": str(idx), "content": chunk},
                                )
                            except asyncio.TimeoutError:
                                pass

                        # flush remaining
                        while not out_queue.empty():
                            chunk = out_queue.get_nowait()
                            yield AgentEvent(
                                type="tool_output",
                                data={"tool_id": str(idx), "content": chunk},
                            )

                        s, d, r, o = t_task.result()
                        self.state.missing_tool_count = 0
                    else:
                        self.state.missing_tool_count += 1
                        tool_list = ", ".join(
                            t["function"]["name"] for t in (self._tools_ollama or [])
                        )
                        error_msg = (
                            "CRITICAL ERROR: You just submitted an empty tool call (missing 'name'). "
                            f"Registered tools: {tool_list}."
                            if not tn
                            else f"Tool '{tn}' does not exist. "
                            f"Registered tools: {tool_list}. "
                            "Use 'execute' to run any shell command in the sandbox."
                        )
                        s, d, r, o = (
                            False,
                            0.0,
                            {"success": False, "error": error_msg},
                            None,
                        )
                        if (
                            self.state.missing_tool_count
                            >= cfg.agent_missing_tool_retry_limit
                        ):
                            yield AgentEvent(
                                type="error",
                                data={
                                    "message": f"Agent called unknown tool '{tn}' {self.state.missing_tool_count}x. Stopping."
                                },
                            )
                            yield AgentEvent(type="done", data={})
                            return
                    # Post-run: merge new output with pre-existing file content
                    # (if any)
                    if tn == "execute":
                        self._apply_output_merge(args, s)
                    all_results[idx] = (idx, tc, tn, args, True, d, r, o, s)

                # Process all results in order and emit events
                for idx in sorted(all_results.keys()):
                    res = all_results[idx]
                    (
                        _,
                        tc,
                        tool_name,
                        arguments,
                        was_valid,
                        duration,
                        result,
                        output_file,
                        success,
                    ) = res

                    if not was_valid:
                        arg_error = result.get(
                            "error", "Unknown validation error")
                        yield AgentEvent(
                            type="tool_end",
                            data={
                                "tool_id": str(idx),
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
                        self.state.missing_tool_count = 0  # reset on any successful tool
                    else:
                        self._consecutive_failures += 1

                    raw_command = (
                        arguments.get(
                            "command", "") if tool_name == "execute" else ""
                    )
                    content_str = self._smart_format_tool_result(
                        tool_name, result, success, raw_command
                    )

                    # --- PHASE TOOL FIT CHECK (soft enforcement) ---
                    if self.pipeline:  # type: ignore[attr-defined]
                        phase_warn = self.pipeline.check_tool_phase_fit(
                            tool_name)  # type: ignore[attr-defined]
                        if phase_warn:
                            content_str = phase_warn + "\n\n" + content_str

                    # --- PHASE 1 ARTIFACT ENFORCEMENT ---
                    if success and tool_name in (
                            "web_search", "browser_action"):
                        content_str += (
                            "\n\n[SYSTEM: MANDATORY FILE SAVE]\n"
                            f"You just executed `{tool_name}` successfully. "
                            "You are STRICTLY FORBIDDEN from keeping these results only in memory. "
                            "You MUST immediately use the `create_file` tool to save these findings "
                            "(URLs, text content, view_source, or console_logs) into the `output/` directory "
                            "(e.g., `output/dork_results.txt` or `output/source.txt`). "
                            "Do NOT proceed until this data is saved to disk!"
                        )

                    # Update session with parsed tool output
                    if success and tool_name == "execute" and self._session:
                        stdout = (
                            result.get(
                                "stdout", "") or result.get(
                                "result", "") or ""
                        )
                        if isinstance(stdout, str) and stdout.strip():
                            parsed_out = parse_tool_output(raw_command, stdout)
                            if parsed_out and parsed_out.total_count > 0:
                                update_from_parsed_output(
                                    self._session, parsed_out, raw_command
                                )
                                save_session(self._session)

                    if not success and self._consecutive_failures >= 3:
                        alt_suggestion = self._suggest_alternative_tool(
                            tool_name, raw_command
                        )
                        content_str += (
                            f"\n\n[SYSTEM: {
                                self._consecutive_failures} CONSECUTIVE FAILURES DETECTED] "
                            "MANDATORY: Stop using the current approach. "
                            "Switch to a completely different tool or strategy. "
                            + (
                                f"SUGGESTED ALTERNATIVES: {alt_suggestion}\n"
                                if alt_suggestion
                                else ""
                            )
                            + "If all options are exhausted, document what was tried and emit [TASK_COMPLETE]."
                        )

                    if success and self.state.tool_counts["total"] >= 1:
                        # --- PLANNED TOOLS CHECK ---
                        if self.state.planned_tools:
                            # Get tools that have been executed
                            executed_tools = set()
                            for hist in self.state.tool_history:
                                executed_tools.add(hist.tool_name)

                            # Find unexecuted planned tools
                            unexecuted = [
                                t
                                for t in self.state.planned_tools
                                if t not in executed_tools and t != "execute"
                            ]

                            if unexecuted:
                                content_str += (
                                    f"\n\n[SYSTEM: PLANNED TOOLS NOT EXECUTED!]\n"
                                    f"You PLANNED to use these tools but haven't executed them: {
                                        ', '.join(unexecuted)}\n"
                                    f"You MUST execute these tools now before moving to the next phase!\n"
                                    f"Examples:\n"
                                    f"- For 'sqlmap': sqlmap -u 'URL' --batch --level=5 --risk=3\n"
                                    f"- For 'nuclei': nuclei -l output/urls.txt -severity critical,high\n"
                                    f"- For 'browser_action': browser_action action='goto' url='https://target'\n"
                                    f"DO NOT skip tools you planned to use!"
                                )

                        content_str += (
                            "\n\n[SYSTEM: SELF-CHECK] MANDATORY — Answer these BEFORE continuing:\n"
                            "1. Does this tool generate NEW output not already in output/ directory? (Check first!)\n"
                            "2. If output file exists: is the existing data sufficient, or do you need fresh data?\n"
                            "3. Does this advance toward exploitation, or are you just repeating recon?\n"
                            "4. Have you already run this exact command in this session? (Check tool_history)\n"
                            "If answer to Q1=NO or Q2=sufficient or Q3=recon or Q4=YES: "
                            "SKIP redundant execution, move to next phase or emit [TASK_COMPLETE]."
                        )

                    self._append_tool_result(
                        tool_name, content_str, success, tc.get("id")
                    )

                # Persist session state incrementally after every tool
                # execution
                if self._session:
                    save_session(self._session)

                if _has_task_complete:
                    logger.info(
                        "Agent emitted [TASK_COMPLETE] after tools — stopping.")
                    yield AgentEvent(type="done", data={})
                    return

            yield AgentEvent(
                type="error", data={"message": "Max tool iterations reached."}
            )
            yield AgentEvent(type="done", data={})

        except Exception as e:
            logger.exception("Fatal error in agent loop")
            yield AgentEvent(
                type="error", data={"message": f"Fatal Agent Error: {str(e)}"}
            )
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
            tool_msg: dict[str, Any] = {
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

    def get_stats(self) -> dict[str, Any]:
        return {
            "message_count": len(self.state.conversation),
            "tool_counts": self.state.tool_counts,
            "token_usage": self.state.token_usage,
            "skills_used": self.state.skills_used,
        }

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
                    candidate = text[start_idx: i + 1]
                    # Only try if it looks like a tool call (has "name" key)
                    if '"name"' in candidate or "'name'" in candidate:
                        tc = self._parse_tool_call_json(
                            candidate, registered_tools)
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
        tc_name = parsed.get("name") or parsed.get(
            "function", {}).get("name", "")
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
        # Use possessive-style pattern for /* */ to avoid catastrophic backtracking
        # on unclosed comments in malformed LLM output.
        cleaned = re.sub(r"//[^\n]*", "", raw)
        cleaned = re.sub(r"/\*[^*]*(?:\*(?!/)[^*]*)*\*/", "", cleaned)
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

    # Extensions that support line-based merge+sort (text, not
    # binary/structured)
    _MERGEABLE_EXTENSIONS = frozenset(
        {".txt", ".csv", ".list", ".hosts", ".log", ".out"})

    def _get_command_output_file(
            self, arguments: dict[str, Any]) -> tuple[str | None, "Path | None"]:
        """Extract the output file path from a command's -o / --output flags.

        Returns (relative_path_str, full_Path) or (None, None) if not found.
        """
        import shlex
        cmd = arguments.get("command", "")
        if not cmd or not self.state.active_target:
            return None, None
        try:
            tokens = shlex.split(cmd)
        except ValueError:
            return None, None

        output_file: str | None = None
        for i, token in enumerate(tokens):
            if token in ("-o", "--output", "-oX", "-oN", "-oG",
                         "-oA", "-oJ") and i + 1 < len(tokens):
                output_file = tokens[i + 1]
                break
            if token.startswith(
                    "-o") and len(token) > 2 and not token.startswith("-oX"):
                output_file = token[2:]
                break

        if not output_file:
            return None, None

        workspace = get_workspace_root() / self.state.active_target
        full_path = (
            workspace / output_file
            if not output_file.startswith("/")
            else Path(output_file)
        )
        return output_file, full_path

    def _check_output_dedup(self, arguments: dict[str, Any]) -> None:
        """If the command's output file already exists, save old content for post-run merge.

        Never blocks — the command always runs. New results are merged+sorted afterwards.
        """
        output_file, full_path = self._get_command_output_file(arguments)
        if not output_file or not full_path:
            return
        if not full_path.exists() or full_path.stat().st_size <= 100:
            return
        # Only pre-save mergeable (line-based) file types
        if full_path.suffix.lower() not in self._MERGEABLE_EXTENSIONS:
            return
        try:
            old_lines = full_path.read_text(errors="ignore").splitlines()
            self._pending_output_merges[str(full_path)] = old_lines
            logger.info(
                f"Saved {
                    len(old_lines)} existing lines from '{output_file}' for post-run merge")
        except Exception as e:
            logger.warning(
                f"Could not save old content of '{output_file}' for merge: {e}")

    def _apply_output_merge(
            self, arguments: dict[str, Any], success: bool) -> None:
        """After a successful execute, merge old + new output lines, dedup, sort."""
        if not success:
            return
        output_file, full_path = self._get_command_output_file(arguments)
        if not output_file or not full_path:
            return
        old_lines = self._pending_output_merges.pop(str(full_path), None)
        if old_lines is None:
            return  # Nothing pre-saved, nothing to merge
        if not full_path.exists():
            return  # Command produced no output file
        try:
            new_lines = full_path.read_text(errors="ignore").splitlines()
            old_set = {line.strip() for line in old_lines if line.strip()}
            new_set = {line.strip() for line in new_lines if line.strip()}
            added = new_set - old_set
            merged = sorted(old_set | new_set)
            full_path.write_text("\n".join(merged) + "\n", encoding="utf-8")
            logger.info(
                f"Merged '{output_file}': {len(added)} new entries added, "
                f"{len(merged)} total lines (sorted)"
            )
        except Exception as e:
            logger.warning(f"Failed to merge output file '{output_file}': {e}")

    # Tool alternative suggestions for smart retry
    _TOOL_ALTERNATIVES: dict[str, str] = _TOOLS_META.get(
        "tool_alternatives", {})

    def _suggest_alternative_tool(
            self, tool_name: str, command: str = "") -> str:
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

    def _build_critical_findings_context(self) -> str:
        """Build critical findings context to pin before truncation."""
        if not self._session:
            return ""

        s = self._session
        parts = ["[SYSTEM: CRITICAL FINDINGS — DO NOT LOSE]"]

        if s.subdomains:
            parts.append(
                f"SUBDOMAINS ({len(s.subdomains)}): {', '.join(s.subdomains[:20])}"
            )
            if len(s.subdomains) > 20:
                parts.append(f"... and {len(s.subdomains) - 20} more")

        if s.live_hosts:
            parts.append(
                f"LIVE HOSTS ({len(s.live_hosts)}): {', '.join(s.live_hosts[:15])}"
            )

        if s.open_ports:
            port_summary = []
            for host, ports in list(s.open_ports.items())[:10]:
                port_summary.append(f"{host}:{','.join(map(str, ports[:5]))}")
            parts.append(f"OPEN PORTS: {'; '.join(port_summary)}")

        if s.urls:
            parts.append(f"URLs ({len(s.urls)}): {', '.join(s.urls[:10])}")

        if s.vulnerabilities:
            vuln_vals = []
            for v in s.vulnerabilities[:10]:
                vt = v.get("title", v.get("finding", "Unknown"))
                vf = v.get("flag")
                if vf:
                    vuln_vals.append(f"{vt} (FLAG: {vf})")
                else:
                    vuln_vals.append(vt)
            parts.append(f"VULNERABILITIES: {'; '.join(vuln_vals)}")

        if s.completed_phases:
            parts.append(f"COMPLETED PHASES: {', '.join(s.completed_phases)}")

        return "\n".join(parts)

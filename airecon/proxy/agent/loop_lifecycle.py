from __future__ import annotations

import asyncio
import logging
import os
import time

from ..config import get_config
from ..memory import get_memory_manager
from ..system import _is_ctf_target
from .models import AgentState
from .pipeline import PipelineEngine
from .session import SessionData
from .tool_defs import get_tool_definitions

logger = logging.getLogger("airecon.agent")


class _LifecycleMixin:
    async def refresh_tool_registry(self) -> None:
        engine_tools = await self.engine.discover_tools()
        tools_llm = self.engine.tools_to_llm_format(engine_tools)
        tools_llm.extend(get_tool_definitions())

        unique: dict[str, dict] = {}
        for t in tools_llm:
            fn = t.get("function", {}) if isinstance(t, dict) else {}
            name = fn.get("name")
            if isinstance(name, str) and name:
                unique[name] = t

        rebuilt = list(unique.values())
        if self._blocked_tools:
            rebuilt = [
                t
                for t in rebuilt
                if t.get("function", {}).get("name") not in self._blocked_tools
            ]

        self._tools_llm = rebuilt

    async def initialize(
        self,
        target: str | None = None,
        user_message: str | None = None,
    ) -> None:
        from . import loop as _loop_module

        self.state.conversation = [
            {
                "role": "system",
                "content": _loop_module.get_system_prompt(
                    target=target, user_message=user_message
                ),
            }
        ]

        if _is_ctf_target(target, user_message):
            self._ctf_mode = True
            if self._override_max_iterations is None:
                self._override_max_iterations = self._CTF_MAX_ITERATIONS

            _ctf_cfg = get_config()
            if self._adaptive_num_ctx == 0:
                self._adaptive_num_ctx = _ctf_cfg.llm_context_window_small
            logger.info(
                "CTF mode activated for target=%r — ctx=%d, max_iterations=%d",
                target,
                self._adaptive_num_ctx,
                self._CTF_MAX_ITERATIONS,
            )
        await self.refresh_tool_registry()

        if self.engine:
            self.state.add_message("system", "[SYSTEM: EXECUTE_COMMAND_AVAILABLE=yes]")

        from ..caido_client import CaidoClient

        try:
            _caido_token = await asyncio.wait_for(CaidoClient._get_token(), timeout=5.0)
        except (asyncio.TimeoutError, Exception) as _caido_err:
            logger.debug("Caido token check failed: %s", _caido_err)
            _caido_token = None
        self._caido_available: bool = bool(_caido_token)
        if _caido_token:
            self.state.add_message(
                "system",
                "[SYSTEM: CAIDO_PROXY=available port=48080] "
                "Caido web proxy is running and capturing ALL HTTP traffic automatically. "
                "Call caido_list_requests NOW (no scope setup needed) to retrieve captured "
                "requests — this reveals real app endpoints, auth flows, cookies, hidden "
                "parameters, and injection points that active scanning cannot find. "
                "After reviewing captured requests, use caido_set_scope to focus future "
                "captures, then periodically call caido_list_requests to check for new traffic.",
            )
        else:
            self.state.add_message(
                "system",
                "[SYSTEM: CAIDO_PROXY=unavailable] "
                "Caido is not running/authenticated on host yet — do NOT call caido_* tools now and NEVER try 'caido-setup' via execute. "
                "Ask user to start/login Caido externally, then verify with caido_intercept(action='status').",
            )

        logger.info("Agent initialized with %d tools", len(self._tools_llm or []))

        tool_names = [t["function"]["name"] for t in self._tools_llm]
        self.state.add_message(
            "system", f"[SYSTEM: REGISTERED TOOLS]\n{', '.join(tool_names)}"
        )

        self._initial_messages = list(self.state.conversation)

        _target = target or self.state.active_target
        if _target:
            try:
                memory = get_memory_manager()
                self._memory_manager = memory
                _memory_context = memory.get_context_for_small_model(
                    target=_target,
                    current_phase=self._session.current_phase
                    if self._session
                    else "RECON",
                    max_tokens=2000,
                )
                if _memory_context:
                    logger.info(
                        "Memory augmentation: loaded context for %s (%d bytes)",
                        _target,
                        len(_memory_context),
                    )
                    self.state.add_message(
                        "system",
                        f"## MEMORY AUGMENTATION (from past sessions)\n{_memory_context}",
                    )

                    # Inject tool performance patterns
                    # Show the agent which tools historically succeed/fail
                    try:
                        tool_stats = memory.get_tool_statistics()
                        if isinstance(tool_stats, list) and tool_stats:
                            high_sr = [
                                t
                                for t in tool_stats
                                if t.get("success_count", 0) + t.get("failure_count", 0) >= 2
                                and t.get("success_count", 0) / max(
                                    t.get("success_count", 0) + t.get("failure_count", 0), 1
                                )
                                >= 0.70
                            ]
                            low_sr = [
                                t
                                for t in tool_stats
                                if t.get("success_count", 0) + t.get("failure_count", 0) >= 3
                                and t.get("success_count", 0) / max(
                                    t.get("success_count", 0) + t.get("failure_count", 0), 1
                                )
                                < 0.50
                            ]
                            if high_sr or low_sr:
                                parts = [
                                    "[SYSTEM: HISTORICAL TOOL PERFORMANCE — learn from past sessions]"
                                ]
                                if high_sr:
                                    lines = []
                                    for t in high_sr[:5]:
                                        total = t["success_count"] + t["failure_count"]
                                        sr = t["success_count"] / max(total, 1) * 100
                                        lines.append(
                                            f"- {t['tool_name']}: {sr:.0f}% success ({total} runs) — proven reliable"
                                        )
                                    parts.append("Proven tools (use these first):")
                                    parts.extend(lines)
                                if low_sr:
                                    lines = []
                                    for t in low_sr[:5]:
                                        total = t["success_count"] + t["failure_count"]
                                        sr = t["success_count"] / max(total, 1) * 100
                                        lines.append(
                                            f"- {t['tool_name']}: {sr:.0f}% success ({total} runs) — unreliable, use with caution"
                                        )
                                    parts.append(
                                        "Unreliable tools (avoid or expect issues):"
                                    )
                                    parts.extend(lines)
                                self.state.add_message("system", "\n".join(parts))
                    except Exception as _tool_perf_err:
                        logger.debug(
                            "Tool performance injection failed: %s", _tool_perf_err
                        )
            except Exception as _mem_err:
                logger.debug("Memory augmentation failed: %s", _mem_err)

        _session_id = (
            os.environ.get("AIRECON_SESSION_ID") if not self._is_subagent else None
        )
        if _session_id:
            # _loop_module = get_loop_module()
            self._session = _loop_module.load_session(_session_id) or SessionData(
                session_id=_session_id,
                target=target or "",
            )
            logger.info(
                "Loaded session %s (target=%s)", _session_id, self._session.target
            )
        else:
            self._session = SessionData(target=target or "")
            logger.info("Created new session %s", self._session.session_id)
        self._sync_recovery_state_from_session()
        self._sync_token_usage_from_session()

        # Cross-session persistence: load payload memory + adaptive learning
        if hasattr(self, "_load_session_persistence"):
            try:
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    loop.create_task(self._load_session_persistence())
            except Exception as exc:
                logger.warning("Operation failed: %s", exc)

        self.pipeline = PipelineEngine(self._session)
        if self._ctf_mode and self.pipeline:
            self.pipeline.set_ctf_mode(True)

    def reset(self) -> None:

        old_target = ""
        old_subdomains = []
        old_live_hosts = []
        old_vulns = []
        if self._session:
            old_target = self._session.target or ""
            old_subdomains = list(self._session.subdomains or [])
            old_live_hosts = list(self._session.live_hosts or [])
            old_vulns = list(self._session.vulnerabilities or [])

        if self._token_snapshot_task and not self._token_snapshot_task.done():
            self._token_snapshot_task.cancel()
        self._token_snapshot_task = None
        self._token_snapshot_resave_requested = False
        self.state = AgentState()
        if self._initial_messages:
            self.state.conversation = list(self._initial_messages)
        self._executed_tool_counts.clear()
        self._executed_cmd_hashes.clear()
        self._executed_cmd_order.clear()
        self._last_output_file = None
        self._stagnation_iterations = 0
        self._recent_tool_names.clear()
        self._last_evidence_count = 0
        self._watchdog_forced_calls = 0
        self._adaptive_num_ctx = 0
        self._vram_crash_count = 0
        self._adaptive_num_predict_cap = 0
        self._fatal_llm_error = ""
        self._context_check_task = None

        self._session = SessionData(target=old_target)
        if old_subdomains:
            self._session.subdomains = old_subdomains
        if old_live_hosts:
            self._session.live_hosts = old_live_hosts
        if old_vulns:
            self._session.vulnerabilities = old_vulns
        self.pipeline = PipelineEngine(self._session)
        if self._ctf_mode and self.pipeline:
            self.pipeline.set_ctf_mode(True)

    async def _reset_llm_context(self) -> bool:
        if not hasattr(self, "llm") or not self.llm:
            return False

        summary = self._build_recon_summary()
        system_prompt = self._build_system_prompt_for_reset()
        full_prompt = f"{system_prompt}\n\n{summary}"

        last_error: Exception | None = None
        if not hasattr(self, "_context_reset_failures"):
            self._context_reset_failures = 0
        for attempt in range(1, 4):
            try:
                success = await self.llm.reset_context(full_prompt)
                if success:
                    logger.info(
                        "LLM context reset with recon summary (tokens: ~%d, attempt=%d)",
                        len(full_prompt) // 4,
                        attempt,
                    )
                    self._context_reset_failures = 0
                    return True
                status = getattr(self.llm, "_last_reset_status", None)
                err_text = str(getattr(self.llm, "_last_reset_error", "") or "").lower()
                if status == 500 or "internal server error" in err_text:
                    last_error = RuntimeError(err_text or "internal server error")
                    self._disable_context_reset_until = time.time() + 900.0
                    logger.warning(
                        "Disabling context reset for 15 minutes due to server 500 errors"
                    )
                    break
            except Exception as e:
                last_error = e

            if attempt < 3:
                await asyncio.sleep(0.25 * attempt)

        if last_error:
            logger.warning("LLM context reset failed after retries: %s", last_error)
            err_text = str(last_error).lower()
            if "runner has unexpectedly stopped" in err_text:
                self._fatal_llm_error = str(last_error)
                logger.error(
                    "Fatal LLM runner failure detected during context reset"
                )
            if "internal server error" in err_text or "500" in err_text:
                self._disable_context_reset_until = time.time() + 900.0
                logger.warning(
                    "Disabling context reset for 15 minutes due to server 500 errors"
                )
        else:
            logger.warning(
                "LLM context reset failed after retries (no exception details)"
            )

        self._context_reset_failures += 1
        try:
            self._apply_local_context_fallback(
                reason="llm reset failed",
                target_messages=40 if not self._ctf_mode else 16,
            )
        except TypeError as exc:
            logger.debug(
                "Fallback signature mismatch for _apply_local_context_fallback: %s",
                exc,
            )
            self._apply_local_context_fallback(reason="llm reset failed")
        return False

    def _apply_local_context_fallback(
        self,
        reason: str = "",
        target_messages: int | None = None,
    ) -> None:
        prev_messages = len(self.state.conversation)
        if prev_messages == 0:
            return

        _critical_ctx = self._build_critical_findings_context()
        _handoff_ctx = self._build_handoff_summary()

        if target_messages is None:
            target_messages = 16 if self._ctf_mode else 40
        self.state.truncate_conversation(max_messages=target_messages)

        if _handoff_ctx:
            self.state.conversation.append({"role": "system", "content": _handoff_ctx})
        if _critical_ctx:
            self.state.conversation.append({"role": "system", "content": _critical_ctx})

        before_used = int(self.state.token_usage.get("used", 0) or 0)
        try:
            self.state.token_usage["used"] = (
                self._recompute_used_tokens_from_conversation()
            )
        except Exception as e:
            logger.debug(
                "Expected failure recomputing token usage after fallback: %s", e
            )
            if before_used > 0:
                self.state.token_usage["used"] = max(0, int(before_used * 0.65))

        logger.warning(
            "Local context fallback applied (%s): %d -> %d messages, token_used %d -> %d",
            reason or "no-reason",
            prev_messages,
            len(self.state.conversation),
            before_used,
            int(self.state.token_usage.get("used", 0) or 0),
        )

    def _build_recon_summary(self) -> str:
        if not self._session:
            return "[No recon progress yet]"

        lines = [
            "=== RECON PROGRESS SUMMARY ===",
            f"Target: {self._session.target}",
            f"Phase: {self._get_current_phase().value if self.pipeline else 'UNKNOWN'}",
            f"Iteration: {self.state.iteration}/{self.state.max_iterations}",
        ]

        goal = ""
        for msg in self.state.conversation:
            if msg.get("role") == "user":
                goal = str(msg.get("content", "")).strip()
                if goal:
                    break
        if goal:
            lines.append(f"Goal: {goal[:220]}")

        pending_objs = [
            o
            for o in (self.state.objective_queue or [])
            if o.get("status") == "pending"
        ][:3]
        if pending_objs:
            lines.append("Active objectives:")
            for obj in pending_objs:
                title = str(obj.get("title") or obj.get("description") or "").strip()
                if title:
                    lines.append(f"- {title[:140]}")

        lines.extend([
            "",
            "--- DISCOVERIES ---",
            f"Subdomains: {len(self._session.subdomains)} found",
            f"Live Hosts: {len(self._session.live_hosts)} found",
            f"Open Ports: {sum(len(p) for p in self._session.open_ports.values())} found",
            f"URLs: {len(self._session.urls)} discovered",
            f"Vulnerabilities: {len(self._session.vulnerabilities)} confirmed",
            "",
            "--- TOOLS RUN ---",
            f"Tools used: {', '.join(list(self._session.tools_run)[:10])}{'...' if len(self._session.tools_run) > 10 else ''}",
            "",
            "--- RECENT FINDINGS ---",
        ])

        recent_evidence = (
            self.state.evidence_log[-5:] if self.state.evidence_log else []
        )
        for ev in recent_evidence:
            if isinstance(ev, dict):
                lines.append(
                    f"- {ev.get('summary', ev.get('finding', 'Unknown'))[:100]}"
                )

        if not recent_evidence:
            lines.append("- No recent findings yet")

        lines.append("")
        lines.append("[END SUMMARY - Continue testing from this point]")

        return "\n".join(lines)

    def _build_system_prompt_for_reset(self) -> str:
        return """[SYSTEM: AIRecon Security Testing Agent]
You are an expert penetration tester conducting authorized security assessments.
Your role: Discover vulnerabilities, validate findings, and create actionable reports.

Rules:
1. Stay in character as security tester
2. Use tools methodically - recon → analysis → exploit → report
3. Validate all findings before reporting
4. Never hallucinate tools or results
5. Ask for user input when blocked (CAPTCHA, TOTP, etc.)

Current workflow: Follow phase transitions (RECON→ANALYSIS→EXPLOIT→REPORT)"""

    def _check_llm_context_pressure(self):
        if not hasattr(self, "llm") or not self.llm:
            return
        if (
            not hasattr(self, "_context_check_task")
            or self._context_check_task is None
            or self._context_check_task.done()
        ):
            self._context_check_task = asyncio.create_task(
                self._check_and_reset_context()
            )
            self._context_check_task.add_done_callback(
                lambda t: (
                    logger.debug("Context check finished: %s", t.exception())
                    if t.exception()
                    else None
                )
            )

    async def _check_and_reset_context(self):
        import time

        now = time.time()
        disable_until = float(getattr(self, "_disable_context_reset_until", 0.0) or 0.0)
        if now < disable_until:
            logger.warning(
                "Context reset temporarily disabled (%.0fs remaining)",
                max(0.0, disable_until - now),
            )
            return

        if not hasattr(self, "_last_context_check"):
            self._last_context_check = 0.0

        if not hasattr(self, "_ctf_mode"):
            self._ctf_mode = False

        check_interval = 30 if self._ctf_mode else 60
        if now - self._last_context_check < check_interval:
            return

        self._last_context_check = now

        if not hasattr(self, "llm") or not self.llm:
            return

        from ..llm import _CONTEXT_RESET_THRESHOLD
        from . import loop as _loop_module

        # Remote OpenAI-compatible gateways are stateless: there is no server-side
        # KV cache to poll (no LLM /api/ps). Drive context-pressure detection
        # purely from our local token-usage estimate.
        used_estimate = int(self.state.token_usage.get("used", 0) or 0)

        cfg = _loop_module.get_config()
        ctf_mode = getattr(self, "_ctf_mode", False)

        if ctf_mode:
            ctx_limit = getattr(cfg, "llm_context_window_small", 65536)
            threshold = int(ctx_limit * 0.70)
        else:
            ctx_limit = _CONTEXT_RESET_THRESHOLD
            threshold = _CONTEXT_RESET_THRESHOLD

        if used_estimate < threshold:
            return

        last_reset = float(getattr(self, "_last_context_reset_ts", 0.0) or 0.0)
        _RESET_COOLDOWN_SECONDS = (
            60.0
            if ctf_mode
            else float(
                max(
                    0,
                    int(
                        getattr(cfg, "agent_context_reset_cooldown_seconds", 300) or 0
                    ),
                )
            )
        )
        _failures = int(getattr(self, "_context_reset_failures", 0) or 0)
        if _failures > 0:
            _RESET_COOLDOWN_SECONDS += min(600.0, _failures * 120.0)
        if now - last_reset < _RESET_COOLDOWN_SECONDS:
            logger.warning(
                "Context reset cooldown active (ctf=%s, used=%d, remaining=%.0fs)",
                ctf_mode,
                used_estimate,
                max(0.0, _RESET_COOLDOWN_SECONDS - (now - last_reset)),
            )
            return

        logger.error(
            "CONTEXT CRITICAL: ctf=%s, used=%d, threshold=%d - resetting with summary injection",
            ctf_mode,
            used_estimate,
            threshold,
        )
        self._last_context_reset_ts = now
        reset_ok = await self._reset_llm_context()
        if not reset_ok:
            logger.warning(
                "Context reset unavailable; continued with local fallback compaction"
            )
        return

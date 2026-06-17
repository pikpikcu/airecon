from __future__ import annotations

from ..config import get_config, get_workspace_root
from ..system import _is_ctf_target, auto_load_skills_for_message
from .file_reference import (
    build_injection_message,
    parse_refs,
    resolve_ref,
    strip_refs,
    workspace_name_for_ref,
)
from .loop_policy import (
    build_full_recon_kickoff_message,
    extract_wildcard_scope_target,
    is_simple_target_kickoff,
    normalize_recon_mode,
    should_autostart_full_recon,
    should_switch_active_target,
)
from .models import MAX_TOOL_ITERATIONS
from .pipeline import PipelineEngine, PipelinePhase
from .session import (
    SessionData,
    find_prior_session,
    merge_prior_findings,
    session_to_context,
)
from .loop_exploration import _get_meaningful_evidence_threshold
from .target_prioritizer import TargetPrioritizer
import logging
import asyncio
from pathlib import Path

logger = logging.getLogger("airecon.agent")


class _MessageEntryMixin:
    async def _prepare_message_context(self, user_message: str):

        _file_refs = parse_refs(user_message)
        if _file_refs:
            user_message = strip_refs(user_message, _file_refs)

        all_targets = self._extract_targets_from_text(user_message)
        extracted_target = all_targets[0] if all_targets else None

        wildcard_scope_target = extract_wildcard_scope_target(user_message)
        if wildcard_scope_target:
            extracted_target = wildcard_scope_target
            all_targets = [wildcard_scope_target] + [
                t for t in all_targets if t != wildcard_scope_target
            ]

        if not self._tools_llm:
            await self.initialize(
                target=extracted_target,
                user_message=user_message,
            )
        else:
            if not self._ctf_mode and extracted_target:
                if _is_ctf_target(extracted_target, user_message=None):
                    self._ctf_mode = True
                    if self._override_max_iterations is None:
                        self._override_max_iterations = self._CTF_MAX_ITERATIONS
                    if self.pipeline:
                        self.pipeline.set_ctf_mode(True)

                    if self._adaptive_num_ctx == 0:
                        self._adaptive_num_ctx = get_config().llm_context_window_small
                    logger.info(
                        "CTF mode activated mid-session for target=%r — ctx=%d",
                        extracted_target,
                        self._adaptive_num_ctx,
                    )

        cfg = get_config()

        _recon_mode = normalize_recon_mode(getattr(cfg, "agent_recon_mode", "standard"))
        _simple_kickoff = is_simple_target_kickoff(user_message, extracted_target)
        _requested_scope_lock = False

        if extracted_target:
            _current = self.state.active_target
            _switch_target = should_switch_active_target(
                extracted_target=extracted_target,
                current_active_target=_current,
                user_message=user_message,
                scope_lock_active=_requested_scope_lock,
            )
            if _switch_target:
                logger.info(
                    "Scope target switch: %r -> %r",
                    _current,
                    extracted_target,
                )
                self.state.active_target = extracted_target
                self._scope_anchor_target = extracted_target
            elif not _current:
                self.state.active_target = extracted_target
                self._scope_anchor_target = extracted_target
            elif _current != extracted_target:
                logger.info(
                    "Scope guard kept active target=%r (extracted=%r)",
                    _current,
                    extracted_target,
                )

        if _file_refs and not self.state.active_target:
            self.state.active_target = workspace_name_for_ref(_file_refs[0])
            self._scope_anchor_target = self.state.active_target

        if isinstance(extracted_target, str) and should_autostart_full_recon(
            cfg=cfg,
            user_message=user_message,
            extracted_target=extracted_target,
        ):
            logger.info(
                "Auto-starting deep recon (agent_recon_mode=%s) for %s",
                _recon_mode,
                extracted_target,
            )
            user_message = build_full_recon_kickoff_message(extracted_target)
            _simple_kickoff = True
            _requested_scope_lock = False

        self._scope_lock_active = _requested_scope_lock
        self._scope_lock_brief = (
            user_message.strip()[:500] if self._scope_lock_active else ""
        )
        if self._scope_lock_active:
            self.state.conversation.append(
                {
                    "role": "system",
                    "content": (
                        "[SYSTEM: STRICT_SCOPE_MODE] "
                        "The current user request is scoped/focused. "
                        "Do NOT widen into broad/full recon, port sweeps, or unrelated phases. "
                        "Execute only actions directly required by the explicit user request."
                    ),
                }
            )

        from .constants import EPHEMERAL_PREFIXES
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

        if self.state.iteration % 10 == 0:
            self._check_llm_context_pressure()

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
            if not self._scope_anchor_target:
                self._scope_anchor_target = self.state.active_target
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

            _lock = getattr(self, "_session_lock", None)
            if _lock is not None:
                async with _lock:
                    await self._create_or_switch_session()
            else:
                await self._create_or_switch_session()

            if (
                self._session
                and self._session.scan_count == 0
                and not getattr(self._session, "_prior_merged", False)
            ):
                prior = find_prior_session(self.state.active_target)
                if prior and prior.session_id != self._session.session_id:
                    merge_prior_findings(self._session, prior)

                    _prior_ctx = (
                        f"[PRIOR SESSION MEMORY] Loaded {len(prior.subdomains)} subdomains, "
                        f"{len(prior.urls)} URLs, {len(prior.injection_points)} injection points "
                        f"from previous scan of {self.state.active_target} "
                        f"(session {prior.session_id}). "
                        "This data is pre-populated in your session — no need to rediscover them. "
                        "Focus on new coverage and deeper exploitation."
                    )
                    self.state.conversation.append(
                        {"role": "system", "content": _prior_ctx}
                    )
                    logger.info(
                        "Cross-session memory: merged prior session %s → %s",
                        prior.session_id,
                        self._session.session_id,
                    )

                self._session._prior_merged = True

            if self._session and self._session.scan_count > 0:
                session_ctx = session_to_context(self._session)
                self.state.conversation.append(
                    {
                        "role": "system",
                        "content": session_ctx,
                    }
                )

                prioritizer = TargetPrioritizer()
                high_value_urls = []
                for url in list(self._session.urls):
                    ts = prioritizer.score_url(url)
                    if ts.score >= 0.5:
                        high_value_urls.append(ts)

                if high_value_urls:
                    high_value_urls.sort(key=lambda s: s.score, reverse=True)
                    top_targets = high_value_urls[:5]
                    lines = [
                        "[SYSTEM: HIGH-VALUE TARGETS DETECTED]",
                        "The following endpoints have been identified as high-priority for testing:",
                        "",
                    ]
                    for i, ts in enumerate(top_targets, 1):
                        lines.append(
                            f"  {i}. {ts.target} (score: {ts.score:.2f}, category: {ts.category})"
                        )
                        if ts.reasons:
                            lines.append(f"     Why: {'; '.join(ts.reasons[:2])}")
                        if ts.attack_vectors:
                            lines.append(
                                f"     Vectors: {', '.join(ts.attack_vectors[:3])}"
                            )
                    lines.append("")
                    lines.append(
                        "Prioritize these endpoints in your next tool calls. "
                        "Focus on the highest-scoring targets first."
                    )
                    self.state.conversation.append(
                        {"role": "system", "content": "\n".join(lines)}
                    )
                    logger.info(
                        "Dynamic re-prioritization: injected %d high-value targets (top score: %.2f)",
                        len(high_value_urls),
                        high_value_urls[0].score,
                    )

                if self.pipeline:
                    _resumed_phase = self.pipeline.get_current_phase()
                    self._sync_phase_objectives(_resumed_phase)
                    self._update_objectives_from_session(_resumed_phase)

        self.state.conversation = [
            msg
            for msg in self.state.conversation
            if not (
                msg.get("role") == "system"
                and msg.get("content", "").startswith("[SYSTEM: PINNED CONTEXT]")
            )
        ]
        if self.state.active_target:
            phase_hint = ""
            try:
                if self.pipeline:
                    phase_hint = self.pipeline.get_current_phase().value
            except Exception as e:
                logger.warning("Operation failed: %s", e)
                phase_hint = ""
            pin_lines = [
                "[SYSTEM: PINNED CONTEXT]",
                f"TARGET: {self.state.active_target}",
            ]
            if self._scope_anchor_target:
                pin_lines.append(f"SCOPE_ANCHOR: {self._scope_anchor_target}")
            pin_lines.append(
                f"SCOPE_LOCK: {'ACTIVE' if self._scope_lock_active else 'INACTIVE'}"
            )
            if self._scope_lock_active and self._scope_lock_brief:
                pin_lines.append(f"SCOPE_BRIEF: {self._scope_lock_brief[:180]}")
            if phase_hint:
                pin_lines.append(f"PHASE: {phase_hint}")
            pin_lines.append("Do not change target unless the user explicitly asks.")
            pin_lines.append(
                "Use session summary and critical findings as the source of truth."
            )
            self.state.conversation.append(
                {"role": "system", "content": "\n".join(pin_lines)}
            )

        if _file_refs:
            _workspace_root = get_workspace_root().resolve()
            _workspace_dir = (
                _workspace_root / (self.state.active_target or "uploads")
            ).resolve()
            try:
                _workspace_dir.relative_to(_workspace_root)
            except ValueError:
                logger.warning(
                    "Blocked unsafe workspace target %r for file refs; using fallback uploads/",
                    self.state.active_target,
                )
                _workspace_dir = _workspace_root / "uploads"
            _resolved = await asyncio.to_thread(
                lambda: [resolve_ref(r, _workspace_dir) for r in _file_refs]
            )
            _injection = build_injection_message(_resolved)
            if _injection:
                self.state.conversation.append(
                    {"role": "system", "content": _injection}
                )

        self.state.conversation.append({"role": "user", "content": user_message})

        _ctx_limit = (
            self._adaptive_num_ctx
            if self._adaptive_num_ctx > 0
            else int(getattr(cfg, "llm_context_window", 0) or 0)
        )
        _ctx_used = int(self.state.token_usage.get("used", 0) or 0)
        if _ctx_used <= 0:
            _ctx_used = self._recompute_used_tokens_from_conversation()

        if _ctx_limit != -1 and _ctx_limit > 0:
            _SOFT_CTX_RATIO = 0.65
            _HARD_CTX_RATIO = 0.80
            _ctx_soft_cap = int(_ctx_limit * _SOFT_CTX_RATIO)
            _ctx_hard_cap = int(_ctx_limit * _HARD_CTX_RATIO)

            if _ctx_used > _ctx_hard_cap:
                logger.error(
                    "Context tokens (%d) exceeded hard cap (%d, num_ctx=%d) — forcing emergency truncation",
                    _ctx_used,
                    _ctx_hard_cap,
                    _ctx_limit,
                )

                _system_msgs = [
                    m for m in self.state.conversation if m.get("role") == "system"
                ]
                _non_system = [
                    m for m in self.state.conversation if m.get("role") != "system"
                ]
                _keep_recent = max(int(len(_non_system) * 0.20), 6)
                _recent_msgs = _non_system[-_keep_recent:]
                _prev_total = len(self.state.conversation)
                self.state.conversation = _system_msgs + _recent_msgs

                _new_used = self._recompute_used_tokens_from_conversation()

                logger.warning(
                    "Emergency truncation complete: %d messages → %d "
                    "(sys=%d kept, non-sys %d → %d), context-used %d → %d tokens",
                    _prev_total,
                    len(self.state.conversation),
                    len(_system_msgs),
                    len(_non_system),
                    len(_recent_msgs),
                    _ctx_used,
                    _new_used,
                )
            elif _ctx_used > _ctx_soft_cap:
                logger.warning(
                    "Context tokens (%d) approaching soft cap (%d, num_ctx=%d) — will truncate soon",
                    _ctx_used,
                    _ctx_soft_cap,
                    _ctx_limit,
                )

        _skill_phase = self._skill_phase_for_message_start()

        _session_skills = None
        if self._session:
            _session_skills = set(self._session.loaded_skills)
        _current_target = (
            self.state.active_target
            if self.state.active_target
            else (self._session.target if self._session else "")
        )
        _memory_manager = getattr(self, "_memory_manager", None)
        if _memory_manager is None and _current_target:
            try:
                from ..memory import get_memory_manager

                _memory_manager = get_memory_manager()
                self._memory_manager = _memory_manager
            except Exception as exc:
                logger.debug("Memory manager lazy init failed: %s", exc)
        skill_context, loaded_skills = auto_load_skills_for_message(
            user_message,
            phase=_skill_phase,
            session_loaded_skills=_session_skills,
            memory_manager=_memory_manager,
            current_target=_current_target,
        )
        if loaded_skills:
            for s in loaded_skills:
                _skill_name = Path(str(s)).stem
                if _skill_name not in self.state.skills_used:
                    self.state.skills_used.append(_skill_name)

            if self._session:
                for skill_rel in loaded_skills:
                    if skill_rel not in self._session.loaded_skills:
                        self._session.loaded_skills.append(skill_rel)

        if skill_context:
            self.state.conversation.append(
                {
                    "role": "system",
                    "content": skill_context,
                    "iteration": self.state.iteration,
                }
            )

        self.state.iteration = 0
        self.state.max_iterations = (
            self._override_max_iterations
            or cfg.agent_max_tool_iterations
            or MAX_TOOL_ITERATIONS
        )
        self.state.warnings_sent = False
        self._stop_requested = False
        self._consecutive_failures = 0
        self._mentor_tool_call_count = 0
        self._no_tool_iterations = 0
        self._stagnation_iterations = 0
        self._recent_tool_names = []
        self._last_evidence_count = sum(
            1
            for e in self.state.evidence_log
            if e.get("confidence", 0) >= _get_meaningful_evidence_threshold()
        )
        self._watchdog_forced_calls = 0
        self._empty_response_retry_count = 0
        self._prev_phase = None

        import uuid

        self._current_trace_id = uuid.uuid4().hex[:12]

        if (
            self._session
            and getattr(self._session, "current_phase", "") == "COMPLETE"
            and self.pipeline
        ):
            self.pipeline.set_phase(PipelinePhase.RECON)
            self.state.objective_queue.clear()

            _HC_THRESHOLD = 0.8
            self.state.evidence_log = [
                e
                for e in self.state.evidence_log
                if e.get("confidence", 0) >= _HC_THRESHOLD
            ][-30:]
            self._last_evidence_count = len(self.state.evidence_log)
            logger.info(
                "Follow-up after TASK_COMPLETE: phase reset to RECON, "
                "objective_queue cleared, evidence_log compacted to %d entries.",
                len(self.state.evidence_log),
            )

        return cfg

    async def _create_or_switch_session(self) -> None:
        """Create a new session or switch to a different target, under caller-provided lock."""
        _session_changed = False
        if not self._session:
            self._session = SessionData(target=self.state.active_target)
            self._sync_token_usage_from_session()
            self.pipeline = PipelineEngine(self._session)
            _session_changed = True
        elif self._session.target != self.state.active_target:
            logger.info(
                "Target switched %s → %s: creating fresh SessionData",
                self._session.target,
                self.state.active_target,
            )
            self._session = SessionData(target=self.state.active_target)
            self._sync_token_usage_from_session()
            self.pipeline = PipelineEngine(self._session)
            _session_changed = True
        if _session_changed and self._ctf_mode and self.pipeline:
            self.pipeline.set_ctf_mode(True)
        if _session_changed:
            self._loaded_session_persistence_target = ""
            self._pending_payload_memory_records = []
            self._payload_memory_records = {}
            self._fuzzer_instance = None
            if self._session and self._session.target and hasattr(
                self, "_load_session_persistence"
            ):
                await self._load_session_persistence()

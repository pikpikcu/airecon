from __future__ import annotations

import hashlib
import json
import logging
import warnings
import asyncio
import re
from collections import deque
from pathlib import Path
from typing import Any

import aiohttp  # noqa: F401

from ..config import get_config, get_workspace_root
from ..docker import DockerEngine
from ..llm import LLMClient
from ..system import get_system_prompt
from .executors import _ExecutorMixin
from .formatters import _FormatterMixin
from .loop_context import _ContextMixin
from .loop_exploration import _ExplorationMixin
from .loop_inference import _InferenceMixin
from .loop_objectives import _ObjectivesMixin
from .loop_lifecycle import _LifecycleMixin
from .loop_policy import is_simple_target_kickoff
from .loop_process import _ProcessMessageMixin
from .loop_state import _StateMixin
from .loop_supervision import _SupervisionMixin
from .models import (
    AgentState,
    AntiLoopState,
    RecoveryState,
    ScopeTrackingState,
    SessionLifecycleState,
    UserInputState,
)
from .pipeline import PipelineEngine, PipelinePhase
from .session import SessionData, load_session, record_tested_endpoint  # noqa: F401
from .validators import _ValidatorMixin
from .workspace import _WorkspaceMixin

# ── Compatibility aliases: map old bare attr names to structured state ──
# All 200+ references across mixin files resolve through these properties.
_ANTI_LOOP_ATTRS = {
    "_no_tool_iterations",
    "_stagnation_iterations",
    "_consecutive_same_approach",
    "_recent_tool_names",
    "_last_evidence_count",
    "_watchdog_forced_calls",
    "_empty_response_retry_count",
    "_consecutive_failures",
    "_mentor_tool_call_count",
}
_RECOVERY_ATTRS = {
    "_recovery_force_tool_calls",
    "_adaptive_num_ctx",
    "_adaptive_num_predict_cap",
    "_vram_crash_count",
    "_token_snapshot_resave_requested",
    "_compression_summary",
    "_budget_pressure_level",
    "_loaded_skill_hashes",
    "_loaded_tech_skill_paths",
}
_LIFECYCLE_ATTRS = {
    "_last_session_save_iteration",
    "_last_conversation_save_iteration",
    "_last_memory_save_iteration",
    "_last_request_time",
    "_last_token_snapshot_time",
    "_last_context_validation",
    "_last_memory_health_check_iteration",
    "_last_user_input_time",
}
_SCOPE_ATTRS = {
    "_visited_browser_urls",
    "_max_browser_visits_per_domain",
    "_scope_lock_active",
    "_scope_lock_brief",
    "_scope_anchor_target",
}
_USER_INPUT_ATTRS = {
    "_user_input_event",
    "_user_input_value",
    "_user_input_cancelled",
    "_user_input_request_id",
    "_user_input_prompt",
    "_user_input_type",
}

_tools_meta_path = Path(__file__).parent.parent / "data" / "tools_meta.json"
try:
    with open(_tools_meta_path, "r") as f:
        _TOOLS_META = json.load(f)
except (OSError, json.JSONDecodeError) as _e:
    warnings.warn(
        f"tools_meta.json unavailable ({_e}); tool catalog features disabled."
    )
    _TOOLS_META = {}

logger = logging.getLogger("airecon.agent")

__all__ = ["AgentLoop", "get_config", "get_system_prompt"]

_MAX_EMPTY_RETRIES = get_config().agent_max_empty_retries


class AgentLoop(
    _ValidatorMixin,
    _FormatterMixin,
    _WorkspaceMixin,
    _ExecutorMixin,
    _InferenceMixin,
    _ExplorationMixin,
    _ObjectivesMixin,
    _SupervisionMixin,
    _ContextMixin,
    _StateMixin,
    _LifecycleMixin,
    _ProcessMessageMixin,
):
    _TOOL_CALL_RE = re.compile(
        r"<tool_call>\s*(\{.*?\})\s*</tool_call>",
        re.DOTALL | re.IGNORECASE,
    )

    _FAKE_CMD_BLOCK_RE = re.compile(
        r"```(?:bash|sh|shell|cmd|terminal|zsh)?\s*\n(.+?)```",
        re.DOTALL | re.IGNORECASE,
    )

    _FAKE_PLAIN_CMD_RE = re.compile(
        r"(?m)^[ \t]*"
        r"(?:"
        r"cd\s+/workspace/\S+\s*&&"
        r"|(?:curl|wget)\s+https?://\S+\s*(?:&&|\||;|\\)"
        r")",
    )

    _DEDUP_EXEMPT_TOOLS = frozenset(
        {
            "create_file",
            "create_vulnerability_report",
            "spawn_agent",
        }
    )

    _DEDUP_EXEMPT_BROWSER_ACTIONS = frozenset(
        {
            "click",
            "type",
            "press_key",
            "scroll_down",
            "scroll_up",
            "wait",
            "get_console_logs",
            "get_network_logs",
            "login_form",
            "handle_totp",
            "save_auth_state",
            "inject_cookies",
            "oauth_authorize",
        }
    )

    _CTF_MAX_ITERATIONS = get_config().agent_ctf_max_iterations

    def __init__(self, llm: LLMClient, engine: DockerEngine) -> None:
        super().__init__()
        self.llm = llm
        self.engine = engine
        self.state = AgentState()
        self._tools_llm: list[dict[str, Any]] | None = None
        self._last_output_file: str | None = None
        self._executed_tool_counts: dict[tuple[str, str], int] = {}

        self._executed_cmd_hashes: set[str] = set()
        self._executed_cmd_order: deque[str] = deque()
        self._cmd_execution_context: dict[str, dict[str, Any]] = {}
        self._initial_messages: list[dict[str, Any]] = []
        self._stop_requested: bool = False

        self._prev_phase: PipelinePhase | None = None
        self._dataset_hint_injected_phase: str = ""
        self._web_search_hint_injected: bool = False

        self._session: SessionData | None = None
        self._blocked_tools: set[str] = set()
        self._session_lock = asyncio.Lock()

        self._override_max_iterations: int | None = None
        self._ctf_mode: bool = False

        self._is_subagent: bool = False
        self.pipeline: PipelineEngine | None = None

        # Session persistence
        self._session_persistence = None

        # ── Structured runtime state (replaces 50+ bare instance variables) ──
        self._anti_loop = AntiLoopState()
        self._lifecycle = SessionLifecycleState()
        self._recovery = RecoveryState()
        self._scope = ScopeTrackingState()
        self._user_input = UserInputState()

        # Config-driven defaults
        self._scope.max_browser_visits_per_domain = (
            get_config().agent_max_browser_visits_per_domain
        )
        self._lifecycle.session_save_interval = 10
        self._lifecycle.conversation_save_interval = 10
        self._lifecycle.memory_save_interval = 5
        self._lifecycle.memory_health_interval = 10
        self._lifecycle.user_input_cooldown = 30.0

        # Non-grouped lifecycle (has unique usage patterns)
        self._token_snapshot_task: asyncio.Task[None] | None = None
        self._request_times: deque[float] = deque(maxlen=10)
        self._last_saved_cumulative: int = 0
        self._memory_manager = None
        self._memory_health_status: dict[str, Any] = {}
        self._pending_adaptive_state: dict[str, Any] | None = None
        self._pending_payload_memory_records: list[dict[str, Any]] = []
        self._payload_memory_records: dict[
            tuple[str, str, str, str], dict[str, Any]
        ] = {}
        self._loaded_session_persistence_target: str = ""
        self._fuzzer_instance: Any = None

        # Attack surface coverage tracker — prevents repetitive testing
        self._surface_tracker: Any = None
        try:
            from .attack_surface import AttackSurfaceTracker

            self._surface_tracker = AttackSurfaceTracker()
        except Exception as _e:
            logger.debug("AttackSurfaceTracker init failed: %s", _e)

    def _hydrate_adaptive_learning_state(
        self,
        adaptive_state: dict[str, Any],
    ) -> bool:
        if not adaptive_state or not hasattr(self, "_adaptive_learning_engine"):
            return False

        from .adaptive_learning import StrategyPattern, ToolPerformance

        engine = self._adaptive_learning_engine

        tp_data = adaptive_state.get("tool_performances", {})
        restored_tools = 0
        for name, pdata in tp_data.items():
            tool_name = str(name or "").strip()
            if not tool_name:
                continue

            perf = engine.tool_performances.get(tool_name)
            if perf is None:
                perf = ToolPerformance(tool_name=tool_name)
                engine.tool_performances[tool_name] = perf

            perf.total_uses = max(perf.total_uses, int(pdata.get("total_uses", 0)))
            perf.successes = max(perf.successes, int(pdata.get("successes", 0)))
            perf.failures = max(perf.failures, int(pdata.get("failures", 0)))
            perf.avg_duration = max(
                perf.avg_duration,
                float(pdata.get("avg_duration", 0.0)),
            )
            perf.avg_confidence = max(
                perf.avg_confidence,
                float(pdata.get("avg_confidence", 0.0)),
            )
            perf.last_used = max(perf.last_used, float(pdata.get("last_used", 0.0)))
            perf.success_streak = max(
                perf.success_streak,
                int(pdata.get("success_streak", 0)),
            )
            perf.failure_streak = max(
                perf.failure_streak,
                int(pdata.get("failure_streak", 0)),
            )

            context_scores = pdata.get("context_scores", {})
            if isinstance(context_scores, dict):
                for key, value in context_scores.items():
                    perf.context_scores[str(key)] = max(
                        float(perf.context_scores.get(str(key), 0.0)),
                        float(value),
                    )

            target_type_scores = pdata.get("target_type_scores", {})
            if isinstance(target_type_scores, dict):
                for key, value in target_type_scores.items():
                    perf.target_type_scores[str(key)] = max(
                        float(perf.target_type_scores.get(str(key), 0.0)),
                        float(value),
                    )

            restored_tools += 1

        existing_patterns = {p.pattern_id: p for p in engine.strategy_patterns}
        restored_patterns = 0
        for pdata in adaptive_state.get("strategy_patterns", []):
            pattern_id = str(pdata.get("pattern_id", "")).strip()
            if not pattern_id:
                continue

            existing = existing_patterns.get(pattern_id)
            tool_sequence = [
                str(tool)
                for tool in list(pdata.get("tool_sequence", []) or [])
                if str(tool).strip()
            ]
            if existing is None:
                existing = StrategyPattern(
                    pattern_id=pattern_id,
                    description=str(pdata.get("description", "")),
                    conditions=dict(pdata.get("conditions", {}) or {}),
                    tool_sequence=tool_sequence,
                    success_count=int(pdata.get("success_count", 0)),
                    failure_count=int(pdata.get("failure_count", 0)),
                    avg_result_confidence=float(
                        pdata.get("avg_result_confidence", 0.0)
                    ),
                    last_applied=float(pdata.get("last_applied", 0.0)),
                )
                engine.strategy_patterns.append(existing)
                existing_patterns[pattern_id] = existing
            else:
                existing.success_count = max(
                    existing.success_count,
                    int(pdata.get("success_count", 0)),
                )
                existing.failure_count = max(
                    existing.failure_count,
                    int(pdata.get("failure_count", 0)),
                )
                existing.avg_result_confidence = max(
                    existing.avg_result_confidence,
                    float(pdata.get("avg_result_confidence", 0.0)),
                )
                existing.last_applied = max(
                    existing.last_applied,
                    float(pdata.get("last_applied", 0.0)),
                )
                if not existing.tool_sequence and tool_sequence:
                    existing.tool_sequence = tool_sequence
                if not existing.conditions:
                    existing.conditions = dict(pdata.get("conditions", {}) or {})
                if not existing.description:
                    existing.description = str(pdata.get("description", ""))

            restored_patterns += 1

        if restored_tools or restored_patterns:
            logger.info(
                "Adaptive learning state restored: %d tools, %d patterns",
                restored_tools,
                restored_patterns,
            )
        return bool(restored_tools or restored_patterns)

    def _ensure_adaptive_learning_engine(self) -> Any:
        if not hasattr(self, "_adaptive_learning_engine"):
            from .adaptive_learning import AdaptiveLearningEngine

            cfg = get_config()
            session_id = getattr(self._session, "session_id", "") if self._session else ""
            try:
                min_observations = int(
                    getattr(cfg, "intelligence_adaptive_min_observations", 3)
                )
            except (TypeError, ValueError):
                min_observations = 3
            self._adaptive_learning_engine = AdaptiveLearningEngine(
                min_observations=min_observations,
                session_id=session_id or "",
            )

        if self._pending_adaptive_state:
            pending = self._pending_adaptive_state
            self._pending_adaptive_state = None
            self._hydrate_adaptive_learning_state(pending)

        return self._adaptive_learning_engine

    # ── Transparent compatibility layer: map old bare attrs to structured state ──
    # All 200+ references across mixin files (loop_cycle_llm.py, loop_exploration.py,
    # loop_tool_cycle.py, loop_cycle_prelude.py, etc.) resolve through these proxies
    # so that no edits to mixin files are needed.

    _ATTR_MAPS: dict[str, tuple[str, str]] = {
        # old_attr: (state_name, field_name)
        "_no_tool_iterations": ("_anti_loop", "no_tool_iterations"),
        "_stagnation_iterations": ("_anti_loop", "stagnation_iterations"),
        "_consecutive_same_approach": ("_anti_loop", "consecutive_same_approach"),
        "_recent_tool_names": ("_anti_loop", "recent_tool_names"),
        "_recent_tool_queue": ("_anti_loop", "recent_tool_queue"),
        "_last_evidence_count": ("_anti_loop", "last_evidence_count"),
        "_watchdog_forced_calls": ("_anti_loop", "watchdog_forced_calls"),
        "_empty_response_retry_count": ("_anti_loop", "empty_response_retry_count"),
        "_consecutive_failures": ("_anti_loop", "consecutive_failures"),
        "_mentor_tool_call_count": ("_anti_loop", "mentor_tool_call_count"),
        "_recovery_force_tool_calls": ("_recovery", "recovery_force_tool_calls"),
        "_adaptive_num_ctx": ("_recovery", "adaptive_num_ctx"),
        "_adaptive_num_predict_cap": ("_recovery", "adaptive_num_predict_cap"),
        "_vram_crash_count": ("_recovery", "vram_crash_count"),
        "_token_snapshot_resave_requested": (
            "_recovery",
            "token_snapshot_resave_requested",
        ),
        "_compression_summary": ("_recovery", "compression_summary"),
        "_budget_pressure_level": ("_recovery", "budget_pressure_level"),
        "_loaded_skill_hashes": ("_recovery", "loaded_skill_hashes"),
        "_loaded_tech_skill_paths": ("_recovery", "loaded_tech_skill_paths"),
        "_last_session_save_iteration": ("_lifecycle", "last_session_save_iteration"),
        "_session_save_interval": ("_lifecycle", "session_save_interval"),
        "_last_conversation_save_iteration": (
            "_lifecycle",
            "last_conversation_save_iteration",
        ),
        "_conversation_save_interval": ("_lifecycle", "conversation_save_interval"),
        "_last_memory_save_iteration": ("_lifecycle", "last_memory_save_iteration"),
        "_memory_save_interval": ("_lifecycle", "memory_save_interval"),
        "_last_request_time": ("_lifecycle", "last_request_time"),
        "_last_token_snapshot_time": ("_lifecycle", "last_token_snapshot_time"),
        "_last_context_validation": ("_lifecycle", "last_context_validation"),
        "_last_memory_health_check_iteration": (
            "_lifecycle",
            "last_memory_health_check_iteration",
        ),
        "_last_user_input_time": ("_lifecycle", "last_user_input_time"),
        "_user_input_cooldown": ("_lifecycle", "user_input_cooldown"),
        "_visited_browser_urls": ("_scope", "visited_browser_urls"),
        "_max_browser_visits_per_domain": ("_scope", "max_browser_visits_per_domain"),
        "_scope_lock_active": ("_scope", "scope_lock_active"),
        "_scope_lock_brief": ("_scope", "scope_lock_brief"),
        "_scope_anchor_target": ("_scope", "scope_anchor_target"),
        "_user_input_event": ("_user_input", "user_input_event"),
        "_user_input_value": ("_user_input", "user_input_value"),
        "_user_input_cancelled": ("_user_input", "user_input_cancelled"),
        "_user_input_request_id": ("_user_input", "user_input_request_id"),
        "_user_input_prompt": ("_user_input", "user_input_prompt"),
        "_user_input_type": ("_user_input", "user_input_type"),
    }

    def __getattr__(self, name: str) -> Any:
        if name in self._ATTR_MAPS:
            state_name, field_name = self._ATTR_MAPS[name]
            state_obj = object.__getattribute__(self, state_name)
            return getattr(state_obj, field_name)
        raise AttributeError(
            f"'{type(self).__name__}' object has no attribute '{name}'"
        )

    def __setattr__(self, name: str, value: Any) -> None:
        if name in self._ATTR_MAPS:
            state_name, field_name = self._ATTR_MAPS[name]
            # If state object doesn't exist yet (e.g. test mocks), fall back
            try:
                state_obj = object.__getattribute__(self, state_name)
                setattr(state_obj, field_name, value)
            except AttributeError:
                object.__setattr__(self, name, value)
        else:
            object.__setattr__(self, name, value)

    def _is_simple_target_kickoff(
        self,
        user_message: str,
        extracted_target: str | None,
    ) -> bool:
        return is_simple_target_kickoff(user_message, extracted_target)

    async def stop(self) -> None:
        logger.warning("Stopping Agent Loop...")
        self._stop_requested = True

        if self._session and self._session.target:
            try:
                logger.info(
                    "Saving session (subdomains: %d, hosts: %d, vulns: %d, msgs: %d)",
                    len(self._session.subdomains),
                    len(self._session.live_hosts),
                    len(self._session.vulnerabilities),
                    len(self._session.conversation)
                    if hasattr(self._session, "conversation")
                    else 0,
                )

                self._sync_token_usage_to_session()
                self._sync_recovery_state_to_session()
                self._sync_conversation_to_session()

                async with self._session_lock:
                    from .session import save_session

                    save_session(self._session)
                logger.info(
                    "Session saved to ~/.airecon/sessions/%s.json",
                    self._session.session_id,
                )

                # Cross-session persistence: save payload memory + adaptive state
                await self._save_session_persistence()

                try:
                    from ..memory import get_memory_manager

                    memory = get_memory_manager()

                    memory.save_session(
                        {
                            "session_id": self._session.session_id,
                            "target": self._session.target,
                            "current_phase": self._session.current_phase,
                            "subdomains": list(self._session.subdomains),
                            "live_hosts": list(self._session.live_hosts),
                            "vulnerabilities": self._session.vulnerabilities,
                            "token_total": self._session.token_total,
                            "model_used": self.llm.model
                            if hasattr(self, "llm")
                            else None,
                        }
                    )

                    memory.save_target_intel(
                        {
                            "target": self._session.target,
                            "subdomains": list(self._session.subdomains),
                            "ports": self._session.open_ports,
                            "technologies": self._session.technologies,
                        }
                    )

                    logger.debug("Session saved to memory database")
                except Exception as _mem_err:
                    logger.debug("Memory database save failed: %s", _mem_err)

            except Exception as e:
                logger.error("Failed to save session during stop: %s", e)

        if self._token_snapshot_task and not self._token_snapshot_task.done():
            self._token_snapshot_resave_requested = True
            try:
                await asyncio.wait_for(
                    asyncio.shield(self._token_snapshot_task),
                    timeout=2.0,
                )
            except asyncio.TimeoutError:
                logger.debug("Token snapshot flush timed out — cancelling task.")
                self._token_snapshot_task.cancel()
                try:
                    await self._token_snapshot_task
                except (asyncio.CancelledError, Exception):
                    pass
            except Exception as e:
                logger.warning("Operation failed: %s", e)
                logger.debug("Token snapshot flush skipped during stop.")

    def _merge_payload_memory_records(self, records: list[dict[str, Any]]) -> int:
        merged = 0
        for raw in records:
            if not isinstance(raw, dict):
                continue

            payload = str(raw.get("payload", "") or "").strip()
            vuln_type = str(raw.get("vuln_type", "") or "").strip()
            target = str(raw.get("target", "") or "").strip()
            param = str(raw.get("param", "") or "").strip()
            if not (payload and vuln_type and target and param):
                continue

            key = (payload, vuln_type, target, param)
            existing = self._payload_memory_records.get(key)
            if existing is None:
                merged_record = dict(raw)
            else:
                merged_record = dict(existing)
                merged_record["attempts"] = max(
                    int(existing.get("attempts", 1) or 1),
                    int(raw.get("attempts", 1) or 1),
                )
                merged_record["confidence"] = max(
                    float(existing.get("confidence", 0.0) or 0.0),
                    float(raw.get("confidence", 0.0) or 0.0),
                )
                merged_record["success"] = bool(
                    existing.get("success", False) or raw.get("success", False)
                )
                merged_record["status_code"] = int(
                    raw.get("status_code", existing.get("status_code", 0)) or 0
                )
                merged_record["timestamp"] = max(
                    float(existing.get("timestamp", 0.0) or 0.0),
                    float(raw.get("timestamp", 0.0) or 0.0),
                )
                merged_record["waf_detected"] = str(
                    raw.get("waf_detected", existing.get("waf_detected", "")) or ""
                )
                merged_record["tech_stack"] = list(
                    dict.fromkeys(
                        [
                            *(
                                existing.get("tech_stack", [])
                                if isinstance(existing.get("tech_stack", []), list)
                                else []
                            ),
                            *(
                                raw.get("tech_stack", [])
                                if isinstance(raw.get("tech_stack", []), list)
                                else []
                            ),
                        ]
                    )
                )
            self._payload_memory_records[key] = merged_record
            merged += 1

        if self._payload_memory_records:
            self._pending_payload_memory_records = list(
                self._payload_memory_records.values()
            )
        return merged

    def _restore_payload_memory_into(self, fuzzer_like: Any) -> int:
        payload_memory = getattr(fuzzer_like, "payload_memory", None)
        if payload_memory is None or not self._pending_payload_memory_records:
            return 0
        try:
            loaded = payload_memory.load_records(self._pending_payload_memory_records)
        except Exception as exc:
            logger.debug("Payload memory restore failed: %s", exc)
            return 0
        if loaded:
            logger.info("Payload memory restored into fuzzer: %d records", loaded)
        return loaded

    def _capture_payload_memory_from(self, fuzzer_like: Any) -> int:
        payload_memory = getattr(fuzzer_like, "payload_memory", None)
        if payload_memory is None:
            return 0
        try:
            records = payload_memory.dump_records()
        except Exception as exc:
            logger.debug("Payload memory export failed: %s", exc)
            return 0
        merged = self._merge_payload_memory_records(records)
        if merged:
            logger.debug("Captured %d payload memory records from fuzzer", merged)
        return merged

    async def _save_session_persistence(self) -> None:
        """Save payload memory and adaptive learning state to workspace."""
        try:
            cfg = get_config()
            if not cfg.session_persistence_enabled:
                return
            if not self._session or not self._session.target:
                return

            from .session_persistence import SessionPersistenceEngine

            ws_root = get_workspace_root()
            persist = SessionPersistenceEngine(ws_root)
            self._session_persistence = persist

            # Save payload memory from fuzzer
            payload_records = list(self._pending_payload_memory_records)
            if (
                hasattr(self, "_fuzzer_instance")
                and self._fuzzer_instance
                and str(getattr(self._fuzzer_instance, "target", "") or "").strip()
                == str(self._session.target or "").strip()
            ):
                self._capture_payload_memory_from(self._fuzzer_instance)
                payload_records = list(self._pending_payload_memory_records)
            if payload_records:
                persist.save_payload_memory(self._session.target, payload_records)

            # Save adaptive learning state
            if hasattr(self, "_adaptive_learning_engine"):
                ale = self._adaptive_learning_engine
                adaptive_state = {
                    "tool_performances": {
                        name: {
                            "total_uses": p.total_uses,
                            "successes": p.successes,
                            "failures": p.failures,
                            "avg_duration": p.avg_duration,
                            "avg_confidence": p.avg_confidence,
                            "last_used": p.last_used,
                            "success_streak": p.success_streak,
                            "failure_streak": p.failure_streak,
                            "context_scores": dict(p.context_scores),
                            "target_type_scores": dict(p.target_type_scores),
                        }
                        for name, p in ale.tool_performances.items()
                    },
                    "strategy_patterns": [
                        {
                            "pattern_id": p.pattern_id,
                            "description": p.description,
                            "conditions": p.conditions,
                            "tool_sequence": p.tool_sequence,
                            "success_count": p.success_count,
                            "failure_count": p.failure_count,
                            "avg_result_confidence": p.avg_result_confidence,
                            "last_applied": p.last_applied,
                        }
                        for p in ale.strategy_patterns
                    ],
                }
                persist.save_adaptive_state(self._session.target, adaptive_state)

            self._last_session_save_iteration = self.state.iteration
        except Exception as e:
            logger.warning("Operation failed: %s", e)

    async def _load_session_persistence(self) -> None:
        """Load payload memory and adaptive learning state from workspace."""
        try:
            cfg = get_config()
            if not cfg.session_persistence_enabled:
                return
            if not self._session or not self._session.target:
                return
            target = str(self._session.target or "").strip()
            if not target:
                return
            if self._loaded_session_persistence_target == target:
                return

            from .session_persistence import SessionPersistenceEngine

            ws_root = get_workspace_root()
            persist = SessionPersistenceEngine(ws_root)
            self._session_persistence = persist

            # Load payload memory into fuzzer
            records = persist.load_payload_memory(target)
            if records:
                self._merge_payload_memory_records(records)
                # Will be loaded when fuzzer is created
                logger.info(
                    "Payload memory available: %d records for %s",
                    len(records),
                    target,
                )

            # Load adaptive learning state
            adaptive_state = persist.load_adaptive_state(target)
            if adaptive_state:
                self._pending_adaptive_state = adaptive_state
                self._ensure_adaptive_learning_engine()
                logger.info(
                    "Adaptive learning state loaded for %s", target
                )
            self._loaded_session_persistence_target = target
        except Exception as e:
            logger.warning("Operation failed: %s", e)

    def _is_duplicate_browser_url(self, url: str, action: str) -> bool:
        if action not in ("goto", "new_tab"):
            return False

        if not url:
            return False

        try:
            normalized = url.strip().lower()
            normalized = re.sub(r"^https?://", "", normalized)
            normalized = re.sub(r"/+$", "", normalized)
        except Exception as e:
            logger.warning("Operation failed: %s", e)
            return False

        count = sum(
            1 for visited in self._visited_browser_urls if visited == normalized
        )
        if count >= self._max_browser_visits_per_domain:
            return True

        return False

    def _is_duplicate_command(
        self, tool_name: str, args: dict[str, Any]
    ) -> tuple[bool, str]:
        if tool_name in self._DEDUP_EXEMPT_TOOLS:
            return False, ""

        if tool_name == "browser_action":
            action = args.get("action", "")
            if action in self._DEDUP_EXEMPT_BROWSER_ACTIONS:
                return False, ""

            if action in ("goto", "new_tab"):
                url = args.get("url", "")
                if self._is_duplicate_browser_url(url, action):
                    msg = (
                        f"[BROWSER URL LIMIT] URL '{url[:50]}...' visited too many "
                        f"times ({self._max_browser_visits_per_domain}). "
                        "Try other methods."
                    )
                    return True, msg

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

        try:
            _phase_ctx = self._get_current_phase().value
        except Exception as e:
            logger.debug("Failed to get phase context: %s", e)
            _phase_ctx = "unknown"
        raw = f"{_phase_ctx}:{tool_name}:{canonical}"
        cmd_hash = hashlib.md5(
            raw.encode("utf-8", errors="replace"), usedforsecurity=False
        ).hexdigest()

        if cmd_hash in self._executed_cmd_hashes:
            ctx = self._cmd_execution_context.get(cmd_hash, {})
            prev_evidence_count = ctx.get("evidence_count", 0)
            current_evidence_count = len(self.state.evidence_log)
            evidence_grown = current_evidence_count > prev_evidence_count
            repeat_count = ctx.get("repeat_count", 0)
            max_repeats = ctx.get("max_repeats", 2)

            if evidence_grown and repeat_count < max_repeats:
                logger.info(
                    "[CONTEXT-AWARE RERUN] '%s' can re-run: evidence growth "
                    "(prev=%d, now=%d), repeat=%d/%d",
                    tool_name,
                    prev_evidence_count,
                    current_evidence_count,
                    repeat_count,
                    max_repeats,
                )
                msg = (
                    f"[EVIDENCE-DRIVEN RERUN] '{tool_name}' can re-run: "
                    f"evidence {prev_evidence_count}→{current_evidence_count}. "
                    f"Validation {repeat_count + 1}/{max_repeats}."
                )
                self._cmd_execution_context[cmd_hash]["repeat_count"] = repeat_count + 1
                self._cmd_execution_context[cmd_hash]["evidence_count"] = (
                    current_evidence_count
                )
                return False, msg
            else:
                if not evidence_grown:
                    msg = (
                        f"[NO NEW EVIDENCE] '{tool_name}' already executed "
                        "with no new evidence. Use existing results."
                    )
                else:
                    msg = (
                        f"[MAX REVALIDATION] '{tool_name}' reached max re-attempts "
                        f"({max_repeats}x). Explore alternative approaches."
                    )
                return True, msg

        if tool_name == "browser_action":
            action = args.get("action", "")
            if action in ("goto", "new_tab"):
                url = args.get("url", "")
                if url:
                    try:
                        normalized = url.strip().lower()
                        normalized = re.sub(r"^https?://", "", normalized)
                        normalized = re.sub(r"/+$", "", normalized)
                        if len(self._visited_browser_urls) > 500:
                            self._visited_browser_urls = set(
                                list(self._visited_browser_urls)[-200:]
                            )
                        self._visited_browser_urls.add(normalized)
                    except Exception as e:
                        logger.debug(
                            "Expected failure normalizing browser URL for dedup: %s", e
                        )

        self._executed_cmd_hashes.add(cmd_hash)
        self._executed_cmd_order.append(cmd_hash)
        self._cmd_execution_context[cmd_hash] = {
            "tool_name": tool_name,
            "args": canonical,
            "phase": _phase_ctx,
            "evidence_count": len(self.state.evidence_log),
            "repeat_count": 0,
            "max_repeats": 2,
        }

        if len(self._executed_cmd_hashes) > get_config().agent_command_hash_cache_limit:
            before = len(self._executed_cmd_hashes)
            while (
                len(self._executed_cmd_order)
                > get_config().agent_command_hash_cache_prune_target
            ):
                oldest = self._executed_cmd_order.popleft()
                self._executed_cmd_hashes.discard(oldest)
                self._cmd_execution_context.pop(oldest, None)
            while len(self._executed_cmd_order) > len(self._executed_cmd_hashes):
                oldest = self._executed_cmd_order.popleft()
                self._cmd_execution_context.pop(oldest, None)
            after = len(self._executed_cmd_hashes)
            if after != before:
                logger.debug(
                    "_executed_cmd_hashes pruned: %d → %d (kept 2500)",
                    before,
                    after,
                )

        return False, ""

    _URL_RE = re.compile(r"https?://[^\s\"']+", re.IGNORECASE)

    def _record_tested_endpoint(
        self, tool_name: str, arguments: dict[str, Any]
    ) -> None:
        if not self._session:
            return
        url: str = ""
        method: str = "GET"

        if tool_name == "execute":
            cmd = arguments.get("command", "")

            m = self._URL_RE.search(cmd)
            if m:
                url = m.group(0).rstrip("'\"\\;,")

            _method_m = re.search(r"(?:-X|--request)\s+([A-Z]+)", cmd, re.IGNORECASE)
            if _method_m:
                method = _method_m.group(1).upper()

            elif re.search(r"\s(?:-d|--data|--data-raw)\s", cmd):
                method = "POST"

        elif tool_name == "browser_action":
            action = arguments.get("action", "")
            if action in ("goto", "new_tab"):
                url = arguments.get("url", "")

        elif tool_name in (
            "quick_fuzz",
            "advanced_fuzz",
            "deep_fuzz",
            "schemathesis_fuzz",
        ):
            url = arguments.get("url", arguments.get("target", ""))

        if url:
            record_tested_endpoint(self._session, url, method)

    def get_stats(self) -> dict[str, Any]:
        from .owasp import evidence_risk_summary

        _caido_sends = self.state.tool_counts.get("caido_send_request", 0)
        _caido_autos = self.state.tool_counts.get("caido_automate", 0)
        _caido_findings = _caido_sends + _caido_autos
        _caido_available = bool(getattr(self, "_caido_available", False))
        current_phase = None
        try:
            if self._session:
                current_phase = self._session.current_phase
        except Exception as e:
            logger.debug("Expected failure in get_stats current_phase: %s", e)
            current_phase = None
        return {
            "message_count": len(self.state.conversation),
            "tool_counts": dict(self.state.tool_counts),
            "token_usage": dict(self.state.token_usage),
            "skills_used": list(self.state.skills_used),
            "phase": current_phase,
            "caido": {
                "active": _caido_available or _caido_findings > 0,
                "findings_count": _caido_findings,
            },
            "risk": evidence_risk_summary(self.state.evidence_log),
            "dynamic_classification": True,
        }

    def _extract_tool_calls_from_text(
        self, text: str, registered_tools: set[str]
    ) -> list[dict[str, Any]]:
        tool_calls: list[dict[str, Any]] = []

        for raw_json in self._TOOL_CALL_RE.findall(text):
            tc = self._parse_tool_call_json(raw_json, registered_tools)
            if tc:
                tool_calls.append(tc)

        if tool_calls:
            return tool_calls

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
                    candidate = text[start_idx : i + 1]

                    if '"name"' in candidate or "'name'" in candidate:
                        tc = self._parse_tool_call_json(candidate, registered_tools)
                        if tc:
                            tool_calls.append(tc)
                    start_idx = None

        return tool_calls

    def _parse_tool_call_json(
        self, raw: str, registered_tools: set[str]
    ) -> dict[str, Any] | None:
        parsed = self._try_parse_json(raw)
        if parsed is None:
            return None

        tc_name = parsed.get("name") or parsed.get("function", {}).get("name", "")
        tc_args = (
            parsed.get("arguments")
            or parsed.get("parameters")
            or parsed.get("function", {}).get("arguments", {})
            or {}
        )

        if tc_name and tc_name in registered_tools:
            logger.info("[fallback] Extracted tool_call: %s", tc_name)
            return {"function": {"name": tc_name, "arguments": tc_args}}
        return None

    @staticmethod
    def _try_parse_json(raw: str) -> dict | None:
        try:
            result = json.loads(raw)
            if isinstance(result, dict):
                return result
        except json.JSONDecodeError:
            pass

        cleaned = re.sub(r"//[^\n]*", "", raw)
        cleaned = re.sub(r"/\*[^*]*(?:\*(?!/)[^*]*)*\*/", "", cleaned)
        try:
            result = json.loads(cleaned)
            if isinstance(result, dict):
                return result
        except json.JSONDecodeError:
            pass

        cleaned = re.sub(r",\s*([}\]])", r"\1", cleaned)
        try:
            result = json.loads(cleaned)
            if isinstance(result, dict):
                return result
        except json.JSONDecodeError:
            pass

        for _extra in range(1, 6):
            try:
                result = json.loads(cleaned + "}" * _extra)
                if isinstance(result, dict):
                    return result
            except json.JSONDecodeError:
                pass

        cleaned = cleaned.replace("'", '"')
        try:
            result = json.loads(cleaned)
            if isinstance(result, dict):
                return result
        except json.JSONDecodeError:
            pass

        return None

    def get_progress(self) -> dict[str, Any]:
        session = self._session
        quality_scores = self._compute_quality_scores()

        # Timeline fields: current phase, last tool/command, and a stuck flag so
        # the UI can show what the agent is doing and whether it's retrying.
        try:
            _phase = self._get_current_phase().value
        except Exception as _e:
            logger.debug("get_progress: phase lookup failed: %s", _e)
            _phase = ""
        _last_tool = ""
        _last_command = ""
        _last_status = ""
        if self.state.tool_history:
            _last = self.state.tool_history[-1]
            _last_tool = getattr(_last, "tool_name", "") or ""
            _last_status = getattr(_last, "status", "") or ""
            _args = getattr(_last, "arguments", {}) or {}
            _last_command = str(
                _args.get("command")
                or _args.get("url")
                or _args.get("endpoint")
                or ""
            )[:200]
        try:
            _stuck_threshold = int(
                getattr(get_config(), "agent_stagnation_threshold", 3)
            )
        except (TypeError, ValueError):
            _stuck_threshold = 3

        progress = {
            "target": self.state.active_target or "none",
            "phase": _phase,
            "iteration": self.state.iteration,
            "max_iterations": self.state.max_iterations,
            "tool_counts": self.state.tool_counts,
            "last_tool": _last_tool,
            "last_command": _last_command,
            "last_tool_status": _last_status,
            "stuck": bool(self._consecutive_failures >= _stuck_threshold),
            "consecutive_failures": self._consecutive_failures,
            "objectives": {
                "total": len(self.state.objective_queue),
                "completed": sum(
                    1
                    for o in self.state.objective_queue
                    if str(o.get("status", "")).lower() == "done"
                ),
            },
            "evidence_count": len(self.state.evidence_log),
            "quality_scores": quality_scores,
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

    def _trim_conversation_to_limit(self) -> None:
        cfg = get_config()
        max_conversation_length = getattr(cfg, "agent_max_conversation_messages", 1000)
        if (
            not max_conversation_length
            or len(self.state.conversation) <= max_conversation_length
        ):
            return

        before_count = len(self.state.conversation)
        important_messages = []
        regular_messages = []
        for msg in self.state.conversation:
            content = msg.get("content", "")
            if msg.get("role") == "system" and (
                "[SYSTEM:" in content
                or "Phase transition" in content
                or "objective" in content.lower()
            ):
                important_messages.append(msg)
            else:
                regular_messages.append(msg)

        max_regular = max(0, max_conversation_length - len(important_messages))
        recent_regular = regular_messages[-max_regular:] if max_regular > 0 else []
        self.state.conversation = important_messages + recent_regular
        logger.info(
            "Proactively trimmed conversation from %d to %d messages",
            before_count,
            len(self.state.conversation),
        )

    def _validate_context_relevance(self):
        if not self.state.conversation:
            return

        current_target = self.state.active_target
        if current_target:
            before_count = len(self.state.conversation)
            filtered_conversation = []
            for msg in self.state.conversation:
                content = msg.get("content", "")
                if (
                    "[SYSTEM: ACTIVE_TARGET=" in content
                    and current_target not in content
                ):
                    continue
                if "previous scan o" in content and current_target not in content:
                    continue
                filtered_conversation.append(msg)

            self.state.conversation = filtered_conversation
            removed_count = before_count - len(filtered_conversation)
            if removed_count > 0:
                logger.info("Removed %d outdated context messages", removed_count)

        self._trim_conversation_to_limit()

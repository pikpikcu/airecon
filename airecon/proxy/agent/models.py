from __future__ import annotations

import asyncio
from pathlib import Path
import heapq
import logging
import re
from collections import deque
from typing import Any
import os
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from time import monotonic
from urllib.parse import urlparse

from ..config import get_config
from ..data_loader import int_to_severity, load_vuln_hypothesis_legacy, severity_to_int
from .constants import SEVERITY_MULTIPLIER as _SEVERITY_MULTIPLIER

logger = logging.getLogger("airecon.agent")

MAX_EVIDENCE_DEDUP_SCAN = 120
MAX_HYPOTHESES = 32
MAX_CAUSAL_INTERVENTIONS = 300
MAX_CAUSAL_HYPOTHESES = 256
MAX_CAUSAL_EDGES = 512
FLAG_PATTERN = re.compile(r"flag\{[^}]+\}", re.IGNORECASE)

_THINK_BLOCK_RE = re.compile(r"<think>.*?</think>", re.DOTALL | re.IGNORECASE)
_THINK_OPEN_RE = re.compile(r"<think>(?!</think>).*$", re.DOTALL | re.IGNORECASE)
_MIN_SEVERITY_FOR_PRESERVATION = 4
# FLEXIBILITY: Lower confidence floor to 0.30 to capture emerging/novel patterns
# Novel discoveries often start with low confidence before validation
_CONF_FLOOR = 0.30


def _get_model_limits() -> dict[str, Any]:
    try:
        config = get_config()
        return {
            "max_tool_iterations": int(config.model_max_tool_iterations),
            "max_tool_history": int(config.model_max_tool_history),
            "max_objectives": int(config.model_max_objectives),
            "max_evidence": int(config.model_max_evidence),
            "max_causal_observations": int(config.model_max_causal_observations),
            "max_tool_result_chars": int(config.model_max_tool_result_chars),
            "min_confidence_for_preservation": float(
                config.model_min_confidence_for_preservation
            ),
        }
    except Exception as e:
        logger.warning("Operation failed: %s", e)
        return {
            "max_tool_iterations": 50,
            "max_tool_history": 100,
            "max_objectives": 64,
            "max_evidence": 200,
            "max_causal_observations": 2000,
            "max_tool_result_chars": 50000,
            "min_confidence_for_preservation": 0.75,
        }


MAX_TOOL_ITERATIONS = 50
MAX_TOOL_HISTORY = 100
MAX_OBJECTIVES = 64
MAX_EVIDENCE = 200
MAX_CAUSAL_OBSERVATIONS = 2000
MAX_TOOL_RESULT_CHARS = 50000
MIN_CONFIDENCE_FOR_PRESERVATION = 0.75


def _get_evidence_similarity_threshold() -> float:
    try:
        config = get_config()
        return float(config.evidence_similarity_threshold)
    except Exception as e:
        logger.debug(
            "Expected failure reading evidence similarity threshold from config: %s", e
        )
        return 0.70


def _get_evidence_dedup_scan_limit() -> int:
    raw = str(os.environ.get("AIRECON_EVIDENCE_DEDUP_SCAN", "")).strip()
    if raw:
        try:
            return max(20, min(int(raw), 1000))
        except ValueError:
            pass
    return MAX_EVIDENCE_DEDUP_SCAN


def _truncate_tool_result(result: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(result, dict):
        return result

    max_chars = _get_model_limits()["max_tool_result_chars"]
    for k, v in result.items():
        if isinstance(v, str) and len(v) > max_chars:
            result[k] = v[:max_chars] + " ... [TRUNCATED]"
    return result


def _get_context_limits():
    try:
        config = get_config()
        dynamic_default = max(100, min(10000, int(config.llm_context_window) // 128))
        configured_max = int(config.agent_max_conversation_messages or 0)
        max_conversation_messages = (
            configured_max if configured_max > 0 else dynamic_default
        )
        trigger_ratio = max(
            0.5, min(0.95, float(config.agent_compression_trigger_ratio))
        )
        return {
            "max_conversation_messages": max_conversation_messages,
            "compression_trigger": int(max_conversation_messages * trigger_ratio),
            "uncompressed_keep_count": config.agent_uncompressed_keep_count,
            "llm_compression_num_ctx": config.agent_llm_compression_num_ctx,
            "llm_compression_num_predict": config.agent_llm_compression_num_predict,
        }
    except Exception as e:
        logger.warning("Operation failed: %s", e)
        return {
            "max_conversation_messages": 1024,
            "compression_trigger": 819,
            "uncompressed_keep_count": 20,
            "llm_compression_num_ctx": 8192,
            "llm_compression_num_predict": 1024,
        }


def jaccard_similarity(a: str, b: str) -> float:
    tokens_a = set(a.lower().split())
    tokens_b = set(b.lower().split())
    if not tokens_a or not tokens_b:
        return 0.0
    return len(tokens_a & tokens_b) / len(tokens_a | tokens_b)


def _calculate_objective_confidence(
    summary: str,
    artifact: str | None,
    source_tool: str,
    severity: int = 3,
) -> float:
    score = 0.5

    if artifact:
        score += 0.2

    if re.search(r"\b(CRITICAL|HIGH|MEDIUM|LOW)\b", summary, re.IGNORECASE):
        score += 0.1

    if re.search(r"\b(http|https|status|response|→)\b", summary.lower()):
        score += 0.15

    if len(summary) > 100:
        score += 0.05

    if severity >= 4 and len(summary) > 80:
        score += 0.05

    return min(score, 1.0)


@dataclass
class ToolExecution:
    tool_name: str
    arguments: dict[str, Any]
    result: dict[str, Any] | None = None
    duration: float = 0.0
    status: str = "pending"


@dataclass
class AgentEvent:
    type: str
    data: dict[str, Any] = field(default_factory=dict)


@dataclass
class CausalObservation:
    observation_type: str
    entity: str
    attribute: str = ""
    value: str = ""
    source_tool: str = ""
    evidence: str = ""
    confidence: float = 0.5
    phase: str = ""
    timestamp: str = ""

    def fingerprint(self) -> str:
        return "|".join(
            [
                self.observation_type.strip().lower(),
                self.entity.strip().lower(),
                self.attribute.strip().lower(),
                self.value.strip().lower(),
            ]
        )

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "CausalObservation":
        return cls(
            observation_type=str(raw.get("observation_type", "")).strip(),
            entity=str(raw.get("entity", "")).strip(),
            attribute=str(raw.get("attribute", "")).strip(),
            value=str(raw.get("value", "")).strip(),
            source_tool=str(raw.get("source_tool", "")).strip(),
            evidence=str(raw.get("evidence", "")).strip()[:600],
            confidence=max(0.0, min(float(raw.get("confidence", 0.5) or 0.5), 1.0)),
            phase=str(raw.get("phase", "")).strip().upper(),
            timestamp=str(raw.get("timestamp", "")).strip(),
        )


@dataclass
class CausalHypothesis:
    hypothesis_id: str
    statement: str
    prior: float = 0.5
    posterior: float = 0.5
    status: str = "pending"
    evidence_refs: list[str] = field(default_factory=list)
    updated_at: str = ""

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "CausalHypothesis":
        return cls(
            hypothesis_id=str(raw.get("hypothesis_id", "")).strip(),
            statement=str(raw.get("statement", "")).strip(),
            prior=max(0.0, min(float(raw.get("prior", 0.5) or 0.5), 1.0)),
            posterior=max(0.0, min(float(raw.get("posterior", 0.5) or 0.5), 1.0)),
            status=str(raw.get("status", "pending")).strip().lower(),
            evidence_refs=[
                str(x).strip()
                for x in (raw.get("evidence_refs", []) or [])
                if str(x).strip()
            ][:30],
            updated_at=str(raw.get("updated_at", "")).strip(),
        )


@dataclass
class CausalEdge:
    cause: str
    effect: str
    relation: str = "supports"
    confidence: float = 0.5

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "CausalEdge":
        return cls(
            cause=str(raw.get("cause", "")).strip(),
            effect=str(raw.get("effect", "")).strip(),
            relation=str(raw.get("relation", "supports")).strip().lower(),
            confidence=max(0.0, min(float(raw.get("confidence", 0.5) or 0.5), 1.0)),
        )


@dataclass
class CausalIntervention:
    intervention_id: str
    action: str
    target: str = ""
    expected_effect: str = ""
    observed_effect: str = ""
    success: bool | None = None
    confidence: float = 0.5
    timestamp: str = ""

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "CausalIntervention":
        return cls(
            intervention_id=str(raw.get("intervention_id", "")).strip(),
            action=str(raw.get("action", "")).strip(),
            target=str(raw.get("target", "")).strip(),
            expected_effect=str(raw.get("expected_effect", "")).strip(),
            observed_effect=str(raw.get("observed_effect", "")).strip(),
            success=raw.get("success"),
            confidence=max(0.0, min(float(raw.get("confidence", 0.5) or 0.5), 1.0)),
            timestamp=str(raw.get("timestamp", "")).strip(),
        )


@dataclass
class CausalState:
    observations: list[CausalObservation] = field(default_factory=list)
    hypotheses: list[CausalHypothesis] = field(default_factory=list)
    edges: list[CausalEdge] = field(default_factory=list)
    interventions: list[CausalIntervention] = field(default_factory=list)
    posterior: dict[str, float] = field(default_factory=dict)

    def record_observation(
        self, observation: CausalObservation | dict[str, Any]
    ) -> bool:
        obs = (
            observation
            if isinstance(observation, CausalObservation)
            else CausalObservation.from_dict(observation)
        )
        if not obs.observation_type or not obs.entity:
            return False
        fp = obs.fingerprint()
        for existing in self.observations:
            if existing.fingerprint() == fp:
                return False
        if not obs.timestamp:
            obs.timestamp = datetime.now(timezone.utc).isoformat()
        self.observations.append(obs)
        limits = _get_model_limits()
        max_obs = limits["max_causal_observations"]
        if len(self.observations) > max_obs:
            self.observations = self.observations[-max_obs:]
        return True

    def add_intervention(
        self, intervention: CausalIntervention | dict[str, Any]
    ) -> None:
        iv = (
            intervention
            if isinstance(intervention, CausalIntervention)
            else CausalIntervention.from_dict(intervention)
        )
        if not iv.intervention_id:
            iv.intervention_id = f"iv_{len(self.interventions) + 1}"
        if not iv.timestamp:
            iv.timestamp = datetime.now(timezone.utc).isoformat()
        self.interventions.append(iv)
        if len(self.interventions) > MAX_CAUSAL_INTERVENTIONS:
            self.interventions = self.interventions[-MAX_CAUSAL_INTERVENTIONS:]

    def add_edge(self, edge: CausalEdge | dict[str, Any]) -> bool:
        ce = edge if isinstance(edge, CausalEdge) else CausalEdge.from_dict(edge)
        if not ce.cause or not ce.effect:
            return False
        for existing in self.edges:
            if (
                existing.cause == ce.cause
                and existing.effect == ce.effect
                and existing.relation == ce.relation
            ):
                if ce.confidence > existing.confidence:
                    existing.confidence = ce.confidence
                return False
        self.edges.append(ce)
        if len(self.edges) > MAX_CAUSAL_EDGES:
            self.edges = self.edges[-MAX_CAUSAL_EDGES:]
        return True

    def upsert_hypothesis(self, hypothesis: CausalHypothesis | dict[str, Any]) -> None:
        h = (
            hypothesis
            if isinstance(hypothesis, CausalHypothesis)
            else CausalHypothesis.from_dict(hypothesis)
        )
        if not h.hypothesis_id:
            h.hypothesis_id = f"hyp_{len(self.hypotheses) + 1}"
        h.updated_at = datetime.now(timezone.utc).isoformat()
        for idx, existing in enumerate(self.hypotheses):
            if existing.hypothesis_id == h.hypothesis_id:
                self.hypotheses[idx] = h
                break
        else:
            self.hypotheses.append(h)
            if len(self.hypotheses) > MAX_CAUSAL_HYPOTHESES:
                self.hypotheses = self.hypotheses[-MAX_CAUSAL_HYPOTHESES:]
        self.posterior[h.hypothesis_id] = h.posterior

    def to_dict(self) -> dict[str, Any]:
        return {
            "observations": [o.__dict__ for o in self.observations],
            "hypotheses": [h.__dict__ for h in self.hypotheses],
            "edges": [e.__dict__ for e in self.edges],
            "interventions": [i.__dict__ for i in self.interventions],
            "posterior": {
                str(k): max(0.0, min(float(v), 1.0)) for k, v in self.posterior.items()
            },
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "CausalState":
        if not isinstance(raw, dict):
            return cls()
        state = cls(
            observations=[
                CausalObservation.from_dict(x)
                for x in (raw.get("observations", []) or [])
                if isinstance(x, dict)
            ],
            hypotheses=[
                CausalHypothesis.from_dict(x)
                for x in (raw.get("hypotheses", []) or [])
                if isinstance(x, dict)
            ],
            edges=[
                CausalEdge.from_dict(x)
                for x in (raw.get("edges", []) or [])
                if isinstance(x, dict)
            ],
            interventions=[
                CausalIntervention.from_dict(x)
                for x in (raw.get("interventions", []) or [])
                if isinstance(x, dict)
            ],
            posterior={},
        )
        raw_post = raw.get("posterior", {})
        if isinstance(raw_post, dict):
            state.posterior = {
                str(k): max(0.0, min(float(v), 1.0))
                for k, v in raw_post.items()
                if str(k).strip()
            }
        return state


# ── Runtime state grouping (replaces 50+ bare instance vars in loop.py) ──


@dataclass
class AntiLoopState:
    """Tracks tool/command diversity to prevent LLM from getting stuck in loops."""

    no_tool_iterations: int = 0
    stagnation_iterations: int = 0
    consecutive_same_approach: int = 0
    recent_tool_names: list[str] = field(default_factory=lambda: [])
    last_evidence_count: int = 0
    watchdog_forced_calls: int = 0
    empty_response_retry_count: int = 0
    consecutive_failures: int = 0
    mentor_tool_call_count: int = 0
    recent_tool_queue: deque[str] = field(default_factory=lambda: deque(maxlen=8))

    def record_tool_use(self, tool_name: str) -> None:
        self.recent_tool_queue.append(tool_name)
        self.recent_tool_names = list(self.recent_tool_queue)
        if len(self.recent_tool_names) > 8:
            self.recent_tool_names = self.recent_tool_names[-8:]

    def get_same_tool_streak(self) -> int:
        if len(self.recent_tool_names) < 2:
            return 0
        last = self.recent_tool_names[-1]
        streak = 1
        for name in reversed(self.recent_tool_names[:-1]):
            if name == last:
                streak += 1
            else:
                break
        return streak

    def reset_stagnation(self) -> None:
        self.stagnation_iterations = 0
        self.consecutive_same_approach = 0

    def has_stagnated(self, threshold: int = 3) -> bool:
        return self.stagnation_iterations >= threshold


@dataclass
class SessionLifecycleState:
    """Session timing, token tracking, and save intervals."""

    last_session_save_iteration: int = 0
    session_save_interval: int = 10
    last_conversation_save_iteration: int = 0
    conversation_save_interval: int = 10
    last_memory_save_iteration: int = 0
    memory_save_interval: int = 5
    last_memory_health_check_iteration: int = -1
    memory_health_interval: int = 10
    last_request_time: float = 0.0
    last_token_snapshot_time: float = 0.0
    last_context_validation: int = 0
    user_input_cooldown: float = 30.0
    last_user_input_time: float = 0.0


@dataclass
class RecoveryState:
    """Tracks recovery attempts and context management state."""

    recovery_force_tool_calls: int = 0
    adaptive_num_ctx: int = 0
    adaptive_num_predict_cap: int = 0
    vram_crash_count: int = 0
    token_snapshot_resave_requested: bool = False
    compression_summary: str = ""
    budget_pressure_level: int = 0
    loaded_skill_hashes: set[int] = field(default_factory=set)
    loaded_tech_skill_paths: set[str] = field(default_factory=set)

    def record_vram_crash(self) -> None:
        self.vram_crash_count += 1
        self.adaptive_num_ctx = max(4096, self.adaptive_num_ctx - 8192)
        self.adaptive_num_predict_cap = max(2048, self.adaptive_num_predict_cap - 1024)


@dataclass
class ScopeTrackingState:
    """Tracks visited URLs, scope locks, and browser visit limits."""

    visited_browser_urls: set[str] = field(default_factory=set)
    max_browser_visits_per_domain: int = 5
    scope_lock_active: bool = False
    scope_lock_brief: str = ""
    scope_anchor_target: str = ""


@dataclass
class UserInputState:
    """Interactive user input handling state."""

    user_input_event: asyncio.Event | None = None
    user_input_value: str = ""
    user_input_cancelled: bool = False
    user_input_request_id: str = ""
    user_input_prompt: str = ""
    user_input_type: str = "text"


@dataclass
class AgentState:
    conversation: list[dict[str, Any]] = field(default_factory=list)
    tool_history: list[ToolExecution] = field(default_factory=list)
    tool_counts: dict[str, int] = field(
        default_factory=lambda: {"exec": 0, "total": 0, "subagents": 0}
    )
    token_usage: dict[str, int] = field(
        default_factory=lambda: {
            "used": 0,
            "limit": 65536,
            "cumulative": 0,
            "cumulative_prompt": 0,
            "cumulative_completion": 0,
            "last_prompt": 0,
            "last_completion": 0,
        }
    )
    skills_used: list[str] = field(default_factory=list)
    planned_tools: list[str] = field(default_factory=list)
    iteration: int = 0
    max_iterations: int = field(
        default_factory=lambda: _get_model_limits()["max_tool_iterations"]
    )
    active_target: str | None = None
    warnings_sent: bool = False

    missing_tool_count: int = 0
    objective_queue: list[dict[str, Any]] = field(default_factory=list)
    evidence_log: list[dict[str, Any]] = field(default_factory=list)

    phase_tool_usage: dict[str, dict[str, int]] = field(default_factory=dict)

    tool_effectiveness: dict[str, dict[str, dict[str, int]]] = field(
        default_factory=dict
    )

    http_baselines: dict[str, dict[str, Any]] = field(default_factory=dict)

    # Per-host HTTP session state. Key: registrable host (e.g. "example.com").
    # Value: {"cookies": {name: value}, "bearer": str|None,
    #         "updated_at_iter": int, "rate_limit_until_iter": int,
    #         "csrf": {"token": str, "field": str, "source": str}}.
    # Used by http_observe to preserve auth across calls in realistic
    # authenticated bug-bounty flows. LLM controls login explicitly;
    # Python just carries the cookie jar, flags rate limits, and harvests
    # CSRF tokens so the LLM can re-inject them on state-changing requests.
    http_sessions: dict[str, dict[str, Any]] = field(default_factory=dict)

    hypothesis_queue: list[dict[str, Any]] = field(default_factory=list)

    exploit_chains: list[dict[str, Any]] = field(default_factory=list)

    dead_hosts: list[str] = field(default_factory=list)

    failure_log: list[dict[str, Any]] = field(default_factory=list)

    objective_dependencies: dict[str, list[str]] = field(default_factory=dict)

    _compress_failures: list[bool] = field(
        default_factory=list, repr=False, compare=False
    )

    def add_message(
        self,
        role: str,
        content: str,
        tool_calls: list[dict[str, Any]] | None = None,
        thinking: str | None = None,
    ) -> None:

        if role == "assistant" and content and "<think" in content:
            content = _THINK_BLOCK_RE.sub("", content)

            content = _THINK_OPEN_RE.sub("", content).strip()

        msg: dict[str, Any] = {"role": role, "content": content}
        if tool_calls:
            msg["tool_calls"] = tool_calls
        if thinking:
            msg["thinking"] = thinking
        self.conversation.append(msg)

        limits = _get_context_limits()
        if len(self.conversation) > limits["max_conversation_messages"]:
            self._smart_truncate_conversation()

        model_limits = _get_model_limits()
        if len(self.tool_history) > model_limits["max_tool_history"]:
            self.tool_history = self.tool_history[-model_limits["max_tool_history"] :]

        if len(self.tool_history) > model_limits["max_tool_history"]:
            scan_pos = int(getattr(self, "_legacy_tool_history_scan_pos", 0) or 0)
            scan_tick = int(getattr(self, "_legacy_tool_history_scan_tick", 0) or 0) + 1

            if scan_pos < 0 or scan_pos > len(self.tool_history):
                scan_pos = 0

            start_idx = 0 if (scan_tick % 20 == 0) else scan_pos
            for entry in self.tool_history[start_idx:]:
                if entry.result and isinstance(entry.result, dict):
                    entry.result = _truncate_tool_result(entry.result)
            self._legacy_tool_history_scan_pos = len(self.tool_history)
            self._legacy_tool_history_scan_tick = scan_tick

    def _smart_truncate_conversation(self) -> None:
        limits = _get_context_limits()
        if len(self.conversation) <= limits["max_conversation_messages"]:
            return

        system_msgs = [m for m in self.conversation if m.get("role") == "system"]
        non_system_msgs = [m for m in self.conversation if m.get("role") != "system"]

        keep_count = max(0, limits["max_conversation_messages"] - len(system_msgs))
        kept_non_system = non_system_msgs[-keep_count:] if keep_count > 0 else []

        self.conversation = system_msgs + kept_non_system

        if len(self.conversation) > limits["max_conversation_messages"]:
            self.conversation = self.conversation[
                -limits["max_conversation_messages"] :
            ]

    def ensure_phase_objectives(self, phase: str, defaults: list[str]) -> None:
        if not defaults:
            return

        existing = {
            str(obj.get("title", "")).strip().lower()
            for obj in self.objective_queue
            if str(obj.get("phase", "")).upper() == phase.upper()
        }
        for idx, title in enumerate(defaults):
            key = title.strip().lower()
            if key in existing:
                continue
            self.objective_queue.append(
                {
                    "phase": phase.upper(),
                    "title": title,
                    "status": "pending",
                    "priority": max(1, 100 - (idx * 10)),
                    "updated_iteration": self.iteration,
                    "updated_at": datetime.now(timezone.utc).isoformat(),
                }
            )

        max_obj = _get_model_limits()["max_objectives"]
        if len(self.objective_queue) > max_obj:
            self.objective_queue = self.objective_queue[-max_obj:]

    def mark_objective(
        self,
        phase: str,
        title: str,
        status: str = "done",
        note: str | None = None,
    ) -> None:
        norm_phase = phase.upper()
        norm_title = title.strip().lower()
        now = datetime.now(timezone.utc).isoformat()
        for obj in self.objective_queue:
            if (
                str(obj.get("phase", "")).upper() == norm_phase
                and str(obj.get("title", "")).strip().lower() == norm_title
            ):
                obj["status"] = status
                obj["updated_iteration"] = self.iteration
                obj["updated_at"] = now
                if note:
                    obj["note"] = note
                return

    @staticmethod
    def _jaccard_similarity(a: str, b: str) -> float:
        return jaccard_similarity(a, b)

    def add_dead_host(self, host: str) -> bool:
        if not host:
            return False

        parsed = urlparse(host if "://" in host else f"http://{host}")
        normalised = (parsed.hostname or host).rstrip(".").lower()
        if normalised in self.dead_hosts:
            return False
        self.dead_hosts.append(normalised)

        if len(self.dead_hosts) > 500:
            self.dead_hosts = self.dead_hosts[-500:]
        logger.info(
            "Dead host recorded: %s (total: %d)", normalised, len(self.dead_hosts)
        )
        return True

    def add_failure(
        self,
        name: str,
        error_detail: str,
        target: str | None = None,
        error_type: str | None = None,
        failure_category: str = "tool",
    ) -> str:
        if not error_type:
            error_lower = error_detail.lower()
            if any(
                x in error_lower
                for x in [
                    "nxdomain",
                    "name_not_resolved",
                    "could not resolve",
                    "dead host",
                    "connection refused",
                    "no route to host",
                    "network is unreachable",
                    "failed to connect",
                    "couldn't connect",
                    "curl: (7)",
                ]
            ):
                error_type = "network"
            elif any(
                x in error_lower
                for x in ["401", "403", "unauthorized", "forbidden", "authentication"]
            ):
                error_type = "auth"
            elif any(
                x in error_lower
                for x in ["timeout", "timed out", "max retries", "curl: (28)"]
            ):
                error_type = "timeout"
            elif any(x in error_lower for x in ["404", "not found", "no such"]):
                error_type = "not_found"
            elif any(
                x in error_lower for x in ["429", "rate limit", "too many requests"]
            ):
                error_type = "rate_limit"
            elif any(
                x in error_lower
                for x in [
                    "<!doctype",
                    "<html",
                    "text/html",
                    "empty response",
                    "curl: (22)",
                    "the requested url returned error",
                ]
            ):
                error_type = "network"
            else:
                error_type = "other"

        suggested_actions = {
            "network": f"SKIP: {target or name} is unreachable. Focus on live hosts.",
            "auth": "Try different credentials or check for authentication bypass.",
            "timeout": "Increase timeout or try a lighter probe (e.g., ping instead of full scan).",
            "not_found": "Verify the endpoint exists or search for alternative paths.",
            "rate_limit": "Slow down requests or try from different IP/timing.",
            "other": f"Investigate root cause: {error_detail[:100]}",
        }

        failure_id = str(uuid.uuid4())[:8]
        failure_entry = {
            "id": failure_id,
            "type": failure_category,
            "name": name,
            "target": target,
            "error_type": error_type,
            "error_detail": error_detail[:500],
            "retry_count": 0,
            "last_retry_iteration": self.iteration,
            "suggested_action": suggested_actions.get(
                error_type, suggested_actions["other"]
            ),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        self.failure_log.append(failure_entry)
        logger.info(
            "Failure recorded: %s (%s) on %s — type=%s, retry=%d",
            name,
            failure_category,
            target or "unknown",
            error_type,
            0,
        )

        if len(self.failure_log) > 50:
            dropped = len(self.failure_log) - 50
            logger.debug("failure_log pruned: dropping %d oldest entries", dropped)
            self.failure_log = self.failure_log[-50:]

        return failure_id

    def retry_failure(self, failure_id: str) -> bool:
        retry_limits = {
            "network": 0,
            "auth": 2,
            "timeout": 1,
            "not_found": 0,
            "rate_limit": 3,
            "other": 1,
        }

        for failure in self.failure_log:
            if failure["id"] == failure_id:
                limit = retry_limits.get(failure["error_type"], 1)
                if failure["retry_count"] >= limit:
                    logger.info(
                        "Retry blocked for %s: already retried %d/%d times",
                        failure["name"],
                        failure["retry_count"],
                        limit,
                    )
                    return False
                failure["retry_count"] += 1
                failure["last_retry_iteration"] = self.iteration
                logger.info(
                    "Retry allowed for %s: attempt %d/%d",
                    failure["name"],
                    failure["retry_count"],
                    limit,
                )
                return True

        return False

    def add_objective_dependency(self, objective: str, depends_on: str) -> None:
        if objective not in self.objective_dependencies:
            self.objective_dependencies[objective] = []

        if depends_on not in self.objective_dependencies[objective]:
            self.objective_dependencies[objective].append(depends_on)
            logger.info(
                "Dependency added: '%s' depends on '%s' (total deps: %d)",
                objective,
                depends_on,
                len(self.objective_dependencies[objective]),
            )

    def get_blocked_objectives(self) -> list[str]:
        completed_titles = {
            obj.get("title", "").lower()
            for obj in self.objective_queue
            if obj.get("status", "").lower() == "done"
        }

        def _has_cycle(node: str, visited: set[str], stack: set[str]) -> bool:
            visited.add(node)
            stack.add(node)
            for neighbour in self.objective_dependencies.get(node, []):
                n_lower = neighbour.lower()
                if n_lower not in visited:
                    if _has_cycle(n_lower, visited, stack):
                        return True
                elif n_lower in stack:
                    return True
            stack.discard(node)
            return False

        visited_global: set[str] = set()
        cyclic: set[str] = set()
        for obj_key in self.objective_dependencies:
            if obj_key not in visited_global:
                if _has_cycle(obj_key.lower(), visited_global, set()):
                    cyclic.add(obj_key.lower())

        blocked = []
        for objective, deps in self.objective_dependencies.items():
            obj_lower = objective.lower()
            if obj_lower in cyclic:
                blocked.append(objective)
                continue
            for dep in deps:
                if dep.lower() not in completed_titles:
                    blocked.append(objective)
                    break

        return blocked

    def get_failure_summary(self) -> dict[str, Any]:
        if not self.failure_log:
            return {"total": 0}

        by_type: dict[str, int] = {}
        for failure in self.failure_log:
            error_type = failure["error_type"]
            by_type[error_type] = by_type.get(error_type, 0) + 1

        recent = self.failure_log[-10:]

        return {
            "total": len(self.failure_log),
            "by_type": by_type,
            "most_common": max(by_type.items(), key=lambda x: x[1])[0]
            if by_type
            else None,
            "recent_failures": [
                {
                    "name": f["name"],
                    "type": f["error_type"],
                    "suggested_action": f["suggested_action"],
                }
                for f in recent
            ],
        }

    def add_evidence(
        self,
        phase: str,
        source_tool: str,
        summary: str,
        confidence: float = 0.70,
        artifact: str | None = None,
        tags: list[str] | None = None,
        severity: int = 1,
    ) -> bool:
        clean_summary = " ".join(str(summary).strip().split())
        if not clean_summary:
            return False

        if confidence < 0.70:
            confidence = _calculate_objective_confidence(
                clean_summary, artifact, source_tool, severity
            )

        phase_key = phase.upper()
        tags = tags or []
        dedup_key = (
            phase_key,
            source_tool.strip().lower(),
            clean_summary.lower(),
            (artifact or "").strip().lower(),
        )

        _dedup_start = monotonic()
        summary_lower = clean_summary.lower()
        scan_limit = _get_evidence_dedup_scan_limit()
        recent_evidence = self.evidence_log[-scan_limit:]
        if len(self.evidence_log) > scan_limit:
            logger.debug(
                "Evidence dedup scan window capped: total=%d scan=%d",
                len(self.evidence_log),
                scan_limit,
            )
        for existing in recent_evidence:
            prev_key = (
                str(existing.get("phase", "")).upper(),
                str(existing.get("source_tool", "")).strip().lower(),
                str(existing.get("summary", "")).strip().lower(),
                str(existing.get("artifact", "")).strip().lower(),
            )
            if dedup_key == prev_key:
                return False

            if str(existing.get("phase", "")).upper() != phase_key:
                if confidence >= 0.85:
                    existing_summary = str(existing.get("summary", "")).strip().lower()
                    if (
                        self._jaccard_similarity(summary_lower, existing_summary)
                        >= 0.85
                    ):
                        logger.debug(
                            "Evidence dedup (cross-phase, high-confidence): '%s...' ~ '%s...'",
                            summary_lower[:40],
                            existing_summary[:40],
                        )
                        return False
                continue

            existing_summary = str(existing.get("summary", "")).strip().lower()
            if (
                self._jaccard_similarity(summary_lower, existing_summary)
                >= _get_evidence_similarity_threshold()
            ):
                logger.debug(
                    "Evidence dedup (semantic): '%s...' ~ '%s...'",
                    summary_lower[:40],
                    existing_summary[:40],
                )
                return False

        _dedup_elapsed = monotonic() - _dedup_start
        if _dedup_elapsed >= 1.0:
            logger.warning(
                "Evidence dedup slow path: %.2fs (scan=%d total=%d)",
                _dedup_elapsed,
                len(recent_evidence),
                len(self.evidence_log),
            )

        raw_severity = severity
        clamped_severity = severity_to_int(severity)
        if isinstance(raw_severity, str) and raw_severity.strip().upper() != int_to_severity(
            clamped_severity
        ):
            logger.warning(
                "Evidence severity normalized from %r to %d: %s",
                raw_severity,
                clamped_severity,
                clean_summary[:100],
            )
        elif (
            isinstance(raw_severity, (int, float))
            and not isinstance(raw_severity, bool)
            and int(raw_severity) != clamped_severity
        ):
            logger.warning(
                "Evidence severity normalized from %r to %d: %s",
                raw_severity,
                clamped_severity,
                clean_summary[:100],
            )
        severity = clamped_severity

        self.evidence_log.append(
            {
                "phase": phase_key,
                "source_tool": source_tool,
                "summary": clean_summary[:600],
                "confidence": max(0.0, min(float(confidence), 1.0)),
                "severity": severity,
                "artifact": artifact,
                "tags": tags,
                "iteration": self.iteration,
                "created_at": datetime.now(timezone.utc).isoformat(),
            }
        )
        max_ev = _get_model_limits()["max_evidence"]
        if len(self.evidence_log) > max_ev:

            def _evidence_score(e: dict) -> float:
                conf = float(e.get("confidence", 0.0))
                sev = severity_to_int(e.get("severity", 3))
                return conf * _SEVERITY_MULTIPLIER.get(sev, 1.0)

            kept = heapq.nlargest(
                max_ev,
                self.evidence_log,
                key=_evidence_score,
            )
            kept.sort(key=lambda e: int(e.get("iteration", 0)))
            self.evidence_log = kept
        return True

    def record_tool_use(self, phase: str, tool_name: str) -> None:
        bucket = self.phase_tool_usage.setdefault(phase, {})
        bucket[tool_name] = bucket.get(tool_name, 0) + 1

    def record_tool_outcome(
        self,
        phase: str,
        tool_name: str,
        *,
        success: bool,
        meaningful_evidence_delta: int = 0,
    ) -> None:
        phase_bucket = self.tool_effectiveness.setdefault(phase, {})
        metrics = phase_bucket.setdefault(
            tool_name,
            {"calls": 0, "successes": 0, "meaningful_hits": 0},
        )
        metrics["calls"] += 1
        if success:
            metrics["successes"] += 1
        if meaningful_evidence_delta > 0:
            metrics["meaningful_hits"] += 1

    def get_tool_effectiveness(self, phase: str, tool_name: str) -> dict[str, float]:
        raw = self.tool_effectiveness.get(phase, {}).get(tool_name, {})
        calls = int(raw.get("calls", 0))
        successes = int(raw.get("successes", 0))
        hits = int(raw.get("meaningful_hits", 0))
        if calls <= 0:
            return {
                "calls": 0.0,
                "success_rate": 0.0,
                "hit_rate": 0.0,
            }
        return {
            "calls": float(calls),
            "success_rate": round(successes / calls, 3),
            "hit_rate": round(hits / calls, 3),
        }

    def get_phase_tool_count(self, phase: str, tool_name: str) -> int:
        return self.phase_tool_usage.get(phase, {}).get(tool_name, 0)

    def get_active_chains(self) -> list[dict[str, Any]]:
        return [
            c for c in self.exploit_chains if c.get("status") in ("planning", "active")
        ]

    def update_chain_step(
        self,
        chain_id: str,
        evidence: str = "",
    ) -> bool:
        for chain in self.exploit_chains:
            if chain.get("chain_id") == chain_id:
                steps = chain.get("steps", [])
                idx = chain.get("current_step_index", 0)
                if idx < len(steps):
                    steps[idx]["status"] = "done"
                    if evidence:
                        steps[idx]["evidence"] = evidence[:300]
                    chain["current_step_index"] = idx + 1
                    if chain.get("status") == "planning":
                        chain["status"] = "active"
                if chain.get("current_step_index", 0) >= len(steps):
                    chain["status"] = "completed"
                return True
        return False

    def add_hypothesis(
        self,
        claim: str,
        test_plan: str,
        phase: str = "RECON",
        tags: list[str] | None = None,
    ) -> str:
        claim = claim.strip()
        if not claim:
            return ""

        for existing in self.hypothesis_queue:
            if (
                jaccard_similarity(
                    claim.lower(), str(existing.get("claim", "")).lower()
                )
                >= 0.80
            ):
                return str(existing.get("id", ""))

        hyp_id = f"h_{self.iteration}_{len(self.hypothesis_queue)}"
        self.hypothesis_queue.append(
            {
                "id": hyp_id,
                "claim": claim,
                "test_plan": test_plan.strip(),
                "status": "pending",
                "evidence_refs": [],
                "iteration_formed": self.iteration,
                "phase": phase.upper(),
                "tags": tags or [],
                "updated_at": datetime.now(timezone.utc).isoformat(),
            }
        )
        if len(self.hypothesis_queue) > MAX_HYPOTHESES:
            self.hypothesis_queue = sorted(
                self.hypothesis_queue,
                key=lambda h: (
                    0
                    if str(h.get("status", "")) in ("pending", "testing")
                    else 1
                    if str(h.get("status", "")) == "confirmed"
                    else 2,
                    int(h.get("iteration_formed", 0)),
                ),
            )[:MAX_HYPOTHESES]
        return hyp_id

    def update_hypothesis(
        self,
        hyp_id: str,
        status: str,
        evidence_summary: str | None = None,
    ) -> bool:
        for hyp in self.hypothesis_queue:
            if hyp.get("id") == hyp_id:
                hyp["status"] = status
                hyp["updated_at"] = datetime.now(timezone.utc).isoformat()
                if evidence_summary:
                    refs = hyp.setdefault("evidence_refs", [])
                    if evidence_summary not in refs:
                        refs.append(evidence_summary[:200])
                return True
        return False

    def get_pending_hypotheses(self, max_items: int = 5) -> list[dict[str, Any]]:
        pending = [
            h
            for h in self.hypothesis_queue
            if str(h.get("status", "pending")) in ("pending", "testing")
        ]
        pending.sort(key=lambda h: int(h.get("iteration_formed", 0)))
        return pending[:max_items]

    def resolve_hypotheses_from_evidence(self) -> int:
        confirmed_count = 0
        min_conf = _get_model_limits()["min_confidence_for_preservation"]
        high_evidence = [
            e
            for e in self.evidence_log
            if severity_to_int(e.get("severity", 1)) >= 4
            and float(e.get("confidence", 0.0)) >= min_conf
        ]
        for hyp in self.hypothesis_queue:
            if str(hyp.get("status", "")) not in ("pending", "testing"):
                continue
            claim_lower = str(hyp.get("claim", "")).lower()
            for ev in high_evidence:
                summary_lower = str(ev.get("summary", "")).lower()
                if jaccard_similarity(claim_lower, summary_lower) >= 0.35:
                    hyp["status"] = "confirmed"
                    hyp["updated_at"] = datetime.now(timezone.utc).isoformat()
                    refs = hyp.setdefault("evidence_refs", [])
                    ref = str(ev.get("summary", ""))[:200]
                    if ref not in refs:
                        refs.append(ref)
                    confirmed_count += 1
                    break
        return confirmed_count

    def build_hypothesis_context(self, max_pending: int = 4) -> str:
        pending = self.get_pending_hypotheses(max_items=max_pending)
        confirmed = [
            h for h in self.hypothesis_queue if str(h.get("status", "")) == "confirmed"
        ][-3:]
        refuted = [
            h for h in self.hypothesis_queue if str(h.get("status", "")) == "refuted"
        ][-2:]

        if not pending and not confirmed:
            return ""

        lines = ["<hypothesis_queue>"]
        if pending:
            lines.append("  <pending>")
            for h in pending:
                hid = h.get("id", "")
                claim = h.get("claim", "")
                plan = h.get("test_plan", "")
                status = h.get("status", "pending")
                lines.append(f'    <hypothesis id="{hid}" status="{status}">')
                lines.append(f"      <claim>{claim}</claim>")
                if plan:
                    lines.append(f"      <test_plan>{plan}</test_plan>")
                lines.append("    </hypothesis>")
            lines.append("  </pending>")
        if confirmed:
            lines.append("  <confirmed>")
            for h in confirmed:
                lines.append(f"    - [{h.get('id', '')}] {h.get('claim', '')}")
            lines.append("  </confirmed>")
        if refuted:
            lines.append("  <refuted_do_not_retry>")
            for h in refuted:
                lines.append(f"    - [{h.get('id', '')}] {h.get('claim', '')}")
            lines.append("  </refuted_do_not_retry>")
        lines.append(
            "  <instruction>Pick one PENDING hypothesis and execute its test_plan "
            "via tool call. Use record_hypothesis to update status after testing.</instruction>"
        )
        lines.append("</hypothesis_queue>")
        return "\n".join(lines)

    def get_phase_context(
        self,
        phase: str,
        max_objectives: int = 4,
        max_evidence: int = 6,
        filter_evidence_by_phase: bool = True,
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
        phase_key = phase.upper()

        pending = [
            o
            for o in self.objective_queue
            if str(o.get("phase", "")).upper() == phase_key
            and str(o.get("status", "pending")).lower() != "done"
        ]
        pending = sorted(
            pending, key=lambda x: int(x.get("priority", 0)), reverse=True
        )[:max_objectives]

        completed = [
            o
            for o in self.objective_queue
            if str(o.get("phase", "")).upper() == phase_key
            and str(o.get("status", "")).lower() == "done"
        ][:max_objectives]

        if filter_evidence_by_phase:
            evidence = [
                e
                for e in reversed(self.evidence_log)
                if str(e.get("phase", "")).upper() == phase_key
                and float(e.get("confidence", 1.0)) >= _CONF_FLOOR
            ][:max_evidence]
        else:
            evidence = [
                e
                for e in reversed(self.evidence_log)
                if float(e.get("confidence", 1.0)) >= _CONF_FLOOR
            ][:max_evidence]

        return pending, completed, evidence

    def build_focus_context(
        self,
        phase: str,
        max_objectives: int = 4,
        max_evidence: int = 6,
    ) -> str:
        phase_key = phase.upper()

        pending, completed, evidence = self.get_phase_context(
            phase_key, max_objectives=max_objectives, max_evidence=max_evidence
        )

        has_dead = bool(self.dead_hosts)
        has_failures = bool(self.failure_log)
        if (
            not pending
            and not evidence
            and not completed
            and not has_dead
            and not has_failures
        ):
            return ""

        lines = [f'<objective_focus phase="{phase_key}">']
        if pending:
            lines.append("  <pending_objectives>")
            for obj in pending:
                lines.append(f"    - {obj.get('title', '')}")
            lines.append("  </pending_objectives>")
        if completed:
            lines.append("  <completed_objectives>")
            for obj in completed:
                lines.append(f"    - {obj.get('title', '')}")
            lines.append("  </completed_objectives>")
        if evidence:
            lines.append("  <recent_evidence>")
            for ev in evidence:
                src = ev.get("source_tool", "tool")
                summary = ev.get("summary", "")
                artifact = ev.get("artifact")
                artifact_note = f" [{artifact}]" if artifact else ""
                sev = severity_to_int(ev.get("severity", 1))
                sev_label = int_to_severity(sev)
                category_tags = [
                    t
                    for t in ev.get("tags", [])
                    if t.startswith("owasp:") or t.startswith("dynamic:")
                ]
                category_note = f" {','.join(category_tags)}" if category_tags else ""
                lines.append(
                    f"    - [{src}][{sev_label}]{category_note} {summary}{artifact_note}"
                )
            lines.append("  </recent_evidence>")

        if self.dead_hosts:
            dead_list = ", ".join(self.dead_hosts[:20])
            lines.append(
                "  <dead_hosts>NEVER use browser_action, httpx, curl, or any HTTP tool "
                f"against these unreachable hosts: {dead_list}</dead_hosts>"
            )

        failure_summary = self.get_failure_summary()
        if failure_summary.get("total", 0) > 0:
            lines.append("  <failure_summary>")
            lines.append(f"    Total failures: {failure_summary['total']}")
            if failure_summary.get("by_type"):
                lines.append("    By type:")
                for error_type, count in failure_summary["by_type"].items():
                    lines.append(f"      - {error_type}: {count}")
            if failure_summary.get("most_common"):
                lines.append(
                    f"    Most common: {failure_summary['most_common']} errors"
                )
            if failure_summary.get("recent_failures"):
                lines.append("    Recent failures (learn from these):")
                for failure in failure_summary["recent_failures"][:5]:
                    lines.append(
                        f"      - {failure['name']} ({failure['type']}): {failure['suggested_action']}"
                    )
            lines.append("  </failure_summary>")

        blocked = self.get_blocked_objectives()
        if blocked:
            lines.append("  <blocked_objectives>")
            lines.append("    These objectives are waiting for dependencies:")
            for obj in blocked[:10]:
                deps = self.objective_dependencies.get(obj, [])
                lines.append(f"    - {obj} (waiting for: {', '.join(deps)})")
            lines.append("  </blocked_objectives>")

        lines.append(
            "  <action_required>Pick one pending objective OR one high-value novel hypothesis."
            " Call the best next tool NOW — no more planning text.</action_required>"
        )
        lines.append("</objective_focus>")
        return "\n".join(lines)

    def patch_objectives(self, ops: list[dict[str, Any]]) -> int:
        from .pipeline import PipelinePhase

        _valid_phases = {p.value for p in PipelinePhase}

        changed = 0
        now = datetime.now(timezone.utc).isoformat()

        for op in ops:
            op_type = op.get("op", "").lower()
            title = str(op.get("title", "")).strip()
            phase = str(op.get("phase", "")).strip().upper()

            if op_type == "add":
                if not title:
                    continue

                _effective_phase = phase or "RECON"

                if _effective_phase not in _valid_phases:
                    logger.warning(
                        "patch_objectives: Invalid phase '%s' in op '%s', defaulting to RECON",
                        phase,
                        op_type,
                    )
                    _effective_phase = "RECON"

                existing_titles = {
                    str(o.get("title", "")).strip().lower()
                    for o in self.objective_queue
                    if str(o.get("phase", "")).upper() == _effective_phase
                }
                if title.lower() in existing_titles:
                    continue
                new_obj: dict[str, Any] = {
                    "phase": _effective_phase,
                    "title": title,
                    "status": "pending",
                    "priority": int(op.get("priority", 50)),
                    "updated_iteration": self.iteration,
                    "updated_at": now,
                }
                after_title = str(op.get("after_title", "")).strip().lower()
                if after_title:
                    idx = next(
                        (
                            i
                            for i, o in enumerate(self.objective_queue)
                            if str(o.get("title", "")).strip().lower() == after_title
                        ),
                        -1,
                    )
                    if idx >= 0:
                        self.objective_queue.insert(idx + 1, new_obj)
                    else:
                        self.objective_queue.append(new_obj)
                else:
                    self.objective_queue.append(new_obj)
                changed += 1

            elif op_type == "remove":
                before = len(self.objective_queue)
                self.objective_queue = [
                    o
                    for o in self.objective_queue
                    if not (
                        str(o.get("title", "")).strip().lower() == title.lower()
                        and (not phase or str(o.get("phase", "")).upper() == phase)
                        and str(o.get("status", "pending")).lower() != "done"
                    )
                ]
                changed += before - len(self.objective_queue)

            elif op_type == "modify":
                new_title = str(op.get("new_title", "")).strip()
                for obj in self.objective_queue:
                    if str(obj.get("title", "")).strip().lower() == title.lower() and (
                        not phase or str(obj.get("phase", "")).upper() == phase
                    ):
                        if new_title:
                            obj["title"] = new_title
                        if "priority" in op:
                            obj["priority"] = int(op["priority"])
                        obj["updated_iteration"] = self.iteration
                        obj["updated_at"] = now
                        changed += 1
                        break

            elif op_type == "done":
                _done_phase = phase or "RECON"
                if _done_phase not in _valid_phases:
                    logger.warning(
                        "patch_objectives: Invalid phase '%s' in op 'done', defaulting to RECON",
                        phase,
                    )
                    _done_phase = "RECON"
                self.mark_objective(
                    _done_phase, title, status="done", note=op.get("note")
                )
                changed += 1

            elif op_type == "reorder":
                obj = next(
                    (
                        o
                        for o in self.objective_queue
                        if str(o.get("title", "")).strip().lower() == title.lower()
                        and (not phase or str(o.get("phase", "")).upper() == phase)
                    ),
                    None,
                )
                if obj:
                    self.objective_queue.remove(obj)
                    after_title = str(op.get("after_title", "")).strip().lower()
                    if after_title:
                        idx = next(
                            (
                                i
                                for i, o in enumerate(self.objective_queue)
                                if str(o.get("title", "")).strip().lower()
                                == after_title
                            ),
                            -1,
                        )
                        self.objective_queue.insert(idx + 1 if idx >= 0 else 0, obj)
                    else:
                        self.objective_queue.insert(0, obj)
                    changed += 1

        max_obj = _get_model_limits()["max_objectives"]
        if len(self.objective_queue) > max_obj:
            self.objective_queue = self.objective_queue[-max_obj:]

        return changed

    def is_approaching_limit(self) -> bool:
        return self.iteration >= (self.max_iterations - 3)

    def increment_iteration(self) -> None:
        self.iteration += 1

    def truncate_conversation(self, max_messages: int = 50) -> None:
        if len(self.conversation) <= max_messages:
            return

        EPHEMERAL_PREFIXES = (
            "[SYSTEM: WORKSPACE",
            "[SYSTEM: ACTIVE_TARGET",
            "[SYSTEM: ADDITIONAL_TARGETS",
            "[SYSTEM: RECENT EXECUTIONS",
            "[SYSTEM: EVALUATION CHECKPOINT",
            "[SYSTEM: MANDATORY PLANNING",
            "[SYSTEM: PREVIOUS SESSION DATA",
            "[SYSTEM: CRITICAL FINDINGS",
            "[SYSTEM: OBJECTIVE FOCUS",
            "<objective_focus",
            "[SYSTEM: PHASE GATE",
            "[SYSTEM: AGGRESSIVE EXPLORATION",
            "[SYSTEM: QUALITY SCOREBOARD",
            "[SYSTEM: CAIDO REMINDER",
            "[SYSTEM: UNVERIFIED CLAIM",
            "<reflector ",
            "<mentor_analysis>",
            "<hypothesis_queue",
            "<exploit_chain_plan>",
            "<waf_bypass ",
        )

        PROTECTED_PREFIXES = (
            "[SYSTEM: RECOVERY STATE",
            "[SYSTEM: PINNED CONTEXT",
            "[SYSTEM: STRICT_SCOPE_MODE",
            "[SYSTEM: MEMORY BRAIN",
            "[SYSTEM: RECOVERY MODE",
            "[SYSTEM: COMPRESSION SUMMARY",
            "[SYSTEM: REPORT PHASE —",
        )

        core_system: list[dict] = []
        ephemeral_system: list[dict] = []
        protected_system: list[dict] = []
        other_messages: list[dict] = []

        for msg in self.conversation:
            if msg.get("role") == "system":
                content = msg.get("content", "")
                if any(content.startswith(p) for p in PROTECTED_PREFIXES):
                    protected_system.append(msg)
                elif any(content.startswith(p) for p in EPHEMERAL_PREFIXES):
                    ephemeral_system.append(msg)
                else:
                    core_system.append(msg)
            else:
                other_messages.append(msg)

        if ephemeral_system:
            ephemeral_system = [ephemeral_system[-1]]

        # Keep the FRESHEST message of each protected type rather than blindly the
        # last two — so scope, pinned findings, recovery state and the compression
        # summary all survive even when several protected messages accumulated.
        if protected_system:
            try:
                _max_protected = int(
                    getattr(get_config(), "memory_protected_context_max", 6)
                )
            except (TypeError, ValueError):
                _max_protected = 6
            _latest_by_type: dict[str, dict] = {}
            for _msg in protected_system:
                _c = str(_msg.get("content", ""))
                _key = next(
                    (p for p in PROTECTED_PREFIXES if _c.startswith(p)), "_other"
                )
                _latest_by_type[_key] = _msg  # latest of each type wins
            protected_system = list(_latest_by_type.values())[-max(1, _max_protected):]

        limits = _get_context_limits()
        compress_boundary = max(
            0, len(other_messages) - limits["uncompressed_keep_count"]
        )
        for i in range(compress_boundary):
            msg = other_messages[i]
            content = msg.get("content", "")
            role = msg.get("role", "")

            if role == "tool" and len(content) > 200:
                if "COMMAND FAILED" in content:
                    first_line = content.split("\n")[0]
                    msg["content"] = f"[COMPRESSED] {first_line}"
                elif "TOTAL:" in content:
                    for line in content.split("\n"):
                        if "TOTAL:" in line:
                            msg["content"] = f"[COMPRESSED] {line.strip()}"
                            break
                elif "Success" in content[:50]:
                    first_line = content.split("\n")[0]
                    msg["content"] = f"[COMPRESSED] {first_line[:150]}"
                else:
                    msg["content"] = f"[COMPRESSED] Tool result ({len(content)} chars)"

            elif (
                role == "assistant" and not msg.get("tool_calls") and len(content) > 500
            ):
                msg["content"] = content[:200] + "... [truncated]"

        assistant_text_only = [
            m
            for m in other_messages
            if m.get("role") == "assistant" and not m.get("tool_calls")
        ]
        if len(assistant_text_only) > 3:
            dropped_text_ids = set(id(m) for m in assistant_text_only[1:-2])
            other_messages = [
                m for m in other_messages if id(m) not in dropped_text_ids
            ]

        budget = (
            max_messages
            - len(core_system)
            - len(ephemeral_system)
            - len(protected_system)
        )
        if len(other_messages) <= budget:
            self.conversation = (
                core_system + ephemeral_system + protected_system + other_messages
            )
            logger.info(
                "Truncated (compressed + text-drop): %d messages",
                len(self.conversation),
            )
            return

        must_keep = []
        can_trim = []
        first_user_seen = False

        for msg in other_messages:
            if msg.get("role") == "user" and not first_user_seen:
                must_keep.append(msg)
                first_user_seen = True
            else:
                can_trim.append(msg)

        tail_budget = max(budget - len(must_keep), 10)
        if len(can_trim) > tail_budget:
            tail = can_trim[-tail_budget:]

            start_idx = len(can_trim) - tail_budget
            while start_idx > 0:
                previous_start_idx = start_idx
                found_orphan = False
                for i in range(start_idx, len(can_trim)):
                    if can_trim[i].get("role") == "tool":
                        for j in range(i - 1, start_idx - 1, -1):
                            if can_trim[j].get("role") == "assistant" and can_trim[
                                j
                            ].get("tool_calls"):
                                break
                        else:
                            found_orphan = True

                            for j in range(i - 1, -1, -1):
                                if can_trim[j].get("role") == "assistant" and can_trim[
                                    j
                                ].get("tool_calls"):
                                    start_idx = j
                                    break
                            else:
                                start_idx -= 1
                            break
                if not found_orphan:
                    break
                if start_idx >= previous_start_idx:
                    start_idx = previous_start_idx - 1
                tail = can_trim[start_idx:]
            trimmed = tail
            dropped_count = len(can_trim) - len(trimmed)
        else:
            trimmed = can_trim
            dropped_count = 0

        separator = {
            "role": "system",
            "content": (
                f"[SYSTEM: {dropped_count} older messages compressed/removed to manage context. "
                "Key findings are preserved in the session summary. "
                "The original user request is preserved above.]"
            ),
        }

        rebuilt = must_keep + ([separator] if dropped_count > 0 else []) + trimmed
        repaired = self._repair_tool_pairs(
            core_system + ephemeral_system + protected_system + rebuilt
        )
        self.conversation = repaired
        logger.info(
            "Truncated (pair-preserving): %d messages (dropped %d older messages)",
            len(self.conversation),
            dropped_count,
        )

    @staticmethod
    def _repair_tool_pairs(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
        surviving_call_ids: set[str] = set()
        for msg in messages:
            if msg.get("role") == "assistant":
                for tc in msg.get("tool_calls") or []:
                    cid = (
                        tc.get("id", "")
                        if isinstance(tc, dict)
                        else getattr(tc, "id", "") or ""
                    )
                    if cid:
                        surviving_call_ids.add(cid)

        result_call_ids: set[str] = set()
        for msg in messages:
            if msg.get("role") == "tool":
                cid = msg.get("tool_call_id", "")
                if cid:
                    result_call_ids.add(cid)

        orphaned_results = result_call_ids - surviving_call_ids
        if orphaned_results:
            messages = [
                m
                for m in messages
                if not (
                    m.get("role") == "tool"
                    and m.get("tool_call_id") in orphaned_results
                )
            ]
            logger.debug(
                "Pair repair: dropped %d orphaned tool result(s) %s",
                len(orphaned_results),
                orphaned_results,
            )

        missing_results = surviving_call_ids - result_call_ids
        if missing_results:
            patched: list[dict[str, Any]] = []
            for msg in messages:
                patched.append(msg)
                if msg.get("role") == "assistant":
                    for tc in msg.get("tool_calls") or []:
                        cid = (
                            tc.get("id", "")
                            if isinstance(tc, dict)
                            else getattr(tc, "id", "") or ""
                        )
                        if cid in missing_results:
                            patched.append(
                                {
                                    "role": "tool",
                                    "tool_call_id": cid,
                                    "content": (
                                        "[Tool result unavailable — "
                                        "earlier context was compressed]"
                                    ),
                                }
                            )
                            logger.debug(
                                "Pair repair: inserted stub for call_id=%s", cid
                            )
            messages = patched

        return messages

    @staticmethod
    def _extract_flags(content: str) -> list[str]:
        return list({m.group(0) for m in FLAG_PATTERN.finditer(content)})

    @staticmethod
    def _extract_subdomains(content: str) -> set[str]:
        pattern = re.compile(
            r"\b([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+(?::\d+)?)\b",
            re.IGNORECASE,
        )
        matches = pattern.findall(content)

        subdomains = set()
        for m in matches:
            parts = m.split(".")
            if len(parts) >= 3:
                subdomains.add(m)
        return subdomains

    @staticmethod
    def _extract_urls(content: str) -> set[str]:
        pattern = re.compile(r"https?://[^\s<>\"]+")
        return set(pattern.findall(content))

    @staticmethod
    def _extract_ports(content: str) -> set[str]:
        patterns = [
            re.compile(r"\b(\d{1,5})/(?:tcp|udp)\b", re.IGNORECASE),
            re.compile(r"\bPORT[:\s]+(\d{1,5})\b", re.IGNORECASE),
            re.compile(r"\b(\d{1,5})/open\b", re.IGNORECASE),
            re.compile(r":(\d{1,5})\b"),
        ]
        ports = set()
        for p in patterns:
            for m in p.findall(content):
                port_num = int(m)
                if 1 <= port_num <= 65535:
                    ports.add(str(port_num))
        return ports

    _cached_vuln_patterns: list[re.Pattern] | None = None

    @staticmethod
    def _load_vuln_patterns() -> list[re.Pattern]:
        if AgentState._cached_vuln_patterns:
            return AgentState._cached_vuln_patterns

        patterns = []
        try:
            for entry in load_vuln_hypothesis_legacy():
                for pat in entry.get("patterns", []):
                    try:
                        patterns.append(re.compile(str(pat), re.IGNORECASE))
                    except re.error:
                        pass
        except Exception as _e:
            logger.debug("Failed to load pin patterns: %s", _e)

        if not patterns:
            patterns = [
                re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE),
                re.compile(r"CWE-\d+", re.IGNORECASE),
                re.compile(
                    r"(?i)(sql\s*injection|xss|csrf|ssrf|lfi|rfi|xxe|rce)",
                    re.IGNORECASE,
                ),
            ]

        AgentState._cached_vuln_patterns = patterns
        return patterns

    @staticmethod
    def _extract_vulns(content: str) -> set[str]:
        patterns = AgentState._load_vuln_patterns()
        vulns = set()
        for p in patterns:
            vulns.update(m.group(0).upper() for m in p.finditer(content))
        return vulns

    @staticmethod
    def _extract_credentials(content: str) -> set[str]:
        pattern = re.compile(r"\b([a-zA-Z0-9_-]+:[a-zA-Z0-9_@#$%^&*!-]+)\b")
        matches = pattern.findall(content)

        creds = set()
        for m in matches:
            if ":" in m and len(m) < 100:
                creds.add(m)
        return creds

    @staticmethod
    def _extract_tools(content: str) -> set[str]:
        if not hasattr(AgentState._extract_tools, "_tool_names"):
            try:
                import json

                tools_path = Path(__file__).parent.parent / "data" / "tools_meta.json"
                with open(tools_path) as f:
                    meta = json.load(f)

                all_tools = set()

                categories = meta.get("categories", {})
                for category_name, subcategories in categories.items():
                    if isinstance(subcategories, dict):
                        for subcategory_name, tools in subcategories.items():
                            if isinstance(tools, list):
                                all_tools.update(tools)

                parallel_tools = meta.get("parallelizable_tools", [])
                all_tools.update(parallel_tools)

                vuln_tools = meta.get("analysis_phase_vuln_tools", [])
                all_tools.update(vuln_tools)

                safe_prefixes = meta.get("watchdog_safe_command_prefixes", [])
                all_tools.update(safe_prefixes)

                parser_patterns = meta.get("output_parser_tool_patterns", {})
                all_tools.update(parser_patterns.keys())

                alternatives = meta.get("tool_alternatives", {})
                all_tools.update(alternatives.keys())

                AgentState._extract_tools._tool_names = list(all_tools)

            except Exception as e:
                logging.getLogger(__name__).debug(
                    "Expected failure reading tool names: %s", e
                )
                AgentState._extract_tools._tool_names = []

        content_lower = content.lower()
        return {
            tool
            for tool in AgentState._extract_tools._tool_names
            if tool.lower() in content_lower
        }

    @staticmethod
    def _extract_phases(content: str) -> set[str]:
        phases = ["RECON", "ANALYSIS", "EXPLOIT", "REPORT"]
        found = set()
        content_upper = content.upper()
        for phase in phases:
            if phase in content_upper:
                found.add(phase)
        return found

    @staticmethod
    def _extract_injection_types(content: str) -> set[str]:
        pattern = re.compile(
            r"\b(SQL|XSS|CMD|RFI|LFI|SSRF|XXE|SSTI|LDAP|XPath|XPath|\bInj|\bInj|\bInj|\bInj|\bInj)\b",
            re.IGNORECASE,
        )
        return set(m.group(1).upper() for m in pattern.finditer(content))

    @staticmethod
    def _extract_key_info(content: str, max_chars: int = 500) -> str:
        PRIORITY_PATTERNS = [
            FLAG_PATTERN,
            re.compile(r"HTTP/[\d.]+ \d+"),
            re.compile(r"https?://\S+"),
            re.compile(
                r"(?i)(error|found|success|failed|token|secret|password|key|"
                r"admin|root|flag|credential|auth|login|cookie|session)"
            ),
        ]

        priority_lines: list[str] = []
        seen: set[str] = set()
        for line in content.split("\n"):
            stripped = line.strip()
            if not stripped or stripped in seen:
                continue
            if any(p.search(stripped) for p in PRIORITY_PATTERNS):
                priority_lines.append(stripped)
                seen.add(stripped)

        key_part = "\n".join(priority_lines[:30])
        if len(key_part) >= max_chars:
            return key_part[:max_chars]

        remaining = max_chars - len(key_part)
        filler = content[:remaining].strip()
        if key_part and filler:
            return key_part + "\n" + filler
        return (key_part or filler)[:max_chars]

    async def compress_with_llm(
        self,
        llm: Any,
        keep_recent: int | None = None,
        num_ctx: int | None = None,
        num_predict: int | None = None,
        phase: str | None = None,
    ) -> None:
        """Improved compression for pentesting/bugbounty/CTF that preserves critical context.

        Key improvements:
        1. Phase-aware compression - different rules for RECON vs EXPLOIT
        2. Evidence preservation - never lose high-severity findings
        3. Hypothesis protection - keeps attack hypotheses intact
        4. Injection point tracking - preserves discovered injection points
        5. Tool chain preservation - remembers successful tool sequences
        """
        limits = _get_context_limits()
        if keep_recent is None:
            keep_recent = 30
        if num_ctx is None:
            num_ctx = limits["llm_compression_num_ctx"]
        if num_predict is None:
            num_predict = limits["llm_compression_num_predict"]

        if phase is None:
            phase = "RECON"

        prior_summary = str(getattr(self, "compression_summary", "") or "").strip()
        pending_hypotheses = self.get_pending_hypotheses(max_items=4)
        recent_failures = self.failure_log[-4:]
        recent_high_evidence = [
            e
            for e in self.evidence_log[-12:]
            if severity_to_int(e.get("severity", 1)) >= 4
            or float(e.get("confidence", 0.0)) >= 0.85
        ][-4:]

        carry_forward_lines: list[str] = []
        if prior_summary:
            carry_forward_lines.append("PREVIOUS SUMMARY TO PRESERVE:")
            carry_forward_lines.append(prior_summary[:1200])

        if pending_hypotheses:
            carry_forward_lines.append("OPEN HYPOTHESES / WORK IN PROGRESS:")
            for hyp in pending_hypotheses:
                claim = str(hyp.get("claim", "") or "").strip()
                test_plan = str(hyp.get("test_plan", "") or "").strip()
                line = f"- {claim[:160]}"
                if test_plan:
                    line += f" -> next: {test_plan[:120]}"
                carry_forward_lines.append(line)

        if recent_failures:
            carry_forward_lines.append("RECENT MISTAKES / FAILURES TO REMEMBER:")
            for failure in recent_failures:
                line = (
                    f"- {str(failure.get('name', 'tool'))} "
                    f"[{str(failure.get('error_type', 'other'))}] "
                    f"on {str(failure.get('target', '') or 'current target')}: "
                    f"{str(failure.get('suggested_action', 'review the last error'))[:160]}"
                )
                carry_forward_lines.append(line)

        if recent_high_evidence:
            carry_forward_lines.append("UNUSUAL / HIGH-VALUE SIGNALS:")
            for ev in recent_high_evidence:
                carry_forward_lines.append(
                    f"- {str(ev.get('summary', '') or '')[:180]}"
                )

        carry_forward_context = "\n".join(carry_forward_lines).strip()

        non_system = [m for m in self.conversation if m.get("role") != "system"]
        if len(non_system) <= keep_recent + 1:
            return

        system_msgs = [m for m in self.conversation if m.get("role") == "system"]
        first_user = non_system[0]
        to_compress = non_system[1 : len(non_system) - keep_recent]
        keep_tail = non_system[len(non_system) - keep_recent :]

        if len(to_compress) < 5:
            return

        CHUNK_SIZE = 10
        summaries: list[dict[str, Any]] = []

        for i in range(0, len(to_compress), CHUNK_SIZE):
            chunk = to_compress[i : i + CHUNK_SIZE]

            extracted_data = {
                "subdomains": set(),
                "urls": set(),
                "ports": set(),
                "vulns": set(),
                "credentials": set(),
                "tools_used": set(),
                "phases": set(),
                "injection_types": set(),
                "evidence_high_severity": [],
                "hypotheses_pending": [],
            }

            for m in chunk:
                content = str(m.get("content", ""))
                role = m.get("role", "unknown")

                extracted_data["subdomains"].update(
                    AgentState._extract_subdomains(content)
                )
                extracted_data["urls"].update(AgentState._extract_urls(content))
                extracted_data["ports"].update(AgentState._extract_ports(content))
                extracted_data["vulns"].update(AgentState._extract_vulns(content))
                extracted_data["credentials"].update(
                    AgentState._extract_credentials(content)
                )
                extracted_data["tools_used"].update(AgentState._extract_tools(content))
                extracted_data["injection_types"].update(
                    AgentState._extract_injection_types(content)
                )
                if role == "system":
                    extracted_data["phases"].update(AgentState._extract_phases(content))

                if (
                    "SEV=5]" in content
                    or "SEV=4]" in content
                    or "[CRITICAL]" in content
                    or "[HIGH]" in content
                ):
                    extracted_data["evidence_high_severity"].append(content[:500])

                if (
                    "PENDING" in content
                    or "TODO" in content
                    or "TEST" in content
                    or "hypothesis" in content.lower()
                ):
                    extracted_data["hypotheses_pending"].append(content[:300])

            chunk_text_parts = []
            for m in chunk:
                role = m.get("role", "unknown")
                content = str(m.get("content", ""))

                key_info = AgentState._extract_key_info(content, 200)
                if key_info.strip():
                    chunk_text_parts.append(f"[{role.upper()}]: {key_info}")

            chunk_text = "\n".join(chunk_text_parts)

            context_header = []
            context_critical = []

            if extracted_data["subdomains"]:
                subs_list = ", ".join(sorted(extracted_data["subdomains"])[:20])
                context_header.append(f"DISCOVERED SUBDOMAINS: {subs_list}")
                context_critical.append(f"SUBDOMAINS: {subs_list}")

            if extracted_data["urls"]:
                urls_str = ", ".join(sorted(extracted_data["urls"])[:15])
                context_header.append(f"DISCOVERED URLs: {urls_str}")
                context_critical.append(f"URLS: {urls_str}")

            if extracted_data["ports"]:
                ports_str = ", ".join(sorted(extracted_data["ports"])[:10])
                context_header.append(f"OPEN PORTS: {ports_str}")
                context_critical.append(f"PORTS: {ports_str}")

            if extracted_data["vulns"]:
                vulns_str = ", ".join(sorted(extracted_data["vulns"])[:10])
                context_header.append(f"VULNERABILITIES FOUND: {vulns_str}")
                context_critical.append(f"VULNS: {vulns_str}")

            if extracted_data["injection_types"]:
                inj_str = ", ".join(sorted(extracted_data["injection_types"])[:5])
                context_header.append(f"INJECTION TYPES: {inj_str}")
                context_critical.append(f"INJECTIONS: {inj_str}")

            if extracted_data["credentials"]:
                creds_str = ", ".join(sorted(extracted_data["credentials"])[:3])
                context_header.append(f"CREDENTIALS FOUND: {creds_str}")
                context_critical.append(f"CREDENTIALS: {creds_str}")

            if extracted_data["tools_used"]:
                tools_str = ", ".join(sorted(extracted_data["tools_used"])[:8])
                context_critical.append(f"TOOLS: {tools_str}")

            phase_context = ""
            if phase == "EXPLOIT":
                phase_context = "\nEXPLICIT INSTRUCTION: This is EXPLOIT phase. Prioritize vulnerability PoCs, exploit chains, and flag retrieval. Do not lose evidence of working exploits."
            elif phase == "ANALYSIS":
                phase_context = "\nEXPLICIT INSTRUCTION: This is ANALYSIS phase. Focus on correlation, evidence linking, and strategic planning."
            elif phase == "RECON":
                phase_context = "\nEXPLICIT INSTRUCTION: This is RECON phase. Focus on discovery, enumeration, and mapping attack surface."

            context_str = (
                "\n".join(context_header)
                if context_header
                else "No critical data extracted."
            )

            recent_failures = (
                sum(self._compress_failures[-10:]) if self._compress_failures else 0
            )
            if recent_failures >= 3:
                logger.warning(
                    "LLM compression circuit breaker tripped (%d/10 failures) — using fallback",
                    recent_failures,
                )
                if len(chunk) > 5:
                    summaries.extend(chunk[-5:])
                else:
                    summaries.extend(chunk)
                continue

            try:
                _start = asyncio.get_running_loop().time()

                compression_prompt = [
                    {
                        "role": "system",
                        "content": (
                            "You are a memory compressor for an AI security testing agent.\n"
                            f"CURRENT PHASE: {phase}{phase_context}\n\n"
                            "TASK: Summarize the conversation into 2-4 DENSE technical sentences.\n\n"
                            "RULES:\n"
                            "0. PRESERVE previous summary, failures, and open work items if they still matter\n"
                            "1. PRESERVE ALL items in CRITICAL DATA section (exact IPs, ports, URLs)\n"
                            "2. For EXPLOIT phase: Keep vulnerability Proof-of-Concepts and exploitation steps\n"
                            "3. For RECON phase: Keep discovery chain and enumeration results\n"
                            "4. NEVER lose CVE IDs, severity ratings, or flag patterns\n"
                            "5. Convert tool outputs to actionable findings\n"
                            "6. EXPLICITLY remember what was already tried, what failed, and what remains pending\n\n"
                            "FORMAT: Technical, specific, no fluff. Example:\n"
                            "'Discovered api.example.com (80, 443), admin.example.com (80). "
                            "SQLi at /login?id=1 (CVE-2024-1234, HIGH). "
                            "Credentials: admin:password123. Prior ffuf on /admin failed due to auth; next verify with member vs owner role.'\n\n"
                            "DO NOT: Add greetings, explanations, or generic statements.\n"
                            "DO: Use abbreviations (sub=domain, url=path, port=80) to save tokens"
                        ),
                    },
                    {
                        "role": "user",
                        "content": (
                            f"CRITICAL DATA TO PRESERVE:\n{context_str}\n\n"
                            + (
                                f"WORKING MEMORY TO CARRY FORWARD:\n{carry_forward_context}\n\n"
                                if carry_forward_context
                                else ""
                            )
                            + f"CONVERSATION TO COMPRESS:\n{chunk_text}"
                        ),
                    },
                ]

                # Model-agnostic compression cap: scale from the configured
                # gateway timeout (slow models/gateways get more headroom),
                # bounded to a sane 20–45s band. No model-name hardcoding —
                # llm.complete already applies its own per-op dynamic timeout.
                try:
                    _cfg_timeout = float(getattr(get_config(), "llm_timeout", 120.0) or 120.0)
                except (TypeError, ValueError):
                    _cfg_timeout = 120.0
                _timeout = max(20.0, min(45.0, _cfg_timeout * 0.25))
                summary_text = await asyncio.wait_for(
                    llm.complete(
                        messages=compression_prompt,
                        options={
                            "num_ctx": num_ctx,
                            "num_predict": 256,
                            "temperature": 0.05,
                        },
                        max_retries=1,
                        operation="compression",
                    ),
                    timeout=_timeout,
                )
                _elapsed = asyncio.get_running_loop().time() - _start

                summary_lower = summary_text.lower()
                missing_critical = []

                if extracted_data["subdomains"]:
                    for subdomain in list(extracted_data["subdomains"])[:3]:
                        sub_short = subdomain.split(".")[0]
                        if sub_short and sub_short not in summary_lower:
                            missing_critical.append(subdomain)

                if extracted_data["vulns"]:
                    for vuln in list(extracted_data["vulns"])[:2]:
                        if vuln.lower().split()[0] not in summary_lower:
                            missing_critical.append(vuln)

                if not summary_text.strip() or len(summary_text.strip()) < 30:
                    logger.warning(
                        "LLM compression returned too short response (%d chars) — using extraction fallback",
                        len(summary_text.strip()) if summary_text else 0,
                    )
                    raise ValueError("Empty summary from LLM")

                self._compress_failures.append(False)
                if len(self._compress_failures) > 20:
                    self._compress_failures.pop(0)

                final_summary = summary_text.strip()

                if missing_critical:
                    missing_str = f" [MISSING:{', '.join(missing_critical)}]"
                    final_summary += missing_str
                    logger.info(
                        "Compression post-process: appended %d missing critical items",
                        len(missing_critical),
                    )

                phase_marker = f"[{phase}_COMP]" if phase else "[COMP]"
                final_summary = f"{phase_marker} {final_summary}"
                self.compression_summary = final_summary[:2000]

                summaries.append(
                    {
                        "role": "system",
                        "content": f"[COMPRESSED MEMORY]: {final_summary}",
                    }
                )
                logger.info(
                    "LLM compression (%s): %d messages → summary in %.1fs (%d chars)",
                    phase,
                    len(chunk),
                    _elapsed,
                    len(final_summary),
                )

            except asyncio.TimeoutError:
                logger.warning(
                    "LLM compression timeout (%ds) — using extraction fallback",
                    _timeout,
                )
                self._compress_failures.append(True)

                if context_header:
                    fallback_summary = f"[{phase}_SUMMARY]: " + "; ".join(context_header)
                    self.compression_summary = fallback_summary[:2000]
                    summaries.append(
                        {
                            "role": "system",
                            "content": fallback_summary,
                        }
                    )
                elif len(chunk) > 5:
                    summaries.extend(chunk[-5:])
                else:
                    summaries.extend(chunk)

            except Exception as e:
                logger.warning(
                    "LLM compression failed: %s — using extraction fallback",
                    str(e)[:100],
                )
                self._compress_failures.append(True)

                if context_header:
                    fallback_summary = f"[{phase}_SUMMARY]: " + "; ".join(context_header)
                    self.compression_summary = fallback_summary[:2000]
                    summaries.append(
                        {
                            "role": "system",
                            "content": fallback_summary,
                        }
                    )
                elif len(chunk) > 5:
                    summaries.extend(chunk[-5:])
                else:
                    summaries.extend(chunk)

        before = len(self.conversation)
        self.conversation = system_msgs + [first_user] + summaries + keep_tail
        logger.info(
            "Memory compressed (%s): %d messages → %d summaries (%d → %d total)",
            phase,
            len(to_compress),
            len(summaries),
            before,
            len(self.conversation),
        )

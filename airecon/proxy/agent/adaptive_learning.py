from __future__ import annotations


import asyncio
import concurrent.futures
import hashlib
import json
import logging
import sqlite3
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from ..memory import (
    MemoryManager,
    _init_schema,
    configure_sqlite_connection,
    get_sqlite_timeout_seconds,
    rollup_tool_usage_rows,
)

logger = logging.getLogger("airecon.agent.adaptive_learning")

_LEARNING_DIR = Path.home() / ".airecon" / "learning"
_MEMORY_DB = Path.home() / ".airecon" / "memory" / "airecon.db"
_TOOLS_META = Path(__file__).resolve().parents[1] / "data" / "tools_meta.json"
_TOOLS_JSON = Path(__file__).resolve().parents[1] / "data" / "tools.json"


def _load_tools_meta() -> dict[str, Any]:
    """Load tool metadata from data/tools_meta.json (cached at module level)."""
    try:
        return json.loads(_TOOLS_META.read_text(encoding="utf-8"))
    except Exception as exc:
        logger.warning("tools_meta.json unavailable (%s)", exc)
        return {}


def _load_tool_definitions() -> list[dict[str, Any]]:
    """Load callable tool definitions from data/tools.json."""
    try:
        data = json.loads(_TOOLS_JSON.read_text(encoding="utf-8"))
    except Exception as exc:
        logger.warning("tools.json unavailable (%s)", exc)
        return []
    return data if isinstance(data, list) else []


def _open_memory_db(read_only: bool) -> sqlite3.Connection:
    timeout = get_sqlite_timeout_seconds()
    if read_only:
        conn = sqlite3.connect(
            f"file:{_MEMORY_DB}?mode=ro",
            uri=True,
            timeout=timeout,
        )
    else:
        _MEMORY_DB.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(_MEMORY_DB), timeout=timeout)
    configure_sqlite_connection(conn)
    conn.row_factory = sqlite3.Row
    return conn


@dataclass
class ToolPerformance:

    tool_name: str
    total_uses: int = 0
    successes: int = 0
    failures: int = 0
    avg_duration: float = 0.0
    avg_confidence: float = 0.0
    last_used: float = 0.0
    success_streak: int = 0
    failure_streak: int = 0
    context_scores: dict[str, float] = field(default_factory=dict)
    target_type_scores: dict[str, float] = field(default_factory=dict)

    @property
    def success_rate(self) -> float:
        if self.total_uses == 0:
            return 0.5
        return self.successes / self.total_uses

    @property
    def effectiveness_score(self) -> float:
        if self.total_uses < 2:
            return 0.5

        score = self.success_rate

        age_hours = (time.time() - self.last_used) / 3600
        recency_bonus = max(0.5, 1.0 - (age_hours / 168))  # Decay over 1 week
        score *= recency_bonus

        if self.success_streak >= 3:
            score *= 1.0 + (self.success_streak * 0.05)
        elif self.failure_streak >= 3:
            score *= max(0.1, 1.0 - (self.failure_streak * 0.15))

        return min(1.0, max(0.0, score))


@dataclass
class StrategyPattern:

    pattern_id: str
    description: str
    conditions: dict[str, Any]  # e.g., {"tech": "nginx", "phase": "EXPLOIT"}
    tool_sequence: list[str]  # e.g., ["nmap", "httpx", "nuclei"]
    success_count: int = 0
    failure_count: int = 0
    avg_result_confidence: float = 0.0
    last_applied: float = 0.0

    @property
    def reliability(self) -> float:
        total = self.success_count + self.failure_count
        if total == 0:
            return 0.5
        return self.success_count / total


@dataclass
class LearnedInsight:


    insight_id: str
    category: str  # "tool_tech", "vuln_pattern", "exploit_chain", "doc_pattern"
    title: str  # e.g. "sqlmap reliably finds SQLi on Express/MySQL"
    description: str  # human-readable summary
    conditions: dict[str, Any]  # when this insight applies
    recommendation: str  # what to do when conditions match
    confidence: float  # 0-1, based on supporting observations
    observation_count: int = 0
    created_at: float = 0.0
    last_updated: float = 0.0
    session_ids: list[str] = field(default_factory=list)


@dataclass
class ObservationLog:
    """A single raw observation stored for later LLM abstraction."""

    timestamp: float
    tool_name: str
    arguments: dict[str, Any]
    result_summary: str  # compressed result for learning
    success: bool
    confidence: float
    phase: str
    target_type: str  # e.g. "nginx/php" or "express/nodejs"
    vuln_found: str | None = None  # if vulnerability was discovered


class AdaptiveLearningEngine:

    def __init__(
        self,
        min_observations: int = 3,
        decay_factor: float = 0.95,
        session_id: str = "",
    ):
        self.min_observations = min_observations
        self.decay_factor = decay_factor
        self.session_id = session_id or f"session_{int(time.time())}"
        self.tool_performances: dict[str, ToolPerformance] = {}
        self.strategy_patterns: list[StrategyPattern] = []
        self.negative_patterns: dict[str, list[str]] = {}
        self.learned_insights: list[LearnedInsight] = []
        self.observation_log: list[ObservationLog] = []

        # Load persistent state from disk + airencon.db
        self._load_state()
        self._import_from_memory_db()
        self._bootstrap_insights_from_patterns()

    # ── Persistence ──────────────────────────────────────────────────────────

    def _load_state(self) -> None:
        """Load learned state from disk. Non-blocking — silent on failure."""
        try:
            state_path = self._state_file
            if not state_path.exists():
                return
            data = json.loads(state_path.read_text(encoding="utf-8"))

            for name, pdict in data.get("tool_performances", {}).items():
                self.tool_performances[name] = ToolPerformance(**pdict)

            for pdict in data.get("strategy_patterns", []):
                self.strategy_patterns.append(StrategyPattern(**pdict))

            self.negative_patterns = data.get("negative_patterns", {})

            for idict in data.get("learned_insights", []):
                self.learned_insights.append(LearnedInsight(**idict))

            for odict in data.get("observation_log", [])[-500:]:
                self.observation_log.append(ObservationLog(**odict))

            logger.info(
                "[AdaptiveLearning] Loaded persistent state: %d tools, %d strategies,"
                " %d insights, %d observations",
                len(self.tool_performances),
                len(self.strategy_patterns),
                len(self.learned_insights),
                len(self.observation_log),
            )
        except Exception as exc:
            logger.debug("Failed to load learning state: %s", exc)

    def _import_from_memory_db(self) -> None:
        """Import existing tool_usage and patterns from ~/.airecon/memory/airecon.db.

        This bridges the gap between the old SQLite-based memory system and
        the new JSON-based persistent learning system so airecon doesn't
        start from zero — it inherits all past session data.
        """
        if not _MEMORY_DB.exists():
            return

        try:
            conn = _open_memory_db(read_only=True)
            cur = conn.cursor()

            cur.execute(
                """
                SELECT tool_name, target, success_count, failure_count,
                       avg_duration_sec, typical_output_size, last_used
                FROM tool_usage
                """
            )
            for row in rollup_tool_usage_rows(cur.fetchall()):
                name = row["tool_name"]
                total = (row["success_count"] or 0) + (row["failure_count"] or 0)
                if name not in self.tool_performances:
                    self.tool_performances[name] = ToolPerformance(
                        tool_name=name,
                        total_uses=total,
                        successes=row["success_count"] or 0,
                        failures=row["failure_count"] or 0,
                        avg_duration=row["avg_duration_sec"] or 0.0,
                        last_used=time.time(),
                    )
                    logger.debug(
                        "[AdaptiveLearning] Imported tool_usage: %s (success=%d, fail=%d)",
                        name, row["success_count"], row["failure_count"],
                    )

            cur.execute("SELECT * FROM patterns")
            for row in cur.fetchall():
                conditions: dict[str, Any] = {}
                if row["target_tech"]:
                    conditions["tech"] = str(row["target_tech"]).strip().lower()
                conditions["phase"] = str(row["pattern_type"]).strip().upper()

                technique = str(row["technique_name"])
                pattern_id = self._make_pattern_id(conditions, [technique])
                commands = []
                try:
                    cmds = json.loads(row["commands_used"] or "[]")
                    commands = [str(c) for c in cmds]
                except (json.JSONDecodeError, TypeError):
                    commands = [technique]

                existing = any(p.pattern_id == pattern_id for p in self.strategy_patterns)
                if not existing:
                    desc = row["description"] or f"When [{row['pattern_type']}] → use [{technique}]"
                    times_used = row["times_used"] or 0
                    times_succ = row["times_successful"] or 0
                    eff_score = row["effectiveness_score"] or 0
                    self.strategy_patterns.append(StrategyPattern(
                        pattern_id=pattern_id,
                        description=desc,
                        conditions=conditions,
                        tool_sequence=commands or [technique],
                        success_count=times_succ,
                        failure_count=times_used - times_succ,
                        avg_result_confidence=eff_score / 100,
                    ))
                    logger.debug(
                        "[AdaptiveLearning] Imported pattern: %s (tech=%s, used=%d, success=%d)",
                        technique, row["target_tech"], row["times_used"], row["times_successful"],
                    )

            conn.close()
            logger.info(
                "[AdaptiveLearning] Imported from airencon.db: %d tools, %d patterns",
                len(self.tool_performances),
                len(self.strategy_patterns),
            )
        except Exception as exc:
            logger.debug("Failed to import from memory DB: %s", exc)

    def save_state(self) -> None:
        """Persist learned state to disk."""
        try:
            self._state_dir.mkdir(parents=True, exist_ok=True)
            data = {
                "tool_performances": {
                    name: asdict(p)
                    for name, p in self.tool_performances.items()
                },
                "strategy_patterns": [asdict(p) for p in self.strategy_patterns],
                "negative_patterns": dict(self.negative_patterns),
                "learned_insights": [asdict(i) for i in self.learned_insights],
                "observation_log": [
                    {
                        "timestamp": o.timestamp,
                        "tool_name": o.tool_name,
                        "arguments": o.arguments,
                        "result_summary": o.result_summary,
                        "success": o.success,
                        "confidence": o.confidence,
                        "phase": o.phase,
                        "target_type": o.target_type,
                        "vuln_found": o.vuln_found,
                    }
                    for o in self.observation_log[-500:]
                ],
            }
            tmp_path = self._state_file.with_suffix(".tmp")
            tmp_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
            tmp_path.rename(self._state_file)
            logger.debug(
                "[AdaptiveLearning] Saved state: %d tools, %d strategies, %d insights",
                len(self.tool_performances),
                len(self.strategy_patterns),
                len(self.learned_insights),
            )
        except Exception as exc:
            logger.debug("Failed to save learning state: %s", exc)
        finally:
            self._sync_to_memory_db()

    def _normalize_conditions(self, conditions: dict[str, Any] | None) -> dict[str, Any]:
        normalized: dict[str, Any] = {}
        for key, value in (conditions or {}).items():
            key_name = str(key or "").strip().lower()
            if not key_name:
                continue
            normalized[key_name] = self._normalize_condition_value(key_name, value)
        return normalized

    def _store_learned_insight(
        self,
        insight: LearnedInsight,
    ) -> tuple[LearnedInsight, bool]:
        for existing in self.learned_insights:
            if existing.insight_id != insight.insight_id:
                continue
            existing.title = insight.title or existing.title
            existing.description = insight.description or existing.description
            existing.recommendation = insight.recommendation or existing.recommendation
            existing.category = insight.category or existing.category
            existing.conditions.update(insight.conditions or {})
            existing.confidence = max(existing.confidence, insight.confidence)
            existing.observation_count = max(
                existing.observation_count,
                insight.observation_count,
            )
            existing.last_updated = max(existing.last_updated, insight.last_updated)
            existing.session_ids = sorted(
                {
                    str(session_id)
                    for session_id in [*existing.session_ids, *insight.session_ids]
                    if str(session_id).strip()
                }
            )
            return existing, False

        self.learned_insights.append(insight)
        return insight, True

    def _knowledge_category_for_insight(self, insight: LearnedInsight) -> str:
        phase = str(insight.conditions.get("phase") or "").strip().upper()
        if phase == "RECON":
            return "reconnaissance"
        if phase == "ANALYSIS":
            return "analysis"
        if phase == "EXPLOIT":
            return "exploitation"
        if phase == "REPORT":
            return "reporting"

        category_map = {
            "tool_tech": "reconnaissance",
            "vuln_pattern": "analysis",
            "exploit_chain": "exploitation",
            "doc_pattern": "reporting",
        }
        return category_map.get(str(insight.category or "").strip().lower(), "general")

    def _knowledge_payload_for_insight(
        self,
        insight: LearnedInsight,
    ) -> dict[str, Any]:
        tags = [
            "adaptive_learning",
            "distilled_insight",
            f"insight:{str(insight.category or 'unknown').strip().lower()}",
        ]
        for key, value in sorted((insight.conditions or {}).items()):
            if value in ("", None):
                continue
            tags.append(f"{str(key).strip().lower()}:{str(value).strip().lower()}")

        return {
            "category": self._knowledge_category_for_insight(insight),
            "title": insight.title,
            "content": insight.recommendation or insight.description or insight.title,
            "confidence": max(0.0, min(float(insight.confidence or 0.0), 1.0)),
            "source_session": self.session_id,
            "tags": tags,
        }

    def _persist_insights_to_memory_db(self, insights: list[LearnedInsight]) -> None:
        if not insights:
            return

        try:
            conn = _open_memory_db(read_only=False)
            _init_schema(conn)
            memory = MemoryManager()
            memory.conn = conn
            try:
                for insight in insights:
                    memory.save_knowledge(self._knowledge_payload_for_insight(insight))
            finally:
                conn.close()
        except Exception as exc:
            logger.debug(
                "Failed to persist distilled insights to memory DB: %s",
                exc,
            )

    def _sync_to_memory_db(self) -> None:
        """Sync learned tool performance back to ~/.airecon/memory/airecon.db."""
        if not _MEMORY_DB.exists():
            return
        try:
            conn = _open_memory_db(read_only=False)
            cur = conn.cursor()
            now = time.strftime("%Y-%m-%d %H:%M:%S")
            for name, perf in self.tool_performances.items():
                cur.execute(
                    """
                    SELECT id, tool_name, target, success_count, failure_count,
                           avg_duration_sec, typical_output_size, last_used
                    FROM tool_usage WHERE tool_name = ?
                    """,
                    (name,),
                )
                existing_rows = cur.fetchall()
                rolled = rollup_tool_usage_rows(existing_rows)
                current_total = rolled[0]["total_calls"] if rolled else 0

                global_rows = [
                    row for row in existing_rows if not str(row["target"] or "").strip()
                ]
                primary_global = (
                    min(global_rows, key=lambda row: int(row["id"]))
                    if global_rows
                    else None
                )
                best_global = (
                    max(
                        global_rows,
                        key=lambda row: (
                            int(row["success_count"] or 0) + int(row["failure_count"] or 0),
                            str(row["last_used"] or ""),
                            int(row["id"]),
                        ),
                    )
                    if global_rows
                    else None
                )

                if primary_global and best_global:
                    best_total = int(best_global["success_count"] or 0) + int(
                        best_global["failure_count"] or 0
                    )
                    if perf.total_uses > best_total:
                        success_count = perf.successes
                        failure_count = perf.failures
                        avg_duration = perf.avg_duration
                    else:
                        success_count = int(best_global["success_count"] or 0)
                        failure_count = int(best_global["failure_count"] or 0)
                        avg_duration = float(best_global["avg_duration_sec"] or 0.0)

                    if (
                        primary_global["id"] != best_global["id"]
                        or len(global_rows) > 1
                        or perf.total_uses > best_total
                    ):
                        cur.execute(
                            """
                            UPDATE tool_usage SET
                                success_count = ?, failure_count = ?, avg_duration_sec = ?,
                                typical_output_size = ?, last_used = ?
                            WHERE id = ?
                            """,
                            (
                                success_count,
                                failure_count,
                                avg_duration,
                                0,
                                now,
                                int(primary_global["id"]),
                            ),
                        )
                    extras = [
                        (int(row["id"]),)
                        for row in global_rows
                        if int(row["id"]) != int(primary_global["id"])
                    ]
                    if extras:
                        cur.executemany("DELETE FROM tool_usage WHERE id = ?", extras)
                    continue

                # Only create or refresh a global aggregate row when in-memory has
                # strictly more evidence than the rolled-up SQLite view.
                if perf.total_uses <= current_total:
                    continue

                if primary_global:
                    cur.execute(
                        """
                        UPDATE tool_usage SET
                            success_count = ?, failure_count = ?, avg_duration_sec = ?,
                            typical_output_size = ?, last_used = ?
                        WHERE id = ?
                        """,
                        (
                            perf.successes,
                            perf.failures,
                            perf.avg_duration,
                            0,
                            now,
                            int(primary_global["id"]),
                        ),
                    )
                else:
                    cur.execute(
                        """
                        INSERT INTO tool_usage
                        (tool_name, target, success_count, failure_count, avg_duration_sec, last_used, typical_output_size)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            name,
                            "",
                            perf.successes,
                            perf.failures,
                            perf.avg_duration,
                            now,
                            0,
                        ),
                    )
            conn.commit()
            conn.close()
            logger.debug("[AdaptiveLearning] Synced tool_performances to airencon.db")
        except Exception as exc:
            logger.debug("Failed to sync to memory DB: %s", exc)

    @property
    def _state_dir(self) -> Path:
        return _LEARNING_DIR / self.session_id.rsplit("_", 1)[0] if "_" in self.session_id else _LEARNING_DIR

    @property
    def _state_file(self) -> Path:
        return _LEARNING_DIR / "global_learning.json"

    # ── Bootstrap ────────────────────────────────────────────────────────────

    def _bootstrap_insights_from_patterns(self) -> None:
        """Convert imported StrategyPatterns into LearnedInsights immediately.

        This ensures the agent has actionable intelligence from session 1
        instead of waiting for 30+ observations + LLM distillation.
        """
        now = time.time()
        type_to_category = {
            "RECON": "tool_tech",
            "EXPLOIT": "vuln_pattern",
            "PRIVESC": "exploit_chain",
            "REPORTING": "doc_pattern",
            "EXFILTRATE": "vuln_pattern",
            "FOOTPRINT": "tool_tech",
        }

        # Dedup insights that were previously bootstrapped
        bootstrapped_ids = {
            i.insight_id.removeprefix("bootstrap_")
            for i in self.learned_insights
            if i.insight_id.startswith("bootstrap_")
        }

        # Aggregate raw commands per tool to find common purposes
        tool_usage: dict[str, dict] = {}
        for perf in self.tool_performances.values():
            if perf.total_uses >= 5 and perf.success_rate >= 0.5:
                tool_usage[perf.tool_name] = {
                    "total_uses": perf.total_uses,
                    "success_rate": perf.success_rate,
                    "effectiveness": perf.effectiveness_score,
                }

        for pat in self.strategy_patterns:
            if pat.pattern_id in bootstrapped_ids:
                continue

            total = pat.success_count + pat.failure_count
            if total == 0:
                continue

            # Extract clean tool name from raw command
            raw_cmd = pat.tool_sequence[0] if pat.tool_sequence else ""
            tool_name = _extract_tool_name(raw_cmd)
            if not tool_name:
                continue

            # Build human-readable description of what the tool does
            purpose = _infer_tool_purpose(tool_name, pat.conditions)

            category = type_to_category.get(
                pat.conditions.get("phase", ""),
                "tool_tech",
            )

            phase = pat.conditions.get("phase", "unknown")

            key = f"{tool_name}:{phase}"
            existing_keys = {
                f"{_extract_tool_name(i.title)}:{i.conditions.get('phase', '')}"
                for i in self.learned_insights
            }
            if key in existing_keys:
                continue

            conf = pat.reliability
            if total < 10:
                conf = min(conf, 0.6 + (total / 100))

            insight = LearnedInsight(
                insight_id=f"bootstrap_{pat.pattern_id}",
                category=category,
                title=f"{tool_name} for {phase.lower()} — {purpose}",
                description=purpose,
                conditions=pat.conditions,
                recommendation=(
                    f"Use {tool_name} during {phase.lower()} phase. "
                    f"Used {total}× historically with {pat.reliability:.0%} success rate. "
                    f"Reliable choice for {phase.lower()}; "
                    f"pair with recommended tools for this phase."
                ),
                confidence=conf,
                observation_count=total,
                created_at=now,
                last_updated=now,
                session_ids=["bootstrap"],
            )
            self.learned_insights.append(insight)
            logger.info(
                "[AdaptiveLearning] Bootstrap insight: %s (confidence=%.2f, obs=%d)",
                insight.title,
                insight.confidence,
                insight.observation_count,
            )

        bootstrapped_tools = {
            _extract_tool_name(i.title)
            for i in self.learned_insights
            if i.insight_id.startswith("bootstrap_")
        }
        for pname, pdata in tool_usage.items():
            if pname in bootstrapped_tools:
                continue

            phase = _infer_phase_from_tool(pname)
            purpose = _infer_tool_purpose(pname, {"phase": phase})

            insight = LearnedInsight(
                insight_id=f"bootstrap_tool_{pname}",
                category="tool_tech",
                title=f"{pname} for {phase.lower()} — {purpose}",
                description=purpose,
                conditions={"phase": phase},
                recommendation=(
                    f"Use {pname} during {phase.lower()} phase. "
                    f"Historical: {pdata['total_uses']} executions, "
                    f"{pdata['success_rate']:.0%} success rate, "
                    f"{pdata['effectiveness']:.2f} effectiveness score."
                ),
                confidence=min(pdata["effectiveness"], 0.95),
                observation_count=pdata["total_uses"],
                created_at=now,
                last_updated=now,
                session_ids=["bootstrap"],
            )
            self.learned_insights.append(insight)
            logger.info(
                "[AdaptiveLearning] Bootstrap tool insight: %s (confidence=%.2f, obs=%d)",
                insight.title,
                insight.confidence,
                insight.observation_count,
            )

        if self.learned_insights:
            logger.info(
                "[AdaptiveLearning] Bootstrapped %d insights from historical patterns",
                len(self.learned_insights),
            )

    # ── Recording ────────────────────────────────────────────────────────────

    def record_tool_result(
        self,
        tool_name: str,
        arguments: dict,
        result: dict,
        success: bool,
        duration: float,
        confidence: float = 0.0,
        context: dict | None = None,
        target_type: str = "",
    ) -> None:
        """Record a tool execution result for learning."""
        if tool_name not in self.tool_performances:
            self.tool_performances[tool_name] = ToolPerformance(tool_name=tool_name)

        perf = self.tool_performances[tool_name]
        perf.total_uses += 1
        perf.last_used = time.time()

        if success:
            perf.successes += 1
            perf.success_streak += 1
            perf.failure_streak = 0
        else:
            perf.failures += 1
            perf.failure_streak += 1
            perf.success_streak = 0

        alpha = 0.3
        perf.avg_duration = (alpha * duration) + ((1 - alpha) * perf.avg_duration)
        perf.avg_confidence = (alpha * confidence) + ((1 - alpha) * perf.avg_confidence)

        if context:
            for key, value in context.items():
                ctx_key = f"{key}={value}"
                if ctx_key not in perf.context_scores:
                    perf.context_scores[ctx_key] = confidence
                else:
                    old = perf.context_scores[ctx_key]
                    perf.context_scores[ctx_key] = (alpha * confidence) + (
                        (1 - alpha) * old
                    )

        if target_type:
            if target_type not in perf.target_type_scores:
                perf.target_type_scores[target_type] = confidence
            else:
                old = perf.target_type_scores[target_type]
                perf.target_type_scores[target_type] = (alpha * confidence) + (
                    (1 - alpha) * old
                )

        if perf.failure_streak >= self.min_observations:
            if tool_name not in self.negative_patterns:
                self.negative_patterns[tool_name] = []
            reason = f"Failed {perf.failure_streak} times consecutively"
            if reason not in self.negative_patterns[tool_name]:
                self.negative_patterns[tool_name].append(reason)
                logger.warning(
                    "[AdaptiveLearning] Tool=%s flagged for AVOIDANCE: %s (effectiveness=%.2f)",
                    tool_name,
                    reason,
                    perf.effectiveness_score,
                )

    def record_observation(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        result_summary: str,
        success: bool,
        confidence: float,
        phase: str,
        target_type: str,
        vuln_found: str | None = None,
    ) -> None:
        """Log a raw observation for later abstraction / LLM distillation.

        These are compressed summaries — not full outputs — to keep memory light.
        """
        obs = ObservationLog(
            timestamp=time.time(),
            tool_name=tool_name,
            arguments={k: str(v)[:200] for k, v in arguments.items()},
            result_summary=result_summary[:500],
            success=success,
            confidence=confidence,
            phase=phase,
            target_type=target_type,
            vuln_found=vuln_found,
        )
        self.observation_log.append(obs)

        if len(self.observation_log) > 1000:
            self.observation_log = self.observation_log[-800:]

    def record_strategy_result(
        self,
        conditions: dict[str, Any],
        tool_sequence: list[str],
        success: bool,
        confidence: float = 0.0,
    ) -> None:
        """Record a strategy pattern result."""
        pattern_id = self._make_pattern_id(conditions, tool_sequence)

        existing = None
        for p in self.strategy_patterns:
            if p.pattern_id == pattern_id:
                existing = p
                break

        if existing is None:
            existing = StrategyPattern(
                pattern_id=pattern_id,
                description=self._describe_pattern(conditions, tool_sequence),
                conditions=conditions,
                tool_sequence=tool_sequence,
            )
            self.strategy_patterns.append(existing)

        if success:
            existing.success_count += 1
        else:
            existing.failure_count += 1

        alpha = 0.3
        existing.avg_result_confidence = (alpha * confidence) + (
            (1 - alpha) * existing.avg_result_confidence
        )
        existing.last_applied = time.time()

    # ── Abstraction (LLM-assisted distillation) ──────────────────────────────

    def distill_insights(
        self, base_url: str = "", model: str = "", api_key: str = ""
    ) -> list[LearnedInsight]:
        """Ask the LLM to abstract patterns from recent observations.

        Returns newly created insights (not the full catalog).
        This is how airecon 'learns' — raw data → generalized rules via LLM.
        Routed through the OpenAI-compatible gateway (LiteLLM/vLLM/hosted).
        """
        if not base_url or not model:
            logger.debug("distill_insights: no LLM config, skipping")
            return []

        # Only distill if we have enough new observations
        new_obs = [
            o for o in self.observation_log
            if o.success and len(self.observation_log) >= self.min_observations * 3
        ]
        if not new_obs:
            return []

        obs_text = "\n".join(
            f"- phase={o.phase}, tool={o.tool_name}, target={o.target_type}, "
            f"vuln={o.vuln_found or 'none'}, result={'success' if o.success else 'fail'}"
            for o in new_obs[-50:]  # send last 50 max
        )

        prompt = (
            "You are a security research analyst. Below are recent observations "
            "from an automated penetration testing session.\n\n"
            f"Observations:\n{obs_text}\n\n"
            "Identify patterns and generate up to 3 generalized insights.\n"
            "Each insight should have:\n"
            "- category: one of [tool_tech, vuln_pattern, exploit_chain, doc_pattern]\n"
            "- title: short description of the pattern\n"
            "- conditions: JSON object of when this applies (e.g., {\"tech\": \"nginx\"})\n"
            "- recommendation: what action to take when conditions match\n"
            "Respond ONLY with a JSON array of insight objects.\n"
            "Each object must have: category, title, conditions, recommendation.\n"
            "Example: [{\"category\": \"vuln_pattern\", \"title\": \"nginx exposes server version\", "
            "\"conditions\": {\"tech\": \"nginx\"}, \"recommendation\": \"Check Server header for version leak\"}]"
        )

        try:
            async def _call():
                # Route through LLMClient so distillation reuses the shared
                # retry/5xx-handling, reasoning-capability detection, and timeout
                # plumbing instead of a bespoke aiohttp call.
                from ..llm import LLMClient

                client = LLMClient(base_url=base_url, model=model)
                await client._async_init()
                answer = await client.complete(
                    [{"role": "user", "content": prompt}],
                    max_retries=1,
                    options={"temperature": 0.1, "num_predict": 1024},
                    operation="compression",
                )
                return (answer or "").strip()

            try:
                asyncio.get_running_loop()
            except RuntimeError:
                raw_answer = asyncio.run(_call())
            else:
                with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                    raw_answer = executor.submit(lambda: asyncio.run(_call())).result(
                        timeout=125
                    )

            new_insights = _parse_insights_json(raw_answer)
            added: list[LearnedInsight] = []
            for ins in new_insights:
                conditions = self._normalize_conditions(ins.get("conditions", {}))
                now = time.time()
                insight = LearnedInsight(
                    insight_id=self._make_pattern_id(
                        conditions,
                        [ins.get("title", "")],
                    ),
                    category=ins.get("category", "unknown"),
                    title=ins.get("title", ""),
                    description=ins.get("recommendation", ""),
                    conditions=conditions,
                    recommendation=ins.get("recommendation", ""),
                    confidence=0.6,
                    observation_count=len(new_obs),
                    created_at=now,
                    last_updated=now,
                    session_ids=[self.session_id],
                )
                stored, created = self._store_learned_insight(insight)
                if not created:
                    continue
                added.append(stored)
                logger.info(
                    "[AdaptiveLearning] New insight distilled: %s",
                    stored.title,
                )
            self._persist_insights_to_memory_db(added)
            return added

        except Exception as exc:
            logger.debug("LLM insight distillation failed: %s", exc)
            return []

    # ── Querying ─────────────────────────────────────────────────────────────

    def recommend_tools(
        self,
        phase: str = "",
        tech_stack: list[str] | None = None,
        target_type: str = "",
        exclude: list[str] | None = None,
        top_n: int = 5,
    ) -> list[tuple[str, float]]:
        """Recommend top N tools based on learned performance."""
        exclude = exclude or []
        scored: list[tuple[str, float]] = []

        for name, perf in self.tool_performances.items():
            if name in exclude:
                continue
            if perf.total_uses < self.min_observations:
                continue
            if perf.failure_streak >= 5:
                continue

            score = perf.effectiveness_score

            if phase:
                phase_key = f"phase={str(phase).strip().upper()}"
                if phase_key in perf.context_scores:
                    score = (score * 0.7) + (perf.context_scores[phase_key] * 0.3)

            if tech_stack:
                for tech in tech_stack:
                    tech_key = f"tech={str(tech).strip().lower()}"
                    if (
                        tech_key in perf.context_scores
                        or f"{tech_key}=detected" in perf.context_scores
                    ):
                        score = min(1.0, score + 0.1)

            if target_type and target_type in perf.target_type_scores:
                score = min(1.0, score + 0.05)

            scored.append((name, round(score, 3)))

        scored.sort(key=lambda x: x[1], reverse=True)
        return scored[:top_n]

    def recommend_strategy(
        self,
        conditions: dict[str, Any],
        min_reliability: float = 0.6,
    ) -> StrategyPattern | None:
        best: StrategyPattern | None = None
        best_score = 0.0
        normalized_conditions = {
            str(key).strip().lower(): self._normalize_condition_value(key, value)
            for key, value in conditions.items()
            if str(key).strip()
        }

        for pattern in self.strategy_patterns:
            if pattern.reliability < min_reliability:
                continue
            normalized_pattern_conditions = {
                str(key).strip().lower(): self._normalize_condition_value(key, value)
                for key, value in pattern.conditions.items()
                if str(key).strip()
            }

            match_count = sum(
                1
                for key, value in normalized_conditions.items()
                if key in normalized_pattern_conditions
                and normalized_pattern_conditions[key] == value
            )
            total_conditions = len(normalized_conditions)
            if total_conditions == 0:
                continue

            match_ratio = match_count / total_conditions
            if match_ratio < 0.5:
                continue

            score = pattern.reliability * match_ratio
            if score > best_score:
                best_score = score
                best = pattern

        return best

    def get_insights_for_context(
        self,
        phase: str = "",
        tech_stack: list[str] | None = None,
    ) -> list[LearnedInsight]:
        """Return insights that match the current context.

        This is the 'knowledge injection' hook — before each LLM call,
        inject relevant insights so the agent benefits from past learning.
        """
        if not self.learned_insights:
            return []

        techs_lc = [t.lower() for t in (tech_stack or [])]
        scored: list[tuple[float, LearnedInsight]] = []
        for insight in self.learned_insights:
            score = 0.0
            conds = insight.conditions
            conds_lc = str(conds).lower()

            if phase and str(conds.get("phase", "")).lower() == phase.lower():
                score += 0.5

            for tech in techs_lc:
                if tech and tech in conds_lc:
                    score += 0.3

            # Keep context-specific matches AND generally-applicable
            # (conditionless) insights, but rank the relevant ones first so the
            # model sees its most pertinent past learning at the top of context.
            if score > 0 or not conds:
                # Blend relevance with how trustworthy/well-supported the
                # insight is: confidence and the number of observations behind
                # it. This stops a high-confidence-but-irrelevant insight from
                # crowding out a directly-relevant one.
                support = min(getattr(insight, "observation_count", 0) / 10.0, 0.5)
                rank = score + (insight.confidence * 0.4) + support
                scored.append((rank, insight))

        scored.sort(key=lambda pair: pair[0], reverse=True)
        return [insight for _, insight in scored[:10]]

    def should_avoid_tool(self, tool_name: str) -> tuple[bool, list[str]]:
        if tool_name in self.negative_patterns:
            reasons = self.negative_patterns[tool_name]
            return True, reasons
        return False, []

    def get_learning_summary(self) -> dict[str, Any]:
        return {
            "total_tools_tracked": len(self.tool_performances),
            "total_patterns_learned": len(self.strategy_patterns),
            "negative_patterns": len(self.negative_patterns),
            "total_insights": len(self.learned_insights),
            "total_observations": len(self.observation_log),
            "top_tools": sorted(
                [
                    (name, perf.effectiveness_score, perf.success_rate, perf.total_uses)
                    for name, perf in self.tool_performances.items()
                    if perf.total_uses >= self.min_observations
                ],
                key=lambda x: x[1],
                reverse=True,
            )[:10],
            "reliable_strategies": sorted(
                [
                    (p.description, p.reliability, p.success_count, p.tool_sequence)
                    for p in self.strategy_patterns
                    if p.success_count + p.failure_count >= self.min_observations
                ],
                key=lambda x: x[1],
                reverse=True,
            )[:5],
        }

    @staticmethod
    def _normalize_condition_value(key: Any, value: Any) -> Any:
        key_name = str(key).strip().lower()
        if isinstance(value, str):
            text = value.strip()
            if key_name == "phase":
                return text.upper()
            if key_name == "tech":
                return text.lower()
            return text.lower()
        return value

    @staticmethod
    def _make_pattern_id(conditions: dict, tool_sequence: list[str]) -> str:
        raw = str(sorted(conditions.items())) + str(tool_sequence)
        return hashlib.md5(raw.encode(), usedforsecurity=False).hexdigest()[:12]

    @staticmethod
    def _describe_pattern(conditions: dict, tool_sequence: list[str]) -> str:
        cond_str = ", ".join(f"{k}={v}" for k, v in conditions.items())
        tools_str = " → ".join(tool_sequence)
        return f"When [{cond_str}] → use [{tools_str}]"


# ── Per-Target Memory ────────────────────────────────────────────────────────

_TARGET_MEMORY_DIR = Path.home() / ".airecon" / "memory" / "by_target"


@dataclass
class TargetMemory:
    """Actionable intelligence for a specific target domain/URL."""

    target: str
    first_seen: float = 0.0
    last_seen: float = 0.0
    session_count: int = 0
    tech_stack: list[str] = field(default_factory=list)
    endpoints: list[str] = field(default_factory=list)
    vulnerabilities: list[dict[str, str]] = field(default_factory=list)
    waf_bypass: list[dict[str, str]] = field(default_factory=list)
    sensitive_params: list[str] = field(default_factory=list)
    auth_endpoints: list[str] = field(default_factory=list)
    session_notes: str = ""

    # Category caps to prevent context bloat
    _MAX_ENDPOINTS = 500
    _MAX_VULNS = 100
    _MAX_BYPASS = 50
    _MAX_PARAMS = 200

    def prune(self) -> None:
        """Trim lists to their max sizes, keeping most recent entries."""
        if len(self.endpoints) > self._MAX_ENDPOINTS:
            self.endpoints = self.endpoints[-self._MAX_ENDPOINTS:]
        if len(self.vulnerabilities) > self._MAX_VULNS:
            self.vulnerabilities = self.vulnerabilities[-self._MAX_VULNS:]
        if len(self.waf_bypass) > self._MAX_BYPASS:
            self.waf_bypass = self.waf_bypass[-self._MAX_BYPASS:]
        if len(self.sensitive_params) > self._MAX_PARAMS:
            self.sensitive_params = self.sensitive_params[-self._MAX_PARAMS:]
        if len(self.auth_endpoints) > self._MAX_ENDPOINTS:
            self.auth_endpoints = self.auth_endpoints[-self._MAX_ENDPOINTS:]


class TargetMemoryStore:
    """Persistence layer for per-target security intelligence.

    Stores: discovered endpoints, vulns with working payloads,
            WAF bypass techniques, sensitive parameters, auth flows.
    Loads automatically when the same target reappears in a new session.
    """

    def __init__(self, base_dir: Path | None = None):
        self.base_dir = base_dir or _TARGET_MEMORY_DIR
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self._cache: dict[str, TargetMemory] = {}
        self._session_touched: set[str] = set()

    def _normalize_target(self, target: str) -> str:
        """Strip protocol, port, and path — returns bare domain."""
        if not target:
            return ""
        t = target.lower().strip()
        for prefix in ("https://", "http://", "ftp://", "ws://", "wss://"):
            if t.startswith(prefix):
                t = t[len(prefix):]
                break
        t = t.split("/")[0]     
        t = t.split(":")[0]      
        t = t.rstrip(".")
        return t

    def _file_path(self, target: str) -> Path:
        norm = self._normalize_target(target)
        safe_name = norm.replace("/", "_").replace("\\", "_")
        return self.base_dir / f"{safe_name}.json"

    # ── Load / Save ──────────────────────────────────────────────────────────

    def load(self, target: str) -> TargetMemory | None:
        """Load memory for a target. Returns None if target is unknown."""
        norm = self._normalize_target(target)
        if norm in self._cache:
            return self._cache[norm]

        fpath = self._file_path(target)
        if not fpath.exists():
            return None

        try:
            data = json.loads(fpath.read_text(encoding="utf-8"))
            tm = TargetMemory(**data)
            self._cache[norm] = tm
            self._touch_target_session(norm, tm, persist=True)
            logger.info(
                "[TargetMemory] Loaded for %s: %d endpoints, %d vulns, "
                "%d bypasses, %d params",
                norm, len(tm.endpoints), len(tm.vulnerabilities),
                len(tm.waf_bypass), len(tm.sensitive_params),
            )
            return tm
        except Exception as exc:
            logger.debug("Failed to load target memory for %s: %s", norm, exc)
            return None

    def save(self, target: str, tm: TargetMemory | None = None) -> None:
        """Persist target memory atomically."""
        norm = self._normalize_target(target)
        mem = tm or self._cache.get(norm)
        if mem is None:
            return

        mem.prune()
        mem.last_seen = time.time()

        fpath = self._file_path(target)
        tmp = fpath.with_suffix(".tmp")
        try:
            tmp.write_text(json.dumps(asdict(mem), indent=2), encoding="utf-8")
            tmp.rename(fpath)
            self._cache[norm] = mem
            logger.debug("[TargetMemory] Saved %s", norm)
        except Exception as exc:
            logger.debug("Failed to save target memory for %s: %s", norm, exc)

    def _touch_target_session(
        self,
        norm: str,
        tm: TargetMemory,
        *,
        persist: bool,
        is_new: bool = False,
    ) -> None:
        if norm in self._session_touched:
            return
        tm.last_seen = time.time()
        if is_new:
            tm.session_count = max(1, int(tm.session_count or 0))
        else:
            tm.session_count = max(1, int(tm.session_count or 0)) + 1
        self._session_touched.add(norm)
        self._cache[norm] = tm
        if persist:
            self.save(norm, tm)

    # ── Recording ────────────────────────────────────────────────────────────

    def ensure(self, target: str) -> TargetMemory:
        """Get existing or create new TargetMemory."""
        norm = self._normalize_target(target)
        if norm in self._cache:
            return self._cache[norm]

        existing = self.load(target)
        if existing is not None:
            return existing

        tm = TargetMemory(
            target=norm,
            first_seen=time.time(),
            last_seen=time.time(),
            session_count=1,
        )
        self._cache[norm] = tm
        self._touch_target_session(norm, tm, persist=False, is_new=True)
        return tm

    def record_endpoint(self, target: str, path: str) -> None:
        tm = self.ensure(target)
        if path not in tm.endpoints:
            tm.endpoints.append(path)

    def record_vulnerability(self, target: str, vuln: dict[str, str]) -> None:
        """Record a vuln dict: {type, path, param, payload, severity, confirmed}."""
        tm = self.ensure(target)
        # Dedup by type+path+param
        key = f"{vuln.get('type','')}|{vuln.get('path','')}|{vuln.get('param','')}"
        for existing in tm.vulnerabilities:
            ekey = f"{existing.get('type','')}|{existing.get('path','')}|{existing.get('param','')}"
            if ekey == key:
                return  # Already tracked
        tm.vulnerabilities.append(vuln)

    def record_bypass(self, target: str, bypass: dict[str, str]) -> None:
        """Record WAF bypass: {technique, header, path, description}."""
        tm = self.ensure(target)
        technique = bypass.get("technique", "")
        for existing in tm.waf_bypass:
            if existing.get("technique", "") == technique and existing.get("header", "") == bypass.get("header", ""):
                return
        bypass["success_count"] = bypass.get("success_count", "1")
        tm.waf_bypass.append(bypass)

    def record_param(self, target: str, param: str) -> None:
        tm = self.ensure(target)
        param_lower = param.lower()
        if param_lower not in [p.lower() for p in tm.sensitive_params]:
            tm.sensitive_params.append(param)

    def record_tech(self, target: str, tech: str) -> None:
        tm = self.ensure(target)
        tech_lower = tech.lower()
        if tech_lower not in [t.lower() for t in tm.tech_stack]:
            tm.tech_stack.append(tech)

    def record_auth_endpoint(self, target: str, path: str) -> None:
        tm = self.ensure(target)
        if path not in tm.auth_endpoints:
            tm.auth_endpoints.append(path)

    def add_session_note(self, target: str, note: str) -> None:
        tm = self.ensure(target)
        tm.session_notes = f"{tm.session_notes}\n{note}" if tm.session_notes else note

    # ── Querying ─────────────────────────────────────────────────────────────

    def list_targets(self) -> list[str]:
        """Return all known target domains."""
        return [
            f.stem for f in self.base_dir.glob("*.json")
            if not f.name.endswith(".tmp")
        ]

    def get_injection_text(self, target: str) -> str | None:
        """Build a system message block for LLM context with target intel.

        Returns None if no memory exists for this target.
        Max ~2000 chars to preserve context budget.
        """
        norm = self._normalize_target(target)
        tm = self._cache.get(norm) or self.load(target)
        if tm is None:
            return None

        if not any([
            tm.endpoints, tm.vulnerabilities, tm.waf_bypass,
            tm.sensitive_params, tm.tech_stack, tm.auth_endpoints,
            tm.session_notes,
        ]):
            return None

        lines = [
            f"<target_intelligence: {tm.target}>",
            f"REMEMBERED INTELLIGENCE from {max(tm.session_count - 1, 0)} previous session(s) on {tm.target}:",
            "",
        ]

        if tm.tech_stack:
            lines.append(f"TECH STACK: {', '.join(tm.tech_stack)}")
            lines.append("")

        if tm.endpoints:
            total = len(tm.endpoints)
            show = tm.endpoints[-30:]  # last 30
            lines.append(f"ENDPOINTS DISCOVERED ({total} total):")
            for ep in show[-20:]:
                lines.append(f"  - {ep}")
            if total > 30:
                lines.append(f"  ... and {total - 30} more")
            lines.append("")

        if tm.vulnerabilities:
            lines.append("CONFIRMED VULNERABILITIES:")
            for v in tm.vulnerabilities[-10:]:
                vtype = v.get("type", "unknown")
                vpath = v.get("path", "")
                vparam = v.get("param", "")
                vpayload = v.get("payload", "")
                vsev = v.get("severity", "")
                confirmed = "CONFIRMED" if v.get("confirmed") == "true" else "unverified"
                parts = [f"  - [{vtype.upper()}] {vpath}"]
                if vparam:
                    parts.append(f" (param: {vparam})")
                if vpayload:
                    parts.append(f" payload={vpayload}")
                if vsev:
                    parts.append(f" severity={vsev}")
                parts.append(f" {confirmed}")
                lines.append("".join(parts))
            lines.append("")

        if tm.waf_bypass:
            lines.append("WAF/BYPASS TECHNIQUES (reuse these):")
            for b in tm.waf_bypass[-8:]:
                lines.append(
                    f"  - {b.get('technique', 'unknown')}: "
                    f"{b.get('header', '')} {b.get('path', '')} "
                    f"— {b.get('description', '')}"
                )
            lines.append("")

        if tm.sensitive_params:
            total = len(tm.sensitive_params)
            show = tm.sensitive_params[-15:]
            lines.append(f"SENSITIVE PARAMETERS ({total}): {', '.join(show)}")
            lines.append("")

        if tm.auth_endpoints:
            lines.append(f"AUTH ENDPOINTS: {', '.join(tm.auth_endpoints)}")
            lines.append("")

        if tm.session_notes:
            lines.append(f"SESSION NOTES:\n  {tm.session_notes[-1000:]}")
            lines.append("")

        lines.append(
            "Use this intelligence. Re-test confirmed vulns. "
            "Reuse bypasses. Do NOT re-discover already-known endpoints."
        )
        lines.append("</target_intelligence>")
        return "\n".join(lines)


# ── Helper ───────────────────────────────────────────────────────────────────

def _extract_tool_name(raw_cmd: str) -> str:
    """Extract the base tool from a raw command string.

    Uses the tool metadata catalog from data/tools_meta.json for lookup.
    """
    if not raw_cmd:
        return ""

    _skip = {"sudo", "time", "nohup", "2>&1", "|", "&&", "||", ";", "do", "done", "then", "fi"}
    cmd = raw_cmd.split("&&")[0].split("|")[0].split(";")[0].strip()
    part = cmd.split()[0] if cmd.split() else cmd
    part = part.lstrip("./").lstrip("/")
    part = part.split(".")[-1] if part.endswith((".py", ".sh", ".js")) else part

    if part in _skip or not part.isalpha():
        # Fall back to known tool names from tools_meta.json
        known = _cache_known_tool_names()
        for k in known:
            if k in raw_cmd.lower():
                return k
        return part
    return part


_TOOL_NAME_CACHE: list[str] = []


def _normalize_tool_names(values: list[Any]) -> set[str]:
    return {str(value).strip().lower() for value in values if str(value).strip()}


def _iter_phase_category_tools(meta: dict[str, Any], phase_name: str) -> set[str]:
    wanted = _normalize_tool_names(
        meta.get("phase_category_map", {}).get(phase_name.upper(), [])
        if isinstance(meta.get("phase_category_map", {}), dict)
        else []
    )
    if not wanted:
        return set()

    resolved: set[str] = set()
    for cat_data in meta.get("categories", {}).values():
        if not isinstance(cat_data, dict):
            continue
        for category_name, tool_list in cat_data.items():
            if str(category_name).strip().lower() not in wanted:
                continue
            if isinstance(tool_list, list):
                resolved.update(_normalize_tool_names(tool_list))
    return resolved


def _cache_known_tool_names() -> list[str]:
    """Build a deduplicated list of all known tool names from repo metadata."""
    global _TOOL_NAME_CACHE
    if _TOOL_NAME_CACHE:
        return _TOOL_NAME_CACHE

    meta = _load_tools_meta()
    names: set[str] = set()

    for cat_data in meta.get("categories", {}).values():
        if isinstance(cat_data, dict):
            for tool_list in cat_data.values():
                if isinstance(tool_list, list):
                    names.update(_normalize_tool_names(tool_list))

    names.update(_normalize_tool_names(list(meta.get("tool_descriptions", {}).keys())))
    names.update(_normalize_tool_names(meta.get("analysis_phase_vuln_tools", [])))
    names.update(_normalize_tool_names(meta.get("watchdog_safe_command_prefixes", [])))

    for tools in meta.get("phase_extras", {}).values():
        if isinstance(tools, list):
            names.update(_normalize_tool_names(tools))

    names.update(_normalize_tool_names(meta.get("callable_core_tools", [])))
    names.update(_normalize_tool_names(meta.get("report_tools", [])))

    for entry in _load_tool_definitions():
        if not isinstance(entry, dict):
            continue
        function = entry.get("function", {})
        if not isinstance(function, dict):
            continue
        tool_name = str(function.get("name", "")).strip().lower()
        if tool_name:
            names.add(tool_name)

    _TOOL_NAME_CACHE = sorted(names, key=len, reverse=True)
    return _TOOL_NAME_CACHE


_PHASE_TOOL_CACHE: dict[str, set[str]] = {}


def _cache_phase_tools() -> dict[str, set[str]]:
    """Build phase → tool set mapping from tools_meta.json."""
    global _PHASE_TOOL_CACHE
    if _PHASE_TOOL_CACHE:
        return _PHASE_TOOL_CACHE

    meta = _load_tools_meta()
    result: dict[str, set[str]] = {
        "recon": set(),
        "analysis": set(),
        "exploit": set(),
        "report": set(),
    }

    for phase_name in tuple(result.keys()):
        result[phase_name].update(_iter_phase_category_tools(meta, phase_name))
        extras = meta.get("phase_extras", {}).get(phase_name.upper(), [])
        if isinstance(extras, list):
            result[phase_name].update(_normalize_tool_names(extras))

    result["analysis"].update(_normalize_tool_names(meta.get("analysis_phase_vuln_tools", [])))
    result["report"].update(_normalize_tool_names(meta.get("report_tools", [])))

    _PHASE_TOOL_CACHE = result
    return _PHASE_TOOL_CACHE


def _infer_tool_purpose(tool_name: str, conditions: dict) -> str:
    """Return a human-readable purpose summary for a tool.

    Uses tool_descriptions from tools_meta.json.
    """
    descriptions = _load_tools_meta().get("tool_descriptions", {})
    tool_lower = tool_name.lower()

    # Direct match
    if tool_lower in descriptions:
        return descriptions[tool_lower]

    # Airecon native tools (not in tools_meta.json tool_descriptions)
    # Unix utility fallbacks not in tools_meta.json
    unix_utils = {
        "find": "file discovery — locate exposed JS/config files and sensitive directories",
        "execute": "execute system commands — primary action hook for tool invocations",
        "cat": "read/concatenate files — quick output inspection",
        "head": "preview first lines — truncated output checks",
        "xargs": "execute commands from stdin — batch processing builder",
        "sh": "POSIX shell — typically an intermediate step, not a target tool",
    }
    if tool_lower in unix_utils:
        return unix_utils[tool_lower]

    meta = _load_tools_meta()
    tool_descs = meta.get("tool_descriptions", {})
    if tool_lower in tool_descs:
        return tool_descs[tool_lower]

    return f"{tool_name} usage pattern observed"


def _infer_phase_from_tool(tool_name: str) -> str:
    """Guess which phase a tool belongs to based on tools_meta.json categories."""
    phase_tools = _cache_phase_tools()
    tool_lower = tool_name.lower()

    for phase_name in ("report", "exploit", "analysis", "recon"):
        if tool_lower in phase_tools.get(phase_name, set()):
            return phase_name

    return "recon"


def _parse_insights_json(raw: str) -> list[dict[str, Any]]:
    """Extract JSON array from LLM response."""
    stripped = raw.strip()
    if stripped.startswith("```"):
        stripped = stripped.split("\n", 1)[-1]
        if stripped.endswith("```"):
            stripped = stripped.rsplit("```", 1)[0]
        stripped = stripped.strip()

    try:
        data = json.loads(stripped)
        return data if isinstance(data, list) else []
    except json.JSONDecodeError:
        start = stripped.find("[")
        end = stripped.rfind("]")
        if start != -1 and end > start:
            try:
                return json.loads(stripped[start:end + 1])
            except json.JSONDecodeError:
                pass
        return []

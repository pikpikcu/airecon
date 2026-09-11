from __future__ import annotations

import asyncio
import logging
import time
import json
from dataclasses import asdict as _asdict
from pathlib import Path
from typing import Any

from ..data_loader import severity_to_int
from .chain_planner import ChainStep as _ChainStep
from .chain_planner import ExploitChain as _ExploitChain
from .chain_planner import build_chain_context, plan_chains
from .novel_discovery import (
    analyze_novel_vectors,
    get_recommendation_for_finding,
)
from .pipeline import PipelinePhase
from .session import save_session, session_to_context

logger = logging.getLogger("airecon.agent")

# A "roomy" context window (in tokens) at/above which the loop tolerates more
# token pressure before compacting. Driven by the actual context window — NOT a
# hardcoded model name — so it generalises across GPT/Claude/Qwen/Gemini/etc.
# 100K sits above the 64K default and below typical long-context tiers (128K+).
_ROOMY_CONTEXT_TOKENS = 100_000

# Static tech→known-issues dataset, used as the cold-start "brain" when the
# cross-session memory has not yet learned anything for the detected stack.
_TECH_CORRELATIONS_FILE = Path(__file__).parent.parent / "data" / "tech_correlations.json"
_tech_correlations_cache: dict[str, Any] | None = None


def _load_tech_correlations() -> dict[str, Any]:
    global _tech_correlations_cache
    if _tech_correlations_cache is None:
        try:
            _tech_correlations_cache = json.loads(
                _TECH_CORRELATIONS_FILE.read_text(encoding="utf-8")
            )
            if not isinstance(_tech_correlations_cache, dict):
                _tech_correlations_cache = {}
        except Exception as _tc_err:
            logger.debug("tech_correlations.json unavailable: %s", _tc_err)
            _tech_correlations_cache = {}
    return _tech_correlations_cache


def _build_cold_start_knowledge(tech_names: list[str]) -> str:
    """Build a KNOWLEDGE BASE brief from the static tech_correlations dataset for
    the detected technologies. Returns "" when nothing matches. Used as the
    cold-start brain before cross-session memory has learned anything."""
    if not tech_names:
        return ""
    tc = _load_tech_correlations()
    lines = ["[SYSTEM: KNOWLEDGE BASE — known issues for detected tech]"]
    added = False
    for tn in tech_names:
        entry = tc.get(str(tn).lower())
        if not isinstance(entry, dict):
            continue
        vulns = [str(v) for v in (entry.get("vulns") or [])][:4]
        paths = [str(p) for p in (entry.get("paths") or [])][:5]
        tools = [str(t) for t in (entry.get("tools") or [])][:4]
        if not (vulns or paths or tools):
            continue
        added = True
        lines.append(f"- {tn}:")
        if vulns:
            lines.append(f"    known issues: {'; '.join(vulns)}")
        if paths:
            lines.append(f"    check paths: {', '.join(paths)}")
        if tools:
            lines.append(f"    tools: {', '.join(tools)}")
    return "\n".join(lines) if added else ""

try:
    from ..server import _trace_chat_event
except (ImportError, ValueError):

    def _trace_chat_event(*args, **kwargs):
        pass


def _chain_step_to_text(step: Any) -> str:
    if isinstance(step, str):
        return step
    if isinstance(step, dict):
        return str(
            step.get("description")
            or step.get("name")
            or step.get("tool_hint")
            or step.get("step")
            or "step"
        )
    return str(step)


def _build_graph_chain_prompt(
    vulnerabilities: list[dict[str, Any]],
) -> tuple[str, list[Any]]:
    """Build a graph-correlation prompt from live findings only."""
    if len(vulnerabilities) < 2:
        return "", []

    from .correlation_engine import get_correlation_engine, reset_correlation_engine

    reset_correlation_engine()
    engine = get_correlation_engine()

    for vuln in vulnerabilities:
        vuln_text = " ".join(
            str(vuln.get(key, "")).strip()
            for key in ("type", "category", "finding", "title", "description")
            if str(vuln.get(key, "")).strip()
        )
        engine.add_finding(
            vuln_class=vuln_text.lower(),
            severity=severity_to_int(vuln.get("severity", 2)),
            confidence=float(vuln.get("confidence", 0.5)),
            endpoint=str(vuln.get("url", vuln.get("endpoint", ""))),
            parameter=str(vuln.get("parameter", "")),
            description=str(vuln.get("title", vuln.get("finding", ""))),
        )

    chains = engine.correlate_findings()
    if not chains:
        return "", []

    lines = ["\n[GRAPH-BASED ATTACK CHAINS]"]
    for chain in chains[:5]:
        lines.append(f"- [{chain.combined_severity}/5] {chain.name}")
        lines.append(f"  Path: {chain.attack_path}")
        lines.append(f"  Reasoning: {chain.reasoning}")
    return "\n".join(lines), chains


def _build_novel_discovery_prompt(
    vulnerabilities: list[dict[str, Any]],
    iteration: int,
) -> str:
    """Generate a prompt for non-template attack paths from observed findings."""
    if not vulnerabilities:
        return ""

    analysis = analyze_novel_vectors(vulnerabilities, iteration=iteration)
    combinations = analysis.get("combinations", [])
    tactics = analysis.get("innovative_tactics", [])
    recommendations = analysis.get("recommendations", [])
    vectors = analysis.get("novel_vectors", [])
    anomalies = analysis.get("anomalies_detected", [])

    if not any((combinations, tactics, recommendations, vectors, anomalies)):
        return ""

    lines = ["\n[NOVEL VECTOR ANALYSIS]"]
    for recommendation in recommendations[:3]:
        lines.append(f"- {recommendation}")
    if anomalies:
        lines.append(
            "- Anomalies observed: "
            + ", ".join(str(a).replace("_", " ") for a in anomalies[:4])
        )
    for vector in vectors[:2]:
        bases = vector.get("bases", [])
        lines.append(
            f"- Novel path: {vector.get('description', 'Emergent chain')} "
            f"(conf={float(vector.get('confidence', 0.0)):.0%})"
        )
        if bases:
            lines.append(f"  Findings: {'; '.join(str(b) for b in bases[:3])}")
    for tactic in tactics[:2]:
        lines.append(f"- Novel tactic: {tactic}")

    for vuln in vulnerabilities[:2]:
        finding_name = str(vuln.get("title", vuln.get("finding", "finding"))).strip()
        recs = get_recommendation_for_finding(vuln, vulnerabilities)
        if finding_name and recs:
            lines.append(f"- Pivot from {finding_name[:70]}: {recs[0]}")

    return "\n".join(lines)


# Anti-repetition directives — dynamically generated from session context
# at runtime. No hardcoded vuln lists or attack vectors in Python code.


def _build_dynamic_anti_loop_rotation(
    tested_vuln_classes: set[str],
    untested_vuln_classes: set[str],
    phase: str,
    iteration: int,
    recent_tools: list[str],
) -> str:
    """Build an anti-repetition directive from live session data.

    Instead of hardcoded vuln lists, this reads:
    - What has actually been tested (from evidence log)
    - What remains untested (from system.txt §11 + skills catalog)
    - What tools have been used recently
    - Current phase context
    """
    tested_str = (
        ", ".join(sorted(tested_vuln_classes)) if tested_vuln_classes else "none yet"
    )
    untested_str = (
        ", ".join(sorted(untested_vuln_classes)[:8])
        if untested_vuln_classes
        else "all covered"
    )

    # Build rotation based on what's been tested vs what's available
    rotation_idx = iteration % 5

    rotations = [
        (
            "[ANTI-REPETITION: Think like a real pentester — every target is unique]\n"
            f"Already tested: {tested_str}\n"
            f"Still untested: {untested_str}\n"
            "Do NOT re-test what you already covered. Pick from the untested classes above.\n"
            "Ask: what is UNIQUE about this target's architecture, technology stack, "
            "authentication flow, data model, or business logic?"
        ),
        (
            "[ANTI-REPETITION: Visionary attacker — think beyond standard tools]\n"
            "Standard scans find standard bugs. To find unique vulnerabilities:\n"
            "1. MAP the attack chain — how do components trust each other? (frontend ↔ API ↔ backend ↔ DB ↔ cloud)\n"
            "2. FIND the gaps — what happens between valid states? (race conditions, TOCTOU, state desync)\n"
            "3. ABUSE the logic — what did the developer assume would never happen?\n"
            "4. CHAIN weaknesses — each minor issue becomes a foothold for the next attack.\n"
            f"Your recent tools: {', '.join(recent_tools[-5:]) if recent_tools else 'none yet'}\n"
            "If these tools find nothing, try: manual request crafting, header manipulation, "
            "JSON/XML confusion, encoding tricks, second-order payloads, or time-based differences."
        ),
        (
            "[ANTI-REPETITION: Think laterally, not just deeper]\n"
            "When one approach yields nothing after multiple attempts, STOP and pivot:\n"
            f"- Tested classes: {tested_str}\n"
            f"- Available alternatives: {untested_str}\n"
            "- Try a completely different vuln class from the untested list\n"
            "- Attack a different component (API → admin panel → mobile endpoints → WebSocket → GraphQL)\n"
            "- Test with different context (authenticated vs anonymous, different user roles, different HTTP methods)\n"
            "- Abuse normal features maliciously (upload as payload, search as injection, export as exfiltration)\n"
            "Remember: the most critical bugs are often the ones nobody thought to test."
        ),
        (
            "[ANTI-REPETITION: Full-spectrum attacker — no blind spots]\n"
            "Your testing should cover ALL vulnerability classes before reporting.\n"
            f"Already covered: {tested_str}\n"
            f"Remaining gaps: {untested_str}\n"
            "If any category remains untested against reachable endpoints — test it now.\n"
            "Load relevant skills from skills/vulnerabilities/ for specific testing methodologies."
        ),
        (
            "[ANTI-REPETITION: Novel attack vectors — what the LLM overlooks]\n"
            "Large language models have blind spots. Force yourself to consider:\n"
            "- HTTP Request Smuggling: CL/TE or TE/TE mismatches behind load balancers\n"
            "- Web Cache Poisoning: unkeyed headers, cookie reflection, fat GET\n"
            "- HTTP Host Header Injection: password reset poisoning, cache key injection\n"
            "- Content-Type Abuse: JSON→XML, form→JSON, multipart confusion\n"
            "- Unicode / Encoding: normalization bypass, homograph attacks, double-encoding\n"
            "- Time-based attacks: race conditions via parallel requests\n"
            "- Out-of-Band (OOB): DNS/exfil via interaction with external server\n"
            "- Second-Order: stored input triggers vulnerability in unrelated context\n"
            f"Already tested: {tested_str}\n"
            "These are rarely tested and often yield critical findings when others miss them."
        ),
    ]

    return rotations[rotation_idx]


class _CyclePreludeMixin:
    async def _run_iteration_housekeeping(self, cfg: Any, current_phase: Any) -> None:
        # Inject attack surface coverage hint + anti-repetition directive
        # on every iteration after iteration 2.
        tracker = getattr(self, "_surface_tracker", None)
        if tracker is not None and self.state.iteration > 2:
            try:
                _hint = tracker.build_coverage_hint()
                if _hint:
                    # Build anti-loop rotation dynamically from session context
                    tested = set()
                    for ev in self.state.evidence_log:
                        for tag in ev.get("tags", []):
                            if tag and isinstance(tag, str):
                                tested.add(tag.lower().replace(" ", "_"))
                    if self._session:
                        for v in getattr(self._session, "vulnerabilities", []):
                            vtype = str(v.get("type", v.get("finding", ""))).lower()
                            if vtype:
                                tested.add(vtype.replace(" ", "_"))

                    # Get untested from exploration mixin if available
                    untested = set()
                    if hasattr(self, "_get_untested_vuln_classes"):
                        untested = self._get_untested_vuln_classes(tested)

                    pipeline_engine = getattr(self, "pipeline", None)
                    phase_name = "RECON"
                    if pipeline_engine:
                        phase_name = (
                            str(
                                getattr(
                                    pipeline_engine, "get_current_phase", lambda: None
                                )()
                            )
                            or "RECON"
                        )

                    _full = (
                        _hint
                        + "\n"
                        + _build_dynamic_anti_loop_rotation(
                            tested_vuln_classes=tested,
                            untested_vuln_classes=untested,
                            phase=phase_name,
                            iteration=self.state.iteration,
                            recent_tools=getattr(self, "_recent_tool_names", []),
                        )
                    )
                    self.state.conversation.append({"role": "system", "content": _full})
                    logger.info(
                        "Attack surface coverage + anti-repetition hint injected "
                        "at iteration %d (tested=%d, untested=%d)",
                        self.state.iteration,
                        len(tested),
                        len(untested),
                    )
            except Exception as _hint_err:
                logger.debug("Coverage hint injection failed: %s", _hint_err)

        # Inject output file manifest at iteration 1 and 3 so the AI knows
        # what artifacts already exist BEFORE running any discovery tools.
        if self.state.iteration in (1, 3) and self._session and not self._ctf_mode:
            try:
                from ..config import get_workspace_root as _gws

                _workspace = _gws() / self._session.target
                _manifest_parts: list[str] = []
                for _subdir in (
                    "output",
                    "recon",
                    "scan_results",
                    "findings",
                    "reports",
                    "tools",
                ):
                    _d = _workspace / _subdir
                    if _d.is_dir():
                        _files = sorted([f.name for f in _d.iterdir() if f.is_file()])[
                            :15
                        ]
                        if _files:
                            _manifest_parts.append(f"{_subdir}/: {', '.join(_files)}")
                if _manifest_parts:
                    _manifest = (
                        "[SYSTEM: OUTPUT FILE MANIFEST — these artifacts already exist]\n"
                        "READ existing files with read_file before re-running any scan.\n"
                        "DO NOT re-scan if the information you need is already in these files.\n"
                        + "\n".join(f"  {p}" for p in _manifest_parts)
                    )
                    self.state.conversation.append(
                        {"role": "system", "content": _manifest}
                    )
                    logger.info(
                        "Output file manifest injected at iteration %d (%d dirs)",
                        self.state.iteration,
                        len(_manifest_parts),
                    )
            except Exception as _manifest_err:
                logger.debug("File manifest injection failed: %s", _manifest_err)

        if self.state.iteration % 10 == 0:
            self._check_llm_context_pressure()

        self._enforce_scope_target_integrity()

        if (
            self._session
            and self.state.iteration % self._conversation_save_interval == 0
            and self.state.iteration != self._last_conversation_save_iteration
        ):
            self._sync_conversation_to_session()
            try:
                self._schedule_token_usage_snapshot_save()
            except Exception as _save_err:
                logger.debug(
                    "Failed to save conversation at iteration %d: %s",
                    self.state.iteration,
                    _save_err,
                )
            self._last_conversation_save_iteration = self.state.iteration
            logger.debug(f"Conversation auto-saved at iteration {self.state.iteration}")

        if (
            self._session
            and self._session.target
            and self.state.iteration > 0
            and self.state.iteration % self._session_save_interval == 0
            and self.state.iteration != self._last_session_save_iteration
            and hasattr(self, "_save_session_persistence")
        ):
            try:
                await self._save_session_persistence()
            except Exception as _persist_err:
                logger.debug(
                    "Failed to persist adaptive/payload state at iteration %d: %s",
                    self.state.iteration,
                    _persist_err,
                )

        if (
            self._session
            and self._session.target
            and self.state.iteration % self._memory_save_interval == 0
            and self.state.iteration != self._last_memory_save_iteration
        ):
            self._save_to_memory_realtime()
            self._last_memory_save_iteration = self.state.iteration

        _memory_health_interval = max(
            1, int(getattr(self, "_memory_health_interval", 10) or 10)
        )
        if (
            self._session
            and self._session.target
            and self.state.iteration > 0
            and self.state.iteration % _memory_health_interval == 0
            and self.state.iteration
            != getattr(self, "_last_memory_health_check_iteration", -1)
        ):
            self._check_memory_brain_health()
            self._last_memory_health_check_iteration = self.state.iteration

        # LLM-driven recon validation to reduce noise before analysis/exploit
        try:
            phase_name = getattr(current_phase, "value", str(current_phase or "")).upper()
        except Exception as exc:
            logger.debug("Failed to read current phase name: %s", exc)
            phase_name = str(current_phase or "").upper()

        if (
            phase_name in ("ANALYSIS", "EXPLOIT")
            and self._session
            and hasattr(self, "llm")
        ):
            last_validation = getattr(self._lifecycle, "last_context_validation", 0)
            if self.state.iteration - last_validation >= 6:
                s = self._session
                if s.urls or s.subdomains or s.live_hosts:
                    urls = list(s.urls)[:80]
                    subs = list(s.subdomains)[:80]
                    hosts = list(s.live_hosts)[:80]
                    techs = list(s.technologies.items())[:40]

                    prompt = (
                        "You are validating recon results for security analysis.\n"
                        "Goal: reduce noise and keep only high-signal assets/endpoints.\n"
                        "Rules:\n"
                        "- Keep endpoints likely to expose auth, data, actions, admin, API, upload, or config.\n"
                        "- Drop static assets, tracking, docs, health checks, or pure marketing pages.\n"
                        "- Be conservative: if unsure, keep.\n"
                        "Return STRICT JSON only with keys:\n"
                        "{\n"
                        '  \"keep_urls\": [...],\n'
                        '  \"drop_urls\": [...],\n'
                        '  \"keep_subdomains\": [...],\n'
                        '  \"drop_subdomains\": [...],\n'
                        '  \"keep_hosts\": [...],\n'
                        '  \"drop_hosts\": [...],\n'
                        '  \"notes\": \"short reasoning\"\n'
                        "}\n"
                    )

                    user_payload = {
                        "urls": urls,
                        "subdomains": subs,
                        "live_hosts": hosts,
                        "technologies": techs,
                    }

                    messages = [
                        {"role": "system", "content": prompt},
                        {
                            "role": "user",
                            "content": json.dumps(user_payload, ensure_ascii=False),
                        },
                    ]

                    try:
                        from ..config import get_config

                        cfg = get_config()
                        num_ctx = max(2048, min(4096, int(cfg.llm_context_window) // 8))
                    except Exception as exc:
                        logger.debug("Failed to resolve llm_context_window: %s", exc)
                        num_ctx = 3072

                    options = {
                        "temperature": 0.1,
                        "num_ctx": num_ctx,
                        "num_predict": 512,
                    }

                    def _extract_json(text: str) -> dict[str, Any] | None:
                        if not text:
                            return None
                        stripped = text.strip()
                        if stripped.startswith("{") and stripped.endswith("}"):
                            try:
                                return json.loads(stripped)
                            except Exception as exc:
                                logger.debug(
                                    "Recon validation JSON parse failed (direct): %s", exc
                                )
                        start = stripped.find("{")
                        end = stripped.rfind("}")
                        if start != -1 and end != -1 and end > start:
                            try:
                                return json.loads(stripped[start : end + 1])
                            except Exception as exc:
                                logger.debug(
                                    "Recon validation JSON parse failed (slice): %s", exc
                                )
                                return None
                        return None

                    try:
                        raw = await self.llm.complete(
                            messages,
                            options=options,
                            operation="analysis",
                        )
                    except Exception as exc:
                        logger.debug("Recon validation LLM call failed: %s", exc)
                        raw = ""

                    data = _extract_json(raw)
                    if isinstance(data, dict):
                        def _sanitize(items: Any, allowed: list[str]) -> list[str]:
                            if not isinstance(items, list):
                                return []
                            allowed_set = {str(x) for x in allowed}
                            result: list[str] = []
                            seen: set[str] = set()
                            for item in items:
                                if not isinstance(item, str):
                                    continue
                                candidate = item.strip()
                                if not candidate or candidate in seen:
                                    continue
                                if candidate in allowed_set:
                                    result.append(candidate)
                                    seen.add(candidate)
                            return result

                        validated_urls = _sanitize(data.get("keep_urls"), urls)
                        validated_subs = _sanitize(data.get("keep_subdomains"), subs)
                        validated_hosts = _sanitize(data.get("keep_hosts"), hosts)

                        if validated_urls or validated_subs or validated_hosts:
                            s.validated_urls = validated_urls
                            s.validated_subdomains = validated_subs
                            s.validated_live_hosts = validated_hosts
                            s.recon_validation_notes = str(
                                data.get("notes", "") or ""
                            )[:400]
                            self._lifecycle.last_context_validation = (
                                self.state.iteration
                            )

                            summary_parts = [
                                "[SYSTEM: LLM RECON VALIDATION — focus these signals]"
                            ]
                            if validated_subs:
                                summary_parts.append(
                                    f"Validated subdomains ({len(validated_subs)}): "
                                    + ", ".join(validated_subs[:6])
                                )
                            if validated_hosts:
                                summary_parts.append(
                                    f"Validated live hosts ({len(validated_hosts)}): "
                                    + ", ".join(validated_hosts[:6])
                                )
                            if validated_urls:
                                summary_parts.append(
                                    f"Validated URLs ({len(validated_urls)}): "
                                    + ", ".join(validated_urls[:6])
                                )
                            if s.recon_validation_notes:
                                summary_parts.append(
                                    f"Notes: {s.recon_validation_notes}"
                                )

                            self.state.conversation.append(
                                {"role": "system", "content": "\n".join(summary_parts)}
                            )
                            logger.info(
                                "LLM recon validation applied (urls=%d, subs=%d, hosts=%d)",
                                len(validated_urls),
                                len(validated_subs),
                                len(validated_hosts),
                            )

        _budget_ratio = self.state.iteration / max(self.state.max_iterations, 1)
        if _budget_ratio >= 1.0 and self._budget_pressure_level < 4:
            self._budget_pressure_level = 4
            logger.warning(
                "Budget exhausted at iteration %d/%d — forcing REPORT phase.",
                self.state.iteration,
                self.state.max_iterations,
            )
            if self.pipeline and current_phase.value != "REPORT":
                self.pipeline.set_phase(PipelinePhase.REPORT)
            self.state.conversation.append(
                {
                    "role": "system",
                    "content": (
                        "[SYSTEM: BUDGET EXHAUSTED] You have used all available "
                        "iterations. STOP all testing immediately. Your ONLY task "
                        "now is to call the report tool and write the final report "
                        "with everything you have found."
                    ),
                }
            )
        elif _budget_ratio >= 0.95 and self._budget_pressure_level < 3:
            self._budget_pressure_level = 3
            remaining = self.state.max_iterations - self.state.iteration
            logger.info(
                "Budget pressure L3 (95%%) at iteration %d, %d remaining.",
                self.state.iteration,
                remaining,
            )
            self.state.conversation.append(
                {
                    "role": "system",
                    "content": (
                        f"[SYSTEM: BUDGET CRITICAL — {remaining} iterations left] "
                        "STOP all new discovery. You must now: (1) call the report "
                        "tool with all confirmed findings, (2) advance to REPORT "
                        "phase if not already there. No more scanning or fuzzing."
                    ),
                }
            )
        elif _budget_ratio >= 0.85 and self._budget_pressure_level < 2:
            self._budget_pressure_level = 2
            remaining = self.state.max_iterations - self.state.iteration
            logger.info(
                "Budget pressure L2 (85%%) at iteration %d, %d remaining.",
                self.state.iteration,
                remaining,
            )
            self.state.conversation.append(
                {
                    "role": "system",
                    "content": (
                        f"[SYSTEM: BUDGET WARNING — {remaining} iterations left] "
                        "Begin consolidating findings for the report. Finish any "
                        "in-progress tests, then switch to REPORT phase. Do not "
                        "start new discovery chains."
                    ),
                }
            )
        elif _budget_ratio >= 0.70 and self._budget_pressure_level < 1:
            self._budget_pressure_level = 1
            remaining = self.state.max_iterations - self.state.iteration
            logger.info(
                "Budget pressure L1 (70%%) at iteration %d, %d remaining.",
                self.state.iteration,
                remaining,
            )
            self.state.conversation.append(
                {
                    "role": "system",
                    "content": (
                        f"[SYSTEM: BUDGET NOTICE — {remaining} iterations left] "
                        "Prioritise your highest-value untested attack vectors only. "
                        "Avoid retrying already-tested paths or broad enumeration."
                    ),
                }
            )

        if self._prev_phase is not None and current_phase != self._prev_phase:
            logger.debug(
                "Phase transition %s → %s: stagnation counter reset.",
                self._prev_phase.value,
                current_phase.value,
            )
            self._stagnation_iterations = 0
            self._recent_tool_names.clear()
        self._prev_phase = current_phase

        # Memory-as-brain: inject learned patterns from past sessions; on cold
        # start (no learned patterns yet for the detected stack) fall back to the
        # static tech_correlations dataset so the agent ALWAYS reasons with real
        # domain knowledge from iteration 1. Cadence is config-driven.
        try:
            _recall_interval = max(
                1, int(getattr(cfg, "intelligence_memory_recall_interval", 4))
            )
        except (TypeError, ValueError):
            _recall_interval = 4
        if (
            self._session
            and self.state.iteration > 0
            and self.state.iteration % _recall_interval == 0
        ):
            try:
                from ..memory import get_memory_manager

                _mem = get_memory_manager()
                _techs = getattr(self._session, "technologies", {}) or {}
                _tech_names = list(_techs.keys())[:3] if _techs else []

                _learned_patterns = _mem.get_patterns(
                    target_tech=_tech_names[0] if _tech_names else None,
                    limit=5,
                    min_success_rate=0.60,
                )
                _similar_findings = _mem.get_similar_findings(
                    target=self._session.target, limit=5
                )

                # Cold-start fallback: no learned patterns → surface dataset
                # knowledge for the detected technologies.
                if not _learned_patterns and _tech_names:
                    _kb = _build_cold_start_knowledge(_tech_names)
                    if _kb:
                        self.state.conversation = [
                            m
                            for m in self.state.conversation
                            if not str(m.get("content", "")).startswith(
                                "[SYSTEM: KNOWLEDGE BASE"
                            )
                        ]
                        self.state.conversation.append(
                            {"role": "system", "content": _kb}
                        )
                        logger.info(
                            "Cold-start dataset knowledge injected for tech=%s",
                            ", ".join(_tech_names),
                        )

                if _learned_patterns:
                    _p_lines = [
                        "[SYSTEM: LEARNED PATTERNS — proven from past sessions]"
                    ]
                    for _p in _learned_patterns[:4]:
                        _desc = str(_p.get("description", ""))[:120]
                        _sr = float(_p.get("success_rate", 0)) * 100
                        _eff = float(_p.get("effectiveness_score", _sr))
                        _tools_used = _p.get("commands_used", [])
                        _tools_str = (
                            f" used: {', '.join(str(x) for x in _tools_used[:3])}"
                            if _tools_used
                            else ""
                        )
                        _p_lines.append(
                            f"- {_desc} (success={_sr:.0f}%, effectiveness={_eff:.0f}){_tools_str}"
                        )
                    self.state.conversation = [
                        m
                        for m in self.state.conversation
                        if not str(m.get("content", "")).startswith(
                            "[SYSTEM: LEARNED PATTERNS"
                        )
                    ]
                    self.state.conversation.append(
                        {"role": "system", "content": "\n".join(_p_lines)}
                    )
                    logger.info(
                        "Learned patterns injected: %d (tech=%s)",
                        len(_learned_patterns),
                        ", ".join(_tech_names) if _tech_names else "generic",
                    )

                if _similar_findings and self.state.iteration <= 16:
                    _f_lines = [
                        "[SYSTEM: SIMILAR TARGET FINDINGS — from past sessions on subdomains]"
                    ]
                    for _f in _similar_findings[:3]:
                        _desc = str(_f.get("description", ""))[:100]
                        _sev = str(_f.get("severity", "Info"))
                        _ftype = str(_f.get("finding_type", "unknown"))
                        _f_lines.append(f"- [{_sev}] {_ftype}: {_desc}")
                    self.state.conversation.append(
                        {"role": "system", "content": "\n".join(_f_lines)}
                    )
                    logger.info("Similar findings injected: %d", len(_similar_findings))
            except Exception as _pattern_err:
                logger.debug("Pattern learning injection failed: %s", _pattern_err)

        current_time = time.time()
        if self._last_request_time > 0:
            response_time = current_time - self._last_request_time
            self._request_times.append(response_time)

            avg_response_time = (
                sum(self._request_times) / len(self._request_times)
                if self._request_times
                else 0
            )

            if avg_response_time > 30:
                logger.warning(
                    "Slow response detected (avg: %.1fs), implementing throttling",
                    avg_response_time,
                )

                await asyncio.sleep(min(avg_response_time / 10, 2.0))

        self._last_request_time = current_time

        if not getattr(self, "_scope_lock_active", False):
            self._sync_phase_objectives(current_phase)
            self._update_objectives_from_session(current_phase)

        _focus_trigger = self._no_tool_iterations >= 2 or (
            not self._ctf_mode
            and (self.state.iteration == 1 or self.state.iteration % 10 == 0)
        )
        if _focus_trigger:
            self.state.conversation = [
                msg
                for msg in self.state.conversation
                if not (
                    msg.get("content", "").startswith("[SYSTEM: OBJECTIVE FOCUS")
                    or msg.get("content", "").startswith("<objective_focus")
                )
            ]
            focus_ctx = self.state.build_focus_context(
                current_phase.value,
                max_objectives=4,
                max_evidence=6,
            )
            if focus_ctx:
                self.state.conversation.append({"role": "system", "content": focus_ctx})

            if not self._ctf_mode:
                self.state.conversation = [
                    msg
                    for msg in self.state.conversation
                    if not msg.get("content", "").startswith(
                        "[SYSTEM: QUALITY SCOREBOARD"
                    )
                ]
                quality_ctx = self._build_quality_scoreboard(current_phase)
                if quality_ctx:
                    self.state.conversation.append(
                        {"role": "system", "content": quality_ctx}
                    )

            self.state.resolve_hypotheses_from_evidence()
            self.state.conversation = [
                msg
                for msg in self.state.conversation
                if not msg.get("content", "").startswith("<hypothesis_queue")
            ]
            hyp_ctx = self.state.build_hypothesis_context(max_pending=4)
            if hyp_ctx:
                self.state.conversation.append({"role": "system", "content": hyp_ctx})

            _confirmed_hyp_vulns: list[dict[str, Any]] = [
                {
                    "finding": h.get("claim", ""),
                    "type": next(iter(h.get("tags", ["unknown"])), "unknown"),
                    "severity": "HIGH",
                    "proof": "; ".join(str(r) for r in h.get("evidence_refs", []))[
                        :200
                    ],
                }
                for h in self.state.hypothesis_queue
                if h.get("status") == "confirmed"
            ]
            _session_vulns = (
                list(self._session.vulnerabilities) if self._session else []
            )
            _all_vulns_for_chains = _session_vulns + _confirmed_hyp_vulns
            if current_phase.value == "EXPLOIT" and _all_vulns_for_chains:
                try:
                    _existing_ids = {
                        str(c.get("chain_id", "")) for c in self.state.exploit_chains
                    }
                    _new_chains = plan_chains(
                        vulnerabilities=_all_vulns_for_chains,
                        existing_chain_ids=_existing_ids,
                        iteration=self.state.iteration,
                        max_chains=3,
                        workflow_context=(
                            self._session.app_model.export_workflow_context()
                            if self._session and getattr(self._session, "app_model", None)
                            else None
                        ),
                        causal_hypotheses=[
                            h.__dict__
                            for h in getattr(
                                getattr(self._session, "causal_state", None),
                                "hypotheses",
                                [],
                            )
                        ],
                    )
                    for _nc in _new_chains:
                        self.state.exploit_chains.append(_asdict(_nc))
                        logger.info(
                            "Exploit chain planned: %s (basis: %s)",
                            _nc.name,
                            _nc.vuln_basis[:60],
                        )

                    _ec_objs: list[_ExploitChain] = []
                    for _cd in self.state.exploit_chains:
                        try:
                            _steps = [
                                _ChainStep(**s) if isinstance(s, dict) else s
                                for s in _cd.get("steps", [])
                            ]
                            _chain_obj = _ExploitChain(
                                chain_id=str(_cd.get("chain_id", "")),
                                name=str(_cd.get("name", "")),
                                description=str(_cd.get("description", "")),
                                steps=_steps,
                                current_step_index=int(
                                    _cd.get("current_step_index", 0)
                                ),
                                status=str(_cd.get("status", "planning")),
                                phase_formed=str(_cd.get("phase_formed", "EXPLOIT")),
                                vuln_basis=str(_cd.get("vuln_basis", "")),
                                iteration_formed=int(_cd.get("iteration_formed", 0)),
                            )
                            _ec_objs.append(_chain_obj)
                        except Exception as _chain_hydrate_err:
                            logger.debug(
                                "Chain hydration error: %s", _chain_hydrate_err
                            )
                    chain_ctx = build_chain_context(_ec_objs, max_chains=2)
                    if chain_ctx:
                        self.state.conversation = [
                            m
                            for m in self.state.conversation
                            if not m.get("content", "").startswith(
                                "<exploit_chain_plan>"
                            )
                        ]
                        self.state.conversation.append(
                            {
                                "role": "system",
                                "content": chain_ctx,
                            }
                        )
                except Exception as _cp_err:
                    logger.debug("Chain planner error: %s", _cp_err)

        trace_id = getattr(self, "_current_trace_id", None)
        if trace_id:
            _trace_chat_event(
                trace_id, "iteration_prepare", iteration=self.state.iteration
            )

        explore_ctx = self._build_exploration_directive(current_phase)
        if explore_ctx:
            self.state.conversation = [
                msg
                for msg in self.state.conversation
                if not msg.get("content", "").startswith(
                    "[SYSTEM: AGGRESSIVE EXPLORATION"
                )
            ]
            self.state.conversation.append({"role": "system", "content": explore_ctx})

        dataset_hint = self._build_dataset_hint(current_phase)
        if dataset_hint:
            self.state.conversation = [
                msg
                for msg in self.state.conversation
                if not msg.get("content", "").startswith("[SYSTEM: KNOWLEDGE BASE")
            ]
            self.state.conversation.append({"role": "system", "content": dataset_hint})

        web_search_hint = self._build_web_search_hint(current_phase)
        if web_search_hint:
            self.state.conversation = [
                msg
                for msg in self.state.conversation
                if not msg.get("content", "").startswith("[SYSTEM: WEB SEARCH")
            ]
            self.state.conversation.append({"role": "system", "content": web_search_hint})

        if self.state.iteration == 1 and not self._ctf_mode:
            self.state.conversation.append(
                {
                    "role": "system",
                    "content": (
                        "[SYSTEM: MANDATORY PLANNING STEP]\n"
                        "Write a brief, goal-oriented plan for your engagement.\n"
                        "Immediately execute the first step of Phase 1 (initial recon, scripts, OSINT) AFTER outputting your plan. Do not wait."
                    ),
                }
            )

            self.state.planned_tools.clear()

        revision_interval = cfg.agent_plan_revision_interval
        if (
            not self._ctf_mode
            and revision_interval > 0
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
            self.state.conversation = [
                msg
                for msg in self.state.conversation
                if not msg.get("content", "").startswith(
                    "[SYSTEM: MANDATORY PLAN REVISION"
                )
            ]
            self.state.conversation.append(
                {
                    "role": "system",
                    "content": (
                        f"[SYSTEM: MANDATORY PLAN REVISION — iteration {self.state.iteration}]{session_info}\n"
                        "Your original plan may be stale. REVISED PLANNING REQUIRED:\n"
                        "1. Compare original plan vs actual findings\n"
                        "2. What has WORKED? What has FAILED?\n"
                        "3. Adjust strategy: which phases to SKIP, which to PRIORITIZE?\n"
                        "4. What is the single most valuable next action?\n"
                        "Output revised plan, then continue."
                    ),
                }
            )

        if self.state.iteration > 1 and self.state.iteration % 5 == 0:
            session_info = ""
            pipeline_prompt = ""

            if self._session:
                s = self._session

                if self.pipeline:
                    self.pipeline._current_iteration = self.state.iteration

                if (
                    self.pipeline
                    and not getattr(self, "_scope_lock_active", False)
                    and self.pipeline.should_transition()
                ):
                    _prev_phase = self.pipeline.get_current_phase()
                    new_phase = self.pipeline.transition()
                    if new_phase:
                        pipeline_prompt = self.pipeline.get_transition_prompt(new_phase)

                        self._compact_phase_context(
                            _prev_phase.value if _prev_phase else "RECON"
                        )

                        from airecon.proxy.agent.pipeline import (
                            PipelinePhase as _PP,
                        )

                        if new_phase == _PP.EXPLOIT:
                            self._inject_exploit_vuln_context()

                        self._stagnation_iterations = 0
                        logger.debug(
                            "Phase transition to %s — stagnation counter reset",
                            new_phase.value,
                        )
                elif self.pipeline:
                    pipeline_prompt = "\n" + self.pipeline.get_phase_prompt()

                if self._ctf_mode:
                    _ctf_recent: list[str] = []
                    for _te in list(self.state.tool_history)[-6:]:
                        _cmd = ""
                        if getattr(_te, "tool_name", "") == "execute":
                            _cmd = str((_te.arguments or {}).get("command", ""))[:80]
                        elif getattr(_te, "tool_name", ""):
                            _cmd = _te.tool_name
                        if _cmd:
                            _rc = (
                                (_te.result or {}).get("exit_code", "?")
                                if isinstance(getattr(_te, "result", None), dict)
                                else "?"
                            )
                            _ctf_recent.append(f"rc={_rc}: {_cmd}")
                    _tried_str = (
                        " | recent: " + "; ".join(_ctf_recent) if _ctf_recent else ""
                    )
                    session_info = (
                        "\n[CTF SESSION SUMMARY] "
                        f"urls={len(s.urls)} "
                        f"live_hosts={len(s.live_hosts)} "
                        f"injection_points={len(s.injection_points)} "
                        f"vulns={len(s.vulnerabilities)} "
                        f"tools={len(s.tools_run)}"
                        f"{_tried_str}"
                    )
                else:
                    session_info = "\n" + session_to_context(s)

                    _app_ctx = s.app_model.build_context()
                    if _app_ctx:
                        session_info += "\n" + _app_ctx

            self.state.conversation = [
                msg
                for msg in self.state.conversation
                if not msg.get("content", "").startswith(
                    "[SYSTEM: EXECUTION CHECKPOINT"
                )
            ]
            self.state.conversation.append(
                {
                    "role": "system",
                    "content": (
                        f"[SYSTEM: EXECUTION CHECKPOINT — Itr {self.state.iteration}]"
                        f"{session_info}\n\n"
                        f"{pipeline_prompt}"
                        "MANDATORY ACTION: Your NEXT response MUST be a tool call — NOT text, NOT a plan, NOT a code block. "
                        "Pick the highest-value next action and call the tool immediately. "
                        "Writing commands as text does nothing. Only tool calls execute. "
                        "If all objectives are complete, output [TASK_COMPLETE]."
                    ),
                }
            )

        if self._ctf_mode:
            _max_itr = self._override_max_iterations or self._CTF_MAX_ITERATIONS
            _m33 = max(5, _max_itr // 3)
            _m66 = max(10, (_max_itr * 2) // 3)
            if self.state.iteration in (_m33, _m66):
                _pct = 33 if self.state.iteration == _m33 else 66

                _tool_names_used = sorted({k[0] for k in self._executed_tool_counts})
                _tools_str = (
                    ", ".join(_tool_names_used) if _tool_names_used else "none yet"
                )
                _recent_cmds: list[str] = []
                for _te in list(self.state.tool_history)[-10:]:
                    if getattr(_te, "tool_name", "") == "execute":
                        _c = str((_te.arguments or {}).get("command", ""))[:100]
                        if _c:
                            _recent_cmds.append(_c)
                _recent_str = (
                    "\nRecent commands: " + " | ".join(_recent_cmds[-5:])
                    if _recent_cmds
                    else ""
                )
                self.state.conversation.append(
                    {
                        "role": "system",
                        "content": (
                            f"[SYSTEM: CTF STRATEGY AUDIT — {_pct}% of budget used]\n"
                            f"Tools used so far: {_tools_str}"
                            f"{_recent_str}\n"
                            "Self-audit required:\n"
                            "1. What attack surfaces / vulnerability classes have you NOT tested yet?\n"
                            "2. What authentication mechanisms exist that you haven't probed?\n"
                            "3. What data flows or state-changing endpoints are unexplored?\n"
                            "4. Are there any cookie values, session tokens, or API responses you haven't analyzed?\n"
                            "Based on your self-audit, pivot to the most promising UNTESTED attack class immediately. "
                            "Reply with a tool call."
                        ),
                    }
                )
                logger.debug(
                    "CTF milestone self-audit injected at iteration %d (%d%% of %d)",
                    self.state.iteration,
                    _pct,
                    _max_itr,
                )

        try:
            _corr_interval = max(
                1, int(getattr(cfg, "intelligence_correlation_interval", 6))
            )
        except (TypeError, ValueError):
            _corr_interval = 6
        if self.state.iteration > 1 and self.state.iteration % _corr_interval == 0:
            vuln_chaining_prompt = ""
            correlation_prompt = ""
            expert_testing_prompt = ""
            graph_chain_prompt = ""
            novel_chain_prompt = ""

            if self._session:
                s = self._session

                if s.open_ports or s.technologies or s.injection_points:
                    from ..correlation import (
                        run_correlation,
                    )

                    correlations = run_correlation(s)
                    if correlations:
                        corr_lines = [
                            "\n[OUTPUT CORRELATION - Attack Surface Analysis]"
                        ]
                        for corr in correlations[:15]:
                            severity = corr.get("severity", "MEDIUM")
                            vuln_type = corr.get("type", "correlation")

                            if vuln_type == "port":
                                port = corr.get("port", "?")
                                service = corr.get("service", "?")
                                vulns = corr.get("vulnerabilities", [])
                                tools = corr.get("tools", [])
                                vuln_str = (
                                    "; ".join(vulns[:2]) if vulns else "Multiple issues"
                                )
                                tool_str = f" | tool: {tools[0]}" if tools else ""
                                corr_lines.append(
                                    f"- [{severity}] Port {port} ({service}): {vuln_str}{tool_str}"
                                )

                            elif vuln_type == "technology":
                                tech = corr.get("technology", "?")
                                vulns = corr.get("vulnerabilities", [])
                                tools = corr.get("tools", [])
                                paths = corr.get("paths", [])
                                vuln_str = (
                                    "; ".join(vulns[:2]) if vulns else "Multiple issues"
                                )
                                extra = ""
                                if tools:
                                    extra += f" | tool: {tools[0]}"
                                if paths:
                                    extra += f" | paths: {', '.join(paths[:2])}"
                                corr_lines.append(
                                    f"- [{severity}] Tech {tech}: {vuln_str}{extra}"
                                )

                            elif vuln_type == "technology_cve":
                                tech = corr.get("technology", "?")
                                vulns = corr.get("vulnerabilities", [])
                                vuln_str = vulns[0] if vulns else "Multiple issues"
                                corr_lines.append(
                                    f"- [{severity}] {tech} CVE: {vuln_str}"
                                )

                            elif vuln_type == "url_path":
                                path = corr.get("path", "?")
                                tech = corr.get("technology", "?")
                                vulns = corr.get("vulnerabilities", [])
                                tools = corr.get("tools", [])
                                vuln_str = f": {vulns[0]}" if vulns else ""
                                tool_str = f" | tool: {tools[0]}" if tools else ""
                                corr_lines.append(
                                    f"- [{severity}] Path '{path}' → {tech}{vuln_str}{tool_str}"
                                )

                            elif vuln_type == "injection_chain":
                                inj_type = corr.get("injection_type", "?")
                                chain_name = corr.get("chain_name", "?")
                                count = corr.get("param_count", 0)
                                params_sample = corr.get("sample_params", [])
                                steps = corr.get("steps", [])
                                steps_str = " → ".join(
                                    _chain_step_to_text(s) for s in steps
                                )
                                params_str = (
                                    ", ".join(params_sample)
                                    if params_sample
                                    else "discovered params"
                                )
                                corr_lines.append(
                                    f"- [{severity}] INJECTION SURFACE ({inj_type}, "
                                    f"{count} params: {params_str}) → Chain: {chain_name}: {steps_str}"
                                )

                            elif vuln_type == "expert_test":
                                pattern = corr.get("pattern", "?")
                                desc = corr.get("description", "?")
                                actions = corr.get("suggested_actions", [])
                                act_lines = [f"  >> {a}" for a in actions[:2]]
                                act_str = (
                                    ("\n" + "\n".join(act_lines)) if act_lines else ""
                                )
                                corr_lines.append(
                                    f"- [{severity}] EXPERT TEST ({pattern}): {desc}{act_str}"
                                )

                            elif vuln_type == "zeroday_potential":
                                pattern = corr.get("pattern", "?")
                                desc = corr.get("description", "?")
                                vectors = corr.get("test_vectors", [])
                                vec_lines = [f"  >> {v}" for v in vectors[:2]]
                                vec_str = (
                                    ("\n" + "\n".join(vec_lines)) if vec_lines else ""
                                )
                                corr_lines.append(
                                    f"- [{severity}] ZERO-DAY ({pattern}): {desc}{vec_str}"
                                )

                            elif vuln_type == "business_logic":
                                pattern = corr.get("pattern", "?")
                                desc = corr.get("description", "?")
                                actions = corr.get("suggested_actions", [])
                                act_lines = [f"  >> {a}" for a in actions[:2]]
                                act_str = (
                                    ("\n" + "\n".join(act_lines)) if act_lines else ""
                                )
                                corr_lines.append(
                                    f"- [{severity}] BUSINESS LOGIC ({pattern}): {desc}{act_str}"
                                )

                            elif vuln_type == "attack_chain":
                                name = corr.get("name", "?")
                                steps = corr.get("steps", [])
                                steps_str = " → ".join(
                                    _chain_step_to_text(s) for s in steps
                                )
                                corr_lines.append(
                                    f"- [{severity}] ATTACK CHAIN DETECTED "
                                    f"({name}): {steps_str}"
                                )

                            elif vuln_type == "synthesized_chain":
                                title = corr.get("title", "?")
                                confidence = corr.get("confidence", 0.0)
                                steps = corr.get("steps", [])
                                steps_str = " → ".join(
                                    _chain_step_to_text(s) for s in steps[:5]
                                )
                                corr_lines.append(
                                    f"- [{severity}] SYNTHESIZED CHAIN "
                                    f"(conf={confidence:.0%}) {title}"
                                    + (f": {steps_str}" if steps_str else "")
                                )

                            else:
                                corr_lines.append(
                                    f"- [{severity}] Unknown Correlation: {corr}"
                                )

                        correlation_prompt = "\n".join(corr_lines)

                if len(s.vulnerabilities) >= 2:
                    vuln_titles = [
                        v.get("title", v.get("finding", "?"))
                        for v in s.vulnerabilities[:10]
                    ]
                    vuln_chaining_prompt = (
                        f"\n\n[VULNERABILITY CHAINING ANALYSIS]\n"
                        f"You have {len(s.vulnerabilities)} vulnerabilities. Consider chaining:\n"
                        f"Current vulns: {'; '.join(vuln_titles)}\n"
                        f"Analyze if combining these can lead to greater impact:\n"
                        f"- Can XSS be combined with CSRF for session hijacking?\n"
                        f"- Can IDOR + broken auth lead to account takeover?\n"
                        f"- Can SSRF + cloud metadata = full cloud compromise?\n"
                        f"Document attack chains in output/attack_chains.txt"
                    )

                if len(s.vulnerabilities) >= 2:
                    try:
                        graph_chain_prompt, chains = _build_graph_chain_prompt(
                            s.vulnerabilities,
                        )
                        if chains:
                            # Persist chains to session memory for cross-session learning
                            try:
                                from ..memory import get_memory_manager
                                memory = get_memory_manager()
                                for chain in chains:
                                    memory.save_chain_discovery({
                                        "chain_id": chain.chain_id,
                                        "name": chain.name,
                                        "combined_severity": chain.combined_severity,
                                        "attack_path": chain.attack_path,
                                        "reasoning": chain.reasoning,
                                        "findings": chain.findings,
                                        "relation_types": chain.relation_types,
                                        "target": getattr(s, 'target', ''),
                                        "discovered_at": __import__('datetime').datetime.now().isoformat(),
                                    })
                            except Exception as _mem_err:
                                logger.debug("Failed to persist correlation chains: %s", _mem_err)
                    except Exception as _corr_err:
                        logger.debug("Graph-based correlation failed: %s", _corr_err)

                if s.vulnerabilities:
                    try:
                        # Populate the target-specific LLM vector cache every few
                        # iterations so the (sync) prompt builder below can surface
                        # genuinely novel, finding-grounded tactics instead of a
                        # generic checklist. No-ops if the backend is unconfigured;
                        # the prompt builder then falls back to evidence-derived
                        # tactics selected from the observed signals.
                        if len(s.vulnerabilities) >= 2 and self.state.iteration % 4 == 0:
                            from .novel_discovery import generate_llm_novel_vectors

                            await generate_llm_novel_vectors(s.vulnerabilities)
                    except Exception as _llm_novel_err:
                        logger.debug(
                            "LLM novel-vector generation skipped: %s", _llm_novel_err
                        )
                    try:
                        novel_chain_prompt = _build_novel_discovery_prompt(
                            s.vulnerabilities,
                            self.state.iteration,
                        )
                    except Exception as _novel_err:
                        logger.debug("Novel discovery prompt failed: %s", _novel_err)

                # Inject the senior-pentester methodology scaffold when there is a
                # REAL attack surface to test (discovered endpoints + concrete
                # injection points / findings) — not on narrow URL-keyword guesses.
                # The previous keyword→canned-hint matcher was removed: it spoon-fed
                # generic advice ("api → fuzz with ffuf") on crude substring matches,
                # which biased a capable model toward a fixed playbook and was, in
                # fact, dead (its strings were discarded — testing.txt has no
                # placeholder). The model now reasons over the real surface below.
                _has_surface = bool(s.urls) and bool(
                    getattr(s, "injection_points", None) or s.vulnerabilities
                )
                if _has_surface:
                    try:
                        prompt_path = (
                            Path(__file__).parent.parent / "prompts" / "testing.txt"
                        )
                        with open(prompt_path, "r") as pf:
                            expert_template = pf.read()
                        # Ground the methodology in the ACTUAL discovered surface so
                        # it is target-specific, not a generic checklist.
                        _eps = [str(u) for u in (s.urls or [])][:12]
                        _ips = [
                            f"{ip.get('method','GET')} {ip.get('url','')} "
                            f"param={ip.get('parameter','')}".strip()
                            for ip in (getattr(s, "injection_points", None) or [])[:12]
                        ]
                        surface_lines = []
                        if _eps:
                            surface_lines.append(
                                "Discovered endpoints:\n"
                                + "\n".join(f"  - {e}" for e in _eps)
                            )
                        if _ips:
                            surface_lines.append(
                                "Concrete injection points:\n"
                                + "\n".join(f"  - {p}" for p in _ips)
                            )
                        surface_str = "\n".join(surface_lines)
                        expert_testing_prompt = (
                            "\n\n"
                            + expert_template
                            + ("\n\nATTACK SURFACE FOR THIS TARGET:\n" + surface_str if surface_str else "")
                        )
                    except Exception as _tmpl_err:
                        logger.debug(
                            "Could not load testing.txt methodology: %s", _tmpl_err
                        )

            if correlation_prompt or vuln_chaining_prompt or expert_testing_prompt or graph_chain_prompt or novel_chain_prompt:
                self.state.conversation.append(
                    {
                        "role": "system",
                        "content": (
                            f"[SYSTEM: ANALYSIS — Itr {self.state.iteration}]"
                            f"{correlation_prompt}"
                            f"{vuln_chaining_prompt}"
                            f"{graph_chain_prompt}"
                            f"{novel_chain_prompt}"
                            f"{expert_testing_prompt}\n"
                        ),
                    }
                )

        if self.state.iteration % 5 == 0 and self._has_scan_work():
            save_session(self._session)

        _presummary_ratio = self.state.token_usage.get("used", 0) / max(
            self._adaptive_num_ctx or cfg.llm_context_window, 1
        )
        # Roomy-context models can tolerate more token pressure before we
        # compress. Decided by the effective context window (model-agnostic),
        # not by matching a specific model family in the name.
        _effective_ctx = int(self._adaptive_num_ctx or cfg.llm_context_window or 0)
        _is_roomy_context = _effective_ctx >= _ROOMY_CONTEXT_TOKENS
        _pressure_threshold = 0.45 if _is_roomy_context else 0.35
        _compress_threshold = 0.38 if _is_roomy_context else 0.30
        _background_interval = 8 if _is_roomy_context else 5
        _background_floor = 0.22 if _is_roomy_context else 0.0

        _pressure_compress = (
            self.state.iteration > 0 and _presummary_ratio >= _pressure_threshold
        )
        _compress_now = self.state.iteration > 0 and (
            _presummary_ratio >= _compress_threshold
            or (
                self.state.iteration % _background_interval == 0
                and _presummary_ratio >= _background_floor
            )
        )
        if _compress_now:
            self._compress_old_tool_outputs(
                aggressive=_pressure_compress or self.state.iteration > 50
            )
            pinned = self._build_compressed_findings_summary()
            if pinned:
                self.state.conversation = [
                    m
                    for m in self.state.conversation
                    if not m.get("content", "").startswith("[SYSTEM: PINNED CONTEXT")
                ]
                self.state.conversation.append(
                    {
                        "role": "system",
                        "content": pinned,
                    }
                )

        _cur_ctx_limit = self._adaptive_num_ctx or cfg.llm_context_window
        _cur_num_predict = self._get_iteration_num_predict(
            cfg, current_phase, _cur_ctx_limit
        )

        _cur_effective_ctx = max(1024, _cur_ctx_limit - _cur_num_predict)
        _cur_token_ratio = self.state.token_usage.get("used", 0) / max(
            _cur_effective_ctx, 1
        )
        _early_pressure = _cur_token_ratio >= 0.40
        _aggressive = self._ctf_mode or _early_pressure or self.state.iteration > 100

        if self.state.iteration % 5 == 0 or _aggressive:
            if self.state.iteration >= 20:
                self._prune_stale_skills(max_age_iterations=10)

            if hasattr(self.state, "token_usage"):
                self.state.token_usage["used"] = (
                    self._recompute_used_tokens_from_conversation()
                )

            current_phase = (
                self._get_current_phase().value
                if self._get_current_phase()
                else "RECON"
            )

            _compress_ctx = min(8192, _cur_ctx_limit // 4)
            _keep_recent = 40 if _is_roomy_context else 30
            try:
                await self.state.compress_with_llm(
                    self.llm,
                    keep_recent=_keep_recent,
                    num_ctx=_compress_ctx,
                    num_predict=1024,
                    phase=current_phase,
                )

                self.state.token_usage["used"] = (
                    self._recompute_used_tokens_from_conversation()
                )
                logger.info(
                    "Compression: token_usage after compression = %d",
                    self.state.token_usage["used"],
                )
            except Exception as compress_err:
                logger.warning(
                    "LLM compression failed (%s) — using aggressive truncate",
                    str(compress_err)[:100],
                )
                self.state.conversation = self.state.conversation[:50]

            self.state.token_usage["used"] = (
                self._recompute_used_tokens_from_conversation()
            )

            _token_used = self.state.token_usage.get("used", 0)
            _ctx_limit = self._adaptive_num_ctx or cfg.llm_context_window
            if _token_used > _ctx_limit * 0.8:
                logger.warning(
                    "Token limit exceeded (%d/%d) - forcing aggressive truncation",
                    _token_used,
                    _ctx_limit,
                )
                self.state.conversation = self.state.conversation[:40]

            critical_context = self._build_critical_findings_context()

            if self.state.iteration < 100:
                _max_msgs = 150
            elif self.state.iteration < 200:
                _max_msgs = 120
            elif self.state.iteration < 300:
                _max_msgs = 100
            else:
                _max_msgs = 80
            self.state.truncate_conversation(max_messages=_max_msgs)

            if critical_context:
                self.state.conversation.append(
                    {"role": "system", "content": critical_context}
                )

        if self.state.iteration > 1 and self.state.iteration % 10 == 0:
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
                history_ctx = self._build_recent_history_context(last_n=10)
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

        _caido_list_used = self.state.tool_counts.get("caido_list_requests", 0)
        _caido_send_used = self.state.tool_counts.get("caido_send_request", 0)
        _caido_auto_used = self.state.tool_counts.get("caido_automate", 0)
        if (
            getattr(self, "_caido_available", False)
            and 0 < self.state.iteration <= 30
            and self.state.iteration % 5 == 0
            and _caido_list_used == 0
            and _caido_send_used == 0
            and _caido_auto_used == 0
        ):
            self.state.conversation = [
                msg
                for msg in self.state.conversation
                if not msg.get("content", "").startswith("[SYSTEM: CAIDO REMINDER")
            ]
            self.state.conversation.append(
                {
                    "role": "system",
                    "content": (
                        "[SYSTEM: CAIDO REMINDER] "
                        "Caido proxy is active and has captured HTTP traffic, "
                        "but you have NOT called caido_list_requests yet. "
                        "Call it NOW with filter=target to retrieve all captured "
                        "requests. Real traffic reveals hidden endpoints, auth tokens, "
                        "injection parameters, and app behavior that scanners miss."
                    ),
                }
            )

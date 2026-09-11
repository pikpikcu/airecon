from __future__ import annotations

import json
import logging
import re
import warnings
from pathlib import Path
from typing import Any

from .pipeline import PipelinePhase
from .tool_scorer import (
    build_tool_recommendation_context,
    rank_tools_for_phase,
)

logger = logging.getLogger("airecon.agent")

_tools_meta_path = Path(__file__).parent.parent / "data" / "tools_meta.json"
try:
    with open(_tools_meta_path, "r") as f:
        _TOOLS_META = json.load(f)
except (OSError, json.JSONDecodeError) as _e:
    warnings.warn(f"tools_meta.json unavailable ({_e}); tool catalog features disabled.")
    _TOOLS_META = {}


# ── Safe string sanitizer for evidence text (prompt injection mitigation) ───

_REPORT_ESCAPE_TABLE = str.maketrans({
    "[": "〔",
    "]": "〕",
})


def _sanitize_evidence_text(value: str) -> str:
    """Strip potential prompt-injection markers from external evidence.

    We don't strip everything — LLM needs the raw data for reports — but we
    neutralize SYSTEM: / INJECT: style markers by bracketing the evidence
    block so the model treats it as quoted data, not instructions.
    """
    return value.strip()


class _CycleLlmMixin:
    _REPORT_PACKET_MAX_CHARS = 32_000  # global cap on entire evidence packet
    _REPORT_EVIDENCE_PER_VULN = 2000   # per-vuln cap for evidence + analysis
    _REPORT_MAX_VULNS = 50             # only report top N vulns by severity

    def _build_report_phase_evidence(self) -> str:

        if not self._session or not self._session.vulnerabilities:
            return ""

        # Only inject once — detect by checking if evidence was already pinned.
        if getattr(self, "_report_evidence_injected", False):
            return ""
        self._report_evidence_injected = True

        _SEVERITY_ORDER = {
            "critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4,
            "unknown": 5,
        }

        # Sort by severity; cap number of vulns reported
        sorted_vulns = sorted(
            self._session.vulnerabilities,
            key=lambda v: (
                _SEVERITY_ORDER.get(
                    str(v.get("severity", "unknown")).lower(), 5
                ),
                str(v.get("title", "")),
            ),
        )
        capped_vulns = sorted_vulns[: self._REPORT_MAX_VULNS]

        truncated_count = len(self._session.vulnerabilities) - len(capped_vulns)

        parts: list[str] = [
            "[SYSTEM: REPORT PHASE — FULL VULNERABILITY EVIDENCE PACKET]",
            "The conversation history has been compressed during earlier phases.",
            "Below is the RAW evidence you must use when calling create_vulnerability_report.",
            "For EACH vulnerability, supply title, description, poc_description,",
            "poc_script_code, and the technical_analysis fields from the evidence below.",
            "",
        ]

        used_chars = 0

        for idx, vuln in enumerate(capped_vulns, 1):
            v_title = vuln.get("title", vuln.get("finding", f"Vulnerability #{idx}"))
            v_severity = vuln.get("severity", "unknown")
            v_confidence = vuln.get("confidence", "")
            v_flag = vuln.get("flag", "")

            # Core identification
            block_parts: list[str] = [
                f"--- VULNERABILITY #{idx} ---",
                f"Title: {v_title}",
                f"Severity: {v_severity}",
            ]
            if v_confidence:
                block_parts.append(f"Confidence: {v_confidence}")
            if v_flag:
                block_parts.append(f"FLAG: {v_flag}")
            if vuln.get("url"):
                block_parts.append(f"URL: {vuln['url']}")
            if vuln.get("endpoint"):
                block_parts.append(f"Endpoint: {vuln['endpoint']}")
            if vuln.get("parameter"):
                block_parts.append(f"Parameter: {vuln['parameter']}")
            if vuln.get("method"):
                block_parts.append(f"Method: {vuln['method']}")
            if vuln.get("source"):
                block_parts.append(f"Source: {vuln['source']}")

            # Evidence / proof data — sanitized and capped
            proof = vuln.get("proof") or vuln.get("evidence", "")
            if proof:
                proof_str = str(proof)
                if isinstance(proof, dict):
                    proof_parts_inner = []
                    for k, v in proof.items():
                        proof_parts_inner.append(f"  {k}: {_sanitize_evidence_text(str(v))}")
                    proof_str = "\n".join(proof_parts_inner)
                else:
                    proof_str = _sanitize_evidence_text(proof_str)

                if len(proof_str) > self._REPORT_EVIDENCE_PER_VULN:
                    proof_str = proof_str[:self._REPORT_EVIDENCE_PER_VULN - 10] + "\n... [truncated]"

                block_parts.append(f"Proof/Evidence:\n{proof_str}")

            # Technical analysis if available
            if vuln.get("technical_analysis"):
                tech = _sanitize_evidence_text(str(vuln["technical_analysis"]))
                tech_limit = self._REPORT_EVIDENCE_PER_VULN // 2
                if len(tech) > tech_limit:
                    tech = tech[:tech_limit - 10] + "\n... [truncated]"
                block_parts.append(f"Technical Analysis:\n{tech}")

            # Remediation if available
            if vuln.get("remediation"):
                block_parts.append(f"Remediation: {vuln['remediation']}")

            # CVE if available
            if vuln.get("cve"):
                block_parts.append(f"CVE: {vuln['cve']}")

            # Exploit chain context if linked
            if vuln.get("exploit_chain"):
                block_parts.append(
                    f"Exploit chain: {vuln['exploit_chain']}"
                )

            block_parts.append("")
            block = "\n".join(block_parts)
            used_chars += len(block)

            # Global budget enforcement — stop adding if we've hit the cap
            if used_chars > self._REPORT_PACKET_MAX_CHARS:
                block = block[:80] + "\n... [truncated: budget exhausted]"
                parts.append(block)
                break

            parts.append(block)

        if truncated_count > 0:
            parts.append(
                f"[NOTE] {truncated_count} more vulnerabilities were found but "
                f"not listed here. Report ALL vulnerabilities, not just those shown."
            )

        # Also expose unreported vulns that the AI flagged but hasn't reported yet
        unreported = [
            v for v in self._session.vulnerabilities
            if not v.get("report_generated")
        ]
        if unreported and unreported != self._session.vulnerabilities:
            parts.append(
                f"[NOTE] {len(unreported)} of {len(self._session.vulnerabilities)} "
                "vulnerabilities still need reports. Generate reports for "
                "ALL items above."
            )
        elif unreported:
            parts.append(
                f"[TASK] Generate vulnerability reports for ALL {len(unreported)} "
                "findings listed above. Each report must include the proof/payload "
                "evidence shown."
            )

        result = "\n".join(parts)
        logger.info(
            "REPORT phase evidence packet built: %d vulns, %d chars (cap=%d)",
            len(self._session.vulnerabilities),
            len(result),
            self._REPORT_PACKET_MAX_CHARS,
        )
        return result

    def _check_phase_constraint(self, tool_name: str) -> tuple[str, str]:
        """Return (mode, advisory_message) for a tool call.

        Mode is always 'advisory' — phase guidance never blocks execution.
        The advisory message is empty when the tool is phase-appropriate or
        when accumulated evidence justifies a cross-phase pivot (≥3 evidence
        items in the log). Callers may log the message but must not abort.
        """
        from .tool_scorer import _PHASE_BLOCKED_TOOLS

        if not self.pipeline:
            return "off", ""

        current_phase = self.pipeline.get_current_phase().value
        blocked_tools = _PHASE_BLOCKED_TOOLS.get(current_phase, set())

        if tool_name.lower() not in {t.lower() for t in blocked_tools}:
            return "advisory", ""

        # Evidence-driven cross-phase pivot: if the session already has
        # meaningful findings, the agent may freely pivot across phases.
        evidence_count = len(self.state.evidence_log) if self.state else 0
        if evidence_count >= 3:
            return "advisory", ""

        return (
            "advisory",
            f"[PHASE ADVISORY] Tool '{tool_name}' is outside the usual {current_phase} tool set.\n"
            f"Use it only if current evidence clearly justifies a cross-phase pivot.",
        )

    def _inject_tool_intelligence(self, wrong_tool_picked: str = "") -> None:

        if not self._tools_llm:
            return

        current_phase = (
            self.pipeline.get_current_phase().value
            if self.pipeline
            else "RECON"
        )

        tool_use_counts: dict[str, int] = {}
        tool_success_counts: dict[str, int] = {}
        tool_failure_counts: dict[str, int] = {}

        if self._session:
            for tool_name, count in getattr(self._session, "tool_counts", {}).items():
                tool_use_counts[tool_name] = count

        recent_tool_names: list[str] = []
        for entry in getattr(self.state, "tool_history", [])[-8:]:
            tool_name = getattr(entry, "tool_name", "")
            if tool_name:
                recent_tool_names.append(str(tool_name))

        tested_vuln_classes: set[str] = set()
        classifier = None
        try:
            from .vuln_classifier import get_classifier

            classifier = get_classifier()
        except Exception as e:
            logger.debug("Failed to load classifier for tested vuln tracking: %s", e)
            classifier = None

        def _collect_labels(text: str) -> None:
            if not classifier or not str(text or "").strip():
                return
            try:
                tested_vuln_classes.update(classifier.resolve_labels(str(text)))
                result = classifier.classify(str(text))
                if result.category and result.category != "UNKNOWN":
                    tested_vuln_classes.add(result.category)
                if result.subcategory:
                    tested_vuln_classes.add(result.subcategory)
            except Exception as e:
                logger.debug("Failed to collect vuln labels from text: %s", e)
                return

        for ev in getattr(self.state, "evidence_log", [])[-20:]:
            if not isinstance(ev, dict):
                continue
            _collect_labels(ev.get("summary", ""))
            for tag in ev.get("tags", []) or []:
                _collect_labels(str(tag))

        if self._session:
            for vuln in getattr(self._session, "vulnerabilities", [])[-20:]:
                if not isinstance(vuln, dict):
                    continue
                _collect_labels(vuln.get("title") or vuln.get("finding") or "")

        adaptive_tool_scores: dict[str, float] = {}
        strategy_tool_sequence: list[str] = []
        try:
            engine = self._ensure_adaptive_learning_engine()
            techs = []
            target_type = ""
            if self._session:
                techs = list(getattr(self._session, "technologies", {}).keys())
                target_type = ", ".join(techs) or getattr(self._session, "target", "")

            adaptive_tool_scores = {
                str(name): float(score)
                for name, score in engine.recommend_tools(
                    phase=current_phase,
                    tech_stack=techs,
                    target_type=target_type,
                    exclude=sorted(getattr(self, "_blocked_tools", set())),
                    top_n=8,
                )
            }

            strategy_conditions: dict[str, Any] = {"phase": current_phase}
            if techs:
                strategy_conditions["tech"] = sorted(techs)[0]
            strategy = engine.recommend_strategy(strategy_conditions)
            if strategy and getattr(strategy, "tool_sequence", None):
                strategy_tool_sequence = [
                    str(tool) for tool in strategy.tool_sequence if str(tool).strip()
                ]
        except Exception as exc:
            logger.debug("Adaptive ranking hints unavailable: %s", exc)

        budget_remaining: dict[str, int] = {}
        if self.pipeline:
            from .pipeline import _PHASE_TOOL_BUDGETS
            phase_budget = _PHASE_TOOL_BUDGETS.get(current_phase, {})
            for tool_name, max_count in phase_budget.items():
                used = tool_use_counts.get(tool_name, 0)
                budget_remaining[tool_name] = max(0, max_count - used)

        chain_step_hint = ""
        if self.state.exploit_chains:
            for chain in self.state.exploit_chains:
                if chain.get("status") in ("planning", "active"):
                    cur_idx = chain.get("current_step_index", 0)
                    steps = chain.get("steps", [])
                    if cur_idx < len(steps):
                        chain_step_hint = steps[cur_idx].get("tool_hint", "")
                        break

        ranked_tools = rank_tools_for_phase(
            self._tools_llm,
            current_phase=current_phase,
            tool_use_counts=tool_use_counts,
            tool_success_counts=tool_success_counts,
            tool_failure_counts=tool_failure_counts,
            budget_remaining=budget_remaining,
            chain_step_hint=chain_step_hint,
            session_evidence_count=len(self.state.evidence_log),
            consecutive_failures=self._consecutive_failures,
            recent_tool_names=recent_tool_names,
            tested_vuln_classes=tested_vuln_classes or None,
            adaptive_tool_scores=adaptive_tool_scores or None,
            strategy_tool_sequence=strategy_tool_sequence or None,
        )

        if ranked_tools and len(ranked_tools) == len(self._tools_llm):
            self._tools_llm = ranked_tools

        rec_context = build_tool_recommendation_context(
            current_phase=current_phase,
            chain_step_hint=chain_step_hint,
            consecutive_failures=self._consecutive_failures,
            wrong_tool_picked=wrong_tool_picked,
            tool_registry=self._tools_llm,
        )

        if rec_context:
            self.state.conversation = [
                m for m in self.state.conversation
                if not m.get("content", "").startswith("<system_tool_intelligence>")
            ]
            self.state.conversation.append({
                "role": "system",
                "content": rec_context,
            })
            logger.debug(
                "Tool intelligence injected for phase=%s (chain_hint='%s', wrong_tool='%s', failures=%d)",
                current_phase, chain_step_hint, wrong_tool_picked, self._consecutive_failures,
            )

        # Inject per-target remembered intelligence (endpoints, vulns, bypasses)
        self._inject_target_memory()

        # Inject learned insights from adaptive learning engine
        self._inject_learned_insights(current_phase)

        # Inject learned tool and strategy recommendations from prior runs
        self._inject_adaptive_recommendations(current_phase)

        # Inject meta-reasoning self-reflection every N iterations
        self._inject_meta_reflection_context(current_phase)

    def _inject_target_memory(self) -> None:
        """Inject per-target intelligence into the conversation.

        If the current target has been scanned before, inject remembered
        endpoints, vulnerabilities, WAF bypasses, and sensitive params.
        """
        target = ""
        if self._session:
            target = getattr(self._session, "target", "")
        if not target:
            return

        if not hasattr(self, "_target_memory_store"):
            from .adaptive_learning import TargetMemoryStore
            self._target_memory_store = TargetMemoryStore()

        text = self._target_memory_store.get_injection_text(target)
        if not text:
            return

        # Remove any old injection before adding fresh one
        self.state.conversation = [
            m for m in self.state.conversation
            if not m.get("content", "").startswith("<target_intelligence:")
        ]
        self.state.conversation.append({
            "role": "system",
            "content": text,
        })
        logger.debug(
            "Target memory injected for %s (%d chars)",
            target,
            len(text),
        )

    def _inject_learned_insights(self, current_phase: str) -> None:
        """Inject learned insights from past sessions into the conversation.

        This is how airecon 'learns' — persistent knowledge from past
        observations gets surfaced as context so the agent doesn't start from
        scratch every session.
        """
        engine = self._ensure_adaptive_learning_engine()
        techs = []
        if self._session:
            techs = list(getattr(self._session, "technologies", {}).keys())

        insights = engine.get_insights_for_context(
            phase=current_phase,
            tech_stack=techs,
        )
        if not insights:
            return

        lines = [
            "<system_learned_insights>",
            "Based on past observations and analysis, the following insights may apply:",
            "",
        ]
        for i, ins in enumerate(insights, 1):
            lines.append(f"{i}. [{ins.category}] {ins.title}")
            if ins.conditions:
                lines.append(f"   Conditions: {ins.conditions}")
            lines.append(f"   Recommendation: {ins.recommendation}")
            lines.append(f"   Confidence: {ins.confidence:.2f} (from {ins.observation_count} observations)")
            lines.append("")

        lines.append("</system_learned_insights>")

        self.state.conversation = [
            m for m in self.state.conversation
            if not m.get("content", "").startswith("<system_learned_insights>")
        ]
        self.state.conversation.append({
            "role": "system",
            "content": "\n".join(lines),
        })
        logger.debug(
            "Learned insights injected: phase=%s, %d insights",
            current_phase,
            len(insights),
        )

    def _inject_adaptive_recommendations(self, current_phase: str) -> None:
        engine = self._ensure_adaptive_learning_engine()

        techs: list[str] = []
        target_type = ""
        if self._session:
            techs = list(getattr(self._session, "technologies", {}).keys())
            target_type = ", ".join(techs) or getattr(self._session, "target", "")

        tool_recs = engine.recommend_tools(
            phase=current_phase,
            tech_stack=techs,
            target_type=target_type,
            exclude=sorted(getattr(self, "_blocked_tools", set())),
            top_n=4,
        )

        strategy_conditions: dict[str, Any] = {"phase": current_phase}
        if techs:
            strategy_conditions["tech"] = sorted(techs)[0]
        strategy = engine.recommend_strategy(strategy_conditions)

        self.state.conversation = [
            m for m in self.state.conversation
            if not m.get("content", "").startswith("<system_adaptive_recommendations>")
        ]
        if not tool_recs and not strategy:
            return

        lines = [
            "<system_adaptive_recommendations>",
            f"Adaptive recommendations from prior runs for {current_phase}:",
        ]
        if tool_recs:
            lines.append("Preferred tools:")
            for tool_name, score in tool_recs:
                lines.append(f"- {tool_name} (learned score {score:.2f})")
        if strategy:
            lines.append("Suggested strategy:")
            lines.append(f"- {strategy.description}")
            if strategy.tool_sequence:
                lines.append(f"- Sequence: {' -> '.join(strategy.tool_sequence[:5])}")
            lines.append(f"- Reliability: {strategy.reliability:.2f}")
        lines.append("</system_adaptive_recommendations>")

        self.state.conversation.append({
            "role": "system",
            "content": "\n".join(lines),
        })
        logger.debug(
            "Adaptive recommendations injected: phase=%s, tools=%d, strategy=%s",
            current_phase,
            len(tool_recs),
            "yes" if strategy else "no",
        )

    def _inject_meta_reflection_context(self, current_phase: str) -> None:
        """Periodically inject meta-reasoning insights into conversation.

        Every 15 iterations, the engine self-reflects on its recent actions
        and stores hints like 'avoid repeating nmap — already ran 3 times'.
        These hints are injected so the agent learns from its own behavior.
        """
        if not hasattr(self, "_meta_reasoning_engine"):
            from .meta_reasoning import MetaReasoningEngine
            self._meta_reasoning_engine = MetaReasoningEngine()

        engine = self._meta_reasoning_engine
        if not engine.should_reflect(self.state.iteration):
            return

        # Build context of recent tool actions
        recent_actions = []
        if hasattr(self.state, "evidence_log"):
            for ev in self.state.evidence_log[-20:]:
                if isinstance(ev, dict):
                    recent_actions.append({
                        "iteration": ev.get("iteration", self.state.iteration),
                        "tool": ev.get("tool", ""),
                        "success": ev.get("success", False),
                    })

        vuln_count = len(self._session.vulnerabilities) if self._session else 0

        prompt = engine.build_reflection_prompt(
            phase=current_phase,
            recent_actions=recent_actions,
            failures=self._consecutive_failures,
            vulnerabilities_found=vuln_count,
            iterations_completed=self.state.iteration,
        )

        # Inject reflection prompt as system message — LLM will reflect
        # in its next response when it sees this context
        self.state.conversation.append({
            "role": "system",
            "content": prompt,
        })
        engine.last_reflection_iteration = self.state.iteration
        engine.record_reflection_hint(
            f"[iter={self.state.iteration}] phase={current_phase}, "
            f"failures={self._consecutive_failures}, vulns={vuln_count}, "
            f"recent_tools={[a.get('tool','?') for a in recent_actions[-5:]]}"
        )
        logger.info(
            "[MetaReasoning] Reflection injected at iteration %d (phase=%s, failures=%d)",
            self.state.iteration,
            current_phase,
            self._consecutive_failures,
        )

    def _analyze_llm_output(
        self,
        current_phase: Any,
        content_acc: str,
        thinking_acc: str,
        tool_calls_acc: list[dict[str, Any]],
    ) -> tuple[str, str, list[dict[str, Any]], bool]:
            combined_response = content_acc + " " + thinking_acc

            hallucination_signals = [
                "i have found",
                "the scan shows",
                "the results indicate",
                "my analysis shows",
                "it appears that",
                "based on my knowledge",
                "without running",
                "i don't have access to",
                "i will run",
                "let me run",
                "let me execute",
                "i'll run",
                "i'll execute",
                "i would run",
                "next, i'll",
                "i should run",
            ]
            combined_lower = combined_response.lower()
            has_hallucination_risk = any(
                signal in combined_lower for signal in hallucination_signals
            )

            has_fake_cmd_block = (
                bool(self._FAKE_CMD_BLOCK_RE.search(content_acc))
                or bool(self._FAKE_PLAIN_CMD_RE.search(content_acc))
            ) if not tool_calls_acc else False

            # Self-consistency check for critical LLM decisions
            if content_acc and not self._is_text_only_response(content_acc):
                self._check_critical_decision_consistency(content_acc, tool_calls_acc)

            is_exploit_phase = self.pipeline and self.pipeline.get_current_phase(
            ) == PipelinePhase.EXPLOIT
            has_vulns = self._session and len(
                self._session.vulnerabilities) > 0
            is_post_vuln_context = has_vulns and (
                is_exploit_phase or self.state.iteration > 15)

            _in_active_session = bool(self.state.active_target)
            _nudge_threshold_met = (
                is_post_vuln_context
                or (_in_active_session and self._no_tool_iterations >= 1)
                or self._no_tool_iterations >= 2
            )
            if (has_hallucination_risk or has_fake_cmd_block) and not tool_calls_acc:
                if has_fake_cmd_block:

                    logger.warning(
                        "Bash code block detected in text response (iteration=%d) — "
                        "LLM wrote a command instead of calling execute{}",
                        self.state.iteration,
                    )
                    self.state.conversation.append({
                        "role": "system",
                        "content": (
                            "[SYSTEM: TOOL CALL REQUIRED — DO NOT WRITE COMMANDS AS TEXT]\n"
                            "You wrote a shell command in a code block instead of calling a tool.\n"
                            "Writing ```bash ... ``` does NOT execute the command.\n"
                            "You MUST call the execute tool to run commands:\n"
                            "  execute({\"command\": \"your_command_here\"})\n"
                            "Call the tool NOW. Do not repeat the code block."
                        ),
                    })
                    content_acc = ""
                elif is_post_vuln_context:

                    logger.warning(
                        "Post-vulnerability hallucination detected "
                        "(phase=exploit=%s, vulns=%d, no_tool_iters=%d)",
                        is_exploit_phase,
                        len(self._session.vulnerabilities) if self._session else 0,
                        self._no_tool_iterations,
                    )
                    self.state.conversation.append({
                        "role": "system",
                        "content": (
                            "[SYSTEM: MANDATORY TOOL CALL - EXPLOIT PHASE]\n"
                            "A vulnerability was found. You MUST now prove it works:\n"
                            "1. Use a command execution, browser, or fuzzing tool\n"
                            "2. Show the actual response/output as evidence\n"
                            "3. DO NOT write analysis-only text\n"
                            "TOOL EXECUTION IS MANDATORY. Do not skip this step."
                        ),
                    })
                elif _nudge_threshold_met:
                    logger.warning(
                        "Hallucination signal detected with no tool call "
                        "(iteration=%d, no_tool_iters=%d)",
                        self.state.iteration,
                        self._no_tool_iterations,
                    )
                    self.state.conversation.append({
                        "role": "system",
                        "content": (
                            "[SYSTEM: HALLUCINATION WARNING]\n"
                            "Your response contains claims without tool execution. "
                            "You have NO data unless a tool actually returned it. "
                            "You MUST call a tool to verify any findings. "
                            "Do NOT fabricate results."
                        ),
                    })

            if not tool_calls_acc:
                _registered = {
                    t["function"]["name"] for t in (self._tools_llm or [])
                }
                _search_text = content_acc + "\n" + thinking_acc
                extracted = self._extract_tool_calls_from_text(
                    _search_text, _registered
                )
                if extracted:
                    tool_calls_acc.extend(extracted)
                    content_acc = self._TOOL_CALL_RE.sub(
                        "", content_acc).strip()

            _text_only_threshold = 1 if _in_active_session else 2
            if not tool_calls_acc and content_acc.strip() and self._no_tool_iterations >= _text_only_threshold:

                _planning_keywords = [
                    "i will", "i'll", "let me", "next step",
                    "i should", "i need to", "i'm going to",
                    "first, i", "to do this", "i would",
                ]
                _analysis_keywords = [
                    "analysis", "shows", "found", "detected",
                    "i have", "based on", "my analysis", "the results",
                    "might", "could be", "appears", "potentially",
                ]
                _all_no_tool_keywords = _planning_keywords + _analysis_keywords
                content_lower = content_acc.lower()
                is_no_tool_text = any(
                    kw in content_lower for kw in _all_no_tool_keywords
                )
                current_phase_name = (
                    self.pipeline.get_current_phase().value
                    if self.pipeline else "UNKNOWN"
                )
                if is_no_tool_text:
                    logger.warning(
                        "Text-only response for %d consecutive iterations "
                        "in %s phase — discarding and forcing tool call.",
                        self._no_tool_iterations,
                        current_phase_name,
                    )
                    self.state.conversation.append({
                        "role": "system",
                        "content": (
                            f"[SYSTEM: TEXT-ONLY RESPONSES NOT ALLOWED]\n"
                            f"You have provided {self._no_tool_iterations} consecutive "
                            f"responses without calling any tool.\n"
                            f"Current phase: {current_phase_name}\n"
                            f"You MUST call a tool NOW. Do NOT plan or describe — EXECUTE."
                        ),
                    })

                    tool_calls_acc = []
                    content_acc = ""

            _has_task_complete = "[TASK_COMPLETE]" in content_acc
            content_acc = content_acc.replace(
                "[TASK_COMPLETE]", "").strip()

            # Ensure assistant message always has non-empty content when
            # tool calls are emitted — models like local LLM get confused
            # by content="" + tool_calls (appears as an empty turn).
            if tool_calls_acc and not content_acc.strip():
                tool_names = ", ".join(
                    tc.get("function", {}).get("name", "unknown")
                    for tc in tool_calls_acc
                )
                content_acc = f"Executing: {tool_names}"

            if "<objective_patch" in content_acc:
                self._apply_objective_patch(content_acc, current_phase)
                content_acc = self._OBJECTIVE_PATCH_RE.sub(
                    "", content_acc
                ).strip()

            self.state.add_message(
                "assistant", content_acc, tool_calls_acc, thinking_acc
            )

            if self._session and content_acc:

                hedge_words = [
                    "might", "could", "possibly", "appears", "suggests",
                    "may", "potentially", "likely", "probable", "seems",
                ]
                is_confident = not any(hedge in content_acc.lower() for hedge in hedge_words)

                if is_confident:

                    vuln_claim_patterns = [
                        r"(sql\s*(injection)?|xss|ssrf|idor|rce|lfi|rfi|xxe|command\s+injection)\s+(in|at|on|found\s+in|detected\s+at)\s+([^\s,.!?]+)",
                    ]
                    for pattern in vuln_claim_patterns:
                        matches = re.findall(pattern, content_acc.lower())
                        for match in matches:

                            if isinstance(match, tuple) and len(match) >= 4:
                                vuln_type = match[0].strip()
                                endpoint = match[3].strip()
                                claim_text = f"{vuln_type} in {endpoint}"
                            else:
                                continue

                            has_session_evidence = False
                            if self._session.vulnerabilities:
                                has_session_evidence = any(
                                    vuln_type in " ".join([
                                        str(v.get("finding", "")),
                                        str(v.get("title", "")),
                                        str(v.get("evidence", "")),
                                        str(v.get("proof", "")),
                                    ]).lower()
                                    and endpoint in " ".join([
                                        str(v.get("finding", "")),
                                        str(v.get("title", "")),
                                        str(v.get("evidence", "")),
                                        str(v.get("proof", "")),
                                    ]).lower()
                                    for v in self._session.vulnerabilities
                                )

                            has_tool_evidence = False
                            _vuln_scan_tools: set[str] = set()
                            _vuln_cats = _TOOLS_META.get("categories", {}).get("vulnerability_scanning", {})
                            if isinstance(_vuln_cats, dict):
                                for _cat_tools in _vuln_cats.values():
                                    if isinstance(_cat_tools, list):
                                        _vuln_scan_tools.update(str(t).lower() for t in _cat_tools)
                            # Also include AIRecon fuzzing tools that target endpoints
                            _vuln_scan_tools |= {"quick_fuzz", "advanced_fuzz", "deep_fuzz", "schemathesis_fuzz"}
                            for tc in tool_calls_acc:
                                tc_name = tc.get("function", {}).get("name", "")
                                tc_args = tc.get("function", {}).get("arguments", {})
                                if tc_name in _vuln_scan_tools:

                                    tc_url = str(tc_args.get("url", tc_args.get("command", ""))).lower()
                                    if endpoint.lower() in tc_url:
                                        has_tool_evidence = True
                                        break

                            if not has_session_evidence and not has_tool_evidence:
                                logger.warning(
                                    "HALLUCINATION DETECTED: Claimed '%s' but no tool called and no session evidence",
                                    claim_text,
                                )

                                self.state.conversation.append({
                                    "role": "system",
                                    "content": (
                                        f"[SYSTEM: HALLUCINATION WARNING] You claimed '{claim_text}' "
                                        f"but no scanner tool (sqlmap/nuclei/ffuf) was called for this endpoint "
                                        f"and it's not in confirmed vulnerabilities. "
                                        f"Either: (1) call the appropriate scanner tool first, "
                                        f"(2) use hedged language ('might be', 'appears to'), or "
                                        f"(3) provide the tool output that confirms this finding."
                                    ),
                                })

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


            return content_acc, thinking_acc, tool_calls_acc, _has_task_complete

    # ── Self-Consistency Check ───────────────────────────────────────────

    def _is_text_only_response(self, text: str) -> bool:
        """Quick check if text is just planning/meta text."""
        return any(w in ("executing:", "[system:") for w in text.lower().split()[:2])

    def _check_critical_decision_consistency(
        self,
        text: str,
        tool_calls: list[dict[str, Any]],
    ) -> None:
        """Run self-consistency check when LLM makes a critical claim.

        When the agent claims to have found a vulnerability or makes a
        confident assertion about security, verify by running the same
        question through the model again (self-consistency).
        """
        # Only check occasionally (every 8 iterations)
        if not hasattr(self, "_consistency_counter"):
            self._consistency_counter = 0
        self._consistency_counter += 1
        if self._consistency_counter % 8 != 0:
            return

        import re as _re
        critical_patterns = [
            _re.compile(r"(?:vulnerabilities?\s+(?:found|detected|discovered|confirmed))", _re.I),
            _re.compile(r"(?:critical|high|medium|low)\s+(?:severity|vulnerab|issue)", _re.I),
            _re.compile(r"(?:sql\s*injection|xss|ssrf|idor|rce|lfi|xxe)\s+(?:in|at|on|found)", _re.I),
        ]

        match = None
        for pattern in critical_patterns:
            match = pattern.search(text)
            if match:
                break

        if not match:
            return

        # Lazy-init meta-reasoning engine
        if not hasattr(self, "_meta_reasoning_engine"):
            from .meta_reasoning import MetaReasoningEngine
            self._meta_reasoning_engine = MetaReasoningEngine()

        engine = self._meta_reasoning_engine

        if not engine.needs_consistency_check("vulnerability_classification", {}):
            return

        engine.build_consistency_check_prompt(
            question="What is the most important next step in this security assessment?",
            initial_answer=text[:300],
            context={
                "phase": self.pipeline.get_current_phase().value if self.pipeline else "RECON",
                "iterations": self.state.iteration,
                "failures": self._consecutive_failures,
            },
        )

        # Fire-and-forget: inject the prompt into conversation so the
        # NEXT LLM call will see it as context for self-correction.
        # This avoids blocking the main loop with extra API calls.
        self.state.conversation.append({
            "role": "system",
            "content": (
                f"<self_consistency_check>\n"
                f"Your previous response was: {text[:200]}\n"
                f"Self-verify: Consider if your reasoning holds up from a different angle. "
                f"Are you certain? Is there an alternative explanation? "
                f"Do you have sufficient evidence?\n"
                f"If confident, continue with tool execution as planned.\n"
                f"If uncertain, choose a safer verification step.\n"
                f"</self_consistency_check>"
            ),
        })
        logger.debug(
            "[SelfConsistency] Check triggered at iteration %d: claim='%s'",
            self.state.iteration,
            match.group()[:80],
        )

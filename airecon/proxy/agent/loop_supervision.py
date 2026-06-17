from __future__ import annotations

import json
import logging
import re
import warnings
from pathlib import Path
from typing import Any

from ..data_loader import int_to_severity, severity_to_int
from .pipeline import PipelinePhase
from .tuning import get_tuning
from .validators import has_dangerous_patterns

logger = logging.getLogger("airecon.agent")

_ab_signals_path = Path(__file__).parent.parent / "data" / "ab_signals.json"
try:
    with open(_ab_signals_path) as _f:
        _AB_SIGNALS_DATA: dict[str, Any] = json.load(_f)
except (OSError, json.JSONDecodeError) as _e:
    warnings.warn(f"ab_signals.json unavailable ({_e}); A→B signal method disabled.")
    _AB_SIGNALS_DATA = {"signals": [], "min_severity": 3}

_tools_meta_path = Path(__file__).parent.parent / "data" / "tools_meta.json"
try:
    with open(_tools_meta_path) as _f:
        _TOOLS_META_SUP: dict[str, Any] = json.load(_f)
except (OSError, json.JSONDecodeError) as _e:
    warnings.warn(f"tools_meta.json unavailable in loop_supervision ({_e})")
    _TOOLS_META_SUP = {}

_watchdog_prefixes = _TOOLS_META_SUP.get("watchdog_safe_command_prefixes", [])
_WATCHDOG_COMMAND_PREFIX_RE: re.Pattern[str] = re.compile(
    r"^(?:" + "|".join(re.escape(p) for p in _watchdog_prefixes) + r")\b",
    re.IGNORECASE,
) if _watchdog_prefixes else re.compile(r"(?!)")
_QUALITY_TUNING = {
    "weak_penalty_per_vuln": float(get_tuning("quality_scoring.weak_penalty_per_vuln", 0.04)),
    "weak_penalty_cap": float(get_tuning("quality_scoring.weak_penalty_cap", 0.20)),
    "evidence_artifact": float(get_tuning("quality_scoring.evidence.artifact", 0.16)),
    "evidence_high_conf": float(get_tuning("quality_scoring.evidence.high_conf", 0.10)),
    "evidence_backed_vuln": float(get_tuning("quality_scoring.evidence.backed_vuln", 0.14)),
    "evidence_non_error": float(get_tuning("quality_scoring.evidence.non_error_event", 0.02)),
    "repro_execution": float(get_tuning("quality_scoring.repro.execution", 0.03)),
    "repro_artifact": float(get_tuning("quality_scoring.repro.artifact", 0.12)),
    "repro_report": float(get_tuning("quality_scoring.repro.report", 0.26)),
    "repro_replay_verified": float(get_tuning("quality_scoring.repro.replay_verified", 0.22)),
    "repro_verified_vuln": float(get_tuning("quality_scoring.repro.verified_vuln", 0.10)),
    "impact_flag": float(get_tuning("quality_scoring.impact.flag", 0.45)),
    "impact_verified_vuln": float(get_tuning("quality_scoring.impact.verified_vuln", 0.22)),
    "impact_report": float(get_tuning("quality_scoring.impact.report", 0.18)),
    "impact_cve": float(get_tuning("quality_scoring.impact.cve", 0.06)),
    "impact_signal": float(get_tuning("quality_scoring.impact.signal", 0.01)),
    "overall_evidence": float(get_tuning("quality_scoring.overall.evidence", 0.40)),
    "overall_repro": float(get_tuning("quality_scoring.overall.repro", 0.35)),
    "overall_impact": float(get_tuning("quality_scoring.overall.impact", 0.25)),
}

class _SupervisionMixin:
    _OBJECTIVE_PATCH_RE = re.compile(
        r"<objective_patch[^>]*>(.*?)</objective_patch>",
        re.DOTALL | re.IGNORECASE,
    )

    def _extract_shell_command_candidate(
        self,
        content_acc: str,
        thinking_acc: str = "",
    ) -> str | None:
        def _safe(cmd: str) -> str | None:
            cleaned = cmd.strip().lstrip("$").strip()
            if not cleaned:
                return None

            if len(cleaned) > 8000:
                return None
            has_danger, _ = has_dangerous_patterns(cleaned)
            if has_danger:
                return None
            return cleaned

        for block in self._FAKE_CMD_BLOCK_RE.findall(content_acc):
            if not block:
                continue
            lines = [ln.strip() for ln in block.splitlines() if ln.strip()]
            if not lines:
                continue

            picked: list[str] = []
            found_first = False
            for line in lines:
                if line.startswith("#"):
                    continue
                line = line.lstrip("-*0123456789. ").strip()
                if not found_first:
                    if not _WATCHDOG_COMMAND_PREFIX_RE.match(line.lstrip("$")):
                        continue
                    found_first = True
                picked.append(line.rstrip("\\").strip())

            if picked:

                candidate = "\n".join(p for p in picked if p)
                safe = _safe(candidate)
                if safe:
                    return safe

        _backtick_re = re.compile(r"`([^`]+)`")
        _run_prefix_re = re.compile(
            r"(?:run|execute|use|call|try|invoke)\s*:?\s*(.+)", re.IGNORECASE
        )
        for raw_line in (content_acc + "\n" + thinking_acc).splitlines():
            line = raw_line.strip().lstrip("-*0123456789. ").strip()
            if not line:
                continue

            bt_match = _backtick_re.search(line)
            candidates = [bt_match.group(1).strip()] if bt_match else []

            rp_match = _run_prefix_re.match(line)
            if rp_match:
                candidates.append(rp_match.group(1).strip().lstrip("`").rstrip("`").strip())

            candidates.append(line.lstrip("$").strip())

            for candidate_line in candidates:
                if _WATCHDOG_COMMAND_PREFIX_RE.match(candidate_line):
                    safe = _safe(candidate_line)
                    if safe:
                        return safe

        return None

    def _reflector_infer_tool_hint(self, content_lower: str) -> str:
        if self._tools_llm:
            for tool_def in self._tools_llm:
                name = str(tool_def.get("function", {}).get("name", ""))
                if name and name.lower() in content_lower:
                    return f"{name}({{...}})"
        return 'execute({"command": "<command>"})'

    def _apply_objective_patch(
        self, content: str, current_phase: PipelinePhase
    ) -> int:
        match = self._OBJECTIVE_PATCH_RE.search(content)
        if not match:
            return 0
        raw = match.group(1).strip()
        try:
            ops = json.loads(raw)
        except (json.JSONDecodeError, ValueError) as e:
            logger.debug("objective_patch JSON parse error: %s", e)
            return 0
        if not isinstance(ops, list):
            ops = [ops]

        for op in ops:
            if isinstance(op, dict) and not op.get("phase"):
                op["phase"] = current_phase.value
        changed = self.state.patch_objectives(ops)
        if changed:
            logger.info(
                "Objective patch applied: %d change(s) (phase=%s)",
                changed,
                current_phase.value,
            )
        return changed

    def _build_reflector_message(
        self,
        content_acc: str,
        attempt: int,
        phase: PipelinePhase,
    ) -> str:
        phase_str = phase.value
        content_lower = content_acc.lower()

        tool_hint = self._reflector_infer_tool_hint(content_lower)

        if attempt == 1:
            issue = "You responded with analysis text but did not call any tool."
            action = (
                f"Call a tool NOW to continue the assessment. "
                f"Based on your analysis, try: {tool_hint}"
            )
        else:
            issue = (
                f"REFLECTOR (attempt {attempt}): Text-only response received again. "
                "No tool call was made."
            )
            action = (
                f"You MUST include a tool_call in your response — no more text planning. "
                f"Execute immediately: {tool_hint}"
            )

        return (
            f'<reflector phase="{phase_str}" attempt="{attempt}">\n'
            f"  <issue>{issue}</issue>\n"
            f"  <required_action>{action}</required_action>\n"
            f"  <escalation_warning>Watchdog auto-execution activates after"
            f" {max(3, self._no_tool_iterations + 1)} uncorrected iterations."
            f" Avoid it by calling a tool now.</escalation_warning>\n"
            f"</reflector>"
        )

    def _get_ab_signals(self, evidence_summary: str) -> dict[str, Any] | None:
        summary_lower = evidence_summary.lower()
        for entry in _AB_SIGNALS_DATA.get("signals", []):
            if not any(kw in summary_lower for kw in entry.get("keywords", [])):
                continue

            if any(nkw in summary_lower for nkw in entry.get("negative_keywords", [])):
                continue
            return entry
        return None

    def _build_mentor_analysis(
        self,
        current_phase: PipelinePhase,
        tool_name: str,
        evidence_added: bool,
    ) -> str:
        phase_str = current_phase.value
        pending, _, recent_evidence = self.state.get_phase_context(
            phase_str, max_objectives=3, max_evidence=3
        )

        total_ev = len(self.state.evidence_log)
        phase_ev = sum(
            1 for e in self.state.evidence_log
            if str(e.get("phase", "")).upper() == phase_str.upper()
        )
        high_sev = sum(
            1 for e in self.state.evidence_log
            if severity_to_int(e.get("severity", 1)) >= 4
        )

        progress_parts = [f"{phase_ev} evidence item(s) in {phase_str} phase"]
        if high_sev:
            progress_parts.append(f"{high_sev} HIGH/CRITICAL finding(s) confirmed")
        if evidence_added:
            progress_parts.append("latest tool run produced new evidence")
        progress = ", ".join(progress_parts) + "."

        latest_summary = ""
        if recent_evidence:
            ev = recent_evidence[0]
            sev = severity_to_int(ev.get("severity", 1))
            sev_label = int_to_severity(sev)
            latest_summary = f"Latest: [{sev_label}] {ev.get('summary', '')[:120]}"

        if pending:
            next_obj = pending[0].get("title", "")
            next_steps = f"Next objective: {next_obj}"
        else:
            next_steps = (
                "All objectives for this phase appear complete. "
                "Consider transitioning to the next phase or deepening current findings."
            )

        issues = ""
        if total_ev == 0:
            issues = "No evidence collected yet — surface mapping incomplete."
        elif high_sev == 0 and phase_str.upper() in ("ANALYSIS", "EXPLOIT"):
            issues = "No HIGH/CRITICAL findings yet — increase test depth or pivot attack vector."

        ab_signal: dict[str, Any] | None = None
        if recent_evidence:
            last_ev = recent_evidence[0]
            last_sev = severity_to_int(last_ev.get("severity", 1))
            _min_sev = severity_to_int(_AB_SIGNALS_DATA.get("min_severity", 3))
            if last_sev >= _min_sev:
                ab_signal = self._get_ab_signals(last_ev.get("summary", ""))

                if ab_signal and ab_signal.get("objective_patches"):

                    _patches = [
                        dict(_p, phase=phase_str)
                        if _p.get("op") == "add" and not _p.get("phase")
                        else _p
                        for _p in ab_signal["objective_patches"]
                    ]
                    self.state.patch_objectives(_patches)

        lines = [f"<mentor_analysis phase=\"{phase_str}\" tool=\"{tool_name}\">"]
        lines.append(f"  <progress_assessment>{progress}{(' ' + latest_summary) if latest_summary else ''}</progress_assessment>")
        if issues:
            lines.append(f"  <identified_issues>{issues}</identified_issues>")
        lines.append(f"  <next_steps>{next_steps}</next_steps>")
        if ab_signal:
            signal_id = ab_signal.get("id", "")
            owasp_id = ab_signal.get("owasp_id", "")
            signal_attr = f' signal="{signal_id}"' if signal_id else ""
            owasp_attr = f' owasp="{owasp_id}"' if owasp_id else ""
            lines.append(f"  <followup_signals{signal_attr}{owasp_attr}>")

            for hint in ab_signal.get("followup", []):
                lines.append(f"    <hint>{hint}</hint>")

            if ab_signal.get("test_vectors"):
                lines.append("    <test_vectors>")
                for tv in ab_signal["test_vectors"]:
                    lbl = tv.get("label", "")
                    pay = tv.get("payload", "")
                    lines.append(f'      <vector label="{lbl}">{pay}</vector>')
                lines.append("    </test_vectors>")

            if ab_signal.get("chain_with"):
                chain_str = ", ".join(ab_signal["chain_with"])
                lines.append(f"    <chain_with>{chain_str}</chain_with>")

            if ab_signal.get("kill_conditions"):
                lines.append("    <kill_conditions>")
                for kc in ab_signal["kill_conditions"]:
                    lines.append(f"      <condition>{kc}</condition>")
                lines.append("    </kill_conditions>")
            lines.append("  </followup_signals>")
        lines.append("</mentor_analysis>")
        return "\n".join(lines)

    def _build_watchdog_tool_call(
        self,
        content_acc: str,
        thinking_acc: str,
        phase: PipelinePhase,
    ) -> dict[str, Any] | None:
        candidate_cmd = self._extract_shell_command_candidate(
            content_acc=content_acc,
            thinking_acc=thinking_acc,
        )
        if candidate_cmd:
            return {
                "id": f"watchdog_execute_{self.state.iteration}",
                "type": "function",
                "function": {
                    "name": "execute",
                    "arguments": {"command": candidate_cmd},
                },
            }

        return None

    def _compute_quality_scores(self) -> dict[str, Any]:
        evidence = self.state.evidence_log
        tags = [tag for ev in evidence for tag in ev.get("tags", [])]

        artifact_count = sum(
            1 for ev in evidence if ev.get("artifact") or "artifact" in ev.get("tags", [])
        )
        execution_count = sum(
            1 for ev in evidence if "execution" in ev.get("tags", []) or "trace" in ev.get("tags", [])
        )
        high_conf_count = sum(
            1 for ev in evidence if float(ev.get("confidence", 0.0)) >= 0.75
        )
        signal_count = tags.count("signal")
        cve_count = tags.count("cve")
        flag_count = tags.count("flag")
        error_count = tags.count("error")

        vuln_count = len(self._session.vulnerabilities) if self._session else 0
        evidence_backed_vuln_count = 0
        verified_vuln_count = 0
        replay_verified_count = 0
        weak_vuln_count = 0
        report_count = 0
        if self._session:
            for v in self._session.vulnerabilities:
                has_report = bool(v.get("report_generated"))
                has_replay = bool(v.get("replay_verified"))
                has_verified = bool(v.get("verified"))
                has_evidence = bool(v.get("proof") or v.get("evidence") or v.get("poc_script_code"))
                has_scope = bool(v.get("url") or v.get("endpoint") or v.get("parameter"))
                if has_report:
                    report_count += 1
                if has_replay:
                    replay_verified_count += 1
                if has_verified or has_report or has_replay:
                    verified_vuln_count += 1
                if has_evidence or has_scope:
                    evidence_backed_vuln_count += 1
                if not (has_report or has_replay or has_verified or has_evidence):
                    weak_vuln_count += 1

        weak_penalty = min(
            _QUALITY_TUNING["weak_penalty_cap"],
            weak_vuln_count * _QUALITY_TUNING["weak_penalty_per_vuln"],
        )

        evidence_score = min(
            1.0,
            (artifact_count * _QUALITY_TUNING["evidence_artifact"])
            + (high_conf_count * _QUALITY_TUNING["evidence_high_conf"])
            + (evidence_backed_vuln_count * _QUALITY_TUNING["evidence_backed_vuln"])
            + (max(0, len(evidence) - error_count) * _QUALITY_TUNING["evidence_non_error"])
            - weak_penalty,
        )
        reproducibility_score = min(
            1.0,
            (execution_count * _QUALITY_TUNING["repro_execution"])
            + (artifact_count * _QUALITY_TUNING["repro_artifact"])
            + (report_count * _QUALITY_TUNING["repro_report"])
            + (replay_verified_count * _QUALITY_TUNING["repro_replay_verified"])
            + (verified_vuln_count * _QUALITY_TUNING["repro_verified_vuln"]),
        )
        impact_score = min(
            1.0,
            (flag_count * _QUALITY_TUNING["impact_flag"])
            + (verified_vuln_count * _QUALITY_TUNING["impact_verified_vuln"])
            + (report_count * _QUALITY_TUNING["impact_report"])
            + (cve_count * _QUALITY_TUNING["impact_cve"])
            + (signal_count * _QUALITY_TUNING["impact_signal"])
            - weak_penalty,
        )
        overall = (
            (evidence_score * _QUALITY_TUNING["overall_evidence"])
            + (reproducibility_score * _QUALITY_TUNING["overall_repro"])
            + (impact_score * _QUALITY_TUNING["overall_impact"])
        )

        return {
            "evidence": round(evidence_score, 3),
            "reproducibility": round(reproducibility_score, 3),
            "impact": round(impact_score, 3),
            "overall": round(overall, 3),
            "counts": {
                "evidence": len(evidence),
                "artifacts": artifact_count,
                "executions": execution_count,
                "vulnerabilities": vuln_count,
                "reports": report_count,
                "flags": flag_count,
                "verified_vulns": verified_vuln_count,
                "replay_verified": replay_verified_count,
            },
        }

    def _build_quality_scoreboard(self, phase: PipelinePhase) -> str:
        scores = self._compute_quality_scores()
        counts = scores.get("counts", {})
        if int(counts.get("evidence", 0)) == 0 and self.state.iteration <= 1:
            return ""

        lines = [
            "[SYSTEM: QUALITY SCOREBOARD]",
            (
                f"Phase={phase.value} | "
                f"Evidence={scores['evidence']:.2f} | "
                f"Reproducibility={scores['reproducibility']:.2f} | "
                f"Impact={scores['impact']:.2f} | "
                f"Overall={scores['overall']:.2f}"
            ),
            (
                "Counts: "
                f"evidence={counts.get('evidence', 0)}, "
                f"artifacts={counts.get('artifacts', 0)}, "
                f"executions={counts.get('executions', 0)}, "
                f"vulns={counts.get('vulnerabilities', 0)}, "
                f"reports={counts.get('reports', 0)}"
            ),
        ]

        if phase in (PipelinePhase.EXPLOIT, PipelinePhase.REPORT):
            if float(scores["reproducibility"]) < 0.45:
                lines.append(
                    "Gap: reproducibility is low. Run one concrete PoC command and save artifact output now."
                )
            if float(scores["impact"]) < 0.35:
                lines.append(
                    "Gap: impact proof is weak. Prioritize evidence showing real access/state change."
                )
        elif phase in (PipelinePhase.RECON, PipelinePhase.ANALYSIS):
            if float(scores["evidence"]) < 0.30:
                lines.append(
                    "Gap: evidence coverage low. Collect fresh host/port/endpoint artifacts before pivoting."
                )

        return "\n".join(lines)

    def _build_recovery_state_context(self) -> str:
        phase = self._get_current_phase()
        quality = self._compute_quality_scores()
        lines = [
            "[SYSTEM: RECOVERY STATE]",
            (
                f"Phase={phase.value} | Iteration={self.state.iteration} | "
                f"Target={self.state.active_target or 'none'}"
            ),
            (
                f"Quality overall={quality['overall']:.2f} "
                f"(evidence={quality['evidence']:.2f}, repro={quality['reproducibility']:.2f}, "
                f"impact={quality['impact']:.2f})"
            ),
        ]

        pending, completed, evidence = self.state.get_phase_context(
            phase.value, max_objectives=5, max_evidence=6, filter_evidence_by_phase=False
        )
        if pending:
            lines.append("Pending objectives:")
            for obj in pending:
                lines.append(f"- {obj.get('title', '')}")
        if completed:
            lines.append(f"Completed objectives ({len(completed)} total):")
            for obj in completed[:3]:
                lines.append(f"  ✓ {obj.get('title', '')}")

        recent_tools = list(reversed(self.state.tool_history))[:5]
        if recent_tools:
            lines.append("Recent tool calls (newest first):")
            for entry in recent_tools:
                status_icon = "✓" if entry.status == "success" else "✗"
                args_hint = ""
                args = getattr(entry, "arguments", None) or {}
                if isinstance(args, dict):

                    for key in ("command", "url", "query", "action", "target"):
                        if key in args:
                            val = str(args[key])[:80]
                            args_hint = f" [{key}={val}]"
                            break
                    if not args_hint and args:
                        first_key = next(iter(args))
                        args_hint = f" [{first_key}={str(args[first_key])[:60]}]"
                lines.append(f"  {status_icon} {entry.tool_name}{args_hint}")

        if evidence:
            lines.append("Recent evidence:")
            for ev in evidence:
                lines.append(f"- [{ev.get('source_tool', 'tool')}] {ev.get('summary', '')[:120]}")

        lines.append(
            "MANDATORY: first response after recovery must include at least one tool_call."
        )
        lines.append(
            "Resume from the last failed/pending step above — do not restart from scratch."
        )
        return "\n".join(lines)

    def _prune_stale_skills(self, max_age_iterations: int = 10) -> int:
        from ..system import _PHASE_SKILL_CATEGORIES

        if not hasattr(self.state, "conversation") or len(self.state.conversation) < 10:
            return 0

        current_phase = self._get_current_phase().value.upper()
        phase_dirs = _PHASE_SKILL_CATEGORIES.get(current_phase, set())

        recommended_skills = set()
        try:
            if self._memory_manager and self._session and self._session.target:
                skill_recs = self._memory_manager.get_skill_recommendations(
                    self._session.target, current_phase
                )
                for rec in skill_recs:
                    skill_path = str(rec.get("skill_path") or rec.get("skill_name") or "")
                    if not skill_path:
                        continue

                    if "/" in skill_path:
                        skill_path = skill_path.replace("\\", "/")
                        if not skill_path.endswith(".md"):
                            skill_path = f"{skill_path}.md"
                        recommended_skills.add(skill_path)
                        continue

                    skill_stem = Path(skill_path).stem
                    default_dir = "ctf" if current_phase == "EXPLOIT" else "reconnaissance"
                    recommended_skills.add(f"{default_dir}/{skill_stem}.md")
                    for phase_dir in phase_dirs:
                        recommended_skills.add(f"{phase_dir}/{skill_stem}.md")
        except Exception as e:
            logger.debug("Skill recommendation lookup for pruning failed: %s", e)

        skills_to_remove = []

        for i, msg in enumerate(self.state.conversation):
            if msg.get("role") != "system":
                continue
            content = msg.get("content", "")
            if "[AUTO-LOADED SKILL:" not in content:
                continue

            skill_paths = [
                p.strip()
                for p in re.findall(r"\[AUTO-LOADED SKILL:\s*([^\]]+)\]", content)
                if p.strip()
            ]
            if not skill_paths:
                continue

            skill_iteration = msg.get("iteration", 0)
            age = self.state.iteration - skill_iteration

            if age < max_age_iterations:
                continue

            is_phase_relevant = any(
                (sp.split("/", 1)[0] if "/" in sp else "") in phase_dirs
                for sp in skill_paths
            )
            if not is_phase_relevant:
                skills_to_remove.append((i, 0))
                continue

            is_recommended = any(sp in recommended_skills for sp in skill_paths)
            if is_recommended:
                if age < max_age_iterations * 2:
                    continue
                skills_to_remove.append((i, 1))
            else:
                skills_to_remove.append((i, 0))

        for i in sorted((t[0] for t in skills_to_remove), reverse=True):
            if i < len(self.state.conversation):
                self.state.conversation.pop(i)

        pruned_count = len(skills_to_remove)
        if pruned_count > 0:
            logger.debug(
                "Pruned %d stale skill messages (age > %d iterations, not phase-relevant or not recommended)",
                pruned_count, max_age_iterations,
            )

        return pruned_count

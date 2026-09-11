from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

from ..config import get_config
from .pipeline import PipelinePhase
from .vuln_classifier import get_classifier

logger = logging.getLogger("airecon.agent")

_STAGNATION_HISTORY: dict[str, list[int]] = {}
_PHASE_STAGNATION_PATTERNS: dict[str, list[int]] = {}


def _get_meaningful_evidence_threshold() -> float:
    return get_config().exploration_meaningful_evidence_threshold


def _calculate_adaptive_threshold(
    phase: PipelinePhase,
    iteration: int,
    evidence_count: int,
    failure_count: int,
) -> tuple[int, int]:
    base_threshold = 1
    base_streak = 2

    if iteration < 5:
        base_threshold = 2
        base_streak = 3
    elif iteration > 30:
        base_threshold = 1
        base_streak = 1

    if evidence_count > 10:
        base_threshold = max(1, base_threshold - 1)

    if failure_count > 5:
        base_threshold = max(1, base_threshold - 1)

    phase_adjustment = getattr(_PHASE_STAGNATION_PATTERNS, phase.value.lower(), [0, 0])
    if phase_adjustment:
        avg_stag = sum(phase_adjustment) / len(phase_adjustment)
        if avg_stag > 5:
            base_threshold += 1
            base_streak += 1
        elif avg_stag < 1:
            base_threshold = max(1, base_threshold - 1)

    return base_threshold, base_streak


def _record_stagnation(phase: str, count: int) -> None:
    if phase not in _STAGNATION_HISTORY:
        _STAGNATION_HISTORY[phase] = []
    _STAGNATION_HISTORY[phase].append(count)
    if len(_STAGNATION_HISTORY[phase]) > 20:
        _STAGNATION_HISTORY[phase] = _STAGNATION_HISTORY[phase][-20:]

    if phase not in _PHASE_STAGNATION_PATTERNS:
        _PHASE_STAGNATION_PATTERNS[phase] = []
    _PHASE_STAGNATION_PATTERNS[phase].append(count)
    if len(_PHASE_STAGNATION_PATTERNS[phase]) > 10:
        _PHASE_STAGNATION_PATTERNS[phase] = _PHASE_STAGNATION_PATTERNS[phase][-10:]


class _ExplorationMixin:
    @staticmethod
    def _normalize_vuln_labels(raw_value: Any) -> set[str]:
        text = str(raw_value or "").strip()
        if not text:
            return set()

        normalized = {
            label.lower()
            for label in get_classifier().resolve_labels(text)
            if str(label).strip()
        }
        if normalized:
            return normalized

        fallback = re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_")
        return {fallback} if len(fallback) >= 3 else set()

    def _track_tool_usage(self, tool_name: str, arguments: dict | None = None) -> None:

        track_as = tool_name
        if self._ctf_mode and tool_name == "execute" and arguments:
            cmd = str(arguments.get("command", "")).strip()

            _ws_prefix = re.sub(r"^cd\s+\S+\s*&&\s*", "", cmd).strip()

            _binary = _ws_prefix.split()[0] if _ws_prefix else ""

            if _binary and _binary not in (
                "cd",
                "echo",
                "export",
                "source",
                ".",
                "for",
                "while",
                "if",
            ):
                track_as = _binary
        self._recent_tool_names.append(track_as)
        cfg = get_config()
        window = max(3, self._cfg_int(cfg, "agent_tool_diversity_window", 8))
        if len(self._recent_tool_names) > window:
            self._recent_tool_names = self._recent_tool_names[-window:]

    def _record_tool_to_memory(
        self,
        tool_name: str,
        success: bool,
        duration: float = 0.0,
        output_size: int = 0,
    ) -> None:
        """Record tool usage to cross-session memory for learning."""
        try:
            from ..memory import get_memory_manager

            target = ""
            if self._session:
                target = self._session.target or ""

            if target and tool_name not in (
                "create_file",
                "read_file",
                "list_files",
                "request_user_input",
            ):
                memory = get_memory_manager()
                memory.record_tool_usage(
                    tool_name=tool_name,
                    target=target,
                    success=success,
                    duration_sec=duration,
                    output_size=output_size,
                )
        except Exception as _e:
            logger.debug("Failed to record tool usage: %s", _e)

    def _get_same_tool_streak(self) -> int:
        if not self._recent_tool_names:
            return 0
        streak = 1
        last = self._recent_tool_names[-1]
        for tn in reversed(self._recent_tool_names[:-1]):
            if tn != last:
                break
            streak += 1
        return streak

    def _refresh_exploration_state(self) -> None:

        meaningful_now = sum(
            1
            for e in self.state.evidence_log
            if e.get("confidence", 0) >= _get_meaningful_evidence_threshold()
        )
        if meaningful_now > self._last_evidence_count:
            self._stagnation_iterations = 0
            self._consecutive_same_approach = 0
        else:
            self._stagnation_iterations += 1
            _record_stagnation(
                self.pipeline.get_current_phase().value if self.pipeline else "UNKNOWN",
                self._stagnation_iterations,
            )

            if not self._recent_tool_names:
                self._consecutive_same_approach = (
                    getattr(self, "_consecutive_same_approach", 0) + 1
                )
            else:
                last_tool = self._recent_tool_names[-1]
                last_cmd = ""
                if hasattr(self, "state") and self.state.tool_history:
                    for te in reversed(self.state.tool_history):
                        if getattr(te, "tool_name", "") == last_tool:
                            last_cmd = str(
                                (te.arguments or {}).get("command", te.arguments or {})
                            )[:120]
                            break
                if last_cmd and hasattr(self, "_last_approach_signature"):
                    if last_cmd[:80] == self._last_approach_signature[:80]:
                        self._consecutive_same_approach = (
                            getattr(self, "_consecutive_same_approach", 0) + 1
                        )
                    else:
                        self._consecutive_same_approach = 0
                self._last_approach_signature = last_cmd
        self._last_evidence_count = meaningful_now

    def _build_exploration_directive(self, phase: PipelinePhase) -> str:
        lock_attr = getattr(self, "_scope_lock_active", False)
        lock_active = (
            lock_attr
            if isinstance(lock_attr, bool)
            else bool(getattr(getattr(self, "_scope", None), "scope_lock_active", False))
        )
        if lock_active:
            return (
                "[SYSTEM: AGGRESSIVE EXPLORATION DISABLED — STRICT_SCOPE_MODE]\n"
                "User requested a focused scope. Do not broaden coverage beyond the explicit request."
            )

        cfg = get_config()
        if not self._cfg_bool(cfg, "agent_exploration_mode", True):
            return ""

        intensity = self._cfg_float(cfg, "agent_exploration_intensity", 0.8)

        stagnation_threshold, max_same_streak = _calculate_adaptive_threshold(
            phase,
            self.state.iteration,
            len(self.state.evidence_log),
            self._consecutive_failures,
        )

        same_tool_streak = self._get_same_tool_streak()
        window = max(3, self._cfg_int(cfg, "agent_tool_diversity_window", 8))
        recent = self._recent_tool_names[-window:]
        unique_recent = len(set(recent)) if recent else 0
        consecutive_same = getattr(self, "_consecutive_same_approach", 0)

        is_stagnating = (
            self._stagnation_iterations >= stagnation_threshold
            or self._consecutive_failures >= 2
            or self._no_tool_iterations >= 1
            or same_tool_streak >= max_same_streak
            or consecutive_same >= 2
        )

        is_creative_phase = phase in (PipelinePhase.ANALYSIS, PipelinePhase.EXPLOIT)

        if not is_stagnating and not is_creative_phase:
            return ""

        # ── Dynamic context from data sources ──────────────────────────
        tested_vuln_classes = self._get_tested_vuln_classes()
        untested_classes = self._get_untested_vuln_classes(tested_vuln_classes)
        session_techs = (
            getattr(self._session, "technologies", {}) if self._session else {}
        )
        session_urls = getattr(self._session, "urls", []) if self._session else []
        session_injection_points = (
            getattr(self._session, "injection_points", []) if self._session else []
        )

        # Build dynamic tactics from session context — no hardcoded lists
        tactics = self._generate_dynamic_tactics(
            phase=phase,
            tested_classes=tested_vuln_classes,
            untested_classes=untested_classes,
            technologies=session_techs,
            urls=session_urls,
            injection_points=session_injection_points,
            iteration=self.state.iteration,
        )

        if not tactics:
            return ""

        if is_stagnating:
            pressure = "HIGH" if intensity >= 0.75 else "MEDIUM"
            lines = [
                f"[SYSTEM: AGGRESSIVE EXPLORATION MODE — {pressure}]",
                f"Phase={phase.value} | stagnation={self._stagnation_iterations} | "
                f"same_tool_streak={same_tool_streak} | diversity={unique_recent}/{max(1, len(recent))} | "
                f"same_approach={consecutive_same}",
                "CRITICAL: Your current approach is not producing results. You MUST pivot NOW.",
                "MANDATORY RULES:",
                "1. Do NOT use the same tool or approach as your last iteration",
                "2. Do NOT test a vulnerability class already tested on this endpoint",
                "3. Pick the highest-value UNTESTED attack vector from the tactics below",
                "4. If exploitation is failing, switch to a completely different vuln class",
                "",
                f"VULN CLASSES ALREADY TESTED: {', '.join(sorted(tested_vuln_classes)) if tested_vuln_classes else 'none yet'}",
                f"UNTESTED CLASSES TO PRIORITIZE: {', '.join(sorted(untested_classes)[:6]) if untested_classes else 'all tested — chain findings instead'}",
                "",
                "Exploration tactics (pick the MOST NOVEL one):",
            ]
        else:
            lines = [
                f"[VISIONARY ANALYSIS — Phase={phase.value}]",
                "Think like an advanced attacker — go beyond standard vulnerability classes.",
                "Consider the FULL attack surface: trust boundaries, state machines, data flows, and component interactions.",
                f"Vuln classes tested so far: {', '.join(sorted(tested_vuln_classes)) if tested_vuln_classes else 'none — start broad'}",
                f"Untested classes available: {', '.join(sorted(untested_classes)[:8]) if untested_classes else 'all covered — focus on chaining'}",
                "",
                "Tactics (prioritize untested classes):",
            ]

        for tactic in tactics:
            lines.append(f"- {tactic}")

        if is_stagnating:
            if same_tool_streak >= max_same_streak:
                lines.append(
                    f"\n[TOOL BLOCK] You used '{recent[-1] if recent else 'unknown'}' {same_tool_streak}x consecutively. "
                    f"You are BLOCKED from using this tool family this iteration. Pick a completely different approach."
                )
            if consecutive_same >= 2:
                lines.append(
                    "\n[APPROACH BLOCK] Your last 2+ iterations used the same approach pattern. "
                    "You MUST switch to a fundamentally different attack class now."
                )
            if self._no_tool_iterations >= 1:
                lines.append("MANDATORY: reply with tool_call, not planning text.")
            lines.append(
                "Keep tests in-scope and non-destructive unless explicitly authorized."
            )

        strategy_hint = self._self_correcting_strategy(phase, recent, same_tool_streak)
        if strategy_hint:
            lines.append(f"\n[STRATEGY ADJUSTMENT] {strategy_hint}")

        return "\n".join(lines)

    # ── Dataset knowledge base phase hint ──────────────────────────────

    # Re-inject the dataset hint every N iterations if the LLM has not called
    # dataset_search recently.  A single injection per phase is not enough —
    # small models routinely skip a hint that appears only once.
    _DATASET_HINT_REPEAT_EVERY: int = 4

    def _dataset_search_called_recently(self, window: int = 10) -> bool:
        """Return True if dataset_search appears in the last `window` tool results."""
        seen = 0
        for msg in reversed(self.state.conversation):  # type: ignore[attr-defined]
            role = msg.get("role", "")
            if role == "tool":
                if msg.get("name") == "dataset_search":
                    return True
                seen += 1
                if seen >= window:
                    break
        return False

    def _build_dataset_hint(self, phase: PipelinePhase) -> str:
        """Return a dataset_search reminder when the LLM has not used it recently.

        Fires on every phase transition AND every _DATASET_HINT_REPEAT_EVERY
        iterations while dataset_search has not been called in the last 10 tool
        results.  Silenced when:
        - No datasets installed at ~/.airecon/datasets/
        - Phase is REPORT
        - dataset_search was already called recently

        Covered phases and their installed categories:
          RECON   → 'recon' (playbooks), 'network', 'api', 'web'
          ANALYSIS → 'pentest', 'bug-bounty', 'web', 'api'
          EXPLOIT  → 'pentest', 'vulnerability', 'bug-bounty'
        """
        # REPORT phase needs no knowledge-base lookup
        if phase == PipelinePhase.REPORT:
            return ""

        # Check datasets actually installed
        datasets_dir = Path.home() / ".airecon" / "datasets"
        try:
            has_db = any(datasets_dir.glob("*.db"))
        except OSError:
            has_db = False
        if not has_db:
            return ""

        phase_key = phase.value
        current_iter: int = getattr(self.state, "iteration", 1)  # type: ignore[attr-defined]
        last_hint_iter: int = getattr(self, "_dataset_last_hint_iter", -self._DATASET_HINT_REPEAT_EVERY)
        is_new_phase = getattr(self, "_dataset_hint_injected_phase", "") != phase_key

        # Suppress if: not a new phase AND not enough iterations since last hint
        if not is_new_phase and (current_iter - last_hint_iter) < self._DATASET_HINT_REPEAT_EVERY:
            return ""

        # Suppress if the LLM already called dataset_search recently
        if self._dataset_search_called_recently():
            return ""

        # ── Collect session context ───────────────────────────────────────
        session_techs: list[str] = []
        if self._session:  # type: ignore[attr-defined]
            techs = getattr(self._session, "technologies", {}) or {}
            session_techs = [t for t in list(techs.keys())[:2] if t]

        tested_vulns = sorted(self._get_tested_vuln_classes())[:3]
        tech_str = session_techs[0] if session_techs else ""

        # ── Detect target type from session ──────────────────────────────
        target: str = ""
        if self._session:  # type: ignore[attr-defined]
            target = str(getattr(self._session, "target", "") or "")
        is_api_target = any(x in target.lower() for x in ("/api/", "/rest/", "/graphql", "/v1/", "/v2/", "/v3/"))

        # ── Build phase-specific examples and guidance ────────────────────
        if phase == PipelinePhase.RECON:
            # airecon-recon-playbook.db (cat: recon), airecon-network-recon.db (cat: network),
            # airecon-api-security.db (cat: api), airecon-web-vuln-patterns.db (cat: web)
            if tech_str:
                example = f'{{"query": "{tech_str} enumeration attack surface", "category": "recon", "limit": 3}}'
            elif is_api_target:
                example = '{"query": "API endpoint discovery authentication bypass", "category": "api", "limit": 3}'
            else:
                example = '{"query": "subdomain enumeration port scan fingerprint", "category": "network", "limit": 3}'
            guidance = (
                "REQUIRED: call dataset_search NOW to get recon methodology and tool sequences "
                "from installed playbooks (categories: recon, network, api, web). "
                "The knowledge base contains AIRecon-specific recon order, nmap sequences, "
                "DNS enumeration, service fingerprinting, and API discovery playbooks."
            )

        elif phase == PipelinePhase.ANALYSIS:
            if tech_str and tested_vulns:
                example = f'{{"query": "{tech_str} {tested_vulns[0]} exploit", "limit": 3}}'
            elif tech_str:
                example = f'{{"query": "{tech_str} vulnerability bypass", "limit": 3}}'
            elif tested_vulns:
                vuln = tested_vulns[0].replace("_", " ")
                example = f'{{"query": "{vuln} bypass payload", "category": "pentest", "limit": 3}}'
            else:
                example = '{"query": "SSRF bypass payload", "category": "bug-bounty", "limit": 3}'
            guidance = (
                "REQUIRED: call dataset_search NOW to retrieve vulnerability techniques, "
                "bypass methods, and payloads for detected technologies before continuing analysis."
            )

        else:  # EXPLOIT
            if tested_vulns:
                vuln = tested_vulns[0].replace("_", " ")
                example = f'{{"query": "{vuln} exploit payload", "category": "pentest", "limit": 3}}'
            elif tech_str:
                example = f'{{"query": "{tech_str} CVE exploit", "category": "vulnerability", "limit": 3}}'
            else:
                example = '{"query": "WAF bypass exploit payload", "category": "pentest", "limit": 3}'
            guidance = (
                "REQUIRED: call dataset_search NOW for CVE exploitation details, PoC techniques, "
                "and WAF bypass payloads before crafting exploits."
            )

        # Update tracking state
        self._dataset_hint_injected_phase = phase_key  # type: ignore[attr-defined]
        self._dataset_last_hint_iter = current_iter  # type: ignore[attr-defined]

        return (
            f"[SYSTEM: KNOWLEDGE BASE — Phase={phase_key} iter={current_iter}]\n"
            f"{guidance}\n"
            f"Example query: {example}\n"
            "Keep queries short (2-3 specific tokens) for best FTS5 recall. "
            "Covers recon playbooks, CVEs, exploit techniques, payloads, WAF bypasses, nuclei templates."
        )

    # ── Web search RECON phase hint ────────────────────────────────────

    def _build_web_search_hint(self, phase: PipelinePhase) -> str:
        """Return a one-time web_search suggestion at RECON phase start.

        Fires once per session (RECON entry). Skipped if no technologies
        are detected yet (too early) or already injected.
        Includes both CVE research and Google dork examples for sensitive exposure.
        """
        if getattr(self, "_web_search_hint_injected", False):
            return ""

        # Only at RECON phase — CVE research and dorking most useful here
        if phase != PipelinePhase.RECON:
            return ""

        # Wait until at least one technology or service is fingerprinted
        session_techs: dict = {}
        target_domain: str = ""
        if self._session:  # type: ignore[attr-defined]
            session_techs = getattr(self._session, "technologies", {}) or {}
            raw_target = getattr(self._session, "target", "") or ""
            # Extract bare domain/host from URL or raw target string
            _m = re.search(r"https?://([^/:]+)", raw_target)
            target_domain = _m.group(1) if _m else raw_target.strip().split("/")[0]

        if not session_techs:
            return ""

        tech_names = [t for t in list(session_techs.keys())[:3] if t]
        if not tech_names:
            return ""

        primary = tech_names[0]
        lines = [
            "[SYSTEM: WEB SEARCH — Phase=RECON]",
            f"Detected technologies: {', '.join(tech_names)}.",
            "Use web_search for both CVE/PoC research AND Google dorking for sensitive exposure.",
            "",
            "CVE / exploit research:",
            f'  web_search: {{"query": "{primary} CVE exploit 2024", "max_results": 10}}',
        ]
        if len(tech_names) > 1:
            lines.append(
                f'  web_search: {{"query": "{tech_names[1]} vulnerability PoC github", "max_results": 10}}'
            )

        if target_domain:
            lines += [
                "",
                f"Google dorking against {target_domain} (sensitive exposure):",
                f'  web_search: {{"query": "site:{target_domain} filetype:env OR filetype:bak OR filetype:sql", "max_results": 20}}',
                f'  web_search: {{"query": "site:{target_domain} inurl:admin OR inurl:config OR inurl:backup", "max_results": 20}}',
                f'  web_search: {{"query": "site:{target_domain} ext:log OR ext:yaml OR ext:json password", "max_results": 20}}',
                f'  web_search: {{"query": "intitle:\\"index of\\" site:{target_domain}", "max_results": 20}}',
            ]

        lines += [
            "",
            "Use specific version numbers when known. Use max_results 20-30 for thorough dork campaigns.",
        ]

        self._web_search_hint_injected = True  # type: ignore[attr-defined]
        return "\n".join(lines)

    # ── Dynamic vuln class tracking from data sources ──────────────────

    def _get_tested_vuln_classes(self) -> set[str]:
        """Extract vulnerability classes already tested — all sources dynamic."""
        tested: set[str] = set()

        # 1. From evidence log tags
        for ev in self.state.evidence_log:
            tags = ev.get("tags", [])
            for tag in tags:
                if tag and isinstance(tag, str):
                    tested.update(self._normalize_vuln_labels(tag))

        # 2. From session vulnerability types (actual findings)
        if self._session:
            for v in getattr(self._session, "vulnerabilities", []):
                vtype = " ".join(
                    str(v.get(k, "")).strip()
                    for k in ("type", "finding", "title", "category", "description")
                    if str(v.get(k, "")).strip()
                )
                tested.update(self._normalize_vuln_labels(vtype))

        # 3. From evidence summaries — match against system.txt §11 terms
        for ev in self.state.evidence_log:
            summary = str(ev.get("summary", "")).lower()
            if summary:
                tested.update(self._normalize_vuln_labels(summary))

        # 4. From skills catalog — check which skill-based vuln classes have been loaded
        try:
            skills_index = self._load_skills_index()
            for skill_path in skills_index:
                if "vulnerabilities" in skill_path.lower():
                    skill_lower = skill_path.lower()
                    if (
                        hasattr(self, "state")
                        and skill_lower.replace("/", "_")
                        in str(self.state.skills_used).lower()
                    ):
                        vuln_class = (
                            skill_path.split("/")[-1].lower().replace(".md", "")
                        )
                        tested.update(self._normalize_vuln_labels(vuln_class))
        except Exception as _e:
            logger.debug("Failed to derive tested vuln classes from skills: %s", _e)

        return tested

    def _get_vuln_terms_from_system_prompt(self) -> list[str]:
        """Parse vulnerability terms from system.txt §11 dynamically."""
        if hasattr(self, "_cached_vuln_terms"):
            return self._cached_vuln_terms

        terms: list[str] = []
        try:
            prompt_path = Path(__file__).parent.parent / "prompts" / "system.txt"
            if prompt_path.exists():
                content = prompt_path.read_text(encoding="utf-8")
                in_section = False
                for line in content.splitlines():
                    if "§11" in line or "VULNERABILITY PRIORITY" in line:
                        in_section = True
                        continue
                    if in_section:
                        if line.startswith("━") or (
                            line.strip().startswith("§") and "§11" not in line
                        ):
                            break
                        if (
                            "P1" in line
                            or "P2" in line
                            or "P3" in line
                            or "P4" in line
                            or "P5" in line
                        ):
                            parts = line.split("  ", 1)
                            if len(parts) > 1:
                                raw_terms = parts[1]
                                for term in raw_terms.split(","):
                                    term = term.strip()
                                    term = term.split("(")[0].strip()
                                    if term.lower() in (
                                        "and",
                                        "or",
                                        "the",
                                        "a",
                                        "an",
                                    ):
                                        continue
                                    if term and len(term) >= 2:
                                        terms.append(term)
        except Exception as _e:
            logger.debug("Failed to parse vuln terms from system prompt: %s", _e)

        # Fallback: derive from skills catalog
        if not terms:
            try:
                skills_index = self._load_skills_index()
                for skill_path in skills_index:
                    if "vulnerabilities" in skill_path.lower():
                        vuln_name = (
                            skill_path.split("/")[-1]
                            .replace(".md", "")
                            .replace("_", " ")
                        )
                        if vuln_name:
                            terms.append(vuln_name)
            except Exception as _e:
                logger.debug("Failed to derive vuln terms from skills: %s", _e)

        self._cached_vuln_terms = terms
        return terms

    def _get_untested_vuln_classes(self, tested: set[str]) -> set[str]:
        """Return vuln classes not yet tested — sourced from data files only."""
        all_classes = set()

        # Source 1: ontology categories and child labels
        try:
            all_classes.update(
                label.lower()
                for label in get_classifier().get_all_categories(include_children=True)
            )
        except Exception as _e:
            logger.debug("Failed to load ontology categories: %s", _e)

        # Source 2: system.txt §11 terms
        system_terms = self._get_vuln_terms_from_system_prompt()
        for term in system_terms:
            all_classes.update(self._normalize_vuln_labels(term))

        # Source 3: skills catalog (vulnerabilities/ category)
        try:
            skills_index = self._load_skills_index()
            for skill_path in skills_index:
                if "vulnerabilities" in skill_path.lower():
                    vuln_name = (
                        skill_path.split("/")[-1].replace(".md", "").replace("-", "_")
                    )
                    all_classes.update(self._normalize_vuln_labels(vuln_name))
        except Exception as _e:
            logger.debug("Failed to derive vuln classes from skills catalog: %s", _e)

        return all_classes - tested

    # ── Dynamic tactic generation — ZERO hardcoded lists ───────────────

    def _generate_dynamic_tactics(
        self,
        phase: PipelinePhase,
        tested_classes: set[str],
        untested_classes: set[str],
        technologies: dict,
        urls: list,
        injection_points: list,
        iteration: int,
    ) -> list[str]:
        """Generate tactics dynamically from session context and data sources.

        No hardcoded vuln lists, tech stacks, URL patterns, or attack vectors.
        All tactics are derived from:
        - system.txt §11 (vuln priorities)
        - skills catalog (vuln skills, tech skills, methodology skills)
        - tools_meta.json (tool descriptions, categories)
        - Session context (tech stack, URLs, injection points)
        - What has already been tested vs what remains
        """
        tactics: list[str] = []
        tech_names = list(technologies.keys()) if technologies else []

        # Priority 1: Untested vuln classes from data sources
        # Pick from untested_classes (dynamically computed), not a hardcoded list
        priority_untested = sorted(untested_classes)[:5]

        for vuln_class in priority_untested:
            tactic = self._tactic_for_vuln_class(
                vuln_class, tech_names, urls, injection_points
            )
            if tactic:
                tactics.append(tactic)

        # Priority 2: Phase-specific guidance from skills catalog
        phase_skill_tactics = self._tactics_from_phase_skills(phase, tested_classes)
        tactics.extend(phase_skill_tactics[:2])

        # Priority 3: Tech-stack tactics from skills catalog
        if tech_names:
            tech_tactics = self._tactics_for_tech_stack(tech_names, tested_classes)
            tactics.extend(tech_tactics[:2])

        # Priority 4: URL-pattern tactics from session data
        if urls:
            url_tactics = self._tactics_for_url_patterns(urls, tested_classes)
            tactics.extend(url_tactics[:2])

        # Priority 5: Novel vectors from skills catalog methodology skills
        novel = self._novel_attack_vectors(tested_classes, iteration)
        tactics.extend(novel[:2])

        return tactics[:8]

    def _tactic_for_vuln_class(
        self, vuln_class: str, tech_names: list, urls: list, injection_points: list
    ) -> str | None:
        """Generate tactic for a vuln class — sourced from skills catalog, not hardcoded."""
        tech_context = (
            f" (target uses: {', '.join(tech_names[:3])})" if tech_names else ""
        )
        param_context = ""
        if injection_points:
            sample = [
                str(p.get("parameter", p.get("name", "")))
                for p in injection_points[:3]
                if isinstance(p, dict)
            ]
            if sample:
                param_context = f" Test on params: {', '.join(sample)}."

        # Try to load skill file for this vuln class
        skill_content = self._load_vuln_skill_content(vuln_class)
        if skill_content:
            return f"{vuln_class.upper()}{tech_context}: {skill_content}{param_context}"

        # Fallback: generate from vuln class name + session context
        # The LLM knows what each vuln class means from system.txt — we just prompt it
        return (
            f"Test for {vuln_class.replace('_', ' ').upper()}{tech_context}. "
            f"Review your loaded skills for this vulnerability class for specific techniques. "
            f"Consider how this applies to the current target's architecture and technology stack.{param_context}"
        )

    def _load_vuln_skill_content(self, vuln_class: str) -> str | None:
        """Load skill file content for a vulnerability class if available."""
        try:
            skills_dir = Path(__file__).parent.parent / "skills" / "vulnerabilities"
            if not skills_dir.is_dir():
                return None

            # Try exact match first
            skill_file = skills_dir / f"{vuln_class}.md"
            if skill_file.exists():
                content = skill_file.read_text(encoding="utf-8")
                # Extract just the first ~200 chars as a hint
                lines = content.splitlines()
                # Skip YAML frontmatter
                in_content = False
                hint_lines = []
                for line in lines:
                    if line.strip() == "---":
                        if in_content:
                            break
                        in_content = True
                        continue
                    if in_content and line.strip() and not line.startswith("#"):
                        hint_lines.append(line.strip())
                        if len(hint_lines) >= 3:
                            break
                return " ".join(hint_lines)[:300] if hint_lines else None

            # Try fuzzy match (replace underscores with hyphens, etc.)
            for alt_name in [
                vuln_class.replace("_", "-"),
                vuln_class.replace("_", " "),
            ]:
                for f in skills_dir.iterdir():
                    if f.stem.lower() == alt_name.lower():
                        content = f.read_text(encoding="utf-8")
                        lines = content.splitlines()
                        in_content = False
                        hint_lines = []
                        for line in lines:
                            if line.strip() == "---":
                                if in_content:
                                    break
                                in_content = True
                                continue
                            if in_content and line.strip() and not line.startswith("#"):
                                hint_lines.append(line.strip())
                                if len(hint_lines) >= 3:
                                    break
                        return " ".join(hint_lines)[:300] if hint_lines else None
        except Exception as _e:
            logger.debug("Failed to load skill hint for %s: %s", vuln_class, _e)
        return None

    def _tactics_from_phase_skills(
        self, phase: PipelinePhase, tested_classes: set[str]
    ) -> list[str]:
        """Generate tactics from skills catalog relevant to this phase."""
        tactics = []
        try:
            skills_index = self._load_skills_index()
            # Map phases to skill categories dynamically
            phase_skill_dirs = {
                PipelinePhase.RECON: ["reconnaissance", "protocols", "tools"],
                PipelinePhase.ANALYSIS: [
                    "vulnerabilities",
                    "frameworks",
                    "technologies",
                    "protocols",
                ],
                PipelinePhase.EXPLOIT: [
                    "payloads",
                    "vulnerabilities",
                    "postexploit",
                    "frameworks",
                ],
            }
            relevant_dirs = phase_skill_dirs.get(phase, [])

            for skill_path in skills_index:
                # Check if skill is in a relevant directory for this phase
                if any(d in skill_path.lower() for d in relevant_dirs):
                    skill_name = skill_path.split("/")[-1].replace(".md", "")
                    # Skip if already tested
                    if skill_name.lower() in tested_classes:
                        continue
                    tactics.append(
                        f"Load skill: {skill_path} — it contains techniques for this phase that may not have been tried yet."
                    )
                    if len(tactics) >= 3:
                        break
        except Exception as _e:
            logger.debug("Failed to derive tactics from phase skills: %s", _e)
        return tactics

    def _tactics_for_tech_stack(
        self, tech_names: list, tested_classes: set[str]
    ) -> list[str]:
        """Generate tactics based on detected tech — from skills catalog, not hardcoded."""
        tactics = []
        try:
            skills_index = self._load_skills_index()
            for tech in tech_names:
                tech_lower = tech.lower()
                # Find skills related to this technology
                for skill_path in skills_index:
                    if (
                        "technologies" in skill_path.lower()
                        or tech_lower in skill_path.lower()
                    ):
                        skill_name = skill_path.split("/")[-1].replace(".md", "")
                        if skill_name.lower() not in tested_classes:
                            tactics.append(
                                f"Load skill: {skill_path} — specific techniques for {tech}."
                            )
                            if len(tactics) >= 2:
                                break
                if len(tactics) >= 2:
                    break
        except Exception as _e:
            logger.debug("Failed to derive tactics for tech stack: %s", _e)

        # If no skills found, generate generic tech-aware guidance
        if not tactics and tech_names:
            tactics.append(
                f"Target technologies detected: {', '.join(tech_names[:5])}. "
                f"Research known vulnerability patterns for these technologies. "
                f"Check skills/technologies/ and skills/vulnerabilities/ for relevant guidance."
            )
        return tactics

    def _tactics_for_url_patterns(
        self, urls: list, tested_classes: set[str]
    ) -> list[str]:
        """Generate tactics based on URL patterns — derived from session data, not hardcoded."""
        tactics = []

        # Dynamically detect patterns from URL content
        # Instead of hardcoded keyword lists, analyze URL structure
        path_segments = set()
        for url in urls:
            try:
                from urllib.parse import urlparse

                parsed = urlparse(url)
                for segment in parsed.path.strip("/").split("/"):
                    if segment:
                        path_segments.add(segment.lower())
            except Exception as _e:
                logger.debug("URL parse failed for %s: %s", url, _e)

        # Generate tactics based on discovered path patterns
        interesting_paths = path_segments - {
            "index",
            "html",
            "css",
            "js",
            "img",
            "assets",
            "static",
        }

        if interesting_paths:
            sample = sorted(interesting_paths)[:5]
            tactics.append(
                f"Interesting path segments discovered: {', '.join(sample)}. "
                f"Test each for: access control bypass, parameter injection, "
                f"path traversal, and unexpected behavior. "
                f"Check skills/vulnerabilities/ for testing methodologies."
            )

        # Check for API-like patterns
        if any("api" in seg for seg in path_segments):
            tactics.append(
                "API endpoints detected — test for BOLA, mass assignment, "
                "improper asset management, and rate limit bypass. "
                "Load skills/vulnerabilities/ for API-specific techniques."
            )

        return tactics

    def _novel_attack_vectors(
        self, tested_classes: set[str], iteration: int
    ) -> list[str]:
        """Generate novel attack vectors from skills catalog methodology skills."""
        vectors = []
        try:
            skills_index = self._load_skills_index()
            # Look for methodology/framework skills that suggest novel approaches
            for skill_path in skills_index:
                if any(
                    kw in skill_path.lower()
                    for kw in ["methodology", "framework", "technique", "advanced"]
                ):
                    skill_name = skill_path.split("/")[-1].replace(".md", "")
                    if skill_name.lower() not in tested_classes:
                        vectors.append(
                            f"Load methodology skill: {skill_path} — "
                            f"advanced techniques that may reveal unique vulnerabilities."
                        )
                        if len(vectors) >= 2:
                            break
        except Exception as _e:
            logger.debug("Failed to derive methodology pivots: %s", _e)

        # If no methodology skills found, derive pivots from ontology edges.
        if not vectors:
            classifier = get_classifier()
            candidate_categories: list[str] = []
            for raw_tested in sorted(tested_classes):
                for label in classifier.resolve_labels(raw_tested):
                    if label in classifier.get_all_categories():
                        for target in classifier.get_escalation_targets(label):
                            if target.lower() not in tested_classes:
                                candidate_categories.append(target)

            if candidate_categories:
                for target in sorted(dict.fromkeys(candidate_categories))[:2]:
                    target_name = target.replace("_", " ")
                    escalations = classifier.get_escalation_targets(target)
                    vectors.append(
                        f"Probe non-obvious pivots around {target_name.upper()}. "
                        f"Look for workflow, trust-boundary, and second-order behaviors that could escalate into "
                        f"{', '.join(e.replace('_', ' ') for e in escalations[:3]) or 'higher impact states'}."
                    )
            else:
                rotation = iteration % 4
                guidance_pool = [
                    "Think about trust boundaries in this application — where do components trust each other? "
                    "Test what happens when that trust is violated.",
                    "Consider the data flow: where does user input enter, how is it processed, where is it stored? "
                    "Test each transformation point for weakness.",
                    "Look for state machine flaws: can you skip steps, replay old states, or trigger operations out of order? "
                    "Developers rarely test edge-case state transitions.",
                    "Think about what the developer assumed would never happen — "
                    "then test exactly that assumption. The most critical bugs are often the ones nobody thought to test.",
                ]
                vectors.append(guidance_pool[rotation])

        return vectors

    def _load_skills_index(self) -> dict[str, str]:
        """Load skills catalog index dynamically."""
        if hasattr(self, "_cached_skills_index"):
            return self._cached_skills_index

        index: dict[str, str] = {}
        try:
            skills_dir = Path(__file__).parent.parent / "skills"
            if skills_dir.is_dir():
                for md_file in skills_dir.rglob("*.md"):
                    rel_path = str(md_file.relative_to(skills_dir))
                    # Read first line as description
                    try:
                        content = md_file.read_text(encoding="utf-8")
                        first_line = content.splitlines()[0].strip().lstrip("#").strip()
                        index[rel_path] = first_line
                    except Exception as _e:
                        logger.debug("Failed to read skill file %s: %s", rel_path, _e)
                        index[rel_path] = ""
        except Exception as _e:
            logger.debug("Failed to build skills index: %s", _e)

        self._cached_skills_index = index
        return index

    @staticmethod
    def _load_recon_tools_from_meta() -> set[str]:
        """Load reconnaissance tool names from tools_meta.json data file."""
        import json
        from pathlib import Path

        try:
            meta_path = Path(__file__).parent.parent / "data" / "tools_meta.json"
            if meta_path.exists():
                with open(meta_path) as f:
                    meta = json.load(f)
                recon = meta.get("categories", {}).get("reconnaissance", {})
                tools: set[str] = set()
                for subcat in recon.values():
                    if isinstance(subcat, list):
                        tools.update(subcat)
                tools |= {"execute", "browser_action"}
                return tools
        except Exception as exc:
            logger.warning("Operation failed: %s", exc)
        # Graceful fallback: only AIRecon-native tools, no shell binaries.
        # Shell-specific tools (httpx, subfinder, etc.) are loaded from
        # tools_meta.json; when unavailable, fall back to the generic
        # execution and browser capabilities only.
        return {"execute", "browser_action"}

    def _self_correcting_strategy(
        self,
        phase: PipelinePhase,
        recent_tools: list[str],
        same_tool_streak: int,
    ) -> str | None:
        """Detect stuck patterns and suggest strategic corrections."""
        if not recent_tools:
            return None

        # Detect: stuck on reconnaissance without moving to exploitation
        if phase == PipelinePhase.RECON:
            recon_tools = self._load_recon_tools_from_meta()
            recon_count = sum(1 for t in recent_tools if t in recon_tools)
            if recon_count >= len(recent_tools) * 0.6 and len(recent_tools) >= 3:
                hint = (
                    "You have been doing RECON for too long without transitioning. "
                    "You should have enough data now. Focus on ANALYSIS: pick the highest-value "
                    "discovered endpoint (admin panel, API, auth endpoint) and start testing it manually. "
                    "Do NOT run more subdomain enumeration or passive recon."
                )
                logger.info(
                    "[Strategy] RECON stagnation detected: %d/%d recon tools, suggesting transition to ANALYSIS",
                    recon_count,
                    len(recent_tools),
                )
                return hint

        # Detect: browser redirect loop trap
        browser_errors = sum(1 for t in recent_tools if t == "browser_action")
        if browser_errors >= 2 and same_tool_streak >= 2:
            hint = (
                "Browser actions are failing repeatedly — likely hitting tracking pixels or redirect loops. "
                "STOP using browser_action. Switch to command-line tools (curl, httpx, ffuf) for HTTP testing. "
                "Browser is only useful for JavaScript-heavy targets with interactive flows."
            )
            logger.info(
                "[Strategy] Browser redirect loop detected: %d browser_action errors, streak=%d",
                browser_errors,
                same_tool_streak,
            )
            return hint

        # Detect: fuzzing without findings
        if phase in (PipelinePhase.RECON, PipelinePhase.ANALYSIS):
            fuzz_count = sum(1 for t in recent_tools if "fuzz" in t)
            if fuzz_count >= 2:
                hint = (
                    "Multiple fuzzing attempts with no findings — you may be fuzzing the wrong targets. "
                    "Stop fuzzing blog URLs, tracking pixels, or content pages. "
                    "Focus on: admin panels, API endpoints, authentication flows, file upload endpoints, "
                    "and any endpoint with user input parameters. Quality over quantity."
                )
                logger.info(
                    "[Strategy] Fuzzing stagnation: %d fuzz attempts with no findings, suggesting target refocus",
                    fuzz_count,
                )
                return hint

        # Detect: tool repetition without progress — lowered from 3 to 2
        if same_tool_streak >= 2:
            hint = (
                f"You've used the same tool {same_tool_streak} times in a row without new findings. "
                "BLOCKED: Do NOT use this tool again this iteration. "
                "Switch to a completely different approach: "
                "if you were using scanners, switch to manual testing. If manual, try automation. "
                "If HTTP testing, try source code analysis. If passive, try active. "
                "If injection testing, try logic flaws. If logic, try crypto."
            )
            logger.info(
                "[Strategy] Tool repetition detected: same tool used %d times consecutively — BLOCKING",
                same_tool_streak,
            )
            return hint

        return None

    def _record_adaptive_learning(
        self,
        tool_name: str,
        arguments: dict,
        result: dict,
        success: bool,
        duration: float,
        phase: str,
    ) -> None:
        """Record tool result to adaptive learning engine for reinforcement feedback."""
        try:
            cfg = get_config()
            if (
                not cfg.intelligence_enabled
                or not cfg.intelligence_adaptive_learning_enabled
            ):
                return

            session_target = ""
            session_id = ""
            session_techs: dict[str, str] = {}
            session_vulns: list[dict] = []
            if hasattr(self, "_session") and self._session:
                session_target = getattr(self._session, "target", "")
                session_id = getattr(self._session, "session_id", "")
                session_techs = getattr(self._session, "technologies", {})
                session_vulns = getattr(self._session, "vulnerabilities", [])

            engine = self._ensure_adaptive_learning_engine()
            if len(engine.observation_log) == 0:
                logger.info(
                    "[AdaptiveLearning] Engine initialized (session=%s, observations=%d)",
                    session_id or "new",
                    len(engine.observation_log),
                )

            self._record_target_memory(tool_name, arguments, result, success)

            confidence = 0.0
            if isinstance(result, dict):
                confidence = float(result.get("confidence", 0.0))
                if not confidence and "findings" in result:
                    findings = result["findings"]
                    if isinstance(findings, list) and findings:
                        confidence = float(findings[0].get("confidence", 0.0))

            tech_summary = ", ".join(session_techs.keys()) if session_techs else ""

            context: dict[str, str] = {"phase": str(phase).strip().upper()}
            for tech_name in session_techs:
                _tech_key = str(tech_name).strip().lower()
                if _tech_key:
                    context[f"tech={_tech_key}"] = "detected"

            engine.record_tool_result(
                tool_name=tool_name,
                arguments=arguments,
                result=result,
                success=success,
                duration=duration,
                confidence=confidence,
                context=context,
                target_type=tech_summary or session_target,
            )

            result_summary = ""
            if isinstance(result, dict):
                findings = result.get("findings", result.get("output", ""))
                if isinstance(findings, list) and findings:
                    result_summary = str(findings[0])[:300]
                elif findings:
                    result_summary = str(findings)[:300]
                vuln_found = None
                if (
                    success
                    and isinstance(result.get("findings"), list)
                    and result["findings"]
                ):
                    for f in result["findings"]:
                        if isinstance(f, dict) and f.get("finding"):
                            vuln_found = str(f["finding"])[:200]
                            break
                if not vuln_found and hasattr(self, "_session") and self._session:
                    cur_count = len(session_vulns)
                    prev_count = getattr(self, "_vuln_count_last_learn", 0)
                    if cur_count > prev_count:
                        self._vuln_count_last_learn = cur_count
                        last_vuln = session_vulns[-1]
                        if isinstance(last_vuln, dict):
                            vuln_found = last_vuln.get(
                                "title", last_vuln.get("finding", "")
                            )[:200]
            engine.record_observation(
                tool_name=tool_name,
                arguments=arguments,
                result_summary=result_summary,
                success=success,
                confidence=confidence,
                phase=phase,
                target_type=tech_summary or session_target,
                vuln_found=vuln_found,
            )

            strategy_conditions: dict[str, Any] = {"phase": phase}
            if session_techs:
                strategy_conditions["tech"] = sorted(session_techs.keys())[0]

            recent_sequence: list[str] = []
            for entry in self.state.tool_history[-3:]:
                entry_name = str(getattr(entry, "tool_name", "")).strip()
                if entry_name:
                    recent_sequence.append(entry_name)
            if tool_name and (not recent_sequence or recent_sequence[-1] != tool_name):
                recent_sequence.append(tool_name)

            engine.record_strategy_result(
                conditions=strategy_conditions,
                tool_sequence=recent_sequence[-3:] or [tool_name],
                success=success,
                confidence=confidence,
            )

            if len(engine.observation_log) % 10 == 0:
                engine.save_state()

            if (
                len(engine.observation_log) > 0
                and len(engine.observation_log) % 30 == 0
            ):
                insights = engine.distill_insights(
                    base_url=cfg.openai_base_url,
                    model=cfg.openai_model,
                    api_key=cfg.openai_api_key,
                )
                if insights:
                    logger.info(
                        "[AdaptiveLearning] Distilled %d new insights from %d observations",
                        len(insights),
                        len(engine.observation_log),
                    )

            logger.debug(
                "[AdaptiveLearning] Recorded: tool=%s success=%s duration=%.2fs phase=%s observations=%d",
                tool_name,
                success,
                duration,
                phase,
                len(engine.observation_log),
            )
        except Exception as exc:
            logger.warning("Operation failed: %s", exc)

    def _record_target_memory(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        result: dict,
        success: bool,
    ) -> None:
        """Record actionable intelligence to per-target memory."""
        target = ""
        if self._session:
            target = getattr(self._session, "target", "")
        if not target:
            return

        if not hasattr(self, "_target_memory_store"):
            from .adaptive_learning import TargetMemoryStore

            self._target_memory_store = TargetMemoryStore()

        store = self._target_memory_store

        if self._session:
            techs = getattr(self._session, "technologies", {})
            for tech_name in techs:
                store.record_tech(target, tech_name)

        if isinstance(result, dict):
            for key in ("endpoints", "urls", "paths", "routes"):
                endpoints = result.get(key, [])
                if isinstance(endpoints, list):
                    for ep in endpoints[:50]:
                        store.record_endpoint(target, str(ep))

            params = result.get("parameters", result.get("params", []))
            if isinstance(params, list):
                for p in params:
                    store.record_param(target, str(p))

        if self._session:
            cur_count = len(getattr(self._session, "vulnerabilities", []))
            prev_count = getattr(self, "_vuln_count_last_target_mem", 0)
            if cur_count > prev_count:
                self._vuln_count_last_target_mem = cur_count
                last_vuln = self._session.vulnerabilities[-1]
                if isinstance(last_vuln, dict):
                    vuln_entry = {
                        "type": last_vuln.get(
                            "type", last_vuln.get("finding", "unknown")
                        ),
                        "path": last_vuln.get("endpoint", last_vuln.get("url", "")),
                        "param": last_vuln.get("parameter", ""),
                        "payload": last_vuln.get("payload", ""),
                        "severity": last_vuln.get("severity", ""),
                        "confirmed": "true" if last_vuln.get("confirmed") else "false",
                    }
                    store.record_vulnerability(target, vuln_entry)

        if tool_name in ("browser_action", "http_observe", "execute"):
            cmd_or_url = str(arguments.get("command", arguments.get("url", ""))).lower()
            if any(
                kw in cmd_or_url
                for kw in ("login", "auth", "token", "session", "register", "password")
            ):
                path = arguments.get("url", "")
                if path:
                    store.record_auth_endpoint(target, str(path))

        # ── Persist high-confidence evidence to TargetMemory ───────────────
        # Evidence with confidence >= 0.85 is saved as a session note so the
        # next session inherits findings without needing to redo discovery.
        if self.state:
            _high_conf = [
                e for e in self.state.evidence_log
                if float(e.get("confidence", 0.0)) >= 0.85
                and str(e.get("summary", "")).strip()
            ]
            _already_noted: set[str] = set(
                getattr(self, "_persisted_evidence_ids", set())
            )
            _new_notes: list[str] = []
            for _ev in _high_conf[-10:]:
                _ev_key = str(_ev.get("summary", ""))[:80]
                if _ev_key not in _already_noted:
                    _new_notes.append(_ev_key)
                    _already_noted.add(_ev_key)
            if _new_notes:
                self._persisted_evidence_ids = _already_noted  # type: ignore[attr-defined]
                for note in _new_notes:
                    store.add_session_note(target, f"[evidence] {note}")

        # ── Persist confirmed hypotheses to TargetMemory ───────────────────
        # Confirmed hypotheses are saved as unverified vulnerabilities so the
        # next session starts with a lead rather than from scratch.
        if self.state:
            _confirmed = [
                h for h in self.state.hypothesis_queue
                if str(h.get("status", "")) == "confirmed"
            ]
            _persisted_hyps: set[str] = set(
                getattr(self, "_persisted_hyp_ids", set())
            )
            for _hyp in _confirmed:
                _hid = str(_hyp.get("id", ""))
                if _hid and _hid not in _persisted_hyps:
                    _claim = str(_hyp.get("claim", ""))[:120]
                    _tags = _hyp.get("tags", [])
                    _vuln_type = str(_tags[0]) if _tags else "unknown"
                    # Verified = independent cross-tool evidence already
                    # backs this claim. Persist as confirmed so next session
                    # inherits a real signal, not just a self-declared claim.
                    _is_verified = bool(_hyp.get("verified"))
                    store.record_vulnerability(target, {
                        "type": _vuln_type,
                        "path": "",
                        "param": "",
                        "payload": "",
                        "severity": "medium",
                        "confirmed": "true" if _is_verified else "false",
                        "note": _claim,
                    })
                    _persisted_hyps.add(_hid)
            self._persisted_hyp_ids = _persisted_hyps  # type: ignore[attr-defined]

        try:
            store.save(target)
        except Exception as exc:
            logger.debug("Target memory save failed for %s: %s", target, exc)

        if getattr(self, "_target_mem_save_counter", 0) % 15 == 0:
            for norm, tm in store._cache.items():
                store.save(norm, tm)
        self._target_mem_save_counter = getattr(self, "_target_mem_save_counter", 0) + 1

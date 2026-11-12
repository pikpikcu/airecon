from __future__ import annotations

import logging
from pathlib import Path
from typing import Any
import os
import random
from dataclasses import dataclass, field
from enum import Enum

from ..config import get_config as _get_config
from ..data_loader import load_tools, load_tools_meta

logger = logging.getLogger("airecon.agent.pipeline")

_PROMPTS_DIR = Path(__file__).parent.parent / "prompts" / "phases"

_TOOLS_META = load_tools_meta()
_TOOLS_DEF = load_tools()
_RECON_HINTS: dict[str, str] = _TOOLS_META.get("recon_phase_hints", {})


def _get_phase_setting(name: str, default: Any) -> Any:
    cfg = _get_config()
    return getattr(cfg, name, default)


_LIVE_HOST_HINT: str = _RECON_HINTS.get(
    "live_host_validation",
    "CRITICAL: After subdomain enumeration, ALWAYS validate which hosts are alive before "
    "port scanning or directory brute-force. Use host probing tools to filter dead/unresolved hosts. "
    "Never scan dead hosts.",
)


class PipelinePhase(Enum):
    RECON = "RECON"
    ANALYSIS = "ANALYSIS"
    EXPLOIT = "EXPLOIT"
    REPORT = "REPORT"
    COMPLETE = "COMPLETE"


_PHASE_SEQUENCE_FALLBACK = [
    "RECON",
    "ANALYSIS",
    "EXPLOIT",
    "REPORT",
    "COMPLETE",
]


def _normalize_phase_sequence(raw_sequence: Any) -> list[PipelinePhase]:
    phases: list[PipelinePhase] = []
    seen: set[PipelinePhase] = set()

    for item in raw_sequence if isinstance(raw_sequence, list) else []:
        try:
            phase = PipelinePhase(str(item).strip().upper())
        except ValueError:
            continue
        if phase not in seen:
            seen.add(phase)
            phases.append(phase)

    for fallback_name in _PHASE_SEQUENCE_FALLBACK:
        phase = PipelinePhase(fallback_name)
        if phase not in seen:
            phases.append(phase)
            seen.add(phase)

    return phases


def _extract_phase_objective_from_prompt(phase: PipelinePhase) -> str:
    prompt_file = _PROMPTS_DIR / f"{phase.value.lower()}.txt"
    if not prompt_file.exists():
        return ""

    try:
        raw_lines = prompt_file.read_text(encoding="utf-8").splitlines()
    except Exception as exc:
        logger.debug("Failed to read phase prompt %s: %s", prompt_file.name, exc)
        return ""

    capture = False
    collected: list[str] = []
    for raw_line in raw_lines:
        stripped = raw_line.strip()
        if not capture and (
            stripped.startswith("OBJECTIVE:") or stripped.startswith("DIRECTIVE:")
        ):
            capture = True
            _, _, tail = stripped.partition(":")
            if tail.strip():
                collected.append(tail.strip())
            continue
        if not capture:
            continue
        if not stripped:
            if collected:
                break
            continue
        if stripped.startswith("<") or stripped.startswith("["):
            break
        if stripped.endswith(":") and collected:
            break
        collected.append(stripped)

    return " ".join(collected).strip()


def _collect_categorized_tools() -> set[str]:
    categorized: set[str] = set()
    categories = _TOOLS_META.get("categories", {})
    if not isinstance(categories, dict):
        return categorized

    for group in categories.values():
        if not isinstance(group, dict):
            continue
        for tool_list in group.values():
            if isinstance(tool_list, list):
                categorized.update(
                    str(tool).strip()
                    for tool in tool_list
                    if str(tool).strip()
                )
    return categorized


def _derive_core_tools() -> set[str]:
    core: set[str] = set()
    for tool_def in _TOOLS_DEF:
        name = str(tool_def.get("function", {}).get("name", "")).strip()
        if name:
            core.add(name)

    core -= _collect_categorized_tools()
    return {
        str(name).strip()
        for name in core
        if str(name).strip()
    }


def _lookup_subcategory_tools(subcategory: str) -> set[str]:
    categories = _TOOLS_META.get("categories", {})
    result: set[str] = set()
    if not isinstance(categories, dict):
        return result

    for group in categories.values():
        if not isinstance(group, dict):
            continue
        tool_list = group.get(subcategory)
        if isinstance(tool_list, list):
            result.update(str(tool).strip() for tool in tool_list if str(tool).strip())
    return result


_PHASE_CRITERIA_FALLBACK: dict[str, list[str]] = {
    "RECON": [
        "subdomains_discovered",
        "live_hosts_validated",
        "ports_scanned",
        "recon_artifacts_saved",
        "subdomain_depth_met",
        "url_discovery_met",
    ],
    "ANALYSIS": [
        "urls_collected",
        "technologies_identified",
        "injection_points_found",
    ],
    "EXPLOIT": [
        "vulnerabilities_tested",
    ],
    "REPORT": [
        "reports_generated",
    ],
}

_PHASE_OBJECTIVE_FALLBACKS: dict[str, str] = {
    "RECON": (
        "Understand the target deeply and adapt reconnaissance to the real "
        "attack surface. " + _LIVE_HOST_HINT
    ),
    "ANALYSIS": (
        "Identify exploitable weaknesses based on observed behavior, trust "
        "boundaries, and detected technology."
    ),
    "EXPLOIT": (
        "Verify exploitability with reproducible impact and convert high-value "
        "candidates into concrete evidence."
    ),
    "REPORT": (
        "Generate decision-grade reports for confirmed findings with clear "
        "reproduction steps and remediation."
    ),
}


def _build_phase_tool_map() -> dict[str, set[str]]:
    core_tools = _derive_core_tools()
    phase_tools: dict[str, set[str]] = {
        phase.value: set(core_tools) for phase in PipelinePhase if phase != PipelinePhase.COMPLETE
    }

    report_tools = {
        str(tool).strip()
        for tool in _TOOLS_META.get("report_tools", [])
        if str(tool).strip()
    }
    if report_tools:
        phase_tools["REPORT"] = set(report_tools)

    phase_extras = _TOOLS_META.get("phase_extras", {})
    if isinstance(phase_extras, dict):
        for phase_name, extras in phase_extras.items():
            if phase_name not in phase_tools or not isinstance(extras, list):
                continue
            phase_tools[phase_name].update(
                str(tool).strip() for tool in extras if str(tool).strip()
            )

    phase_category_map = _TOOLS_META.get("phase_category_map", {})
    if isinstance(phase_category_map, dict):
        for phase_name, subcategories in phase_category_map.items():
            if phase_name not in phase_tools or not isinstance(subcategories, list):
                continue
            for subcategory in subcategories:
                phase_tools[phase_name].update(_lookup_subcategory_tools(str(subcategory)))

    return phase_tools


_PHASE_TOOL_MAP = _build_phase_tool_map()


def _build_tool_phase_expectations() -> dict[str, set[str]]:
    expectations: dict[str, set[str]] = {}
    for phase_name, tools in _PHASE_TOOL_MAP.items():
        for tool_name in tools:
            expectations.setdefault(tool_name, set()).add(phase_name)
    return expectations


_TOOL_PHASE_EXPECTATIONS = _build_tool_phase_expectations()


def _load_phase_transition_criteria(phase: PipelinePhase) -> list[str]:
    criteria_map = _TOOLS_META.get("phase_criteria", {})
    criteria = criteria_map.get(phase.value, []) if isinstance(criteria_map, dict) else []
    if isinstance(criteria, list) and criteria:
        return [str(item).strip() for item in criteria if str(item).strip()]
    return list(_PHASE_CRITERIA_FALLBACK.get(phase.value, []))


def _load_phase_confidence_thresholds() -> dict[PipelinePhase, float]:
    cfg = _get_config()
    return {
        PipelinePhase.RECON: getattr(cfg, "pipeline_confidence_threshold_recon", 0.60),
        PipelinePhase.ANALYSIS: getattr(
            cfg, "pipeline_confidence_threshold_analysis", 0.58
        ),
        PipelinePhase.EXPLOIT: getattr(
            cfg, "pipeline_confidence_threshold_exploit", 0.55
        ),
        PipelinePhase.REPORT: getattr(
            cfg, "pipeline_confidence_threshold_report", 0.50
        ),
    }


_PHASE_CONFIDENCE_THRESHOLDS: dict[PipelinePhase, float] = (
    _load_phase_confidence_thresholds()
)


@dataclass
class PhaseConfig:
    phase: PipelinePhase
    max_iterations: int
    objective: str
    recommended_tools: list[str] = field(default_factory=list)
    transition_criteria: list[str] = field(default_factory=list)

    exploration_hints: list[str] = field(default_factory=list)


def _phase_max_iterations(phase: PipelinePhase) -> int:
    cfg = _get_config()
    attr_name = f"pipeline_{phase.value.lower()}_max_iterations"
    return int(getattr(cfg, attr_name, 100))


def _build_phase_configs() -> dict[PipelinePhase, PhaseConfig]:
    configs: dict[PipelinePhase, PhaseConfig] = {}
    for phase in (
        PipelinePhase.RECON,
        PipelinePhase.ANALYSIS,
        PipelinePhase.EXPLOIT,
        PipelinePhase.REPORT,
    ):
        configs[phase] = PhaseConfig(
            phase=phase,
            max_iterations=_phase_max_iterations(phase),
            objective=(
                _extract_phase_objective_from_prompt(phase)
                or _PHASE_OBJECTIVE_FALLBACKS[phase.value]
            ),
            recommended_tools=sorted(_PHASE_TOOL_MAP.get(phase.value, set())),
            transition_criteria=_load_phase_transition_criteria(phase),
        )
    return configs


DEFAULT_PHASES: dict[PipelinePhase, PhaseConfig] = _build_phase_configs()

RECON_PHASE_CONFIG = DEFAULT_PHASES[PipelinePhase.RECON]
ANALYSIS_PHASE_CONFIG = DEFAULT_PHASES[PipelinePhase.ANALYSIS]
EXPLOIT_PHASE_CONFIG = DEFAULT_PHASES[PipelinePhase.EXPLOIT]
REPORT_PHASE_CONFIG = DEFAULT_PHASES[PipelinePhase.REPORT]

_PHASE_ORDER = _normalize_phase_sequence(_TOOLS_META.get("phase_sequence"))


def _load_phase_tool_budgets() -> dict[str, dict[str, int]]:
    cfg = _get_config()
    return {
        "RECON": {
            "quick_fuzz": getattr(cfg, "pipeline_tool_budget_recon_quick_fuzz", 10),
            "advanced_fuzz": getattr(
                cfg, "pipeline_tool_budget_recon_advanced_fuzz", 5
            ),
            "deep_fuzz": getattr(cfg, "pipeline_tool_budget_recon_deep_fuzz", 0),
            "caido_automate": getattr(
                cfg, "pipeline_tool_budget_recon_caido_automate", 5
            ),
            "create_vulnerability_report": getattr(
                cfg, "pipeline_tool_budget_recon_create_vulnerability_report", 2
            ),
        },
        "ANALYSIS": {
            "advanced_fuzz": getattr(
                cfg, "pipeline_tool_budget_analysis_advanced_fuzz", 20
            ),
            "deep_fuzz": getattr(cfg, "pipeline_tool_budget_analysis_deep_fuzz", 5),
            "create_vulnerability_report": getattr(
                cfg, "pipeline_tool_budget_analysis_create_vulnerability_report", 5
            ),
        },
        "EXPLOIT": {
            "advanced_fuzz": getattr(
                cfg, "pipeline_tool_budget_exploit_advanced_fuzz", 50
            ),
            "deep_fuzz": getattr(cfg, "pipeline_tool_budget_exploit_deep_fuzz", 25),
            "quick_fuzz": getattr(cfg, "pipeline_tool_budget_exploit_quick_fuzz", 30),
            "caido_automate": getattr(
                cfg, "pipeline_tool_budget_exploit_caido_automate", 40
            ),
        },
        "REPORT": {
            "execute": getattr(cfg, "pipeline_tool_budget_report_execute", 50),
            "advanced_fuzz": getattr(
                cfg, "pipeline_tool_budget_report_advanced_fuzz", 2
            ),
            "deep_fuzz": getattr(cfg, "pipeline_tool_budget_report_deep_fuzz", 1),
            "quick_fuzz": getattr(cfg, "pipeline_tool_budget_report_quick_fuzz", 2),
        },
    }


_PHASE_TOOL_BUDGETS: dict[str, dict[str, int]] = _load_phase_tool_budgets()

_TOOL_ADVISORY_LEVELS: dict[str, dict[str, str]] = {
    "RECON": {
        "quick_fuzz": "courageous",
        "advanced_fuzz": "useful",
        "deep_fuzz": "courageous",
        "caido_automate": "optional",
        "create_vulnerability_report": "premature",
    },
    "ANALYSIS": {
        "quick_fuzz": "optional",
        "advanced_fuzz": "optimal",
        "deep_fuzz": "useful",
        "caido_automate": "useful",
        "create_vulnerability_report": "premature",
    },
    "EXPLOIT": {
        "quick_fuzz": "optimal",
        "advanced_fuzz": "optimal",
        "deep_fuzz": "useful",
        "caido_automate": "useful",
        "create_vulnerability_report": "optimal",
    },
    "REPORT": {
        "execute": "optimal",
        "create_vulnerability_report": "optimal",
        "advanced_fuzz": "validation",
        "deep_fuzz": "validation",
        "quick_fuzz": "validation",
    },
}


_HINT_POOLS: dict[str, list[str]] = _TOOLS_META.get("phase_exploration_hints", {})


def _generate_dynamic_hints(
    phase: PipelinePhase,
    session: Any,
    evidence_log: list[dict[str, Any]],
    iteration: int,
    consecutive_failures: int = 0,
) -> list[str]:
    hints: list[str] = []
    phase_value = phase.value

    technologies = {}
    urls = []
    vuln_types_tested: set[str] = set()
    try:
        technologies = getattr(session, "technologies", {}) or {}
        urls = getattr(session, "urls", []) or []
    except AttributeError:
        pass

    for ev in evidence_log:
        tags = ev.get("tags", []) or []
        for tag in tags:
            if tag and isinstance(tag, str):
                vuln_types_tested.add(tag.lower())

    if phase_value == "RECON":
        has_subdomains = bool(getattr(session, "subdomains", []))
        has_live = bool(getattr(session, "live_hosts", []))
        if not has_subdomains:
            pool = _HINT_POOLS["recon_osint"] + _HINT_POOLS["recon_surface"]
        elif has_subdomains and not has_live:
            hints.append(
                "You have subdomains — validate which are ALIVE before deeper scanning"
            )
            pool = _HINT_POOLS["recon_fingerprint"]
        else:
            pool = _HINT_POOLS["recon_surface"] + _HINT_POOLS["recon_fingerprint"]

        if technologies:
            tech_names = list(technologies.keys())
            hints.append(
                f"Target uses: {', '.join(tech_names[:5])}. "
                f"Research version-specific recon techniques for these technologies."
            )

        if pool:
            rotation = iteration % max(1, len(pool))
            n = min(3, len(pool))
            selected = pool[rotation : rotation + n]
            if len(selected) < n:
                selected += pool[: n - len(selected)]
            hints.extend(selected)

    elif phase_value == "ANALYSIS":
        tech_names = list(technologies.keys())

        auth_keywords = {
            "login",
            "auth",
            "session",
            "token",
            "password",
            "register",
            "oauth",
        }
        url_segments = set()
        for url in urls:
            for seg in str(url).lower().split("/"):
                url_segments.add(seg)

        if url_segments & auth_keywords:
            hints.extend(
                random.sample(
                    _HINT_POOLS["analysis_auth"],
                    min(3, len(_HINT_POOLS["analysis_auth"])),
                )
            )

        if tech_names:
            hints.append(
                f"Technologies: {', '.join(tech_names[:4])}. "
                f"Research EXACT version vulnerabilities — not just product names."
            )
            hints.extend(
                random.sample(
                    _HINT_POOLS["analysis_tech"],
                    min(2, len(_HINT_POOLS["analysis_tech"])),
                )
            )

        hints.extend(
            random.sample(
                _HINT_POOLS["analysis_logic"],
                min(2, len(_HINT_POOLS["analysis_logic"])),
            )
        )

        hints.extend(
            random.sample(
                _HINT_POOLS["analysis_injection"],
                min(2, len(_HINT_POOLS["analysis_injection"])),
            )
        )

        api_urls = [u for u in urls if "/api/" in str(u) or "/graphql" in str(u)]
        if api_urls:
            hints.append(
                "API endpoints detected — test for BOLA, mass assignment, "
                "improper asset management, introspection exposure."
            )
            api_specific = [
                h for h in _HINT_POOLS["analysis_auth"] if "BOLA" in h or "API" in h
            ]
            hints.extend(api_specific)

    elif phase_value == "EXPLOIT":
        vuln_count = len(getattr(session, "vulnerabilities", []))
        if vuln_count == 0:
            hints.append(
                "No vulnerabilities confirmed yet. Focus on proof-of-concept: "
                "pick the most likely candidate from ANALYSIS findings and demonstrate it."
            )
        else:
            hints.append(
                f"{vuln_count} vulnerability(ies) confirmed. Focus on demonstrating actual impact "
                f"and chaining related findings."
            )

        hints.extend(
            random.sample(
                _HINT_POOLS["exploit_verify"],
                min(2, len(_HINT_POOLS["exploit_verify"])),
            )
        )

        _advanced_hints_failure_threshold = _get_phase_setting(
            "pipeline_advanced_hints_failure_threshold", 3
        )
        if consecutive_failures >= _advanced_hints_failure_threshold:
            hints.extend(
                random.sample(
                    _HINT_POOLS["exploit_advanced"],
                    min(2, len(_HINT_POOLS["exploit_advanced"])),
                )
            )

    vuln_count = len(getattr(session, "vulnerabilities", []) or [])
    _simple = _get_phase_setting("pipeline_counterfactual_interval_simple", 8)
    _complex = _get_phase_setting("pipeline_counterfactual_interval_complex", 5)
    counterfactual_interval = _complex if vuln_count >= 5 else _simple

    if iteration > 0 and (
        iteration % counterfactual_interval == 0 or consecutive_failures >= 3
    ):
        counterfactual = _generate_counterfactual(
            phase=phase_value, session=session, technologies=technologies
        )
        if counterfactual:
            hints.append(counterfactual)

    unique = []
    seen: set[str] = set()
    for h in hints:
        if h not in seen:
            seen.add(h)
            unique.append(h)

    return unique[:5]


def _generate_counterfactual(
    phase: str, session: Any, technologies: dict
) -> str | None:
    vulns = getattr(session, "vulnerabilities", []) or []
    tech_names = list(technologies.keys()) if technologies else []

    counterfactuals = []

    if tech_names:
        counterfactuals.append(
            f"Counterfactual: You detected {', '.join(tech_names[:3])}. "
            f"What if one of these is a decoy/CDN/proxy and the real technology is different? "
            f"Test the actual origin server."
        )

    if vulns:
        vuln_types = set()
        for v in vulns:
            vt = str(v.get("type", v.get("finding", ""))).lower()
            if vt:
                vuln_types.add(vt)

        if "xss" in str(vuln_types):
            counterfactuals.append(
                "Counterfactual: You confirmed XSS. But what if the injection is processed server-side? "
                "That means the same entry point could allow SSTI or SSRF — test those."
            )
        if "sqli" in str(vuln_types) or "sql" in str(vuln_types):
            counterfactuals.append(
                "Counterfactual: You found SQL injection. But what if the real value is not data extraction "
                "but RCE via xp_cmdshell, INTO OUTFILE, or pg_read_file? Test for code execution."
            )
        if "idor" in str(vuln_types) or "access" in str(vuln_types):
            counterfactuals.append(
                "Counterfactual: You found an access control flaw. What if there are MULTIPLE "
                "levels of broken authorization? Test admin endpoints, API endpoints, and internal services."
            )

    if not counterfactuals:
        counterfactuals.append(
            "Counterfactual: Everything appears secure from the outside. "
            "What internal assumption would the developer make that, if wrong, "
            "would be catastrophic? Test exactly that."
        )

    idx = int(session.scan_count or 0) % len(counterfactuals)
    return f"COUNTERFACTUAL CHALLENGE: {counterfactuals[idx]}"


class PipelineEngine:
    MIN_ITERATIONS_PER_PHASE = 10

    def __init__(self, session: Any, config: Any = None) -> None:
        self.session = session
        self._phase_prompts: dict[PipelinePhase, str] = {}
        self._phase_entry_iteration: int = 0
        self._current_iteration: int = 0
        self._ctf_mode: bool = False
        self._last_hint_seed: int = 0
        self._previous_hints: list[str] = []

        cfg = config if config is not None else _get_config()

        self._recon_min_subdomains: int = _get_phase_setting(
            "pipeline_recon_min_subdomains", 3
        )
        self._recon_min_urls: int = _get_phase_setting("pipeline_recon_min_urls", 1)
        self._recon_soft_timeout: int = _get_phase_setting(
            "pipeline_recon_soft_timeout", 30
        )

        self._recon_hard_timeout: int = _get_phase_setting(
            "pipeline_recon_hard_timeout", 60
        )

        self._exploit_max_iterations: int = getattr(
            cfg, "pipeline_exploit_max_iterations", 800
        )
        self._analysis_max_iterations: int = getattr(
            cfg, "pipeline_analysis_max_iterations", 300
        )
        self._recon_max_iterations: int = getattr(
            cfg, "pipeline_recon_max_iterations", 500
        )

        self._phase_vuln_baseline: int = 0

        self._load_phase_prompts()

    def _load_phase_prompts(self) -> None:
        for phase in PipelinePhase:
            if phase == PipelinePhase.COMPLETE:
                continue
            prompt_file = _PROMPTS_DIR / f"{phase.value.lower()}.txt"
            try:
                if prompt_file.exists():
                    self._phase_prompts[phase] = prompt_file.read_text(encoding="utf-8")
                else:
                    self._phase_prompts[phase] = self._default_prompt(phase)
            except Exception as e:
                logger.warning("Failed to load phase prompt for %s: %s", phase.value, e)
                self._phase_prompts[phase] = self._default_prompt(phase)

    def _default_prompt(self, phase: PipelinePhase) -> str:
        config = DEFAULT_PHASES.get(phase)
        if not config:
            return ""
        return (
            f"[PIPELINE PHASE: {phase.value}]\n"
            f"Objective: {config.objective}\n"
            "Use the most suitable available capabilities for this phase objective.\n"
            "Complete this phase thoroughly before moving to the next."
        )

    def get_current_phase(self) -> PipelinePhase:
        phase_str = getattr(self.session, "current_phase", "RECON")
        try:
            return PipelinePhase(phase_str)
        except ValueError:
            return PipelinePhase.RECON

    def get_tool_budget(self, phase: str, tool_name: str) -> int | None:
        phase_budgets = _PHASE_TOOL_BUDGETS.get(phase, {})
        return phase_budgets.get(tool_name)

    def set_phase(self, phase: PipelinePhase) -> None:
        self.session.current_phase = phase.value
        self._phase_entry_iteration = self._current_iteration
        self._previous_hints = []
        logger.info("Pipeline phase set to: %s", phase.value)

    def set_ctf_mode(self, enabled: bool = True) -> None:
        self._ctf_mode = enabled
        if enabled:
            current = self.get_current_phase()
            if current == PipelinePhase.RECON:
                self.set_phase(PipelinePhase.EXPLOIT)
            logger.info("Pipeline CTF mode enabled — skipped to EXPLOIT phase")

    def check_tool_phase_fit(self, tool_name: str) -> str | None:
        current = self.get_current_phase()
        expected_phases = sorted(_TOOL_PHASE_EXPECTATIONS.get(tool_name, set()))
        if not expected_phases:
            return None
        if current.value in expected_phases:
            return None

        return (
            f"[PHASE MISMATCH] Tool '{tool_name}' is typically used in "
            f"{', '.join(expected_phases)} phase(s), but current phase is "
            f"{current.value}. This may be intentional — proceed if justified."
        )

    def should_transition(self) -> bool:
        if self._ctf_mode:
            logger.debug("[Pipeline] CTF mode — blocking transition")
            return False

        current = self.get_current_phase()
        if current == PipelinePhase.COMPLETE:
            logger.debug("[Pipeline] Phase COMPLETE — blocking transition")
            return False

        config = DEFAULT_PHASES.get(current)
        if not config:
            logger.debug(
                "[Pipeline] No config for phase %s — blocking transition", current.value
            )
            return False

        iterations_in_phase = self._current_iteration - self._phase_entry_iteration

        min_iterations = self._calculate_dynamic_min_iterations(current)
        if iterations_in_phase < min_iterations:
            logger.debug(
                "[Pipeline] Phase %s: %d iterations < dynamic min %d (based on evidence collected) — continue",
                current.value,
                iterations_in_phase,
                min_iterations,
            )
            return False

        _max_cap = _get_phase_setting("pipeline_max_iterations_cap", 350)
        MAX_PHASE_ITERATIONS = _max_cap
        if iterations_in_phase > MAX_PHASE_ITERATIONS:
            logger.warning(
                "Phase %s has run for %d iterations (limit=%d) - forcing transition to prevent stagnation",
                current.value,
                iterations_in_phase,
                MAX_PHASE_ITERATIONS,
            )
            return True

        if current == PipelinePhase.RECON:
            met_criteria = self._evaluate_criteria(current)
            has_any_data = bool(
                getattr(self.session, "urls", [])
                or getattr(self.session, "open_ports", {})
                or getattr(self.session, "subdomains", [])
                or getattr(self.session, "live_hosts", [])
            )

            if iterations_in_phase >= self._recon_soft_timeout:
                if has_any_data:
                    if "live_hosts_validated" in met_criteria:
                        logger.info(
                            "RECON soft timeout (%d iter) reached with data and mandatory met. Transitioning.",
                            iterations_in_phase,
                        )
                        return True
                    else:
                        if iterations_in_phase >= self._recon_hard_timeout:
                            logger.warning(
                                "RECON hard timeout (%d iter) with data but mandatory not met. Forcing transition.",
                                iterations_in_phase,
                            )
                            return True
                        logger.info(
                            "RECON soft timeout reached with data but mandatory not met; continuing exploration."
                        )
                        return False
                else:
                    logger.info(
                        "RECON soft timeout (%d iter) with no data; forcing transition.",
                        iterations_in_phase,
                    )
                    return True

            has_subs = "subdomains_discovered" in met_criteria
            has_live = "live_hosts_validated" in met_criteria
            has_urls = "url_discovery_met" in met_criteria
            has_ports = "ports_scanned" in met_criteria
            has_artifacts = "recon_artifacts_saved" in met_criteria

            strong_signals = sum(
                [has_subs, has_live, has_urls, has_ports, has_artifacts]
            )
            _recon_strong_signals_threshold = _get_phase_setting(
                "pipeline_recon_strong_signals_threshold", 2
            )
            if strong_signals >= _recon_strong_signals_threshold:
                logger.info(
                    "RECON: %d strong signals found (subdomains=%s, live_hosts=%s, urls=%s, ports=%s, artifacts=%s) — ready to transition",
                    strong_signals,
                    has_subs,
                    has_live,
                    has_urls,
                    has_ports,
                    has_artifacts,
                )
                return True
            else:
                logger.debug(
                    "[Pipeline] RECON: only %d strong signals (need ≥2) — continue discovery",
                    strong_signals,
                )
                return False

        met_criteria = self._evaluate_criteria(current)
        total = len(config.transition_criteria)
        coverage = len(met_criteria) / max(1, total) if total > 0 else 0

        logger.debug(
            "[Pipeline] Phase %s evaluation: coverage=%.0%% (met=%d/%d)",
            current.value,
            coverage * 100,
            len(met_criteria),
            total,
        )

        confidence = self._phase_transition_confidence(
            current,
            met_criteria=met_criteria,
            total_criteria=total,
            iterations_in_phase=iterations_in_phase,
        )
        threshold = _PHASE_CONFIDENCE_THRESHOLDS.get(current, 0.50)
        decision = confidence >= threshold

        logger.info(
            "[Pipeline] %s transition: confidence=%.2f threshold=%.2f → %s",
            current.value,
            confidence,
            threshold,
            "ALLOW" if decision else "CONTINUE",
        )
        return decision

    def _calculate_dynamic_min_iterations(self, phase: PipelinePhase) -> int:
        if phase == PipelinePhase.RECON:
            has_data = bool(
                getattr(self.session, "urls", [])
                or getattr(self.session, "open_ports", {})
                or getattr(self.session, "subdomains", [])
            )
            return 10 if has_data else 20
        elif phase == PipelinePhase.ANALYSIS:
            return 3
        elif phase == PipelinePhase.EXPLOIT:
            return 2
        return 5

    def _phase_transition_confidence(
        self,
        phase: PipelinePhase,
        *,
        met_criteria: list[str],
        total_criteria: int,
        iterations_in_phase: int,
    ) -> float:
        if total_criteria <= 0:
            return 0.0
        coverage = len(met_criteria) / max(1, total_criteria)
        maturity = min(1.0, iterations_in_phase / max(1, self.MIN_ITERATIONS_PER_PHASE))
        evidence_quality, consistency_penalty = self._phase_causal_signals(phase)

        base = coverage * (0.55 + (0.25 * evidence_quality) + (0.20 * maturity))
        confidence = (
            base + (evidence_quality * 0.25) + (maturity * 0.08) - consistency_penalty
        )
        result = round(min(1.0, max(0.0, confidence)), 3)
        logger.debug(
            "[Pipeline] Confidence calc: phase=%s coverage=%.2f maturity=%.2f "
            "evidence_quality=%.2f penalty=%.2f base=%.2f → %.3",
            phase.value,
            coverage,
            maturity,
            evidence_quality,
            consistency_penalty,
            base,
            result,
        )
        return result

    @staticmethod
    def _vulnerability_severity(vuln: dict[str, Any]) -> str:
        sev = str(vuln.get("severity", "")).strip().upper()
        if sev in {"1", "2", "3", "4", "5"}:
            return {
                "1": "INFO",
                "2": "LOW",
                "3": "MEDIUM",
                "4": "HIGH",
                "5": "CRITICAL",
            }[sev]
        if sev in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}:
            return sev
        finding = str(vuln.get("finding", "")).upper()
        for label in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            if f"[{label}]" in finding:
                return label
        return "MEDIUM"

    def _phase_causal_signals(self, phase: PipelinePhase) -> tuple[float, float]:
        s = self.session
        penalty = 0.0

        if phase == PipelinePhase.RECON:
            subdomains = max(1, len(getattr(s, "subdomains", [])))
            live_hosts = len(getattr(s, "live_hosts", []))
            urls = len(getattr(s, "urls", []))
            open_ports = sum(
                len(ports)
                for ports in getattr(s, "open_ports", {}).values()
                if isinstance(ports, list)
            )

            host_coverage = min(1.0, live_hosts / subdomains)
            service_coverage = min(1.0, open_ports / max(1, live_hosts * 2))
            endpoint_depth = min(1.0, urls / max(1, live_hosts * 2))

            if open_ports > 0 and live_hosts == 0:
                penalty += 0.18
            if urls > 0 and live_hosts == 0:
                penalty += 0.10

            quality = (
                (host_coverage * 0.40)
                + (service_coverage * 0.35)
                + (endpoint_depth * 0.25)
            )
            return quality, min(0.40, penalty)

        if phase == PipelinePhase.ANALYSIS:
            urls = len(getattr(s, "urls", []))
            tech_count = len(getattr(s, "technologies", {}))
            inj_points = len(getattr(s, "injection_points", []))
            vuln_count = len(getattr(s, "vulnerabilities", []))

            injection_density = min(
                1.0, inj_points / max(1, min(20, urls if urls > 0 else 4))
            )
            tech_context = min(1.0, tech_count / 6)
            vuln_signal = min(
                1.0, vuln_count / max(1, inj_points if inj_points > 0 else 3)
            )

            if inj_points > 0 and urls == 0:
                penalty += 0.15
            if vuln_count > 0 and inj_points == 0:
                penalty += 0.12
            if urls >= 5 and tech_count == 0:
                penalty += 0.06

            quality = (
                (injection_density * 0.45)
                + (tech_context * 0.35)
                + (vuln_signal * 0.20)
            )
            return quality, min(0.40, penalty)

        if phase == PipelinePhase.EXPLOIT:
            vulns = getattr(s, "vulnerabilities", [])
            if not vulns:
                return 0.0, 0.0

            severe = 0
            confirmed = 0
            poc_backed = 0
            for vuln in vulns:
                sev = self._vulnerability_severity(vuln)
                if sev in {"CRITICAL", "HIGH", "MEDIUM"}:
                    severe += 1
                if bool(
                    vuln.get("report_generated")
                    or vuln.get("replay_verified")
                    or vuln.get("verified")
                ):
                    confirmed += 1
                if bool(
                    vuln.get("proo")
                    or vuln.get("evidence")
                    or vuln.get("poc_script_code")
                ):
                    poc_backed += 1

            severe_ratio = severe / len(vulns)
            confirmation_ratio = confirmed / len(vulns)
            exploitability_ratio = poc_backed / len(vulns)

            if severe > 0 and poc_backed == 0:
                penalty += 0.12
            if confirmation_ratio < 0.2 and len(vulns) >= 3:
                penalty += 0.08

            quality = (
                (confirmation_ratio * 0.45)
                + (exploitability_ratio * 0.35)
                + (severe_ratio * 0.20)
            )
            return quality, min(0.35, penalty)

        if phase == PipelinePhase.REPORT:
            vulns = getattr(s, "vulnerabilities", [])
            if not vulns:
                return 0.0, 0.0

            reported = 0
            replay_verified = 0
            technical_complete = 0
            for vuln in vulns:
                if vuln.get("report_generated"):
                    reported += 1
                if (
                    vuln.get("replay_verified")
                    or vuln.get("verified")
                    or float(vuln.get("verification_score", 0.0)) >= 0.6
                ):
                    replay_verified += 1
                if vuln.get("technical_analysis") and vuln.get("remediation"):
                    technical_complete += 1

            report_ratio = reported / len(vulns)
            replay_ratio = replay_verified / len(vulns)
            technical_ratio = technical_complete / len(vulns)

            if reported > 0 and replay_verified == 0:
                penalty += 0.15
            if report_ratio < 0.5 and len(vulns) >= 2:
                penalty += 0.08

            quality = (
                (report_ratio * 0.40) + (replay_ratio * 0.40) + (technical_ratio * 0.20)
            )
            return quality, min(0.35, penalty)

        return 0.0, 0.0

    def get_phase_transition_confidence(self) -> float:
        current = self.get_current_phase()
        if current == PipelinePhase.COMPLETE:
            return 1.0
        config = DEFAULT_PHASES.get(current)
        if not config:
            return 0.0
        met = self._evaluate_criteria(current)
        iterations_in_phase = self._current_iteration - self._phase_entry_iteration
        return self._phase_transition_confidence(
            current,
            met_criteria=met,
            total_criteria=len(config.transition_criteria),
            iterations_in_phase=iterations_in_phase,
        )

    def _evaluate_criteria(self, phase: PipelinePhase) -> list[str]:
        met: list[str] = []
        session = self.session

        if phase == PipelinePhase.RECON:
            if getattr(session, "subdomains", []):
                met.append("subdomains_discovered")

            if getattr(session, "live_hosts", []):
                met.append("live_hosts_validated")
            if getattr(session, "open_ports", {}):
                met.append("ports_scanned")

            _recon_extensions = {
                ".txt",
                ".out",
                ".nmap",
                ".csv",
                ".json",
                ".xml",
                ".html",
                ".log",
            }
            _has_output_files = False
            try:
                from ..config import get_workspace_root

                target = getattr(session, "target", "") or "unknown"
                output_dir = get_workspace_root() / target / "output"
                if output_dir.exists():
                    _has_output_files = any(
                        os.path.splitext(f)[1].lower() in _recon_extensions
                        for f in os.listdir(output_dir)
                        if os.path.getsize(output_dir / f) > 0
                    )
            except Exception as _e:
                logger.debug("Could not check workspace artifacts: %s", _e)

            _scan_count = 0
            try:
                _scan_count = int(getattr(session, "scan_count", 0) or 0)
            except Exception as e:
                logger.warning("Operation failed: %s", e)
                _scan_count = 0

            _recon_artifacts_scan_threshold = _get_phase_setting(
                "pipeline_recon_artifacts_scan_threshold", 3
            )
            _has_recon_signals = bool(
                getattr(session, "open_ports", {})
                or getattr(session, "urls", [])
                or (
                    getattr(session, "subdomains", [])
                    and getattr(session, "live_hosts", [])
                )
            )
            if _has_output_files or (
                _scan_count >= _recon_artifacts_scan_threshold and _has_recon_signals
            ):
                met.append("recon_artifacts_saved")

            if len(getattr(session, "subdomains", [])) >= self._recon_min_subdomains:
                met.append("subdomain_depth_met")
            if len(getattr(session, "urls", [])) >= self._recon_min_urls:
                met.append("url_discovery_met")

            logger.debug(
                "[Pipeline] RECON criteria evaluation: met=%s total=%d",
                met,
                len(RECON_PHASE_CONFIG.transition_criteria),
            )

        elif phase == PipelinePhase.ANALYSIS:
            if getattr(session, "urls", []):
                met.append("urls_collected")
            if getattr(session, "technologies", {}):
                met.append("technologies_identified")

            _ips = getattr(session, "injection_points", [])
            _has_meaningful = any(
                p.get("type_hint") and str(p.get("type_hint", "")).strip() for p in _ips
            )
            _analysis_min_inj_points = _get_phase_setting(
                "pipeline_analysis_min_injection_points", 3
            )
            if len(_ips) >= _analysis_min_inj_points or _has_meaningful:
                met.append("injection_points_found")

            logger.debug(
                "[Pipeline] ANALYSIS criteria evaluation: met=%s total=%d",
                met,
                len(ANALYSIS_PHASE_CONFIG.transition_criteria),
            )

        elif phase == PipelinePhase.EXPLOIT:
            vulns = getattr(session, "vulnerabilities", [])

            _confirmed = any(
                v.get("report_generated") or v.get("replay_verified") or v.get("verified")
                for v in vulns
            )

            def _is_significant(vuln: dict[str, Any]) -> bool:
                raw_severity = str(vuln.get("severity", "")).strip().upper()
                if raw_severity in {"3", "4", "5", "MEDIUM", "HIGH", "CRITICAL"}:
                    return True
                finding_text = str(vuln.get("finding", "")).upper()
                return any(
                    f"[{label}]" in finding_text
                    for label in ("MEDIUM", "HIGH", "CRITICAL")
                )

            _has_significant = any(_is_significant(v) for v in vulns)
            if _confirmed or _has_significant:
                met.append("vulnerabilities_tested")

        elif phase == PipelinePhase.REPORT:
            vulns = getattr(session, "vulnerabilities", [])
            if any(v.get("report_generated") for v in vulns):
                met.append("reports_generated")

        return met

    def _next_phase_from_catalog(self, current: PipelinePhase) -> PipelinePhase:
        try:
            idx = _PHASE_ORDER.index(current)
        except ValueError:
            return PipelinePhase.COMPLETE
        if idx + 1 >= len(_PHASE_ORDER):
            return PipelinePhase.COMPLETE
        return _PHASE_ORDER[idx + 1]

    def _has_actionable_exploit_signal(self) -> bool:
        vulns = getattr(self.session, "vulnerabilities", []) or []
        for vuln in vulns:
            finding = str(vuln.get("finding", "")).strip()
            if not finding:
                continue
            if vuln.get("report_generated") or vuln.get("replay_verified") or vuln.get("verified"):
                return True
            if self._vulnerability_severity(vuln) in {"CRITICAL", "HIGH"}:
                return True
            if vuln.get("proo") or vuln.get("evidence") or vuln.get("poc_script_code"):
                return True

        injection_points = getattr(self.session, "injection_points", []) or []
        if any(str(point.get("type_hint", "")).strip() for point in injection_points):
            return True

        if hasattr(self, "state") and hasattr(self.state, "get_pending_hypotheses"):
            try:
                pending = self.state.get_pending_hypotheses(max_items=1)
            except Exception as exc:
                logger.debug("Failed to read pending hypotheses for routing: %s", exc)
                pending = []
            if pending:
                return True

        return False

    def _has_reportable_findings(self) -> bool:
        vulns = getattr(self.session, "vulnerabilities", []) or []
        for vuln in vulns:
            if vuln.get("report_generated"):
                return True
            if vuln.get("replay_verified") or vuln.get("verified"):
                return True
            has_poc = bool(
                vuln.get("proo") or vuln.get("evidence") or vuln.get("poc_script_code")
            )
            if has_poc and self._vulnerability_severity(vuln) in {
                "CRITICAL",
                "HIGH",
                "MEDIUM",
            }:
                return True
        return False

    def _surface_needs_more_recon(self) -> bool:
        subdomains = getattr(self.session, "subdomains", []) or []
        live_hosts = getattr(self.session, "live_hosts", []) or []
        urls = getattr(self.session, "urls", []) or []
        technologies = getattr(self.session, "technologies", {}) or {}

        if subdomains and not live_hosts:
            return True
        if live_hosts and not urls:
            return True
        if urls and not technologies and not self._has_actionable_exploit_signal():
            return True
        return False

    def _resolve_next_phase(
        self,
        current: PipelinePhase,
        *,
        stagnation_trigger: bool = False,
    ) -> PipelinePhase:
        catalog_next = self._next_phase_from_catalog(current)

        if current == PipelinePhase.RECON:
            if self._has_actionable_exploit_signal():
                return PipelinePhase.EXPLOIT
            return catalog_next

        if current == PipelinePhase.ANALYSIS:
            if self._has_actionable_exploit_signal():
                return PipelinePhase.EXPLOIT
            if self._surface_needs_more_recon():
                return PipelinePhase.RECON
            return catalog_next

        if current == PipelinePhase.EXPLOIT:
            if self._has_reportable_findings():
                return PipelinePhase.REPORT
            if stagnation_trigger:
                return PipelinePhase.ANALYSIS
            return catalog_next

        return catalog_next

    def transition(self) -> PipelinePhase | None:
        current = self.get_current_phase()
        if current == PipelinePhase.COMPLETE:
            return None

        iterations_in_phase = self._current_iteration - self._phase_entry_iteration
        current_vulns = len(getattr(self.session, "vulnerabilities", []))

        _stagnation_max = {
            PipelinePhase.RECON: self._recon_max_iterations,
            PipelinePhase.ANALYSIS: self._analysis_max_iterations,
            PipelinePhase.EXPLOIT: self._exploit_max_iterations,
        }.get(current, 999999)
        _stagnation_trigger = iterations_in_phase >= _stagnation_max

        _stag_vuln_iters = _get_phase_setting(
            "pipeline_stagnation_vuln_baseline_iterations", 30
        )
        if current == PipelinePhase.EXPLOIT and not _stagnation_trigger:
            _vuln_new = current_vulns - self._phase_vuln_baseline
            if iterations_in_phase >= _stag_vuln_iters and _vuln_new <= 0:
                _stagnation_trigger = True
                logger.info(
                    "[Pipeline] EXPLOIT stagnation: %d iters, no new vulns "
                    "(baseline=%d, current=%d) — forcing transition",
                    iterations_in_phase,
                    self._phase_vuln_baseline,
                    current_vulns,
                )

        _soft_timeout_bypass = (
            current == PipelinePhase.RECON
            and iterations_in_phase >= self._recon_soft_timeout
        )

        if (
            not _soft_timeout_bypass
            and not _stagnation_trigger
            and not self.should_transition()
        ):
            logger.warning(
                "Attempted transition from %s without meeting confidence/criteria gate",
                current.value,
            )
            return current

        if _stagnation_trigger and not _soft_timeout_bypass:
            logger.info(
                "[Pipeline] Phase %s stagnation escape activated (iters=%d, max=%d) — "
                "allowing transition despite unmet criteria",
                current.value,
                iterations_in_phase,
                _stagnation_max,
            )

        if current.value not in self.session.completed_phases:
            self.session.completed_phases.append(current.value)

        next_phase = self._resolve_next_phase(
            current,
            stagnation_trigger=_stagnation_trigger or _soft_timeout_bypass,
        )
        if next_phase == PipelinePhase.COMPLETE:
            self.set_phase(PipelinePhase.COMPLETE)
            return PipelinePhase.COMPLETE
        self._phase_vuln_baseline = current_vulns
        self.set_phase(next_phase)

        self._phase_entry_iteration = self._current_iteration
        logger.info("Pipeline transition: %s → %s", current.value, next_phase.value)
        return next_phase

    def get_phase_prompt(self) -> str:
        current = self.get_current_phase()
        return self._get_phase_prompt_text(current)

    def get_transition_prompt(self, target_phase: PipelinePhase) -> str:
        lines = [
            f"[PHASE TRANSITION → {target_phase.value}]",
            "",
            f"You are transitioning from {self.get_current_phase().value} to {target_phase.value}.",
            "",
        ]

        objective = DEFAULT_PHASES.get(target_phase, PhaseConfig(
            phase=target_phase,
            max_iterations=0,
            objective="Continue testing.",
        )).objective
        lines.append(f"Primary objective: {objective}")
        lines.append("")
        lines.append(
            f"Ensure all {target_phase.value} objectives are addressed before moving on."
        )

        return "\n".join(lines)

    def _get_phase_prompt_text(self, phase: PipelinePhase) -> str:
        current = self.get_current_phase()
        if current == PipelinePhase.COMPLETE:
            return "[PIPELINE: ALL PHASES COMPLETE] — Target fully tested."

        if self._ctf_mode:
            return (
                "[CTF MODE ACTIVE]\n"
                "Objective: find the exact runtime flag value from the target.\n"
                "Placeholder values like FLAG{...} are INVALID.\n"
                "Use short direct actions; avoid long generated scripts unless strictly necessary.\n"
                "Do not repeat the same strategy more than twice without new evidence.\n"
                "When a concrete flag is found, return it immediately with minimal proof."
            )

        config = DEFAULT_PHASES.get(current)
        base_prompt = self._phase_prompts.get(current, "")

        met = self._evaluate_criteria(current)
        total_criteria = len(config.transition_criteria) if config else 0
        confidence = self.get_phase_transition_confidence()
        progress = (
            f"Progress: {len(met)}/{total_criteria} criteria met"
            f" | transition_confidence={confidence:.0%}"
        )

        completed = (
            ", ".join(self.session.completed_phases)
            if self.session.completed_phases
            else "none"
        )

        skill_line = ""

        skill_hint = self._dynamic_skill_hint(current)
        if skill_hint:
            skill_line = f"\n{skill_hint}"

        exploration_line = ""
        dynamic_hints = _generate_dynamic_hints(
            phase=current,
            session=self.session,
            evidence_log=self.state.evidence_log if hasattr(self, "state") else [],
            iteration=self.state.iteration if hasattr(self, "state") else 0,
            consecutive_failures=getattr(self.state, "consecutive_failures", 0)
            if hasattr(self, "state")
            else 0,
        )

        if dynamic_hints:
            new_hints = [h for h in dynamic_hints if h not in self._previous_hints]
            if len(new_hints) < len(dynamic_hints) // 2:
                self._previous_hints = []
                new_hints = dynamic_hints
            self._previous_hints = new_hints[:5]
            hints_str = "\n".join(f"  • {h}" for h in new_hints[:5])
            exploration_line = f"\nEXPLORATION ANGLES (pick approaches you haven't tried):\n{hints_str}"

        return (
            f"{base_prompt}\n\n"
            f"Completed phases: {completed}\n"
            f"{progress}"
            f"{skill_line}"
            f"{exploration_line}"
        )

    def _dynamic_skill_hint(self, phase: PipelinePhase) -> str | None:
        parts: list[str] = []
        phase_value = phase.value

        skills_path = Path(__file__).parent.parent / "skills"
        if not skills_path.is_dir():
            return None

        tested: set[str] = set()
        try:
            for ev in self.state.evidence_log:
                for tag in ev.get("tags", []) or []:
                    if tag and isinstance(tag, str):
                        tested.add(tag.lower().replace(" ", "_").replace("-", "_"))

            for v in getattr(self.session, "vulnerabilities", []):
                vt = str(v.get("type", v.get("finding", ""))).lower()
                if vt:
                    tested.add(vt.replace(" ", "_").replace("-", "_"))
        except (AttributeError, Exception):
            pass

        phase_dirs = {
            "RECON": {"reconnaissance", "protocols"},
            "ANALYSIS": {"vulnerabilities", "frameworks", "technologies"},
            "EXPLOIT": {"vulnerabilities", "postexploit", "frameworks"},
            "REPORT": {"reporting"},
        }
        relevant_dirs = phase_dirs.get(phase_value, set())

        untested_skills: list[str] = []
        for md_file in skills_path.rglob("*.md"):
            rel = str(md_file.relative_to(skills_path))
            parts_list = rel.split("/")
            if len(parts_list) >= 2 and parts_list[0] in relevant_dirs:
                skill_name = md_file.stem.lower().replace("-", "_")
                if skill_name not in tested:
                    untested_skills.append(rel)

        if untested_skills:
            techs = getattr(self.session, "technologies", {}) or {}
            tech_names = list(techs.keys())

            scored: list[tuple[int, str]] = []
            for skill_path in untested_skills:
                score = 0
                skill_lower = skill_path.lower()
                for tech in tech_names:
                    if tech.lower() in skill_lower:
                        score += 3
                if (
                    phase_value in ("ANALYSIS", "EXPLOIT")
                    and "vulnerabilities" in skill_lower
                ):
                    score += 2
                scored.append((score, skill_path))

            scored.sort(reverse=True)
            top_skills = [p for _, p in scored[:3]]

            if top_skills:
                untested_str = " | ".join(top_skills)
                if phase_value == "RECON":
                    parts.append(f"Phase skills (untested): {untested_str}")
                elif phase_value in ("ANALYSIS", "EXPLOIT"):
                    parts.append(
                        f"Recommended skills for this phase (untested, relevant to findings): "
                        f"{untested_str}"
                    )
                else:
                    parts.append(f"Available skills for this phase: {untested_str}")
        else:
            parts.append(
                "All phase skills have been tested — focus on chaining confirmed findings "
                "into multi-step attack scenarios."
            )

        return " | ".join(parts) if parts else None

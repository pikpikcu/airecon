from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any

from ..data_loader import load_vuln_hypothesis_legacy
from ..system import _SKILL_KEYWORDS, _discover_all_skills, _phase_preferred_skill_dirs
from .vuln_classifier import get_classifier

logger = logging.getLogger("airecon.agent.tool_scorer")

_TOOLS_META_PATH = Path(__file__).parent.parent / "data" / "tools_meta.json"
_TOOLS_JSON_PATH = Path(__file__).parent.parent / "data" / "tools.json"
try:
    _TOOLS_META = json.loads(_TOOLS_META_PATH.read_text(encoding="utf-8"))
except Exception as _e:
    logger.warning("tools_meta.json unavailable: %s", _e)
    _TOOLS_META = {}


def _load_callable_tool_registry() -> tuple[frozenset[str], dict[str, str]]:
    names: set[str] = set()
    descriptions: dict[str, str] = {}
    try:
        if _TOOLS_JSON_PATH.exists():
            tools_list = json.loads(_TOOLS_JSON_PATH.read_text(encoding="utf-8"))
            for tool_def in tools_list:
                function_def = tool_def.get("function", {})
                name = str(function_def.get("name", "") or "").strip()
                if not name:
                    continue
                names.add(name)
                description = str(function_def.get("description", "") or "").strip()
                if description:
                    descriptions[name.lower()] = description
    except Exception as exc:
        logger.warning("Failed to load callable tool registry: %s", exc)
    return frozenset(names), descriptions


_CALLABLE_TOOL_NAMES, _CALLABLE_TOOL_DESCRIPTIONS = _load_callable_tool_registry()


def _derive_core_tools() -> frozenset[str]:
    configured = _TOOLS_META.get("callable_core_tools", [])
    if not isinstance(configured, list):
        return frozenset()

    callable_lookup = {name.lower() for name in _CALLABLE_TOOL_NAMES}
    return frozenset(
        str(name).strip()
        for name in configured
        if str(name).strip() and str(name).strip().lower() in callable_lookup
    )


_CORE_TOOLS = _derive_core_tools()

_CATEGORY_PHASE_MAP: dict[str, list[str]] = _TOOLS_META.get("phase_category_map", {})

_PHASE_EXTRAS: dict[str, set[str]] = {
    phase: set(tools) for phase, tools in _TOOLS_META.get("phase_extras", {}).items()
}

_REPORT_TOOLS = frozenset(_TOOLS_META.get("report_tools", []))
_VULN_HYPOTHESIS = load_vuln_hypothesis_legacy()
_SKILLS_DIR = Path(__file__).resolve().parent.parent / "skills"


def _lookup_category(categories: dict, name: str) -> set[str]:
    tools: set[str] = set()
    for group_name, subcats in categories.items():
        if not isinstance(subcats, dict):
            continue
        for subcat_name, tool_list in subcats.items():
            if subcat_name == name and isinstance(tool_list, list):
                tools.update(t for t in tool_list if isinstance(t, str))
    return tools


def _collect_shell_binary_names() -> set[str]:
    shell_tools: set[str] = set()
    categories = _TOOLS_META.get("categories", {})
    if isinstance(categories, dict):
        for group in categories.values():
            if isinstance(group, dict):
                for tool_list in group.values():
                    if isinstance(tool_list, list):
                        shell_tools.update(t for t in tool_list if isinstance(t, str))
    return shell_tools


def _collect_all_known_tools() -> set[str]:
    return set(_CALLABLE_TOOL_NAMES) | _collect_shell_binary_names()


def _normalize_signal_term(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(text or "").lower()).strip("_")


def _contains_term(haystack: str, needle: str) -> bool:
    norm_haystack = _normalize_signal_term(haystack)
    norm_needle = _normalize_signal_term(needle)
    if not norm_haystack or not norm_needle:
        return False
    return f"_{norm_needle}_" in f"_{norm_haystack}_"


def _resolve_labels_for_hypothesis(
    hypo_name: str,
    indicators: list[str],
) -> set[str]:
    classifier = get_classifier()
    labels: set[str] = set()
    base_name = str(hypo_name or "").replace("hypothesis_", "").replace("_", " ")

    for candidate in [base_name, *indicators]:
        if not str(candidate).strip():
            continue
        labels.update(classifier.resolve_labels(str(candidate)))
        result = classifier.classify(str(candidate))
        if result.category != "UNKNOWN":
            labels.add(result.category)
        if result.subcategory:
            labels.add(result.subcategory)

    return {label for label in labels if label and label != "UNKNOWN"}


def _build_tool_vuln_label_map() -> dict[str, set[str]]:
    tool_vuln_map: dict[str, set[str]] = {}
    descriptions = _TOOLS_META.get("tool_descriptions", {})
    categories = _TOOLS_META.get("categories", {})

    def _searchable_text(tool_name: str) -> str:
        parts = [tool_name]
        description = descriptions.get(tool_name, "")
        if isinstance(description, str) and description:
            parts.append(description)
        for group in categories.values():
            if not isinstance(group, dict):
                continue
            for subcat_name, tool_list in group.items():
                if isinstance(tool_list, list) and tool_name in tool_list:
                    parts.append(str(subcat_name))
        return " ".join(parts)

    for tool_name in _collect_all_known_tools():
        searchable = _searchable_text(tool_name)
        if not searchable:
            continue
        labels: set[str] = set()
        for entry in _VULN_HYPOTHESIS:
            indicators = [
                str(ind).strip()
                for ind in (entry.get("patterns") or entry.get("indicators", []))
                if str(ind).strip()
            ]
            if not indicators:
                continue
            if any(_contains_term(searchable, ind) for ind in indicators):
                labels.update(
                    _resolve_labels_for_hypothesis(
                        str(entry.get("type", entry.get("name", ""))),
                        indicators,
                    )
                )
        if labels:
            tool_vuln_map[str(tool_name).lower()] = labels

    return tool_vuln_map


def _load_all_skills() -> dict[str, str]:
    try:
        return _discover_all_skills(_SKILLS_DIR)
    except Exception as exc:
        logger.debug("Could not discover skills for tool scorer: %s", exc)
        return {}


def _build_phase_appropriate() -> dict[str, set[str]]:
    phase_tools: dict[str, set[str]] = {
        "RECON": set(_CORE_TOOLS),
        "ANALYSIS": set(_CORE_TOOLS),
        "EXPLOIT": set(_CORE_TOOLS),
        "REPORT": set(_REPORT_TOOLS),
    }

    for phase, extras in _PHASE_EXTRAS.items():
        phase_tools[phase].update(extras)

    categories = _TOOLS_META.get("categories", {})
    if isinstance(categories, dict):
        for phase, cat_names in _CATEGORY_PHASE_MAP.items():
            for cat_name in cat_names:
                phase_tools[phase].update(_lookup_category(categories, cat_name))

    return phase_tools


def _build_phase_blocked() -> dict[str, set[str]]:

    all_phase_tools = _build_phase_appropriate()
    all_known = _collect_all_known_tools()

    report_block = (all_known | _CORE_TOOLS) - _REPORT_TOOLS

    blocked: dict[str, set[str]] = {
        "RECON": set(),
        "ANALYSIS": set(),
        "EXPLOIT": set(),
        "REPORT": report_block,
    }

    phases = ["RECON", "ANALYSIS", "EXPLOIT"]
    for phase in phases:
        for other_phase in phases:
            if other_phase == phase:
                continue
            other_only = (
                all_phase_tools[other_phase] - all_phase_tools[phase] - _CORE_TOOLS
            )
            blocked[phase].update(other_only)

    return blocked


_PHASE_APPROPRIATE_TOOLS: dict[str, set[str]] = _build_phase_appropriate()
_PHASE_BLOCKED_TOOLS: dict[str, set[str]] = _build_phase_blocked()
_KNOWN_TOOL_BINARIES: set[str] = _collect_shell_binary_names()
_TOOL_VULN_LABEL_MAP: dict[str, set[str]] = _build_tool_vuln_label_map()
_ALL_SKILLS: dict[str, str] = _load_all_skills()


def _collect_shell_binary_descriptions() -> dict[str, str]:
    descriptions = _TOOLS_META.get("tool_descriptions", {})
    if not isinstance(descriptions, dict):
        descriptions = {}
    return descriptions


def _match_shells_for_phase(phase: str) -> set[str]:
    category_names = _CATEGORY_PHASE_MAP.get(phase, [])
    if not category_names:
        return set()

    result: set[str] = set()
    categories = _TOOLS_META.get("categories", {})
    for cat_name in category_names:
        for group in categories.values():
            if isinstance(group, dict) and cat_name in group:
                tlist = group[cat_name]
                if isinstance(tlist, list):
                    result.update(t for t in tlist if isinstance(t, str))
    return result


def _resolve_skill_labels(skill_stem: str, description: str = "") -> set[str]:
    classifier = get_classifier()
    labels: set[str] = set()
    for candidate in (skill_stem, skill_stem.replace("_", " "), description):
        if not str(candidate).strip():
            continue
        labels.update(classifier.resolve_labels(str(candidate)))
        result = classifier.classify(str(candidate))
        if result.category != "UNKNOWN":
            labels.add(result.category)
        if result.subcategory:
            labels.add(result.subcategory)
    return {label for label in labels if label and label != "UNKNOWN"}


def _lookup_skill_description(skills_catalog: dict[str, Any], rel_path: str) -> str:
    category = rel_path.split("/", 1)[0] if "/" in rel_path else rel_path
    stem = Path(rel_path).stem.lower()
    category_catalog = skills_catalog.get(category, {})
    if isinstance(category_catalog, dict):
        return str(category_catalog.get(stem, ""))
    return ""


def _resolve_explicit_skill_paths(terms: list[str]) -> list[str]:
    paths: list[str] = []
    seen: set[str] = set()
    for term in terms:
        key = str(term or "").strip().lower()
        if not key:
            continue
        rel_path = str(_SKILL_KEYWORDS.get(key, "") or "").strip()
        if not rel_path or rel_path in seen or rel_path not in _ALL_SKILLS:
            continue
        seen.add(rel_path)
        paths.append(rel_path)
    return paths


def _build_skill_catalog_entries(
    phase: str,
    context_tools: list[str] | None = None,
    chain_step_hint: str = "",
    wrong_tool_picked: str = "",
    max_entries: int = 10,
) -> list[str]:
    skills_catalog = _TOOLS_META.get("skills_catalog", {})
    if not isinstance(skills_catalog, dict) or not _ALL_SKILLS:
        return []

    context_terms = [
        str(term).strip()
        for term in [*(context_tools or []), chain_step_hint, wrong_tool_picked]
        if str(term).strip()
    ]
    preferred_dirs = _phase_preferred_skill_dirs(phase)
    normalized_terms = {_normalize_signal_term(term) for term in context_terms if term}
    explicit_paths = _resolve_explicit_skill_paths(context_terms)

    classifier = get_classifier()
    context_labels: set[str] = set()
    for term in context_terms:
        context_labels.update(_TOOL_VULN_LABEL_MAP.get(term.lower(), set()))
        context_labels.update(classifier.resolve_labels(term))
        result = classifier.classify(term)
        if result.category != "UNKNOWN":
            context_labels.add(result.category)
        if result.subcategory:
            context_labels.add(result.subcategory)

    scored: list[tuple[int, str, str]] = []
    explicit_set = set(explicit_paths)
    for index, rel_path in enumerate(explicit_paths):
        description = _lookup_skill_description(skills_catalog, rel_path)
        scored.append((1000 - index, rel_path, description))

    if not preferred_dirs:
        entries: list[str] = []
        for _, rel_path, description in scored[:max_entries]:
            if description:
                desc = description[:177] + "..." if len(description) > 180 else description
                entries.append(f"    - skills/{rel_path}: {desc}")
            else:
                entries.append(f"    - skills/{rel_path}")
        return entries

    for rel_path, stem in _ALL_SKILLS.items():
        if rel_path in explicit_set:
            continue
        category = rel_path.split("/", 1)[0] if "/" in rel_path else rel_path
        if category not in preferred_dirs:
            continue

        description = _lookup_skill_description(skills_catalog, rel_path)

        rel_norm = _normalize_signal_term(rel_path)
        stem_norm = _normalize_signal_term(stem)
        score = 0 if normalized_terms or context_labels or explicit_paths else 1

        for term_norm in normalized_terms:
            if not term_norm:
                continue
            if stem_norm == term_norm:
                score += 10
            elif term_norm in rel_norm:
                score += 6

        overlap = _resolve_skill_labels(stem, description) & context_labels
        if overlap:
            score += 4 + len(overlap)

        if score > 0:
            scored.append((score, rel_path, description))

    scored.sort(key=lambda item: (-item[0], item[1]))

    entries: list[str] = []
    for _, rel_path, description in scored[:max_entries]:
        if description:
            desc = description[:177] + "..." if len(description) > 180 else description
            entries.append(f"    - skills/{rel_path}: {desc}")
        else:
            entries.append(f"    - skills/{rel_path}")
    return entries


def extract_binary_from_command(command: str) -> str:
    if not command:
        return ""
    cmd = re.sub(r"^cd\s+\S+\s*&&\s*", "", command).strip()
    if not cmd:
        return ""
    binary = cmd.split()[0].lower() if cmd.split() else ""
    binary = binary.rsplit("/", 1)[-1]
    _shell_builtins = {
        "cd",
        "echo",
        "export",
        "source",
        ".",
        "for",
        "while",
        "if",
        "then",
        "fi",
        "done",
        "do",
        "case",
        "esac",
        "true",
        "false",
    }
    if binary in _shell_builtins:
        for token in cmd.split():
            t = token.rsplit("/", 1)[-1].lower()
            if t in _KNOWN_TOOL_BINARIES:
                return t
        return ""
    return binary


def _get_memory_tool_stats() -> tuple[dict[str, int], dict[str, int], dict[str, int]]:
    success_counts: dict[str, int] = {}
    failure_counts: dict[str, int] = {}
    use_counts: dict[str, int] = {}

    try:
        from ..memory import get_memory_manager

        memory = get_memory_manager()
        stats = memory.get_tool_statistics()

        if isinstance(stats, list):
            for s in stats:
                tool = s.get("tool_name", "")
                if tool:
                    success_counts[tool] = s.get("success_count", 0)
                    failure_counts[tool] = s.get("failure_count", 0)
                    use_counts[tool] = success_counts[tool] + failure_counts[tool]
        elif isinstance(stats, dict):
            tool = stats.get("tool_name", "")
            if tool:
                success_counts[tool] = stats.get("success_count", 0)
                failure_counts[tool] = stats.get("failure_count", 0)
                use_counts[tool] = success_counts[tool] + failure_counts[tool]
    except Exception as _e:
        logger.debug("Could not load memory tool stats: %s", _e)

    return success_counts, failure_counts, use_counts


def score_tool(
    tool_name: str,
    *,
    current_phase: str = "RECON",
    tool_use_counts: dict[str, int] | None = None,
    tool_success_counts: dict[str, int] | None = None,
    tool_failure_counts: dict[str, int] | None = None,
    budget_remaining: dict[str, int] | None = None,
    chain_step_hint: str = "",
    session_evidence_count: int = 0,
    consecutive_failures: int = 0,
    recent_tool_names: list[str] | None = None,
    tested_vuln_classes: set[str] | None = None,
    adaptive_tool_scores: dict[str, float] | None = None,
    strategy_tool_sequence: list[str] | None = None,
) -> dict[str, Any]:
    reasons: list[str] = []
    score = 0.5

    phase_upper = current_phase.upper()
    appropriate_tools = _PHASE_APPROPRIATE_TOOLS.get(phase_upper, set())
    blocked_tools = _PHASE_BLOCKED_TOOLS.get(phase_upper, set())

    is_blocked = tool_name.lower() in {t.lower() for t in blocked_tools}
    is_appropriate = tool_name.lower() in {t.lower() for t in appropriate_tools}

    discovery_exception = False
    if is_blocked and session_evidence_count >= 3:
        discovery_exception = True
        reasons.append(
            f"[DISCOVERY OVERRIDE] '{tool_name}' normally blocked in {phase_upper}, but enabled due to active investigation"
        )

    if is_blocked and not discovery_exception:
        score = 0.0
        reasons.append(
            f"[PHASE BLOCKED] '{tool_name}' is not allowed in {phase_upper} phase"
        )
    elif is_blocked and discovery_exception:
        score = 0.6
        reasons.append(
            f"[CROSS-PHASE ALLOWED] Research mode active - using {tool_name} despite phase"
        )
    elif is_appropriate:
        score += 0.15
        reasons.append(f"Phase-appropriate for {phase_upper}")

    if tool_success_counts and tool_failure_counts:
        successes = tool_success_counts.get(tool_name, 0)
        failures = tool_failure_counts.get(tool_name, 0)
        total = successes + failures
        if total >= 2:
            success_rate = successes / total
            if success_rate >= 0.8:
                score += 0.15
                reasons.append(f"High historical success rate ({success_rate:.0%})")
            elif success_rate >= 0.6:
                score += 0.05
                reasons.append(f"Moderate historical success rate ({success_rate:.0%})")
            elif success_rate < 0.4:
                score -= 0.15
                reasons.append(
                    f"Low historical success rate ({success_rate:.0%}) — consider alternatives"
                )

    if tool_use_counts:
        use_count = tool_use_counts.get(tool_name, 0)
        if use_count > 10:
            score -= 0.1
            reasons.append(f"Overused in this session ({use_count} times) — diversify")
        elif use_count == 0 and is_appropriate:
            score += 0.05
            reasons.append("Not yet used this session — worth trying")

    if recent_tool_names:
        recent_count = recent_tool_names.count(tool_name)
        window_size = len(recent_tool_names)
        if recent_count > 0:
            frequency = recent_count / max(window_size, 1)
            penalty = min(0.4, frequency * 0.5)
            score -= penalty
            reasons.append(
                f"DIVERSITY PENALTY: used {recent_count}/{window_size} recent calls ({frequency:.0%}) — score -{penalty:.2f}"
            )
            if frequency >= 0.6:
                score = max(0.0, score - 0.3)
                reasons.append(
                    "HEAVY PENALTY: tool dominates recent window — strongly prefer alternatives"
                )
        if (
            recent_count == 0
            and is_appropriate
            and tool_name
            not in (
                "execute",
                "browser_action",
                "create_file",
                "read_file",
                "list_files",
            )
        ):
            score += 0.1
            reasons.append("DIVERSITY BONUS: not used recently — fresh approach")

    if tested_vuln_classes:
        tool_lower = tool_name.lower()
        tool_classes = _TOOL_VULN_LABEL_MAP.get(tool_lower, set())
        untested_by_tool = tool_classes - tested_vuln_classes
        if untested_by_tool:
            score += 0.1 * len(untested_by_tool)
            reasons.append(
                f"COVERAGE BONUS: can test untested classes: {', '.join(untested_by_tool)}"
            )

    if budget_remaining:
        remaining = budget_remaining.get(tool_name, 999)
        if remaining <= 0:
            score -= 0.3
            reasons.append("Tool budget exhausted (0 remaining) — use sparingly")
        elif remaining <= 3:
            score -= 0.1
            reasons.append(f"Tool budget low ({remaining} remaining)")

    if chain_step_hint:
        chain_hint_lower = chain_step_hint.lower()
        tool_lower = tool_name.lower()
        if tool_lower in chain_hint_lower or chain_hint_lower in tool_lower:
            score += 0.25
            reasons.append(
                f"ALIGNMENT: Matches current exploit chain step hint '{chain_step_hint}'"
            )

    if adaptive_tool_scores and tool_name in adaptive_tool_scores:
        learned_score = float(adaptive_tool_scores.get(tool_name, 0.0) or 0.0)
        if learned_score >= 0.75:
            score += 0.15
            reasons.append(
                f"ADAPTIVE BONUS: prior runs strongly favor this tool ({learned_score:.2f})"
            )
        elif learned_score >= 0.6:
            score += 0.08
            reasons.append(
                f"ADAPTIVE BONUS: prior runs favor this tool ({learned_score:.2f})"
            )
        elif learned_score <= 0.3:
            score -= 0.08
            reasons.append(
                f"ADAPTIVE PENALTY: prior runs show weak returns ({learned_score:.2f})"
            )

    if strategy_tool_sequence and tool_name in strategy_tool_sequence:
        idx = strategy_tool_sequence.index(tool_name)
        boost = max(0.04, 0.12 - (idx * 0.02))
        score += boost
        reasons.append(
            f"STRATEGY ALIGNMENT: matches learned sequence position {idx + 1}/{len(strategy_tool_sequence)}"
        )

    if consecutive_failures >= 3:
        if tool_use_counts and tool_name in tool_use_counts:
            if tool_use_counts.get(tool_name, 0) > 0:
                score -= 0.1
                reasons.append("Consecutive failures — try a different approach")

    score = max(0.0, min(1.0, score))

    return {
        "score": round(score, 3),
        "phase_appropriate": is_appropriate,
        "phase_blocked": is_blocked,
        "reasons": reasons,
    }


def rank_tools_for_phase(
    available_tools: list[dict[str, Any]],
    *,
    current_phase: str = "RECON",
    tool_use_counts: dict[str, int] | None = None,
    tool_success_counts: dict[str, int] | None = None,
    tool_failure_counts: dict[str, int] | None = None,
    budget_remaining: dict[str, int] | None = None,
    chain_step_hint: str = "",
    session_evidence_count: int = 0,
    consecutive_failures: int = 0,
    recent_tool_names: list[str] | None = None,
    tested_vuln_classes: set[str] | None = None,
    adaptive_tool_scores: dict[str, float] | None = None,
    strategy_tool_sequence: list[str] | None = None,
    top_n: int | None = None,
    use_memory: bool = True,
) -> list[dict[str, Any]]:
    if use_memory and tool_success_counts is None and tool_failure_counts is None:
        mem_success, mem_failure, mem_use = _get_memory_tool_stats()
        if tool_success_counts is None:
            tool_success_counts = mem_success
        if tool_failure_counts is None:
            tool_failure_counts = mem_failure
        if tool_use_counts is None:
            tool_use_counts = mem_use

    scored_tools: list[tuple[float, dict[str, Any]]] = []

    for tool_def in available_tools:
        tool_name = tool_def.get("function", {}).get("name", "") or tool_def.get(
            "name", ""
        )
        if not tool_name:
            continue

        result = score_tool(
            tool_name,
            current_phase=current_phase,
            tool_use_counts=tool_use_counts,
            tool_success_counts=tool_success_counts,
            tool_failure_counts=tool_failure_counts,
            budget_remaining=budget_remaining,
            chain_step_hint=chain_step_hint,
            session_evidence_count=session_evidence_count,
            consecutive_failures=consecutive_failures,
            recent_tool_names=recent_tool_names,
            tested_vuln_classes=tested_vuln_classes,
            adaptive_tool_scores=adaptive_tool_scores,
            strategy_tool_sequence=strategy_tool_sequence,
        )

        scored_tools.append((result["score"], tool_def))

    scored_tools.sort(key=lambda x: x[0], reverse=True)

    if top_n and len(scored_tools) > top_n:
        scored_tools = scored_tools[:top_n]

    return [tool_def for _, tool_def in scored_tools]


def build_tool_recommendation_context(
    current_phase: str = "RECON",
    tool_scores: dict[str, dict[str, Any]] | None = None,
    chain_step_hint: str = "",
    consecutive_failures: int = 0,
    blocked_tools: list[str] | None = None,
    wrong_tool_picked: str = "",
    tool_registry: list[dict[str, Any]] | None = None,
) -> str:
    parts: list[str] = []

    phase_upper = current_phase.upper()
    appropriate = _PHASE_APPROPRIATE_TOOLS.get(phase_upper, set())
    top_tools: list[str] = []
    if appropriate:
        callable_registry_names = {
            str(tdef.get("function", {}).get("name", "") or "").strip()
            for tdef in (tool_registry or [])
            if isinstance(tdef, dict)
        }
        callable_registry_lookup = {
            tool_name.lower() for tool_name in callable_registry_names if tool_name
        }

        def _tool_priority(name: str) -> tuple[float, str]:
            if not tool_scores:
                return (0.0, name)
            score_entry = tool_scores.get(name) or tool_scores.get(name.lower()) or {}
            raw_score = (
                score_entry.get("score", 0.0) if isinstance(score_entry, dict) else 0.0
            )
            try:
                score = float(raw_score or 0.0)
            except (TypeError, ValueError):
                score = 0.0
            return (-score, name)

        callable_lookup = {name.lower() for name in _CALLABLE_TOOL_NAMES}
        callable_candidates = [
            name
            for name in appropriate
            if name.lower() in callable_lookup
            and (
                not callable_registry_names
                or name in callable_registry_names
                or name.lower() in callable_registry_lookup
            )
        ]
        top_tools = sorted(callable_candidates, key=_tool_priority)[:15]

        desc_map: dict[str, str] = dict(_CALLABLE_TOOL_DESCRIPTIONS)
        if tool_registry:
            for tdef in tool_registry:
                fn = tdef.get("function", {}) if isinstance(tdef, dict) else {}
                tname = fn.get("name", "")
                tdesc = fn.get("description", "")
                if tname and tdesc:
                    desc_map[tname.lower()] = tdesc

        callable_lines: list[str] = []
        for tname in top_tools:
            tl = tname.lower()
            desc = desc_map.get(tl, "")
            if desc:
                if len(desc) > 200:
                    desc = desc[:197] + "..."
                callable_lines.append(f"    - {tname}: {desc}")
            else:
                callable_lines.append(f"    - {tname}")

        guidance_lines: list[str] = []
        if callable_lines:
            guidance_lines.append("  Recommended callable tools for this phase:")
            guidance_lines.extend(callable_lines)

        shell_binaries = _collect_shell_binary_descriptions()
        relevant_shells = _match_shells_for_phase(phase_upper)
        if relevant_shells:
            shell_lines: list[str] = []
            for shell_name in sorted(relevant_shells)[:25]:
                desc = shell_binaries.get(shell_name, "")
                if desc:
                    shell_lines.append(f"    - {shell_name}: {desc}")
                    desc_len = len(shell_name) + len(desc)
                    if desc_len > 150:
                        break
                else:
                    shell_lines.append(f"    - {shell_name}")
                if len(shell_lines) >= 25:
                    break

            if guidance_lines:
                guidance_lines.append("")
            guidance_lines.append("  Useful execute(command='...') binaries for this phase:")
            guidance_lines.extend(shell_lines)

        parts.append(
            '<tool_guidance phase="' + phase_upper + '">\n'
            + "\n".join(guidance_lines)
            + "\n  Prioritize tools that advance your current objective.\n"
            "</tool_guidance>"
        )

    blocked = {
        str(name).strip().lower()
        for name in _PHASE_BLOCKED_TOOLS.get(phase_upper, set())
        if str(name).strip()
    }
    if blocked_tools:
        blocked.update(
            str(name).strip().lower() for name in blocked_tools if str(name).strip()
        )
    if blocked:
        top_blocked = sorted(blocked)[:10]
        parts.append(
            f"<phase_advisory_tools>\n"
            f"  These tools are outside the usual {phase_upper} set: {', '.join(top_blocked)}\n"
            f"  Prefer phase-aligned tools first, but cross-phase pivots are allowed when evidence justifies them.\n"
            f"</phase_advisory_tools>"
        )

    if chain_step_hint:
        if wrong_tool_picked:
            parts.append(
                f"<exploit_chain_correction>\n"
                f"  ⚠️ WRONG TOOL SELECTED: You used '{wrong_tool_picked}' but your exploit chain requires '{chain_step_hint}'.\n"
                f"  STOP what you're doing. Use '{chain_step_hint}' NOW to advance the chain.\n"
                f"  The current chain step is waiting for this specific tool.\n"
                f"</exploit_chain_correction>"
            )
        else:
            parts.append(
                f"<exploit_chain_guidance>\n"
                f"  Your exploit chain's current step suggests using: '{chain_step_hint}'\n"
                f"  PRIORITIZE this tool to advance the chain.\n"
                f"</exploit_chain_guidance>"
            )

    if consecutive_failures >= 3:
        parts.append(
            f"<failure_recovery>\n"
            f"  ⚠️ {consecutive_failures} consecutive tool failures detected!\n"
            f"  STOP using the same approach. Switch to a completely different tool or strategy.\n"
            f"  Check tools_meta.json for alternative suggestions.\n"
            f"</failure_recovery>"
        )

    skill_entries = _build_skill_catalog_entries(
        phase_upper,
        context_tools=top_tools[:8],
        chain_step_hint=chain_step_hint,
        wrong_tool_picked=wrong_tool_picked,
    )
    if skill_entries:
        parts.append(
            "<skills_catalog>\n"
            '  Available knowledge modules. Load with read_file(path="skills/<cat>/<name>.md"):\n'
            + "\n".join(skill_entries)
            + "\n  Use these modules to guide your approach and avoid common pitfalls.\n"
            "</skills_catalog>"
        )

    if not parts:
        return ""

    return "\n\n".join(
        ["<system_tool_intelligence>"] + parts + ["</system_tool_intelligence>"]
    )

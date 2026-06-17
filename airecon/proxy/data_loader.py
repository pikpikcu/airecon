from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any

logger = logging.getLogger("airecon.proxy.data_loader")

_DATA_DIR = Path(__file__).parent / "data"


def _load_json(filename: str) -> dict[str, Any]:
    """Load a JSON file from the data directory. Returns empty dict on failure."""
    path = _DATA_DIR / filename
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        logger.warning("Failed to load %s: %s", filename, exc)
        return {}


# ── Unified vulnerability patterns (merged from 6 separate files) ─────────────

_UNIFIED_PATTERNS: dict[str, Any] | None = None


def _load_unified_patterns() -> dict[str, Any]:
    """Load unified pattern catalog. Falls back to legacy files if unified not found."""
    global _UNIFIED_PATTERNS
    if _UNIFIED_PATTERNS is not None:
        return _UNIFIED_PATTERNS

    unified_path = _DATA_DIR / "unified_patterns.json"
    if unified_path.exists():
        try:
            loaded = json.loads(unified_path.read_text(encoding="utf-8"))
            _UNIFIED_PATTERNS = loaded if isinstance(loaded, dict) else {}
            return _UNIFIED_PATTERNS
        except Exception as exc:
            logger.warning("Failed to load unified_patterns.json: %s", exc)

    # Fallback: merge legacy files
    result: dict[str, Any] = {"_fallback": True}
    for fname in ["patterns.json", "business_logic_patterns.json", "zeroday_patterns.json"]:
        result.update(_load_json(fname))
    _UNIFIED_PATTERNS = result
    return _UNIFIED_PATTERNS


def load_vuln_patterns() -> dict[str, Any]:
    """Load unified vulnerability patterns (merged from patterns.json, business_logic_patterns.json, zeroday_patterns.json)."""
    return _load_unified_patterns()


def load_vuln_hypothesis() -> list[dict[str, Any]]:
    """Load vulnerability hypothesis list from unified patterns."""
    data = _load_unified_patterns()
    return [v for k, v in data.items() if not k.startswith("_")]


def load_pattern_by_category(category: str) -> dict[str, Any] | None:
    """Get a single pattern entry by name from unified catalog."""
    data = _load_unified_patterns()
    entry = data.get(category)
    if entry and not isinstance(entry, dict):
        return None
    return entry if entry and not entry.get("_comment") else None


# ── Legacy compatibility — still loads from unified catalog ──────────────────

def load_expert_testing_patterns() -> dict[str, Any]:
    """Load expert testing patterns (from unified catalog, filtered by severity)."""
    data = _load_unified_patterns()
    return {k: v for k, v in data.items() if not k.startswith("_") and v.get("severity") in ("HIGH", "CRITICAL")}


def load_zeroday_patterns() -> dict[str, Any]:
    """Load zeroday/advanced patterns (from unified catalog, CRITICAL severity)."""
    data = _load_unified_patterns()
    return {k: v for k, v in data.items() if not k.startswith("_") and v.get("severity") == "CRITICAL"}


def load_business_logic_patterns() -> dict[str, Any]:
    """Load business logic patterns (from unified catalog, business-related entries)."""
    data = _load_unified_patterns()
    return {
        k: v for k, v in data.items()
        if not k.startswith("_") and any(
            term in k.lower()
            for term in ["business", "workflow", "checkout", "payment", "coupon", "subscription", "race", "loyalty"]
        )
    }


def load_objective_patterns() -> dict[str, Any]:
    """Load objective patterns (objectives section from unified catalog)."""
    data = _load_unified_patterns()
    objectives = data.get("objectives", {})
    if isinstance(objectives, dict):
        return {"objectives": objectives}
    return {"objectives": {}}


def load_vuln_hypothesis_legacy() -> list[dict[str, Any]]:
    """Load vuln hypothesis (from unified catalog)."""
    data = _load_unified_patterns()
    return [
        {"type": name, "patterns": entry.get("indicators", [])}
        for name, entry in data.items()
        if not name.startswith("_") and "hypothesis" in name.lower()
    ]


# ── Verification patterns ────────────────────────────────────────────────────


def load_verification_patterns() -> dict[str, Any]:
    """Load verification patterns (clean response, dynamic content, honeypot, etc.)."""
    return _load_json("verification_patterns.json")


# ── Model refusal markers ────────────────────────────────────────────────────


def load_refusal_markers() -> list[str]:
    """Load lowercase substrings that flag an LLM-side refusal (declined task).

    Used only to label a model refusal clearly to the user — refusals are an
    LLM/provider behaviour, not an AIRecon bug.
    """
    data = _load_json("refusal_markers.json")
    markers = data.get("markers", []) if isinstance(data, dict) else []
    return [str(m).lower() for m in markers if str(m).strip()]


def load_awaiting_input_markers() -> list[str]:
    """Load lowercase substrings that flag the model asking for a new objective.

    Used only to end a text-only watchdog abort gracefully (model considers the
    step finished and is awaiting operator input) instead of erroring out.
    """
    data = _load_json("awaiting_input_markers.json")
    markers = data.get("markers", []) if isinstance(data, dict) else []
    return [str(m).lower() for m in markers if str(m).strip()]


# ── File extensions ──────────────────────────────────────────────────────────


def load_file_extensions() -> dict[str, Any]:
    """Load file extension categories (static, high_value, document, backend)."""
    return _load_json("file_extensions.json")


# ── Endpoint patterns ────────────────────────────────────────────────────────


def load_endpoint_patterns() -> dict[str, Any]:
    """Load endpoint and subdomain scoring patterns."""
    return _load_json("endpoint_patterns.json")


# ── Tech correlations ────────────────────────────────────────────────────────


def load_tech_correlations() -> dict[str, Any]:
    """Load technology correlation data (vulns, paths, tools, severity)."""
    return _load_json("tech_correlations.json")


# ── Tools metadata ───────────────────────────────────────────────────────────


def load_tools_meta() -> dict[str, Any]:
    """Load tools metadata (categories, tuning, hints, etc.)."""
    return _load_json("tools_meta.json")


# ── Tools definitions ────────────────────────────────────────────────────────


def load_tools() -> list[dict[str, Any]]:
    """Load tool definitions from tools.json."""
    path = _DATA_DIR / "tools.json"
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        logger.warning("Failed to load tools.json: %s", exc)
        return []


# ── Fuzzer data ──────────────────────────────────────────────────────────────


def load_fuzzer_data() -> dict[str, Any]:
    """Load fuzzer payloads, vulnerable patterns, and chain rules."""
    return _load_json("fuzzer_data.json")


# ── WAF signatures ───────────────────────────────────────────────────────────


def load_waf_signatures() -> dict[str, Any]:
    """Load WAF detection signatures."""
    return _load_json("waf_signatures.json")


# ── WAF bypass strategies ────────────────────────────────────────────────────


def load_waf_bypass_strategies(waf_name: str) -> list[str]:
    """Load WAF bypass strategies for a specific WAF."""
    data = _load_json("waff_bypass.json")
    strategies = data.get("BYPASS_STRATEGIES", {})
    waf_key = waf_name.lower().replace(" ", "_")
    waf_data = strategies.get(waf_key, {})
    if isinstance(waf_data, list):
        return [str(s) for s in waf_data]
    if isinstance(waf_data, dict):
        return [f"{waf_data.get('name', '')}: {waf_data.get('description', '')}"]
    return []


# ── Recon tools ──────────────────────────────────────────────────────────────


def load_recon_tools() -> set[str]:
    """Load all reconnaissance tool names from tools_meta.json."""
    meta = _load_json("tools_meta.json")
    categories = meta.get("categories", {}).get("reconnaissance", {})
    tools: set[str] = set()
    for subcat in categories.values():
        if isinstance(subcat, list):
            tools.update(subcat)
    tools |= {"execute", "browser_action"}
    return tools


# ── Attack chains ────────────────────────────────────────────────────────────


def load_attack_chains() -> list[dict[str, Any]]:
    """Load and normalize attack chains from attack_chains.json."""
    raw = _load_json("attack_chains.json")
    if not raw:
        return []

    if isinstance(raw, dict) and "chains" in raw:
        chains = raw["chains"]
    elif isinstance(raw, list):
        chains = raw
    else:
        return []

    normalized: list[dict[str, Any]] = []
    for i, entry in enumerate(chains):
        if not isinstance(entry, dict):
            continue
        triggers = entry.get("triggers") or entry.get("required_findings") or []
        raw_steps = entry.get("steps", [])
        steps: list[dict[str, Any]] = []
        for step in raw_steps:
            if isinstance(step, dict):
                steps.append(step)
            elif isinstance(step, str):
                steps.append({"description": step, "tool_hint": "execute"})

        normalized.append(
            {
                "id": entry.get("id") or f"chain_{i}",
                "name": entry.get("name", f"Chain {i}"),
                "description": entry.get("description", ""),
                "triggers": [str(t).lower() for t in triggers],
                "required_findings": [str(t).lower() for t in triggers],
                "steps": steps,
                "severity": entry.get("severity", ""),
                "estimated_time": entry.get("estimated_time", ""),
                "detection_risk": entry.get("detection_risk", ""),
                "prerequisites": entry.get("prerequisites", []),
                "post_exploitation": entry.get("post_exploitation", []),
            }
        )
    return normalized


# ── Utility: merge headers ───────────────────────────────────────────────────


def merge_headers(
    base_headers: dict[str, str] | None,
    override_headers: dict[str, str] | None,
) -> dict[str, str] | None:
    """Merge two header dicts. Override takes precedence."""
    if not base_headers and not override_headers:
        return None
    merged: dict[str, str] = {}
    if base_headers:
        merged.update(base_headers)
    if override_headers:
        merged.update(override_headers)
    return merged


# ── Severity ranking (consistent 1-5 scale) ──────────────────────────────────

SEVERITY_TO_INT: dict[str, int] = {
    "CRITICAL": 5,
    "HIGH": 4,
    "MEDIUM": 3,
    "LOW": 2,
    "INFO": 1,
    "INFORMATIONAL": 1,
    "NOTICE": 2,
    "WARNING": 3,
    "WARN": 3,
    "ERROR": 4,
    "UNKNOWN": 1,
}

INT_TO_SEVERITY: dict[int, str] = {
    5: "CRITICAL",
    4: "HIGH",
    3: "MEDIUM",
    2: "LOW",
    1: "INFO",
}


def severity_to_int(severity: Any) -> int:
    """Convert a severity value to integer (1-5 scale).

    Accepts numeric values, numeric strings, and common labels emitted by
    heterogeneous tools such as HIGH/critical/WARNING/ERROR.
    """
    if isinstance(severity, (int, float)) and not isinstance(severity, bool):
        return max(1, min(int(severity), 5))

    text = str(severity or "").strip()
    if not text:
        return 1

    try:
        return max(1, min(int(float(text)), 5))
    except (TypeError, ValueError):
        pass

    normalized = re.sub(r"[^A-Z0-9]+", "_", text.upper()).strip("_")
    if normalized in SEVERITY_TO_INT:
        return SEVERITY_TO_INT[normalized]

    for token, value in (
        ("CRIT", 5),
        ("HIGH", 4),
        ("MED", 3),
        ("WARN", 3),
        ("ERROR", 4),
        ("LOW", 2),
        ("INFO", 1),
    ):
        if token in normalized:
            return value

    return 1


def int_to_severity(value: Any) -> str:
    """Convert integer to severity label (1-5 scale)."""
    return INT_TO_SEVERITY.get(severity_to_int(value), "INFO")


# ── WAF bypass strategies ────────────────────────────────────────────────────

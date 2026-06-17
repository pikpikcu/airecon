from __future__ import annotations

import hashlib
import json
import logging
import re
from pathlib import Path
from typing import Any

from ..data_loader import severity_to_int

logger = logging.getLogger("airecon.agent.novel_discovery")

_LEARNING_FILE = Path.home() / ".airecon" / "learning" / "novel_vectors.json"

_NOVELTY_MIN_CONFIDENCE = 0.4
_VECTOR_GENERATION_ENABLED = True


def _load_learned_vectors() -> dict[str, Any]:
    try:
        if _LEARNING_FILE.exists():
            return json.loads(_LEARNING_FILE.read_text(encoding="utf-8"))
    except Exception as e:
        logger.debug("Failed to load learned vectors: %s", e)
    return {}


def _save_learned_vectors(vectors: dict[str, Any]) -> None:
    try:
        _LEARNING_FILE.parent.mkdir(parents=True, exist_ok=True)
        _LEARNING_FILE.write_text(json.dumps(vectors, indent=2), encoding="utf-8")
    except Exception as e:
        logger.debug("Failed to save novel vectors: %s", e)


_LEARNED_VECTORS = _load_learned_vectors()

_ANOMALY_INDICATORS = [
    (r"timeout|timed.out|connection.refused|connection.reset", "network_timeout"),
    (r"unusual|unexpected|anomaly|odd|strange", "behavior_anomaly"),
    (r"differs|difference|changed|modified|alteration", "response_diff"),
    (r"reveal|expose|disclose|leak|display", "information_disclosure"),
    (r"guess|predictable|deterministic|pattern", "predictability"),
    (r"race.condition|toctou|concurrency", "concurrency_issue"),
    (r"cache|poison|stale", "caching_issue"),
    (r"permission|access.denied|unauthorized", "access_control"),
    (r"inconsistent|conflict|contradiction", "logic_conflict"),
    (r"mass.assignment|over.post|extra.field", "mass_assignment"),
]

_COMBINATION_PATTERNS = [
    {
        "name": "Info_Disclosure_to_Auth_Bypass",
        "components": ["information_disclosure", "access_control"],
        "description": "Use leaked info (version, paths, configs) to find auth bypass",
        "escalation": "Use disclosed info to access protected endpoints",
    },
    {
        "name": "Race_Condition_to_Financial_Impact",
        "components": ["concurrency_issue", "logic_conflict"],
        "description": "Exploit race conditions for double-spend or coupon abuse",
        "escalation": "Send multiple concurrent requests to exploit race",
    },
    {
        "name": "Cache_Poisoning_to_Stored_Impact",
        "components": ["caching_issue", "response_diff"],
        "description": "Poison cache with XSS to affect all users",
        "escalation": "Use unkeyed headers to inject malicious content",
    },
    {
        "name": "Mass_Assignment_to_Privilege_Escalation",
        "components": ["mass_assignment", "access_control"],
        "description": "Submit extra fields to escalate privileges",
        "escalation": "Add admin=true or role=admin to request",
    },
    {
        "name": "Prediction_to_Account_Takeover",
        "components": ["predictability", "access_control"],
        "description": "Predictable IDs/tokens allow account enumeration",
        "escalation": "Enumerate and takeover accounts via predictable values",
    },
]

# Curated tactic library. Unlike the old flat list (picked at random on a
# mechanical iteration cadence), each tactic carries `themes` — the signal
# keywords that make it relevant. Tactics are selected only when the actual
# findings/anomalies for THIS target contain a matching signal, so the output
# is target-specific and stable instead of generic and repetitive.
_TACTIC_LIBRARY: list[dict[str, Any]] = [
    {"tactic": "Test for business logic flaws in workflow sequences",
     "themes": ["logic_conflict", "behavior_anomaly", "workflow", "checkout", "cart", "order", "step"]},
    {"tactic": "Check for state machine violations in multi-step processes",
     "themes": ["logic_conflict", "behavior_anomaly", "wizard", "step", "status", "state"]},
    {"tactic": "Examine for race conditions in time-sensitive operations",
     "themes": ["concurrency_issue", "race", "coupon", "balance", "transfer", "withdraw", "redeem"]},
    {"tactic": "Look for mass assignment in API parameter binding",
     "themes": ["mass_assignment", "api", "json", "role", "admin", "isadmin", "privilege"]},
    {"tactic": "Search for predictable resource identifiers",
     "themes": ["predictability", "idor", "id=", "uuid", "sequential", "user_id", "order_id"]},
    {"tactic": "Check for cache poisoning via unkeyed headers",
     "themes": ["caching_issue", "cache", "x-forwarded", "host header", "cdn"]},
    {"tactic": "Test for second-order vulnerabilities (stored XSS, SQLi)",
     "themes": ["response_diff", "stored", "profile", "comment", "xss", "sqli", "injection"]},
    {"tactic": "Examine for client-side validation bypass opportunities",
     "themes": ["behavior_anomaly", "client", "javascript", "validation", "disabled"]},
    {"tactic": "Look for information disclosure in error messages",
     "themes": ["information_disclosure", "error", "stack", "trace", "verbose", "exception", "debug"]},
    {"tactic": "Check for improper handling of file extensions",
     "themes": ["upload", "file", "extension", "content-type", "multipart"]},
    {"tactic": "Test for prototype pollution in JavaScript apps",
     "themes": ["javascript", "json", "__proto__", "node", "merge", "constructor"]},
    {"tactic": "Search for insecure deserialization in data parsing",
     "themes": ["deserial", "pickle", "java", "serialized", "gadget", "viewstate"]},
    {"tactic": "Check for broken cryptographic implementations",
     "themes": ["crypto", "jwt", "hash", "token", "cipher", "weak", "md5"]},
    {"tactic": "Examine for improper session management",
     "themes": ["access_control", "session", "cookie", "logout", "fixation", "samesite"]},
    {"tactic": "Look for SAML validation bypass opportunities",
     "themes": ["saml", "sso", "assertion", "xml", "signature"]},
    {"tactic": "Test for OAuth/SSO implementation flaws",
     "themes": ["oauth", "sso", "redirect_uri", "state", "token", "openid"]},
    {"tactic": "Search for JWT validation weaknesses",
     "themes": ["jwt", "token", "alg", "none", "signature", "kid", "bearer"]},
    {"tactic": "Check for GraphQL introspection exposure",
     "themes": ["graphql", "introspection", "query", "schema", "__schema"]},
    {"tactic": "Examine for WebSocket security issues",
     "themes": ["websocket", "ws://", "wss://", "origin", "upgrade"]},
    {"tactic": "Search for API rate limiting bypass",
     "themes": ["api", "rate", "limit", "throttle", "429", "brute"]},
]

# Cache of LLM-generated, target-specific vectors keyed by findings signature.
# Populated asynchronously via generate_llm_novel_vectors() and consumed by the
# synchronous analyze_novel_vectors().
_LLM_VECTOR_CACHE: dict[str, dict[str, Any]] = {}


def _detect_anomalies(text: str) -> list[tuple[str, str]]:
    text_lower = text.lower()
    detected = []

    for pattern, category in _ANOMALY_INDICATORS:
        if re.search(pattern, text_lower, re.IGNORECASE):
            detected.append((category, pattern))

    return detected


def _analyze_combination_potential(
    findings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    if len(findings) < 2:
        return []

    finding_categories = set()
    for f in findings:
        cat = f.get("category", f.get("type", "unknown")).lower()
        finding_categories.add(cat)

    combinations = []
    for pattern in _COMBINATION_PATTERNS:
        match_count = sum(1 for c in pattern["components"] if c in finding_categories)
        if match_count >= 2:
            combinations.append(
                {
                    "name": pattern["name"],
                    "description": pattern["description"],
                    "escalation": pattern["escalation"],
                    "confidence": match_count / len(pattern["components"]),
                    "components_found": [
                        c for c in pattern["components"] if c in finding_categories
                    ],
                }
            )

    return sorted(combinations, key=lambda x: x["confidence"], reverse=True)


_FINDING_TEXT_KEYS = (
    "title", "finding", "description", "summary", "category", "type",
    "vuln_class", "endpoint", "parameter", "url", "evidence",
)


def _build_signal_text(findings: list[dict[str, Any]]) -> str:
    """Flatten the salient text of all findings into one lowercase blob."""
    parts: list[str] = []
    for f in findings:
        for key in _FINDING_TEXT_KEYS:
            value = f.get(key)
            if value:
                parts.append(str(value))
    return " ".join(parts).lower()


def _select_relevant_tactics(
    findings: list[dict[str, Any]],
    limit: int = 2,
) -> list[str]:
    """Pick tactics whose themes actually appear in the findings for this target.

    Deterministic and evidence-driven: a tactic surfaces only when its theme
    keywords match the observed signals, ranked by number of matches. Returns
    [] when nothing matches, so no generic filler is injected.
    """
    text = _build_signal_text(findings)
    if not text:
        return []

    scored: list[tuple[int, str]] = []
    for entry in _TACTIC_LIBRARY:
        hits = sum(1 for theme in entry["themes"] if theme in text)
        if hits > 0:
            scored.append((hits, entry["tactic"]))

    # Highest match count first; tie-break alphabetically for stable output.
    scored.sort(key=lambda x: (-x[0], x[1]))
    return [tactic for _hits, tactic in scored[:limit]]


def _findings_signature(findings: list[dict[str, Any]]) -> str:
    """Stable id for a set of findings (order-independent)."""
    bases = sorted(
        str(f.get("title", f.get("finding", "")))[:60] for f in findings
    )
    return hashlib.md5(  # non-cryptographic identifier
        "|".join(bases).encode(), usedforsecurity=False
    ).hexdigest()[:16]


def _build_emergent_vector(
    findings: list[dict[str, Any]],
    anomaly_categories: list[str],
    combinations: list[dict[str, Any]],
) -> dict[str, Any] | None:
    """Build a deterministic, finding-grounded emergent escalation vector.

    Replaces the old random-md5 / hardcoded-description / formulaic-confidence
    vector. Fires on evidence (≥3 findings AND ≥2 distinct signal types), not on
    an iteration counter, and grounds its confidence in the signal count.
    """
    distinct_signals: set[str] = set(anomaly_categories) | {
        str(c.get("name", "")) for c in combinations if c.get("name")
    }
    if len(findings) < 3 or len(distinct_signals) < 2:
        return None

    bases = [
        str(f.get("title", f.get("finding", "unknown")))[:60]
        for f in findings[:3]
    ]
    sig = hashlib.md5(  # non-cryptographic identifier
        ("|".join(sorted(bases)) + "::" + "|".join(sorted(distinct_signals))).encode(),
        usedforsecurity=False,
    ).hexdigest()[:12]
    vector_id = f"novel_{sig}"

    escalation = (
        combinations[0].get("escalation")
        if combinations
        else "Chain these findings: pivot from the lower-impact signals into the access-control or injection finding."
    )
    signal_phrase = ", ".join(sorted(distinct_signals)[:3]).replace("_", " ")
    description = f"Emergent escalation path linking {signal_phrase}"
    # Confidence grounded in real evidence: distinct signal types + breadth.
    confidence = round(
        min(0.85, 0.35 + 0.10 * len(distinct_signals) + 0.05 * min(len(findings), 5)),
        2,
    )

    vector = {
        "id": vector_id,
        "description": description,
        "bases": bases,
        "escalation": escalation,
        "confidence": confidence,
        "source": "heuristic",
    }

    if vector_id not in _LEARNED_VECTORS:
        _LEARNED_VECTORS[vector_id] = dict(vector)
        _LEARNED_VECTORS[vector_id]["discovery_count"] = 0
    _LEARNED_VECTORS[vector_id]["discovery_count"] = (
        _LEARNED_VECTORS[vector_id].get("discovery_count", 0) + 1
    )
    if len(_LEARNED_VECTORS) % 5 == 0:
        _save_learned_vectors(_LEARNED_VECTORS)

    return vector


def _format_findings_for_prompt(findings: list[dict[str, Any]]) -> str:
    lines: list[str] = []
    for f in findings:
        title = str(f.get("title", f.get("finding", "finding")))[:90]
        cat = str(f.get("category", f.get("vuln_class", f.get("type", "")))).strip()
        ep = str(f.get("endpoint", f.get("url", ""))).strip()[:90]
        param = str(f.get("parameter", "")).strip()
        sev = str(f.get("severity", "")).strip()
        meta = ", ".join(
            p for p in (
                f"cat={cat}" if cat else "",
                f"endpoint={ep}" if ep else "",
                f"param={param}" if param else "",
                f"sev={sev}" if sev else "",
            ) if p
        )
        lines.append(f"- {title}" + (f" ({meta})" if meta else ""))
    return "\n".join(lines)


def _parse_llm_vector_json(raw: str) -> dict[str, Any]:
    """Parse the LLM response into {tactics:[...], vector:{...}}; tolerant."""
    if not raw or not raw.strip():
        return {}
    text = raw.strip()
    # Strip code fences if present.
    fence = re.search(r"```(?:json)?\s*(.+?)```", text, re.DOTALL | re.IGNORECASE)
    if fence:
        text = fence.group(1).strip()
    # Find the first JSON object.
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end <= start:
        return {}
    try:
        data = json.loads(text[start : end + 1])
    except Exception as e:
        logger.debug("Failed to parse LLM novel-vector JSON: %s", e)
        return {}
    if not isinstance(data, dict):
        return {}

    out: dict[str, Any] = {}
    tactics = data.get("tactics")
    if isinstance(tactics, list):
        out["tactics"] = [str(t).strip() for t in tactics if str(t).strip()][:4]
    vector = data.get("vector")
    if isinstance(vector, dict) and str(vector.get("description", "")).strip():
        try:
            conf = float(vector.get("confidence", 0.5))
        except (TypeError, ValueError):
            conf = 0.5
        out["vector"] = {
            "description": str(vector["description"]).strip()[:200],
            "escalation": str(vector.get("escalation", "")).strip()[:300]
            or "Chain these findings to escalate impact.",
            "confidence": round(max(0.1, min(0.95, conf)), 2),
        }
    return out


async def generate_llm_novel_vectors(
    findings: list[dict[str, Any]],
    *,
    max_findings: int = 15,
) -> dict[str, Any]:
    """Ask the configured LLM for target-specific tactics + an emergent vector.

    This is the genuinely creative layer: instead of replaying a fixed list, it
    reasons over the ACTUAL findings of this target and proposes non-obvious
    attack paths. Results are cached by findings signature so the synchronous
    analyze_novel_vectors() can consume them without blocking. No-ops cleanly
    when the LLM backend is not configured.
    """
    if not findings:
        return {}
    try:
        from ..config import get_config
        from ..llm import LLMClient

        cfg = get_config()
        if not getattr(cfg, "openai_base_url", "") or not getattr(cfg, "openai_model", ""):
            return {}

        sig = _findings_signature(findings)
        if sig in _LLM_VECTOR_CACHE:
            return _LLM_VECTOR_CACHE[sig]

        findings_text = _format_findings_for_prompt(findings[:max_findings])
        prompt = (
            "You are an elite bug-bounty hunter doing creative attack-path "
            "synthesis. Below are the CONFIRMED/observed findings on a single "
            "authorized target.\n\n"
            f"Findings:\n{findings_text}\n\n"
            "Propose NON-OBVIOUS, target-specific next moves that a creative "
            "pentester would try by chaining or pivoting from these specific "
            "findings. Do NOT restate generic checklists — tie every suggestion "
            "to the actual endpoints/params/categories above.\n"
            "Return ONLY a JSON object:\n"
            '{"tactics": ["<=4 concrete target-specific tactics"], '
            '"vector": {"description": "one emergent multi-finding escalation '
            'path", "escalation": "the concrete step", "confidence": 0.0-1.0}}'
        )

        client = LLMClient()
        raw = await client.complete(
            [{"role": "user", "content": prompt}],
            max_retries=1,
            options={"temperature": 0.4},
            operation="analysis",
        )
        data = _parse_llm_vector_json(raw)
        if data:
            _LLM_VECTOR_CACHE[sig] = data
        return data or {}
    except Exception as e:
        logger.debug("LLM novel-vector generation failed: %s", e)
        return {}


def analyze_novel_vectors(
    findings: list[dict[str, Any]],
    iteration: int = 0,
) -> dict[str, Any]:
    if not findings or not _VECTOR_GENERATION_ENABLED:
        return {
            "novel_vectors": [],
            "combinations": [],
            "innovative_tactics": [],
            "recommendations": [],
        }

    detected_anomalies = []
    for f in findings:
        summary = f.get("summary", f.get("description", ""))
        if summary:
            anomalies = _detect_anomalies(summary)
            detected_anomalies.extend(anomalies)
        # Also scan the title — many findings carry their signal there.
        title = f.get("title", f.get("finding", ""))
        if title:
            detected_anomalies.extend(_detect_anomalies(str(title)))

    unique_anomalies = list(set(detected_anomalies))
    anomaly_categories = list({a[0] for a in unique_anomalies})

    combinations = _analyze_combination_potential(findings)

    # Prefer LLM-generated, target-specific output when it has been produced for
    # this finding-set; otherwise fall back to evidence-derived selection. Either
    # way the output is tied to THIS target — never a random generic checklist.
    llm_data = _LLM_VECTOR_CACHE.get(_findings_signature(findings), {})

    tactics = list(llm_data.get("tactics", []))[:3]
    if not tactics:
        tactics = _select_relevant_tactics(findings, limit=2)

    recommendations = []
    if combinations:
        recommendations.append(
            f"Consider combining: {combinations[0]['name']} "
            f"({combinations[0]['confidence']:.0%} confidence)"
        )
    if anomaly_categories:
        recommendations.append(
            "Detected anomaly signals: "
            + ", ".join(c.replace("_", " ") for c in anomaly_categories[:4])
        )

    novel_vectors: list[dict[str, Any]] = []
    llm_vec = llm_data.get("vector")
    if isinstance(llm_vec, dict) and llm_vec.get("description"):
        bases = [
            str(f.get("title", f.get("finding", "unknown")))[:60]
            for f in findings[:3]
        ]
        vec_id = f"novel_llm_{_findings_signature(findings)[:12]}"
        vector = {
            "id": vec_id,
            "description": llm_vec["description"],
            "bases": bases,
            "escalation": llm_vec.get("escalation", "Analyze for escalation"),
            "confidence": llm_vec.get("confidence", 0.5),
            "source": "llm",
        }
        if vec_id not in _LEARNED_VECTORS:
            _LEARNED_VECTORS[vec_id] = dict(vector)
            _LEARNED_VECTORS[vec_id]["discovery_count"] = 0
        _LEARNED_VECTORS[vec_id]["discovery_count"] = (
            _LEARNED_VECTORS[vec_id].get("discovery_count", 0) + 1
        )
        if len(_LEARNED_VECTORS) % 5 == 0:
            _save_learned_vectors(_LEARNED_VECTORS)
        novel_vectors.append(vector)
    else:
        heuristic_vec = _build_emergent_vector(
            findings, anomaly_categories, combinations
        )
        if heuristic_vec:
            novel_vectors.append(heuristic_vec)

    result = {
        "novel_vectors": novel_vectors,
        "combinations": combinations[:3],
        "innovative_tactics": tactics,
        "recommendations": recommendations,
        "anomalies_detected": anomaly_categories,
    }

    return result


def get_recommendation_for_finding(
    finding: dict[str, Any],
    all_findings: list[dict[str, Any]],
) -> list[str]:
    recommendations = []

    finding_cat = finding.get("category", "unknown").lower()
    finding_sev = severity_to_int(finding.get("severity", 3))

    if finding_sev <= 2:
        combinations = _analyze_combination_potential(all_findings)
        if combinations:
            recommendations.append(
                f"LOW severity can be escalated via: {combinations[0]['name']}"
            )

    anomalies = _detect_anomalies(finding.get("summary", ""))
    anomaly_types = list(set([a[0] for a in anomalies]))

    if "network_timeout" in anomaly_types:
        recommendations.append(
            "Timeout anomalies may indicate SSRF or blind injection - probe internal services"
        )
    if "behavior_anomaly" in anomaly_types:
        recommendations.append(
            "Behavioral anomalies may reveal logic flaws - test edge cases"
        )
    if "information_disclosure" in anomaly_types:
        recommendations.append(
            "Disclosed info can enable further exploitation - enumerate using revealed paths"
        )
    if "predictability" in anomaly_types:
        recommendations.append(
            "Predictable values enable enumeration attacks - test systematically"
        )

    if len(all_findings) >= 5 and finding_cat != "unknown":
        recommendations.append(
            "With multiple findings, consider chaining for higher impact"
        )

    if not recommendations:
        recommendations.append(
            "Review in attack chain context for escalation opportunities"
        )

    return recommendations


def get_all_learned_vectors() -> dict[str, Any]:
    return dict(_LEARNED_VECTORS)


def clear_learned_vectors() -> None:
    global _LEARNED_VECTORS
    _LEARNED_VECTORS = {}
    try:
        if _LEARNING_FILE.exists():
            _LEARNING_FILE.unlink()
    except Exception as e:
        logger.debug("Failed to clear learned vectors: %s", e)

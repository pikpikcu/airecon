"""Dynamic vulnerability classifier — evidence-driven, NOT keyword-pattern based.

Old approach (removed): hardcoded _GENERIC_KEYWORDS dict + regex anomaly detection.
That system only caught findings where evidence text contained specific words.
If the LLM wrote "balance went negative" it missed the race condition because
"race" wasn't in the text.  If the evidence said "user could change role field"
it missed IDOR because "access"/"permission"/"privilege" weren't present.

New approach: classify by impact structure, not by words.
"""

from __future__ import annotations

import logging
from typing import Any

from ..data_loader import severity_to_int

logger = logging.getLogger("airecon.dynamic_classifier")

# ── Impact-level taxonomies (NOT keyword lists) ─────────────────────────────
# These describe WHAT the attacker CAN DO, not WHAT WORDS appear.
# A finding is classified by matching its OBSERVED EFFECT against these
# impact signatures.  The matching is done via evidence structure analysis
# rather than keyword presence.

_IMPACT_SIGNATURES = [
    # Signature 0: Attacker reads or exfiltrates data they shouldn't
    {
        "category": "DATA_EXPOSURE",
        "effect_verbs": {"read", "leak", "expose", "dump", "disclose", "enumerate",
                         "extract", "download", "view", "list", "query", "traverse"},
        "effect_targets": {"data", "file", "source", "config", "env", "credential",
                            "database", "token", "secret", "key", "password", "header",
                            "response", "error", "stack", "trace", "backup", "log"},
        "severity_base": 3,
    },
    # Signature 1: Attacker modifies state or data
    {
        "category": "STATE_MANIPULATION",
        "effect_verbs": {"modify", "change", "update", "overwrite", "delete", "create",
                          "inject", "execute", "run", "alter", "tamper", "replace",
                          "manipulate", "bypass", "skip"},
        "effect_targets": {"query", "command", "code", "script", "payload", "request",
                            "response", "parameter", "input", "form", "header",
                            "cookie", "session", "workflow", "step", "logic"},
        "severity_base": 4,
    },
    # Signature 2: Attacker gains unauthorized access or privilege
    {
        "category": "UNAUTHORIZED_ACCESS",
        "effect_verbs": {"access", "login", "authenticate", "bypass", "elevate",
                          "impersonate", "forge", "spoof", "hijack", "takeover",
                          "escalate", "promote", "assume"},
        "effect_targets": {"admin", "panel", "dashboard", "account", "user", "session",
                            "token", "role", "permission", "privilege", "auth",
                            "api", "endpoint", "resource", "object", "tenant"},
        "severity_base": 4,
    },
    # Signature 3: System behaves incorrectly under unusual conditions
    {
        "category": "LOGIC_FLAW",
        "effect_verbs": {"skip", "bypass", "repeat", "replay", "race", "overflow",
                          "underflow", "negative", "exceed", "duplicate", "reorder",
                          "corrupt", "crash", "freeze", "loop", "hang"},
        "effect_targets": {"balance", "quantity", "price", "cost", "state", "flow",
                            "workflow", "process", "transaction", "order", "payment",
                            "limit", "threshold", "counter", "sequence", "step"},
        "severity_base": 3,
    },
    # Signature 4: Attacker causes unintended network behavior
    {
        "category": "NETWORK_ABUSE",
        "effect_verbs": {"request", "fetch", "connect", "resolve", "scan", "probe",
                          "forward", "redirect", "relay", "tunnel", "smuggle"},
        "effect_targets": {"internal", "localhost", "127.0.0.1", "metadata", "cloud",
                            "aws", "gcp", "azure", "header", "dns", "cache",
                            "proxy", "origin", "backend", "server"},
        "severity_base": 3,
    },
    # Signature 5: Attacker causes resource exhaustion
    {
        "category": "RESOURCE_EXHAUSTION",
        "effect_verbs": {"exhaust", "consume", "flood", "bomb", "deplete", "overload",
                          "slow", "timeout", "crash", "freeze", "hang", "amplify"},
        "effect_targets": {"memory", "cpu", "disk", "bandwidth", "connection", "pool",
                            "thread", "process", "request", "rate", "limit",
                            "cache", "buffer", "stack", "queue"},
        "severity_base": 2,
    },
    # Signature 6: Information leakage about system internals
    {
        "category": "INFORMATION_DISCLOSURE",
        "effect_verbs": {"reveal", "show", "return", "display", "leak", "expose",
                          "disclose", "print", "output", "emit", "transmit"},
        "effect_targets": {"version", "path", "framework", "technology", "library",
                            "stack", "trace", "error", "debug", "config", "header",
                            "server", "environment", "component", "signature"},
        "severity_base": 1,
    },
]


# ── OWASP mapping (kept for compliance reporting, NOT for classification) ───
# Extended to include OWASP API Security 2023 and CWE mappings
_OWL_MAPPING: dict[str, list[int]] = {
    # Impact category → list of OWASP 2021 IDs it maps to
    "DATA_EXPOSURE": [2, 4],           # Crypto Failures, Insecure Design
    "STATE_MANIPULATION": [1, 3, 7],    # Access Control, Injection, Data Integrity
    "UNAUTHORIZED_ACCESS": [1, 7],      # Access Control, Auth Failures
    "LOGIC_FLAW": [4, 8],              # Insecure Design, Integrity Failures
    "NETWORK_ABUSE": [5, 10],           # Misconfiguration, SSRF
    "RESOURCE_EXHAUSTION": [5, 6],      # Misconfiguration, Outdated Components
    "INFORMATION_DISCLOSURE": [2, 9],   # Crypto Failures, Logging Failures
}

# OWASP API Security 2023 mapping
_OWL_API_MAPPING: dict[str, list[str]] = {
    "DATA_EXPOSURE": ["API1:2023", "API3:2023", "API4:2023"],
    "UNAUTHORIZED_ACCESS": ["API1:2023", "API2:2023", "API5:2023"],
    "STATE_MANIPULATION": ["API3:2023", "API6:2023", "API10:2023"],
    "LOGIC_FLAW": ["API6:2023", "API7:2023", "API9:2023"],
    "NETWORK_ABUSE": ["API4:2023", "API7:2023"],
    "RESOURCE_EXHAUSTION": ["API4:2023", "API8:2023"],
    "INFORMATION_DISCLOSURE": ["API3:2023", "API9:2023"],
}

_OWL_LABELS: dict[str, str] = {
    "A01:2021": "Broken Access Control",
    "A02:2021": "Cryptographic Failures",
    "A03:2021": "Injection",
    "A04:2021": "Insecure Design",
    "A05:2021": "Security Misconfiguration",
    "A06:2021": "Vulnerable and Outdated Components",
    "A07:2021": "Identification and Authentication Failures",
    "A08:2021": "Software and Data Integrity Failures",
    "A09:2021": "Security Logging and Monitoring Failures",
    "A10:2021": "Server-Side Request Forgery",
    # OWASP API Security 2023
    "API1:2023": "Broken Object Level Authorization",
    "API2:2023": "Broken Authentication",
    "API3:2023": "Broken Object Property Level Authorization",
    "API4:2023": "Unrestricted Resource Consumption",
    "API5:2023": "Broken Function Level Authorization",
    "API6:2023": "Unrestricted Access to Sensitive Business Flows",
    "API7:2023": "Server Side Request Forgery",
    "API8:2023": "Security Misconfiguration",
    "API9:2023": "Improper Inventory Management",
    "API10:2023": "Unsafe Consumption of APIs",
}


def _extract_effect_words(text: str) -> tuple[set[str], set[str]]:
    """Extract verbs and target nouns from evidence text.

    This replaces keyword-in-category matching.  Instead of checking if text
    contains words from a hardcoded category list, we identify what ACTION
    is being described (verbs) and what is being AFFECTED (targets near those
    verbs in proximity).
    """
    text_lower = text.lower()
    words = text_lower.split()
    verbs = set()
    targets = set()

    # Known verb set that describes attacker EFFECT
    all_verbs = set()
    for sig in _IMPACT_SIGNATURES:
        all_verbs.update(sig["effect_verbs"])
    all_targets = set()
    for sig in _IMPACT_SIGNATURES:
        all_targets.update(sig["effect_targets"])

    for i, word in enumerate(words):
        # Strip common punctuation
        cleaned = word.strip(".,;:()[]{}\"'`")

        if cleaned in all_verbs:
            verbs.add(cleaned)

        # Targets: words that appear within 3 words of a verb
        if cleaned in all_targets:
            # Check proximity to any recognized verb
            start = max(0, i - 4)
            end = min(len(words), i + 4)
            window = words[start:end]
            for w in window:
                if w.strip(".,;:()[]{}\"'`") in all_verbs:
                    targets.add(cleaned)
                    break

    return verbs, targets


def _classify_by_keyword(summary: str) -> list[str]:
    """Keyword-based OWASP classification — supplements impact-based classification.

    Returns list of OWASP tags matched by keywords in the summary.
    This ensures well-known vulnerability keywords map to correct OWASP IDs.
    """
    summary_lower = summary.lower()
    owasp_tags = []

    _positive_indicators = [
        "confirmed", "verified", "exploitable", "exploit works",
        "proof of concept", "poc works", "replay_verified", "report_generated",
    ]

    # Negative keyword suppression — checks for negation proximity to vuln keywords
    # If a negative word appears near a vuln keyword, that specific vuln is suppressed
    _neg_words = [
        "not vulnerable", "false positive", "unverified", "needs verification",
        "potential vulnerability", "could be vulnerable", "might be vulnerable",
        "no evidence", "could not confirm", "unable to confirm",
        "no vulnerability", "no issues found", "patched",
        "not vulnerable to",
    ]

    def _is_negated(vuln_kw: str) -> bool:
        """Check if a vuln keyword is negated by nearby negative words.
        
        Only suppresses if the negation is specifically about this vuln type
        (e.g., 'no sql injection' should not suppress 'ssrf').
        """
        idx = summary_lower.find(vuln_kw)
        if idx < 0:
            return False

        # Check for vuln-specific negation patterns
        vuln_specific_neg = [
            f"no {vuln_kw}", f"not {vuln_kw}", f"no {vuln_kw.split()[0]}",
            f"{vuln_kw} not found", f"{vuln_kw} patched",
        ]
        for neg in vuln_specific_neg:
            if neg in summary_lower:
                return True

        local_window = summary_lower[max(0, idx - 40): idx + len(vuln_kw) + 80]
        local_positive = any(pos in local_window for pos in _positive_indicators)

        # Check for generic negation words near the keyword (within 150 chars)
        for neg in _neg_words:
            neg_idx = summary_lower.find(neg)
            if neg_idx >= 0 and abs(idx - neg_idx) < 150:
                return not local_positive

        return False

    # Keyword → OWASP mapping
    keyword_map = [
        (["sql injection", "sqli", "union select"], "A03:2021"),
        (["xss", "cross-site scripting", "script injection"], "A03:2021"),
        (["ssrf", "server-side request forgery", "169.254.169.254"], "A10:2021"),
        (["rce", "command injection", "code execution", "remote code execution"], "A03:2021"),
        (["log4j", "log4shell", "jndi"], "A03:2021"),
        (["log4j", "log4shell"], "A06:2021"),  # Log4Shell is also a vulnerable component
        (["idor", "insecure direct object reference"], "A01:2021"),
        (["broken access", "access control"], "A01:2021"),
        (["misconfiguration", "misconfig", "default cred", "exposed", "directory listing"], "A05:2021"),
        (["crypto", "encryption", "hash", "tls", "certificate"], "A02:2021"),
        (["cve-", "vulnerable component", "outdated"], "A06:2021"),
        (["mass assignment", "object property"], "API3:2023"),
        (["bola", "broken object level"], "API1:2023"),
        (["bfla", "broken function level"], "API5:2023"),
        (["open redirect", "redirect_url", "forward_path"], "A01:2021"),
    ]

    for keywords, owasp_id in keyword_map:
        for kw in keywords:
            if kw in summary_lower and not _is_negated(kw):
                tag = f"owasp:{owasp_id}"
                if tag not in owasp_tags:
                    owasp_tags.append(tag)
                break

    return owasp_tags


def _classify_by_tag(tags: list[str]) -> list[str]:
    """Classify vulnerability by tags (e.g., 'ssrf' tag → owasp:A10:2021)."""
    owasp_tags = []
    tag_lower = [t.lower() for t in tags]

    tag_map = {
        "ssrf": "A10:2021",
        "xss": "A03:2021",
        "sqli": "A03:2021",
        "sql injection": "A03:2021",
        "idor": "A01:2021",
        "broken access": "A01:2021",
        "misconfiguration": "A05:2021",
        "crypto": "A02:2021",
        "cve": "A06:2021",
        "bola": "API1:2023",
        "bfla": "API5:2023",
        "mass assignment": "API3:2023",
        "open redirect": "A01:2021",
        "rce": "A03:2021",
        "command injection": "A03:2021",
    }

    for tag in tag_lower:
        for known_tag, owasp_id in tag_map.items():
            if known_tag in tag:
                tag_str = f"owasp:{owasp_id}"
                if tag_str not in owasp_tags:
                    owasp_tags.append(tag_str)

    return owasp_tags


def _classify_by_impact(
    verbs: set[str],
    targets: set[str],
) -> tuple[str, int]:
    """Match effect structure against impact signatures.

    Returns (category, severity_base).
    A finding matches a signature if it shares verbs AND/OR targets with it.
    The score is the Jaccard-like overlap of verbs + targets.
    """
    best_category = "UNKNOWN"
    best_severity = 1
    best_score = 0.0

    for sig in _IMPACT_SIGNATURES:
        sig_verbs = sig["effect_verbs"]
        sig_targets = sig["effect_targets"]

        # Verb overlap: how many of the finding's verbs appear in this signature
        verb_overlap = len(verbs & sig_verbs) / max(len(sig_verbs), 1)

        # Target overlap: how many affected targets match
        target_overlap = len(targets & sig_targets) / max(len(sig_targets), 1)

        # Combined score — verbs weighted higher because they define the attack type
        score = (verb_overlap * 0.65) + (target_overlap * 0.35)

        if score > best_score:
            best_score = score
            best_category = sig["category"]
            best_severity = sig["severity_base"]

    return best_category, best_severity


def _calculate_dynamic_severity(
    category: str,
    severity_base: int,
    confidence: float,
    has_exploit_evidence: bool,
) -> int:
    """Adjust severity by confirmation and impact scope."""
    if category == "UNKNOWN":
        return 1

    score = severity_base

    if has_exploit_evidence:
        score += 1

    if confidence > 0.85:
        score += 1
    elif confidence < 0.4:
        score = max(1, score - 1)

    return min(5, max(1, score))


def _infer_impact_from_context(
    category: str,
    technology: list[str],
    endpoint: str,
) -> dict[str, list[str]]:
    """Infer attack impact from context, not from hardcoded tech strings."""
    impacts: list[str] = []

    endpoint_lower = endpoint.lower() if endpoint else ""
    # Impact inference based on endpoint role, not tech name matching
    if any(p in endpoint_lower for p in ("/admin", "/dashboard", "/manage", "/console")):
        impacts.append("Sensitive management interface affected")

    if any(p in endpoint_lower for p in ("/api/", "/graphql", "/rpc")):
        impacts.append("API surface accessible to attacker")

    if any(p in endpoint_lower for p in ("/upload", "/import", "/file")):
        impacts.append("File handling vector present")

    # Impact inference from category
    impact_map = {
        "DATA_EXPOSURE": "Unauthorized data access or exfiltration",
        "STATE_MANIPULATION": "Application state or data integrity compromised",
        "UNAUTHORIZED_ACCESS": "Access control boundary crossed",
        "LOGIC_FLAW": "Application logic produces unintended outcomes",
        "NETWORK_ABUSE": "Network boundary violation or unintended outbound requests",
        "RESOURCE_EXHAUSTION": "Service availability degraded",
        "INFORMATION_DISCLOSURE": "System internals exposed to attacker",
    }
    if category in impact_map:
        impacts.append(impact_map[category])

    return {"impact": impacts[:3]}


def _generate_recommendation(category: str, severity: int) -> str:
    """Generate remediation from category semantics, not hardcoded per-category dicts."""
    recommendations = {
        "DATA_EXPOSURE": "Restrict data access with proper authorization; encrypt sensitive data; audit data flows",
        "STATE_MANIPULATION": "Validate and sanitize all inputs; use parameterized queries; implement integrity checks",
        "UNAUTHORIZED_ACCESS": "Implement least-privilege access; verify authorization on every request; use RBAC",
        "LOGIC_FLAW": "Threat-model business workflows; enforce state transitions server-side; add idempotency checks",
        "NETWORK_ABUSE": "Restrict outbound requests; validate all URLs; use network-level egress controls",
        "RESOURCE_EXHAUSTION": "Implement rate limiting; add request size limits; use resource quotas",
        "INFORMATION_DISCLOSURE": "Remove debug/error details from responses; use generic error messages; harden headers",
    }
    base = recommendations.get(
        category,
        "Investigate root cause; apply defense-in-depth; review security controls",
    )
    if severity >= 4:
        return f"CRITICAL: {base}"
    if severity >= 3:
        return f"HIGH: {base}"
    return base


def _generate_generic_recommendation(category: str, severity: int) -> str:
    """Same as _generate_recommendation — kept for API compatibility."""
    return _generate_recommendation(category, severity)


# ── Public API ───────────────────────────────────────────────────────────────

def classify_vulnerability(
    summary: str,
    tags: list[str],
    source_tool: str = "",
    technology: list[str] | None = None,
    endpoint: str = "",
    evidence: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Classify a vulnerability by its IMPACT STRUCTURE, not by keywords.

    Steps:
    1. Extract effect verbs and target nouns from the evidence summary
    2. Match against 7 impact signatures (DATA_EXPOSURE, STATE_MANIPULATION,
       UNAUTHORIZED_ACCESS, LOGIC_FLAW, NETWORK_ABUSE, RESOURCE_EXHAUSTION,
       INFORMATION_DISCLOSURE)
    3. Score by Jaccard overlap of verb+target sets
    4. Adjust severity by confidence and exploit evidence

    This catches logic flaws that keyword matching misses:
    - "balance went negative" → LOGIC_FLAW (no "race" keyword needed)
    - "changed role field to admin" → UNAUTHORIZED_ACCESS or STATE_MANIPULATION
    - "skipped payment step" → LOGIC_FLAW (not just the word "bypass")
    """
    summary_text = " ".join(str(summary).strip().split())
    if not summary_text:
        return {
            "category": "UNKNOWN",
            "severity": 1,
            "confidence": 0.0,
            "anomalies_detected": [],
            "semantic_features": {},
            "impact": {"impact": []},
            "tags": list(tags),
            "recommendation": "Unable to classify — empty evidence summary",
        }

    # Step 1: extract effect structure
    verbs, targets = _extract_effect_words(summary_text)

    # Step 2: classify by impact
    category, severity_base = _classify_by_impact(verbs, targets)

    # Fallback: if impact classification returned UNKNOWN, use keyword-based severity
    if category == "UNKNOWN":
        keyword_owasp = _classify_by_keyword(summary_text)
        if keyword_owasp:
            # Map OWASP IDs to reasonable severity
            keyword_severity_map = {
                "A03:2021": 4,  # Injection → High
                "A01:2021": 4,  # Broken Access → High
                "A10:2021": 4,  # SSRF → High
                "A06:2021": 3,  # Vulnerable Components → Medium
                "A05:2021": 2,  # Misconfiguration → Low
                "A02:2021": 3,  # Crypto Failures → Medium
                "API1:2023": 4,  # BOLA → High
                "API3:2023": 3,  # Mass Assignment → Medium
                "API5:2023": 4,  # BFLA → High
            }
            for tag in keyword_owasp:
                if tag.startswith("owasp:"):
                    owasp_id = tag[6:]
                    sev = keyword_severity_map.get(owasp_id, 3)
                    if sev > severity_base:
                        severity_base = sev
                        category = "KEYWORD_MATCH"

    # Step 3: adjust severity
    confidence = 0.5
    if evidence:
        confidence = float(evidence.get("confidence", 0.5))

    has_exploit = bool(
        evidence and (
            evidence.get("proof")
            or evidence.get("evidence")
            or evidence.get("poc_script_code")
        )
    )
    severity = _calculate_dynamic_severity(
        category, severity_base, confidence, has_exploit
    )

    # Step 4: infer impact
    impact = _infer_impact_from_context(category, technology or [], endpoint)

    # Build result
    semantic_features = {}
    if verbs:
        semantic_features["effect_verbs"] = sorted(verbs)
    if targets:
        semantic_features["affected_targets"] = sorted(targets)

    owasp_tags = []
    for oid in _OWL_MAPPING.get(category, []):
        prefix = "API" if oid >= 100 else "A"
        oid_str = f"{prefix}{oid % 100:02d}:2021"
        owasp_tags.append(f"owasp:{oid_str}")

    # Also add keyword-based OWASP tags (supplements impact-based classification)
    keyword_owasp_tags = _classify_by_keyword(summary_text)
    for tag in keyword_owasp_tags:
        if tag not in owasp_tags:
            owasp_tags.append(tag)

    # Also add tag-based OWASP tags (e.g., 'ssrf' tag → A10:2021)
    tag_owasp_tags = _classify_by_tag(tags)
    for tag in tag_owasp_tags:
        if tag not in owasp_tags:
            owasp_tags.append(tag)

    # Build result tags: only add dynamic category if we actually classified something
    dynamic_tags = []
    if category != "UNKNOWN":
        dynamic_tags.append(f"dynamic:{category.lower()}")

    result = {
        "category": category,
        "severity": severity,
        "confidence": confidence,
        "anomalies_detected": list(verbs),  # verbs ARE the detected anomalies
        "semantic_features": semantic_features,
        "impact": impact,
        "tags": tags + dynamic_tags + owasp_tags,
    }

    result["recommendation"] = _generate_recommendation(category, severity)
    return result


def classify_batch(
    findings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    results = []
    for finding in findings:
        result = classify_vulnerability(
            summary=finding.get("summary", finding.get("description", "")),
            tags=finding.get("tags", []),
            source_tool=finding.get("source_tool", ""),
            technology=finding.get("technology", []),
            endpoint=finding.get("endpoint", ""),
            evidence=finding,
        )
        results.append(result)
    return results


def severity_label(severity: int) -> str:
    return {5: "Critical", 4: "High", 3: "Medium", 2: "Low", 1: "Info"}.get(
        severity, "Info"
    )


def evidence_risk_summary(evidence: list[dict[str, Any]]) -> dict[str, Any]:
    if not evidence:
        return {
            "severity_distribution": {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0},
            "top_categories": [],
            "total_evidence": 0,
            "high_or_critical": 0,
        }

    sev_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    category_counts: dict[str, int] = {}

    for item in evidence:
        sev = severity_to_int(item.get("severity", 1))
        label = severity_label(sev)
        sev_counts[label] = sev_counts.get(label, 0) + 1

        category = item.get(
            "category",
            item.get("tags", ["unknown"])[0] if item.get("tags") else "unknown",
        )
        category_counts[category] = category_counts.get(category, 0) + 1

    top_categories = sorted(category_counts.items(), key=lambda x: x[1], reverse=True)[:5]

    # Count OWASP categories from tags
    owasp_counts: dict[str, int] = {}
    for item in evidence:
        for tag in item.get("tags", []):
            if isinstance(tag, str) and tag.startswith("owasp:"):
                owasp_counts[tag] = owasp_counts.get(tag, 0) + 1

    top_owasp = sorted(owasp_counts.items(), key=lambda x: x[1], reverse=True)[:5]

    return {
        "severity_distribution": sev_counts,
        "top_categories": [{"id": k, "count": v} for k, v in top_categories],
        "top_owasp_categories": [{"id": k, "count": v} for k, v in top_owasp],
        "total_evidence": len(evidence),
        "high_or_critical": sev_counts["Critical"] + sev_counts["High"],
    }


def classify_owasp(
    summary: str,
    tags: list[str],
    source_tool: str = "",
) -> list[str]:
    result = classify_vulnerability(
        summary=summary,
        tags=tags,
        source_tool=source_tool,
    )
    return result.get("tags", [])


def owasp_label(owasp_id: str) -> str:
    if owasp_id.startswith("owasp:"):
        id_part = owasp_id[6:]
        name = _OWL_LABELS.get(id_part)
        if name:
            return f"{id_part} - {name}"
        return owasp_id
    return owasp_id


def remediation_for_owasp(owasp_id: str) -> list[str]:
    """Generic remediation by OWASP ID — no longer used as primary flow."""
    generic = {
        "A01:2021": ["Implement least privilege", "Use RBAC", "Deny by default"],
        "A02:2021": ["Use strong encryption", "Rotate keys regularly", "Use HSMs"],
        "A03:2021": ["Use parameterized queries", "Validate all inputs", "Use ORM"],
        "A04:2021": ["Threat model features", "Apply secure design patterns"],
        "A05:2021": ["Disable unnecessary features", "Implement security headers"],
        "A06:2021": ["Update components regularly", "Remove unused dependencies"],
        "A07:2021": ["Implement MFA", "Strong password policies", "Rate limiting"],
        "A08:2021": ["Verify integrity of updates", "Use digital signatures"],
        "A09:2021": ["Implement comprehensive logging", "Monitor for anomalies"],
        "A10:2021": ["Validate URLs", "Allowlist external access", "Network controls"],
    }
    if owasp_id.startswith("owasp:"):
        id_part = owasp_id[6:]
        return generic.get(id_part, [])
    return []


def cwe_for_owasp(owasp_id: str) -> list[str]:
    """Return CWE IDs associated with an OWASP category as formatted strings."""
    cwe_map = {
        "A01:2021": [22, 59, 73, 913],
        "A02:2021": [259, 261, 266, 319, 326, 327],
        "A03:2021": [74, 78, 79, 89, 434, 502],
        "A04:2021": [209, 256, 319, 326, 327, 330],
        "A05:2021": [2, 11, 13, 15, 16, 22],
        "A06:2021": [1021, 1035, 1100],
        "A07:2021": [287, 288, 290, 294, 295, 307, 384, 521],
        "A08:2021": [345, 347, 353, 426, 494, 502],
        "A09:2021": [117, 532, 778],
        "A10:2021": [918],
    }
    if owasp_id.startswith("owasp:"):
        id_part = owasp_id[6:]
        return [f"CWE-{cwe}" for cwe in cwe_map.get(id_part, [])]
    return []


def severity_for_evidence(
    summary: str,
    tags: list[str],
    confidence: float,
    source_tool: str = "",
) -> int:
    result = classify_vulnerability(
        summary=summary,
        tags=tags,
        source_tool=source_tool,
        evidence={"confidence": confidence},
    )
    return result.get("severity", 1)

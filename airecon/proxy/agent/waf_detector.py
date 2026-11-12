from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger("airecon.agent.waf_detector")

_SIG_FILE = Path(__file__).parent.parent / "data" / "waf_signatures.json"

def _load_waf_signatures() -> tuple[
    dict[str, list[dict[str, Any]]],
    list[tuple[re.Pattern[str], str, float]],
    frozenset[int],
    float,
]:
    try:
        data: dict[str, Any] = json.loads(_SIG_FILE.read_text(encoding="utf-8"))

        header_index: dict[str, list[dict[str, Any]]] = {}
        for sig in data.get("header_signatures", []):
            hname = str(sig.get("header", "")).lower().strip()
            if hname:
                header_index.setdefault(hname, []).append(sig)

        body_sigs: list[tuple[re.Pattern[str], str, float]] = []
        for sig in data.get("body_signatures", []):
            pat_str = str(sig.get("pattern", "")).strip()
            if not pat_str:
                continue
            try:
                body_sigs.append((
                    re.compile(pat_str, re.IGNORECASE),
                    str(sig.get("waf", "Generic WAF")),
                    float(sig.get("confidence", 0.35)),
                ))
            except re.error as exc:
                logger.debug("Bad body regex %r in waf_signatures.json: %s", pat_str, exc)

        block_codes = frozenset(
            int(c) for c in data.get("block_status_codes", [403, 406, 429, 501, 999])
        )
        status_conf = float(data.get("status_code_confidence", 0.15))

        logger.debug(
            "WAF signatures loaded: %d header rules, %d body patterns, %d block codes",
            sum(len(v) for v in header_index.values()),
            len(body_sigs),
            len(block_codes),
        )
        return header_index, body_sigs, block_codes, status_conf

    except Exception as exc:
        logger.warning(
            "Could not load waf_signatures.json (%s) — WAF detection will be limited", exc
        )
        return {}, [], frozenset({403, 406, 429, 501, 999}), 0.15

_HEADER_SIG_INDEX: dict[str, list[dict[str, Any]]]
_BODY_SIGS: list[tuple[re.Pattern[str], str, float]]
_BLOCK_STATUS_CODES: frozenset[int]
_STATUS_CODE_CONFIDENCE: float

_HEADER_SIG_INDEX, _BODY_SIGS, _BLOCK_STATUS_CODES, _STATUS_CODE_CONFIDENCE = (
    _load_waf_signatures()
)

@dataclass
class WAFProfile:
    host: str
    waf_name: str = "Unknown"
    confidence: float = 0.0
    evidence: list[str] = field(default_factory=list)
    bypass_strategies: list[str] = field(default_factory=list)
    detected_at_iteration: int = 0

def detect_waf_from_response(
    host: str,
    status_code: int,
    headers: dict[str, str],
    body_excerpt: str,
    iteration: int = 0,
) -> WAFProfile | None:
    confidence = 0.0
    evidence: list[str] = []

    waf_scores: dict[str, float] = {}
    waf_evidence: dict[str, list[str]] = {}

    def _record_signal(waf_name: str, score: float, note: str) -> None:
        nonlocal confidence
        confidence += score
        evidence.append(note)
        waf_scores[waf_name] = waf_scores.get(waf_name, 0.0) + score
        waf_evidence.setdefault(waf_name, []).append(note)

    if status_code in _BLOCK_STATUS_CODES:
        _record_signal(
            "Generic WAF",
            _STATUS_CODE_CONFIDENCE,
            f"Block status code: {status_code}",
        )

    headers_lower = {k.lower(): v for k, v in headers.items()}
    for header_name, sigs in _HEADER_SIG_INDEX.items():
        if header_name not in headers_lower:
            continue
        header_val = headers_lower[header_name].lower()
        for sig in sigs:
            pat = str(sig.get("pattern", ""))

            if not pat or pat in header_val:
                sig_conf = float(sig.get("confidence", 0.40))
                waf = str(sig.get("waf", "Generic WAF"))
                _record_signal(
                    waf,
                    sig_conf,
                    f"Header {header_name}: {waf} (conf={sig_conf:.0%})",
                )
                break

    body_check = body_excerpt[:3000]
    for body_re, waf, sig_conf in _BODY_SIGS:
        if body_re.search(body_check):
            _record_signal(
                waf,
                sig_conf,
                f"Body signature: {waf} (conf={sig_conf:.0%})",
            )
            break

    if confidence < 0.30:
        return None

    if waf_scores:
        detected_waf = max(
            waf_scores.items(),
            key=lambda kv: (kv[1], 0 if kv[0].lower() == "generic waf" else 1),
        )[0]
    else:
        detected_waf = "Generic WAF"

    primary_evidence = waf_evidence.get(detected_waf, [])
    secondary_evidence = [e for e in evidence if e not in primary_evidence]
    ordered_evidence = primary_evidence + secondary_evidence

    return WAFProfile(
        host=host,
        waf_name=detected_waf,
        confidence=min(confidence, 1.0),
        evidence=ordered_evidence,
        detected_at_iteration=iteration,
    )

def _coerce_profile(existing: dict[str, Any] | WAFProfile | None) -> WAFProfile | None:
    if existing is None:
        return None
    if isinstance(existing, WAFProfile):
        return existing
    if not isinstance(existing, dict):
        return None
    host = str(existing.get("host", "") or "")
    waf_name = str(existing.get("waf_name", "Unknown"))
    try:
        confidence = float(existing.get("confidence", 0.0))
    except (TypeError, ValueError):
        confidence = 0.0
    evidence = existing.get("evidence", [])
    detected_at = int(existing.get("detected_at") or existing.get("detected_at_iteration") or 0)
    return WAFProfile(
        host=host,
        waf_name=waf_name,
        confidence=max(0.0, min(confidence, 1.0)),
        evidence=[str(e) for e in evidence] if isinstance(evidence, list) else [],
        detected_at_iteration=detected_at,
    )

def merge_waf_profiles(
    existing: dict[str, Any] | WAFProfile | None,
    observed: WAFProfile | None,
    *,
    host: str,
    status_code: int = 0,
    iteration: int = 0,
) -> WAFProfile | None:
    prev = _coerce_profile(existing)

    if prev is None and observed is None:
        return None

    base = observed or prev
    if base is None:
        return None
    merged = WAFProfile(
        host=host or base.host,
        waf_name=base.waf_name,
        confidence=base.confidence,
        evidence=list(base.evidence),
        detected_at_iteration=max(iteration, base.detected_at_iteration),
    )

    if prev and observed:
        merged.confidence = min(1.0, prev.confidence * 0.55 + observed.confidence * 0.75)
        merged.waf_name = observed.waf_name if observed.confidence >= prev.confidence else prev.waf_name
        merged.evidence = list(dict.fromkeys((prev.evidence + observed.evidence)))[:10]
    elif prev and not observed:
        if status_code in _BLOCK_STATUS_CODES:
            merged.confidence = min(1.0, prev.confidence + 0.05)
            merged.evidence = list(dict.fromkeys(prev.evidence + [f"Repeated block status code: {status_code}"]))[:10]
        else:
            merged.confidence = max(0.25, prev.confidence * 0.98)
            merged.evidence = prev.evidence[:10]
    elif observed and not prev:
        merged.evidence = observed.evidence[:10]

    if merged.confidence < 0.30:
        return None
    return merged

_GENERIC_BYPASS_FALLBACK: list[str] = [
    "Case variation: change SQLi keywords to mixed case (SeLeCt, UnIoN)",
    "URL encoding: double-encode special chars (%27 → %2527, ' → %252527)",
    "Whitespace substitution: use tab (\\t) or comments (/**/) instead of spaces",
    "Chunked encoding: split payloads across multiple parameters",
    "HTTP verb tampering: try POST instead of GET for injection parameters",
    "Header injection: move payload to X-Forwarded-For or User-Agent header",
]

def _load_bypass_strategies(waf_name: str) -> list[str]:
    try:
        patterns_file = Path(__file__).parent.parent / "data" / "patterns.json"
        data = json.loads(patterns_file.read_text(encoding="utf-8"))
        waf_bypasses: dict[str, Any] = data.get("waf_bypass_strategies", {})

        waf_key = waf_name.lower().replace(" ", "_")
        strategies = (
            waf_bypasses.get(waf_key)
            or waf_bypasses.get("generic")
            or []
        )
        return [str(s) for s in strategies]
    except Exception as exc:
        logger.debug("Could not load waf_bypass_strategies: %s", exc)
        return _GENERIC_BYPASS_FALLBACK

def rank_bypass_strategies(
    profile: WAFProfile,
    strategy_stats: dict[str, dict[str, int]] | None = None,
) -> list[str]:
    strategies = _load_bypass_strategies(profile.waf_name) or list(_GENERIC_BYPASS_FALLBACK)
    waf = profile.waf_name.lower()

    def _base_weight(text: str) -> float:
        t = text.lower()
        score = 1.0
        if "cloudflare" in waf and ("encoding" in t or "header" in t or "case variation" in t):
            score += 0.35
        if "modsecurity" in waf and ("comment" in t or "whitespace" in t or "case variation" in t):
            score += 0.35
        if "akamai" in waf and ("header" in t or "verb" in t):
            score += 0.25
        if "aws" in waf and ("header" in t or "chunked" in t):
            score += 0.25
        return score

    ranked: list[tuple[float, str]] = []
    stats = strategy_stats or {}
    for strategy in strategies:
        stat = stats.get(strategy, {})
        attempts = int(stat.get("attempts", 0))
        successes = int(stat.get("successes", 0))
        success_rate = (successes / attempts) if attempts > 0 else 0.5
        score = _base_weight(strategy) * (0.8 + success_rate)

        if attempts == 0:
            score += 0.1
        ranked.append((score, strategy))

    ranked.sort(key=lambda x: x[0], reverse=True)
    return [s for _, s in ranked]

def build_waf_bypass_context(profile: WAFProfile) -> str:
    if not profile or profile.confidence < 0.30:
        return ""

    strategies = profile.bypass_strategies or rank_bypass_strategies(profile)
    if not strategies:
        strategies = _GENERIC_BYPASS_FALLBACK

    lines = [
        f'<waf_bypass host="{profile.host}" waf="{profile.waf_name}" '
        f'confidence="{profile.confidence:.0%}">'
    ]
    lines.append("  <evidence>" + "; ".join(profile.evidence) + "</evidence>")
    lines.append("  <bypass_strategies>")
    for s in strategies[:8]:
        lines.append(f"    - {s}")
    lines.append("  </bypass_strategies>")
    lines.append(
        "  <instruction>WAF detected — use the bypass strategies above. "
        "Test each technique on the blocked payload before moving to the next. "
        "Record result via record_hypothesis.</instruction>"
    )
    lines.append("</waf_bypass>")
    return "\n".join(lines)

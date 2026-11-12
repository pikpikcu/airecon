from __future__ import annotations

import json
import re
from pathlib import Path
import logging
from dataclasses import dataclass, field
from urllib.parse import urlparse

logger = logging.getLogger("airecon.agent.target_prioritizer")

_ENDPOINT_PATTERNS_PATH = (
    Path(__file__).parent.parent / "data" / "endpoint_patterns.json"
)
try:
    _ENDPOINT_DATA = json.loads(_ENDPOINT_PATTERNS_PATH.read_text(encoding="utf-8"))
except Exception as e:
    logger.warning("Operation failed: %s", e)
    _ENDPOINT_DATA = {}

_URL_PATTERNS: list[tuple[re.Pattern, float, str, list[str]]] = []
for entry in _ENDPOINT_DATA.get("url_patterns", []):
    try:
        _URL_PATTERNS.append(
            (
                re.compile(entry["pattern"]),
                entry["score"],
                entry["category"],
                entry.get("attack_vectors", []),
            )
        )
    except (KeyError, re.error):
        pass

_SUBDOMAIN_PATTERNS: list[tuple[re.Pattern, float, str, list[str]]] = []
for entry in _ENDPOINT_DATA.get("subdomain_patterns", []):
    try:
        _SUBDOMAIN_PATTERNS.append(
            (
                re.compile(entry["pattern"]),
                entry["score"],
                entry["category"],
                entry.get("attack_vectors", []),
            )
        )
    except (KeyError, re.error):
        pass

_TECH_CORRELATIONS_PATH = (
    Path(__file__).parent.parent / "data" / "tech_correlations.json"
)
_TECH_RISK: dict[str, float] = {}
try:
    _TECH_CORR = json.loads(_TECH_CORRELATIONS_PATH.read_text(encoding="utf-8"))
    for tech, info in _TECH_CORR.get("technologies", {}).items():
        _TECH_RISK[tech.lower()] = info.get("risk_score", 0.5)
except Exception as e:
    logger.warning("Operation failed: %s", e)
    _TECH_RISK = {
        "wordpress": 0.75,
        "redis": 0.70,
        "elasticsearch": 0.65,
        "mongodb": 0.55,
        "grafana": 0.65,
        "kibana": 0.65,
        "jenkins": 0.75,
        "n8n": 0.60,
        "php": 0.55,
    }


@dataclass
class TargetScore:
    target: str
    score: float
    category: str = ""
    reasons: list[str] = field(default_factory=list)
    attack_vectors: list[str] = field(default_factory=list)
    tech_stack: list[str] = field(default_factory=list)
    http_status: int = 0
    is_tracking: bool = False


class TargetPrioritizer:
    def __init__(self):
        self._compiled_url_patterns = _URL_PATTERNS
        self._compiled_subdomain_patterns = _SUBDOMAIN_PATTERNS

    def score_url(
        self, url: str, tech_stack: list[str] | None = None, http_status: int = 0
    ) -> TargetScore:
        score = 0.0
        reasons: list[str] = []
        attack_vectors: list[str] = []
        is_tracking = False

        parsed = urlparse(url)
        path = parsed.path
        query = parsed.query

        for pattern, pat_score, category, vectors in self._compiled_url_patterns:
            if pattern.search(path) or pattern.search(query):
                score = max(score, pat_score)
                reasons.append(f"URL pattern: {category} (+{pat_score:.2f})")
                logger.debug(
                    "[TargetPriority] URL pattern match: category=%s score=+%.2f url=%s",
                    category,
                    pat_score,
                    url[:100],
                )
                if category not in (
                    "content_page",
                    "tracking_pixel",
                    "cloudflare_internal",
                    "feed_endpoint",
                ):
                    attack_vectors.extend(vectors)
                if category == "tracking_pixel":
                    is_tracking = True

        if tech_stack:
            tech_bonus = sum(_TECH_RISK.get(t.lower(), 0.0) for t in tech_stack)
            if tech_bonus > 0:
                tech_bonus = min(0.3, tech_bonus * 0.1)
                score += tech_bonus
                reasons.append(f"Tech risk bonus: +{tech_bonus:.2f}")

        if http_status == 200:
            score += 0.05
            reasons.append("HTTP 200 (accessible)")
        elif http_status in (301, 302, 307):
            score += 0.03
            reasons.append("Redirect (may expose auth flow)")
        elif http_status == 403:
            score += 0.10
            reasons.append("HTTP 403 (forbidden — worth bypass attempt)")
        elif http_status == 401:
            score += 0.15
            reasons.append("HTTP 401 (auth required — test for bypass)")
        elif http_status == 500:
            score += 0.10
            reasons.append("HTTP 500 (server error — potential injection)")
        elif http_status == 404:
            score -= 0.10
            reasons.append("HTTP 404 (not found)")

        if query:
            param_count = len(query.split("&"))
            score += min(0.15, param_count * 0.03)
            reasons.append(
                f"Query params: {param_count} (+{min(0.15, param_count * 0.03):.2f})"
            )
            logger.debug(
                "[TargetPriority] URL query params: %d params score=+%.2",
                param_count,
                min(0.15, param_count * 0.03),
            )

        logger.debug(
            "[TargetPriority] URL scored: %s final=%.3f reasons=%s",
            url[:80],
            round(min(1.0, max(0.0, score)), 3),
            reasons,
        )
        return TargetScore(
            target=url,
            score=round(min(1.0, max(0.0, score)), 3),
            category=reasons[0].split(": ")[-1].split(" (")[0]
            if reasons
            else "unknown",
            reasons=reasons,
            attack_vectors=attack_vectors,
            is_tracking=is_tracking,
            http_status=http_status,
        )

    def score_subdomain(
        self, subdomain: str, tech_stack: list[str] | None = None
    ) -> TargetScore:
        score = 0.0
        reasons: list[str] = []
        attack_vectors: list[str] = []

        parts = subdomain.split(".")
        subdomain_part = parts[0] if parts else subdomain

        for pattern, pat_score, category, vectors in self._compiled_subdomain_patterns:
            if pattern.search(subdomain_part):
                score = max(score, pat_score)
                reasons.append(f"Subdomain pattern: {category} (+{pat_score:.2f})")
                logger.debug(
                    "[TargetPriority] Subdomain pattern match: category=%s score=+%.2f subdomain=%s",
                    category,
                    pat_score,
                    subdomain,
                )
                attack_vectors.extend(vectors)

        if tech_stack:
            tech_bonus = sum(_TECH_RISK.get(t.lower(), 0.0) for t in tech_stack)
            if tech_bonus > 0:
                tech_bonus = min(0.3, tech_bonus * 0.1)
                score += tech_bonus
                reasons.append(f"Tech risk bonus: +{tech_bonus:.2f}")

        logger.debug(
            "[TargetPriority] Subdomain scored: %s final=%.3f reasons=%s",
            subdomain,
            round(min(1.0, max(0.0, score)), 3),
            reasons,
        )
        return TargetScore(
            target=subdomain,
            score=round(min(1.0, max(0.0, score)), 3),
            category=reasons[0].split(": ")[-1].split(" (")[0]
            if reasons
            else "unknown",
            reasons=reasons,
            attack_vectors=attack_vectors,
            tech_stack=tech_stack or [],
        )

    def prioritize_urls(
        self,
        urls: list[str],
        tech_map: dict[str, list[str]] | None = None,
        status_map: dict[str, int] | None = None,
        top_n: int = 20,
    ) -> list[TargetScore]:
        scored = []
        for url in urls:
            tech = (tech_map or {}).get(urlparse(url).netloc, [])
            status = (status_map or {}).get(url, 0)
            ts = self.score_url(url, tech_stack=tech, http_status=status)
            if not ts.is_tracking and ts.score > 0.15:
                scored.append(ts)

        scored.sort(key=lambda s: s.score, reverse=True)
        result = scored[:top_n]
        logger.info(
            "[TargetPriority] Prioritized %d URLs (from %d input), top scores: %s",
            len(result),
            len(urls),
            [(s.target[:60], s.score) for s in result[:5]],
        )
        return result

    def prioritize_subdomains(
        self,
        subdomains: list[str],
        tech_map: dict[str, list[str]] | None = None,
        top_n: int = 15,
    ) -> list[TargetScore]:
        scored = []
        for sub in subdomains:
            tech = (tech_map or {}).get(sub, [])
            ts = self.score_subdomain(sub, tech_stack=tech)
            if ts.score > 0.15:
                scored.append(ts)

        scored.sort(key=lambda s: s.score, reverse=True)
        result = scored[:top_n]
        logger.info(
            "[TargetPriority] Prioritized %d subdomains (from %d input), top scores: %s",
            len(result),
            len(subdomains),
            [(s.target, s.score) for s in result[:5]],
        )
        return result

    def generate_attack_plan(self, targets: list[TargetScore]) -> str:
        if not targets:
            return "No high-value targets identified."

        lines = [
            f"[ATTACK PLAN — {len(targets)} prioritized targets]",
            "",
        ]

        for i, ts in enumerate(targets[:10], 1):
            lines.append(f"{i}. {ts.target} (score: {ts.score:.2f})")
            if ts.reasons:
                lines.append(f"   Why: {'; '.join(ts.reasons[:2])}")
            if ts.attack_vectors:
                lines.append(f"   Vectors: {', '.join(ts.attack_vectors[:3])}")
            lines.append("")

        return "\n".join(lines)

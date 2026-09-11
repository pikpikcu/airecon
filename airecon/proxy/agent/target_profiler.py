from __future__ import annotations


import logging
import re
import time
from dataclasses import dataclass, field
from typing import Any

import httpx

from ..data_loader import load_tech_correlations

logger = logging.getLogger("airecon.agent.target_profiler")

# ── Technology Signatures — built dynamically from tech_correlations.json ─────
_TECH_CORRELATIONS: dict[str, Any] = load_tech_correlations()

_TECH_SIGNATURES: dict[str, list[re.Pattern]] = {}
for tech_name, tech_data in _TECH_CORRELATIONS.items():
    patterns: list[re.Pattern] = []
    # Build patterns from tech name itself
    patterns.append(re.compile(re.escape(tech_name), re.IGNORECASE))
    # Add patterns from known paths
    for path in tech_data.get("paths", []):
        if path and path != "/":
            patterns.append(re.compile(re.escape(path), re.IGNORECASE))
    _TECH_SIGNATURES[tech_name] = patterns

# ── Security Header Checks ──────────────────────────────────────────────────
_SECURITY_HEADERS: dict[str, str] = {
    "strict-transport-security": "HSTS not configured — vulnerable to MITM attacks that can intercept and modify traffic in transit",
    "content-security-policy": "CSP not configured — vulnerable to XSS, data injection, and clickjacking attacks via uncontrolled resource loading",
    "x-content-type-options": "X-Content-Type-Options missing — MIME type sniffing allows browsers to interpret files as different content types, enabling drive-by downloads",
    "x-frame-options": "X-Frame-Options missing — clickjacking attacks can trick users into interacting with hidden UI elements on the target site",
    "x-xss-protection": "X-XSS-Protection missing — legacy browser XSS filter is disabled, though modern browsers rely on CSP instead",
    "referrer-policy": "Referrer-Policy missing — sensitive URL information including tokens and internal paths may leak to third-party sites via Referer header",
    "permissions-policy": "Permissions-Policy missing — browser features like camera, microphone, geolocation, and payment APIs remain unrestricted and potentially exploitable",
    "cache-control": "Cache-Control missing — sensitive data, authentication tokens, and private responses may be cached by intermediaries or shared browsers",
}

# ── Security Posture Scoring ─────────────────────────────────────────────────
_SECURITY_WEIGHTS: dict[str, float] = {
    "missing_security_headers": 0.15,
    "outdated_technology": 0.20,
    "exposed_services": 0.25,
    "weak_auth_indicators": 0.15,
    "information_disclosure": 0.10,
    "known_vuln_tech": 0.15,
}


@dataclass
class TechFingerprint:
    """Detected technology with confidence."""

    name: str
    version: str = ""
    confidence: float = 0.0
    evidence: str = ""


@dataclass
class SecurityFinding:
    """Security posture finding."""

    category: str
    severity: str  # critical, high, medium, low, info
    title: str
    description: str
    evidence: str = ""
    cvss_estimate: float = 0.0


@dataclass
class TargetProfile:
    """Complete target profile."""

    target_url: str
    profiled_at: float = 0.0
    technologies: list[TechFingerprint] = field(default_factory=list)
    security_findings: list[SecurityFinding] = field(default_factory=list)
    security_score: float = 0.0  # 0-100, lower = worse
    risk_level: str = "unknown"  # critical, high, medium, low
    attack_surface: dict[str, Any] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    status_code: int = 0
    response_time_ms: float = 0.0
    server_info: str = ""
    cookies: list[str] = field(default_factory=list)
    endpoints_discovered: list[str] = field(default_factory=list)
    parameters_discovered: list[str] = field(default_factory=list)
    notes: str = ""


class TargetProfiler:
    """Intelligent target profiling engine."""

    def __init__(self, timeout: int = 15):
        self.timeout = timeout
        self.profiles: dict[str, TargetProfile] = {}

    async def profile_target(
        self, url: str, headers: dict | None = None
    ) -> TargetProfile:
        """Create a comprehensive profile of the target."""
        logger.info("[TargetProfile] Starting profiling of %s", url)
        profile = TargetProfile(target_url=url, profiled_at=time.time())

        try:
            async with httpx.AsyncClient(
                timeout=self.timeout,
                follow_redirects=True,
                verify=False,  # nosec B501 — intentional for pentesting
            ) as client:
                resp = await client.get(url, headers=headers or {})
                profile.status_code = resp.status_code
                profile.headers = dict(resp.headers)
                profile.response_time_ms = resp.extensions.get(
                    "airecon_request_ms", 0.0
                )
                profile.server_info = resp.headers.get("Server", "")
                profile.cookies = list(resp.cookies.keys())

                # Detect technologies
                profile.technologies = self._detect_technologies(resp)

                # Assess security posture
                profile.security_findings = self._assess_security_posture(resp)

                # Calculate security score
                profile.security_score = self._calculate_security_score(
                    profile.security_findings
                )

                # Determine risk level
                profile.risk_level = self._determine_risk_level(
                    profile.security_score, profile.technologies
                )

                # Map attack surface
                profile.attack_surface = self._map_attack_surface(
                    profile.technologies, profile.headers
                )

        except Exception as e:
            logger.warning(f"Target profiling error for {url}: {e}")
            profile.notes = f"Profiling error: {e}"

        self.profiles[url] = profile
        logger.info(
            "[TargetProfile] Profiling complete for %s: score=%.1f risk=%s techs=%d findings=%d",
            url,
            profile.security_score,
            profile.risk_level,
            len(profile.technologies),
            len(profile.security_findings),
        )
        return profile

    def _detect_technologies(self, resp: httpx.Response) -> list[TechFingerprint]:
        """Detect technologies from response headers and body."""
        detected: list[TechFingerprint] = []
        combined = (
            resp.headers.get("Server", "")
            + "\n"
            + resp.headers.get("X-Powered-By", "")
            + "\n"
            + resp.text[:10000]
        )

        for tech_name, patterns in _TECH_SIGNATURES.items():
            for pattern in patterns:
                match = pattern.search(combined)
                if match:
                    # Try to extract version
                    version_match = re.search(
                        rf"{tech_name}[/\s]([\d.]+)", combined, re.IGNORECASE
                    )
                    version = version_match.group(1) if version_match else ""

                    detected.append(
                        TechFingerprint(
                            name=tech_name,
                            version=version,
                            confidence=0.85 if version else 0.70,
                            evidence=f"Pattern match: {match.group()}",
                        )
                    )
                    logger.debug(
                        "[TargetProfile] Detected technology: %s version=%s confidence=%.2f evidence=%s",
                        tech_name,
                        version,
                        0.85 if version else 0.70,
                        match.group(),
                    )
                    break

        # Check for specific tech indicators
        if resp.headers.get("X-Generator"):
            detected.append(
                TechFingerprint(
                    name="cms",
                    version="",
                    confidence=0.60,
                    evidence=f"X-Generator: {resp.headers['X-Generator']}",
                )
            )
            logger.debug(
                "[TargetProfile] Detected CMS via X-Generator: %s",
                resp.headers["X-Generator"],
            )

        logger.debug(
            "[TargetProfile] Technology detection complete: %d technologies found: %s",
            len(detected),
            [t.name for t in detected],
        )
        return detected

    def _assess_security_posture(self, resp: httpx.Response) -> list[SecurityFinding]:
        """Assess security posture from response."""
        findings: list[SecurityFinding] = []
        headers_lower = {k.lower(): v for k, v in resp.headers.items()}

        # Check missing security headers
        for header, description in _SECURITY_HEADERS.items():
            if header not in headers_lower:
                findings.append(
                    SecurityFinding(
                        category="missing_security_headers",
                        severity="medium",
                        title=f"Missing {header} header",
                        description=description,
                    )
                )
                logger.debug(
                    "[TargetProfile] Security finding: Missing %s header", header
                )

        # Check for information disclosure
        if "X-Powered-By" in resp.headers:
            findings.append(
                SecurityFinding(
                    category="information_disclosure",
                    severity="low",
                    title="Technology disclosure via X-Powered-By",
                    description=f"Server reveals technology: {resp.headers['X-Powered-By']}",
                    evidence=resp.headers["X-Powered-By"],
                )
            )
            logger.debug(
                "[TargetProfile] Security finding: Technology disclosure via X-Powered-By: %s",
                resp.headers["X-Powered-By"],
            )

        # Check for verbose error messages
        if resp.status_code >= 400:
            error_indicators = [
                "stack trace",
                "traceback",
                "exception",
                "error details",
                "debug",
            ]
            body_lower = resp.text.lower()
            if any(ind in body_lower for ind in error_indicators):
                findings.append(
                    SecurityFinding(
                        category="information_disclosure",
                        severity="high",
                        title="Verbose error messages",
                        description="Server returns detailed error information that may reveal internal architecture",
                        evidence=resp.text[:500],
                    )
                )
                logger.debug(
                    "[TargetProfile] Security finding: Verbose error messages detected"
                )

        # Check for insecure cookies
        for cookie_name in resp.cookies:
            cookie_lower = cookie_name.lower()
            if "session" in cookie_lower or "token" in cookie_lower:
                if "; secure" not in headers_lower.get("set-cookie", "").lower():
                    findings.append(
                        SecurityFinding(
                            category="weak_auth_indicators",
                            severity="medium",
                            title=f"Insecure cookie: {cookie_name}",
                            description="Session cookie without Secure flag",
                        )
                    )
                    logger.debug(
                        "[TargetProfile] Security finding: Insecure cookie %s",
                        cookie_name,
                    )

        # Check for CORS misconfiguration
        acao = headers_lower.get("access-control-allow-origin", "")
        if acao == "*":
            findings.append(
                SecurityFinding(
                    category="exposed_services",
                    severity="medium",
                    title="Wildcard CORS policy",
                    description="Access-Control-Allow-Origin: * allows any origin",
                )
            )
            logger.debug("[TargetProfile] Security finding: Wildcard CORS policy")

        logger.debug(
            "[TargetProfile] Security assessment complete: %d findings",
            len(findings),
        )
        return findings

    def _calculate_security_score(self, findings: list[SecurityFinding]) -> float:
        """Calculate security score (0-100, lower = worse)."""
        if not findings:
            logger.debug("[TargetProfile] Security score: 100.0 (no findings)")
            return 100.0

        severity_scores = {
            "critical": 20,
            "high": 15,
            "medium": 8,
            "low": 3,
            "info": 1,
        }

        total_penalty = sum(severity_scores.get(f.severity, 0) for f in findings)
        score = max(0.0, min(100.0, 100.0 - total_penalty))
        logger.debug(
            "[TargetProfile] Security score breakdown: penalty=%d final=%.1f findings_by_severity=%s",
            total_penalty,
            score,
            {
                sev: sum(1 for f in findings if f.severity == sev)
                for sev in severity_scores
            },
        )
        return score

    def _determine_risk_level(
        self, security_score: float, technologies: list[TechFingerprint]
    ) -> str:
        """Determine overall risk level."""
        if security_score < 30:
            return "critical"
        elif security_score < 50:
            return "high"
        elif security_score < 70:
            return "medium"
        return "low"

    def _map_attack_surface(
        self, technologies: list[TechFingerprint], headers: dict
    ) -> dict[str, Any]:
        """Map attack surface based on detected technologies from tech_correlations.json."""
        surface: dict[str, Any] = {
            "web_framework": [],
            "database": [],
            "cloud_provider": [],
            "cdn_waf": [],
            "cms": [],
            "attack_vectors": [],
        }

        for tech in technologies:
            name = tech.name.lower()
            category = _TECH_CORRELATIONS.get(name, {}).get("category", "")
            if category == "framework":
                surface["web_framework"].append(tech.name)
            elif category == "database":
                surface["database"].append(tech.name)
            elif category == "cloud":
                surface["cloud_provider"].append(tech.name)
            elif category == "cdn_waf":
                surface["cdn_waf"].append(tech.name)
            elif category == "cms":
                surface["cms"].append(tech.name)

        # Suggest attack vectors based on tech stack from tech_correlations.json
        for tech in technologies:
            tech_lower = tech.name.lower()
            if tech_lower in _TECH_CORRELATIONS:
                vulns = _TECH_CORRELATIONS[tech_lower].get("vulns", [])
                for vuln in vulns:
                    vuln_lower = vuln.lower()
                    if "rce" in vuln_lower or "command execution" in vuln_lower:
                        surface["attack_vectors"].append(f"rce_via_{tech_lower}")
                    elif "sql injection" in vuln_lower or "sqli" in vuln_lower:
                        surface["attack_vectors"].append(
                            f"sql_injection_via_{tech_lower}"
                        )
                    elif "xss" in vuln_lower:
                        surface["attack_vectors"].append(f"xss_via_{tech_lower}")
                    elif "ssrf" in vuln_lower:
                        surface["attack_vectors"].append(f"ssrf_via_{tech_lower}")
                    elif (
                        "lfi" in vuln_lower
                        or "file read" in vuln_lower
                        or "file disclosure" in vuln_lower
                    ):
                        surface["attack_vectors"].append(f"lfi_via_{tech_lower}")
                    elif (
                        "unauthenticated" in vuln_lower
                        or "default credential" in vuln_lower
                    ):
                        surface["attack_vectors"].append(
                            f"unauthenticated_access_{tech_lower}"
                        )
                    elif (
                        "auth bypass" in vuln_lower
                        or "authorization bypass" in vuln_lower
                    ):
                        surface["attack_vectors"].append(f"auth_bypass_{tech_lower}")
                    elif "deserialization" in vuln_lower:
                        surface["attack_vectors"].append(
                            f"deserialization_{tech_lower}"
                        )
                    elif "information disclosure" in vuln_lower:
                        surface["attack_vectors"].append(
                            f"info_disclosure_{tech_lower}"
                        )

        surface["attack_vectors"] = list(set(surface["attack_vectors"]))

        logger.debug(
            "[TargetProfile] Attack surface mapped: frameworks=%s db=%s cloud=%s cdn_waf=%s cms=%s vectors=%s",
            surface["web_framework"],
            surface["database"],
            surface["cloud_provider"],
            surface["cdn_waf"],
            surface["cms"],
            surface["attack_vectors"],
        )
        return surface

    def get_profile(self, url: str) -> TargetProfile | None:
        """Get cached profile for a URL."""
        return self.profiles.get(url)

    def get_attack_recommendations(self, profile: TargetProfile) -> list[str]:
        """Generate attack recommendations based on profile and tech_correlations.json."""
        recommendations: list[str] = []
        _tech_names = [t.name.lower() for t in profile.technologies]

        # Tech-specific recommendations from tech_correlations.json
        for tech_name in _tech_names:
            if tech_name in _TECH_CORRELATIONS:
                tech_data = _TECH_CORRELATIONS[tech_name]
                tools = tech_data.get("tools", [])
                paths = tech_data.get("paths", [])
                vulns = tech_data.get("vulns", [])
                if tools:
                    recommendations.append(
                        f"Recommended tools for {tech_name}: {', '.join(tools)}"
                    )
                if paths:
                    recommendations.append(
                        f"Check {tech_name} paths: {', '.join(paths)}"
                    )
                if vulns:
                    recommendations.append(
                        f"Known {tech_name} issues: {', '.join(vulns[:5])}"
                    )

        # Security finding-based recommendations
        for finding in profile.security_findings:
            if finding.severity in ("critical", "high"):
                recommendations.append(
                    f"Priority: {finding.title} — {finding.description}"
                )

        return recommendations

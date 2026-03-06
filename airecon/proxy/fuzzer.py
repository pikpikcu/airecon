"""Fuzzing Engine for Zero-Day Discovery

This module provides intelligent fuzzing capabilities to discover:
- Unknown vulnerabilities
- Business logic flaws
- Race conditions
- Parameter pollution
- Mass assignment
- Improper input validation

Engines provided:
- Fuzzer: Core HTTP fuzzing engine (httpx-backed, concurrent)
- MutationEngine: Creative payload mutation
- ExpertHeuristics: Expert intuition heuristics + differential analysis
- ExploitChainEngine: Creative exploit chaining for compounded impact
- InteractiveRealTimeTester: Real-time streaming interactive testing mode
"""

from __future__ import annotations
from pathlib import Path
import json

import asyncio
import logging
import math
import time
from dataclasses import dataclass, field
from typing import Any, AsyncIterator, Callable
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import httpx

logger = logging.getLogger("airecon.fuzzer")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------


_data_file = Path(__file__).parent / "data" / "fuzzer_data.json"
try:
    with open(_data_file, "r") as f:
        _fuzzer_data = json.load(f)
except FileNotFoundError:
    logger.warning(
        f"AIRecon fuzzer data file not found at {_data_file}. Fuzzer will be disabled. "
        "Ensure the package is installed correctly (pip install -e .)."
    )
    _fuzzer_data = {}
except json.JSONDecodeError as e:
    logger.warning(
        f"AIRecon fuzzer data file is corrupted at {_data_file}: {e}. Fuzzer will be disabled."
    )
    _fuzzer_data = {}

FUZZ_POINTS = _fuzzer_data.get("FUZZ_POINTS", [])
FUZZ_PAYLOADS = _fuzzer_data.get("FUZZ_PAYLOADS", {})
VULNERABLE_PATTERNS = _fuzzer_data.get("VULNERABLE_PATTERNS", {})
WAF_SIGNATURES = _fuzzer_data.get("WAF_SIGNATURES", {})
CHAIN_RULES = _fuzzer_data.get("CHAIN_RULES", {})
CHAIN_PAYLOADS = _fuzzer_data.get("CHAIN_PAYLOADS", {})
# Fallback order (low → high) used when not present in fuzzer_data.json.
# Index 0 = lowest priority in sort key (-index), so CRITICAL must be last.
_SEVERITY_ORDER: list[str] = _fuzzer_data.get(
    "_SEVERITY_ORDER",
    ["info", "low", "medium", "high", "critical"],
)

# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass
class FuzzResult:
    """Result of a single fuzzing test."""

    target: str
    parameter: str
    payload: str
    vuln_type: str
    severity: str
    evidence: str
    confidence: float      # 0-1
    response_code: int
    response_length: int
    time_ms: float


@dataclass
class ChainLink:
    """Single step in an exploit chain."""

    vuln_type: str
    parameter: str
    payload: str
    prerequisite: str | None       # vuln_type that enabled this step
    impact_description: str
    confidence: float


@dataclass
class ExploitChain:
    """A chain of exploits with compounded impact."""

    name: str
    trigger_vuln: str              # First vulnerability that started the chain
    steps: list[ChainLink]
    total_confidence: float        # Geometric mean of step confidences
    combined_severity: str         # Escalated severity
    narrative: str                 # Human-readable attack story


@dataclass
class RealTimeEvent:
    """Event emitted during real-time fuzzing."""

    # "finding", "progress", "chain_discovered", "complete", "error"
    event_type: str
    data: dict[str, Any]
    timestamp: float = field(default_factory=time.monotonic)


@dataclass
class ExpertGuidance:
    """Expert-level guidance for testing."""

    recommendation: str
    reason: str
    priority: str                  # critical, high, medium, low
    tools_suggested: list[str]
    confidence: float


# ---------------------------------------------------------------------------
# Fuzzer — core HTTP fuzzing engine
# ---------------------------------------------------------------------------

class Fuzzer:
    """Intelligent HTTP fuzzer for vulnerability discovery.

    Uses httpx.AsyncClient for real HTTP requests and asyncio.Semaphore
    for concurrency control.
    """

    def __init__(
        self,
        target: str,
        wordlist: list[str] | None = None,
        threads: int = 10,
        timeout: int = 30,
        method: str = "GET",
    ):
        self.target = target
        self.wordlist = wordlist or FUZZ_POINTS
        self.threads = threads
        self.timeout = timeout
        self.method = method.upper()
        self.results: list[FuzzResult] = []
        self._baseline: dict[str, dict[str, Any]] = {}  # param → baseline data
        self._semaphore = asyncio.Semaphore(threads)

    async def _fetch_baseline(self, param: str) -> dict[str, Any]:
        """Fetch baseline response for a parameter with a benign value."""
        if param in self._baseline:
            return self._baseline[param]
        try:
            async with httpx.AsyncClient(
                timeout=self.timeout, verify=False, follow_redirects=True  # nosec B501 - security testing tool
            ) as client:
                t0 = time.monotonic()
                if self.method == "GET":
                    parsed = urlparse(self.target)
                    params = parse_qs(parsed.query)
                    params[param] = ["test"]
                    url = urlunparse(
                        parsed._replace(
                            query=urlencode(
                                params, doseq=True)))
                    resp = await client.get(url)
                else:
                    resp = await client.post(self.target, data={param: "test"})
                elapsed = (time.monotonic() - t0) * 1000
                baseline = {
                    "body": resp.text,
                    "status": resp.status_code,
                    "time_ms": elapsed,
                    "length": len(resp.text),
                }
                self._baseline[param] = baseline
                return baseline
        except Exception as exc:
            logger.debug(f"Baseline fetch failed for param={param}: {exc}")
            return {"body": "", "status": 200, "time_ms": 0.0, "length": 0}

    async def fuzz_parameters(
        self,
        params: list[str],
        vuln_types: list[str] | None = None,
    ) -> list[FuzzResult]:
        """Fuzz multiple parameters concurrently."""
        if not FUZZ_PAYLOADS:
            logger.error(
                "Fuzzer payload data is empty — fuzzer_data.json was not loaded. "
                "No fuzzing will be performed. Check package installation."
            )
            return []

        vuln_types = vuln_types or list(FUZZ_PAYLOADS.keys())

        # Build baseline for each param first
        baseline_tasks = [self._fetch_baseline(p) for p in params]
        await asyncio.gather(*baseline_tasks, return_exceptions=True)

        # Build all (param, payload, vuln_type) combos
        tasks = []
        for param in params:
            for vuln_type in vuln_types:
                for payload in FUZZ_PAYLOADS.get(vuln_type, []):
                    tasks.append(self._fuzz_single(param, payload, vuln_type))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for r in results:
            if isinstance(r, FuzzResult) and r.confidence > 0.6:
                self.results.append(r)

        return self.results

    async def _fuzz_single(
        self,
        param: str,
        payload: str,
        vuln_type: str,
    ) -> FuzzResult | None:
        """Fuzz a single parameter with a single payload."""
        async with self._semaphore:
            baseline = self._baseline.get(param, {
                "body": "", "status": 200, "time_ms": 100.0, "length": 0
            })
            try:
                async with httpx.AsyncClient(
                    timeout=self.timeout, verify=False, follow_redirects=True  # nosec B501 - security testing tool
                ) as client:
                    t0 = time.monotonic()
                    if self.method == "GET":
                        parsed = urlparse(self.target)
                        params = parse_qs(parsed.query)
                        params[param] = [payload]
                        url = urlunparse(
                            parsed._replace(
                                query=urlencode(
                                    params, doseq=True)))
                        resp = await client.get(url)
                    else:
                        resp = await client.post(self.target, data={param: payload})
                    elapsed = (time.monotonic() - t0) * 1000

                analysis = ExpertHeuristics.analyze_response_differential(
                    baseline_body=baseline["body"],
                    baseline_status=baseline["status"],
                    baseline_time_ms=baseline["time_ms"],
                    fuzz_body=resp.text,
                    fuzz_status=resp.status_code,
                    fuzz_time_ms=elapsed,
                    payload=payload,
                    vuln_type=vuln_type,
                )

                if analysis["vuln_confirmed"] or analysis["confidence"] > 0.5:
                    return FuzzResult(
                        target=self.target,
                        parameter=param,
                        payload=payload,
                        vuln_type=analysis.get("vuln_type", vuln_type),
                        severity=_confidence_to_severity(
                            analysis["confidence"]),
                        evidence="; ".join(analysis["evidence"][:3]),
                        confidence=analysis["confidence"],
                        response_code=resp.status_code,
                        response_length=len(resp.text),
                        time_ms=elapsed,
                    )
            except httpx.TimeoutException:
                # Timeout itself can indicate time-based injection
                if vuln_type in ("sql_injection", "ssti", "command_injection"):
                    return FuzzResult(
                        target=self.target,
                        parameter=param,
                        payload=payload,
                        vuln_type=f"time_based_{vuln_type}",
                        severity="high",
                        evidence="Request timed out — possible time-based injection",
                        confidence=0.65,
                        response_code=0,
                        response_length=0,
                        time_ms=self.timeout * 1000.0,
                    )
            except Exception as exc:
                logger.debug(
                    f"Fuzz request error param={param} payload={
                        payload!r}: {exc}")
        return None

    def get_high_priority_targets(self) -> list[str]:
        """Get high-priority parameters based on heuristics (deduplicated)."""
        priority: list[str] = []
        seen: set[str] = set()

        categories = [
            ["password", "token", "auth", "session"],
            ["_id", "uid", "user_id", "order_id", "account_id"],
            ["file", "path", "template"],
            ["price", "amount", "discount", "coupon"],
        ]

        for category_keywords in categories:
            for p in self.wordlist:
                if p not in seen and any(x in p.lower()
                                         for x in category_keywords):
                    priority.append(p)
                    seen.add(p)

        return priority


# ---------------------------------------------------------------------------
# MutationEngine
# ---------------------------------------------------------------------------

class MutationEngine:
    """Engine for creative mutation of payloads."""

    @staticmethod
    def mutate_payload(payload: str, technique: str) -> list[str]:
        """Generate variations of a payload."""
        mutations = [payload]

        if technique == "encoding":
            mutations.append(payload.replace("/", "%2F"))
            mutations.append(payload.replace(" ", "%20"))
            mutations.append(payload.replace("'", "%27"))
            mutations.append(payload.replace('"', "%22"))
            # Double encoding
            mutations.append(payload.replace("/", "%252F"))

        elif technique == "case":
            mutations.append(payload.upper())
            mutations.append(payload.lower())
            mutations.append(payload.capitalize())
            # Mixed case for WAF bypass
            mutations.append("".join(
                c.upper() if i % 2 == 0 else c.lower()
                for i, c in enumerate(payload)
            ))

        elif technique == "comment":
            if " " in payload:
                base = payload.split()[0]
                mutations.append(f"{base}--")
                mutations.append(f"{base}#")
                mutations.append(f"{base}/*")
                mutations.append(f"{base}/*!*/")

        elif technique == "padding":
            mutations.append(f"{payload} " * 5)
            mutations.append(f"{payload}\n" * 3)
            mutations.append(f"{payload}\t" * 3)

        elif technique == "nullbyte":
            mutations.append(f"{payload}%00")
            mutations.append(f"{payload}\x00")
            mutations.append(f"{payload}%00.jpg")
            mutations.append(f"{payload}\x00.png")

        elif technique == "unicode":
            mutations.append(payload.replace("'", "\u02bc"))
            mutations.append(payload.replace("<", "\uff1c"))
            mutations.append(payload.replace(">", "\uff1e"))

        return mutations

    @staticmethod
    def generate_wordlist_combinations(
        base_words: list[str],
        max_size: int = 500,
    ) -> list[str]:
        """Generate parameter name mutations (capped to avoid memory issues).

        Generates variants useful for parameter discovery and bypass attempts:
        - Privilege escalation suffixes (admin, root, superuser, privileged)
        - Environment suffixes (dev, debug, staging, backup, internal)
        - Common API/auth key suffixes (_id, _key, _token, _secret, _hash)
        - Numeric suffixes (1, 2, 0, null, true, false, undefined)
        - camelCase and snake_case variants
        - Two-word combinations with _ and - separators
        """
        # Suffixes grouped by purpose (ordered: high-value first)
        _PRIVILEGE_SUFFIXES = [
            "admin", "root", "superuser", "administrator", "super",
            "owner", "master", "privileged", "god", "system",
        ]
        _ENV_SUFFIXES = [
            "test", "dev", "debug", "staging", "prod", "local",
            "backup", "old", "new", "temp", "tmp", "internal", "hidden",
        ]
        _NUMERIC_SUFFIXES = [
            "1", "2", "0", "01", "123", "1234", "12345", "0x1",
            "null", "none", "true", "false", "undefined", "empty",
        ]
        _KEY_SUFFIXES = [
            "_id", "_key", "_token", "_secret", "_hash", "_code",
            "_api", "_flag", "_data", "_info", "_val", "_value",
            "_param", "_field", "_attr",
        ]
        _DEMO_SUFFIXES = ["demo", "sample", "example", "mock", "dummy", "fake"]

        seen: set[str] = set()
        combinations: list[str] = []

        def _add(item: str) -> bool:
            """Add item if not duplicate. Returns False when cap reached."""
            if item not in seen:
                seen.add(item)
                combinations.append(item)
            return len(combinations) < max_size

        # 1. Privilege + env suffixes — highest value for bypass/enumeration
        for suffix in _PRIVILEGE_SUFFIXES + _ENV_SUFFIXES + _DEMO_SUFFIXES:
            for word in base_words:
                if not _add(f"{word}_{suffix}"):
                    return combinations
                if not _add(f"{word}{suffix}"):
                    return combinations
                if not _add(f"{suffix}_{word}"):
                    return combinations

        # 2. Key-type suffixes (already include underscore)
        for suffix in _KEY_SUFFIXES:
            for word in base_words:
                if not _add(f"{word}{suffix}"):
                    return combinations

        # 3. Numeric suffixes
        for suffix in _NUMERIC_SUFFIXES:
            for word in base_words:
                if not _add(f"{word}{suffix}"):
                    return combinations
                if not _add(f"{word}_{suffix}"):
                    return combinations

        # 4. camelCase variants (userId, adminToken, etc.)
        for word in base_words:
            for suffix in _PRIVILEGE_SUFFIXES[:5] + \
                    ["Id", "Key", "Token", "Secret"]:
                camel = f"{word}{suffix[0].upper()}{suffix[1:]}"
                if not _add(camel):
                    return combinations

        # 5. Two-word combinations with _ and - separators
        for w1 in base_words:
            for w2 in base_words:
                if w1 != w2:
                    if not _add(f"{w1}_{w2}"):
                        return combinations
                    if not _add(f"{w1}-{w2}"):
                        return combinations

        return combinations


# ---------------------------------------------------------------------------
# ExpertHeuristics — fixed + extended with differential analysis
# ---------------------------------------------------------------------------

class ExpertHeuristics:
    """Expert-level heuristics for vulnerability discovery."""

    @staticmethod
    def analyze_response(response: str) -> dict[str, Any]:
        """Analyze a single response for vulnerability indicators.

        Fixed: no double-counting, uses specific patterns, caps per-category.
        """
        analysis: dict[str, Any] = {
            "is_vulnerable": False,
            "vuln_types": [],
            "confidence": 0.0,
            "indicators": [],
        }
        seen_vulns: set[str] = set()
        response_lower = response.lower()

        def _add(vuln: str, indicator: str, score: float) -> None:
            analysis["indicators"].append(indicator)
            analysis["confidence"] += score
            if vuln not in seen_vulns:
                analysis["vuln_types"].append(vuln)
                seen_vulns.add(vuln)

        # SQL error patterns (capped at 0.4 total for this category)
        sql_hit = False
        for pattern in VULNERABLE_PATTERNS["sql_error"]:
            if pattern in response_lower and not sql_hit:
                _add("sql_injection", f"SQL error pattern: {pattern}", 0.4)
                sql_hit = True

        # Generic server errors
        for pattern in VULNERABLE_PATTERNS["generic_error"]:
            if pattern in response_lower:
                _add("error_disclosure", f"Server error: {pattern}", 0.2)
                break  # only count once

        # Code execution indicators (separate category, no overlap with
        # sql_error)
        code_hit = False
        for pattern in VULNERABLE_PATTERNS["code_execution"]:
            if pattern in response_lower and not code_hit:
                _add("rce", f"Code execution indicator: {pattern}", 0.45)
                code_hit = True

        # Specific sensitive data (not generic words like "key", "admin")
        specific_sensitive = [
            "/etc/passwd",
            "root:x:",
            "c:\\windows\\",
            "db_password="]
        for pattern in specific_sensitive:
            if pattern in response_lower:
                _add(
                    "information_disclosure",
                    f"Sensitive data: {pattern}",
                    0.5)
                break

        analysis["confidence"] = min(analysis["confidence"], 1.0)
        analysis["is_vulnerable"] = analysis["confidence"] > 0.5
        return analysis

    @staticmethod
    def analyze_response_differential(
        baseline_body: str,
        baseline_status: int,
        baseline_time_ms: float,
        fuzz_body: str,
        fuzz_status: int,
        fuzz_time_ms: float,
        payload: str,
        vuln_type: str,
    ) -> dict[str, Any]:
        """Differential response analysis — compare fuzz vs baseline.

        Much lower false-positive rate than single-response analysis because
        differences relative to a clean baseline are the signal.
        """
        result: dict[str, Any] = {
            "vuln_confirmed": False,
            "confidence": 0.0,
            "evidence": [],
            "vuln_type": vuln_type,
        }
        confidence = 0.0
        evidence: list[str] = []

        # 1. Payload reflection — XSS/SSTI signal
        if payload and len(payload) > 3 and payload in fuzz_body:
            if payload not in baseline_body:
                confidence += 0.6
                evidence.append(
                    f"Payload reflected in response: {payload[:40]!r}")
                if any(tag in payload for tag in [
                       "<script", "<img", "<svg", "javascript:"]):
                    result["vuln_type"] = "xss"
                elif any(t in payload for t in ["{{", "${", "<%= ", "#{"]):
                    result["vuln_type"] = "ssti"

        # 2. Time-based anomaly (requires fuzz to be 3x slower + absolute >3s)
        if (
            baseline_time_ms > 0
            and fuzz_time_ms > baseline_time_ms * 3
            and fuzz_time_ms > 3000
        ):
            confidence += 0.65
            evidence.append(
                f"Time anomaly: baseline={
                    baseline_time_ms:.0f}ms fuzz={
                    fuzz_time_ms:.0f}ms"
            )
            result["vuln_type"] = f"time_based_{vuln_type}"

        # 3. Status code change
        if fuzz_status != baseline_status:
            if baseline_status == 200 and fuzz_status == 500:
                confidence += 0.4
                evidence.append(
                    "Status change 200→500 (server error on payload)")
            elif fuzz_status == 403:
                confidence += 0.1
                evidence.append("WAF/403 triggered by payload")
            elif baseline_status == 200 and fuzz_status in (301, 302):
                confidence += 0.3
                evidence.append(
                    f"Redirect triggered (possible open redirect/SSRF): {fuzz_status}")
                result["vuln_type"] = "open_redirect"

        # 4. Content length anomaly
        baseline_len = len(baseline_body)
        fuzz_len = len(fuzz_body)
        if baseline_len > 0:
            delta_ratio = (fuzz_len - baseline_len) / baseline_len
            if delta_ratio > 0.5 and fuzz_len > baseline_len + 200:
                confidence += 0.25
                evidence.append(
                    f"Response significantly larger (+{fuzz_len - baseline_len}B) — possible data leak")
            elif delta_ratio < -0.5 and baseline_len > 200:
                confidence += 0.15
                evidence.append(
                    "Response significantly smaller — possible truncation/filter")

        # 5. SQL error patterns appearing in fuzz but not baseline
        fuzz_lower = fuzz_body.lower()
        baseline_lower = baseline_body.lower()
        for pattern in VULNERABLE_PATTERNS["sql_error"]:
            if pattern in fuzz_lower and pattern not in baseline_lower:
                confidence += 0.5
                evidence.append(
                    f"SQL error in fuzz response (not in baseline): {
                        pattern!r}")
                result["vuln_type"] = "sql_injection"
                break

        # 6. Code execution patterns new in fuzz response
        for pattern in VULNERABLE_PATTERNS["code_execution"]:
            if pattern in fuzz_lower and pattern not in baseline_lower:
                confidence += 0.45
                evidence.append(
                    f"Code execution indicator (new in fuzz): {
                        pattern!r}")
                result["vuln_type"] = "rce"
                break

        # 7. /etc/passwd or win paths appearing in fuzz
        lfi_signatures = [
            "/etc/passwd",
            "root:x:",
            "c:\\windows\\",
            "[boot loader]"]
        for sig in lfi_signatures:
            if sig in fuzz_lower and sig not in baseline_lower:
                confidence += 0.8
                evidence.append(
                    f"LFI/path traversal signature in fuzz response: {sig!r}")
                result["vuln_type"] = "path_traversal"
                break

        result["confidence"] = min(confidence, 1.0)
        result["vuln_confirmed"] = result["confidence"] > 0.55
        result["evidence"] = evidence
        return result

    @staticmethod
    def get_priority_parameters(url: str, method: str = "GET") -> list[str]:
        """Get priority parameters based on URL analysis."""
        priority: list[str] = []

        if "login" in url or "signin" in url:
            priority.extend(["username", "password", "email", "token"])
        elif "profile" in url or "user" in url:
            priority.extend(["user_id", "id", "username", "email", "role"])
        elif "admin" in url:
            priority.extend(["id", "user_id", "action", "page"])
        elif "search" in url or "query" in url:
            priority.extend(["q", "query", "search", "keyword"])
        elif "api" in url:
            priority.extend(["api_key", "token", "id", "action"])
        elif "file" in url or "download" in url or "upload" in url:
            priority.extend(["file", "path", "filename", "name", "template"])
        elif "pay" in url or "checkout" in url or "order" in url:
            priority.extend(
                ["price", "amount", "quantity", "coupon", "discount"])

        return list(dict.fromkeys(priority))  # deduplicate preserving order

    @staticmethod
    def get_attack_surface_heuristics(
        url: str,
        params: dict[str, str],
        request_headers: dict[str, str],
        response_headers: dict[str, str],
    ) -> list[ExpertGuidance]:
        """Detect tech stack and return targeted attack guidance."""
        guidance: list[ExpertGuidance] = []
        resp_lower = {k.lower(): v.lower()
                      for k, v in response_headers.items()}
        req_lower = {k.lower(): v.lower() for k, v in request_headers.items()}

        server = resp_lower.get("server", "")
        powered_by = resp_lower.get("x-powered-by", "")
        generator = resp_lower.get("x-generator", "")
        auth_header = req_lower.get("authorization", "")

        # PHP detection
        if "php" in powered_by or ".php" in url:
            guidance.append(ExpertGuidance(
                recommendation="Test PHP-specific vulnerabilities: type juggling, LFI, XXE",
                reason="PHP detected via X-Powered-By or URL extension",
                priority="high",
                tools_suggested=[
                    "ffuf -e .php",
                    "wfuzz",
                    "curl with XXE payload"],
                confidence=0.85,
            ))

        # WordPress
        if "wordpress" in generator or "/wp-" in url:
            guidance.append(ExpertGuidance(
                recommendation="Run wpscan; check xmlrpc.php, wp-login.php brute force",
                reason="WordPress detected",
                priority="high",
                tools_suggested=["wpscan", "curl /xmlrpc.php"],
                confidence=0.9,
            ))

        # Apache
        if "apache" in server:
            guidance.append(ExpertGuidance(
                recommendation="Test Apache path traversal, .htaccess disclosure, mod_status",
                reason="Apache detected in Server header",
                priority="medium",
                tools_suggested=["curl /server-status", "nikto"],
                confidence=0.7,
            ))

        # Nginx
        if "nginx" in server:
            guidance.append(ExpertGuidance(
                recommendation="Test nginx alias traversal and off-by-slash misconfiguration",
                reason="Nginx detected in Server header",
                priority="medium",
                tools_suggested=[
                    "curl /static../etc/passwd",
                    "nuclei -t nginx"],
                confidence=0.7,
            ))

        # JWT in Authorization header
        if auth_header.startswith("bearer ") and auth_header.count(".") == 2:
            guidance.append(ExpertGuidance(
                recommendation="Test JWT: alg:none, weak HMAC secret, kid injection",
                reason="JWT Bearer token detected in Authorization header",
                priority="high",
                tools_suggested=["jwt_tool", "hashcat -m 16500"],
                confidence=0.8,
            ))

        # GraphQL
        if "graphql" in url or "gql" in url:
            guidance.append(ExpertGuidance(
                recommendation="Test GraphQL: introspection, batching DoS, IDOR via IDs",
                reason="GraphQL endpoint detected",
                priority="high",
                tools_suggested=["graphqlmap", "clairvoyance"],
                confidence=0.85,
            ))

        # Numeric IDs in params → IDOR
        for k, v in params.items():
            if v.isdigit() and k.lower() in ("id", "user_id", "account_id", "order_id"):
                guidance.append(ExpertGuidance(
                    recommendation=f"Test IDOR on parameter '{k}' — try adjacent IDs and negative values",
                    reason=f"Numeric ID parameter detected: {k}={v}",
                    priority="high",
                    tools_suggested=["burp intruder", "ffuf -w ids.txt"],
                    confidence=0.75,
                ))
                break

        return guidance

    @staticmethod
    def fingerprint_waf(
        response_headers: dict[str, str],
        status_code: int,
    ) -> str | None:
        """Identify WAF from response headers and status code."""
        headers_lower = {k.lower(): v.lower()
                         for k, v in response_headers.items()}

        for waf_name, sig in WAF_SIGNATURES.items():
            # Header match
            for h in sig["headers"]:
                if h in headers_lower:
                    return waf_name
            # Status code + body pattern match requires body, check status at
            # least
            if status_code in sig["status_codes"]:
                # Tentative match on status alone — caller should verify body
                # too
                for h in sig["headers"]:
                    if any(h.split("-")[0] in k for k in headers_lower):
                        return waf_name

        return None

    @staticmethod
    def suggest_next_tests(vuln_type: str) -> list[str]:
        """Suggest follow-up tests based on confirmed vulnerability type."""
        suggestions: dict[str, list[str]] = {
            "sql_injection": [
                "Try UNION-based extraction: ' UNION SELECT table_name FROM information_schema.tables--",
                "Test time-based blind: ' AND SLEEP(5)--",
                "Attempt INTO OUTFILE for webshell upload",
                "Test for second-order SQL injection in profile/update flows",
                "Use sqlmap --dbs for automated enumeration",
            ],
            "xss": [
                "Test stored XSS in all input fields",
                "Test DOM-based XSS via URL fragment (#)",
                "Try CSP bypass: base64, data URI, JSONP",
                "Attempt session hijacking via document.cookie exfil",
                "Test XSS in HTTP headers: User-Agent, Referer",
            ],
            "idor": [
                "Test horizontal privilege escalation (other users' data)",
                "Test vertical privilege escalation (admin functions)",
                "Try parameter pollution: id=1&id=2",
                "Test IDOR in file download/upload endpoints",
                "Check UUID predictability if UUIDs used",
            ],
            "ssti": [
                "Identify template engine: Jinja2/Twig/Freemarker",
                "Attempt RCE via config/os.popen",
                "Extract environment variables and secrets",
                "Try sandbox escape techniques",
            ],
            "path_traversal": [
                "Read /etc/passwd, /etc/shadow, /proc/self/environ",
                "Read application source and config files",
                "Test log poisoning for RCE",
                "Try absolute path injection: /etc/passwd",
            ],
            "xxe": [
                "Read internal files via SYSTEM entity",
                "Test SSRF via external DTD",
                "Attempt blind XXE with out-of-band DNS callback",
                "Try error-based XXE for file content extraction",
            ],
            "command_injection": [
                "Confirm RCE with: id; whoami; hostname",
                "Attempt reverse shell",
                "Enumerate internal network",
                "Check for sudo permissions",
            ],
        }
        return suggestions.get(vuln_type, [
            f"Enumerate further with {vuln_type}-specific payloads",
            "Check other endpoints for same vulnerability class",
            "Test in different HTTP methods (GET→POST→PUT)",
        ])


# ---------------------------------------------------------------------------
# ExploitChainEngine
# ---------------------------------------------------------------------------

class ExploitChainEngine:
    """Discover and chain multiple vulnerabilities for compounded impact.

    When a vulnerability is found, this engine automatically tests for
    follow-on vulnerabilities that become possible, building a narrative
    of chained exploits that significantly escalate overall severity.
    """

    def __init__(self, fuzzer: Fuzzer):
        self.fuzzer = fuzzer
        self.discovered_chains: list[ExploitChain] = []

    async def discover_chains(
        self,
        initial_findings: list[FuzzResult],
    ) -> list[ExploitChain]:
        """For each finding, test follow-on vulns and build exploit chains."""
        chains: list[ExploitChain] = []

        for finding in initial_findings:
            follow_ons = CHAIN_RULES.get(finding.vuln_type, [])
            if not follow_ons:
                continue

            steps: list[ChainLink] = []
            for chain_vuln in follow_ons:
                link = await self._test_chain_step(finding, chain_vuln)
                if link:
                    steps.append(link)

            if steps:
                chain = self._build_chain(finding, steps)
                chains.append(chain)

        self.discovered_chains = self.prioritize_chains(chains)
        return self.discovered_chains

    async def _test_chain_step(
        self,
        parent: FuzzResult,
        chain_vuln: str,
    ) -> ChainLink | None:
        """Test if a follow-on vuln is exploitable given the parent finding."""
        payloads = CHAIN_PAYLOADS.get(chain_vuln, [])
        if not payloads:
            # No HTTP test available — still record as theoretical chain step
            return ChainLink(
                vuln_type=chain_vuln,
                parameter=parent.parameter,
                payload="[theoretical — no active test payload]",
                prerequisite=parent.vuln_type,
                impact_description=_chain_impact(parent.vuln_type, chain_vuln),
                confidence=0.45,  # Theoretical confidence
            )

        for payload in payloads[:2]:  # Test at most 2 chain payloads
            result = await self.fuzzer._fuzz_single(
                parent.parameter, payload, chain_vuln
            )
            if result and result.confidence > 0.5:
                return ChainLink(
                    vuln_type=chain_vuln,
                    parameter=parent.parameter,
                    payload=payload,
                    prerequisite=parent.vuln_type,
                    impact_description=_chain_impact(
                        parent.vuln_type, chain_vuln),
                    confidence=result.confidence,
                )
        return None

    def _build_chain(
        self,
        trigger: FuzzResult,
        steps: list[ChainLink],
    ) -> ExploitChain:
        trigger_link = ChainLink(
            vuln_type=trigger.vuln_type,
            parameter=trigger.parameter,
            payload=trigger.payload,
            prerequisite=None,
            impact_description=f"Initial {trigger.vuln_type} vulnerability",
            confidence=trigger.confidence,
        )
        all_steps = [trigger_link] + steps
        severity = self._compute_chain_severity(all_steps)
        total_conf = _geometric_mean([s.confidence for s in all_steps])
        return ExploitChain(
            name=f"{
                trigger.vuln_type} → {
                ' → '.join(
                    s.vuln_type for s in steps)}",
            trigger_vuln=trigger.vuln_type,
            steps=all_steps,
            total_confidence=total_conf,
            combined_severity=severity,
            narrative=self.generate_chain_report_from_steps(
                all_steps, trigger.target),
        )

    def prioritize_chains(
            self, chains: list[ExploitChain]) -> list[ExploitChain]:
        """Sort chains by severity then confidence (highest first)."""
        _sev_lower = [s.lower() for s in _SEVERITY_ORDER]

        def _sort_key(c: ExploitChain) -> tuple[int, float]:
            sev = (c.combined_severity or "").lower()
            sev_score = _sev_lower.index(sev) if sev in _sev_lower else -1
            return (-sev_score, -c.total_confidence)

        return sorted(chains, key=_sort_key)

    def generate_chain_report(self, chain: ExploitChain) -> str:
        """Generate human-readable exploit chain narrative."""
        return self.generate_chain_report_from_steps(
            chain.steps, self.fuzzer.target)

    @staticmethod
    def generate_chain_report_from_steps(
        steps: list[ChainLink],
        target: str,
    ) -> str:
        lines = [f"Exploit Chain — Target: {target}", "=" * 60]
        for i, step in enumerate(steps, 1):
            prereq = f" (requires: {
                step.prerequisite})" if step.prerequisite else ""
            lines.append(
                f"Step {i}: [{step.vuln_type.upper()}]{prereq}\n"
                f"  Parameter : {step.parameter}\n"
                f"  Payload   : {step.payload[:80]}\n"
                f"  Impact    : {step.impact_description}\n"
                f"  Confidence: {step.confidence:.0%}"
            )
        return "\n".join(lines)

    @staticmethod
    def _compute_chain_severity(steps: list[ChainLink]) -> str:
        """Escalate severity based on chain contents."""
        critical_types = {
            "rce",
            "rce_via_outfile",
            "rce_via_log_poison",
            "reverse_shell",
            "data_exfiltration"}
        high_types = {
            "auth_bypass",
            "privilege_escalation",
            "account_takeover",
            "ssrf"}

        all_types = {s.vuln_type for s in steps}

        if all_types & critical_types:
            return "critical"
        if all_types & high_types:
            return "high"
        if len(steps) >= 3:
            return "high"  # Long chains escalate severity
        return "medium"


# ---------------------------------------------------------------------------
# InteractiveRealTimeTester
# ---------------------------------------------------------------------------

class InteractiveRealTimeTester:
    """Real-time fuzzing with live result streaming and exploit chaining.

    Wraps Fuzzer and ExploitChainEngine to emit RealTimeEvents as an
    async generator so callers can display results immediately.

    Usage:
        tester = InteractiveRealTimeTester("https://target.com/search")
        async for event in tester.stream_fuzz(params=["q", "id"]):
            if event.event_type == "finding":
                print(f"[{event.data['severity'].upper()}] {event.data['vuln_type']}")
            elif event.event_type == "chain_discovered":
                print(f"Chain: {event.data['name']}")
    """

    def __init__(
        self,
        target: str,
        threads: int = 5,
        timeout: int = 10,
        on_finding: Callable[[FuzzResult], None] | None = None,
    ):
        self.target = target
        self.fuzzer = Fuzzer(target=target, threads=threads, timeout=timeout)
        self.chain_engine = ExploitChainEngine(self.fuzzer)
        self.on_finding = on_finding
        self._stop_event = asyncio.Event()
        self._findings: list[FuzzResult] = []
        self._chains: list[ExploitChain] = []

    async def probe_baseline(self, params: list[str]) -> dict[str, Any]:
        """Fetch baseline responses for all params before fuzzing begins."""
        tasks = [self.fuzzer._fetch_baseline(p) for p in params]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return {
            p: r for p, r in zip(params, results)
            if not isinstance(r, Exception)
        }

    async def stream_fuzz(
        self,
        params: list[str] | None = None,
        vuln_types: list[str] | None = None,
    ) -> AsyncIterator[RealTimeEvent]:
        """Async generator: yields RealTimeEvents as fuzzing progresses."""
        params = params or self.fuzzer.get_high_priority_targets()[:10]
        vuln_types = vuln_types or list(FUZZ_PAYLOADS.keys())

        # Baseline phase
        yield RealTimeEvent(
            event_type="progress",
            data={"phase": "baseline", "params": params,
                  "message": "Probing baseline responses..."},
        )
        await self.probe_baseline(params)

        total = sum(len(FUZZ_PAYLOADS.get(vt, []))
                    for vt in vuln_types) * len(params)
        done = 0

        yield RealTimeEvent(
            event_type="progress",
            data={"phase": "fuzzing", "total_tests": total,
                  "message": f"Starting {total} fuzz tests..."},
        )

        # Fuzz each param/payload combo and yield findings immediately
        for param in params:
            if self._stop_event.is_set():
                break
            for vuln_type in vuln_types:
                if self._stop_event.is_set():
                    break
                for payload in FUZZ_PAYLOADS.get(vuln_type, []):
                    if self._stop_event.is_set():
                        break

                    result = await self.fuzzer._fuzz_single(param, payload, vuln_type)
                    done += 1

                    if result and result.confidence > 0.6:
                        self._findings.append(result)
                        if self.on_finding:
                            try:
                                self.on_finding(result)
                            except Exception:  # nosec B110 - callback is optional
                                pass
                        yield RealTimeEvent(
                            event_type="finding",
                            data={
                                "vuln_type": result.vuln_type,
                                "parameter": result.parameter,
                                "payload": result.payload,
                                "severity": result.severity,
                                "confidence": result.confidence,
                                "evidence": result.evidence,
                                "response_code": result.response_code,
                                "time_ms": result.time_ms,
                            },
                        )

                    # Emit progress every 20 tests
                    if done % 20 == 0:
                        yield RealTimeEvent(
                            event_type="progress",
                            data={
                                "phase": "fuzzing",
                                "done": done,
                                "total": total,
                                "findings_so_far": len(self._findings),
                                "pct": round(done / total * 100, 1) if total else 0,
                            },
                        )

        # Chain discovery phase
        if self._findings:
            yield RealTimeEvent(
                event_type="progress",
                data={
                    "phase": "chaining",
                    "message": f"Discovering exploit chains from {
                        len(
                            self._findings)} findings..."},
            )
            self._chains = await self.chain_engine.discover_chains(self._findings)
            for chain in self._chains:
                yield RealTimeEvent(
                    event_type="chain_discovered",
                    data={
                        "name": chain.name,
                        "trigger_vuln": chain.trigger_vuln,
                        "steps": len(chain.steps),
                        "severity": chain.combined_severity,
                        "confidence": chain.total_confidence,
                        "narrative": chain.narrative,
                    },
                )

        yield RealTimeEvent(
            event_type="complete",
            data=self.get_summary(),
        )

    async def stop(self) -> None:
        """Signal graceful stop."""
        self._stop_event.set()

    def get_summary(self) -> dict[str, Any]:
        """Return current findings and chains summary."""
        sev_counts: dict[str, int] = {}
        for f in self._findings:
            sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1

        return {
            "target": self.target,
            "total_findings": len(self._findings),
            "total_chains": len(self._chains),
            "severity_breakdown": sev_counts,
            "vuln_types": list({f.vuln_type for f in self._findings}),
            "chains": [
                {"name": c.name,
                 "severity": c.combined_severity,
                 "confidence": c.total_confidence}
                for c in self._chains
            ],
        }


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _confidence_to_severity(confidence: float) -> str:
    if confidence >= 0.85:
        return "critical"
    if confidence >= 0.70:
        return "high"
    if confidence >= 0.50:
        return "medium"
    if confidence >= 0.30:
        return "low"
    return "info"


def _geometric_mean(values: list[float]) -> float:
    if not values:
        return 0.0
    return math.exp(sum(math.log(max(v, 1e-9)) for v in values) / len(values))


def _chain_impact(trigger: str, follow_on: str) -> str:
    """Describe the combined impact of trigger + follow-on vuln."""
    impact_map = {
        ("xss", "csrf"): "Attacker can forge state-changing requests from victim's browser",
        ("xss", "session_hijacking"): "Attacker can steal session cookies and take over accounts",
        ("xss", "account_takeover"): "Full account takeover via scripted credential change",
        ("sql_injection", "auth_bypass"): "Attacker can log in as any user without credentials",
        ("sql_injection", "data_exfiltration"): "Full database dump including credentials possible",
        ("sql_injection", "rce_via_outfile"): "Remote code execution via SQL INTO OUTFILE webshell",
        ("idor", "privilege_escalation"): "Access admin-level functions as regular user",
        ("idor", "data_exfiltration"): "Read other users' private data at scale",
        ("ssti", "rce"): "Execute arbitrary OS commands via template injection",
        ("path_traversal", "lfi"): "Read arbitrary local files including /etc/shadow",
        ("path_traversal", "rce_via_log_poison"): "RCE via log file poisoning + path traversal",
        ("xxe", "ssrf"): "Internal network access and metadata service disclosure",
        ("xxe", "rce"): "Arbitrary file write leading to code execution",
        ("race_condition", "double_spend"): "Financial fraud — purchase items at no cost",
        ("command_injection", "rce"): "Full remote code execution on the server",
        ("command_injection", "reverse_shell"): "Interactive shell access to server",
    }
    return impact_map.get(
        (trigger, follow_on),
        f"Chained {trigger} enables {follow_on} exploitation"
    )


# ---------------------------------------------------------------------------
# Public convenience functions
# ---------------------------------------------------------------------------

async def quick_fuzz_url(
        url: str, params: list[str] | None = None) -> list[FuzzResult]:
    """Quick fuzz a URL with common payloads and return findings."""
    params = params or ["q", "search", "id", "page"]
    fuzzer = Fuzzer(url, threads=5, timeout=15)
    return await fuzzer.fuzz_parameters(
        params=params,
        vuln_types=["sql_injection", "xss", "path_traversal", "ssti"],
    )


def generate_fuzz_wordlist(
    max_combinations: int = 300,
    vuln_types: list[str] | None = None,
) -> list[str]:
    """Generate fuzzing wordlist combining exploit payloads + parameter name mutations.

    Priority order:
    1. Exploit payloads from FUZZ_PAYLOADS (SQLi, XSS, SSTI, SSRF, etc.) — always included first
    2. FUZZ_POINTS parameter names (for parameter discovery mode)
    3. MutationEngine suffix/combination variants (capped to max_combinations)

    Args:
        max_combinations: Cap on parameter name mutation variants (default 300, max 1000).
        vuln_types: Filter payload categories (e.g. ["sql_injection", "xss"]).
                    None = include all categories.
    """
    all_payloads: dict[str, list[str]] = _fuzzer_data.get("FUZZ_PAYLOADS", {})
    categories = vuln_types if vuln_types else list(all_payloads.keys())

    seen: set[str] = set()
    result: list[str] = []

    def _add(item: str) -> None:
        if item not in seen:
            seen.add(item)
            result.append(item)

    # 1. Exploit payloads first — these are the most valuable entries
    for cat in categories:
        for payload in all_payloads.get(cat, []):
            _add(payload)

    # 2. Parameter names for discovery mode (ffuf -u url?FUZZ=value)
    for param in FUZZ_POINTS:
        _add(param)

    # 3. Mutation combinations (capped)
    for combo in MutationEngine.generate_wordlist_combinations(
        FUZZ_POINTS, max_size=max_combinations
    ):
        _add(combo)

    return result

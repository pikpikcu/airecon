from __future__ import annotations

import hashlib
import logging
import re
import time
from dataclasses import dataclass, field
from typing import Any

import httpx

from ..data_loader import (
    load_fuzzer_data,
    load_verification_patterns,
    load_waf_signatures,
)

logger = logging.getLogger("airecon.agent.verification")

# ── Load verification patterns from data file (single source of truth) ────────
_VERIFICATION_DATA = load_verification_patterns()

_CLEAN_RESPONSE_PATTERNS: list[re.Pattern] = [
    re.compile(p, re.IGNORECASE)
    for p in _VERIFICATION_DATA.get("clean_response_patterns", [])
]

_DYNAMIC_CONTENT_MARKERS: list[re.Pattern] = [
    re.compile(p) for p in _VERIFICATION_DATA.get("dynamic_content_markers", [])
]

_HONEYPOT_INDICATORS: list[re.Pattern] = [
    re.compile(p, re.IGNORECASE)
    for p in _VERIFICATION_DATA.get("honeypot_indicators", [])
]

_WAF_BLOCK_INDICATORS: list[str] = _VERIFICATION_DATA.get("waf_block_indicators", [])

_LFI_FILE_INDICATORS: list[str] = _VERIFICATION_DATA.get("lfi_file_indicators", [])

_SQL_ERROR_PATTERNS: list[str] = _VERIFICATION_DATA.get("sql_error_patterns", [])

# ── WAF/CDN signatures — loaded from waf_signatures.json via data_loader ─────
_WAF_CDN_SIGNATURES: list[tuple[str, re.Pattern]] = []
try:
    _waf_data = load_waf_signatures()
    _seen_wafs: set[str] = set()
    for sig in _waf_data.get("header_signatures", []):
        waf_name = sig.get("waf", "").lower()
        if waf_name and waf_name not in _seen_wafs:
            _seen_wafs.add(waf_name)
            pattern_str = sig.get("pattern", "")
            header_name = sig.get("header", "")
            if pattern_str:
                compiled = re.compile(pattern_str, re.IGNORECASE)
            elif header_name:
                compiled = re.compile(re.escape(header_name), re.IGNORECASE)
            else:
                continue
            _WAF_CDN_SIGNATURES.append((sig["waf"], compiled))
    for sig in _waf_data.get("body_signatures", []):
        waf_name = sig.get("waf", "").lower()
        pat = sig.get("pattern", "")
        if pat and waf_name not in _seen_wafs:
            _seen_wafs.add(waf_name)
            _WAF_CDN_SIGNATURES.append((sig["waf"], re.compile(pat, re.IGNORECASE)))
except Exception as _e:
    logger.warning("Failed to load WAF signatures for verification: %s", _e)

# ── Independent verification payloads — loaded from fuzzer_data.json ──────────
_VERIFY_PAYLOADS: dict[str, list[str]] = dict(load_fuzzer_data().get("FUZZ_PAYLOADS", {}))

# Supplemental replay payloads for vuln types that benefit from deterministic
# runtime confirmation but may be sparse/absent in fuzzer data. Additive only —
# never overrides payloads already supplied by fuzzer_data.json.
_SUPPLEMENTAL_VERIFY_PAYLOADS: dict[str, list[str]] = {
    "open_redirect": [
        "https://airecon-verify.example",
        "//airecon-verify.example",
        "https:airecon-verify.example",
    ],
    "ssrf": [
        "http://169.254.169.254/latest/meta-data/",
        "http://metadata.google.internal/computeMetadata/v1/",
    ],
    "xxe": [
        '<!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><x>&xxe;</x>',
    ],
}
for _vk, _vp in _SUPPLEMENTAL_VERIFY_PAYLOADS.items():
    _existing = _VERIFY_PAYLOADS.get(_vk, [])
    _VERIFY_PAYLOADS[_vk] = list(_existing) + [p for p in _vp if p not in _existing]

# ── Clean test payloads (should NOT trigger vulns) ────────────────────────────
_CLEAN_PAYLOADS: list[str] = [
    "abc123clean",
    "test_normal_value",
    "safe_parameter",
    "benign_input_99",
]


@dataclass
class VerificationResult:
    """Result of a verification attempt."""

    finding_id: str
    vuln_type: str
    parameter: str
    target: str
    original_confidence: float
    verified_confidence: float
    verification_tier: int  # 0=unverified, 1=replay, 2=cross-tool, 3=certified
    is_false_positive: bool
    fp_reason: str = ""
    replay_success: bool = False
    replay_count: int = 0
    cross_tool_signals: list[str] = field(default_factory=list)
    evidence_bundle: list[dict] = field(default_factory=list)
    dynamic_content_detected: bool = False
    waf_detected: str = ""
    honeypot_detected: bool = False
    negative_test_passed: bool = True
    verification_time_ms: float = 0.0
    details: dict = field(default_factory=dict)


class FalsePositiveDetector:
    """Detects conditions that commonly cause false positives."""

    def detect_dynamic_content(
        self, baseline_body: str, fuzz_body: str
    ) -> tuple[bool, list[str]]:
        """Check if response differences are due to dynamic content rather than actual vulnerability exploitation."""
        reasons: list[str] = []

        baseline_markers = set()
        fuzz_markers = set()

        for pattern in _DYNAMIC_CONTENT_MARKERS:
            baseline_markers.update(
                m.group() for m in pattern.finditer(baseline_body[:5000])
            )
            fuzz_markers.update(m.group() for m in pattern.finditer(fuzz_body[:5000]))

        unique_to_fuzz = fuzz_markers - baseline_markers
        if len(unique_to_fuzz) > 5:
            reasons.append(
                f"High dynamic content: {len(unique_to_fuzz)} unique markers in fuzz response"
            )
            return True, reasons

        for pattern in _CLEAN_RESPONSE_PATTERNS:
            if pattern.search(fuzz_body) and not pattern.search(baseline_body):
                reasons.append(f"Clean pattern detected: {pattern.pattern}")

        return len(reasons) > 0, reasons

    def detect_waf_cdn(
        self, status_code: int, headers: dict, body: str
    ) -> tuple[bool, str]:
        """Detect WAF/CDN responses that may cause false positives or block exploitation."""
        header_str = "\n".join(f"{k}: {v}" for k, v in headers.items())
        combined = header_str + "\n" + body[:5000]

        for waf_name, pattern in _WAF_CDN_SIGNATURES:
            if pattern.search(combined):
                return True, waf_name

        if status_code == 403:
            body_lower = body.lower()
            matches = sum(1 for ind in _WAF_BLOCK_INDICATORS if ind in body_lower)
            if matches >= 2:
                return True, "generic_waf"

        return False, ""

    def detect_honeypot(self, body: str, status_code: int) -> tuple[bool, list[str]]:
        """Detect honeypot responses designed to trap automated scanners."""
        reasons: list[str] = []

        for pattern in _HONEYPOT_INDICATORS:
            if pattern.search(body[:5000]):
                reasons.append(f"Honeypot indicator: {pattern.pattern}")

        if status_code == 200 and len(body) < 100:
            reasons.append("Empty 200 response (possible honeypot)")

        return len(reasons) > 0, reasons

    def detect_reflection_only(
        self, payload: str, baseline_body: str, fuzz_body: str
    ) -> tuple[bool, str]:
        """Check if payload is merely reflected without execution, indicating no actual vulnerability."""
        if payload not in fuzz_body:
            return False, ""

        encoded = (
            payload.replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
        )
        if encoded in fuzz_body:
            return True, "Payload HTML-encoded (safe reflection)"

        if f"<!--{payload}" in fuzz_body or f"{payload}-->" in fuzz_body:
            return True, "Payload in HTML comment (safe reflection)"

        if f'"{payload}"' in fuzz_body or f"'{payload}'" in fuzz_body:
            exec_patterns = [
                f"<script>{payload}",
                f"javascript:{payload}",
                f"onerror={payload}",
                f"onload={payload}",
            ]
            if not any(p in fuzz_body for p in exec_patterns):
                return True, "Payload in non-executable context"

        return False, ""

    def detect_header_only_reflection(
        self, status_code: int, headers: dict, body: str, payload: str
    ) -> tuple[bool, str]:
        """Detect vulnerabilities reported solely from HTTP header reflection.

        Catches false positives where 'reflected XSS' is claimed based on
        Location/redirect headers with no HTML body — classic feedly.com scenario.
        """
        if not body or len(body.strip()) == 0:
            if 300 <= status_code < 400:
                location = headers.get("location", "")
                if location and payload.lower() in location.lower():
                    is_encoded = any(
                        enc in location for enc in ("%3C", "%3c", "%3E", "%3e")
                    )
                    encoding_note = (
                        " Payload is URL-encoded in the header, so it will NOT execute."
                        if is_encoded
                        else ""
                    )
                    return (
                        True,
                        f"Payload only reflected in {status_code} redirect Location header with empty body.{encoding_note}"
                        " HTTP headers are not an executable JavaScript context — XSS is impossible here.",
                    )
            return (
                True,
                "Response body is empty — no HTML/DOM execution context exists for XSS.",
            )

        # Check 3xx redirect where destination is same-origin
        if 300 <= status_code < 400 and headers.get("location"):
            try:
                if len(body.strip()) == 0:
                    return (
                        True,
                        "Redirect response with empty body — no execution context. "
                        "The Location header is not a JavaScript execution target.",
                    )
            except Exception as _e:
                logger.debug("Redirect body check failed: %s", _e)

        return False, ""


class ReplayVerifier:
    """Re-tests findings with independent payloads to confirm vulnerabilities."""

    def __init__(self, timeout: int = 15, max_replays: int = 3):
        self.timeout = timeout
        self.max_replays = max_replays
        self.fp_detector = FalsePositiveDetector()

    async def verify_finding(
        self,
        target_url: str,
        param: str,
        vuln_type: str,
        original_payload: str,
        original_confidence: float,
        headers: dict | None = None,
    ) -> VerificationResult:
        """Verify a finding through replay testing with independent payloads."""
        start_time = time.monotonic()
        result = VerificationResult(
            finding_id=self._make_id(target_url, param, vuln_type),
            vuln_type=vuln_type,
            parameter=param,
            target=target_url,
            original_confidence=original_confidence,
            verified_confidence=original_confidence,
            verification_tier=0,
            is_false_positive=False,
        )

        payloads = _VERIFY_PAYLOADS.get(vuln_type, [])
        if not payloads:
            result.verified_confidence = max(0.1, original_confidence * 0.5)
            result.is_false_positive = False
            result.fp_reason = f"No verification payloads for {vuln_type} — untestable"
            return result

        confirmations = 0
        total_attempts = 0

        async with httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=False,
            verify=False,  # nosec B501
        ) as client:
            for payload in payloads[: self.max_replays]:
                total_attempts += 1
                try:
                    resp = await client.request(
                        "GET",
                        target_url,
                        params={param: payload},
                        headers=headers or {},
                    )

                    if self._check_confirmation(resp, payload, vuln_type):
                        confirmations += 1
                        result.evidence_bundle.append(
                            {
                                "payload": payload,
                                "status": resp.status_code,
                                "length": len(resp.text),
                                "confirmed": True,
                            }
                        )

                except Exception as e:
                    logger.debug("Replay verification error: %s", e)
                    result.evidence_bundle.append(
                        {
                            "payload": payload,
                            "error": str(e),
                            "confirmed": False,
                        }
                    )

        result.replay_count = total_attempts
        result.replay_success = confirmations > 0

        if confirmations == 0:
            result.verified_confidence = max(0.1, original_confidence * 0.3)
            result.is_false_positive = True
            result.fp_reason = "No replay confirmations"
        elif confirmations == 1:
            result.verified_confidence = min(0.85, original_confidence * 0.8)
            result.verification_tier = 1
        elif confirmations >= 2:
            result.verified_confidence = min(0.95, original_confidence * 1.1)
            result.verification_tier = 1
        else:
            result.verified_confidence = min(0.90, original_confidence * 0.9)
            result.verification_tier = 1

        result.verification_time_ms = (time.monotonic() - start_time) * 1000
        return result

    def _check_confirmation(
        self, resp: httpx.Response, payload: str, vuln_type: str
    ) -> bool:
        """Check if replay payload confirms the vulnerability."""
        body = resp.text
        status = resp.status_code

        if vuln_type == "sql_injection":
            if any(err.lower() in body.lower() for err in _SQL_ERROR_PATTERNS):
                return True
            if status == 200 and len(body) > 100:
                if "admin" in payload.lower() and "welcome" in body.lower():
                    return True

        elif vuln_type == "xss":
            if payload in body:
                encoded = payload.replace("<", "&lt;").replace(">", "&gt;")
                if encoded not in body:
                    return True
                if "<script>" in body and "alert" in body:
                    return True

        elif vuln_type == "path_traversal":
            if any(ind.lower() in body.lower() for ind in _LFI_FILE_INDICATORS):
                return True

        elif vuln_type == "ssti":
            if "49" in body:
                if "{{7*7}}" in body or "${7*7}" in body:
                    return True
                if re.search(r"[{<\$]49[}>]", body):
                    return True

        elif vuln_type == "command_injection":
            if "VERIFY_CMD_INJECT" in body:
                return True

        elif vuln_type == "ssrf":
            # Confirmed only when the response actually reflects internal /
            # cloud-metadata content fetched server-side (not mere echo of URL).
            body_l = body.lower()
            ssrf_markers = (
                "ami-id",
                "instance-id",
                "iam/security-credentials",
                "computemetadata",
                "metadata.google",
                "x-aws-ec2-metadata",
                "169.254.169.254",
                "root:x:",
            )
            if any(m in body_l for m in ssrf_markers):
                return True

        elif vuln_type == "xxe":
            body_l = body.lower()
            if any(ind.lower() in body_l for ind in _LFI_FILE_INDICATORS):
                return True
            if "root:x:" in body_l:
                return True

        elif vuln_type == "open_redirect":
            # Confirmed only when a 3xx Location header redirects to the
            # externally-controlled host injected by the payload.
            location = resp.headers.get("location", "")
            if 300 <= status < 400 and location:
                host = self._payload_redirect_host(payload)
                if host and host in location.lower():
                    return True

        return False

    @staticmethod
    def _payload_redirect_host(payload: str) -> str:
        """Extract the destination host from an open-redirect payload.

        Handles forms like ``https://evil.tld/x``, ``//evil.tld``,
        ``https:evil.tld`` → ``evil.tld``.
        """
        p = (payload or "").strip()
        p = re.sub(r"^https?:", "", p, flags=re.IGNORECASE)
        p = p.lstrip("/\\")
        host = re.split(r"[/?#\\]", p, 1)[0]
        return host.lower()

    @staticmethod
    def _make_id(url: str, param: str, vuln_type: str) -> str:
        raw = f"{url}|{param}|{vuln_type}"
        return hashlib.md5(raw.encode(), usedforsecurity=False).hexdigest()[:12]


class CrossToolValidator:
    """Requires 2+ independent signals from different tools/sources."""

    def validate(
        self,
        vuln_type: str,
        parameter: str,
        target: str,
        signals: list[dict[str, Any]],
    ) -> tuple[bool, float, list[str]]:
        """Validate finding requires multiple independent signals.

        Args:
            signals: List of dicts with keys: source, confidence, evidence_type

        Returns:
            (is_valid, adjusted_confidence, reasons)
        """
        if not signals:
            return False, 0.0, ["No independent signals"]

        sources = set()
        max_confidence = 0.0
        evidence_types = set()

        for sig in signals:
            sources.add(sig.get("source", "unknown"))
            max_confidence = max(max_confidence, sig.get("confidence", 0.0))
            evidence_types.add(sig.get("evidence_type", "unknown"))

        independent_count = max(len(sources), len(evidence_types))

        if independent_count < 2:
            return (
                False,
                max_confidence * 0.5,
                [f"Only {independent_count} independent signal(s), need 2+"],
            )

        avg_confidence = sum(s.get("confidence", 0.0) for s in signals) / len(signals)
        source_bonus = min(0.15, len(sources) * 0.05)
        adjusted = min(0.99, avg_confidence + source_bonus)

        return (
            True,
            adjusted,
            [
                f"{len(sources)} sources: {', '.join(sources)}",
                f"{len(evidence_types)} evidence types: {', '.join(evidence_types)}",
            ],
        )


class NegativeTester:
    """Tests against known-clean patterns to calibrate false positive rates."""

    def __init__(self, timeout: int = 10):
        self.timeout = timeout

    async def test_clean(
        self,
        target_url: str,
        param: str,
        headers: dict | None = None,
    ) -> tuple[bool, list[str]]:
        """Test that clean payloads do NOT trigger vulnerability signals.

        Returns:
            (passed, reasons)
        """
        reasons: list[str] = []
        passed = True

        async with httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=False,
            verify=False,  # nosec B501 — intentional for pentesting
        ) as client:
            for clean_payload in _CLEAN_PAYLOADS:
                try:
                    resp = await client.request(
                        "GET",
                        target_url,
                        params={param: clean_payload},
                        headers=headers or {},
                    )

                    body = resp.text.lower()

                    fp_signals = self._check_fp_signals(body, resp.status_code)
                    if fp_signals:
                        passed = False
                        reasons.append(
                            f"Clean payload '{clean_payload}' triggered: {', '.join(fp_signals)}"
                        )

                except Exception as e:
                    logger.debug("Negative test error: %s", e)

        return passed, reasons

    def _check_fp_signals(self, body: str, status: int) -> list[str]:
        """Check for false positive signals in response."""
        signals: list[str] = []

        if any(err.lower() in body for err in _SQL_ERROR_PATTERNS[:4]):
            signals.append("sql_error_on_clean_input")

        if "root:x:" in body or "/etc/passwd" in body:
            signals.append("file_disclosure_on_clean_input")

        if re.search(r"[{<\$]49[}>]", body):
            signals.append("template_execution_on_clean_input")

        if status == 500:
            signals.append("server_error_on_clean_input")

        return signals


class ConfidenceEscalator:
    """Tiered verification system with escalating confidence levels."""

    TIER_UNVERIFIED = 0
    TIER_REPLAY = 1
    TIER_CROSS_TOOL = 2
    TIER_CERTIFIED = 3

    TIER_THRESHOLDS: dict[int, float] = {
        TIER_UNVERIFIED: 0.0,
        TIER_REPLAY: 0.60,
        TIER_CROSS_TOOL: 0.75,
        TIER_CERTIFIED: 0.90,
    }

    def escalate(
        self,
        original_confidence: float,
        replay_verified: bool,
        cross_tool_validated: bool,
        negative_test_passed: bool,
        fp_detected: bool,
        dynamic_content: bool,
    ) -> tuple[int, float, str]:
        """Calculate final verification tier and confidence.

        Returns:
            (tier, final_confidence, status_label)
        """
        confidence = original_confidence
        tier = self.TIER_UNVERIFIED
        reasons: list[str] = []

        if fp_detected:
            return (
                self.TIER_UNVERIFIED,
                max(0.05, confidence * 0.2),
                "BLOCKED: False positive detected",
            )

        if dynamic_content:
            confidence *= 0.7
            reasons.append("Dynamic content detected")

        if not negative_test_passed:
            confidence *= 0.6
            reasons.append("Negative test failed")

        if replay_verified:
            tier = max(tier, self.TIER_REPLAY)
            confidence = min(0.95, confidence * 1.15)
            reasons.append("Replay verified")

        if cross_tool_validated:
            tier = max(tier, self.TIER_CROSS_TOOL)
            confidence = min(0.98, confidence * 1.10)
            reasons.append("Cross-tool validated")

        if (
            replay_verified
            and cross_tool_validated
            and negative_test_passed
            and not dynamic_content
            and confidence >= self.TIER_THRESHOLDS[self.TIER_CERTIFIED]
        ):
            tier = self.TIER_CERTIFIED
            reasons.append("Certified")

        if tier == self.TIER_CERTIFIED:
            status = "CERTIFIED"
        elif tier == self.TIER_CROSS_TOOL:
            status = "VALIDATED"
        elif tier == self.TIER_REPLAY:
            status = "CONFIRMED"
        else:
            status = "UNVERIFIED"

        return tier, confidence, status


class VerificationEngine:
    """Main verification engine orchestrating all stages."""

    def __init__(
        self,
        timeout: int = 15,
        max_replays: int = 3,
        enable_replay: bool = True,
        enable_cross_tool: bool = True,
        enable_negative_test: bool = True,
        enable_fp_detection: bool = True,
    ):
        self.replay_verifier = ReplayVerifier(timeout=timeout, max_replays=max_replays)
        self.cross_tool_validator = CrossToolValidator()
        self.negative_tester = NegativeTester(timeout=timeout)
        self.fp_detector = FalsePositiveDetector()
        self.escalator = ConfidenceEscalator()

        self.enable_replay = enable_replay
        self.enable_cross_tool = enable_cross_tool
        self.enable_negative_test = enable_negative_test
        self.enable_fp_detection = enable_fp_detection

    async def verify_finding(
        self,
        target_url: str,
        param: str,
        vuln_type: str,
        original_payload: str,
        original_confidence: float,
        baseline_body: str = "",
        fuzz_body: str = "",
        response_headers: dict | None = None,
        response_status: int = 200,
        additional_signals: list[dict] | None = None,
        http_headers: dict | None = None,
    ) -> VerificationResult:
        """Run full verification pipeline on a finding.

        Pipeline:
        1. FP Detection (dynamic content, WAF, honeypot, reflection-only)
        2. Negative Testing (clean payloads)
        3. Replay Verification (independent payloads)
        4. Cross-Tool Validation (multiple signals)
        5. Confidence Escalation (final tier calculation)
        """
        start_time = time.monotonic()
        result = VerificationResult(
            finding_id=self.replay_verifier._make_id(target_url, param, vuln_type),
            vuln_type=vuln_type,
            parameter=param,
            target=target_url,
            original_confidence=original_confidence,
            verified_confidence=original_confidence,
            verification_tier=0,
            is_false_positive=False,
        )

        logger.debug(
            f"[Zero-FP] Verifying finding: {vuln_type} on '{param}' "
            f"at {target_url} (original confidence={original_confidence:.2f})"
        )

        if self.enable_fp_detection:
            if baseline_body and fuzz_body:
                is_dynamic, dyn_reasons = self.fp_detector.detect_dynamic_content(
                    baseline_body, fuzz_body
                )
                result.dynamic_content_detected = is_dynamic
                if is_dynamic:
                    result.details["dynamic_content_reasons"] = dyn_reasons
                    logger.debug(
                        f"[Zero-FP] FP Detection: dynamic content detected — {dyn_reasons}"
                    )

            # ── Header-only reflection check (e.g. 301 Location with no body) ──
            if response_headers is not None:
                is_header_only, hdr_reason = (
                    self.fp_detector.detect_header_only_reflection(
                        response_status, response_headers, fuzz_body, original_payload
                    )
                )
                if is_header_only:
                    result.is_false_positive = True
                    result.fp_reason = f"Header-only reflection: {hdr_reason}"
                    result.verified_confidence = max(0.05, original_confidence * 0.2)
                    result.verification_time_ms = (time.monotonic() - start_time) * 1000
                    logger.warning(
                        f"[Zero-FP] FILTERED (header-only reflection): {param}={original_payload} "
                        f"status={response_status} confidence {original_confidence:.2f} → {result.verified_confidence:.2f}"
                    )
                    return result

            if response_headers:
                is_waf, waf_name = self.fp_detector.detect_waf_cdn(
                    response_status, response_headers, fuzz_body
                )
                if is_waf:
                    result.waf_detected = waf_name
                    result.details["waf_detected"] = waf_name
                    logger.debug(
                        f"[Zero-FP] FP Detection: WAF/CDN detected — {waf_name}"
                    )

            is_honeypot, hp_reasons = self.fp_detector.detect_honeypot(
                fuzz_body, response_status
            )
            result.honeypot_detected = is_honeypot
            if is_honeypot:
                result.details["honeypot_reasons"] = hp_reasons
                logger.debug(
                    f"[Zero-FP] FP Detection: honeypot indicators — {hp_reasons}"
                )

            is_reflection_only, refl_reason = self.fp_detector.detect_reflection_only(
                original_payload, baseline_body, fuzz_body
            )
            if is_reflection_only:
                result.is_false_positive = True
                result.fp_reason = f"Reflection-only: {refl_reason}"
                result.verified_confidence = max(0.1, original_confidence * 0.3)
                result.verification_time_ms = (time.monotonic() - start_time) * 1000
                logger.debug(
                    f"[Zero-FP] FILTERED (reflection-only): {param}={original_payload} "
                    f"confidence {original_confidence:.2f} → {result.verified_confidence:.2f}"
                )
                return result

        if self.enable_negative_test:
            neg_passed, neg_reasons = await self.negative_tester.test_clean(
                target_url, param, headers=http_headers
            )
            result.negative_test_passed = neg_passed
            if not neg_passed:
                result.details["negative_test_reasons"] = neg_reasons
                logger.debug(f"[Zero-FP] Negative test FAILED: {neg_reasons}")
            else:
                logger.debug("[Zero-FP] Negative test PASSED")

        if self.enable_replay:
            replay_result = await self.replay_verifier.verify_finding(
                target_url=target_url,
                param=param,
                vuln_type=vuln_type,
                original_payload=original_payload,
                original_confidence=original_confidence,
                headers=http_headers,
            )
            result.replay_success = replay_result.replay_success
            result.replay_count = replay_result.replay_count
            result.evidence_bundle.extend(replay_result.evidence_bundle)
            logger.debug(
                f"[Zero-FP] Replay: {replay_result.replay_count} attempts, "
                f"{'CONFIRMED' if replay_result.replay_success else 'NOT confirmed'}"
            )

        if self.enable_cross_tool and additional_signals:
            is_valid, adjusted_conf, ct_reasons = self.cross_tool_validator.validate(
                vuln_type=vuln_type,
                parameter=param,
                target=target_url,
                signals=additional_signals,
            )
            result.cross_tool_signals = ct_reasons
            if is_valid:
                result.verified_confidence = min(0.99, adjusted_conf)
            logger.debug(
                f"[Zero-FP] Cross-tool: {'VALID' if is_valid else 'INVALID'} "
                f"(confidence={adjusted_conf:.2f}) — {ct_reasons}"
            )

        tier, final_conf, status = self.escalator.escalate(
            original_confidence=original_confidence,
            replay_verified=result.replay_success,
            cross_tool_validated=bool(result.cross_tool_signals),
            negative_test_passed=result.negative_test_passed,
            fp_detected=result.is_false_positive,
            dynamic_content=result.dynamic_content_detected,
        )

        result.verification_tier = tier
        result.verified_confidence = final_conf
        result.details["status"] = status
        result.details["escalation_reasons"] = self.escalator.TIER_THRESHOLDS

        if result.is_false_positive or result.honeypot_detected:
            result.verification_tier = 0
            result.verified_confidence = max(0.05, result.verified_confidence * 0.2)

        result.verification_time_ms = (time.monotonic() - start_time) * 1000

        logger.debug(
            f"[Zero-FP] RESULT: {vuln_type} on '{param}' → "
            f"tier={tier} ({status}), confidence {original_confidence:.2f} → {final_conf:.2f}, "
            f"time={result.verification_time_ms:.0f}ms"
        )

        return result

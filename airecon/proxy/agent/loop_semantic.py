from __future__ import annotations

import hashlib
import json
import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

logger = logging.getLogger("airecon.agent.semantic")

@dataclass
class VulnIntent:
    vuln_class: str
    target_endpoint: str
    target_parameter: str
    test_variant: str
    success: bool = False
    attempt_count: int = 0


class SemanticDeduplicator:
    _vuln_patterns: dict[str, Any] | None = None

    @classmethod
    def _ensure_patterns_loaded(cls) -> None:
        if cls._vuln_patterns is not None:
            return
        try:
            patterns_path = Path(__file__).parent.parent / "data" / "unified_patterns.json"
            data = json.loads(patterns_path.read_text(encoding="utf-8"))
            cls._vuln_patterns = data.get("vuln_detection_patterns", {})
        except Exception as e:
            logger.warning("Failed to load vuln detection patterns from JSON: %s", e)
            cls._vuln_patterns = {}

    @classmethod
    def _get_command_patterns(cls, vuln_class: str) -> list[str]:
        cls._ensure_patterns_loaded()
        patterns = cls._vuln_patterns or {}
        return patterns.get("command_patterns", {}).get(vuln_class, [])

    @classmethod
    def _get_result_keywords(cls, vuln_class: str) -> list[str]:
        cls._ensure_patterns_loaded()
        patterns = cls._vuln_patterns or {}
        return patterns.get("result_keywords", {}).get(vuln_class, [])

    @classmethod
    def _get_tool_vuln_map(cls) -> dict[str, str]:
        cls._ensure_patterns_loaded()
        patterns = cls._vuln_patterns or {}
        return patterns.get("tool_vuln_map", {})

    @classmethod
    def _get_test_variants(cls, vuln_class: str) -> dict[str, str]:
        cls._ensure_patterns_loaded()
        patterns = cls._vuln_patterns or {}
        return patterns.get("test_variants", {}).get(vuln_class, {})

    def __init__(self, max_history: int = 500):
        self._tested_intents: dict[str, VulnIntent] = {}
        self._max_history = max_history

    def _detect_vuln_class_from_command(self, command: str) -> str:
        cmd_lower = command.lower()

        vuln_classes = ["sql_injection", "xss", "path_traversal", "command_injection", "ssrf", "idor"]
        for vuln_class in vuln_classes:
            patterns = self._get_command_patterns(vuln_class)
            for pattern in patterns:
                if re.search(pattern, cmd_lower, re.IGNORECASE):
                    return vuln_class

        for tool, vuln_class in self._get_tool_vuln_map().items():
            if tool in cmd_lower:
                return vuln_class

        return "unknown"

    def _detect_vuln_class_from_result(self, result_text: str) -> str:
        result_lower = result_text.lower()

        for vuln_class in ["sql_injection", "xss", "path_traversal", "command_injection", "ssrf", "idor"]:
            keywords = self._get_result_keywords(vuln_class)
            for kw in keywords:
                if kw in result_lower:
                    return vuln_class

        return "unknown"

    def _extract_endpoint_and_param(self, command: str) -> tuple[str, str]:
        endpoint = ""
        parameter = ""

        url_match = re.search(r"(https?://[^\s\"'<>]+)", command)
        if url_match:
            url = url_match.group(1)
            try:
                from urllib.parse import urlparse, parse_qs
                parsed = urlparse(url)
                endpoint = parsed.path
                params = parse_qs(parsed.query)
                if params:
                    parameter = list(params.keys())[0]
            except Exception as _e:
                logger.debug("Failed to parse URL params: %s", _e)
                endpoint = url.split("?")[0] if "?" in url else url

        return endpoint, parameter

    def _detect_test_variant(self, command: str, vuln_class: str) -> str:
        cmd_lower = command.lower()

        variants = self._get_test_variants(vuln_class)
        for variant, pattern in variants.items():
            if re.search(pattern, cmd_lower, re.IGNORECASE):
                return variant

        return "standard"

    def build_intent(self, command: str, result_text: str = "") -> VulnIntent | None:
        vuln_class = self._detect_vuln_class_from_command(command)
        if vuln_class == "unknown" and result_text:
            vuln_class = self._detect_vuln_class_from_result(result_text)

        if vuln_class == "unknown":
            return None

        endpoint, parameter = self._extract_endpoint_and_param(command)
        variant = self._detect_test_variant(command, vuln_class)

        return VulnIntent(
            vuln_class=vuln_class,
            target_endpoint=endpoint,
            target_parameter=parameter,
            test_variant=variant,
        )

    def _intent_hash(self, intent: VulnIntent) -> str:
        raw = f"{intent.vuln_class}:{intent.target_endpoint}:{intent.target_parameter}:{intent.test_variant}"
        return hashlib.sha256(raw.encode("utf-8", errors="replace"), usedforsecurity=False).hexdigest()[:16]

    def is_duplicate_test(self, intent: VulnIntent) -> tuple[bool, str]:
        intent_key = self._intent_hash(intent)

        if intent_key not in self._tested_intents:
            return False, ""

        existing = self._tested_intents[intent_key]
        existing.attempt_count += 1

        if existing.success:
            msg = (
                f"[SEMANTIC DEDUP] Already confirmed {existing.vuln_class} on "
                f"{existing.target_endpoint}"
            )
            if existing.target_parameter:
                msg += f"?{existing.target_parameter}"
            msg += f" ({existing.attempt_count} attempts). Focus elsewhere."
            return True, msg

        if existing.attempt_count >= 3:
            msg = (
                f"[SEMANTIC DEDUP] Tested {existing.vuln_class} on "
                f"{existing.target_endpoint}"
            )
            if existing.target_parameter:
                msg += f"?{existing.target_parameter}"
            msg += f" {existing.attempt_count}x without success. Try different vector."
            return True, msg

        return False, f"[SEMANTIC TRACKING] {existing.vuln_class} attempt #{existing.attempt_count + 1} on same target"

    def record_test(self, intent: VulnIntent, success: bool = False) -> None:
        intent_key = self._intent_hash(intent)

        if intent_key not in self._tested_intents:
            self._tested_intents[intent_key] = intent

        existing = self._tested_intents[intent_key]
        existing.success = existing.success or success
        existing.attempt_count += 1

        if len(self._tested_intents) > self._max_history:
            oldest_keys = list(self._tested_intents.keys())[:50]
            for key in oldest_keys:
                del self._tested_intents[key]

    def get_coverage_summary(self) -> dict[str, Any]:
        by_class: dict[str, int] = {}
        by_endpoint: dict[str, int] = {}
        confirmed: list[str] = []

        for intent in self._tested_intents.values():
            by_class[intent.vuln_class] = by_class.get(intent.vuln_class, 0) + 1
            endpoint = intent.target_endpoint or "unknown"
            by_endpoint[endpoint] = by_endpoint.get(endpoint, 0) + 1
            if intent.success:
                confirmed.append(f"{intent.vuln_class} on {endpoint}")

        return {
            "total_unique_tests": len(self._tested_intents),
            "by_vuln_class": by_class,
            "by_endpoint": by_endpoint,
            "confirmed_vulns": confirmed,
            "repeated_attempts": sum(
                i.attempt_count for i in self._tested_intents.values() if i.attempt_count > 1
            ),
        }

    def get_untested_vectors(self, endpoints: list[str], all_vuln_classes: list[str]) -> list[str]:
        untested = []
        for endpoint in endpoints:
            for vuln_class in all_vuln_classes:
                already_tested = any(
                    i.vuln_class == vuln_class and i.target_endpoint == endpoint
                    for i in self._tested_intents.values()
                )
                if not already_tested:
                    untested.append(f"{vuln_class} on {endpoint}")
        return untested


_deduplicator: SemanticDeduplicator | None = None


def get_deduplicator() -> SemanticDeduplicator:
    global _deduplicator
    if _deduplicator is None:
        _deduplicator = SemanticDeduplicator()
    return _deduplicator


def reset_deduplicator() -> None:
    global _deduplicator
    _deduplicator = None

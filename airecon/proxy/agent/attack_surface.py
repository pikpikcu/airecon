from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger("airecon.agent")

@dataclass
class _EndpointState:
    endpoint: str
    vuln_types_tested: dict[str, list[str]] = field(default_factory=dict)
    findings: int = 0
    last_test_time: float = 0.0
    attempts: int = 0

    def record(self, vuln_type: str, tool_used: str) -> None:
        seen = self.vuln_types_tested.setdefault(vuln_type, [])
        if tool_used not in seen:
            seen.append(tool_used)
        self.attempts += 1
        self.last_test_time = time.time()

    def coverage_hints(self) -> list[str]:
        hints: list[str] = []
        if self.attempts > 0 and self.findings == 0:
            tried = ", ".join(sorted(self.vuln_types_tested))
            hints.append(
                f"SKIP (no findings after {self.attempts} attempts): {self.endpoint} "
                f"[tried: {tried}]"
            )
        elif self.attempts > 0:
            tried = sorted(self.vuln_types_tested)
            hints.append(
                f"TESTED ({self.attempts} runs, {self.findings} findings): {self.endpoint} "
                f"[vuln types: {', '.join(tried)}]"
            )
        return hints


class AttackSurfaceTracker:
    def __init__(self, max_no_finding_skip: int = 2) -> None:
        self._endpoints: dict[str, _EndpointState] = {}
        self._max_no_finding_skip = max_no_finding_skip

    def record_test(
        self,
        endpoint: str,
        vuln_type: str,
        tool_used: str,
        findings: int = 0,
    ) -> None:
        normed = self._normalise_endpoint(endpoint)
        state = self._endpoints.setdefault(normed, _EndpointState(endpoint=normed))
        state.record(vuln_type, tool_used)
        state.findings += findings

    def build_coverage_hint(self) -> str | None:
        if not self._endpoints:
            return None

        lines: list[str] = []
        for _path, state in sorted(
            self._endpoints.items(),
            key=lambda kv: kv[1].attempts,
            reverse=True,
        ):
            lines.extend(state.coverage_hints())

        if not lines:
            return None

        header = (
            "[SYSTEM: ATTACK SURFACE COVERAGE — do not repeat what is already done]\n"
            "Each line below shows an endpoint, how many attempts were made, and "
            "which vulnerability types were already tested."
        )
        return header + "\n" + "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        return {
            ep: {
                "vuln_types_tested": state.vuln_types_tested,
                "findings": state.findings,
                "attempts": state.attempts,
            }
            for ep, state in self._endpoints.items()
        }

    def restore(self, data: dict[str, Any]) -> None:
        for ep, info in data.items():
            state = _EndpointState(
                endpoint=ep,
                vuln_types_tested=info.get("vuln_types_tested", {}),
                findings=info.get("findings", 0),
                attempts=info.get("attempts", 0),
            )
            self._endpoints[ep] = state

    @staticmethod
    def _normalise_endpoint(endpoint: str) -> str:
        if not endpoint:
            return "<root>"
        if endpoint.startswith(("http://", "https://")):
            try:
                from urllib.parse import urlparse

                parsed = urlparse(endpoint)
                endpoint = parsed.path or "/"
            except Exception as _e:
                logger.debug("Failed to parse endpoint %s: %s", endpoint, _e)
        endpoint = endpoint.rstrip("/") or "/"
        endpoint = endpoint.lower()
        return endpoint

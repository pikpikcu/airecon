from __future__ import annotations

import asyncio
import logging
import re
import time
from typing import Any
from urllib.parse import urlparse

from .models import ToolExecution

from ..reporting import create_vulnerability_report

logger = logging.getLogger("airecon.agent")

# ── False-positive regex rules loaded once from verification_patterns.json ─
_fp_compiled: list[tuple[str, re.Pattern[str]]] = []

# Map free-text report claims → verification vuln_type keys that have a
# deterministic runtime confirmator in verification.py. Order matters: first
# match wins. Vuln classes NOT listed here (IDOR, auth bypass, CSRF, business
# logic, race conditions, …) are intentionally never blocked by active replay —
# they are validated by evidence grounding, keeping the agent free to report
# novel/stateful findings rather than forcing a rigid, monotonous checklist.
_RUNTIME_VERIFY_KEYWORDS: list[tuple[str, re.Pattern[str]]] = [
    ("sql_injection", re.compile(
        r"sql\s*injection|sqli|union\s+select|error[\s-]based|boolean[\s-]based|"
        r"time[\s-]based\s+blind", re.IGNORECASE)),
    ("command_injection", re.compile(
        r"command\s*injection|\brce\b|remote\s+code\s+execution|os\s+command", re.IGNORECASE)),
    ("ssti", re.compile(
        r"\bssti\b|template\s+injection|\{\{\s*\d+\s*\*\s*\d+\s*\}\}", re.IGNORECASE)),
    ("xxe", re.compile(r"\bxxe\b|xml\s+external\s+entity", re.IGNORECASE)),
    ("ssrf", re.compile(
        r"\bssrf\b|server[\s-]*side\s*request\s*forgery|metadata\s+endpoint", re.IGNORECASE)),
    ("path_traversal", re.compile(
        r"path\s*traversal|directory\s*traversal|\blfi\b|local\s+file\s+inclusion", re.IGNORECASE)),
    ("open_redirect", re.compile(r"open\s*redirect|unvalidated\s+redirect", re.IGNORECASE)),
    ("xss", re.compile(
        r"\bxss\b|cross[\s-]*site\s*scripting|reflected\s+(?:script|payload)", re.IGNORECASE)),
]

# Vuln types where a stateless GET replay reliably reproduces a true positive.
# Only these may produce an active-verification BLOCK, and only under strict
# guards (confident extraction, GET method, live endpoint, clean negative test).
_REPLAY_RELIABLE_TYPES: frozenset[str] = frozenset({
    "xss", "sql_injection", "ssti", "path_traversal",
    "command_injection", "open_redirect", "ssrf", "xxe",
})


def _load_fp_indicators() -> list[tuple[str, re.Pattern[str]]]:
    global _fp_compiled
    if _fp_compiled:
        return _fp_compiled
    try:
        from ..data_loader import load_verification_patterns

        _verif_data = load_verification_patterns()
        _raw_indicators = _verif_data.get("false_positive_indicators", [])
        _fp_compiled = [
            (pat, re.compile(pat, re.IGNORECASE))
            for pat in _raw_indicators
            if isinstance(pat, str)
        ]
    except Exception as _e:
        logger.debug("Could not load FP indicators for pre-report check: %s", _e)
    return _fp_compiled


class _ReportingExecutorMixin:
    async def _execute_report_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> tuple[bool, float, dict[str, Any], str | None]:
        self._last_output_file = None
        start_time = time.time()

        try:
            # ── Pre-report verification: catch false positives before file is written ──
            _verification_block = self._verify_before_report(arguments)
            if _verification_block:
                logger.warning("[Zero-FP] Report BLOCKED: %s", _verification_block)
                return (
                    False,
                    time.time() - start_time,
                    {
                        "success": False,
                        "blocked_by_verifier": True,
                        "reason": _verification_block,
                    },
                    None,
                )

            # ── Active runtime verification: re-test the live target ──────────
            _runtime = await self._runtime_verify_report(arguments)
            if _runtime.get("blocked"):
                logger.warning(
                    "[Zero-FP] Report BLOCKED by active verification: %s",
                    _runtime.get("reason"),
                )
                return (
                    False,
                    time.time() - start_time,
                    {
                        "success": False,
                        "blocked_by_verifier": True,
                        "reason": _runtime.get("reason"),
                        "verification": _runtime,
                    },
                    None,
                )

            if _runtime.get("ran"):
                _v_status = (
                    (_runtime.get("status") or "CONFIRMED")
                    if _runtime.get("replay_success")
                    else "RUNTIME-INCONCLUSIVE"
                )
                _v_conf = float(_runtime.get("confidence", 0.0) or 0.0)
            else:
                _v_status = "EVIDENCE-GROUNDED"
                _v_conf = None
            _report_params = {
                "title",
                "description",
                "target",
                "poc_description",
                "poc_script_code",
                "impact",
                "technical_analysis",
                "remediation_steps",
                "attack_vector",
                "attack_complexity",
                "privileges_required",
                "user_interaction",
                "scope",
                "confidentiality",
                "integrity",
                "availability",
                "endpoint",
                "method",
                "cve",
                "cwe",
                "owasp",
                "suggested_fix",
                "flag",
            }
            _report_kwargs = {k: v for k, v in arguments.items() if k in _report_params}
            _report_kwargs["_active_target"] = self.state.active_target
            _report_kwargs["_verification_status"] = _v_status
            _report_kwargs["_verification_confidence"] = _v_conf
            _report_kwargs["_evidence_artifacts"] = _runtime.get("evidence") or None
            result = await asyncio.to_thread(
                create_vulnerability_report,
                **_report_kwargs,
            )
            success = result.get("success", False)
            if success:
                result.setdefault("artifact_type", "vulnerability_report")
                result.setdefault("report_generated", True)
                result.setdefault(
                    "message",
                    "Final vulnerability report generated and saved under vulnerabilities/.",
                )
            try:
                self._save_tool_output(tool_name, arguments, result)
            except Exception as _e:
                logger.debug("Could not save tool output: %s", _e)

            if success and self._session:
                report_title = str(arguments.get("title", "") or "").strip()
                flag = arguments.get("flag", "")

                def _token_set(text: str) -> set[str]:
                    return {
                        tok
                        for tok in re.findall(r"[a-z0-9]{4,}", text.lower())
                        if tok not in {"vulnerability", "report", "issue", "finding"}
                    }

                def _scope_hints(data: dict[str, Any]) -> set[str]:
                    hints: set[str] = set()
                    for key in (
                        "url",
                        "endpoint",
                        "affected_endpoint",
                        "target",
                        "parameter",
                    ):
                        raw = str(data.get(key, "") or "").strip().lower()
                        if not raw:
                            continue
                        hints.add(raw)
                        try:
                            parsed = urlparse(raw)
                            if parsed.netloc:
                                hints.add(parsed.netloc.lower())
                            if parsed.path:
                                hints.add(parsed.path.lower())
                        except Exception as e:
                            logging.getLogger(__name__).debug(
                                "Expected failure parsing URL in report scope hints: %s",
                                e,
                            )
                    return hints

                report_scope = _scope_hints(arguments)
                report_tokens = _token_set(report_title)
                matched = False
                for vuln in self._session.vulnerabilities:
                    v_title = str(
                        vuln.get("title") or vuln.get("finding") or ""
                    ).strip()
                    if not report_title or not v_title:
                        continue

                    v_lower = v_title.lower()
                    r_lower = report_title.lower()
                    strict_title_hit = v_lower in r_lower or r_lower in v_lower
                    v_tokens = _token_set(v_title)
                    overlap_ratio = (
                        (len(report_tokens & v_tokens) / max(1, len(report_tokens)))
                        if report_tokens
                        else 0.0
                    )

                    vuln_scope = _scope_hints(vuln)
                    scope_hit = False
                    if report_scope and vuln_scope:
                        scope_hit = any(
                            rs in vs or vs in rs
                            for rs in report_scope
                            for vs in vuln_scope
                        )

                    title_confident = strict_title_hit or overlap_ratio >= 0.75
                    if title_confident and (
                        scope_hit or strict_title_hit or overlap_ratio >= 0.90
                    ):
                        vuln["report_generated"] = True
                        if flag:
                            vuln["flag"] = flag
                        # Stamp active-verification outcome onto the finding so
                        # supervision/quality scoring and future report-readiness
                        # reflect what was actually re-tested at runtime.
                        if _runtime.get("ran"):
                            _existing_conf = float(
                                vuln.get("verified_confidence", 0.0) or 0.0
                            )
                            vuln["verified_confidence"] = max(
                                _existing_conf, float(_runtime.get("confidence", 0.0) or 0.0)
                            )
                            if _runtime.get("replay_success"):
                                vuln["verified"] = True
                                vuln["replay_verified"] = True
                        matched = True

                if success and report_title and not matched:
                    logger.info(
                        "Report created but not bound to existing vulnerability: title=%r",
                        report_title[:120],
                    )

                # Record to attack surface tracker
                try:
                    _tracker = getattr(self, "_surface_tracker", None)
                    if _tracker and report_title:
                        _ep = str(
                            arguments.get("endpoint", "")
                            or arguments.get("target", "")
                            or ""
                        )
                        _vuln_type = _token_set(report_title)
                        _vt = (
                            " | ".join(sorted(_vuln_type))
                            if _vuln_type
                            else report_title
                        )
                        _n_findings = 1 if success else 0
                        _tracker.record_test(
                            endpoint=_ep,
                            vuln_type=_vt,
                            tool_used="create_vulnerability_report",
                            findings=_n_findings,
                        )
                except Exception as _e:
                    logger.debug("Surface tracker update failed: %s", _e)
        except Exception as e:
            success = False
            result = {"success": False, "error": str(e)}
            logger.error("Reporting tool exec error: %s", e)

        duration = time.time() - start_time
        self.state.tool_history.append(
            ToolExecution(
                tool_name=tool_name,
                arguments=arguments,
                result=result,
                duration=duration,
                status="success" if success else "error",
            )
        )
        self.state.tool_counts["exec"] += 1
        self.state.tool_counts["total"] += 1
        return success, duration, result, self._last_output_file

    # ------------------------------------------------------------------
    # Pre-report false-positive prevention — data-driven, no hardcoded vuln types
    # ------------------------------------------------------------------

    @staticmethod
    def _token_set(text: str) -> set[str]:
        return {
            token
            for token in re.findall(r"[a-z0-9]{4,}", str(text or "").lower())
            if token not in {"vulnerability", "report", "issue", "finding"}
        }

    @staticmethod
    def _scope_hints(data: dict[str, Any]) -> set[str]:
        hints: set[str] = set()
        for key in ("url", "endpoint", "affected_endpoint", "target", "parameter"):
            raw = str(data.get(key, "") or "").strip().lower()
            if not raw:
                continue
            hints.add(raw)
            try:
                parsed = urlparse(raw)
                if parsed.netloc:
                    hints.add(parsed.netloc.lower())
                if parsed.path:
                    hints.add(parsed.path.lower())
            except Exception as e:
                logger.debug("Scope hint parse failed for %s: %s", raw, e)
        return hints

    def _collect_report_support(self, arguments: dict[str, Any]) -> dict[str, Any]:
        title = str(arguments.get("title", "") or "").strip()
        description = str(arguments.get("description", "") or "").strip()
        report_tokens = self._token_set(f"{title} {description}")
        report_scope = self._scope_hints(arguments)

        evidence_matches: list[dict[str, Any]] = []
        for ev in reversed(getattr(self.state, "evidence_log", [])[-60:]):
            if not isinstance(ev, dict):
                continue
            summary = str(ev.get("summary", "") or "")
            artifact = str(ev.get("artifact", "") or "")
            ev_scope = self._scope_hints(
                {
                    "target": artifact,
                    "endpoint": summary,
                }
            )
            ev_tokens = self._token_set(summary)
            overlap = len(report_tokens & ev_tokens)
            scope_hit = bool(report_scope and ev_scope and any(
                rs in es or es in rs for rs in report_scope for es in ev_scope
            ))
            if overlap >= 2 or scope_hit:
                evidence_matches.append(ev)

        session_matches: list[dict[str, Any]] = []
        if self._session:
            for vuln in getattr(self._session, "vulnerabilities", []):
                if not isinstance(vuln, dict):
                    continue
                vuln_title = str(vuln.get("title") or vuln.get("finding") or "")
                vuln_scope = self._scope_hints(vuln)
                vuln_tokens = self._token_set(vuln_title)
                overlap = len(report_tokens & vuln_tokens)
                scope_hit = bool(report_scope and vuln_scope and any(
                    rs in vs or vs in rs for rs in report_scope for vs in vuln_scope
                ))
                if overlap >= 2 or scope_hit:
                    session_matches.append(vuln)

        verified_session = any(
            bool(v.get("verified"))
            or bool(v.get("replay_verified"))
            or float(v.get("verified_confidence", 0.0) or 0.0) >= 0.65
            for v in session_matches
        )

        return {
            "report_scope": report_scope,
            "evidence_matches": evidence_matches,
            "session_matches": session_matches,
            "verified_session": verified_session,
        }

    def _assess_report_readiness(self, arguments: dict[str, Any]) -> str | None:
        poc_desc = str(arguments.get("poc_description", "") or "").strip()
        poc_code = str(arguments.get("poc_script_code", "") or "").strip()
        description = str(arguments.get("description", "") or "").strip()
        impact = str(arguments.get("impact", "") or "").strip()

        support = self._collect_report_support(arguments)
        report_scope = support["report_scope"]
        evidence_matches = support["evidence_matches"]
        session_matches = support["session_matches"]
        verified_session = support["verified_session"]

        if not report_scope:
            return "Report must include a concrete target/endpoint/scope, not only a generic title."

        combined_poc = f"{poc_desc}\n{poc_code}"
        has_repro_step = bool(
            re.search(
                r"(?i)(?:\bcurl\b|\bhttpie\b|\bpython\b|requests\.|browser_action|"
                r"sqlmap|nuclei|ffuf|wfuzz|(?:get|post|put|patch|delete)\s+/|https?://)",
                combined_poc,
            )
        )
        has_observable_effect = bool(
            re.search(
                r"(?i)\b(returned|response|status|body|cookie|token|credential|admin|"
                r"reflected|dump|leak|bypass|access|updated|deleted|created|downloaded|"
                r"charged|credited|approved|escalated|cross-tenant)\b",
                f"{poc_desc}\n{description}\n{impact}",
            )
        )
        if not has_repro_step or not has_observable_effect:
            return (
                "Report PoC must show a reproducible action plus an observable security outcome "
                "(for example response/status/data/state change)."
            )

        has_context = bool(getattr(self.state, "evidence_log", [])) or bool(
            getattr(self._session, "vulnerabilities", []) if self._session else []
        )
        if has_context and not evidence_matches and not session_matches:
            return (
                "Report is not grounded in current session evidence. Match it to recorded evidence "
                "or a tracked vulnerability before creating the final report."
            )

        if session_matches and not verified_session and len(evidence_matches) < 2:
            return (
                "Matched vulnerability exists, but corroboration is still weak. Gather replay/cross-tool evidence "
                "or additional session evidence before reporting."
            )

        return None

    def _verify_before_report(self, arguments: dict[str, Any]) -> str | None:
        """Synchronous pre-flight check against known-false-positive patterns.

        Does NOT classify vulnerability types — that's the LLM's job via prompts.
        Only rejects claims that match data-driven FP indicators.
        """
        poc_desc = str(arguments.get("poc_description", "")).strip()
        poc_code = str(arguments.get("poc_script_code", "")).strip()
        title = str(arguments.get("title", "")).strip()

        # 1. PoC is mandatory for any report
        if not poc_code:
            return "PoC script/code is required but missing in report arguments."

        # 2. Match against FP indicators from verification_patterns.json (data-driven)
        combined = f"{title} {poc_desc} {poc_code}"
        for pattern_str, compiled_regex in _load_fp_indicators():
            if compiled_regex.search(combined):
                return (
                    f"Vulnerability claim matches known false-positive pattern: "
                    f"{pattern_str[:100]}"
                )

        readiness_block = self._assess_report_readiness(arguments)
        if readiness_block:
            return readiness_block

        return None  # no blocking reason found

    # ------------------------------------------------------------------
    # Active runtime verification — re-tests the live target before a report
    # is written. Corroborates true positives and stamps session findings;
    # blocks ONLY deterministically-reproducible types that fail to reproduce.
    # ------------------------------------------------------------------

    def _infer_runtime_vuln_type(self, arguments: dict[str, Any]) -> str | None:
        blob = "\n".join(
            str(arguments.get(k, "") or "")
            for k in ("title", "description", "poc_description", "poc_script_code")
        )
        for vuln_type, pattern in _RUNTIME_VERIFY_KEYWORDS:
            if pattern.search(blob):
                return vuln_type
        return None

    def _extract_http_target(self, arguments: dict[str, Any]) -> str:
        for key in ("endpoint", "target"):
            raw = str(arguments.get(key, "") or "").strip()
            if raw.startswith(("http://", "https://")):
                return raw.split()[0]
        endpoint = str(arguments.get("endpoint", "") or "").strip()
        active = str(getattr(self.state, "active_target", "") or "").strip()
        if active.startswith(("http://", "https://")):
            if endpoint.startswith("/"):
                from urllib.parse import urljoin

                return urljoin(active, endpoint.split()[0])
            if not endpoint:
                return active.split()[0]
        return ""

    @staticmethod
    def _extract_injection_param(arguments: dict[str, Any], target_url: str) -> tuple[str, bool]:
        explicit = str(arguments.get("parameter", "") or "").strip()
        if explicit:
            return explicit, True
        try:
            from urllib.parse import parse_qs, urlparse

            query = parse_qs(urlparse(target_url).query)
            if query:
                return next(iter(query.keys())), True
        except Exception as _e:
            logger.debug("injection-param extraction failed for %r: %s", target_url, _e)
        return "", False

    def _verification_http_headers(self) -> dict[str, str] | None:
        """Best-effort auth headers so authed endpoints are tested as the agent
        sees them — prevents false 'unreproducible' blocks on protected routes."""
        for attr in ("auth_headers", "session_headers", "http_headers"):
            headers = getattr(self.state, attr, None)
            if isinstance(headers, dict) and headers:
                return {str(k): str(v) for k, v in headers.items()}
        return None

    async def _runtime_verify_report(self, arguments: dict[str, Any]) -> dict[str, Any]:
        out: dict[str, Any] = {
            "ran": False,
            "blocked": False,
            "reason": "",
            "status": "",
            "confidence": 0.0,
            "replay_success": False,
            "tier": 0,
        }
        try:
            from ..config import get_config

            cfg = get_config()
        except Exception as _e:
            logger.debug("runtime verify: config load failed: %s", _e)
            return out
        if not getattr(cfg, "verification_enabled", False):
            return out

        vuln_type = self._infer_runtime_vuln_type(arguments)
        if not vuln_type:
            return out  # novel / stateful class — corroborate via evidence only

        target_url = self._extract_http_target(arguments)
        if not target_url:
            return out

        param, confident = self._extract_injection_param(arguments, target_url)
        if not param:
            return out  # no injection point to actively test

        method = str(arguments.get("method", "") or "").strip().upper()

        try:
            from .verification import VerificationEngine

            engine = VerificationEngine(
                timeout=cfg.verification_timeout,
                max_replays=cfg.verification_max_replays,
                enable_replay=cfg.verification_enable_replay,
                enable_cross_tool=False,
                enable_negative_test=cfg.verification_enable_negative_test,
                enable_fp_detection=cfg.verification_enable_fp_detection,
            )
            vres = await engine.verify_finding(
                target_url=target_url,
                param=param,
                vuln_type=vuln_type,
                original_payload="",
                original_confidence=0.6,
                http_headers=self._verification_http_headers(),
            )
        except Exception as e:
            logger.debug("[Zero-FP] runtime report verification skipped: %s", e)
            return out

        out["ran"] = True
        out["replay_success"] = bool(vres.replay_success)
        out["confidence"] = float(vres.verified_confidence)
        out["tier"] = int(vres.verification_tier)
        # Machine-captured proof (payload/status/length per replay attempt) so the
        # report can persist concrete request/response evidence, not just the
        # model's PoC text.
        out["evidence"] = [
            ev for ev in vres.evidence_bundle if isinstance(ev, dict)
        ][:25]
        out["status"] = (
            str(vres.details.get("status", "") or "")
            or ("CONFIRMED" if vres.replay_success else "RUNTIME-INCONCLUSIVE")
        )

        # Only the endpoint was actually exercised by GET replay if we saw a
        # live (<400) response. Authed/POST-only/unreachable routes must NOT
        # be treated as disproof of the finding.
        endpoint_live = any(
            isinstance(ev, dict)
            and isinstance(ev.get("status"), int)
            and ev["status"] < 400
            for ev in vres.evidence_bundle
        )

        allow_block = (
            confident
            and method in ("", "GET", "HEAD")
            and vuln_type in _REPLAY_RELIABLE_TYPES
            and endpoint_live
            and vres.replay_count >= 2
            and not vres.replay_success
            and vres.negative_test_passed
            and not vres.is_false_positive
        )
        if allow_block:
            out["blocked"] = True
            out["reason"] = (
                f"Active replay verification could not reproduce the claimed {vuln_type} "
                f"on parameter '{param}' at {target_url} across {vres.replay_count} "
                f"independent payloads, while clean inputs produced no signal. "
                f"Re-confirm with a working PoC before reporting."
            )
        return out

from __future__ import annotations

import json
import logging
import re
import warnings
from pathlib import Path
from typing import Any

from ..config import get_config
from ..correlation import PORT_CORRELATIONS
from ..data_loader import (
    load_objective_patterns,
    load_vuln_hypothesis_legacy,
)
from .executors import (
    _RECON_CONTENT_DISCOVERY_BINS,
    _RECON_LIVE_HOST_BINS,
    _RECON_PORT_SCAN_BINS,
    _RECON_SUBDOMAIN_BINS,
)
from .owasp import classify_owasp, severity_for_evidence
from .pipeline import _PHASE_TOOL_BUDGETS, PipelinePhase
from .vuln_classifier import get_classifier

_BUDGET_DEFAULT_MIN_CALLS: int   = 8
_BUDGET_DEFAULT_THRESHOLD: float = 0.08
_BUDGET_EXPLOIT_MIN_CALLS: int   = 14
_BUDGET_EXPLOIT_THRESHOLD: float = 0.05
_BUDGET_EVIDENCE_EXEMPTION: int  = 3

logger = logging.getLogger("airecon.agent.loop_objectives")

_OBJECTIVE_PATTERNS: dict[str, Any] = {}


def _load_objective_patterns() -> dict[str, Any]:
    global _OBJECTIVE_PATTERNS
    if _OBJECTIVE_PATTERNS:
        return _OBJECTIVE_PATTERNS
    _OBJECTIVE_PATTERNS = load_objective_patterns()
    return _OBJECTIVE_PATTERNS


def _get_objective_regex(category: str) -> list[re.Pattern]:
    patterns = _load_objective_patterns()
    obj_data = patterns.get("objectives", {}).get(category, {})
    indicators = obj_data.get("indicators", [])
    result = []
    for ind in indicators:
        try:
            result.append(re.compile(ind, re.IGNORECASE))
        except re.error:
            pass
    return result


_tools_meta_path = Path(__file__).parent.parent / "data" / "tools_meta.json"
try:
    with open(_tools_meta_path) as _f:
        _TOOLS_META_OBJ: dict[str, Any] = json.load(_f)
except (OSError, json.JSONDecodeError) as _e:
    warnings.warn(f"tools_meta.json unavailable in loop_objectives ({_e})")
    _TOOLS_META_OBJ = {}

_ANALYSIS_VULN_TOOLS: frozenset[str] = frozenset(
    _TOOLS_META_OBJ.get("analysis_phase_vuln_tools", [])
)


def _normalize_signal_term(term: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(term or "").lower()).strip("_")


def _indicator_pattern(indicators: list[str]) -> re.Pattern | None:
    terms: list[str] = []
    for indicator in indicators:
        indicator = str(indicator).strip()
        if not indicator:
            continue
        escaped = re.escape(indicator).replace(r"\ ", r"[_ ]+")
        if indicator[:1].isalnum() and indicator[-1:].isalnum():
            escaped = rf"\b{escaped}\b"
        terms.append(escaped)
    if not terms:
        return None
    try:
        return re.compile(r"(?i)(?:" + "|".join(dict.fromkeys(terms)) + r")")
    except re.error:
        return None

def _resolve_vuln_labels(name: str, indicators: list[str] | None = None) -> list[str]:
    classifier = get_classifier()
    labels: set[str] = set()
    raw_name = str(name or "").replace("hypothesis_", "").replace("_", " ").strip()
    if raw_name:
        labels.update(classifier.resolve_labels(raw_name))
        result = classifier.classify(raw_name)
        if result.category != "UNKNOWN":
            labels.add(result.category)
        if result.subcategory:
            labels.add(result.subcategory)
    for indicator in indicators or []:
        labels.update(classifier.resolve_labels(str(indicator)))
        result = classifier.classify(str(indicator))
        if result.category != "UNKNOWN":
            labels.add(result.category)
        if result.subcategory:
            labels.add(result.subcategory)
    return sorted(label for label in labels if label and label != "UNKNOWN")


def _choose_confirm_tool(vuln_name: str, indicators: list[str]) -> str:
    descriptions = _TOOLS_META_OBJ.get("tool_descriptions", {})
    if not isinstance(descriptions, dict) or not descriptions:
        return "manual_probe"

    indicator_terms = [
        str(ind).strip().lower()
        for ind in indicators
        if str(ind).strip() and len(str(ind).strip()) >= 3
    ]
    name_terms = [
        t
        for t in {
            str(vuln_name or "").replace("hypothesis_", "").replace("_", " ").lower(),
            *indicator_terms[:6],
        }
        if t
    ]

    best_tool = "manual_probe"
    best_score = 0
    for tool_name, description in descriptions.items():
        haystack = f"{tool_name} {description}".lower()
        score = 0
        for term in name_terms:
            if term and term in haystack:
                score += 2
        if score > best_score:
            best_tool = str(tool_name).lower()
            best_score = score
    return best_tool if best_score > 0 else "manual_probe"


def _load_exploit_heavy_tools() -> frozenset[str]:
    try:
        path = Path(__file__).parent.parent / "data" / "tools_meta.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        tools = data.get("tool_classifications", {}).get("exploit_heavy_tools", [])
        return frozenset(str(t).strip().lower() for t in tools if str(t).strip())
    except Exception as e:
        logger.warning("Failed to load exploit_heavy_tools from JSON: %s", e)
        return frozenset()


_PHASE_PROMPTS_DIR = Path(__file__).parent.parent / "prompts" / "phases"


def _load_phase_objectives() -> dict[str, list[str]]:
    objectives: dict[str, list[str]] = {}
    if not _PHASE_PROMPTS_DIR.exists():
        return objectives

    for phase_file in _PHASE_PROMPTS_DIR.glob("*.txt"):
        phase_name = phase_file.stem.upper()
        try:
            content = phase_file.read_text(encoding="utf-8")
            lines = [line.strip() for line in content.splitlines() if line.strip()]
            obj_start = 0
            for i, line in enumerate(lines):
                if line.startswith("OBJECTIVE:") or line.startswith("DIRECTIVE:"):
                    obj_start = i + 1
                    break

            objs = []
            for line in lines[obj_start:obj_start+12]:
                if line.startswith("<") or line.startswith("[") or not line:
                    continue
                cleaned = line.lstrip("0123456789.-• ").strip()
                if cleaned and len(cleaned) > 20:
                    objs.append(cleaned)
                if len(objs) >= 6:
                    break

            if objs:
                objectives[phase_name] = objs
        except Exception as e:
            logger.debug("Failed to load phase objectives from %s: %s", phase_file.name, e)

    return objectives


def _build_vuln_hypo_index() -> list[dict[str, Any]]:
    raw_hypotheses = load_vuln_hypothesis_legacy()
    if not raw_hypotheses:
        return []

    index: list[dict[str, Any]] = []
    for entry in raw_hypotheses:
        indicators = {
            str(ind).strip().lower()
            for ind in (entry.get("patterns") or entry.get("indicators", []))
            if str(ind).strip()
        }
        if not indicators:
            continue
        index.append(
            {
                "key": entry.get("type", entry.get("name", "unknown")),
                "indicators": indicators,
                "description": str(entry.get("description", "")),
                "suggested_actions": entry.get("actions", entry.get("suggested_actions", [])),
            }
        )
    return index


class _ObjectivesMixin:
    _vuln_hypo_index: list[dict[str, Any]] = _build_vuln_hypo_index()

    _PHASE_OBJECTIVES: dict[str, list[str]] = _load_phase_objectives()
    _EXPLOIT_HEAVY_TOOLS: frozenset[str] = _load_exploit_heavy_tools()

    def _get_current_phase(self) -> PipelinePhase:
        if self.pipeline:
            return self.pipeline.get_current_phase()
        return PipelinePhase.RECON

    def _dynamic_phase_objectives(self, phase: PipelinePhase) -> list[str]:
        s = self._session
        if not s:
            return []

        dynamic: list[str] = []
        if phase == PipelinePhase.RECON:
            if s.subdomains and not s.live_hosts:
                dynamic.append(
                    "Validate liveness for newly discovered subdomains before deeper scans"
                )
            if s.open_ports:
                high_value_ports = sorted(
                    {
                        int(p)
                        for ports in s.open_ports.values()
                        for p in ports
                        if isinstance(p, int) and p not in (80, 443)
                    }
                )[:4]
                if high_value_ports:
                    dynamic.append(
                        f"Map HTTP/services on non-standard ports: {', '.join(str(p) for p in high_value_ports)}"
                    )

        elif phase == PipelinePhase.ANALYSIS:
            hints = {
                str(pt.get("type_hint", "")).upper()
                for pt in s.injection_points
                if pt.get("type_hint")
            }
            if "IDOR" in hints:
                dynamic.append(
                    "Correlate object IDs across endpoints for horizontal/vertical privilege abuse"
                )
            if "SSRF" in hints:
                dynamic.append(
                    "Validate SSRF impact against internal metadata and localhost surfaces"
                )
            if "OPEN_REDIRECT" in hints:
                dynamic.append(
                    "Differentiate open redirect from SSRF and confirm redirect-chain impact"
                )
            if s.technologies:
                top_techs = ", ".join(list(s.technologies.keys())[:3])
                dynamic.append(
                    f"Prioritize stack-specific checks for detected technologies: {top_techs}"
                )

        elif phase == PipelinePhase.EXPLOIT:
            if s.waf_profiles:
                dynamic.append(
                    "Apply WAF-specific evasion strategy per host and compare blocked vs bypassed responses"
                )
            pending_hyp = self.state.get_pending_hypotheses(max_items=1)
            if pending_hyp:
                hyp = pending_hyp[0]
                dynamic.append(
                    f"Resolve top hypothesis [{hyp.get('id', 'h')}] with a concrete confirm/refute test"
                )
            if s.vulnerabilities and not any(
                v.get("report_generated") for v in s.vulnerabilities
            ):
                dynamic.append(
                    "Convert highest-severity confirmed exploit into reproducible PoC evidence"
                )
            if s.injection_points:
                dynamic.append(
                    "Test all discovered injection points with targeted payloads"
                )
            if s.technologies:
                dynamic.append(
                    "Research and test version-specific exploits for detected technologies"
                )

        elif phase == PipelinePhase.REPORT:
            unreported = [v for v in s.vulnerabilities if not v.get("report_generated")]
            if unreported:
                dynamic.append(
                    f"Generate reports for all unreported confirmed findings ({len(unreported)} remaining)"
                )

        return dynamic[:4]

    def _sync_phase_objectives(self, phase: PipelinePhase) -> None:
        defaults = self._PHASE_OBJECTIVES.get(phase.value, [])
        dynamic = self._dynamic_phase_objectives(phase)
        merged = defaults + [d for d in dynamic if d not in defaults]
        self.state.ensure_phase_objectives(phase.value, merged)

    def _update_objectives_from_session(self, phase: PipelinePhase) -> None:
        if not self._session:
            return
        defaults = self._PHASE_OBJECTIVES.get(phase.value, [])
        if len(defaults) < 3:
            return

        s = self._session
        if phase == PipelinePhase.RECON:
            if s.subdomains or s.live_hosts:
                self.state.mark_objective(phase.value, defaults[0], "done")

            if s.live_hosts and len(defaults) > 1:
                self.state.mark_objective(phase.value, defaults[1], "done")

            if s.open_ports and len(defaults) > 2:
                self.state.mark_objective(phase.value, defaults[2], "done")

            if s.urls and len(defaults) > 3:
                self.state.mark_objective(phase.value, defaults[3], "done")

            if s.scan_count >= 3 and len(defaults) > 4:
                self.state.mark_objective(phase.value, defaults[4], "done")
        elif phase == PipelinePhase.ANALYSIS:
            if s.technologies or s.urls:
                self.state.mark_objective(phase.value, defaults[0], "done")
            if s.injection_points:
                self.state.mark_objective(phase.value, defaults[1], "done")
            if s.vulnerabilities or len(self.state.evidence_log) >= 3:
                self.state.mark_objective(phase.value, defaults[2], "done")
        elif phase == PipelinePhase.EXPLOIT:
            _vuln_blob = " ".join(
                " ".join(
                    [
                        str(v.get("finding", "")),
                        str(v.get("title", "")),
                        str(v.get("proo", "")),
                        str(v.get("evidence", "")),
                        str(v.get("url", "")),
                        str(v.get("endpoint", "")),
                    ]
                )
                for v in s.vulnerabilities
            )
            _ev_blob = " ".join(
                str(e.get("summary", "")) for e in self.state.evidence_log
            )
            _combined = f"{_vuln_blob}\n{_ev_blob}"

            def _has(pat: str) -> bool:
                return bool(re.search(pat, _combined, re.IGNORECASE))

            if (
                s.urls
                or s.tested_endpoints
                or _has(r"https?://|/(api|admin|login|dashboard|register)\b")
            ) and len(defaults) > 0:
                self.state.mark_objective(phase.value, defaults[0], "done")

            if (
                _has(
                    r"\b(login\s+success|authenticated|401|403|token|session|cookie|default\s+cred|weak\s+pass|brute)\b"
                )
                and len(defaults) > 1
            ):
                self.state.mark_objective(phase.value, defaults[1], "done")

            if (
                _has(
                    r"\b(idor|bola|broken\s+access|access\s+control|forbidden|unauthorized|privilege\s+escalation|horizontal|vertical)\b"
                )
                and len(defaults) > 2
            ):
                self.state.mark_objective(phase.value, defaults[2], "done")

            if (
                _has(
                    r"\b(sqli|sql\s+injection|xss|ssti|ssrf|xxe|rce|command\s+injection|lfi|rfi|union\s+select|sleep\s*\(|<script|onerror=)\b"
                )
                and len(defaults) > 3
            ):
                self.state.mark_objective(phase.value, defaults[3], "done")

            if (
                any(
                    v.get("flag")
                    or v.get("proo")
                    or v.get("evidence")
                    or v.get("poc_script_code")
                    for v in s.vulnerabilities
                )
                or _has(
                    r"\b(flag\{[^}\n]+\}|credential|secret|token|api[_-]?key|database\s+dump|exfiltrat|unauthorized\s+data|admin\s+access|read\s+/etc/passwd)\b"
                )
            ) and len(defaults) > 4:
                self.state.mark_objective(phase.value, defaults[4], "done")
        elif phase == PipelinePhase.REPORT:
            if any(v.get("report_generated") for v in s.vulnerabilities):
                self.state.mark_objective(phase.value, defaults[0], "done")
            if s.vulnerabilities:
                self.state.mark_objective(phase.value, defaults[1], "done")
            if "REPORT" in s.completed_phases:
                self.state.mark_objective(phase.value, defaults[2], "done")

    def _update_objectives_from_tool(
        self,
        phase: PipelinePhase,
        tool_name: str,
        arguments: dict[str, Any],
        success: bool,
        result: dict[str, Any],
        output_file: str | None,
    ) -> None:
        if not success:
            return
        defaults = self._PHASE_OBJECTIVES.get(phase.value, [])
        if len(defaults) < 3:
            return

        cmd = ""
        if tool_name == "execute":
            cmd = str(arguments.get("command", "")).lower()

        if phase == PipelinePhase.RECON:
            _subdomain_hit = (
                cmd and any(b in cmd for b in _RECON_SUBDOMAIN_BINS)
            ) or tool_name in ("web_search", "browser_action")
            if _subdomain_hit:
                self.state.mark_objective(phase.value, defaults[0], "done")

            if (
                cmd
                and any(b in cmd for b in _RECON_LIVE_HOST_BINS)
                and len(defaults) > 1
            ):
                self.state.mark_objective(phase.value, defaults[1], "done")

            if (
                cmd
                and any(b in cmd for b in _RECON_PORT_SCAN_BINS)
                and len(defaults) > 2
            ):
                self.state.mark_objective(phase.value, defaults[2], "done")

            _crawl_hit = (
                cmd and any(b in cmd for b in _RECON_CONTENT_DISCOVERY_BINS)
            ) or (
                output_file
                and output_file.startswith("output/")
                and re.search(r"url|endpoint|path|dir", output_file, re.IGNORECASE)
            )
            if _crawl_hit and len(defaults) > 3:
                self.state.mark_objective(phase.value, defaults[3], "done")

            if output_file and output_file.startswith("output/") and len(defaults) > 4:
                self.state.mark_objective(phase.value, defaults[4], "done")

        elif phase == PipelinePhase.ANALYSIS:
            _result_text = self._extract_result_text(result)
            _has_tech_evidence = bool(
                re.search(
                    r"\b(apache|nginx|iis|php|python|django|flask|express|rails|laravel|"
                    r"wordpress|drupal|joomla|jquery|react|angular|vue|spring|struts|"
                    r"server:|x-powered-by|content-type:|location:|set-cookie:)\b",
                    _result_text,
                    re.IGNORECASE,
                )
            ) or bool(
                self._session and (self._session.technologies or self._session.urls)
            )
            if tool_name in ("read_file", "browser_action", "web_search") or (
                tool_name == "execute" and _has_tech_evidence
            ):
                self.state.mark_objective(phase.value, defaults[0], "done")

            if cmd and any(hint in cmd for hint in _ANALYSIS_VULN_TOOLS):
                self.state.mark_objective(phase.value, defaults[1], "done")

            meaningful_ev = [
                e
                for e in self.state.evidence_log
                if float(e.get("confidence", 0)) >= 0.65
            ]
            if len(meaningful_ev) >= 2:
                self.state.mark_objective(phase.value, defaults[2], "done")

        elif phase == PipelinePhase.EXPLOIT:
            result_text = self._extract_result_text(result)

            _enum_hit = tool_name in self._EXPLOIT_HEAVY_TOOLS or (
                tool_name == "execute"
                and bool(
                    re.search(
                        r"(GET|POST|PUT|DELETE|PATCH)\s+/|status[:\s]+\d{3}|https?://",
                        result_text,
                        re.IGNORECASE,
                    )
                )
            )
            if _enum_hit:
                self.state.mark_objective(phase.value, defaults[0], "done")

            _auth_patterns = _get_objective_regex("authentication")
            _auth_hit = (
                any(p.search(result_text) for p in _auth_patterns)
                if _auth_patterns
                else bool(
                    re.search(
                        r"(FLAG\{[^}\n]+\}|CVE-\d{4}-\d+|"
                        r"login\s+success|authenticated|access\s+denied|"
                        r"401|403|session\s+creat|token\s+issued|cookie)",
                        result_text,
                        re.IGNORECASE,
                    )
                )
            )
            if _auth_hit and len(defaults) > 1:
                self.state.mark_objective(phase.value, defaults[1], "done")

            _authz_patterns = _get_objective_regex("authorization")
            _authz_hit = (
                any(p.search(result_text) for p in _authz_patterns)
                if _authz_patterns
                else bool(
                    re.search(
                        r"(idor|bola|broken\s+access|access\s+control|forbidden|unauthorized|"
                        r"privilege\s+escalation|horizontal|vertical)",
                        result_text,
                        re.IGNORECASE,
                    )
                )
            )
            if _authz_hit and len(defaults) > 2:
                self.state.mark_objective(phase.value, defaults[2], "done")

            _inject_patterns = _get_objective_regex("injection")
            _inject_hit = (
                any(p.search(result_text) for p in _inject_patterns)
                if _inject_patterns
                else (
                    bool(
                        re.search(
                            r"(sqli|sql\s+injection|xss|ssti|command\s+injection|"
                            r"ssrf|xxe|lfi|rfi|union\s+select|sleep\s*\(|"
                            r"<script|onerror=|alert\s*\(|\{\{.*\}\}|%27|'--)",
                            result_text,
                            re.IGNORECASE,
                        )
                    )
                    or tool_name in self._EXPLOIT_HEAVY_TOOLS
                )
            )
            if _inject_hit and len(defaults) > 3:
                self.state.mark_objective(phase.value, defaults[3], "done")

            _impact_hit = bool(
                re.search(
                    r"(FLAG\{[^}\n]+\}|credential|secret|api[_-]?key|database\s+dump|"
                    r"exfiltrat|unauthorized\s+data|admin\s+access|read\s+/etc/passwd)",
                    result_text,
                    re.IGNORECASE,
                )
            ) or bool(
                output_file
                and re.search(
                    r"(proof|poc|dump|credential|secret|flag)",
                    output_file,
                    re.IGNORECASE,
                )
            )
            if _impact_hit and len(defaults) > 4:
                self.state.mark_objective(phase.value, defaults[4], "done")

        elif phase == PipelinePhase.REPORT:
            result_text = self._extract_result_text(result)
            _note_tools = {
                "create_note",
                "list_notes",
                "search_notes",
                "read_note",
                "export_notes_wiki",
            }
            _is_note_tool = tool_name in _note_tools
            _is_report_tool = tool_name == "create_vulnerability_report"
            _has_report_marker = bool(
                isinstance(result, dict)
                and (
                    result.get("artifact_type") == "vulnerability_report"
                    or result.get("report_generated") is True
                )
            )
            _has_report_content = bool(
                (not _is_note_tool)
                and re.search(
                    r"\b(vulnerability report|executive summary|CVSS|severity[:\s]|"
                    r"remediation|proof.of.concept|PoC|report generated|report written|"
                    r"risk rating|findings? documented)\b",
                    result_text,
                    re.IGNORECASE,
                )
            )
            _is_report_output = bool(
                output_file
                and (
                    "/vulnerabilities/" in output_file.replace("\\", "/")
                    or output_file.replace("\\", "/").startswith("vulnerabilities/")
                )
            )
            if (
                (_is_report_tool and not _is_note_tool)
                or _has_report_marker
                or _has_report_content
                or _is_report_output
            ):
                self.state.mark_objective(phase.value, defaults[0], "done")
                self.state.mark_objective(phase.value, defaults[1], "done")
            if output_file and output_file.startswith("output/"):
                self.state.mark_objective(phase.value, defaults[2], "done")

    def _extract_result_text(self, result: dict[str, Any] | Any) -> str:
        if result is None:
            return ""
        if isinstance(result, str):
            return result
        if not isinstance(result, dict):
            return str(result)

        parts: list[str] = []
        for key in (
            "stdout",
            "stderr",
            "result",
            "summary",
            "error",
            "message",
            "note",
            "findings",
        ):
            value = result.get(key)
            if isinstance(value, str):
                parts.append(value)
            elif isinstance(value, list):
                list_lines = [str(x) for x in value[:8]]
                if list_lines:
                    parts.append("\n".join(list_lines))
            elif isinstance(value, dict):
                for sub_key in ("summary", "result", "error", "message", "note"):
                    sub_val = value.get(sub_key)
                    if isinstance(sub_val, str):
                        parts.append(sub_val)
        merged = "\n".join(p for p in parts if p).strip()
        return merged[:7000]

    def _enrich_evidence(
        self,
        summary: str,
        base_tags: list[str],
        confidence: float,
        tool_name: str,
    ) -> tuple[list[str], int]:
        owasp_tags = classify_owasp(summary, base_tags, tool_name)
        enriched_tags = list(dict.fromkeys(base_tags + owasp_tags))
        sev = severity_for_evidence(summary, enriched_tags, confidence, tool_name)
        return enriched_tags, sev

    def _record_evidence_from_result(
        self,
        phase: str,
        tool_name: str,
        arguments: dict[str, Any],
        result: dict[str, Any],
        success: bool,
        output_file: str | None,
    ) -> None:
        if output_file:
            _t, _s = self._enrich_evidence(
                f"Artifact saved to {output_file}", ["artifact", "file"], 0.9, tool_name
            )
            self.state.add_evidence(
                phase=phase,
                source_tool=tool_name,
                summary=f"Artifact saved to {output_file}",
                confidence=0.9,
                artifact=output_file,
                tags=_t,
                severity=_s,
            )

        blob = self._extract_result_text(result)
        if not blob:
            return

        if not success:
            err = (
                str(result.get("error", "")).strip() if isinstance(result, dict) else ""
            )
            if err:
                _summary = f"Execution error observed: {err[:240]}"
                _t, _s = self._enrich_evidence(_summary, ["error"], 0.4, tool_name)
                self.state.add_evidence(
                    phase=phase,
                    source_tool=tool_name,
                    summary=_summary,
                    confidence=0.4,
                    tags=_t,
                    severity=_s,
                )
            return

        for flag in re.findall(r"(?:FLAG|flag)\{[^}\n]{1,200}\}", blob):
            _summary = f"Flag pattern captured: {flag}"
            _t, _s = self._enrich_evidence(_summary, ["flag", "ct"], 1.0, tool_name)
            self.state.add_evidence(
                phase=phase,
                source_tool=tool_name,
                summary=_summary,
                confidence=1.0,
                tags=_t,
                severity=_s,
            )

            try:
                from .correlation_engine import get_correlation_engine
                engine = get_correlation_engine()
                engine.add_finding(
                    vuln_class="flag_capture",
                    severity=_s,
                    confidence=1.0,
                    endpoint="",
                    parameter="",
                    description=_summary,
                )
            except Exception as _corr_err:
                logger.debug("Continuous correlation failed: %s", _corr_err)

        for cve in re.findall(r"CVE-\d{4}-\d{4,7}", blob, re.IGNORECASE):
            _summary = f"CVE reference discovered: {cve.upper()}"
            _t, _s = self._enrich_evidence(
                _summary, ["cve", "vulnerability"], 0.75, tool_name
            )
            self.state.add_evidence(
                phase=phase,
                source_tool=tool_name,
                summary=_summary,
                confidence=0.75,
                tags=_t,
                severity=_s,
            )

        url_matches = list(
            dict.fromkeys(re.findall(r"https?://[^\s\"'<>]+", blob, re.IGNORECASE))
        )

        _target_domain: str = ""
        if self._session and self._session.target:
            import urllib.parse as _up

            _parsed = _up.urlparse(
                self._session.target
                if "://" in self._session.target
                else f"http://{self._session.target}"
            )
            _host = _parsed.hostname or ""

            _parts = _host.split(".")
            _target_domain = ".".join(_parts[-2:]) if len(_parts) >= 2 else _host

        in_scope_urls: list[str] = []
        if _target_domain:
            import urllib.parse as _up2

            for _u in url_matches:
                try:
                    _h = _up2.urlparse(_u).hostname or ""
                except Exception as _e:
                    logger.warning("Operation failed: %s", _e)
                    continue
                if _h.endswith(_target_domain):
                    in_scope_urls.append(_u)

        for url in in_scope_urls[:4]:
            _summary = f"Interesting URL collected: {url}"
            _t, _s = self._enrich_evidence(
                _summary, ["url", "endpoint"], 0.65, tool_name
            )
            self.state.add_evidence(
                phase=phase,
                source_tool=tool_name,
                summary=_summary,
                confidence=0.65,
                tags=_t,
                severity=_s,
            )

        _port_service_re = re.compile(
            r"\b(\d{1,5})/(tcp|udp)\s+open(?:\s+(\S+))?", re.IGNORECASE
        )
        _seen_ports: set[int] = set()
        for m in _port_service_re.finditer(blob):
            port_num = int(m.group(1))
            banner_service = (m.group(3) or "").lower().strip("?")
            if port_num in _seen_ports or len(_seen_ports) >= 6:
                break
            _seen_ports.add(port_num)

            corr = PORT_CORRELATIONS.get(port_num, {})
            service_name = corr.get("service") or banner_service or f"port {port_num}"
            vuln_list: list[str] = corr.get("vulns", [])
            top_vulns = "; ".join(vuln_list[:3]) if vuln_list else ""

            _summary = (
                f"Open port {port_num}/{m.group(2)} ({service_name})"
                + (f" — known attack surface: {top_vulns}" if top_vulns else "")
            )
            _t, _s = self._enrich_evidence(
                _summary, ["network", "recon", service_name.lower()], 0.75, tool_name
            )
            self.state.add_evidence(
                phase=phase,
                source_tool=tool_name,
                summary=_summary,
                confidence=0.75,
                tags=_t,
                severity=_s,
            )

            if corr and vuln_list:
                suggested_tools = corr.get("tools", [])
                first_tool = suggested_tools[0] if suggested_tools else f"nmap -sV -p {port_num}"
                self.state.add_hypothesis(
                    claim=(
                        f"Port {port_num} ({service_name}) is open — "
                        f"test for: {'; '.join(vuln_list[:4])}"
                    ),
                    test_plan=(
                        f"Start with: {first_tool}. "
                        "Check service version against CVE database. "
                        f"Test attack surface: {top_vulns}."
                    ),
                    phase=phase,
                    tags=["network", service_name.lower(), "service-inference"],
                )

        _raw_port_re = re.compile(
            r"\b\d{1,5}/(?:tcp|udp)\b|\b(?:\d{1,3}\.){3}\d{1,3}:\d{1,5}\b",
            re.IGNORECASE,
        )
        for hit in list(dict.fromkeys(_raw_port_re.findall(blob)))[:4]:
            port_str = re.search(r"\d+", hit)
            if port_str and int(port_str.group()) in _seen_ports:
                continue
            _summary = f"Service/port evidence: {hit}"
            _t, _s = self._enrich_evidence(
                _summary, ["network", "recon"], 0.65, tool_name
            )
            self.state.add_evidence(
                phase=phase,
                source_tool=tool_name,
                summary=_summary,
                confidence=0.65,
                tags=_t,
                severity=_s,
            )

        high_signal_lines = []
        signal_re = re.compile(
            r"(?i)(vulnerab|injection|xss|sqli|idor|ssrf|rce|auth bypass|token|secret|credential)"
        )

        _FALSE_SIGNAL_RE = re.compile(
            r"(?i)\b("
            r"0\s+vuln|no\s+vuln|not\s+vuln|no\s+injection|not\s+found|not\s+detected|"
            r"no\s+xss|no\s+sqli|no\s+idor|no\s+ssrf|no\s+rce|"
            r"testing\s+for|checking\s+for|scanning\s+for|looking\s+for|"
            r"test(?:ing)?\s+(?:xss|sqli|injection|vulnerability)|"
            r"attempt(?:ing)?\s+to|trying\s+to|will\s+test|starting\s+test|"
            r"no\s+result|0\s+result|nothing\s+found"
            r")\b"
        )
        for line in blob.splitlines():
            line = line.strip()
            if not line or len(line) < 12:
                continue
            if signal_re.search(line) and not _FALSE_SIGNAL_RE.search(line):
                high_signal_lines.append(line[:260])
            if len(high_signal_lines) >= 3:
                break
        for line in high_signal_lines:
            _summary = f"Security signal: {line}"

            _t, _s = self._enrich_evidence(_summary, ["signal"], 0.6, tool_name)
            self.state.add_evidence(
                phase=phase,
                source_tool=tool_name,
                summary=_summary,
                confidence=0.6,
                tags=_t,
                severity=_s,
            )

        if tool_name == "execute":
            cmd = str(arguments.get("command", "")).strip()
            if cmd:
                _summary = f"Executed command: {cmd[:220]}"
                _t, _s = self._enrich_evidence(
                    _summary, ["execution", "trace"], 0.55, tool_name
                )
                self.state.add_evidence(
                    phase=phase,
                    source_tool=tool_name,
                    summary=_summary,
                    confidence=0.55,
                    tags=_t,
                    severity=_s,
                )

        if self._session and getattr(self._session, "app_model", None):
            observed_endpoint = str(
                arguments.get("url")
                or arguments.get("endpoint")
                or arguments.get("path")
                or arguments.get("target")
                or ""
            ).strip()
            observed_params = [
                key
                for key in arguments.keys()
                if key
                not in {
                    "command",
                    "url",
                    "endpoint",
                    "path",
                    "target",
                    "body",
                    "data",
                    "headers",
                    "cookies",
                }
            ]
            try:
                self._session.app_model.record_text_signal(
                    blob,
                    endpoint=observed_endpoint,
                    param_names=observed_params,
                    auth_type=getattr(self._session, "auth_type", ""),
                    method=str(arguments.get("method", tool_name)).upper(),
                )
            except Exception as _model_err:
                logger.debug("Application model signal ingest failed: %s", _model_err)

        if success:
            self._auto_form_hypotheses(phase, tool_name, arguments, blob)

        self._check_evidence_corroboration(phase, tool_name)

    def _check_evidence_corroboration(self, phase: str, current_tool: str) -> None:
        if not self.state or len(self.state.evidence_log) < 2:
            return

        tag_tools: dict[str, set[str]] = {}
        for ev in self.state.evidence_log[-40:]:
            src = str(ev.get("source_tool", "")).strip()
            for tag in ev.get("tags", []):
                tag_str = str(tag).strip().lower()
                if tag_str and len(tag_str) >= 4 and tag_str not in (
                    "artifact", "file", "error", "recon", "trace", "network",
                    "signal", "url", "endpoint", "execution",
                ):
                    tag_tools.setdefault(tag_str, set()).add(src)

        _already_noted: set[str] = getattr(self, "_corroborated_tags", set())
        for tag, tools in tag_tools.items():
            if len(tools) >= 2 and tag not in _already_noted:
                _already_noted.add(tag)
                _tools_str = ", ".join(sorted(tools)[:3])
                self.state.add_evidence(
                    phase=phase,
                    source_tool=current_tool,
                    summary=(
                        f"CORROBORATED: '{tag}' signal independently seen from "
                        f"{len(tools)} different tool(s): {_tools_str}"
                    ),
                    confidence=0.88,
                    tags=[tag, "corroborated", "multi-source"],
                    severity=3,
                )
                logger.info(
                    "Evidence corroboration: tag=%r across tools=%s",
                    tag,
                    _tools_str,
                )

        self._corroborated_tags = _already_noted  # type: ignore[attr-defined]

    def _verify_confirmed_hypotheses(self) -> list[str]:
        if not self.state:
            return []
        queue = getattr(self.state, "hypothesis_queue", None) or []
        evidence_log = getattr(self.state, "evidence_log", None) or []
        if not queue or not evidence_log:
            return []

        newly_verified: list[str] = []
        _already: set[str] = getattr(self, "_verified_hyp_ids", set())

        for hyp in queue:
            if str(hyp.get("status", "")) != "confirmed":
                continue
            hid = str(hyp.get("id", "")).strip()
            if not hid or hid in _already:
                continue
            if bool(hyp.get("verified")):
                _already.add(hid)
                continue

            claim_lower = str(hyp.get("claim", "")).lower()
            hyp_tags = {str(t).lower() for t in hyp.get("tags", []) if str(t).strip()}
            claim_keywords = {
                w.strip(".,;:!?()[]{}\"'")
                for w in claim_lower.split()
                if len(w) >= 5
                and w not in {"about", "which", "there", "their", "these", "those"}
            }

            supporting_tools: set[str] = set()
            for ev in evidence_log[-80:]:
                if float(ev.get("confidence", 0.0)) < 0.65:
                    continue
                ev_summary = str(ev.get("summary", "")).lower()
                ev_tags = {str(t).lower() for t in ev.get("tags", [])}
                ev_tool = str(ev.get("source_tool", "")).strip().lower()
                if not ev_tool or ev_tool == "corroborated":
                    continue

                tag_overlap = bool(claim_keywords & {t for t in ev_tags if len(t) >= 4})
                tag_shared = bool(hyp_tags & ev_tags)
                keyword_overlap = (
                    len(claim_keywords & set(ev_summary.split())) >= 2
                )
                if tag_overlap or tag_shared or keyword_overlap:
                    supporting_tools.add(ev_tool)

            if len(supporting_tools) >= 2:
                hyp["verified"] = True
                hyp["verified_by"] = sorted(supporting_tools)[:5]
                newly_verified.append(hid)
                _already.add(hid)
                logger.info(
                    "Hypothesis %s verified by %d independent tools: %s",
                    hid,
                    len(supporting_tools),
                    ", ".join(sorted(supporting_tools)),
                )

        if newly_verified:
            self._verified_hyp_ids = _already  # type: ignore[attr-defined]
        return newly_verified

    def _build_verification_note(self, verified_ids: list[str]) -> str:
        if not verified_ids:
            return ""
        queue = getattr(self.state, "hypothesis_queue", None) or []
        lookup = {str(h.get("id", "")): h for h in queue}
        lines = ["[VERIFICATION — cross-tool independent evidence]"]
        for hid in verified_ids[:3]:
            h = lookup.get(hid)
            if not h:
                continue
            claim = str(h.get("claim", ""))[:140]
            tools = ", ".join(h.get("verified_by", [])[:4])
            lines.append(f"  • {hid}: {claim}")
            lines.append(f"      backed by: {tools}")
        lines.append(
            "These claims are backed by evidence from multiple independent "
            "tools. Promote them to a full report with reproducible PoC, or "
            "refute if re-examination shows the overlap is coincidental. Do "
            "not stop at the verification — produce the artefact."
        )
        return "\n".join(lines)

    @staticmethod
    def _load_vuln_hypo_index() -> list[dict[str, Any]]:
        _patterns_path = Path(__file__).parent.parent / "data" / "patterns.json"
        if not _patterns_path.exists():
            return []
        try:
            with open(_patterns_path) as _pf:
                _raw: dict[str, dict[str, Any]] = json.load(_pf)
        except (json.JSONDecodeError, OSError):
            return []

        index: list[dict[str, Any]] = []
        for key, entry in _raw.items():
            indicators = {
                str(ind).strip().lower()
                for ind in (entry.get("indicators") or [])
                if str(ind).strip()
            }
            if not indicators:
                continue
            index.append(
                {
                    "key": key,
                    "indicators": indicators,
                    "description": str(entry.get("description", "")),
                    "suggested_actions": entry.get("suggested_actions", []),
                }
            )
        return index

    _vuln_hypo_index: list[dict[str, Any]] = []

    _HYPO_FALSE_SIGNAL_RE = re.compile(
        r"(?i)\b("
        r"testing\s+for|checking\s+for|scanning\s+for|looking\s+for|"
        r"no\s+vuln|0\s+vuln|not\s+vuln|not\s+found|not\s+detected|"
        r"no\s+xss|no\s+sqli|no\s+idor|no\s+ssrf|no\s+rce|no\s+injection|"
        r"attempt(?:ing)?\s+to|trying\s+to|will\s+test|starting\s+test|"
        r"nothing\s+found|no\s+result|0\s+result"
        r")\b"
    )

    @staticmethod
    def _load_vuln_hypo_patterns() -> list[tuple[re.Pattern, str, str]]:
        patterns: list[tuple[re.Pattern, str, str]] = []

        try:
            for entry in load_vuln_hypothesis_legacy():
                indicators = [
                    str(ind).strip()
                    for ind in (entry.get("patterns") or entry.get("indicators", []))
                    if str(ind).strip()
                ]
                if not indicators:
                    continue
                vuln_type = (
                    str(entry.get("type", entry.get("name", "")))
                    .strip()
                    .lower()
                    .replace("-", "_")
                )
                if vuln_type.startswith("hypothesis_"):
                    vuln_type = vuln_type[len("hypothesis_") :]
                if not vuln_type:
                    continue
                pattern = _indicator_pattern(indicators)
                if pattern is None:
                    continue
                confirm_tool = _choose_confirm_tool(vuln_type, indicators)
                patterns.append((pattern, vuln_type, confirm_tool))
        except Exception as exc:
            logger.debug("Failed to load hypothesis patterns from unified catalog: %s", exc)

        try:
            prompt_path = Path(__file__).parent.parent / "prompts" / "system.txt"
            if prompt_path.exists():
                content = prompt_path.read_text(encoding="utf-8")
                in_section = False
                for line in content.splitlines():
                    if "§12" in line or "VULNERABILITY PRIORITY" in line:
                        in_section = True
                        continue
                    if in_section:
                        if line.startswith("━") or (
                            line.strip().startswith("§") and "§12" not in line
                        ):
                            break
                        if (
                            "P1" in line
                            or "P2" in line
                            or "P3" in line
                            or "P4" in line
                            or "P5" in line
                        ):
                            parts = line.split("  ", 1)
                            if len(parts) > 1:
                                raw_terms = parts[1]
                                for term in raw_terms.split(","):
                                    term = term.strip().split("(")[0].strip()
                                    if (
                                        term
                                        and len(term) >= 3
                                        and term.lower()
                                        not in (
                                            "and",
                                            "or",
                                            "the",
                                        )
                                    ):
                                        vuln_type = term.lower().replace(" ", "_")
                                        _pat = _indicator_pattern([term])
                                        if _pat is not None:
                                            _labels = _resolve_vuln_labels(
                                                vuln_type, [term]
                                            )
                                            _confirm = _choose_confirm_tool(
                                                vuln_type, [term, *_labels]
                                            )
                                            patterns.append(
                                                (_pat, vuln_type, _confirm)
                                            )
        except Exception as exc:
            logger.debug("Failed to load hypothesis patterns from system prompt: %s", exc)

        try:
            skills_dir = Path(__file__).parent.parent / "skills" / "vulnerabilities"
            if skills_dir.is_dir():
                for md_file in skills_dir.iterdir():
                    if md_file.suffix == ".md":
                        vuln_type = md_file.stem.lower().replace("-", "_")
                        _term = md_file.stem.replace("-", " ").replace("_", " ")
                        _pat = _indicator_pattern([_term])
                        if _pat is not None:
                            _labels = _resolve_vuln_labels(vuln_type, [_term])
                            _confirm = _choose_confirm_tool(
                                vuln_type, [_term, *_labels]
                            )
                            patterns.append((_pat, vuln_type, _confirm))
        except Exception as exc:
            logger.debug("Failed to load hypothesis patterns from skills catalog: %s", exc)

        return patterns

    _cached_vuln_hypo_patterns: list[tuple[re.Pattern, str, str]] | None = None

    @property
    def _VULN_HYPO_PATTERNS(self) -> list[tuple[re.Pattern, str, str]]:
        if self.__class__._cached_vuln_hypo_patterns is None:
            self.__class__._cached_vuln_hypo_patterns = self._load_vuln_hypo_patterns()
        return self.__class__._cached_vuln_hypo_patterns

    def _auto_form_hypotheses(
        self,
        phase: str,
        tool_name: str,
        arguments: dict[str, Any],
        result_text: str,
    ) -> None:
        _MAX_HYPO_PER_CALL = 2
        formed = 0

        _cmd = str(arguments.get("command", "")) if tool_name == "execute" else ""
        _url_m = re.search(r"https?://[^\s\"'<>{}\[\]]+", _cmd or result_text)
        _endpoint = _url_m.group(0)[:80] if _url_m else "the target"

        for cve in re.findall(r"CVE-\d{4}-\d{4,7}", result_text, re.IGNORECASE):
            if formed >= _MAX_HYPO_PER_CALL:
                break
            _cve = cve.upper()
            self.state.add_hypothesis(
                claim=f"{_cve} is present and may be exploitable on this target",
                test_plan=(
                    f"Search for a public PoC for {_cve}. "
                    f"Run: nuclei -t cve/{_cve.lower()}.yaml "
                    f"or searchsploit {_cve}. "
                    "Verify exploitability against the installed version."
                ),
                phase=phase,
                tags=["cve", "vulnerability"],
            )
            formed += 1

        for _pat, _vuln_type, _confirm_tool in self._VULN_HYPO_PATTERNS:
            if formed >= _MAX_HYPO_PER_CALL:
                break
            if not _pat.search(result_text):
                continue
            if self._HYPO_FALSE_SIGNAL_RE.search(result_text):
                continue
            _label = _vuln_type.replace("_", " ").upper()
            self.state.add_hypothesis(
                claim=(f"Potential {_label} vulnerability detected near {_endpoint}"),
                test_plan=(
                    f"Use {_confirm_tool} to confirm. "
                    "Test all input parameters on the endpoint. "
                    "Look for error messages or behavioural differences "
                    "that distinguish positive from negative responses."
                ),
                phase=phase,
                tags=[_vuln_type, "needs_confirmation"],
            )
            formed += 1

            if phase == "RECON" and formed < _MAX_HYPO_PER_CALL:
                _port_hits = list(
                    dict.fromkeys(
                        re.findall(r"\b(\d{1,5})/open\b", result_text, re.IGNORECASE)
                    )
                )
                if _port_hits:
                    _ports_str = ", ".join(_port_hits[:3])
                    self.state.add_hypothesis(
                        claim=(
                            f"Open port(s) {_ports_str} may expose exploitable services"
                        ),
                        test_plan=(
                            f"Run: nmap -sV -sC -p {','.join(_port_hits[:3])} <target>. "
                            "Check service versions against CVE databases. "
                            "Test for default credentials and known exploits."
                        ),
                        phase=phase,
                        tags=["network", "service"],
                    )

    def _build_phase_gate_note(self, tool_name: str, success: bool) -> str:
        phase = self._get_current_phase()
        phase_name = phase.value
        phase_evidence = [
            e
            for e in self.state.evidence_log
            if str(e.get("phase", "")).upper() == phase_name
        ]
        cfg = get_config()
        explore_mode = self._cfg_bool(cfg, "agent_exploration_mode", True)
        intensity = self._cfg_float(cfg, "agent_exploration_intensity", 0.8)
        min_required_evidence = 1 if explore_mode and intensity >= 0.7 else 2

        if (
            phase in (PipelinePhase.RECON, PipelinePhase.ANALYSIS)
            and tool_name in self._EXPLOIT_HEAVY_TOOLS
            and len(phase_evidence) < min_required_evidence
        ):
            return (
                "[SYSTEM: PHASE GATE]\n"
                f"You used exploit-heavy tool '{tool_name}' while phase is {phase_name} "
                "with insufficient evidence.\n"
                "Before further exploitation, collect stronger artifacts first "
                "(live hosts, open ports, endpoints, injection points)."
            )

        if (
            phase == PipelinePhase.EXPLOIT
            and not success
            and self._consecutive_failures >= 2
        ):
            return (
                "[SYSTEM: PHASE GATE]\n"
                "Exploit attempts are failing repeatedly. Pivot strategy now:\n"
                "- Switch tool family (web -> network, or network -> browser)\n"
                "- Use evidence_log to choose a different vector\n"
                "- Avoid repeating same payload/command."
            )
        return ""

    def _check_tool_budget(self, tool_name: str, phase: str) -> str:
        is_exploit = phase.upper() == "EXPLOIT"
        _min_calls    = _BUDGET_EXPLOIT_MIN_CALLS  if is_exploit else _BUDGET_DEFAULT_MIN_CALLS
        _warn_thresh  = _BUDGET_EXPLOIT_THRESHOLD   if is_exploit else _BUDGET_DEFAULT_THRESHOLD

        eff = self.state.get_tool_effectiveness(phase, tool_name)
        calls    = int(eff.get("calls", 0.0))
        hit_rate = float(eff.get("hit_rate", 0.0))

        recent_evidence = len(self.state.evidence_log)
        evidence_exemption = recent_evidence >= _BUDGET_EVIDENCE_EXEMPTION

        budget = _PHASE_TOOL_BUDGETS.get(phase, {}).get(tool_name)

        if budget is None:
            if calls >= _min_calls and hit_rate < _warn_thresh and not evidence_exemption:
                return (
                    f"[TOOL BUDGET] '{tool_name}' is low-yield in {phase} "
                    f"(hit-rate={hit_rate:.0%}, calls={calls}/{_min_calls} min). "
                    "Consider pivoting to a different tool or vector."
                )
            return ""

        usage = self.state.get_phase_tool_count(phase, tool_name)

        effective_budget = budget
        if calls >= 4:
            if hit_rate < _warn_thresh and not evidence_exemption:
                effective_budget = max(1, int(budget * 0.80))
            elif hit_rate >= 0.55:
                effective_budget = int(budget * 1.20)

        if budget == 0 and usage >= 1:
            return (
                f"[TOOL BUDGET] '{tool_name}' is not recommended in {phase} phase "
                f"(used {usage}×). Switch to a phase-appropriate tool."
            )
        if usage >= effective_budget:
            return (
                f"[TOOL BUDGET] '{tool_name}' has exhausted its {phase} phase budget "
                f"({usage}/{effective_budget}, base={budget}, hit-rate={hit_rate:.0%}). "
                "Switch approach or tool family."
            )
        if effective_budget > 0 and usage >= int(effective_budget * 0.80):
            return (
                f"[TOOL BUDGET] '{tool_name}' is at {usage}/{effective_budget} of {phase} budget "
                f"(base={budget}, hit-rate={hit_rate:.0%}). Plan remaining calls carefully."
            )
        return ""

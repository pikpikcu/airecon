from __future__ import annotations

import json
import logging
import re
import warnings
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from defusedxml.ElementTree import ParseError as XMLParseError
import defusedxml.ElementTree as ET

from .command_parse import extract_primary_binary
from .constants import SEVERITY_ORDER

logger = logging.getLogger("airecon.agent.output_parser")


@dataclass
class ParsedOutput:
    tool: str
    summary: str
    items: list[str] = field(default_factory=list)
    total_count: int = 0
    raw_truncated: str = ""

    technologies: dict[str, str] = field(default_factory=dict)

    parse_quality: str = "known"

    causal_observations: list[dict[str, Any]] = field(default_factory=list)


def _get_max_items_by_phase() -> dict[str, int]:
    from ..config import get_config as _get_config

    cfg = _get_config()
    return {
        "RECON": getattr(cfg, "pipeline_output_parser_max_items_recon", 200),
        "ANALYSIS": getattr(cfg, "pipeline_output_parser_max_items_analysis", 150),
        "EXPLOIT": getattr(cfg, "pipeline_output_parser_max_items_exploit", 50),
        "REPORT": getattr(cfg, "pipeline_output_parser_max_items_report", 25),
    }


_MAX_ITEMS_BY_PHASE: dict[str, int] = _get_max_items_by_phase()

DEFAULT_MAX_ITEMS = 100

MAX_RAW_FALLBACK = 3000


def _load_tools_meta() -> dict[str, Any]:
    try:
        path = Path(__file__).resolve().parent.parent / "data" / "tools_meta.json"
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        logger.warning("Could not load tools_meta.json: %s", exc)
        return {}


_TOOLS_META: dict[str, Any] = _load_tools_meta()


def _get_causal_confidence(key: str, default: float) -> float:
    from ..config import get_config as _get_config

    cfg = _get_config()
    config_key = f"causal_confidence_{key}"
    value = getattr(cfg, config_key, default)
    return max(0.0, min(float(value), 1.0)) if value else default


_causal_confidence = _get_causal_confidence


def _load_tool_patterns() -> list[tuple[re.Pattern[str], str]]:
    patterns = _TOOLS_META.get("output_parser_tool_patterns", {})
    if not isinstance(patterns, dict):
        logger.warning(
            "Invalid output_parser_tool_patterns format in tools_meta.json — "
            "tool detection disabled, generic parser will be used for all tools."
        )
        return []
    return [
        (re.compile(rf"\b{re.escape(binary)}\b"), parser_type)
        for binary, parser_type in patterns.items()
        if binary and parser_type
    ]


def _compile_regex_list(raw_patterns: list[Any]) -> list[re.Pattern[str]]:
    compiled: list[re.Pattern[str]] = []
    for pattern in raw_patterns:
        p = str(pattern or "").strip()
        if not p:
            continue
        try:
            compiled.append(re.compile(p, re.IGNORECASE))
        except re.error:
            logger.debug("Skipping invalid adaptive regex pattern: %r", p)
    return compiled


def _load_adaptive_unknown_hints() -> tuple[
    list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], dict[str, str]
]:
    cfg = _TOOLS_META.get("output_parser_adaptive_hints", {})
    if not isinstance(cfg, dict):
        return [], [], [], {}

    content_rules: list[dict[str, Any]] = []
    count_rules: list[dict[str, Any]] = []
    json_rules: list[dict[str, Any]] = []

    for raw in cfg.get("content_rules", []) or []:
        if not isinstance(raw, dict):
            continue
        parser_name = str(raw.get("parser", "")).strip().lower()
        if not parser_name:
            continue
        content_rules.append(
            {
                "parser": parser_name,
                "contains_any": [
                    str(v).lower()
                    for v in (raw.get("contains_any") or [])
                    if str(v).strip()
                ],
                "contains_all": [
                    str(v).lower()
                    for v in (raw.get("contains_all") or [])
                    if str(v).strip()
                ],
                "command_contains_any": [
                    str(v).lower()
                    for v in (raw.get("command_contains_any") or [])
                    if str(v).strip()
                ],
                "regex_any": _compile_regex_list(raw.get("regex_any") or []),
                "regex_all": _compile_regex_list(raw.get("regex_all") or []),
            }
        )

    for raw in cfg.get("count_rules", []) or []:
        if not isinstance(raw, dict):
            continue
        parser_name = str(raw.get("parser", "")).strip().lower()
        metric_name = str(raw.get("metric", "")).strip()
        if not parser_name or not metric_name:
            continue
        try:
            min_abs = int(raw.get("min_abs", 1))
        except (TypeError, ValueError):
            min_abs = 1
        try:
            min_ratio = float(raw.get("min_ratio", 0.0))
        except (TypeError, ValueError):
            min_ratio = 0.0
        count_rules.append(
            {
                "parser": parser_name,
                "metric": metric_name,
                "min_abs": max(0, min_abs),
                "min_ratio": max(0.0, min_ratio),
            }
        )

    for raw in cfg.get("json_rules", []) or []:
        if not isinstance(raw, dict):
            continue
        parser_name = str(raw.get("parser", "")).strip().lower()
        if not parser_name:
            continue
        json_rules.append(
            {
                "parser": parser_name,
                "contains_any": [
                    str(v).lower()
                    for v in (raw.get("contains_any") or [])
                    if str(v).strip()
                ],
                "contains_all": [
                    str(v).lower()
                    for v in (raw.get("contains_all") or [])
                    if str(v).strip()
                ],
                "regex_any": _compile_regex_list(raw.get("regex_any") or []),
                "regex_all": _compile_regex_list(raw.get("regex_all") or []),
            }
        )

    command_hints_raw = cfg.get("command_hints", {})
    command_hints: dict[str, str] = {}
    if isinstance(command_hints_raw, dict):
        for needle, parser_name in command_hints_raw.items():
            n = str(needle or "").strip().lower()
            p = str(parser_name or "").strip().lower()
            if n and p:
                command_hints[n] = p

    return content_rules, count_rules, json_rules, command_hints


_TOOL_PATTERNS: list[tuple[re.Pattern[str], str]] = _load_tool_patterns()
_GENERIC_WARNED_TOOLS: set[str] = set()

_COMMON_SHELL_TOOLS: frozenset[str] = frozenset(
    {
        "which",
        "whereis",
        "type",
        "cat",
        "head",
        "tail",
        "wc",
        "sort",
        "uniq",
        "grep",
        "egrep",
        "fgrep",
        "zgrep",
        "awk",
        "sed",
        "cut",
        "tr",
        "xargs",
        "tee",
        "paste",
        "echo",
        "printf",
        "true",
        "false",
        "cd",
        "pwd",
        "ls",
        "dir",
        "cp",
        "mv",
        "rm",
        "mkdir",
        "touch",
        "chmod",
        "chown",
        "env",
        "export",
        "curl",
        "wget",
        "for",
        "while",
        "if",
        "then",
        "do",
        "done",
    }
)

_ADAPTIVE_TOOL_HINTS: dict[str, str] = {}
_MAX_ADAPTIVE_TOOL_HINTS = 128
(
    _ADAPTIVE_CONTENT_RULES,
    _ADAPTIVE_COUNT_RULES,
    _ADAPTIVE_JSON_RULES,
    _ADAPTIVE_COMMAND_HINTS,
) = _load_adaptive_unknown_hints()


def _remember_adaptive_tool_hint(binary: str, parser_name: str) -> None:
    b = str(binary or "").strip().lower()
    p = str(parser_name or "").strip().lower()
    if not b or not p:
        return
    if b in _ADAPTIVE_TOOL_HINTS:
        _ADAPTIVE_TOOL_HINTS.pop(b, None)
    _ADAPTIVE_TOOL_HINTS[b] = p
    while len(_ADAPTIVE_TOOL_HINTS) > _MAX_ADAPTIVE_TOOL_HINTS:
        oldest = next(iter(_ADAPTIVE_TOOL_HINTS))
        _ADAPTIVE_TOOL_HINTS.pop(oldest, None)


def detect_tool(command: str) -> str | None:
    first_token = extract_primary_binary(command)
    if not first_token:
        return None

    for pattern, tool_name in _TOOL_PATTERNS:
        if pattern.search(first_token):
            return tool_name
    return None


def _signature_candidates_for_unknown(command: str, stdout: str) -> list[str]:
    cmd = (command or "").lower()
    out = stdout or ""
    lower_out = out.lower()
    lines = [line.strip() for line in out.splitlines() if line.strip()]
    head = lines[:20]
    candidates: list[str] = []

    def _add(name: str) -> None:
        if name in _PARSERS and name not in candidates:
            candidates.append(name)

    def _rule_matches(
        text: str, rule: dict[str, Any], *, command_text: str = ""
    ) -> bool:
        contains_any = rule.get("contains_any", [])
        if contains_any and not any(token in text for token in contains_any):
            return False
        contains_all = rule.get("contains_all", [])
        if contains_all and not all(token in text for token in contains_all):
            return False
        command_contains_any = rule.get("command_contains_any", [])
        if command_contains_any and not any(
            token in command_text for token in command_contains_any
        ):
            return False
        regex_any = rule.get("regex_any", [])
        if regex_any and not any(rx.search(text) for rx in regex_any):
            return False
        regex_all = rule.get("regex_all", [])
        if regex_all and not all(rx.search(text) for rx in regex_all):
            return False
        return True

    json_lines = sum(1 for line in head if line.startswith("{"))
    url_lines = sum(1 for line in head if re.match(r"https?://", line))
    host_port_lines = sum(1 for line in head if re.match(r"^[\w\.\-]+:\d{1,5}$", line))
    subdomain_lines = sum(
        1
        for line in head
        if re.match(r"^[a-z0-9][a-z0-9\.\-]+\.[a-z]{2,}$", line, re.IGNORECASE)
    )
    metric_values: dict[str, int] = {
        "json_lines": json_lines,
        "url_lines": url_lines,
        "host_port_lines": host_port_lines,
        "subdomain_lines": subdomain_lines,
    }

    for rule in _ADAPTIVE_CONTENT_RULES:
        if _rule_matches(lower_out, rule, command_text=cmd):
            _add(rule.get("parser", ""))

    sample_size = max(1, len(head))
    for rule in _ADAPTIVE_COUNT_RULES:
        metric_name = str(rule.get("metric", ""))
        metric_value = metric_values.get(metric_name, 0)
        min_abs = int(rule.get("min_abs", 1))
        min_ratio = float(rule.get("min_ratio", 0.0))
        threshold = max(min_abs, int(sample_size * min_ratio))
        if metric_value >= threshold:
            _add(rule.get("parser", ""))

    json_blob = "\n".join(head)
    for rule in _ADAPTIVE_JSON_RULES:
        if _rule_matches(json_blob, rule):
            _add(rule.get("parser", ""))

    for needle, parser in _ADAPTIVE_COMMAND_HINTS.items():
        if needle in cmd:
            _add(parser)

    return candidates


def _score_parsed_quality(parsed: ParsedOutput, stdout: str) -> float:
    lines = [line.strip() for line in stdout.splitlines() if line.strip()]
    raw_count = len(lines)
    if raw_count <= 0:
        return 0.0

    items = [str(i).strip() for i in parsed.items if str(i).strip()]
    unique_items = len(set(items))
    coverage = min(1.0, parsed.total_count / max(1, raw_count))
    uniqueness = unique_items / max(1, len(items)) if items else 0.0
    structured = 0
    for item in items[:30]:
        if (
            re.search(r"\bhttps?://", item, re.IGNORECASE)
            or re.search(r"\b\d{1,5}/(tcp|udp)\b", item, re.IGNORECASE)
            or re.search(r"\b(CRITICAL|HIGH|MEDIUM|LOW|INFO)\b", item, re.IGNORECASE)
            or re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}:\d{1,5}\b", item)
        ):
            structured += 1
    structure_ratio = structured / max(1, min(len(items), 30))
    summary_quality = (
        1.0 if parsed.summary and not parsed.summary.startswith("Output:") else 0.4
    )
    raw_fallback_penalty = 0.15 if parsed.raw_truncated and not items else 0.0

    score = (
        (coverage * 0.30)
        + (uniqueness * 0.20)
        + (structure_ratio * 0.30)
        + (summary_quality * 0.20)
        - raw_fallback_penalty
    )
    return max(0.0, min(1.0, score))


def _adaptive_unknown_parse(
    command: str,
    stdout: str,
    *,
    detected_binary: str,
    max_items: int,
) -> tuple[ParsedOutput, str, float]:
    candidates = _signature_candidates_for_unknown(command, stdout)
    hinted_parser = _ADAPTIVE_TOOL_HINTS.get(detected_binary.lower())
    if hinted_parser in _PARSERS and hinted_parser not in candidates:
        candidates.insert(0, hinted_parser)
    attempts: list[tuple[ParsedOutput, str, float]] = []

    for parser_name in candidates:
        parser_fn = _PARSERS.get(parser_name)
        if not parser_fn:
            continue
        try:
            parsed = parser_fn(stdout, max_items=max_items)
            score = _score_parsed_quality(parsed, stdout)
            attempts.append((parsed, parser_name, score))
        except Exception as exc:
            logger.debug("Adaptive parser candidate failed (%s): %s", parser_name, exc)

    generic = _parse_generic_smart(stdout, max_items=max_items)
    generic_score = _score_parsed_quality(generic, stdout)
    attempts.append((generic, "generic", generic_score))

    best_parsed, best_parser, best_score = max(attempts, key=lambda item: item[2])
    if best_parser != "generic" and best_score >= 0.45 and detected_binary:
        _remember_adaptive_tool_hint(detected_binary, best_parser)
    return best_parsed, best_parser, best_score


_CAUSAL_URL_STATUS_RE = re.compile(r"(https?://\S+?)\s+\[(\d{3})[^\]]*\]")
_CAUSAL_URL_RE = re.compile(r"^https?://\S+")
_CAUSAL_ANY_URL_RE = re.compile(r"https?://\S+")
_CAUSAL_HOST_PORT_RE = re.compile(r"^([a-zA-Z0-9.\-]+):(\d{1,5})$")
_CAUSAL_PORT_STATE_RE = re.compile(r"(\d+)/(tcp|udp)\s+(open|filtered)")
_CAUSAL_SUBDOMAIN_RE = re.compile(
    r"^[a-z0-9]([a-z0-9\-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)+$",
    re.IGNORECASE,
)
_CAUSAL_SEVERITY_RE = re.compile(r"\[(CRITICAL|HIGH|MEDIUM|LOW|INFO)\]", re.IGNORECASE)

_DYNAMIC_VULN_PATTERNS: list[tuple[str, str, float]] = []


def _load_vuln_patterns() -> list[tuple[str, str, float]]:
    patterns = []
    try:
        from pathlib import Path

        patterns_file = Path(__file__).parent.parent / "data" / "vuln_patterns.json"
        if patterns_file.exists():
            import json

            data = json.loads(patterns_file.read_text(encoding="utf-8"))
            for p in data.get("patterns", []):
                patterns.append(
                    (
                        p.get("pattern", ""),
                        p.get("category", "unknown"),
                        p.get("weight", 0.5),
                    )
                )
    except Exception as _e:
        logger.debug("Failed to load vulnerability hint patterns: %s", _e)

    if not patterns:
        patterns = [
            (r"vulnerab", "general_vuln", 0.6),
            (r"exploit", "exploitation", 0.7),
            (r"injection", "injection", 0.8),
            (r"bypass", "bypass", 0.6),
            (r"exposed", "exposure", 0.5),
        ]

    return patterns


def _get_vuln_hint_re() -> re.Pattern[str]:
    global _DYNAMIC_VULN_PATTERNS
    if not _DYNAMIC_VULN_PATTERNS:
        _DYNAMIC_VULN_PATTERNS = _load_vuln_patterns()

    if _DYNAMIC_VULN_PATTERNS:
        pattern = "|".join(p[0] for p in _DYNAMIC_VULN_PATTERNS)
        return re.compile(rf"\b({pattern}|cve-\d{{4}}-\d{{4,7}})\b", re.IGNORECASE)

    return re.compile(r"\bvulnerab|exploit\b", re.IGNORECASE)


def _append_causal_observation(
    observations: list[dict[str, Any]],
    seen: set[tuple[str, str, str, str]],
    *,
    observation_type: str,
    entity: str,
    attribute: str = "",
    value: str = "",
    source_tool: str = "",
    evidence: str = "",
    confidence: float = 0.5,
    phase: str = "",
) -> None:
    obs_type = str(observation_type or "").strip().lower()
    ent = str(entity or "").strip()
    attr = str(attribute or "").strip().lower()
    val = str(value or "").strip()
    if not obs_type or not ent:
        return
    key = (obs_type, ent.lower(), attr, val.lower())
    if key in seen:
        return
    seen.add(key)
    observations.append(
        {
            "observation_type": obs_type,
            "entity": ent[:200],
            "attribute": attr[:80],
            "value": val[:200],
            "source_tool": str(source_tool or "").strip().lower()[:80],
            "evidence": str(evidence or "").strip()[:600],
            "confidence": max(0.0, min(float(confidence), 1.0)),
            "phase": str(phase or "").strip().upper()[:24],
        }
    )


def _extract_causal_observations(
    command: str,
    parsed: ParsedOutput,
    stdout: str,
    phase: str = "",
) -> list[dict[str, Any]]:
    observations: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str, str]] = set()
    source_tool = (parsed.tool or extract_primary_binary(command) or "unknown").lower()

    for tech_name, tech_ver in (parsed.technologies or {}).items():
        _append_causal_observation(
            observations,
            seen,
            observation_type="technology_detected",
            entity=str(tech_name),
            attribute="version",
            value=str(tech_ver or ""),
            source_tool=source_tool,
            evidence=f"{tech_name} {tech_ver}".strip(),
            confidence=_causal_confidence("technology_detected", 0.86),
            phase=phase,
        )

    for raw_item in parsed.items[:250]:
        item = str(raw_item or "").strip()
        if not item:
            continue

        url_status_m = _CAUSAL_URL_STATUS_RE.search(item)
        if url_status_m:
            url = url_status_m.group(1).rstrip(".,;:)]}>\"'")
            status = url_status_m.group(2)
            _append_causal_observation(
                observations,
                seen,
                observation_type="endpoint_observed",
                entity=url,
                attribute="status_code",
                value=status,
                source_tool=source_tool,
                evidence=item,
                confidence=_causal_confidence("endpoint_observed", 0.82),
                phase=phase,
            )
            status_int = int(status)
            if 200 <= status_int < 400:
                _append_causal_observation(
                    observations,
                    seen,
                    observation_type="endpoint_accessible",
                    entity=url,
                    attribute="status_class",
                    value=f"{status_int // 100}xx",
                    source_tool=source_tool,
                    evidence=item,
                    confidence=_causal_confidence("endpoint_accessible", 0.80),
                    phase=phase,
                )
            continue

        host_port_m = _CAUSAL_HOST_PORT_RE.match(item)
        if host_port_m:
            host, port = host_port_m.groups()
            _append_causal_observation(
                observations,
                seen,
                observation_type="service_exposed",
                entity=host,
                attribute="port",
                value=port,
                source_tool=source_tool,
                evidence=item,
                confidence=_causal_confidence("service_exposed", 0.80),
                phase=phase,
            )
            continue

        port_state_m = _CAUSAL_PORT_STATE_RE.search(item)
        if port_state_m:
            port, proto, state = port_state_m.groups()
            _append_causal_observation(
                observations,
                seen,
                observation_type="port_state_observed",
                entity=f"{port}/{proto}",
                attribute="state",
                value=state,
                source_tool=source_tool,
                evidence=item,
                confidence=_causal_confidence("port_state_observed", 0.78),
                phase=phase,
            )
            continue

        if _CAUSAL_URL_RE.match(item):
            url = item.split()[0].rstrip(".,;:)]}>\"'")
            _append_causal_observation(
                observations,
                seen,
                observation_type="endpoint_discovered",
                entity=url,
                attribute="discovery",
                value="url",
                source_tool=source_tool,
                evidence=item,
                confidence=_causal_confidence("endpoint_discovered", 0.74),
                phase=phase,
            )
            continue

        embedded_url = _CAUSAL_ANY_URL_RE.search(item)
        if embedded_url:
            url = embedded_url.group(0).rstrip(".,;:)]}>\"'")
            _append_causal_observation(
                observations,
                seen,
                observation_type="endpoint_discovered",
                entity=url,
                attribute="discovery",
                value="embedded_url",
                source_tool=source_tool,
                evidence=item,
                confidence=_causal_confidence("endpoint_discovered", 0.70),
                phase=phase,
            )
            continue

        token = item.split()[0].strip()
        if _CAUSAL_SUBDOMAIN_RE.match(token):
            _append_causal_observation(
                observations,
                seen,
                observation_type="asset_discovered",
                entity=token,
                attribute="asset_type",
                value="subdomain",
                source_tool=source_tool,
                evidence=item,
                confidence=_causal_confidence("asset_discovered", 0.72),
                phase=phase,
            )

        sev_match = _CAUSAL_SEVERITY_RE.search(item)
        vuln_hint_re = _get_vuln_hint_re()
        if sev_match or vuln_hint_re.search(item):
            severity = sev_match.group(1).upper() if sev_match else "UNSPECIFIED"
            _append_causal_observation(
                observations,
                seen,
                observation_type="vulnerability_signal",
                entity=source_tool or "scanner",
                attribute="severity",
                value=severity,
                source_tool=source_tool,
                evidence=item,
                confidence=_causal_confidence("vulnerability_signal", 0.68),
                phase=phase,
            )

    if not observations and stdout:
        summary = parsed.summary or stdout.strip().splitlines()[0][:200]
        _append_causal_observation(
            observations,
            seen,
            observation_type="tool_output_observed",
            entity=source_tool or "unknown",
            attribute="summary",
            value=summary[:120],
            source_tool=source_tool,
            evidence=summary,
            confidence=_causal_confidence("tool_output_observed", 0.55),
            phase=phase,
        )

    return observations


def parse_tool_output(
    command: str,
    stdout: str,
    phase: str = "",
) -> ParsedOutput | None:
    if not stdout or not stdout.strip():
        return None

    tool = detect_tool(command)

    if tool is None and command.strip() in _PARSERS:
        tool = command.strip()

    max_items = _MAX_ITEMS_BY_PHASE.get(phase.upper(), DEFAULT_MAX_ITEMS)

    parser_fn = _PARSERS.get(tool) if tool else None
    if parser_fn:
        try:
            result = parser_fn(stdout, max_items=max_items)
            result.tool = tool or ""
            result.parse_quality = "known"
            result.causal_observations = _extract_causal_observations(
                command=command,
                parsed=result,
                stdout=stdout,
                phase=phase,
            )
            return result
        except Exception as e:
            logger.warning(f"Parser failed for {tool}: {e}")

    try:
        detected = (tool or extract_primary_binary(command) or "unknown").lower()
        result, chosen_parser, quality_score = _adaptive_unknown_parse(
            command,
            stdout,
            detected_binary=detected,
            max_items=max_items,
        )
        detected = tool or extract_primary_binary(command) or "unknown"
        if not result.raw_truncated:
            result.raw_truncated = stdout[:MAX_RAW_FALLBACK]

        is_common_tool = detected in _COMMON_SHELL_TOOLS

        if detected not in _GENERIC_WARNED_TOOLS and not is_common_tool:
            if chosen_parser == "generic":
                logger.warning(
                    f"Unknown tool detected: {detected}. Using generic parser. "
                    f"Output quality may be reduced. Command: {command[:100]}"
                )
            else:
                logger.info(
                    "Unknown tool '%s' parsed adaptively via '%s' (quality=%.2f).",
                    detected,
                    chosen_parser,
                    quality_score,
                )
            _GENERIC_WARNED_TOOLS.add(detected)
        elif is_common_tool:
            logger.debug(
                "Common shell tool '%s' parsed via '%s' (quality=%.2f).",
                detected,
                chosen_parser,
                quality_score,
            )
        result.tool = detected
        result.parse_quality = "fallback" if chosen_parser == "generic" else "adaptive"
        result.causal_observations = _extract_causal_observations(
            command=command,
            parsed=result,
            stdout=stdout,
            phase=phase,
        )
        return result
    except Exception as e:
        logger.warning(f"Generic parser failed: {e}")
        return None


def register_output_parser(
    parser_name: str,
    parser_fn: Any,
    binaries: list[str] | None = None,
) -> None:
    name = str(parser_name or "").strip().lower()
    if not name:
        raise ValueError("parser_name must be non-empty")
    _PARSERS[name] = parser_fn
    if binaries:
        for binary in binaries:
            b = str(binary or "").strip().lower()
            if not b:
                continue
            _TOOL_PATTERNS.append((re.compile(rf"\b{re.escape(b)}\b"), name))


def _parse_nmap(stdout: str, max_items: int = DEFAULT_MAX_ITEMS) -> ParsedOutput:
    if "<?xml" in stdout or "<nmaprun" in stdout:
        return _parse_nmap_xml(stdout)

    open_ports: list[str] = []
    hosts_up = 0
    hosts_down = 0

    for line in stdout.split("\n"):
        line = line.strip()

        port_match = re.match(r"(\d+)/(tcp|udp)\s+(open|filtered)\s+(\S+)\s*(.*)", line)
        if port_match:
            port, proto, state, service, version = port_match.groups()
            version = version.strip()[:60]
            entry = f"{port}/{proto} {state} {service}"
            if version:
                entry += f" ({version})"
            open_ports.append(entry)
        elif "Host is up" in line:
            hosts_up += 1
        elif "host down" in line.lower():
            hosts_down += 1

    if not open_ports:
        return ParsedOutput(
            tool="nmap",
            summary=f"Nmap scan complete — 0 open ports found ({hosts_up} hosts up, {hosts_down} down)",
            items=[],
            total_count=0,
            raw_truncated=stdout[:MAX_RAW_FALLBACK],
        )

    return ParsedOutput(
        tool="nmap",
        summary=f"Nmap: {len(open_ports)} open ports found ({hosts_up} hosts up)",
        items=open_ports[:max_items],
        total_count=len(open_ports),
    )


def _parse_nmap_xml(stdout: str, max_items: int = DEFAULT_MAX_ITEMS) -> ParsedOutput:
    xml_start = stdout.find("<?xml")
    if xml_start == -1:
        xml_start = stdout.find("<nmaprun")
    if xml_start == -1:
        return _parse_nmap(stdout.replace("<?xml", ""))

    xml_content = stdout[xml_start:]

    try:
        root = ET.fromstring(xml_content)
    except XMLParseError:
        return ParsedOutput(
            tool="nmap",
            summary="Nmap XML parse failed — showing raw output",
            raw_truncated=stdout[:MAX_RAW_FALLBACK],
        )

    open_ports: list[str] = []
    hosts_up = 0

    for host in root.findall(".//host"):
        addr_el = host.find("address")
        addr = addr_el.get("addr", "?") if addr_el is not None else "?"
        status = host.find("status")
        if status is not None and status.get("state") == "up":
            hosts_up += 1

        for port in host.findall(".//port"):
            state_el = port.find("state")
            if state_el is not None and state_el.get("state") in ("open", "filtered"):
                portid = port.get("portid", "?")
                proto = port.get("protocol", "tcp")
                service_el = port.find("service")
                service = (
                    service_el.get("name", "unknown")
                    if service_el is not None
                    else "unknown"
                )
                product = (
                    service_el.get("product", "") if service_el is not None else ""
                )
                version = (
                    service_el.get("version", "") if service_el is not None else ""
                )
                state = state_el.get("state")
                entry = f"{addr}:{portid}/{proto} {state} {service}"
                if product:
                    entry += f" {product}"
                if version:
                    entry += f" {version}"
                open_ports.append(entry)

    return ParsedOutput(
        tool="nmap",
        summary=f"Nmap: {len(open_ports)} open ports across {hosts_up} hosts",
        items=open_ports[:max_items],
        total_count=len(open_ports),
    )


def _parse_nuclei(stdout: str, max_items: int = DEFAULT_MAX_ITEMS) -> ParsedOutput:
    findings: list[str] = []
    severity_counts: dict[str, int] = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }

    for line in stdout.strip().split("\n"):
        line = line.strip()
        if not line:
            continue

        if line.startswith("{"):
            try:
                data = json.loads(line)
                template_id = data.get("template-id", data.get("templateID", "?"))
                severity = data.get("info", {}).get("severity", "info").lower()
                matched = data.get("matched-at", data.get("matched", ""))
                name = data.get("info", {}).get("name", template_id)
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
                findings.append(f"[{severity.upper()}] {name} — {matched}")
                continue
            except json.JSONDecodeError:
                pass

        text_match = re.match(r"\[([^\]]+)\]\s*\[([^\]]+)\]\s*(.*)", line)
        if text_match:
            template_id, severity, rest = text_match.groups()
            severity = severity.strip().lower()
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            findings.append(f"[{severity.upper()}] {template_id} — {rest.strip()}")

    if not findings:
        return ParsedOutput(
            tool="nuclei",
            summary="Nuclei scan complete — 0 findings",
            items=[],
            total_count=0,
            raw_truncated=stdout[:MAX_RAW_FALLBACK],
        )

    sev_str = ", ".join(f"{v} {k}" for k, v in severity_counts.items() if v > 0)

    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    findings.sort(key=lambda f: sev_order.get(f.split("]")[0].strip("["), 5))

    return ParsedOutput(
        tool="nuclei",
        summary=f"Nuclei: {len(findings)} findings ({sev_str})",
        items=findings[:max_items],
        total_count=len(findings),
    )


def _parse_httpx(stdout: str, max_items: int = DEFAULT_MAX_ITEMS) -> ParsedOutput:
    hosts: list[str] = []
    technologies: dict[str, str] = {}

    for line in stdout.strip().split("\n"):
        line = line.strip()
        if not line:
            continue

        if line.startswith("{"):
            try:
                data = json.loads(line)
                url = data.get("url", data.get("input", ""))
                status = data.get("status_code", data.get("status-code", ""))
                title = data.get("title", "")

                tech_raw = data.get("tech", [])
                entry = f"{url} [{status}]"
                if title:
                    entry += f' "{title}"'
                if tech_raw:
                    entry += f" [{','.join(tech_raw[:3])}]"
                    for t in tech_raw:
                        if "/" in t:
                            name, _, ver = t.partition("/")
                            technologies[name.strip()] = ver.strip()
                        else:
                            technologies[t.strip()] = ""
                hosts.append(entry)
                continue
            except json.JSONDecodeError:
                pass

        if line.startswith("http"):
            hosts.append(line)

    if not hosts:
        return ParsedOutput(
            tool="httpx",
            summary="httpx probe complete — 0 live hosts",
            items=[],
            total_count=0,
            raw_truncated=stdout[:MAX_RAW_FALLBACK],
            technologies=technologies,
        )

    return ParsedOutput(
        tool="httpx",
        summary=f"httpx: {len(hosts)} live hosts found"
        + (f", {len(technologies)} technologies" if technologies else ""),
        items=hosts[:max_items],
        total_count=len(hosts),
        technologies=technologies,
    )


def _parse_whatweb(stdout: str, max_items: int = DEFAULT_MAX_ITEMS) -> ParsedOutput:
    technologies: dict[str, str] = {}
    items: list[str] = []

    stripped = stdout.strip()
    if stripped.startswith("[") or stripped.startswith("{"):
        try:
            data = json.loads(stripped)
            if isinstance(data, dict):
                data = [data]
            for entry in data if isinstance(data, list) else []:
                target = entry.get("target", "")
                plugins = entry.get("plugins", {})
                for name, info in plugins.items():
                    versions = info.get("version", info.get("string", []))
                    ver = versions[0] if versions else ""
                    technologies[name] = ver
                    items.append(f"{name}{('/' + ver) if ver else ''} on {target}")
            if technologies:
                return ParsedOutput(
                    tool="whatweb",
                    summary=f"WhatWeb: {len(technologies)} technologies fingerprinted",
                    items=items[:max_items],
                    total_count=len(technologies),
                    technologies=technologies,
                )
        except (json.JSONDecodeError, TypeError):
            pass

    _summary_re = re.compile(r"^Summary\s*:\s*(.+)$", re.IGNORECASE)
    _tech_token_re = re.compile(r"([A-Za-z0-9_.\-]+)\[([^\]]+)\]")
    _tech_bare_re = re.compile(r"\b([A-Z][A-Za-z0-9_.\-]+)\b")
    current_target = ""

    for line in stdout.split("\n"):
        line = line.strip()
        if line.lower().startswith("whatweb report for"):
            current_target = line.split("for", 1)[-1].strip()
        m = _summary_re.match(line)
        if not m:
            continue
        summary_str = m.group(1)

        found_any = False
        for tech_m in _tech_token_re.finditer(summary_str):
            name, value = tech_m.group(1), tech_m.group(2)

            _SKIP = {"Email", "Country", "IP", "Meta", "Script", "Title", "Frame"}
            if name in _SKIP:
                continue
            technologies[name] = value if re.match(r"[\d.]", value) else ""
            items.append(
                f"{name}{('/' + technologies[name]) if technologies[name] else ''}"
                + (f" on {current_target}" if current_target else "")
            )
            found_any = True

        if not found_any:
            for bare_m in _tech_bare_re.finditer(summary_str):
                name = bare_m.group(1)
                if name not in {"HTTP", "HTML", "URL", "API"}:
                    technologies[name] = ""
                    items.append(
                        name + (f" on {current_target}" if current_target else "")
                    )

    if not technologies:
        return ParsedOutput(
            tool="whatweb",
            summary="WhatWeb: no technologies parsed",
            items=[],
            total_count=0,
            raw_truncated=stdout[:MAX_RAW_FALLBACK],
        )

    return ParsedOutput(
        tool="whatweb",
        summary=f"WhatWeb: {len(technologies)} technologies fingerprinted",
        items=items[:max_items],
        total_count=len(technologies),
        technologies=technologies,
    )


def _parse_line_list(stdout: str, max_items: int = DEFAULT_MAX_ITEMS) -> ParsedOutput:
    _LOG_PREFIX_RE = re.compile(
        r"^\[(INFO|ERR|WRN|DEBUG|WARN|ERROR|FATAL)\]", re.IGNORECASE
    )
    items = []
    for line in stdout.strip().split("\n"):
        line = line.strip()
        if not line:
            continue
        if line.startswith("//"):
            continue

        if line.startswith("[") and _LOG_PREFIX_RE.match(line):
            continue
        items.append(line)

    seen: set[str] = set()
    unique: list[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            unique.append(item)

    return ParsedOutput(
        tool="list",
        summary=f"Found {len(unique)} items ({len(items) - len(unique)} duplicates removed)",
        items=unique[:max_items],
        total_count=len(unique),
    )


def _parse_ffuf(stdout: str, max_items: int = DEFAULT_MAX_ITEMS) -> ParsedOutput:
    results: list[str] = []

    try:
        data = json.loads(stdout)
        if isinstance(data, dict) and "results" in data:
            for r in data["results"]:
                url = r.get("url", r.get("input", {}).get("FUZZ", "?"))
                status = r.get("status", "?")
                length = r.get("length", "?")
                words = r.get("words", "?")
                results.append(
                    f"{url} [Status: {status}, Size: {length}, Words: {words}]"
                )
    except (json.JSONDecodeError, TypeError):
        pass

    if not results:
        for line in stdout.strip().split("\n"):
            if "[Status:" in line:
                results.append(line.strip())
            elif re.match(r"\S+\s+\[", line):
                results.append(line.strip())

    if not results:
        return ParsedOutput(
            tool="ffuf",
            summary="ffuf scan complete — 0 results",
            items=[],
            total_count=0,
            raw_truncated=stdout[:MAX_RAW_FALLBACK],
        )

    return ParsedOutput(
        tool="ffuf",
        summary=f"ffuf: {len(results)} endpoints discovered",
        items=results[:max_items],
        total_count=len(results),
    )


def _parse_naabu(stdout: str, max_items: int = DEFAULT_MAX_ITEMS) -> ParsedOutput:
    ports: list[str] = []
    port_counts: dict[str, list[str]] = {}

    for line in stdout.strip().split("\n"):
        line = line.strip()
        if not line:
            continue

        if ":" in line:
            parts = line.rsplit(":", 1)
            if len(parts) == 2 and parts[1].isdigit():
                host, port = parts
                port_counts.setdefault(host, []).append(port)
                ports.append(line)
        elif line.isdigit():
            ports.append(f":{line}")

    if not ports:
        return ParsedOutput(
            tool="naabu",
            summary="naabu scan complete — 0 open ports",
            items=[],
            total_count=0,
            raw_truncated=stdout[:MAX_RAW_FALLBACK],
        )

    host_summary = ", ".join(
        f"{h}({len(p)} ports)" for h, p in list(port_counts.items())[:5]
    )
    return ParsedOutput(
        tool="naabu",
        summary=f"naabu: {len(ports)} open ports across {len(port_counts)} hosts — {host_summary}",
        items=ports[:max_items],
        total_count=len(ports),
    )


def _parse_sqlmap(stdout: str, max_items: int = DEFAULT_MAX_ITEMS) -> ParsedOutput:
    findings: list[str] = []
    param_vulns: list[str] = []
    dbms: str = ""
    current_url: str = ""

    for line in stdout.split("\n"):
        line = line.strip()
        if not line:
            continue

        if line.startswith("URL:") or "testing URL" in line.lower():
            m = re.search(r"https?://\S+", line)
            if m:
                current_url = m.group(0)

        vuln_param = re.match(
            r".*parameter\s+'?([^']+?)'?\s+(?:is|appears to be|was found)\s+(?:vulnerable|injectable)",
            line,
            re.IGNORECASE,
        )
        if vuln_param:
            param = vuln_param.group(1).strip()
            entry = f"[HIGH] SQLi parameter vulnerable: {param}"
            if current_url:
                entry += f" @ {current_url}"
            param_vulns.append(entry)
            findings.append(entry)
            continue

        if re.match(r"\s+Type:", line, re.IGNORECASE):
            findings.append(f"  Technique: {line.strip()}")
        elif re.match(r"\s+Payload:", line, re.IGNORECASE):
            findings.append(f"  {line.strip()}")

        m_db = re.search(r"back-end DBMS(?:\s+is)?\s*:?\s+(.+)", line, re.IGNORECASE)
        if m_db:
            dbms = m_db.group(1).strip()

        if re.match(r"\[INFO\].*(?:fetching|dumping|retrieving)", line, re.IGNORECASE):
            findings.append(line)

        if re.match(r"Database:\s+", line, re.IGNORECASE):
            findings.append(f"[CRITICAL] {line}")
        elif re.match(r"Table:\s+", line, re.IGNORECASE):
            findings.append(f"[HIGH] {line}")

    if not findings and not param_vulns:
        if "sqlmap identified the following injection point" in stdout.lower():
            findings.append(
                "[HIGH] sqlmap identified injection points (check full output)"
            )
        elif (
            "no parameter(s) found" in stdout.lower()
            or "not injectable" in stdout.lower()
        ):
            return ParsedOutput(
                tool="sqlmap",
                summary="sqlmap: no injectable parameters found",
                items=[],
                total_count=0,
                raw_truncated=stdout[:MAX_RAW_FALLBACK],
            )
        else:
            return ParsedOutput(
                tool="sqlmap",
                summary="sqlmap: scan complete",
                items=[],
                total_count=0,
                raw_truncated=stdout[:MAX_RAW_FALLBACK],
            )

    vuln_count = len(param_vulns)
    dbms_note = f" | DBMS: {dbms}" if dbms else ""
    return ParsedOutput(
        tool="sqlmap",
        summary=f"sqlmap: {vuln_count} vulnerable parameter(s) found{dbms_note}",
        items=findings[:max_items],
        total_count=len(findings),
    )


def _parse_nikto(stdout: str, max_items: int = DEFAULT_MAX_ITEMS) -> ParsedOutput:
    findings: list[str] = []
    target: str = ""

    for line in stdout.split("\n"):
        line = line.strip()
        if not line:
            continue

        if line.startswith("- Target IP:") or line.startswith("+ Target IP:"):
            target = line
            continue
        if line.startswith("+ Target Hostname:") or line.startswith(
            "- Target Hostname:"
        ):
            target += " " + line.split(":", 1)[-1].strip()
            continue

        if line.startswith("+ ") or line.startswith("- "):
            content = line[2:].strip()

            skip_patterns = (
                "Nikto",
                "Start Time",
                "End Time",
                "No CGI",
                "allowed HTTP Methods",
                "Server:",
                "retrieved:",
                "items found",
                "0 errors",
                "scan took",
                "Host:",
            )
            if any(s.lower() in content.lower() for s in skip_patterns):
                continue

            sev = "MEDIUM"
            high_patterns = (
                "XSS",
                "SQL",
                "RCE",
                "command",
                "injection",
                "traversal",
                "passwd",
                "password",
                "credentials",
                "admin",
                "phpinfo",
                "config",
                "backup",
                "shell",
            )
            low_patterns = (
                "X-Frame-Options",
                "X-Content-Type",
                "anti-clickjacking",
                "Strict-Transport",
                "Content-Security",
            )
            if any(p.lower() in content.lower() for p in high_patterns):
                sev = "HIGH"
            elif any(p.lower() in content.lower() for p in low_patterns):
                sev = "LOW"

            osvdb_match = re.search(r"OSVDB-(\d+)", content)
            osvdb_note = f" [OSVDB-{osvdb_match.group(1)}]" if osvdb_match else ""

            findings.append(f"[{sev}] {content}{osvdb_note}")

    if not findings:
        return ParsedOutput(
            tool="nikto",
            summary="nikto: no findings",
            items=[],
            total_count=0,
            raw_truncated=stdout[:MAX_RAW_FALLBACK],
        )

    high_count = sum(1 for f in findings if f.startswith("[HIGH]"))
    target_note = f" on {target}" if target else ""
    return ParsedOutput(
        tool="nikto",
        summary=f"nikto: {len(findings)} findings ({high_count} HIGH){target_note}",
        items=findings[:max_items],
        total_count=len(findings),
    )


def _parse_dalfox(stdout: str, max_items: int = DEFAULT_MAX_ITEMS) -> ParsedOutput:
    findings: list[str] = []
    poc_lines: list[str] = []

    for line in stdout.split("\n"):
        line = line.strip()
        if not line:
            continue

        if line.startswith("[V]") or "] [V]" in line:
            findings.append(f"[HIGH] XSS VERIFIED: {line}")
        elif line.startswith("[POC]") or "] [POC]" in line:
            poc_lines.append(f"  PoC: {line}")
        elif line.startswith("[G]") or "] [G]" in line:
            findings.append(f"[MEDIUM] XSS potential: {line}")
        elif re.match(r"\[WEAK\]|\[I\]", line, re.IGNORECASE):
            findings.append(f"[LOW] {line}")

    combined = findings[:max_items]
    if poc_lines:
        combined.extend(poc_lines[:10])

    if not combined:
        return ParsedOutput(
            tool="dalfox",
            summary="dalfox: no XSS vulnerabilities found",
            items=[],
            total_count=0,
            raw_truncated=stdout[:MAX_RAW_FALLBACK],
        )

    verified = sum(1 for f in findings if "[HIGH]" in f)
    return ParsedOutput(
        tool="dalfox",
        summary=f"dalfox: {len(findings)} XSS findings ({verified} verified)",
        items=combined,
        total_count=len(combined),
    )


def _parse_wpscan(stdout: str, max_items: int = DEFAULT_MAX_ITEMS) -> ParsedOutput:
    findings: list[str] = []
    current_section: str = ""

    lines = stdout.split("\n")
    i = 0
    while i < len(lines):
        line = lines[i].strip()

        if re.match(
            r"\[i\]\s+(WordPress|Plugins|Themes|Users|Config)", line, re.IGNORECASE
        ):
            current_section = line
        elif re.match(r"\[\+\]\s+WordPress version", line, re.IGNORECASE):
            findings.append(f"[INFO] {line}")
        elif re.match(r"\[!\]", line):
            sev = "HIGH"
            content = line[3:].strip()
            if any(k in content.lower() for k in ("critical", "rce", "sqli", "exec")):
                sev = "CRITICAL"
            elif any(k in content.lower() for k in ("xss", "csrf", "auth", "bypass")):
                sev = "HIGH"
            elif any(k in content.lower() for k in ("info", "disclosure", "enum")):
                sev = "MEDIUM"
            findings.append(f"[{sev}] {content}")
        elif re.match(r"\[\+\]\s+Username found", line, re.IGNORECASE):
            findings.append(f"[MEDIUM] {line[3:].strip()}")
        elif (
            re.match(r"\[\+\]\s+.+found", line, re.IGNORECASE)
            and "plugin" in current_section.lower()
        ):
            findings.append(f"[INFO] Plugin: {line[3:].strip()}")

        if (
            findings
            and "[HIGH]" in findings[-1]
            or (findings and "[CRITICAL]" in findings[-1])
        ):
            for j in range(1, min(5, len(lines) - i)):
                ahead = lines[i + j].strip()
                cve_m = re.search(r"CVE-\d{4}-\d+", ahead)
                if cve_m:
                    findings[-1] += f" ({cve_m.group(0)})"
                    break
                if not ahead or ahead.startswith("["):
                    break

        i += 1

    if not findings:
        return ParsedOutput(
            tool="wpscan",
            summary="wpscan: no vulnerabilities found",
            items=[],
            total_count=0,
            raw_truncated=stdout[:MAX_RAW_FALLBACK],
        )

    vuln_count = sum(1 for f in findings if "[HIGH]" in f or "[CRITICAL]" in f)
    return ParsedOutput(
        tool="wpscan",
        summary=f"wpscan: {len(findings)} findings ({vuln_count} HIGH/CRITICAL)",
        items=findings[:max_items],
        total_count=len(findings),
    )


def _parse_generic_smart(
    stdout: str, max_items: int = DEFAULT_MAX_ITEMS
) -> ParsedOutput:
    lines = [line.strip() for line in stdout.strip().split("\n") if line.strip()]
    total = len(lines)

    if total == 0:
        return ParsedOutput(tool="unknown", summary="Empty output", total_count=0)

    json_count = sum(1 for line in lines[:20] if line.startswith("{"))
    if json_count > len(lines[:20]) * 0.5:
        return _parse_generic_jsonl(lines, max_items=max_items)

    url_count = sum(1 for line in lines[:20] if re.match(r"https?://", line))
    if url_count > len(lines[:20]) * 0.7:
        return _parse_line_list(stdout, max_items=max_items)

    tag_count = sum(1 for line in lines[:20] if re.match(r"^\[.+\]", line))
    if tag_count > len(lines[:20]) * 0.5:
        return _parse_generic_tagged(lines, max_items=max_items)

    col_counts = [len(re.split(r"\s{2,}|\t", line)) for line in lines[:10]]
    if col_counts and min(col_counts) >= 3 and max(col_counts) - min(col_counts) <= 1:
        return _parse_generic_table(lines, max_items=max_items)

    kv_count = sum(1 for line in lines[:20] if re.match(r"^[\w\-\.]+:\s+.+", line))
    if kv_count > len(lines[:20]) * 0.5:
        return _parse_generic_kv(lines, max_items=max_items)

    return _parse_generic_lines(lines, max_items=max_items)


def _parse_generic_jsonl(
    lines: list[str], max_items: int = DEFAULT_MAX_ITEMS
) -> ParsedOutput:
    items: list[str] = []
    for line in lines:
        if not line.startswith("{"):
            continue
        try:
            data = json.loads(line)

            summary_parts = []
            for key in (
                "url",
                "host",
                "ip",
                "domain",
                "target",
                "matched",
                "name",
                "input",
            ):
                if key in data:
                    summary_parts.append(str(data[key]))
                    break

            for key in ("severity", "status", "status_code", "type", "level"):
                if key in data:
                    summary_parts.append(f"[{data[key]}]")
                    break

            for key in ("info", "title", "description", "message"):
                val = data.get(key)
                if isinstance(val, str) and val:
                    summary_parts.append(val[:80])
                    break
                elif isinstance(val, dict) and "name" in val:
                    summary_parts.append(val["name"][:80])
                    break
            items.append(" ".join(summary_parts) if summary_parts else line[:120])
        except json.JSONDecodeError:
            items.append(line[:120])

    seen: set[str] = set()
    unique = [i for i in items if i not in seen and not seen.add(i)]

    return ParsedOutput(
        tool="json",
        summary=f"JSON output: {len(unique)} entries",
        items=unique[:max_items],
        total_count=len(unique),
    )


def _parse_generic_tagged(
    lines: list[str], max_items: int = DEFAULT_MAX_ITEMS
) -> ParsedOutput:
    items: list[str] = []
    tag_counts: dict[str, int] = {}

    for line in lines:
        match = re.match(r"^\[([^\]]+)\]\s*(.*)", line)
        if match:
            tag, content = match.groups()
            tag = tag.strip().upper()
            tag_counts[tag] = tag_counts.get(tag, 0) + 1
            if content.strip():
                items.append(f"[{tag}] {content.strip()[:120]}")
        else:
            items.append(line[:120])

    tag_str = ", ".join(
        f"{v}x {k}" for k, v in sorted(tag_counts.items(), key=lambda x: -x[1])[:5]
    )

    seen: set[str] = set()
    unique = [i for i in items if i not in seen and not seen.add(i)]

    return ParsedOutput(
        tool="tagged",
        summary=f"{len(unique)} results ({tag_str})",
        items=unique[:max_items],
        total_count=len(unique),
    )


def _parse_generic_table(
    lines: list[str], max_items: int = DEFAULT_MAX_ITEMS
) -> ParsedOutput:
    items: list[str] = []

    for line in lines[: max_items + 5]:
        items.append(line[:150])

    return ParsedOutput(
        tool="table",
        summary=f"Table output: {len(lines)} rows",
        items=items[:max_items],
        total_count=len(lines),
    )


def _parse_generic_kv(
    lines: list[str], max_items: int = DEFAULT_MAX_ITEMS
) -> ParsedOutput:
    items: list[str] = []
    for line in lines:
        items.append(line[:150])

    return ParsedOutput(
        tool="kv",
        summary=f"Output: {len(lines)} entries",
        items=items[:max_items],
        total_count=len(lines),
    )


def _parse_generic_lines(
    lines: list[str], max_items: int = DEFAULT_MAX_ITEMS
) -> ParsedOutput:
    meaningful = [
        line
        for line in lines
        if len(line) > 3
        and not line.startswith(("---", "===", "###", "✓", "✗", "Error", "Warning"))
    ]

    seen: set[str] = set()
    unique = [i for i in meaningful if i not in seen and not seen.add(i)]

    dupes = len(meaningful) - len(unique)
    return ParsedOutput(
        tool="text",
        summary=f"Output: {len(unique)} lines"
        + (f" ({dupes} duplicates removed)" if dupes > 0 else ""),
        items=unique[:max_items],
        total_count=len(unique),
        raw_truncated="" if len(unique) <= max_items else "\n".join(lines[-10:]),
    )


def _parse_hydra(stdout: str, max_items: int = DEFAULT_MAX_ITEMS) -> ParsedOutput:
    findings: list[str] = []

    for line in stdout.split("\n"):
        line = line.strip()
        if not line:
            continue

        if re.match(r"\[\d+\]\[", line) and ("login:" in line or "password:" in line):
            findings.append(f"[HIGH] Credential found: {line}")

        elif re.match(r"ACCOUNT FOUND:", line, re.IGNORECASE):
            findings.append(f"[HIGH] Credential found: {line}")

        elif line.startswith("[DATA]") and "valid" in line.lower():
            findings.append(f"[MEDIUM] {line}")

    if not findings:
        return ParsedOutput(
            tool="hydra",
            summary="hydra: no credentials found",
            items=[],
            total_count=0,
            raw_truncated=stdout[:MAX_RAW_FALLBACK],
        )
    return ParsedOutput(
        tool="hydra",
        summary=f"hydra: {len(findings)} credential(s) found",
        items=findings[:max_items],
        total_count=len(findings),
    )


def _parse_metasploit(stdout: str, max_items: int = DEFAULT_MAX_ITEMS) -> ParsedOutput:
    findings: list[str] = []
    _NEGATIVE_RE = re.compile(
        r"\b(?:"
        r"not\s+vulnerable(?:\s+to)?"
        r"|not\s+affected"
        r"|unaffected"
        r"|not\s+impacted"
        r"|no\s+vulnerabilit(?:y|ies)"
        r"|not\s+exploitable"
        r"|already\s+patched"
        r"|fully\s+patched"
        r"|fixed\s+in"
        r"|patch\s+available"
        r")\b",
        re.IGNORECASE,
    )

    for line in stdout.split("\n"):
        line = line.strip()
        if not line:
            continue
        if _NEGATIVE_RE.search(line):
            continue

        if line.startswith("[+]") and any(
            kw in line.lower()
            for kw in (
                "vulnerable",
                "session opened",
                "shell",
                "meterpreter",
                "exploit succeeded",
                "access granted",
                "root",
            )
        ):
            findings.append(f"[HIGH] {line}")

        elif line.startswith("[*]") and "found" in line.lower():
            findings.append(f"[MEDIUM] {line}")

    if not findings:
        return ParsedOutput(
            tool="metasploit",
            summary="metasploit: no exploitation results",
            items=[],
            total_count=0,
            raw_truncated=stdout[:MAX_RAW_FALLBACK],
        )
    return ParsedOutput(
        tool="metasploit",
        summary=f"metasploit: {len(findings)} result(s)",
        items=findings[:max_items],
        total_count=len(findings),
    )


def _parse_quick_fuzz(stdout: str, max_items: int = DEFAULT_MAX_ITEMS) -> ParsedOutput:
    findings: list[str] = []
    severity_counts: dict[str, int] = {}

    for line in stdout.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        m = re.match(r"\[(\w+)\]\s+(.+)", line)
        if m:
            sev = m.group(1).upper()
            if sev in SEVERITY_ORDER:
                severity_counts[sev] = severity_counts.get(sev, 0) + 1
                findings.append(f"[{sev}] {m.group(2)}")

    if not findings:
        return ParsedOutput(
            tool="quick_fuzz",
            summary="quick_fuzz: 0 findings with confidence > 0.60",
            items=[],
            total_count=0,
            raw_truncated=stdout[:MAX_RAW_FALLBACK],
        )

    findings.sort(key=lambda f: SEVERITY_ORDER.get(f.split("]")[0].strip("["), 5))
    sev_str = ", ".join(f"{v} {k.lower()}" for k, v in severity_counts.items() if v > 0)
    return ParsedOutput(
        tool="quick_fuzz",
        summary=f"quick_fuzz: {len(findings)} finding(s) ({sev_str})",
        items=findings[:max_items],
        total_count=len(findings),
    )


_PARSER_FUNCS: dict[str, Any] = {
    "nmap": _parse_nmap,
    "nuclei": _parse_nuclei,
    "httpx": _parse_httpx,
    "url_list": _parse_line_list,
    "ffuf": _parse_ffuf,
    "naabu": _parse_naabu,
    "sqlmap": _parse_sqlmap,
    "nikto": _parse_nikto,
    "dalfox": _parse_dalfox,
    "wpscan": _parse_wpscan,
    "whatweb": _parse_whatweb,
    "dig": _parse_line_list,
    "hydra": _parse_hydra,
    "metasploit": _parse_metasploit,
}

_PARSERS: dict[str, Any] = {}

_tools_meta_parser_path = (
    Path(__file__).resolve().parent.parent / "data" / "tools_meta.json"
)
try:
    _parser_meta = json.loads(_tools_meta_parser_path.read_text(encoding="utf-8"))
    _tool_to_pattern: dict[str, str] = _parser_meta.get(
        "output_parser_tool_patterns", {}
    )
    for _tool_bin, _pattern_name in _tool_to_pattern.items():
        _parser_fn = _PARSER_FUNCS.get(_pattern_name) or _PARSER_FUNCS.get("url_list")
        if _parser_fn:
            _PARSERS[_tool_bin.lower()] = _parser_fn
except Exception as _e:
    warnings.warn(f"Could not load parser registration from tools_meta.json: {_e}")
    _PARSERS.update(_PARSER_FUNCS)

_PARSERS["quick_fuzz"] = _parse_quick_fuzz
_PARSERS["advanced_fuzz"] = _parse_quick_fuzz
_PARSERS["metasploit"] = _parse_metasploit
_PARSERS["url_list"] = _parse_line_list

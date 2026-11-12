from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any

from .agent.session import SessionData
from .agent.tuning import get_tuning
from .data_loader import (
    load_business_logic_patterns,
    load_expert_testing_patterns,
    load_zeroday_patterns,
)

logger = logging.getLogger("airecon.correlation")

_DATA_DIR = Path(__file__).parent / "data"


def _load(filename: str, default: Any = None) -> Any:
    path = _DATA_DIR / filename
    if default is None:
        default = {}
    try:
        with open(path, "r") as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Failed to load {filename}: {e}")
        return default


PORT_CORRELATIONS: dict[int, dict] = {
    int(k): v for k, v in _load("port_correlations.json").items()
}

TECH_CORRELATIONS: dict[str, dict] = _load("tech_correlations.json")
CVE_CORRELATIONS: dict[str, dict] = _load("cve_correlations.json")
_attack_chains_raw = _load("attack_chains.json")

ATTACK_CHAINS: list[dict] = (
    _attack_chains_raw.get("chains", [])
    if isinstance(_attack_chains_raw, dict)
    else _attack_chains_raw
)


BUSINESS_LOGIC_PATTERNS: dict[str, dict] = load_business_logic_patterns()
EXPERT_TESTING_PATTERNS: dict[str, dict] = load_expert_testing_patterns()
ZERODAY_PATTERNS: dict[str, dict] = load_zeroday_patterns()

_URL_TECH_MAP: dict[str, str] = {
    path.lower(): tech
    for tech, info in TECH_CORRELATIONS.items()
    for path in info.get("paths", [])
    if path
}

_URL_TECH_PATH_RES: dict[str, re.Pattern[str]] = {
    path: re.compile(re.escape(path) + r"(?:[/?# ]|$)") for path in _URL_TECH_MAP
}

_INJECTION_TO_CHAIN_KEYWORD: dict[str, str] = {
    "IDOR": "IDOR",
    "SSRF": "SSRF",
    "OPEN_REDIRECT": "open redirect",
    "PATH_TRAVERSAL": "LFI",
    "SQLi_XSS": "SQL injection",
    "AUTH": "JWT",
}

_CHAIN_MIN_MATCH_RATIO: float = float(
    get_tuning("correlation.chain_min_match_ratio", 0.5)
)

_CHAIN_MAX_RESULTS: int = int(get_tuning("correlation.chain_max_results", 10))
_CHAIN_SEVERITY_RANK: dict[str, int] = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
_CHAIN_CONFIDENCE_TUNING = {
    "ratio_multiplier": float(
        get_tuning("correlation.confidence.ratio_multiplier", 1.05)
    ),
    "quality_per_hit": float(
        get_tuning("correlation.confidence.quality_per_hit", 0.04)
    ),
    "quality_cap": float(get_tuning("correlation.confidence.quality_cap", 0.12)),
    "diversity_per_source": float(
        get_tuning("correlation.confidence.diversity_per_source", 0.05)
    ),
    "diversity_cap": float(get_tuning("correlation.confidence.diversity_cap", 0.10)),
    "mono_source_penalty": float(
        get_tuning("correlation.confidence.mono_source_penalty", 0.08)
    ),
    "min_sources_without_hq": int(
        get_tuning("correlation.confidence.min_sources_without_hq", 2)
    ),
    "attack_chain_cross_source_bonus": float(
        get_tuning("correlation.confidence.attack_chain_cross_source_bonus", 0.10)
    ),
    "attack_chain_min_cross_sources": int(
        get_tuning("correlation.confidence.attack_chain_min_cross_sources", 2)
    ),
    "attack_chain_min_matches_with_vuln_anchor": int(
        get_tuning(
            "correlation.confidence.attack_chain_min_matches_with_vuln_anchor", 2
        )
    ),
}


def _normalize_port_token(port_value: Any) -> int | None:
    try:
        return int(str(port_value).split("/", 1)[0])
    except (TypeError, ValueError):
        return None


def _signal_matches(haystack: str, needle: str) -> bool:
    n = needle.strip().lower()
    if not n:
        return False

    if " " in n or any(ch in n for ch in ("/", ":", "-", "_")):
        return n in haystack

    return re.search(r"\b" + re.escape(n) + r"\b", haystack, re.IGNORECASE) is not None


def build_attack_graph(session: SessionData) -> dict[str, Any] | None:
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    node_ids: set[str] = set()

    def _add_node(
        node_id: str, node_type: str, label: str, severity: str = "INFO"
    ) -> None:
        if node_id in node_ids:
            return
        node_ids.add(node_id)
        nodes.append(
            {
                "id": node_id,
                "type": node_type,
                "label": label[:120],
                "severity": severity.upper(),
            }
        )

    for tech, version in list(getattr(session, "technologies", {}).items())[:15]:
        label = f"{tech} {version}".strip()
        _add_node(f"tech:{tech.lower()}", "technology", label, "LOW")

    for host, ports in list(getattr(session, "open_ports", {}).items())[:20]:
        if not isinstance(ports, list):
            continue
        for p in ports[:20]:
            p_norm = _normalize_port_token(p)
            if p_norm is None:
                continue
            svc = PORT_CORRELATIONS.get(p_norm, {}).get("service", f"port {p_norm}")
            _add_node(
                f"svc:{host}:{p_norm}", "service", f"{host}:{p_norm} ({svc})", "LOW"
            )

    inj_types = sorted(
        {
            str(pt.get("type_hint", "")).upper()
            for pt in getattr(session, "injection_points", [])
            if pt.get("type_hint")
        }
    )
    for inj in inj_types[:10]:
        _add_node(f"inj:{inj}", "injection", inj, "MEDIUM")

    vulns = getattr(session, "vulnerabilities", [])
    sev_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
    vuln_nodes: list[tuple[str, str, str, dict[str, Any]]] = []
    for idx, v in enumerate(vulns[:20]):
        finding = str(v.get("title") or v.get("finding") or "").strip()
        if not finding:
            continue
        sev = str(v.get("severity", "")).upper()
        if sev in {"5", "4", "3", "2", "1"}:
            sev = {
                "5": "CRITICAL",
                "4": "HIGH",
                "3": "MEDIUM",
                "2": "LOW",
                "1": "INFO",
            }[sev]
        if sev not in sev_rank:
            for lbl in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
                if f"[{lbl}]" in finding.upper():
                    sev = lbl
                    break
        if sev not in sev_rank:
            sev = "MEDIUM"
        node_id = f"vuln:{idx}"
        _add_node(node_id, "vulnerability", finding, sev)
        vuln_nodes.append((node_id, finding.lower(), sev, v))

    tech_keys = list(getattr(session, "technologies", {}).keys())
    for node_id, vuln_text, _, _ in vuln_nodes:
        for tech in tech_keys[:15]:
            if _signal_matches(vuln_text, tech.lower()):
                edges.append(
                    {
                        "source": f"tech:{tech.lower()}",
                        "target": node_id,
                        "relation": "affects",
                        "weight": 0.8,
                    }
                )
        for inj in inj_types[:10]:
            if _signal_matches(vuln_text, inj.lower().replace("_", " ")):
                edges.append(
                    {
                        "source": f"inj:{inj}",
                        "target": node_id,
                        "relation": "vector",
                        "weight": 0.85,
                    }
                )
        for host, ports in list(getattr(session, "open_ports", {}).items())[:20]:
            if not isinstance(ports, list):
                continue
            for p in ports[:20]:
                p_norm = _normalize_port_token(p)
                if p_norm is None:
                    continue
                svc = str(PORT_CORRELATIONS.get(p_norm, {}).get("service", "")).lower()
                if svc and _signal_matches(vuln_text, svc):
                    edges.append(
                        {
                            "source": f"svc:{host}:{p_norm}",
                            "target": node_id,
                            "relation": "exposes",
                            "weight": 0.7,
                        }
                    )

    if len(nodes) < 3 or not vuln_nodes:
        return None

    unique_edges: list[dict[str, Any]] = []
    seen_edge_keys: set[tuple[str, str, str]] = set()
    for e in edges:
        key = (e["source"], e["target"], e["relation"])
        if key in seen_edge_keys:
            continue
        seen_edge_keys.add(key)
        unique_edges.append(e)

    if not unique_edges:
        return None

    avg_severity = sum(sev_rank.get(sev, 0) for _, _, sev, _ in vuln_nodes) / max(
        1, len(vuln_nodes)
    )
    severity_component = min(1.0, avg_severity / 4.0)

    exploitability_votes = 0
    weak_findings = 0
    for _, _, _, raw in vuln_nodes:
        if (
            raw.get("report_generated")
            or raw.get("replay_verified")
            or raw.get("verified")
            or raw.get("proof")
            or raw.get("poc_script_code")
            or raw.get("evidence")
        ):
            exploitability_votes += 1
        else:
            weak_findings += 1
    exploitability_component = exploitability_votes / max(1, len(vuln_nodes))

    incoming_types: dict[str, set[str]] = {}
    for edge in unique_edges:
        target = str(edge.get("target", ""))
        source = str(edge.get("source", ""))
        if not target.startswith("vuln:") or ":" not in source:
            continue
        src_type = source.split(":", 1)[0]
        incoming_types.setdefault(target, set()).add(src_type)

    convergence_scores = [
        min(1.0, len(types) / 3.0) for types in incoming_types.values()
    ]
    convergence_component = (
        sum(convergence_scores) / len(convergence_scores) if convergence_scores else 0.0
    )

    node_types_present = {n.get("type", "") for n in nodes}
    killchain_component = (
        len(
            node_types_present & {"technology", "service", "injection", "vulnerability"}
        )
        / 4.0
    )

    uncertainty_penalty = min(0.25, (weak_findings / max(1, len(vuln_nodes))) * 0.25)
    risk_score = round(
        min(
            1.0,
            max(
                0.0,
                (severity_component * 0.38)
                + (exploitability_component * 0.28)
                + (convergence_component * 0.22)
                + (killchain_component * 0.12)
                - uncertainty_penalty,
            ),
        ),
        3,
    )
    return {
        "type": "attack_graph",
        "nodes": nodes[:40],
        "edges": unique_edges[:80],
        "risk_score": risk_score,
        "node_count": len(nodes),
        "edge_count": len(unique_edges),
        "risk_factors": {
            "severity_component": round(severity_component, 3),
            "exploitability_component": round(exploitability_component, 3),
            "convergence_component": round(convergence_component, 3),
            "killchain_component": round(killchain_component, 3),
            "uncertainty_penalty": round(uncertainty_penalty, 3),
        },
    }


def synthesize_attack_chains(session: SessionData) -> list[dict]:

    port_signals: list[str] = []
    for host_ports in session.open_ports.values():
        if not isinstance(host_ports, list):
            continue
        for p in host_ports:
            p_int = _normalize_port_token(p)
            if p_int is None:
                continue
            info = PORT_CORRELATIONS.get(p_int)
            if info:
                port_signals.append(info.get("service", "").lower())

    techs = session.technologies
    if isinstance(techs, dict):
        tech_signals = [f"{n} {v}".lower() for n, v in techs.items()]
    else:
        tech_signals = [str(t).lower() for t in techs]

    inj_signals = [
        ip.get("type_hint", "").lower()
        for ip in getattr(session, "injection_points", [])
        if ip.get("type_hint")
    ]
    inj_signal_str = " ".join(inj_signals)

    url_signals = " ".join(session.urls).lower()

    vuln_signals = " ".join(
        v.get("title", v.get("finding", "")).lower()
        for v in getattr(session, "vulnerabilities", [])
    )

    source_texts: dict[str, str] = {
        "port": " ".join(port_signals),
        "tech": " ".join(tech_signals),
        "inj": inj_signal_str,
        "url": url_signals,
        "vuln": vuln_signals,
    }

    full_signal_str = " ".join(source_texts.values())

    scored: list[tuple[int, float, dict]] = []
    for chain in ATTACK_CHAINS:
        req = chain.get("required_findings", [])
        if not req:
            continue

        matched: list[str] = []
        high_quality_hits = 0
        matched_sources: set[str] = set()
        for finding in req:
            f = finding.strip()
            if not f:
                continue
            f_lower = f.lower()
            if _signal_matches(full_signal_str, f_lower):
                matched.append(f)
                for source_name, source_blob in source_texts.items():
                    if source_blob and _signal_matches(source_blob, f_lower):
                        matched_sources.add(source_name)

                if _signal_matches(vuln_signals, f_lower) or _signal_matches(
                    inj_signal_str, f_lower
                ):
                    high_quality_hits += 1

        match_ratio = len(matched) / len(req)
        if match_ratio < _CHAIN_MIN_MATCH_RATIO:
            continue

        source_diversity = len(matched_sources)
        if (
            source_diversity < _CHAIN_CONFIDENCE_TUNING["min_sources_without_hq"]
            and high_quality_hits == 0
        ):
            continue

        quality_boost = min(
            _CHAIN_CONFIDENCE_TUNING["quality_cap"],
            high_quality_hits * _CHAIN_CONFIDENCE_TUNING["quality_per_hit"],
        )
        diversity_boost = min(
            _CHAIN_CONFIDENCE_TUNING["diversity_cap"],
            max(0, source_diversity - 1)
            * _CHAIN_CONFIDENCE_TUNING["diversity_per_source"],
        )
        mono_source_penalty = (
            _CHAIN_CONFIDENCE_TUNING["mono_source_penalty"]
            if source_diversity <= 1
            else 0.0
        )
        confidence = round(
            min(
                1.0,
                max(
                    0.0,
                    (match_ratio * _CHAIN_CONFIDENCE_TUNING["ratio_multiplier"])
                    + quality_boost
                    + diversity_boost
                    - mono_source_penalty,
                ),
            ),
            2,
        )
        evidence_strength = (
            "high"
            if high_quality_hits >= 2
            or (high_quality_hits >= 1 and source_diversity >= 3)
            else "medium"
            if high_quality_hits == 1 or source_diversity >= 2
            else "low"
        )
        severity_rank = _CHAIN_SEVERITY_RANK.get(
            str(chain.get("severity", "MEDIUM")).upper(), 2
        )
        scored.append(
            (
                severity_rank,
                confidence,
                {
                    "type": "synthesized_chain",
                    "chain_id": chain.get("name", "Unknown Chain"),
                    "title": (
                        f"{chain.get('name')} — {len(matched)}/{len(req)} signals matched"
                        f" ({', '.join(matched[:3])}{'…' if len(matched) > 3 else ''})"
                    ),
                    "steps": chain.get("steps", []),
                    "severity": chain.get("severity", "MEDIUM"),
                    "confidence": confidence,
                    "evidence_strength": evidence_strength,
                    "required_findings": req,
                    "matched_signals": matched,
                    "matched_sources": sorted(matched_sources),
                },
            )
        )

    scored.sort(key=lambda x: (x[0], x[1]), reverse=True)
    return [item[2] for item in scored[:_CHAIN_MAX_RESULTS]]


def _corr_fingerprint(corr: dict) -> str:
    ctype = corr.get("type", "unknown")
    if ctype == "port":
        return f"port:{corr.get('port', '?')}"
    if ctype in ("technology", "technology_cve"):
        return f"tech:{corr.get('technology', '?')}"
    if ctype == "url_path":
        return f"url_path:{corr.get('path', '?')}"
    if ctype == "expert_test":
        return f"expert:{corr.get('pattern', '?')}"
    if ctype == "zeroday_potential":
        return f"zeroday:{corr.get('pattern', '?')}"
    if ctype == "business_logic":
        return f"bizlogic:{corr.get('pattern', '?')}"
    if ctype == "injection_chain":
        return (
            f"injchain:{corr.get('injection_type', '?')}:{corr.get('chain_name', '?')}"
        )
    if ctype == "attack_chain":
        return f"chain:{corr.get('name', '?')}"
    if ctype == "synthesized_chain":
        return f"synth:{corr.get('chain_id', '?')}"
    if ctype == "attack_graph":
        return (
            f"attack_graph:{corr.get('node_count', 0)}:"
            f"{corr.get('edge_count', 0)}:{corr.get('risk_score', 0)}"
        )
    return f"{ctype}:{str(corr)[:40]}"


def run_correlation(session: SessionData) -> list[dict]:
    results = []
    _already_suggested: set[str] = set(getattr(session, "suggested_correlations", []))

    for port, info in PORT_CORRELATIONS.items():
        for host, host_ports in session.open_ports.items():
            if not isinstance(host_ports, list):
                continue
            normalized_ports = {
                p
                for p in (_normalize_port_token(v) for v in host_ports)
                if p is not None
            }
            matched = port in normalized_ports
            if matched:
                results.append(
                    {
                        "type": "port",
                        "port": port,
                        "service": info.get("service"),
                        "vulnerabilities": info.get("vulns", []),
                        "tools": info.get("tools", []),
                        "severity": info.get("severity", "MEDIUM"),
                    }
                )

    techs = session.technologies
    if isinstance(techs, dict):
        tech_str = " ".join(
            f"{name} {version}" for name, version in techs.items()
        ).lower()
    else:
        tech_str = " ".join(str(t) for t in techs).lower()
    for tech, info in TECH_CORRELATIONS.items():
        if re.search(r"\b" + re.escape(tech.lower()) + r"\b", tech_str):
            results.append(
                {
                    "type": "technology",
                    "technology": tech,
                    "vulnerabilities": info.get("vulns", []),
                    "tools": info.get("tools", []),
                    "paths": info.get("paths", []),
                    "severity": info.get("severity", "MEDIUM"),
                }
            )

    for cve_id, cve_info in CVE_CORRELATIONS.items():
        targets = cve_info.get("targets", [])
        for target in targets:
            if re.search(r"\b" + re.escape(target.lower()) + r"\b", tech_str):
                results.append(
                    {
                        "type": "technology_cve",
                        "technology": target,
                        "vulnerabilities": [
                            f"{cve_id} - {cve_info.get('name')}: {cve_info.get('description')}"
                        ],
                        "severity": cve_info.get("severity", "HIGH"),
                    }
                )
                break

    url_str = " ".join(session.urls).lower()
    seen_url_techs: set[str] = set()
    for path, tech in _URL_TECH_MAP.items():
        if _URL_TECH_PATH_RES[path].search(url_str) and tech not in seen_url_techs:
            tech_info = TECH_CORRELATIONS.get(tech, {})
            results.append(
                {
                    "type": "url_path",
                    "path": path,
                    "technology": tech,
                    "vulnerabilities": tech_info.get("vulns", [])[:3],
                    "tools": tech_info.get("tools", []),
                    "severity": tech_info.get("severity", "MEDIUM"),
                }
            )
            seen_url_techs.add(tech)

    ip_param_names_early: set[str] = {
        pt.get("parameter", "").lower().rstrip("[]")
        for pt in getattr(session, "injection_points", [])
        if pt.get("parameter")
    }
    for pattern_name, pattern_info in EXPERT_TESTING_PATTERNS.items():
        indicators = pattern_info.get("indicators", [])
        if any(
            ind.lower() in url_str
            or ind.lower() in tech_str
            or ind.lower() in ip_param_names_early
            for ind in indicators
        ):
            results.append(
                {
                    "type": "expert_test",
                    "pattern": pattern_name,
                    "description": pattern_info.get("description"),
                    "suggested_actions": pattern_info.get("suggested_actions", []),
                    "severity": pattern_info.get("severity", "MEDIUM"),
                }
            )

    for pattern_name, pattern_info in ZERODAY_PATTERNS.items():
        indicators = pattern_info.get("indicators", [])
        if any(ind.lower() in url_str or ind.lower() in tech_str for ind in indicators):
            results.append(
                {
                    "type": "zeroday_potential",
                    "pattern": pattern_name,
                    "description": pattern_info.get("description"),
                    "test_vectors": pattern_info.get("test_vectors", []),
                    "severity": pattern_info.get("severity", "HIGH"),
                }
            )

    injection_points = getattr(session, "injection_points", [])
    if injection_points:
        type_counts: dict[str, int] = {}
        type_params: dict[str, list[str]] = {}
        for pt in injection_points:
            t = pt.get("type_hint", "INJECT")
            type_counts[t] = type_counts.get(t, 0) + 1
            type_params.setdefault(t, [])
            param = pt.get("parameter", "")
            if param and param not in type_params[t]:
                type_params[t].append(param)

        for inj_type, count in type_counts.items():
            chain_keyword = _INJECTION_TO_CHAIN_KEYWORD.get(inj_type)
            if not chain_keyword:
                continue
            for chain in ATTACK_CHAINS:
                req = chain.get("required_findings", [])
                if any(chain_keyword.lower() in r.lower() for r in req):
                    sample_params = type_params.get(inj_type, [])[:3]
                    results.append(
                        {
                            "type": "injection_chain",
                            "injection_type": inj_type,
                            "param_count": count,
                            "sample_params": sample_params,
                            "chain_name": chain.get("name"),
                            "steps": chain.get("steps", []),
                            "severity": chain.get("severity", "HIGH"),
                        }
                    )
                    break

    ip_param_names: set[str] = ip_param_names_early
    for pattern_name, pattern_info in BUSINESS_LOGIC_PATTERNS.items():
        indicators = pattern_info.get("indicators", [])
        if any(ind.lower() in url_str for ind in indicators) or any(
            ind.lower() in ip_param_names for ind in indicators
        ):
            results.append(
                {
                    "type": "business_logic",
                    "pattern": pattern_name,
                    "description": pattern_info.get("description"),
                    "suggested_actions": pattern_info.get("suggested_actions", []),
                    "severity": pattern_info.get("severity", "HIGH"),
                }
            )

    vuln_names_str = " ".join(
        [
            v.get("title", v.get("finding", ""))
            for v in getattr(session, "vulnerabilities", [])
        ]
    ).lower()
    full_attack_context = url_str + " " + tech_str + " " + vuln_names_str
    _attack_sources = {
        "url": url_str,
        "tech": tech_str,
        "vuln": vuln_names_str,
    }

    for chain in ATTACK_CHAINS:
        req_findings = chain.get("required_findings", [])
        if not req_findings:
            continue

        def _attack_signal_match(blob: str, needle: str) -> bool:
            if _signal_matches(blob, needle):
                return True

            if _signal_matches(blob, f"{needle}s"):
                return True
            if needle.endswith("y") and _signal_matches(blob, f"{needle[:-1]}ies"):
                return True
            return False

        matched_req: list[str] = []
        matched_sources: set[str] = set()
        vuln_hits = 0
        for finding in req_findings:
            needle = str(finding).strip().lower()
            if not needle or not _attack_signal_match(full_attack_context, needle):
                continue
            matched_req.append(str(finding))
            for src_name, src_blob in _attack_sources.items():
                if src_blob and _attack_signal_match(src_blob, needle):
                    matched_sources.add(src_name)
                    if src_name == "vuln":
                        vuln_hits += 1

        match_ratio = len(matched_req) / max(1, len(req_findings))
        has_cross_source = (
            len(matched_sources)
            >= _CHAIN_CONFIDENCE_TUNING["attack_chain_min_cross_sources"]
        )
        has_vuln_anchor = vuln_hits >= 1
        if match_ratio >= _CHAIN_MIN_MATCH_RATIO and (
            has_cross_source
            or (
                has_vuln_anchor
                and len(matched_req)
                >= _CHAIN_CONFIDENCE_TUNING["attack_chain_min_matches_with_vuln_anchor"]
            )
        ):
            results.append(
                {
                    "type": "attack_chain",
                    "name": chain.get("name"),
                    "steps": chain.get("steps", []),
                    "severity": chain.get("severity", "CRITICAL"),
                    "confidence": round(
                        min(
                            1.0,
                            match_ratio
                            + (
                                _CHAIN_CONFIDENCE_TUNING[
                                    "attack_chain_cross_source_bonus"
                                ]
                                if has_cross_source
                                else 0.0
                            ),
                        ),
                        2,
                    ),
                    "matched_signals": matched_req[:6],
                }
            )

    synthesized = synthesize_attack_chains(session)
    results.extend(synthesized)

    graph = build_attack_graph(session)
    if graph:
        results.append(graph)

    _high_severities = {"CRITICAL", "HIGH"}
    _already_injected_count = len(_already_suggested)
    filtered: list[dict] = []
    new_fingerprints: list[str] = []

    for r in results:
        fp = _corr_fingerprint(r)
        sev = str(r.get("severity", "MEDIUM")).upper()

        already_seen = fp in _already_suggested
        resurface = (
            already_seen
            and sev in _high_severities
            and (_already_injected_count % 5 == 0)
        )
        if not already_seen or resurface:
            filtered.append(r)
            if not already_seen:
                new_fingerprints.append(fp)

    _sc = getattr(session, "suggested_correlations", None)
    if _sc is not None:
        for fp in new_fingerprints:
            if fp not in _sc:
                _sc.append(fp)

    return filtered

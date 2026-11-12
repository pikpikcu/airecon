from __future__ import annotations

import hashlib
import json
import logging
import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger("airecon.agent.correlation_engine")

REL_SPATIAL = "spatial"
REL_INPUT = "input_shared"
REL_DATA_FLOW = "data_flow"
REL_TRUST = "trust_boundary"
REL_SEQUENTIAL = "sequential"
REL_AMPLIFICATION = "amplification"


@dataclass
class Finding:
    finding_id: str
    vuln_class: str
    severity: int
    confidence: float
    endpoint: str
    parameter: str
    description: str
    evidence: str = ""
    tags: list[str] = field(default_factory=list)
    related_findings: list[str] = field(default_factory=list)
    affected_hosts: list[str] = field(default_factory=list)
    affected_params: list[str] = field(default_factory=list)
    outputs_produced: list[str] = field(default_factory=list)
    inputs_required: list[str] = field(default_factory=list)
    trust_level_change: str = ""


@dataclass
class AttackChain:
    chain_id: str
    name: str
    description: str
    findings: list[str]
    combined_severity: int
    reasoning: str
    attack_path: str
    relation_types: list[str] = field(default_factory=list)


class CorrelationEngine:
    def __init__(self):
        self._findings: dict[str, Finding] = {}
        self._chains: list[AttackChain] = []
        self._learned_chains: list[dict[str, Any]] = []
        self._load_learned_chains()

    def _load_learned_chains(self) -> None:
        try:
            learned_file = Path.home() / ".airecon" / "learning" / "learned_correlations.json"
            if learned_file.exists():
                with open(learned_file) as f:
                    data = json.load(f)
                self._learned_chains = data.get("chains", [])
        except Exception as e:
            logger.debug("Failed to load learned correlations: %s", e)

    def add_finding(
        self,
        vuln_class: str,
        severity: int,
        confidence: float,
        endpoint: str = "",
        parameter: str = "",
        description: str = "",
        evidence: str = "",
        tags: list[str] | None = None,
    ) -> str:
        finding_id = hashlib.md5(
            f"{vuln_class}:{endpoint}:{parameter}:{description[:50]}".encode(),
            usedforsecurity=False,
        ).hexdigest()[:12]

        affected_hosts: list[str] = []
        if endpoint:
            host_match = re.search(r"(?:https?://)?([a-zA-Z0-9][-a-zA-Z0-9]*(?:\.[a-zA-Z0-9][-a-zA-Z0-9]*)+)", endpoint)
            if host_match:
                affected_hosts.append(host_match.group(1))

        affected_params = [parameter] if parameter else []

        trust_change = "none"
        vc_lower = vuln_class.lower()
        if any(kw in vc_lower for kw in ("auth", "access", "privilege", "bypass", "escalat")):
            trust_change = "escalated"
        elif any(kw in vc_lower for kw in ("disclosure", "exposure", "leak", "information")):
            trust_change = "reduced"
        elif any(kw in vc_lower for kw in ("injection", "manipulation", "modification")):
            trust_change = "gained"

        finding = Finding(
            finding_id=finding_id,
            vuln_class=vuln_class.lower().replace(" ", "_"),
            severity=severity,
            confidence=confidence,
            endpoint=endpoint,
            parameter=parameter,
            description=description,
            evidence=evidence,
            tags=tags or [],
            affected_hosts=affected_hosts,
            affected_params=affected_params,
            trust_level_change=trust_change,
        )

        self._findings[finding_id] = finding
        return finding_id

    def correlate_findings(self) -> list[AttackChain]:
        if len(self._findings) < 2:
            return []

        edges = self._build_relationship_graph()

        raw_chains = self._find_chains(edges)

        unique_chains = self._deduplicate_chains(raw_chains)
        unique_chains.sort(key=lambda c: c.combined_severity, reverse=True)

        self._chains = unique_chains[:10]
        return self._chains

    def _build_relationship_graph(self) -> list[tuple[str, str, str]]:
        edges: list[tuple[str, str, str]] = []
        findings_list = list(self._findings.values())

        for i, fa in enumerate(findings_list):
            for fb in findings_list[i + 1:]:
                relations = self._find_relations(fa, fb)
                for rel_type in relations:
                    edges.append((fa.finding_id, fb.finding_id, rel_type))

        return edges

    def _find_relations(self, a: Finding, b: Finding) -> list[str]:
        relations: list[str] = []

        if a.endpoint and b.endpoint:
            if a.endpoint == b.endpoint:
                relations.append(REL_SPATIAL)
            elif a.affected_hosts and b.affected_hosts:
                if set(a.affected_hosts) & set(b.affected_hosts):
                    relations.append(REL_SPATIAL)

        if a.parameter and b.parameter and a.parameter == b.parameter:
            relations.append(REL_INPUT)

        if a.outputs_produced and b.inputs_required:
            a_outputs = set(a.outputs_produced)
            b_inputs = set(b.inputs_required)
            if a_outputs & b_inputs:
                relations.append(REL_DATA_FLOW)

        if a.trust_level_change in ("reduced", "gained") and \
           b.trust_level_change in ("escalated", "gained"):
            relations.append(REL_TRUST)
        if b.trust_level_change in ("reduced", "gained") and \
           a.trust_level_change in ("escalated", "gained"):
            if REL_TRUST not in relations:
                relations.append(REL_TRUST)

        if a.severity >= 2 and b.severity >= 2:
            combined_score = self._estimate_combined_severity([a, b])
            if combined_score >= max(a.severity, b.severity) + 1:
                relations.append(REL_AMPLIFICATION)

        return relations

    @staticmethod
    def _estimate_combined_severity(findings: list[Finding]) -> int:
        max_sev = max(f.severity for f in findings)

        endpoints = {f.endpoint for f in findings if f.endpoint}
        params = {f.parameter for f in findings if f.parameter}

        if len(endpoints) == 1 and len(params) > 1:
            return min(5, max_sev + min(2, len(params) - 1))

        if len(findings) >= 3:
            has_auth = any("auth" in f.vuln_class or "access" in f.vuln_class
                          for f in findings)
            has_data = any("data" in f.vuln_class or "disclosure" in f.vuln_class
                          or "exposure" in f.vuln_class for f in findings)
            has_execution = any("inject" in f.vuln_class or "rce" in f.vuln_class
                               or "code" in f.vuln_class for f in findings)

            if has_auth and has_data:
                return min(5, max_sev + 2)
            if has_auth and has_execution:
                return min(5, max_sev + 2)
            if has_data and has_execution:
                return min(5, max_sev + 2)

        return min(5, max_sev + 1) if len(findings) >= 2 else max_sev

    def _find_chains(
        self,
        edges: list[tuple[str, str, str]],
        max_length: int = 5,
    ) -> list[AttackChain]:
        adjacency: dict[str, list[tuple[str, str]]] = defaultdict(list)
        for a, b, rel in edges:
            adjacency[a].append((b, rel))
            adjacency[b].append((a, rel))

        chains: list[AttackChain] = []
        visited_global: set[frozenset] = set()

        def dfs(current: str, path: list[str], relations: list[str]) -> None:
            if len(path) >= 2:
                path_set = frozenset(path)
                if path_set not in visited_global:
                    visited_global.add(path_set)
                    chain = self._build_chain_from_path(path, relations)
                    if chain:
                        chains.append(chain)

            if len(path) >= max_length:
                return

            for neighbor, rel in adjacency.get(current, []):
                if neighbor not in path and neighbor in self._findings:
                    dfs(neighbor, path + [neighbor], relations + [rel])

        for start_id in self._findings:
            dfs(start_id, [start_id], [])

        return chains

    def _build_chain_from_path(
        self,
        path: list[str],
        relations: list[str],
    ) -> AttackChain | None:
        if len(path) < 2:
            return None

        findings = [self._findings[fid] for fid in path if fid in self._findings]
        if len(findings) < 2:
            return None

        max_sev = max(f.severity for f in findings)
        combined_sev = self._estimate_combined_severity(findings)

        finding_types = [f.vuln_class for f in findings]
        unique_relations = list(set(relations))

        relation_explanations = {
            REL_SPATIAL: "found on the same endpoint/host",
            REL_INPUT: "affect the same input parameter",
            REL_DATA_FLOW: "one finding's output enables the other",
            REL_TRUST: "combined trust boundary violations",
            REL_SEQUENTIAL: "must be exploited in sequence",
            REL_AMPLIFICATION: "severity amplifies when combined",
        }

        relation_strs = [
            relation_explanations.get(r, r)
            for r in unique_relations
        ]

        reasoning = (
            f"Chain of {len(findings)} related findings: "
            f"{', '.join(finding_types)}. "
            f"Relationships: {'; '.join(relation_strs)}. "
            f"Individual severity range: {min(f.severity for f in findings)}-"
            f"{max_sev}. Combined estimated severity: {combined_sev}."
        )

        attack_path = " → ".join(
            f"{f.vuln_class} ({f.endpoint or f.parameter or 'N/A'})"
            for f in findings
        )

        name = f"Attack chain: {' → '.join(finding_types[:3])}"
        if len(finding_types) > 3:
            name += f" (+{len(finding_types) - 3} more)"

        chain_id = hashlib.md5(
            json.dumps(sorted(path)).encode(),
            usedforsecurity=False,
        ).hexdigest()[:12]

        return AttackChain(
            chain_id=chain_id,
            name=name,
            description=reasoning,
            findings=path,
            combined_severity=combined_sev,
            reasoning=reasoning,
            attack_path=attack_path,
            relation_types=unique_relations,
        )

    def _deduplicate_chains(self, chains: list[AttackChain]) -> list[AttackChain]:
        unique: list[AttackChain] = []
        seen_sets: list[frozenset] = []

        for chain in chains:
            finding_set = frozenset(chain.findings)
            is_duplicate = False
            for seen in seen_sets:
                if len(finding_set & seen) >= len(finding_set) * 0.8:
                    is_duplicate = True
                    break
            if not is_duplicate:
                unique.append(chain)
                seen_sets.append(finding_set)

        return unique

    def learn_successful_chain(self, chain: AttackChain, outcome: str) -> None:
        findings = [self._findings[fid] for fid in chain.findings if fid in self._findings]
        if len(findings) < 2:
            return

        learned = {
            "id": chain.chain_id,
            "name": chain.name,
            "description": chain.description,
            "vuln_classes": [f.vuln_class for f in findings],
            "relation_types": chain.relation_types,
            "reasoning": chain.reasoning,
            "outcome": outcome,
            "discovered_at": str(datetime.now().isoformat()),
        }

        self._learned_chains.append(learned)

        try:
            learned_file = Path.home() / ".airecon" / "learning" / "learned_correlations.json"
            learned_file.parent.mkdir(parents=True, exist_ok=True)
            with open(learned_file, "w") as f:
                json.dump({"chains": self._learned_chains}, f, indent=2)
        except Exception as e:
            logger.debug("Failed to save learned chain: %s", e)

    def get_correlation_summary(self) -> str:
        if not self._chains:
            return "No correlated attack chains discovered yet."

        lines = ["<correlated_attack_chains>"]
        for i, chain in enumerate(self._chains, 1):
            lines.append(f"  <chain id=\"{i}\" severity=\"{chain.combined_severity}\">")
            lines.append(f"    <name>{chain.name}</name>")
            lines.append(f"    <description>{chain.description}</description>")
            lines.append(f"    <attack_path>{chain.attack_path}</attack_path>")
            lines.append(f"    <reasoning>{chain.reasoning}</reasoning>")
            lines.append(f"    <relations>{', '.join(chain.relation_types)}</relations>")
            lines.append(f"    <findings count=\"{len(chain.findings)}\"/>")
            lines.append("  </chain>")
        lines.append("</correlated_attack_chains>")
        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        return {
            "total_findings": len(self._findings),
            "total_chains": len(self._chains),
            "highest_chain_severity": max((c.combined_severity for c in self._chains), default=0),
            "learned_patterns": len(self._learned_chains),
        }


_engine: CorrelationEngine | None = None


def get_correlation_engine() -> CorrelationEngine:
    global _engine
    if _engine is None:
        _engine = CorrelationEngine()
    return _engine


def reset_correlation_engine() -> None:
    global _engine
    _engine = None

from __future__ import annotations

import hashlib
import json
import logging
import random
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .novel_discovery import analyze_novel_vectors
from .tuning import get_tuning
from .vuln_classifier import get_classifier

logger = logging.getLogger("airecon.agent.chain_planner")
rng = random.SystemRandom()

_NEGATIVE_VULN_RE = __import__("re").compile(
    r"\b("
    r"not vulnerable|false positive|unverified|needs verification|"
    r"potential vulnerability|could be vulnerable|might be vulnerable"
    r")\b",
    __import__("re").IGNORECASE,
)

_TUNING_CHAIN_CREATION = bool(get_tuning("chain_planner.dynamic_creation", True))
_DYNAMIC_CHAIN_PROBABILITY = float(get_tuning("chain_planner.dynamic_probability", 0.6))
_MIN_VULNS_FOR_CHAIN = int(get_tuning("chain_planner.min_vulns_for_chain", 2))

_ESCALATION_PATTERNS_FILE = Path(__file__).parent.parent / "data" / "escalation_patterns.json"
_DYNAMIC_CHAINS_FILE = Path.home() / ".airecon" / "learning" / "dynamic_chains.json"
_LEARNED_PATTERNS_FILE = Path.home() / ".airecon" / "learning" / "learned_escalation_patterns.json"

def _load_json_data(file_path: Path) -> dict[str, Any]:
    try:
        if file_path.exists():
            with open(file_path) as f:
                return json.load(f)
    except Exception as e:
        logger.debug("Failed to load %s: %s", file_path.name, e)
    return {}


def _load_escalation_templates() -> dict[str, list[tuple[str, str]]]:
    raw = _load_json_data(_ESCALATION_PATTERNS_FILE)
    templates = raw.get("templates", {})
    result: dict[str, list[tuple[str, str]]] = {}
    for category, steps in templates.items():
        if category.startswith("_") or not isinstance(steps, list):
            continue
        if not steps:
            continue
        first = steps[0]
        if isinstance(first, dict):
            result[category] = [
                (s.get("step", s.get("description", "")), s.get("tool_hint", "manual"))
                for s in steps if isinstance(s, dict)
            ]
        elif isinstance(first, (list, tuple)) and len(first) >= 2:
            result[category] = [(s[0], s[1]) for s in steps if isinstance(s, (list, tuple)) and len(s) >= 2]
    return result


def _load_escalation_patterns() -> list[dict[str, Any]]:
    patterns: list[dict[str, Any]] = []
    raw = _load_json_data(_ESCALATION_PATTERNS_FILE)
    patterns.extend(raw.get("patterns", []))
    patterns.extend(raw.get("_learned_patterns", []))
    learned = _load_json_data(_LEARNED_PATTERNS_FILE)
    patterns.extend(learned.get("patterns", []))
    return patterns


def _save_learned_escalation_pattern(pattern: dict[str, Any]) -> None:
    _LEARNED_PATTERNS_FILE.parent.mkdir(parents=True, exist_ok=True)
    existing = _load_json_data(_LEARNED_PATTERNS_FILE)
    pattern_id = pattern.get(
        "id",
        hashlib.md5(
            json.dumps(pattern, sort_keys=True).encode(),
            usedforsecurity=False,
        ).hexdigest()[:12],
    )
    pattern["id"] = pattern_id
    existing_ids = {p.get("id") for p in existing.get("patterns", [])}
    if pattern_id not in existing_ids:
        existing.setdefault("patterns", []).append(pattern)
        _LEARNED_PATTERNS_FILE.write_text(json.dumps(existing, indent=2), encoding="utf-8")
        logger.info("Learned new escalation pattern: %s", pattern_id)


_EXPANSION_TEMPLATES = _load_escalation_templates()
_ESCALATION_PATTERNS = _load_escalation_patterns()

def _load_dynamic_chains() -> dict[str, Any]:
    return _load_json_data(_DYNAMIC_CHAINS_FILE)


def _save_dynamic_chains(chains: dict[str, Any]) -> None:
    try:
        _DYNAMIC_CHAINS_FILE.parent.mkdir(parents=True, exist_ok=True)
        _DYNAMIC_CHAINS_FILE.write_text(json.dumps(chains, indent=2), encoding="utf-8")
    except Exception as e:
        logger.debug("Failed to save dynamic chains: %s", e)


_DYNAMIC_CHAINS = _load_dynamic_chains()

@dataclass
class ChainStep:
    step_id: int
    description: str
    tool_hint: str = ""
    status: str = "pending"
    evidence: str = ""


@dataclass
class ExploitChain:
    chain_id: str
    name: str
    description: str = ""
    steps: list[ChainStep] = field(default_factory=list)
    current_step_index: int = 0
    status: str = "planning"
    phase_formed: str = "EXPLOIT"
    vuln_basis: str = ""
    iteration_formed: int = 0
    is_dynamic: bool = False

    def current_step(self) -> ChainStep | None:
        if self.current_step_index >= len(self.steps):
            return None
        return self.steps[self.current_step_index]

    def advance(self, evidence: str = "") -> ChainStep | None:
        if self.current_step_index < len(self.steps):
            current = self.steps[self.current_step_index]
            current.status = "done"
            current.evidence = evidence[:300] if evidence else ""
            self.current_step_index += 1
            if self.status == "planning":
                self.status = "active"
        if self.current_step_index >= len(self.steps):
            self.status = "completed"
            return None
        return self.steps[self.current_step_index]

    def completed_steps(self) -> list[ChainStep]:
        return [s for s in self.steps if s.status == "done"]

    def pending_steps(self) -> list[ChainStep]:
        return [s for s in self.steps if s.status == "pending"]

def _extract_category_from_finding(finding: dict[str, Any]) -> str:
    finding_text = " ".join(
        str(finding.get(k, "")).lower()
        for k in ("finding", "title", "description", "category", "vuln_type")
    )
    if not finding_text.strip():
        return "UNKNOWN"

    result = get_classifier().classify(finding_text)
    if result.category != "UNKNOWN":
        return result.category

    _LEGACY_KEYWORDS: dict[str, list[str]] = {
        "CREDENTIAL_EXPOSURE": ["credential", "password", "secret", "token", "api_key"],
        "QUERY_INJECTION": ["sql injection", "sqli", "nosql", "injection", "union select"],
        "SCRIPT_INJECTION": ["xss", "cross-site scripting", "script injection"],
        "PATH_TRAVERSAL": ["lfi", "path traversal", "directory traversal", "../"],
    }
    for category, keywords in _LEGACY_KEYWORDS.items():
        for kw in keywords:
            if kw in finding_text:
                return category

    if "ssrf" in finding_text or "request forgery" in finding_text:
        return "SERVER_SIDE_REQUEST"
    if "csrf" in finding_text:
        return "AUTHENTICATION"

    return "UNKNOWN"

def _build_step(step_id: int, step_entry: Any) -> ChainStep:
    if isinstance(step_entry, dict):
        return ChainStep(
            step_id=step_id,
            description=step_entry.get("step", step_entry.get("description", "")),
            tool_hint=step_entry.get("tool_hint", "manual"),
        )
    if isinstance(step_entry, (list, tuple)) and len(step_entry) >= 2:
        return ChainStep(step_id=step_id, description=step_entry[0], tool_hint=step_entry[1])
    return ChainStep(step_id=step_id, description=str(step_entry), tool_hint="manual")

def _generate_dynamic_chain(
    vulns: list[dict[str, Any]],
    iteration: int,
) -> list[ExploitChain]:
    if not _TUNING_CHAIN_CREATION or rng.random() > _DYNAMIC_CHAIN_PROBABILITY:
        return []

    categories: dict[str, list[dict[str, Any]]] = {}
    for vuln in vulns:
        cat = _extract_category_from_finding(vuln)
        categories.setdefault(cat, []).append(vuln)

    if len(categories) < 2 and len(vulns) < _MIN_VULNS_FOR_CHAIN:
        return []

    chains: list[ExploitChain] = []
    chain_seed = hashlib.md5(
        f"{rng.random()}:{iteration}:{len(vulns)}".encode(),
        usedforsecurity=False,
    ).hexdigest()[:12]

    for pattern in _ESCALATION_PATTERNS:
        matched_from = [c for c in pattern["from"] if c in categories]
        if not matched_from or rng.random() > pattern["probability"]:
            continue

        source_cat = rng.choice(matched_from)
        source_vuln = rng.choice(categories[source_cat])

        chain_id = f"dynamic_{chain_seed}_{source_cat.lower()}_{pattern['to'].lower()}"
        steps = [
            ChainStep(step_id=0, description=f"Exploit {source_cat} (basis: {source_vuln.get('finding', 'N/A')[:80]})", tool_hint="manual"),
            ChainStep(step_id=1, description=pattern["description"], tool_hint="manual"),
        ]

        template_steps = _EXPANSION_TEMPLATES.get(source_cat, [])
        if template_steps:
            for i, step_entry in enumerate(
                rng.sample(template_steps, min(2, len(template_steps))),
                start=2,
            ):
                if len(steps) >= 5:
                    break
                steps.append(_build_step(i, step_entry))

        chains.append(ExploitChain(
            chain_id=chain_id,
            name=f"Dynamic Chain: {source_cat} → {pattern['to']}",
            description=pattern["description"],
            steps=steps,
            phase_formed="EXPLOIT",
            vuln_basis=f"{source_cat} + {pattern['to']}",
            iteration_formed=iteration,
            is_dynamic=True,
        ))

        if chain_id not in _DYNAMIC_CHAINS:
            _DYNAMIC_CHAINS[chain_id] = {
                "from_category": source_cat,
                "to_category": pattern["to"],
                "description": pattern["description"],
                "discovery_count": 0,
            }
        _DYNAMIC_CHAINS[chain_id]["discovery_count"] += 1

    if len(_DYNAMIC_CHAINS) % 5 == 0:
        _save_dynamic_chains(_DYNAMIC_CHAINS)

    return chains


def _build_novel_discovery_chains(
    vulnerabilities: list[dict[str, Any]],
    existing_chain_ids: set[str],
    iteration: int,
    max_chains: int,
) -> list[ExploitChain]:
    analysis = analyze_novel_vectors(vulnerabilities, iteration=iteration)
    combinations = analysis.get("combinations", [])
    tactics = analysis.get("innovative_tactics", [])
    anomalies = analysis.get("anomalies_detected", [])
    novel_vectors = analysis.get("novel_vectors", [])

    chains: list[ExploitChain] = []
    for idx, combo in enumerate(combinations[:max_chains]):
        combo_name = str(combo.get("name", "novel_combo")).lower()
        chain_id = f"novel_combo_{combo_name}_{iteration}"
        if chain_id in existing_chain_ids:
            continue

        components = combo.get("components_found", []) or ["observed findings"]
        escalation = combo.get("escalation", "Validate whether the combination escalates impact")
        steps = [
            ChainStep(
                step_id=0,
                description=f"Validate component findings together: {', '.join(components)}",
                tool_hint="manual",
            ),
            ChainStep(
                step_id=1,
                description=escalation,
                tool_hint="manual",
            ),
        ]
        if tactics:
            steps.append(
                ChainStep(
                    step_id=len(steps),
                    description=tactics[idx % len(tactics)],
                    tool_hint="manual",
                )
            )

        confidence = float(combo.get("confidence", 0.0) or 0.0)
        chains.append(
            ExploitChain(
                chain_id=chain_id,
                name=f"Novel Combination: {combo.get('name', 'Emergent Chain')}",
                description=(
                    f"{combo.get('description', 'Combine observed findings for higher impact')} "
                    f"(confidence={confidence:.0%})"
                ),
                steps=steps,
                phase_formed="EXPLOIT",
                vuln_basis=f"novel_combination: {', '.join(components)}",
                iteration_formed=iteration,
                is_dynamic=True,
            )
        )
        existing_chain_ids.add(chain_id)

    if chains or (not anomalies and not tactics and not novel_vectors):
        return chains[:max_chains]

    vector = novel_vectors[0] if novel_vectors else {}
    chain_id = f"novel_vector_{iteration}"
    if chain_id in existing_chain_ids:
        return chains[:max_chains]

    basis_findings = vector.get("bases", []) or [
        str(v.get("finding", v.get("title", "unknown"))).strip()[:60]
        for v in vulnerabilities[:3]
    ]
    anomaly_text = ", ".join(str(a).replace("_", " ") for a in anomalies[:3]) or "emergent behavior"
    vector_desc = vector.get("description", "Emergent attack path across multiple weak signals")
    escalation = vector.get("escalation", "Chain the observed behavior into a concrete impact path")
    top_tactic = tactics[0] if tactics else "Probe edge-case workflow states, caching layers, and second-order sinks."

    chains.append(
        ExploitChain(
            chain_id=chain_id,
            name="Novel Attack Discovery",
            description=f"{vector_desc} rooted in {anomaly_text}",
            steps=[
                ChainStep(
                    step_id=0,
                    description=f"Reconstruct the unusual path across findings: {'; '.join(basis_findings[:3])}",
                    tool_hint="manual",
                ),
                ChainStep(
                    step_id=1,
                    description=escalation,
                    tool_hint="manual",
                ),
                ChainStep(
                    step_id=2,
                    description=top_tactic,
                    tool_hint="manual",
                ),
            ],
            phase_formed="EXPLOIT",
            vuln_basis=f"novel_vector: {anomaly_text}",
            iteration_formed=iteration,
            is_dynamic=True,
        )
    )
    existing_chain_ids.add(chain_id)
    return chains[:max_chains]


def _build_workflow_context_chains(
    vulnerabilities: list[dict[str, Any]],
    workflow_context: dict[str, Any] | None,
    existing_chain_ids: set[str],
    iteration: int,
    max_chains: int,
) -> list[ExploitChain]:
    if not workflow_context or max_chains <= 0:
        return []

    workflow_paths = workflow_context.get("workflow_paths", {}) or {}
    principals = workflow_context.get("principals", {}) or {}
    roles = workflow_context.get("roles", []) or []
    tenant_markers = workflow_context.get("tenant_markers", []) or []
    trust_boundaries = workflow_context.get("trust_boundaries", []) or []

    vuln_blob = " ".join(
        str(v.get("finding", v.get("title", ""))) for v in vulnerabilities[:8]
    ).lower()
    stage_names = sorted(workflow_paths.keys())
    has_workflow_surface = bool(
        stage_names
        or principals
        or tenant_markers
        or trust_boundaries
        or any(
            token in vuln_blob
            for token in (
                "workflow",
                "state",
                "checkout",
                "payment",
                "coupon",
                "refund",
                "tenant",
                "role",
                "admin",
                "approval",
                "invite",
                "otp",
                "totp",
            )
        )
    )
    if not has_workflow_surface:
        return []

    chains: list[ExploitChain] = []
    principal_preview = ", ".join(sorted(set(roles))[:4] or sorted(principals.keys())[:4]) or "anonymous, authenticated"
    workflow_preview = ", ".join(stage_names[:4]) or "stateful application flow"
    boundary_preview = ", ".join(trust_boundaries[:4]) or "auth, data, and state transitions"
    tenant_preview = ", ".join(tenant_markers[:4]) or "tenant_id/org_id selectors"

    workflow_chain_id = f"workflow_logic_{iteration}"
    if workflow_chain_id not in existing_chain_ids:
        chains.append(
            ExploitChain(
                chain_id=workflow_chain_id,
                name="Workflow Abuse Chain",
                description=(
                    f"Model actor/state abuse across {workflow_preview} with principals {principal_preview}"
                ),
                steps=[
                    ChainStep(
                        step_id=0,
                        description=(
                            f"Build an actor x action x resource matrix for principals {principal_preview} across {workflow_preview}."
                        ),
                        tool_hint="browser_action",
                    ),
                    ChainStep(
                        step_id=1,
                        description=(
                            f"Attempt out-of-order, replayed, or skipped transitions around {workflow_preview}; focus on {boundary_preview}."
                        ),
                        tool_hint="manual",
                    ),
                    ChainStep(
                        step_id=2,
                        description=(
                            f"Tamper trusted context such as {tenant_preview} and compare responses across principals."
                        ),
                        tool_hint="manual",
                    ),
                    ChainStep(
                        step_id=3,
                        description="Verify a durable unauthorized state change or cross-scope action, then capture a minimal reproducible PoC.",
                        tool_hint="manual",
                    ),
                ],
                phase_formed="EXPLOIT",
                vuln_basis=f"workflow_context: {workflow_preview}",
                iteration_formed=iteration,
                is_dynamic=True,
            )
        )
        existing_chain_ids.add(workflow_chain_id)

    if len(chains) >= max_chains:
        return chains[:max_chains]

    if tenant_markers or len(principals) >= 2 or len(roles) >= 2:
        principal_chain_id = f"principal_matrix_{iteration}"
        if principal_chain_id not in existing_chain_ids:
            chains.append(
                ExploitChain(
                    chain_id=principal_chain_id,
                    name="Principal Isolation Chain",
                    description=(
                        "Compare the same state-changing action across roles, tenants, and account contexts."
                    ),
                    steps=[
                        ChainStep(
                            step_id=0,
                            description=(
                                f"Replay one critical workflow request for each principal ({principal_preview}) and note authorization deltas."
                            ),
                            tool_hint="browser_action",
                        ),
                        ChainStep(
                            step_id=1,
                            description=(
                                f"Swap resource IDs and scope selectors ({tenant_preview}) between principals to test horizontal, vertical, and cross-tenant isolation."
                            ),
                            tool_hint="manual",
                        ),
                        ChainStep(
                            step_id=2,
                            description="Prove impact with an unauthorized read/write/action that persists beyond a single response.",
                            tool_hint="manual",
                        ),
                    ],
                    phase_formed="EXPLOIT",
                    vuln_basis=f"principal_matrix: {principal_preview}",
                    iteration_formed=iteration,
                    is_dynamic=True,
                )
            )
            existing_chain_ids.add(principal_chain_id)

    return chains[:max_chains]

def plan_chains(
    vulnerabilities: list[dict[str, Any]],
    existing_chain_ids: set[str],
    iteration: int = 0,
    max_chains: int = 5,
    causal_hypotheses: list[dict[str, Any]] | None = None,
    workflow_context: dict[str, Any] | None = None,
) -> list[ExploitChain]:
    new_chains: list[ExploitChain] = []
    candidates = list(vulnerabilities or [])

    if causal_hypotheses:
        for raw in causal_hypotheses:
            if not isinstance(raw, dict):
                continue
            statement = str(raw.get("statement", "")).strip()
            if statement:
                try:
                    posterior = float(raw.get("posterior", 0.0) or 0.0)
                except (TypeError, ValueError):
                    posterior = 0.0
                candidates.append({
                    "finding": statement,
                    "severity": "HIGH" if posterior >= 0.82 else "MEDIUM",
                    "type": "causal_hypothesis",
                })
                break

    if not candidates:
        return new_chains

    for chain in _generate_dynamic_chain(candidates, iteration):
        if len(new_chains) >= max_chains:
            break
        if chain.chain_id not in existing_chain_ids:
            new_chains.append(chain)
            existing_chain_ids.add(chain.chain_id)

    categories: dict[str, list[dict[str, Any]]] = {}
    for vuln in candidates:
        cat = _extract_category_from_finding(vuln)
        categories.setdefault(cat, []).append(vuln)

    for source_cat, vulns in categories.items():
        if len(new_chains) >= max_chains or source_cat == "UNKNOWN":
            continue

        template_steps = _EXPANSION_TEMPLATES.get(source_cat, [])
        if not template_steps:
            continue

        chain_id = f"expansion_{source_cat.lower()}_{iteration}"
        if chain_id in existing_chain_ids:
            continue

        steps = [_build_step(i, entry) for i, entry in enumerate(template_steps[:4])]
        new_chains.append(ExploitChain(
            chain_id=chain_id,
            name=f"Expand: {source_cat}",
            description=f"Explore additional attack vectors for {source_cat}",
            steps=steps,
            phase_formed="EXPLOIT",
            vuln_basis=source_cat,
            iteration_formed=iteration,
            is_dynamic=True,
        ))
        existing_chain_ids.add(chain_id)

    if len(new_chains) < max_chains:
        for chain in _build_novel_discovery_chains(
            candidates,
            existing_chain_ids=existing_chain_ids,
            iteration=iteration,
            max_chains=max_chains - len(new_chains),
        ):
            if len(new_chains) >= max_chains:
                break
            new_chains.append(chain)

    if len(new_chains) < max_chains:
        for chain in _build_workflow_context_chains(
            candidates,
            workflow_context=workflow_context,
            existing_chain_ids=existing_chain_ids,
            iteration=iteration,
            max_chains=max_chains - len(new_chains),
        ):
            if len(new_chains) >= max_chains:
                break
            new_chains.append(chain)

    if not new_chains:
        classifier = get_classifier()
        all_categories = classifier.get_all_categories()
        tested_cats = {c for c in categories.keys() if c != "UNKNOWN"}
        escalation_candidates: list[str] = []
        for cat in sorted(tested_cats):
            escalation_candidates.extend(
                target
                for target in classifier.get_escalation_targets(cat)
                if target not in tested_cats and target != "UNKNOWN"
            )

        prioritized_untested = list(dict.fromkeys(escalation_candidates))
        prioritized_untested.extend(
            c for c in all_categories if c not in tested_cats and c not in prioritized_untested and c != "UNKNOWN"
        )

        if prioritized_untested:
            suggested = prioritized_untested[:3]
            steps = []
            for idx, cat in enumerate(suggested):
                steps.append(
                    ChainStep(
                        step_id=idx,
                        description=(
                            f"Research {cat} attack vectors for this target"
                            if cat not in escalation_candidates
                            else f"Pivot from observed findings into {cat} using ontology escalation paths"
                        ),
                        tool_hint="web_search"
                        if cat not in escalation_candidates
                        else "manual",
                    )
                )
            steps.append(
                ChainStep(
                    step_id=len(steps),
                    description=(
                        "Test the highest-confidence adjacent category first, then branch into remaining untested classes"
                    ),
                    tool_hint="manual",
                )
            )
            chain_id = f"dynamic_generic_{iteration}"
            if chain_id not in existing_chain_ids:
                new_chains.append(ExploitChain(
                    chain_id=chain_id,
                    name=f"Novel Vector Exploration: {', '.join(suggested[:2])}",
                    description=f"Explore untested vulnerability categories: {', '.join(suggested[:3])}",
                    steps=steps,
                    phase_formed="EXPLOIT",
                    vuln_basis=f"untested: {', '.join(suggested[:3])}",
                    iteration_formed=iteration,
                    is_dynamic=True,
                ))
        else:
            chain_id = f"generic_exploit_{iteration}"
            if chain_id not in existing_chain_ids:
                new_chains.append(ExploitChain(
                    chain_id=chain_id,
                    name="Novel Attack Discovery",
                    description="All known categories tested — search for emergent workflow, protocol, and second-order attack paths",
                    steps=[
                        ChainStep(step_id=0, description="Analyze cross-component trust boundaries and business workflow for edge-case abuse", tool_hint="manual"),
                        ChainStep(step_id=1, description="Test state desync, cache/proxy behavior, and time-based races around real user actions", tool_hint="manual"),
                        ChainStep(step_id=2, description="Chain weak findings, telemetry anomalies, or second-order effects into a concrete high-impact exploit", tool_hint="manual"),
                    ],
                    phase_formed="EXPLOIT",
                    vuln_basis="novel_discovery",
                    iteration_formed=iteration,
                    is_dynamic=True,
                ))

    return new_chains[:max_chains]


def advance_chain(chain: ExploitChain, evidence: str = "") -> ChainStep | None:
    return chain.advance(evidence=evidence)


def build_chain_context(chains: list[ExploitChain], max_chains: int = 3) -> str:
    active = [c for c in chains if c.status in ("planning", "active")][:max_chains]
    if not active:
        return ""

    lines = ["<exploit_chain_plan>"]
    for chain in active:
        lines.append(f'  <chain id="{chain.chain_id}" name="{chain.name}" status="{chain.status}">')
        if chain.is_dynamic:
            lines.append("    <type>dynamic_generated</type>")
        if chain.description:
            lines.append(f"    <description>{chain.description}</description>")
        if chain.vuln_basis:
            lines.append(f'    <based_on vuln="{chain.vuln_basis[:100]}"/>')

        current = chain.current_step()
        if current:
            lines.append(f'    <current_step id="{current.step_id}" tool_hint="{current.tool_hint}">')
            lines.append(f"      {current.description}")
            lines.append("    </current_step>")

        done = chain.completed_steps()
        if done:
            lines.append(f'    <completed_steps count="{len(done)}">')
            for s in done[-3:]:
                lines.append(f"      ✓ Step {s.step_id}: {s.description[:80]}")
            lines.append("    </completed_steps>")

        remaining = chain.pending_steps()
        if remaining:
            lines.append(f'    <remaining_steps count="{len(remaining)}"/>')

        lines.append("  </chain>")

    lines.append(
        "  <instruction>Execute the CURRENT_STEP of the highest-priority chain. "
        "If no chains available, explore novel attack vectors not in templates.</instruction>"
    )
    lines.append("</exploit_chain_plan>")
    return "\n".join(lines)


def get_dynamic_chain_stats() -> dict[str, Any]:
    return {"total_dynamic_chains": len(_DYNAMIC_CHAINS), "chains": _DYNAMIC_CHAINS}


def clear_dynamic_chains() -> None:
    global _DYNAMIC_CHAINS
    _DYNAMIC_CHAINS = {}
    try:
        if _DYNAMIC_CHAINS_FILE.exists():
            _DYNAMIC_CHAINS_FILE.unlink()
    except Exception as e:
        logger.debug("Failed to clear dynamic chains: %s", e)

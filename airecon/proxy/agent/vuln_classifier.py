from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

logger = logging.getLogger("airecon.agent.vuln_classifier")

_ONTOLOGY_FILE = Path(__file__).parent.parent / "data" / "vuln_ontology.json"
_LEARNED_VULNS_FILE = Path.home() / ".airecon" / "learning" / "discovered_vuln_types.json"


@dataclass
class ClassificationResult:
    category: str
    subcategory: str
    confidence: float
    matched_signals: list[str]
    recommended_escalations: list[str]
    dedup_key: str


class UnifiedVulnClassifier:
    def __init__(self) -> None:
        self._ontology = self._load_ontology()
        self._learned_types: dict[str, Any] = self._load_learned_types()
        self._compiled_signals: dict[str, list[tuple[re.Pattern, str, float]]] = {}
        self._compile_signals()

    def _load_ontology(self) -> dict[str, Any]:
        try:
            if _ONTOLOGY_FILE.exists():
                with open(_ONTOLOGY_FILE) as f:
                    return json.load(f)
        except Exception as e:
            logger.debug("Failed to load vuln ontology: %s", e)
        return {"categories": {}, "escalation_graph": {"edges": []}}

    def _load_learned_types(self) -> dict[str, Any]:
        try:
            if _LEARNED_VULNS_FILE.exists():
                with open(_LEARNED_VULNS_FILE) as f:
                    return json.load(f)
        except Exception as e:
            logger.debug("Failed to load learned vuln types: %s", e)
        return {}

    def _compile_signals(self) -> None:
        for cat_name, cat_def in self._ontology.get("categories", {}).items():
            signals: list[tuple[re.Pattern, str, float]] = []
            for sig in cat_def.get("regex_signals", []):
                try:
                    pattern = re.compile(sig["pattern"], re.IGNORECASE)
                    signals.append((pattern, sig["label"], sig.get("weight", 0.5)))
                except re.error as e:
                    logger.debug("Invalid regex in %s: %s", cat_name, e)
            self._compiled_signals[cat_name] = signals

    def classify(
        self,
        text: str,
        context: dict[str, Any] | None = None,
    ) -> ClassificationResult:
        text_lower = text.lower()
        best_category = "UNKNOWN"
        best_subcategory = ""
        best_confidence = 0.0
        matched_signals: list[str] = []

        for cat_name, signals in self._compiled_signals.items():
            for pattern, label, weight in signals:
                if pattern.search(text_lower):
                    synonym_boost = sum(
                        0.05 for syn in self._ontology["categories"].get(cat_name, {}).get("synonyms", [])
                        if syn.lower() in text_lower
                    )
                    final_score = min(1.0, weight + synonym_boost)
                    if final_score > best_confidence:
                        best_category = cat_name
                        best_subcategory = label
                        best_confidence = final_score
                        matched_signals = [f"{label} (weight={weight:.2f})"]

        if best_confidence < 0.3:
            for cat_name, cat_def in self._ontology["categories"].items():
                match_count = sum(1 for syn in cat_def.get("synonyms", []) if syn.lower() in text_lower)
                if match_count >= 2:
                    score = min(1.0, 0.3 + (match_count * 0.1))
                    if score > best_confidence:
                        best_category = cat_name
                        best_subcategory = cat_name
                        best_confidence = score
                        matched_signals = [f"synonym_match ({match_count} terms)"]

        if best_confidence < 0.4:
            for learned_name, learned_def in self._learned_types.items():
                for indicator in learned_def.get("indicators", []):
                    if indicator.lower() in text_lower:
                        score = learned_def.get("confidence", 0.5)
                        if score > best_confidence:
                            best_category = learned_def.get("category", "UNKNOWN")
                            best_subcategory = learned_name
                            best_confidence = score
                            matched_signals = [f"learned_type: {learned_name}"]

        escalations = self._get_escalation_targets(best_category)
        dedup_key = self._build_dedup_key(best_category, best_subcategory, context)

        return ClassificationResult(
            category=best_category,
            subcategory=best_subcategory,
            confidence=best_confidence,
            matched_signals=matched_signals,
            recommended_escalations=escalations,
            dedup_key=dedup_key,
        )

    def _get_escalation_targets(self, category: str) -> list[str]:
        targets: set[str] = set()
        cat_def = self._ontology["categories"].get(category, {})
        targets.update(cat_def.get("escalation_targets", []))
        for edge in self._ontology.get("escalation_graph", {}).get("edges", []):
            if edge["from"] == category:
                targets.add(edge["to"])
        return sorted(targets)

    def _build_dedup_key(
        self,
        category: str,
        subcategory: str,
        context: dict[str, Any] | None,
    ) -> str:
        cat_def = self._ontology["categories"].get(category, {})
        key_fields = cat_def.get("dedup_key_fields", ["endpoint", "parameter"])
        parts = [category, subcategory]
        if context:
            for field_name in key_fields:
                value = context.get(field_name, "")
                if value:
                    parts.append(f"{field_name}={value}")
        return ":".join(parts)

    def learn_new_type(
        self,
        name: str,
        category: str,
        indicators: list[str],
        confidence: float = 0.6,
        description: str = "",
    ) -> None:
        self._learned_types[name] = {
            "category": category,
            "indicators": indicators,
            "confidence": confidence,
            "description": description,
            "discovered_at": __import__("datetime").datetime.now().isoformat(),
        }
        try:
            _LEARNED_VULNS_FILE.parent.mkdir(parents=True, exist_ok=True)
            with open(_LEARNED_VULNS_FILE, "w") as f:
                json.dump(self._learned_types, f, indent=2)
        except Exception as e:
            logger.debug("Failed to save learned vuln type: %s", e)

    def get_all_categories(self, include_children: bool = False) -> list[str]:
        labels = set(self._ontology["categories"].keys())
        if include_children:
            for cat_def in self._ontology.get("categories", {}).values():
                labels.update(cat_def.get("children", []))
        return sorted(labels)

    def get_escalation_targets(self, category: str) -> list[str]:
        return self._get_escalation_targets(category)

    def resolve_labels(self, text: str) -> list[str]:
        normalized = re.sub(r"[^a-z0-9]+", "_", str(text or "").lower()).strip("_")
        if not normalized:
            return []

        labels: set[str] = set()
        for cat_name, cat_def in self._ontology.get("categories", {}).items():
            cat_norm = re.sub(r"[^a-z0-9]+", "_", cat_name.lower()).strip("_")
            if normalized == cat_norm:
                labels.add(cat_name)

            for child in cat_def.get("children", []):
                child_norm = re.sub(r"[^a-z0-9]+", "_", str(child).lower()).strip("_")
                if normalized == child_norm:
                    labels.add(cat_name)
                    labels.add(str(child))

            for synonym in cat_def.get("synonyms", []):
                syn_norm = re.sub(r"[^a-z0-9]+", "_", str(synonym).lower()).strip("_")
                if normalized == syn_norm:
                    labels.add(cat_name)

        if not labels:
            result = self.classify(str(text))
            if result.category != "UNKNOWN":
                labels.add(result.category)
                if result.subcategory:
                    labels.add(result.subcategory)

        return sorted(labels)

    def get_escalation_graph(self) -> list[dict[str, Any]]:
        return self._ontology.get("escalation_graph", {}).get("edges", [])


_classifier: UnifiedVulnClassifier | None = None


def get_classifier() -> UnifiedVulnClassifier:
    global _classifier
    if _classifier is None:
        _classifier = UnifiedVulnClassifier()
    return _classifier


def classify_vulnerability(
    text: str,
    context: dict[str, Any] | None = None,
) -> ClassificationResult:
    return get_classifier().classify(text, context)


def reset_classifier() -> None:
    global _classifier
    _classifier = None

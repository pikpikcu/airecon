from __future__ import annotations


import logging
import random
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger("airecon.agent.generative_fuzzing")
rng = random.SystemRandom()


def mutate_url_encode(payload: str) -> str:
    encoding_map = {
        " ": "%20",
        "'": "%27",
        '"': "%22",
        "<": "%3C",
        ">": "%3E",
        "&": "%26",
        "=": "%3D",
        "+": "%2B",
        "#": "%23",
        ";": "%3B",
        "/": "%2F",
        "\\": "%5C",
        "(": "%28",
        ")": "%29",
    }
    result = payload
    for char, encoded in encoding_map.items():
        if char in result and rng.random() > 0.5:
            result = result.replace(char, encoded, 1)
    return result


def mutate_double_url_encode(payload: str) -> str:
    first = mutate_url_encode(payload)
    return mutate_url_encode(first)


def mutate_unicode(payload: str) -> str:
    unicode_map = {
        "'": "\u02bc",
        '"': "\u201c",
        "<": "\ufe64",
        ">": "\ufe65",
        "/": "\u2044",
        "\\": "\u2216",
    }
    result = payload
    for char, uni in unicode_map.items():
        if char in result and rng.random() > 0.5:
            result = result.replace(char, uni, 1)
    return result


def mutate_case_toggle(payload: str) -> str:
    return "".join(c.upper() if rng.random() > 0.5 else c.lower() for c in payload)


def mutate_null_byte(payload: str) -> str:
    pos = rng.randint(1, max(1, len(payload) - 1))
    return payload[:pos] + "%00" + payload[pos:]


def mutate_comment_injection(payload: str) -> str:
    comment_styles = [
        f"/*{payload}*/",
        f"/*!{payload}*/",
        f"--{payload}--",
        f"#{payload}#",
    ]
    return rng.choice(comment_styles)


def mutate_whitespace(payload: str) -> str:
    whitespaces = ["%09", "%0a", "%0d", "+", "\t", "\n"]
    parts = list(payload)
    if len(parts) > 1:
        pos = rng.randint(1, len(parts) - 1)
        ws = rng.choice(whitespaces)
        parts.insert(pos, ws)
    return "".join(parts)


def mutate_concat(payload: str) -> str:
    if "'" in payload:
        parts = payload.split("'", 1)
        return f"' CONCAT({parts[0]!r}, {parts[1]!r})" if len(parts) > 1 else payload
    return f"CONCAT({payload!r})"


def mutate_html_entity(payload: str) -> str:
    entity_map = {
        "'": "&apos;",
        '"': "&quot;",
        "<": "&lt;",
        ">": "&gt;",
        "&": "&amp;",
    }
    result = payload
    for char, entity in entity_map.items():
        if char in result and rng.random() > 0.5:
            result = result.replace(char, entity, 1)
    return result


def mutate_backtick(payload: str) -> str:
    """Wrap in backticks (MySQL)."""
    return f"`{payload}`"


def mutate_nested_tags(payload: str) -> str:
    """Nest XSS payload in multiple tags."""
    if "<script" in payload.lower():
        return f"<div><span>{payload}</span></div>"
    return f"<div>{payload}</div>"


_MUTATION_OPERATORS: dict[str, callable] = {
    "url_encode": mutate_url_encode,
    "double_url_encode": mutate_double_url_encode,
    "unicode": mutate_unicode,
    "case_toggle": mutate_case_toggle,
    "null_byte": mutate_null_byte,
    "comment_injection": mutate_comment_injection,
    "whitespace": mutate_whitespace,
    "concat": mutate_concat,
    "html_entity": mutate_html_entity,
    "backtick": mutate_backtick,
    "nested_tags": mutate_nested_tags,
}


@dataclass
class PayloadGenome:

    payload: str
    vuln_type: str
    fitness: float = 0.0
    generation: int = 0
    mutation_history: list[str] = field(default_factory=list)
    waf_bypassed: list[str] = field(default_factory=list)
    test_count: int = 0
    success_count: int = 0

    @property
    def success_rate(self) -> float:
        if self.test_count == 0:
            return 0.0
        return self.success_count / self.test_count


class GenerativeFuzzingEngine:

    def __init__(
        self,
        population_size: int = 50,
        mutation_rate: float = 0.3,
        crossover_rate: float = 0.2,
        elite_count: int = 5,
        max_generations: int = 10,
    ):
        self.population_size = population_size
        self.mutation_rate = mutation_rate
        self.crossover_rate = crossover_rate
        self.elite_count = elite_count
        self.max_generations = max_generations
        self.population: dict[str, list[PayloadGenome]] = {}
        self.best_payloads: dict[str, list[PayloadGenome]] = {}

    def initialize_population(self, seed_payloads: dict[str, list[str]]) -> None:
        total = 0
        for vuln_type, payloads in seed_payloads.items():
            self.population[vuln_type] = [
                PayloadGenome(payload=p, vuln_type=vuln_type, generation=0)
                for p in payloads
            ]
            # Pad to population_size with mutated variants
            while len(self.population[vuln_type]) < self.population_size:
                parent = rng.choice(payloads)
                mutated = self._mutate(parent, vuln_type)
                self.population[vuln_type].append(
                    PayloadGenome(payload=mutated, vuln_type=vuln_type, generation=0)
                )
            total += len(self.population[vuln_type])
        logger.info(
            "[GenFuzz] Population initialized: %d vuln types, %d total genomes",
            len(seed_payloads),
            total,
        )
        logger.debug(
            "[GenFuzz] Vuln types: %s (sizes: %s)",
            list(seed_payloads.keys()),
            {k: len(v) for k, v in self.population.items()},
        )

    def evolve(
        self,
        vuln_type: str,
        test_results: list[dict[str, Any]],
    ) -> list[str]:
        """Evolve population based on test results.

        Args:
            vuln_type: Vulnerability type to evolve
            test_results: List of {"payload": str, "fitness": float, "waf": str|None}

        Returns:
            New generation of payloads
        """
        if vuln_type not in self.population:
            return []

        # Update fitness scores
        fitness_map = {r["payload"]: r.get("fitness", 0.0) for r in test_results}
        waf_map = {r["payload"]: r.get("waf", "") for r in test_results}

        for genome in self.population[vuln_type]:
            if genome.payload in fitness_map:
                genome.fitness = fitness_map[genome.payload]
                genome.test_count += 1
                if genome.fitness > 0.5:
                    genome.success_count += 1
                if waf_map.get(genome.payload):
                    genome.waf_bypassed.append(waf_map[genome.payload])
                    logger.debug(
                        "[GenFuzz] Payload WAF bypass: vuln_type=%s waf=%s payload=%.30s",
                        vuln_type,
                        waf_map[genome.payload],
                        genome.payload[:60],
                    )

        # Sort by fitness
        self.population[vuln_type].sort(key=lambda g: g.fitness, reverse=True)

        # Track best payloads
        best = [
            g for g in self.population[vuln_type][: self.elite_count] if g.fitness > 0.3
        ]
        if vuln_type not in self.best_payloads:
            self.best_payloads[vuln_type] = []
        self.best_payloads[vuln_type].extend(best)
        self.best_payloads[vuln_type] = sorted(
            self.best_payloads[vuln_type], key=lambda g: g.fitness, reverse=True
        )[:20]

        stats = self.get_generation_stats(vuln_type)
        top_payloads = [g.payload[:50] for g in self.population[vuln_type][:3]]
        logger.info(
            "[GenFuzz] Generation=%s vuln_type=%s avg_fitness=%.3f max_fitness=%.3f top_payloads=%s",
            stats["generation"],
            vuln_type,
            stats["avg_fitness"],
            stats["max_fitness"],
            top_payloads,
        )

        # Create next generation
        next_gen = self._create_next_generation(vuln_type)
        logger.debug(
            "[GenFuzz] Next generation created: %d genomes for vuln_type=%s",
            len(next_gen),
            vuln_type,
        )
        self.population[vuln_type] = next_gen

        result = [g.payload for g in self.best_payloads.get(vuln_type, [])]
        logger.debug(
            "[GenFuzz] Returning %d best payloads for vuln_type=%s",
            len(result),
            vuln_type,
        )
        return result

    def get_top_payloads(
        self, vuln_type: str, n: int = 10, min_fitness: float = 0.3
    ) -> list[str]:
        """Get top N payloads for a vulnerability type."""
        best = self.best_payloads.get(vuln_type, [])
        result = [g.payload for g in best if g.fitness >= min_fitness][:n]
        logger.debug(
            "[GenFuzz] get_top_payloads: vuln_type=%s n=%d min_fitness=%.2f returned=%d",
            vuln_type,
            n,
            min_fitness,
            len(result),
        )
        return result

    def get_waf_bypass_payloads(
        self, vuln_type: str, waf_name: str, n: int = 5
    ) -> list[str]:
        bypassed = [
            g
            for g in self.best_payloads.get(vuln_type, [])
            if waf_name.lower() in [w.lower() for w in g.waf_bypassed]
        ]
        return [g.payload for g in bypassed[:n]]

    def _create_next_generation(self, vuln_type: str) -> list[PayloadGenome]:
        current = self.population[vuln_type]
        if not current:
            return []

        next_gen: list[PayloadGenome] = []

        # Elitism: keep top performers
        for genome in current[: self.elite_count]:
            next_gen.append(
                PayloadGenome(
                    payload=genome.payload,
                    vuln_type=vuln_type,
                    fitness=genome.fitness,
                    generation=genome.generation + 1,
                    mutation_history=genome.mutation_history.copy(),
                    waf_bypassed=genome.waf_bypassed.copy(),
                    test_count=genome.test_count,
                    success_count=genome.success_count,
                )
            )

        # Crossover and mutation
        while len(next_gen) < self.population_size:
            # Tournament selection
            parent1 = self._tournament_select(current)
            parent2 = self._tournament_select(current)

            if parent1 and parent2 and rng.random() < self.crossover_rate:
                child_payload = self._crossover(parent1.payload, parent2.payload)
                logger.debug(
                    "[GenFuzz] Crossover: parent1=%.20s + parent2=%.20s -> child=%.20s",
                    parent1.payload[:30],
                    parent2.payload[:30],
                    child_payload[:30],
                )
            elif parent1:
                child_payload = parent1.payload
            else:
                child_payload = rng.choice(current).payload if current else "test"

            # Mutate
            if rng.random() < self.mutation_rate:
                child_payload, mutation_name = self._mutate_with_name(
                    child_payload, vuln_type
                )
                logger.debug(
                    "[GenFuzz] Mutation applied: operator=%s vuln_type=%s",
                    mutation_name,
                    vuln_type,
                )
                mutation_history = (parent1.mutation_history if parent1 else []) + [
                    mutation_name
                ]
            else:
                mutation_history = parent1.mutation_history if parent1 else []

            next_gen.append(
                PayloadGenome(
                    payload=child_payload,
                    vuln_type=vuln_type,
                    generation=current[0].generation + 1 if current else 1,
                    mutation_history=mutation_history,
                )
            )

        return next_gen[: self.population_size]

    def _tournament_select(
        self, population: list[PayloadGenome], tournament_size: int = 5
    ) -> PayloadGenome | None:
        if not population:
            return None
        tournament = rng.sample(population, min(tournament_size, len(population)))
        return max(tournament, key=lambda g: g.fitness)

    def _crossover(self, parent1: str, parent2: str) -> str:
        if not parent1 or not parent2:
            return parent1 or parent2

        min_len = min(len(parent1), len(parent2))
        if min_len < 2:
            return parent1

        point = rng.randint(1, min_len - 1)
        if rng.random() > 0.5:
            return parent1[:point] + parent2[point:]
        return parent2[:point] + parent1[point:]

    def _mutate(self, payload: str, vuln_type: str) -> str:
        mutated, _ = self._mutate_with_name(payload, vuln_type)
        return mutated

    def _mutate_with_name(self, payload: str, vuln_type: str) -> tuple[str, str]:
        applicable = list(_MUTATION_OPERATORS.keys())

        if vuln_type == "sql_injection":
            applicable = [
                "comment_injection",
                "concat",
                "backtick",
                "url_encode",
                "whitespace",
                "null_byte",
            ]
        elif vuln_type == "xss":
            applicable = [
                "nested_tags",
                "unicode",
                "html_entity",
                "url_encode",
                "case_toggle",
            ]
        elif vuln_type == "path_traversal":
            applicable = ["double_url_encode", "unicode", "null_byte", "whitespace"]
        elif vuln_type == "ssti":
            applicable = ["unicode", "whitespace", "url_encode"]
        elif vuln_type == "command_injection":
            applicable = ["whitespace", "null_byte", "url_encode", "comment_injection"]

        mutation_name = rng.choice(applicable)
        operator = _MUTATION_OPERATORS[mutation_name]
        return operator(payload), mutation_name

    def get_generation_stats(self, vuln_type: str) -> dict[str, Any]:
        pop = self.population.get(vuln_type, [])
        if not pop:
            logger.debug(
                "[GenFuzz] get_generation_stats: no population for vuln_type=%s",
                vuln_type,
            )
            return {"count": 0}

        fitnesses = [g.fitness for g in pop]
        stats = {
            "count": len(pop),
            "generation": pop[0].generation if pop else 0,
            "avg_fitness": sum(fitnesses) / len(fitnesses),
            "max_fitness": max(fitnesses),
            "min_fitness": min(fitnesses),
            "top_payloads": [
                g.payload
                for g in sorted(pop, key=lambda g: g.fitness, reverse=True)[:5]
            ],
        }
        logger.debug(
            "[GenFuzz] Stats vuln_type=%s gen=%d count=%d avg=%.3f max=%.3f min=%.3f",
            vuln_type,
            stats["generation"],
            stats["count"],
            stats["avg_fitness"],
            stats["max_fitness"],
            stats["min_fitness"],
        )
        return stats

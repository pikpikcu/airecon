from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import math
import re
import time
import uuid
from collections.abc import AsyncIterator as AsyncIteratorABC
from collections.abc import Awaitable, Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, AsyncIterator, Callable, cast
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import httpx

logger = logging.getLogger("airecon.fuzzer")


def response_signature(status: int, body: str) -> str:
    body_bytes = body.encode("utf-8", errors="replace")
    digest = hashlib.md5(body_bytes[:1000], usedforsecurity=False).hexdigest()
    return f"{status}:{len(body_bytes)}:{digest}"


_data_file = Path(__file__).parent / "data" / "fuzzer_data.json"
try:
    with open(_data_file, "r") as f:
        _fuzzer_data = json.load(f)
except FileNotFoundError:
    logger.warning(
        f"AIRecon fuzzer data file not found at {_data_file}. Fuzzer will be disabled. "
        "Ensure the package is installed correctly (pip install -e .)."
    )
    _fuzzer_data = {}
except json.JSONDecodeError as e:
    logger.warning(
        f"AIRecon fuzzer data file is corrupted at {_data_file}: {e}. Fuzzer will be disabled."
    )
    _fuzzer_data = {}

FUZZ_POINTS = _fuzzer_data.get("FUZZ_POINTS", [])
FUZZ_PAYLOADS = _fuzzer_data.get("FUZZ_PAYLOADS", {})
VULNERABLE_PATTERNS = _fuzzer_data.get("VULNERABLE_PATTERNS", {})
WAF_SIGNATURES = _fuzzer_data.get("WAF_SIGNATURES", {})
CHAIN_RULES = _fuzzer_data.get("CHAIN_RULES", {})
CHAIN_PAYLOADS = _fuzzer_data.get("CHAIN_PAYLOADS", {})
PARAM_TYPE_MAP: dict[str, list[str]] = _fuzzer_data.get("PARAM_TYPE_MAP", {})
# Tech-stack → extra payloads, data-driven (no hardcoded tech branches in code).
# Shape: {vuln_type: {tech_token: [payloads]}}; tech_token matches a detected
# technology name (exact) or as a substring of the joined tech string.
TECH_PAYLOAD_AUGMENTS: dict[str, dict[str, list[str]]] = _fuzzer_data.get(
    "TECH_PAYLOAD_AUGMENTS", {}
)
# URL-context → priority parameter names, data-driven and ordered (first match
# wins). No hardcoded url-keyword branches in code.
PRIORITY_PARAM_HINTS: list[dict[str, list[str]]] = _fuzzer_data.get(
    "PRIORITY_PARAM_HINTS", []
)
# Vuln-family → extra follow-on chain steps, data-driven (no hardcoded family
# membership in code). Each entry: {"members": [...], "follow_ons": [...]}.
CHAIN_FAMILY_FOLLOWONS: list[dict[str, list[str]]] = _fuzzer_data.get(
    "CHAIN_FAMILY_FOLLOWONS", []
)

_SEVERITY_ORDER: list[str] = _fuzzer_data.get(
    "_SEVERITY_ORDER",
    ["info", "low", "medium", "high", "critical"],
)

_FUZZ_GATHER_BATCH: int = 50

_ATTACK_TYPE_TO_PAYLOADS: dict[str, list[str]] = {
    "IDOR": ["idor", "parameter_pollution"],
    "SSRF": ["ssrf"],
    "PATH_TRAVERSAL": ["path_traversal"],
    "SQLi_XSS": ["sql_injection", "xss"],
    "AUTH": ["jwt", "mass_assignment"],
    "BUSINESS_LOGIC": ["mass_assignment", "parameter_pollution"],
    "INJECT": ["sql_injection", "xss", "command_injection", "ssti"],
}

_PATTERN_URL_RE = re.compile(r"https?://[^\s\"')>]+", re.IGNORECASE)
_CACHE_HEADER_RE = re.compile(
    r"^(?:x-cache|cf-cache-status|age|via|x-served-by|x-cache-hits)$",
    re.IGNORECASE,
)


def _load_json_safely(path: Path, default: Any) -> Any:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as exc:
        logger.debug("Could not load %s: %s", path, exc)
        return default


def _flatten_chain_entries(raw: Any) -> list[dict[str, Any]]:
    if isinstance(raw, dict):
        candidate = raw.get("chains", [])
    elif isinstance(raw, list):
        candidate = raw
    else:
        return []
    return [entry for entry in candidate if isinstance(entry, dict)]


_patterns_file = Path(__file__).parent / "data" / "unified_patterns.json"
_zeroday_file = Path(__file__).parent / "data" / "zeroday_patterns.json.bak"
_attack_chain_file = Path(__file__).parent / "data" / "attack_chains.json"

def _load_expert_patterns() -> dict[str, Any]:
    """Load expert patterns from unified catalog."""
    try:
        from .data_loader import load_vuln_patterns
        data = load_vuln_patterns()
        return {k: v for k, v in data.items() if not k.startswith("_")}
    except Exception:
        return {}

def _load_zeroday_patterns() -> dict[str, Any]:
    """Load zeroday patterns from unified catalog (CRITICAL severity only)."""
    try:
        from .data_loader import load_zeroday_patterns
        return load_zeroday_patterns()
    except Exception:
        return {}

_EXPERT_PATTERNS: dict[str, dict[str, Any]] = _load_expert_patterns()
_ZERODAY_PATTERNS: dict[str, dict[str, Any]] = _load_zeroday_patterns()
_ATTACK_CHAIN_LIBRARY: list[dict[str, Any]] = _flatten_chain_entries(
    _load_json_safely(_attack_chain_file, [])
)


@dataclass
class FuzzResult:
    target: str
    parameter: str
    payload: str
    vuln_type: str
    severity: str
    evidence: str
    confidence: float
    response_code: int
    response_length: int
    time_ms: float


@dataclass
class ChainLink:
    vuln_type: str
    parameter: str
    payload: str
    prerequisite: str | None
    impact_description: str
    confidence: float


@dataclass
class ExploitChain:
    name: str
    trigger_vuln: str
    steps: list[ChainLink]
    total_confidence: float
    combined_severity: str
    narrative: str


@dataclass
class RealTimeEvent:
    event_type: str
    data: dict[str, Any]
    timestamp: float = field(default_factory=time.monotonic)


@dataclass
class ExpertGuidance:
    recommendation: str
    reason: str
    priority: str
    tools_suggested: list[str]
    confidence: float


class Fuzzer:
    def __init__(
        self,
        target: str,
        wordlist: list[str] | None = None,
        threads: int = 10,
        timeout: int = 30,
        method: str = "GET",
        headers: dict[str, str] | None = None,
        enable_waf_bypass: bool = True,
        enable_rate_limit: bool = True,
        enable_auth_recovery: bool = True,
        auth_login_url: str | None = None,
    ):
        self.target = target
        self.wordlist = wordlist or FUZZ_POINTS
        self.threads = threads
        self.timeout = timeout
        self.method = method.upper()
        self.headers: dict[str, str] = headers or {}
        self.results: list[FuzzResult] = []
        self._baseline: dict[str, dict[str, Any]] = {}
        self._semaphore = asyncio.Semaphore(threads)

        self._timeout_counts: dict[str, int] = {}
        self._direct_client: httpx.AsyncClient | None = None
        self._waf_bypass_attempts: dict[str, int] = {}
        self._waf_bypass_limit = self._get_fuzzer_config().fuzzer_waf_bypass_limit
        self._payload_memory_tech_stack: list[str] = []

        self.enable_waf_bypass = enable_waf_bypass
        if enable_waf_bypass:
            from .agent.waf_bypass import WAFBypassEngine

            self.waf_engine = WAFBypassEngine(timeout=timeout)
        else:
            self.waf_engine = None
        self.detected_wafs: list[str] = []

        self.enable_rate_limit = enable_rate_limit
        if enable_rate_limit:
            from .agent.rate_limiter import AdaptiveRateLimiter

            self.rate_limiter = AdaptiveRateLimiter(
                base_delay=1.0 / threads,
                max_delay=60.0,
                max_retries=5,
                timeout=timeout,
            )
        else:
            self.rate_limiter = None

        self.enable_auth_recovery = enable_auth_recovery
        if enable_auth_recovery:
            from .agent.auth_manager import AuthManager

            self.auth_manager = AuthManager(timeout=timeout)
        else:
            self.auth_manager = None
        self.auth_login_url = (
            auth_login_url.strip()
            if isinstance(auth_login_url, str) and auth_login_url.strip()
            else None
        )

        # Payload Memory Engine
        self.payload_memory = None
        try:
            from .config import get_config

            cfg = get_config()
            if cfg.payload_memory_enabled:
                from .agent.payload_memory import PayloadMemoryEngine

                self.payload_memory = PayloadMemoryEngine(
                    max_records=cfg.payload_memory_max_records,
                    ttl_seconds=cfg.payload_memory_ttl_days * 86400,
                )
        except Exception as exc:
            logger.debug("Payload memory init skipped: %s", exc)

    async def close(self) -> None:
        if self.waf_engine:
            await self.waf_engine.close()
        if self.rate_limiter:
            await self.rate_limiter.close()
        if self.auth_manager:
            await self.auth_manager.close()
        if self._direct_client:
            await self._direct_client.aclose()
            self._direct_client = None

    async def __aenter__(self) -> "Fuzzer":
        return self

    async def __aexit__(self, *_: object) -> None:
        await self.close()

    @staticmethod
    def _get_fuzzer_config():
        from .config import get_config

        return get_config()

    async def _profile_target_if_enabled(self):
        """Profile target if intelligence is enabled."""
        try:
            cfg = self._get_fuzzer_config()
            if (
                not cfg.intelligence_enabled
                or not cfg.intelligence_target_profiling_enabled
            ):
                return None

            from .agent.target_profiler import TargetProfiler

            profiler = TargetProfiler(timeout=min(self.timeout, 15))
            profile = await profiler.profile_target(self.target, self.headers or None)
            logger.info(
                f"Target profiled: {len(profile.technologies)} technologies detected, "
                f"security score={profile.security_score:.0f}, risk={profile.risk_level}"
            )
            return profile
        except Exception as e:
            logger.debug(f"Target profiling skipped: {e}")
            return None

    def _prioritize_vuln_types(
        self, vuln_types: list[str] | None, profile
    ) -> list[str] | None:
        """Prioritize vulnerability types based on target profile."""
        if not profile or not profile.attack_surface:
            return vuln_types

        attack_vectors = profile.attack_surface.get("attack_vectors", [])
        tech_names = [t.name.lower() for t in profile.technologies]

        priority_map = {
            "sql_injection": ("mysql" in tech_names or "postgresql" in tech_names),
            "nosql_injection": "mongodb" in tech_names,
            "xss": any(
                fw in tech_names for fw in ("django", "rails", "express", "flask")
            ),
            "path_traversal": "nginx" in tech_names,
            "ssti": any(fw in tech_names for fw in ("flask", "django", "express")),
            "command_injection": True,
        }

        if vuln_types:
            scored = []
            for vt in vuln_types:
                is_relevant = priority_map.get(vt, False)
                if vt in attack_vectors:
                    is_relevant = True
                scored.append((vt, 1.0 if is_relevant else 0.5))
            scored.sort(key=lambda x: x[1], reverse=True)
            return [vt for vt, _ in scored]

        return vuln_types

    async def _init_generative_fuzzing_if_enabled(self):
        """Initialize generative fuzzing engine.

        Generative fuzzing is now enabled by default for all fuzzing operations.
        The config gates are kept for backward compatibility but default to True.
        """
        try:
            cfg = self._get_fuzzer_config()
            # Generative fuzzing is now always enabled unless explicitly disabled
            if not getattr(cfg, 'intelligence_generative_fuzzing_enabled', True):
                return None

            from .agent.generative_fuzzing import GenerativeFuzzingEngine

            engine = GenerativeFuzzingEngine(
                population_size=cfg.intelligence_generative_population_size,
                max_generations=cfg.intelligence_generative_max_generations,
            )
            engine.initialize_population(FUZZ_PAYLOADS)
            logger.info(
                f"Generative fuzzing initialized: pop={cfg.intelligence_generative_population_size}, "
                f"max_gen={cfg.intelligence_generative_max_generations}"
            )
            return engine
        except Exception as e:
            logger.debug(f"Generative fuzzing init skipped: {e}")
            return None

    async def _evolve_payloads_batch(self, gen_engine, results: list, batch_idx: int):
        """Evolve payloads based on batch results."""
        try:
            test_results = []
            for r in results:
                if isinstance(r, FuzzResult):
                    test_results.append(
                        {
                            "payload": r.payload,
                            "fitness": r.confidence,
                            "waf": self.detected_wafs[0]
                            if self.detected_wafs
                            else None,
                        }
                    )

            if not test_results:
                return

            for vt in set(r.vuln_type for r in results if isinstance(r, FuzzResult)):
                vt_results = [tr for tr in test_results if tr.get("vuln_type") == vt]
                if vt_results:
                    gen_engine.evolve(vt, vt_results)
                    top = gen_engine.get_top_payloads(vt, n=3, min_fitness=0.5)
                    if top:
                        logger.debug(
                            f"Gen fuzz batch {batch_idx}: evolved {len(top)} top {vt} payloads"
                        )
        except Exception as e:
            logger.debug(f"Payload evolution skipped: {e}")

    async def _get_direct_client(self) -> httpx.AsyncClient:
        if self._direct_client is None:
            self._direct_client = httpx.AsyncClient(
                timeout=self.timeout,
                verify=False,  # nosec B501 — intentional for pentesting
                follow_redirects=True,
                headers=self.headers,
            )
        return self._direct_client

    def _request_kwargs_for_value(self, param: str, value: str) -> dict[str, Any]:
        kwargs: dict[str, Any] = {"headers": self.headers}
        if self.method == "GET":
            kwargs["params"] = {param: value}
        else:
            kwargs["data"] = {param: value}
        return kwargs

    def set_auth_credentials(
        self,
        username: str,
        password: str,
        extra_fields: dict[str, str] | None = None,
        login_url: str | None = None,
    ) -> None:
        if not self.auth_manager:
            return
        self.auth_manager.set_credentials(username, password, extra_fields)
        if isinstance(login_url, str) and login_url.strip():
            self.auth_login_url = login_url.strip()

    def set_auth_login_url(self, login_url: str) -> None:
        clean = login_url.strip()
        if clean:
            self.auth_login_url = clean

    def _resolve_auth_login_url(self) -> str | None:
        if self.auth_login_url:
            return self.auth_login_url
        parsed = urlparse(self.target)
        path = parsed.path.lower()
        if any(
            token in path
            for token in ("/login", "/signin", "/sign-in", "/auth", "/session")
        ):
            return self.target
        return None

    def _refresh_cookie_header_from_auth(self) -> None:
        if not self.auth_manager or not self.auth_manager.auth_cookies:
            return
        pairs: list[str] = []
        for cookie in self.auth_manager.auth_cookies:
            name = str(cookie.get("name", "")).strip()
            value = str(cookie.get("value", "")).strip()
            if name:
                pairs.append(f"{name}={value}")
        if pairs:
            self.headers["Cookie"] = "; ".join(pairs)

    async def _maybe_recover_auth(
        self,
        response: httpx.Response,
        *,
        param: str,
        value: str,
    ) -> httpx.Response:
        if not self.auth_manager:
            return response
        if response.status_code not in (401, 403):
            return response

        login_url = self._resolve_auth_login_url()
        if not login_url:
            logger.debug(
                "Skipping auth recovery for %s: no login URL configured",
                self.target,
            )
            return response

        recovered = await self.auth_manager.handle_auth_failure(response, login_url)
        if not recovered:
            return response

        self._refresh_cookie_header_from_auth()
        req_kwargs = self._request_kwargs_for_value(param, value)

        try:
            if self.rate_limiter:
                retried = await self.rate_limiter.request(
                    self.method,
                    self.target,
                    **req_kwargs,
                )
            else:
                client = await self._get_direct_client()
                if self.method == "GET":
                    retried = await client.get(self.target, params={param: value})
                else:
                    retried = await client.post(self.target, data={param: value})
        except Exception as exc:
            logger.debug("Auth recovery retry failed: %s", exc)
            return response

        return retried if retried is not None else response

    @staticmethod
    def _response_elapsed_ms(response: httpx.Response, fallback_ms: float) -> float:
        ext_val = response.extensions.get("airecon_request_ms")
        if ext_val is not None:
            try:
                return float(ext_val)
            except (TypeError, ValueError):
                pass
        if response.elapsed is not None:
            try:
                return float(response.elapsed.total_seconds() * 1000.0)
            except Exception as e:
                logger.debug("Expected failure reading response elapsed time: %s", e)
        return fallback_ms

    @staticmethod
    def _merge_headers(
        base_headers: dict[str, str] | None,
        override_headers: dict[str, str] | None,
    ) -> dict[str, str] | None:
        if not base_headers and not override_headers:
            return None
        merged: dict[str, str] = {}
        if base_headers:
            merged.update(base_headers)
        if override_headers:
            merged.update(override_headers)
        return merged

    @staticmethod
    def _extract_urls_from_text(values: list[str]) -> list[str]:
        found: list[str] = []
        seen: set[str] = set()
        for value in values:
            for match in _PATTERN_URL_RE.findall(str(value)):
                url = match.strip().rstrip(".,;")
                if url and url not in seen:
                    seen.add(url)
                    found.append(url)
        return found

    def _collect_pattern_texts(self, keys: list[str], fields: list[str]) -> list[str]:
        texts: list[str] = []
        for key in keys:
            expert = _EXPERT_PATTERNS.get(key, {})
            zeroday = _ZERODAY_PATTERNS.get(key, {})
            for source in (expert, zeroday):
                for pattern_field in fields:
                    items = source.get(pattern_field, [])
                    if isinstance(items, list):
                        texts.extend(str(item) for item in items if item)
        return texts

    def _collect_attack_chain_step_texts(
        self, trigger_keywords: list[str]
    ) -> list[str]:
        texts: list[str] = []
        lowered_keywords = [k.lower() for k in trigger_keywords if k]
        for chain in _ATTACK_CHAIN_LIBRARY:
            trigger_blob = " ".join(str(t).lower() for t in chain.get("triggers", []))
            if lowered_keywords and not any(
                kw in trigger_blob for kw in lowered_keywords
            ):
                continue
            for step in chain.get("steps", []):
                if isinstance(step, dict):
                    desc = step.get("description", "")
                else:
                    desc = str(step)
                if desc:
                    texts.append(str(desc))
        return texts

    async def _probe_request(
        self,
        *,
        url: str | None = None,
        method: str | None = None,
        params: dict[str, str] | None = None,
        data: dict[str, str] | None = None,
        json_body: Any = None,
        headers: dict[str, str] | None = None,
        content: bytes | str | None = None,
        use_rate_limiter: bool = True,
    ) -> tuple[httpx.Response | None, float]:
        target_url = url or self.target
        http_method = (method or self.method).upper()
        merged_headers = self._merge_headers(self.headers, headers)
        req_kwargs: dict[str, Any] = {}
        if params is not None:
            req_kwargs["params"] = params
        if data is not None:
            req_kwargs["data"] = data
        if json_body is not None:
            req_kwargs["json"] = json_body
        if content is not None:
            req_kwargs["content"] = content
        if merged_headers is not None:
            req_kwargs["headers"] = merged_headers

        t0 = time.monotonic()
        try:
            if use_rate_limiter and self.rate_limiter:
                response = await self.rate_limiter.request(
                    http_method, target_url, **req_kwargs
                )
                if response is None:
                    return None, (time.monotonic() - t0) * 1000.0
                elapsed = self._response_elapsed_ms(
                    response,
                    fallback_ms=(time.monotonic() - t0) * 1000.0,
                )
                return response, elapsed

            client = await self._get_direct_client()
            response = await client.request(http_method, target_url, **req_kwargs)
            elapsed = (time.monotonic() - t0) * 1000.0
            return response, elapsed
        except httpx.TimeoutException:
            return None, self.timeout * 1000.0
        except Exception as exc:
            logger.debug(
                "Advanced probe request failed method=%s url=%s: %s",
                http_method,
                target_url,
                exc,
            )
            return None, (time.monotonic() - t0) * 1000.0

    async def _fetch_baseline(self, param: str) -> dict[str, Any]:
        if param in self._baseline:
            return self._baseline[param]
        try:
            samples: list[dict[str, Any]] = []

            if self.rate_limiter:
                for _ in range(2):
                    t0 = time.monotonic()
                    resp = await self.rate_limiter.request(
                        self.method,
                        self.target,
                        **self._request_kwargs_for_value(param, "test"),
                    )
                    if resp is None:
                        raise RuntimeError("baseline request failed after retries")
                    elapsed = self._response_elapsed_ms(
                        resp,
                        fallback_ms=(time.monotonic() - t0) * 1000.0,
                    )
                    samples.append(
                        {
                            "body": resp.text,
                            "status": resp.status_code,
                            "time_ms": elapsed,
                            "length": len(resp.text),
                            "headers": dict(resp.headers),
                        }
                    )
            else:
                client = await self._get_direct_client()
                for _ in range(2):
                    t0 = time.monotonic()
                    if self.method == "GET":
                        parsed = urlparse(self.target)
                        params = parse_qs(parsed.query)
                        params[param] = ["test"]
                        url = urlunparse(
                            parsed._replace(query=urlencode(params, doseq=True))
                        )
                        resp = await client.get(url)
                    else:
                        resp = await client.post(self.target, data={param: "test"})
                    elapsed = (time.monotonic() - t0) * 1000
                    samples.append(
                        {
                            "body": resp.text,
                            "status": resp.status_code,
                            "time_ms": elapsed,
                            "length": len(resp.text),
                            "headers": dict(resp.headers),
                        }
                    )

            if self.waf_engine and samples:
                detected = self.waf_engine.detect_waf(
                    samples[0].get("headers", {}),
                    samples[0].get("body", ""),
                    samples[0].get("status", 200),
                )
                if detected and not self.detected_wafs:
                    self.detected_wafs = detected
                    logger.info(f"WAF detected during baseline: {', '.join(detected)}")

            length_variance = abs(samples[1]["length"] - samples[0]["length"])
            baseline = {
                "body": samples[0]["body"],
                "status": samples[0]["status"],
                "time_ms": (samples[0]["time_ms"] + samples[1]["time_ms"]) / 2,
                "length": samples[0]["length"],
                "length_variance": length_variance,
                "signature": response_signature(
                    samples[0]["status"], samples[0]["body"]
                ),
            }
            if length_variance > 50:
                logger.debug(
                    "Param '%s' baseline length varies by %d bytes between requests "
                    "(dynamic content detected — noise floor raised)",
                    param,
                    length_variance,
                )
            self._baseline[param] = baseline
            return baseline
        except Exception as exc:
            logger.debug(f"Baseline fetch failed for param={param}: {exc}")

            return {
                "body": "",
                "status": -1,
                "time_ms": 0.0,
                "length": 0,
                "length_variance": 0,
            }

    async def probe(self, param: str) -> dict[str, Any]:
        baseline = await self._fetch_baseline(param)
        return {
            "status": int(baseline.get("status", -1)),
            "response_time": float(baseline.get("time_ms", 0.0)) / 1000.0,
            "body_length": int(baseline.get("length", 0)),
            "signature": str(baseline.get("signature", "")),
        }

    def _select_context_aware_payloads(
        self,
        vuln_type: str,
        target_profile: Any,
        param: str,
        base_payloads: list[str],
    ) -> list[str]:
        """Select payloads based on target context.

        Enhances static payload lists with context-aware filtering and augmentation:
        - Technology stack (e.g., MySQL-specific payloads for MySQL)
        - Input context (e.g., numeric payloads for number fields)
        - Existing findings (e.g., if SQLi found, add RCE payloads)
        """
        if not target_profile:
            return base_payloads

        payloads = list(base_payloads)  # Start with base payloads

        # Tech-specific payload augmentation — fully data-driven. The vuln_type →
        # tech_token → payloads mapping lives in fuzzer_data.json
        # (TECH_PAYLOAD_AUGMENTS); no per-tech branches are hardcoded here, so new
        # stacks/payloads are added by editing data, not code.
        tech_names = [t.name.lower() for t in target_profile.technologies]
        tech_str = " ".join(tech_names)
        for tech_token, extra_payloads in TECH_PAYLOAD_AUGMENTS.get(vuln_type, {}).items():
            token = str(tech_token).lower()
            if token in tech_names or token in tech_str:
                payloads.extend(extra_payloads)

        # Deduplicate while preserving order
        seen = set()
        unique_payloads = []
        for p in payloads:
            if p not in seen:
                seen.add(p)
                unique_payloads.append(p)

        return unique_payloads

    async def fuzz_parameters(
        self,
        params: list[str],
        vuln_types: list[str] | None = None,
        param_type_hints: dict[str, str] | None = None,
        max_payloads_per_type: int = 0,
    ) -> list[FuzzResult]:
        self._timeout_counts.clear()

        if not FUZZ_PAYLOADS:
            logger.error(
                "Fuzzer payload data is empty — fuzzer_data.json was not loaded. "
                "No fuzzing will be performed. Check package installation."
            )
            return []

        # ── Intelligence: Target Profiling ─────────────────────────────────
        target_profile = await self._profile_target_if_enabled()
        priority_vuln_types = self._prioritize_vuln_types(vuln_types, target_profile)
        self._payload_memory_tech_stack = [
            str(t.name).strip()
            for t in getattr(target_profile, "technologies", [])
            if str(getattr(t, "name", "")).strip()
        ]

        baseline_tasks = [self._fetch_baseline(p) for p in params]
        baseline_results = await asyncio.gather(*baseline_tasks, return_exceptions=True)

        unreachable_params = []
        for i, (param, result) in enumerate(zip(params, baseline_results)):
            if isinstance(result, BaseException):
                logger.warning(
                    f"Param '{param}' baseline fetch raised exception: {result}"
                )
                unreachable_params.append(param)
            elif isinstance(result, dict) and result.get("status") == -1:
                logger.warning(
                    f"Param '{param}' baseline returned status=-1 (target unreachable)"
                )
                unreachable_params.append(param)

        if unreachable_params:
            logger.info(
                f"Skipping {len(unreachable_params)}/{len(params)} params due to baseline failures: "
                f"{unreachable_params[:5]}{'...' if len(unreachable_params) > 5 else ''}"
            )

        clean_params = self._filter_fuzzable_params(params)

        all_vuln_types = list(FUZZ_PAYLOADS.keys())

        # ── Intelligence: Generative Fuzzing Init ──────────────────────────
        gen_engine = await self._init_generative_fuzzing_if_enabled()

        # Skip payloads that already failed
        _skip_count = 0
        filtered_tasks = []
        for param in clean_params:
            if param_type_hints and param in param_type_hints:
                p_type = param_type_hints[param]
                effective = _ATTACK_TYPE_TO_PAYLOADS.get(
                    p_type, priority_vuln_types or all_vuln_types
                )
            else:
                effective = priority_vuln_types or all_vuln_types
            for vt in effective:
                base_payloads = FUZZ_PAYLOADS.get(vt, [])
                # Apply context-aware payload selection
                payloads = self._select_context_aware_payloads(
                    vt, target_profile, param, base_payloads
                )
                if self.payload_memory:
                    payloads = self.payload_memory.prioritize_payloads(
                        payloads,
                        vuln_type=vt,
                        target=self.target,
                        waf=self.detected_wafs[0] if self.detected_wafs else "",
                        tech=self._payload_memory_tech_stack[0]
                        if self._payload_memory_tech_stack
                        else "",
                    )
                if max_payloads_per_type > 0:
                    payloads = payloads[:max_payloads_per_type]
                for payload in payloads:
                    if self.payload_memory:
                        should_skip, reason = self.payload_memory.should_skip_payload(
                            payload, vt, self.target, param
                        )
                        if should_skip:
                            _skip_count += 1
                            continue
                    filtered_tasks.append(self._fuzz_single(param, payload, vt))
        if _skip_count:
            logger.info(
                f"Payload memory: skipped {_skip_count} previously-failed payloads"
            )

        tasks = filtered_tasks

        results: list[Any] = []
        total_batches = max(
            1, (len(tasks) + _FUZZ_GATHER_BATCH - 1) // _FUZZ_GATHER_BATCH
        )
        logger.info(f"Starting fuzz: {len(tasks)} tests in {total_batches} batches")
        for batch_idx, _i in enumerate(range(0, len(tasks), _FUZZ_GATHER_BATCH)):
            _batch = tasks[_i : _i + _FUZZ_GATHER_BATCH]
            logger.info(f"Batch {batch_idx + 1}/{total_batches} ({len(_batch)} tests)")
            results.extend(await asyncio.gather(*_batch, return_exceptions=True))

            # ── Intelligence: Evolve payloads after each batch ─────────────
            if gen_engine:
                await self._evolve_payloads_batch(gen_engine, results, batch_idx)

        for r in results:
            if isinstance(r, FuzzResult) and r.confidence > 0.6:
                self.results.append(r)

        # ── Zero-FP Verification Stage ─────────────────────────────────────
        verified_results = await self._verify_findings(self.results)
        return verified_results

    async def _verify_findings(self, findings: list[FuzzResult]) -> list[FuzzResult]:
        """Run zero-FP verification on all findings."""
        try:
            from .config import get_config

            cfg = get_config()
        except Exception:
            return findings

        if not cfg.verification_enabled:
            return findings

        from .agent.verification import VerificationEngine

        engine = VerificationEngine(
            timeout=cfg.verification_timeout,
            max_replays=cfg.verification_max_replays,
            enable_replay=cfg.verification_enable_replay,
            enable_cross_tool=cfg.verification_enable_cross_tool,
            enable_negative_test=cfg.verification_enable_negative_test,
            enable_fp_detection=cfg.verification_enable_fp_detection,
        )

        verified: list[FuzzResult] = []
        min_report_conf = cfg.verification_min_report_confidence

        logger.info(
            f"Starting zero-FP verification on {len(findings)} findings "
            f"(min report confidence: {min_report_conf})"
        )

        for finding in findings:
            baseline = self._baseline.get(finding.parameter, {})
            verification = await engine.verify_finding(
                target_url=self.target,
                param=finding.parameter,
                vuln_type=finding.vuln_type,
                original_payload=finding.payload,
                original_confidence=finding.confidence,
                baseline_body=baseline.get("body", ""),
                fuzz_body=finding.payload,
                response_headers={},
                response_status=finding.response_code or 200,
                http_headers=self.headers or None,
            )

            if verification.verified_confidence >= min_report_conf:
                finding.confidence = verification.verified_confidence
                finding.evidence = (
                    f"[VERIFIED:{verification.details.get('status', 'OK')}] "
                    f"{finding.evidence}"
                )
                verified.append(finding)
                logger.info(
                    f"  VERIFIED {finding.vuln_type} on '{finding.parameter}': "
                    f"confidence {finding.confidence:.2f} "
                    f"(tier={verification.verification_tier})"
                )
            else:
                logger.info(
                    f"  FILTERED {finding.vuln_type} on '{finding.parameter}': "
                    f"confidence {verification.verified_confidence:.2f} "
                    f"(reason: {verification.fp_reason or verification.details.get('status', 'low confidence')})"
                )

        logger.info(
            f"Verification complete: {len(verified)}/{len(findings)} findings passed "
            f"(filtered {len(findings) - len(verified)} potential false positives)"
        )
        return verified

    def _filter_fuzzable_params(self, params: list[str]) -> list[str]:
        has_auth = bool(self.headers)
        clean_params: list[str] = []
        for param in params:
            b_status = self._baseline.get(param, {}).get("status", 200)
            if b_status == -1:
                logger.warning(
                    f"Skipping param '{param}' — baseline fetch failed (target unreachable)"
                )
            elif b_status in (429, 503):
                logger.warning(
                    f"Skipping param '{param}' — baseline returned HTTP {b_status} "
                    "(rate-limited / service unavailable)"
                )
            elif b_status in (401, 403) and not has_auth:
                logger.warning(
                    f"Skipping param '{param}' — baseline returned HTTP {b_status} "
                    "(WAF/auth blocking detected; pass auth headers to fuzz anyway)"
                )
            else:
                if b_status in (401, 403) and has_auth:
                    logger.info(
                        f"Param '{param}' baseline returned HTTP {b_status} but auth headers "
                        "are configured — fuzzing anyway (may reveal auth bypass)"
                    )
                clean_params.append(param)
        return clean_params

    async def fuzz(
        self,
        params: list[str],
        vuln_types: list[str] | None = None,
        param_type_hints: dict[str, str] | None = None,
        *,
        skip_baseline: bool = False,
    ) -> AsyncIterator[FuzzResult]:
        self._timeout_counts.clear()
        if not FUZZ_PAYLOADS:
            return

        if not skip_baseline:
            baseline_tasks = [self._fetch_baseline(p) for p in params]
            await asyncio.gather(*baseline_tasks, return_exceptions=True)

        clean_params = self._filter_fuzzable_params(params)
        all_vuln_types = list(FUZZ_PAYLOADS.keys())

        for param in clean_params:
            if param_type_hints and param in param_type_hints:
                p_type = param_type_hints[param]
                effective = _ATTACK_TYPE_TO_PAYLOADS.get(
                    p_type, vuln_types or all_vuln_types
                )
            else:
                effective = vuln_types or all_vuln_types
            for vt in effective:
                for payload in FUZZ_PAYLOADS.get(vt, []):
                    result = await self._fuzz_single(param, payload, vt)
                    if isinstance(result, FuzzResult) and result.confidence > 0.6:
                        self.results.append(result)
                        yield result

    async def _fuzz_single(
        self,
        param: str,
        payload: str,
        vuln_type: str,
    ) -> FuzzResult | None:
        baseline = self._baseline.get(
            param,
            {
                "body": "",
                "status": 200,
                "time_ms": 100.0,
                "length": 0,
                "length_variance": 0,
            },
        )
        resp: httpx.Response | None = None
        elapsed: float = 0.0

        async with self._semaphore:
            try:
                if self.rate_limiter:
                    t0 = time.monotonic()
                    rate_limited_resp = await self.rate_limiter.request(
                        self.method,
                        self.target,
                        **self._request_kwargs_for_value(param, payload),
                    )
                    if rate_limited_resp is None:
                        return None
                    resp = rate_limited_resp
                    elapsed = self._response_elapsed_ms(
                        resp,
                        fallback_ms=(time.monotonic() - t0) * 1000.0,
                    )
                else:
                    client = await self._get_direct_client()
                    t0 = time.monotonic()
                    if self.method == "GET":
                        resp = await client.get(self.target, params={param: payload})
                    else:
                        resp = await client.post(self.target, data={param: payload})
                    elapsed = (time.monotonic() - t0) * 1000

                resp = await self._maybe_recover_auth(resp, param=param, value=payload)
                elapsed = self._response_elapsed_ms(resp, fallback_ms=elapsed)

            except httpx.TimeoutException:
                if vuln_type in ("sql_injection", "ssti", "command_injection"):
                    hit_key = f"{param}:{vuln_type}"
                    self._timeout_counts[hit_key] = (
                        self._timeout_counts.get(hit_key, 0) + 1
                    )
                    if self._timeout_counts[hit_key] >= 2:
                        return FuzzResult(
                            target=self.target,
                            parameter=param,
                            payload=payload,
                            vuln_type=f"time_based_{vuln_type}",
                            severity="high",
                            evidence=(
                                f"Request timed out {self._timeout_counts[hit_key]}x "
                                "— consistent time-based injection (multi-sample confirmed)"
                            ),
                            confidence=0.75,
                            response_code=0,
                            response_length=0,
                            time_ms=self.timeout * 1000.0,
                        )
                    logger.debug(
                        "Timeout hit #%d for param=%s vuln=%s — waiting for 2nd confirmation",
                        self._timeout_counts[hit_key],
                        param,
                        vuln_type,
                    )
                return None
            except Exception as exc:
                logger.debug(
                    f"Fuzz request error param={param} payload={payload!r}: {exc}"
                )
                return None

        if resp is None:
            return None

        if resp.status_code == 403 and self.waf_engine and self.detected_wafs:
            waf_key = f"{param}:{vuln_type}"
            current_attempts = self._waf_bypass_attempts.get(waf_key, 0)
            if current_attempts >= self._waf_bypass_limit:
                logger.debug(
                    f"WAF bypass limit reached ({self._waf_bypass_limit}) for {waf_key}, skipping further bypasses"
                )
            else:
                self._waf_bypass_attempts[waf_key] = current_attempts + 1
                logger.info(
                    f"403 detected on param={param} — attempting WAF bypass "
                    f"for {', '.join(self.detected_wafs)}"
                )
                bypass_result = await self.waf_engine.test_bypass(
                    target_url=self.target,
                    waf_type=self.detected_wafs[0],
                    payload=payload,
                    param_name=param,
                    method=self.method,
                    base_headers=self.headers,
                )
                if bypass_result.get("successful_bypasses"):
                    bypass_resp = bypass_result.get("response")
                    if isinstance(bypass_resp, httpx.Response):
                        # Validate that bypass actually changed behavior meaningfully
                        # A real bypass should NOT return 403 or a generic block page
                        bypass_status = bypass_resp.status_code
                        bypass_body = bypass_resp.text.lower()

                        # Check if it's still a block page (false bypass)
                        block_indicators = [
                            "access denied",
                            "blocked",
                            "forbidden",
                            "security check",
                            "challenge",
                            "verify you are human",
                        ]
                        still_blocked = (
                            bypass_status == 403
                            or sum(1 for ind in block_indicators if ind in bypass_body)
                            >= 2
                        )

                        if still_blocked:
                            logger.debug(
                                f"WAF bypass for {param}={payload}: still blocked "
                                f"(status={bypass_status}) — false bypass, ignoring"
                            )
                        else:
                            logger.info(
                                f"WAF bypass successful for {param}={payload}: "
                                f"{bypass_result['successful_bypasses'][0]['strategy']} "
                                f"(status {bypass_status})"
                            )
                            resp = bypass_resp
                            elapsed = self._response_elapsed_ms(
                                resp, fallback_ms=elapsed
                            )

        fuzz_sig = response_signature(resp.status_code, resp.text)
        baseline_sig = baseline.get("signature", "")

        _is_time_based = vuln_type in (
            "sql_injection",
            "command_injection",
            "time_based",
        )
        if baseline_sig and fuzz_sig == baseline_sig and not _is_time_based:
            return None

        analysis = ExpertHeuristics.analyze_response_differential(
            baseline_body=baseline["body"],
            baseline_status=baseline["status"],
            baseline_time_ms=baseline["time_ms"],
            fuzz_body=resp.text,
            fuzz_status=resp.status_code,
            fuzz_time_ms=elapsed,
            payload=payload,
            vuln_type=vuln_type,
            baseline_length_variance=baseline.get("length_variance", 0),
            baseline_sig=baseline_sig,
            fuzz_sig=fuzz_sig,
        )

        if analysis["vuln_confirmed"] or analysis["confidence"] > 0.5:
            # Record successful payload
            if self.payload_memory:
                self.payload_memory.record_attempt(
                    payload=payload,
                    vuln_type=vuln_type,
                    target=self.target,
                    param=param,
                    success=True,
                    confidence=analysis["confidence"],
                    status_code=resp.status_code,
                    waf_detected=self.detected_wafs[0] if self.detected_wafs else "",
                    tech_stack=list(self._payload_memory_tech_stack),
                    response_time_ms=elapsed,
                )
            return FuzzResult(
                target=self.target,
                parameter=param,
                payload=payload,
                vuln_type=analysis.get("vuln_type", vuln_type),
                severity=_confidence_to_severity(analysis["confidence"]),
                evidence="; ".join(analysis["evidence"][:3]),
                confidence=analysis["confidence"],
                response_code=resp.status_code,
                response_length=len(resp.text),
                time_ms=elapsed,
            )
        # Record failed payload
        if self.payload_memory:
            self.payload_memory.record_attempt(
                payload=payload,
                vuln_type=vuln_type,
                target=self.target,
                param=param,
                success=False,
                confidence=analysis.get("confidence", 0.0),
                status_code=resp.status_code if resp else 0,
                waf_detected=self.detected_wafs[0] if self.detected_wafs else "",
                tech_stack=list(self._payload_memory_tech_stack),
                response_time_ms=elapsed,
            )
        return None

    @staticmethod
    def _dedupe_payloads(payloads: list[str], limit: int = 12) -> list[str]:
        seen: set[str] = set()
        result: list[str] = []
        for payload in payloads:
            p = str(payload).strip()
            if not p or p in seen:
                continue
            seen.add(p)
            result.append(p)
            if len(result) >= limit:
                break
        return result

    def _candidate_params_for_type(
        self, type_hint: str, max_items: int = 5
    ) -> list[str]:
        known = [p.lower() for p in PARAM_TYPE_MAP.get(type_hint, [])]
        from_wordlist = [p for p in self.wordlist if p.lower() in known]
        merged = self._dedupe_payloads(
            from_wordlist + PARAM_TYPE_MAP.get(type_hint, []), limit=max_items
        )
        return merged

    def _build_finding(
        self,
        *,
        param: str,
        payload: str,
        vuln_type: str,
        confidence: float,
        evidence: str,
        response: httpx.Response | None,
        time_ms: float,
    ) -> FuzzResult:
        if response is None:
            code = 0
            length = 0
        else:
            code = response.status_code
            length = len(response.text)
        return FuzzResult(
            target=self.target,
            parameter=param,
            payload=payload,
            vuln_type=vuln_type,
            severity=_confidence_to_severity(confidence),
            evidence=evidence,
            confidence=confidence,
            response_code=code,
            response_length=length,
            time_ms=time_ms,
        )

    def _record_findings(self, findings: list[FuzzResult]) -> list[FuzzResult]:
        existing = {
            (r.parameter, r.payload, r.vuln_type, r.response_code) for r in self.results
        }
        added: list[FuzzResult] = []
        for finding in findings:
            fp = (
                finding.parameter,
                finding.payload,
                finding.vuln_type,
                finding.response_code,
            )
            if fp in existing:
                continue
            existing.add(fp)
            self.results.append(finding)
            added.append(finding)
        return added

    async def run_phase2_advanced_tests(
        self,
        *,
        ssrf_params: list[str] | None = None,
        graphql_endpoints: list[str] | None = None,
        race_params: list[str] | None = None,
    ) -> list[FuzzResult]:
        findings: list[FuzzResult] = []
        findings.extend(await self._run_cloud_ssrf_exploitation(ssrf_params))
        findings.extend(await self._run_graphql_automation(graphql_endpoints))
        findings.extend(await self._run_race_condition_testing(race_params))
        return self._record_findings(findings)

    async def run_phase3_advanced_tests(
        self,
        *,
        store_params: list[str] | None = None,
        trigger_paths: list[str] | None = None,
    ) -> list[FuzzResult]:
        findings: list[FuzzResult] = []
        findings.extend(
            await self._run_second_order_detection(store_params, trigger_paths)
        )
        findings.extend(await self._run_http_desync_cache_testing())
        return self._record_findings(findings)

    async def _run_cloud_ssrf_exploitation(
        self,
        params: list[str] | None,
    ) -> list[FuzzResult]:
        candidates = (
            params[:]
            if params
            else self._candidate_params_for_type("SSRF", max_items=4)
        )
        if not candidates:
            return []

        pattern_texts = self._collect_pattern_texts(
            ["cloud_metadata_testing", "ssrf_via_headers"],
            ["suggested_actions", "test_vectors"],
        )
        pattern_texts.extend(
            self._collect_attack_chain_step_texts(["ssrf", "metadata"])
        )
        payloads = (
            CHAIN_PAYLOADS.get("ssrf", [])
            + FUZZ_PAYLOADS.get("ssrf", [])[:6]
            + self._extract_urls_from_text(pattern_texts)
        )
        payloads = [
            p
            for p in self._dedupe_payloads(payloads, limit=10)
            if p.lower().startswith("http")
        ]
        if not payloads:
            return []

        findings: list[FuzzResult] = []
        metadata_markers = (
            "latest/meta-data",
            "security-credentials",
            "metadata-flavor",
            "computeMetadata",
            "subscriptionid",
            "instance-id",
            "ami-id",
        )

        for param in candidates:
            baseline = await self._fetch_baseline(param)
            baseline_status = int(baseline.get("status", 0))
            for payload in payloads:
                extra_headers: dict[str, str] = {}
                lowered_payload = payload.lower()
                if "metadata.google.internal" in lowered_payload:
                    extra_headers["Metadata-Flavor"] = "Google"
                if (
                    "/metadata/instance" in lowered_payload
                    or "api-version=" in lowered_payload
                ):
                    extra_headers["Metadata"] = "true"

                req_data = {param: payload}
                if self.method == "GET":
                    resp, elapsed = await self._probe_request(
                        method=self.method,
                        params=req_data,
                        headers=extra_headers,
                    )
                else:
                    resp, elapsed = await self._probe_request(
                        method=self.method,
                        data=req_data,
                        headers=extra_headers,
                    )
                if resp is None:
                    continue

                body_lower = resp.text.lower()
                marker_hits = [m for m in metadata_markers if m in body_lower]
                if resp.status_code in (200, 206) and marker_hits:
                    confidence = min(0.95, 0.82 + (0.03 * len(marker_hits)))
                    findings.append(
                        self._build_finding(
                            param=param,
                            payload=payload,
                            vuln_type="ssrf_cloud_metadata",
                            confidence=confidence,
                            evidence=(
                                f"SSRF payload reached metadata/internal content (markers: {', '.join(marker_hits[:3])})"
                            ),
                            response=resp,
                            time_ms=elapsed,
                        )
                    )
                    break

                if (
                    baseline_status > 0
                    and resp.status_code != baseline_status
                    and resp.status_code in (301, 302, 307, 308, 401, 403)
                    and (
                        "169.254.169.254" in lowered_payload
                        or "metadata.google.internal" in lowered_payload
                    )
                ):
                    findings.append(
                        self._build_finding(
                            param=param,
                            payload=payload,
                            vuln_type="ssrf_internal_probe",
                            confidence=0.64,
                            evidence=(
                                f"SSRF probe changed response code {baseline_status}→{resp.status_code} for cloud metadata target"
                            ),
                            response=resp,
                            time_ms=elapsed,
                        )
                    )
                    break

        return findings

    async def _run_graphql_automation(
        self,
        endpoint_hints: list[str] | None,
    ) -> list[FuzzResult]:
        parsed = urlparse(self.target)
        base = (
            f"{parsed.scheme}://{parsed.netloc}"
            if parsed.scheme and parsed.netloc
            else self.target
        )
        default_paths = ["/graphql", "/api/graphql", "/v1/graphql", "/gql", "/query"]
        endpoints: list[str] = []
        if endpoint_hints:
            endpoints.extend(endpoint_hints)
        if "/graphql" in parsed.path or "/gql" in parsed.path:
            endpoints.append(self.target)
        endpoints.extend([base.rstrip("/") + p for p in default_paths])
        endpoints = self._dedupe_payloads(endpoints, limit=4)

        graphql_payloads = FUZZ_PAYLOADS.get("graphql", [])
        introspection = next(
            (p for p in graphql_payloads if "__schema" in p),
            "query{__schema{types{name}}}",
        )
        idor_probe = next(
            (p for p in graphql_payloads if "user(id:" in p.lower()),
            'query{user(id:"1"){id,name,email,role}}',
        )
        findings: list[FuzzResult] = []

        for endpoint in endpoints:
            probe_resp, probe_ms = await self._probe_request(
                url=endpoint,
                method="POST",
                json_body={"query": "{__typename}"},
                headers={"Content-Type": "application/json"},
            )
            if probe_resp is None:
                continue
            probe_lower = probe_resp.text.lower()
            if not (
                "__typename" in probe_lower
                or '"data"' in probe_lower
                or "graphql" in probe_resp.headers.get("content-type", "").lower()
            ):
                continue

            introspection_resp, introspection_ms = await self._probe_request(
                url=endpoint,
                method="POST",
                json_body={"query": introspection},
                headers={"Content-Type": "application/json"},
            )
            if introspection_resp is not None:
                body_lower = introspection_resp.text.lower()
                if (
                    introspection_resp.status_code == 200
                    and "__schema" in body_lower
                    and "types" in body_lower
                ):
                    findings.append(
                        self._build_finding(
                            param="graphql",
                            payload=introspection[:120],
                            vuln_type="graphql_introspection_exposed",
                            confidence=0.90,
                            evidence=f"GraphQL introspection enabled on {endpoint}",
                            response=introspection_resp,
                            time_ms=introspection_ms,
                        )
                    )

            batch_payload = [{"query": "query{__typename}"} for _ in range(10)]
            batch_resp, batch_ms = await self._probe_request(
                url=endpoint,
                method="POST",
                json_body=batch_payload,
                headers={"Content-Type": "application/json"},
            )
            if (
                batch_resp is not None
                and batch_resp.status_code == 200
                and batch_resp.text.lstrip().startswith("[")
            ):
                findings.append(
                    self._build_finding(
                        param="graphql",
                        payload="batch_query(10)",
                        vuln_type="graphql_batching_enabled",
                        confidence=0.75,
                        evidence=f"GraphQL batching accepted on {endpoint}; potential rate-limit bypass vector",
                        response=batch_resp,
                        time_ms=batch_ms,
                    )
                )

            id1_resp, id1_ms = await self._probe_request(
                url=endpoint,
                method="POST",
                json_body={"query": idor_probe},
                headers={"Content-Type": "application/json"},
            )
            id2_query = idor_probe.replace('id:"1"', 'id:"2"')
            id2_resp, _ = await self._probe_request(
                url=endpoint,
                method="POST",
                json_body={"query": id2_query},
                headers={"Content-Type": "application/json"},
            )
            if id1_resp is not None and id2_resp is not None:
                s1 = response_signature(id1_resp.status_code, id1_resp.text)
                s2 = response_signature(id2_resp.status_code, id2_resp.text)
                sensitive_markers = ("email", "password", "token", "secret", "role")
                if (
                    s1 != s2
                    and any(m in id1_resp.text.lower() for m in sensitive_markers)
                    and any(m in id2_resp.text.lower() for m in sensitive_markers)
                ):
                    findings.append(
                        self._build_finding(
                            param="graphql",
                            payload=idor_probe[:120],
                            vuln_type="graphql_idor_candidate",
                            confidence=0.79,
                            evidence=f"GraphQL object access differs by sequential IDs on {endpoint} with sensitive fields returned",
                            response=id2_resp,
                            time_ms=id1_ms,
                        )
                    )

        return findings

    async def _run_race_condition_testing(
        self,
        params: list[str] | None,
    ) -> list[FuzzResult]:
        candidate_params = (
            params[:]
            if params
            else self._candidate_params_for_type("BUSINESS_LOGIC", max_items=2)
        )
        race_payloads = self._dedupe_payloads(
            FUZZ_PAYLOADS.get("race_condition", [])[:3], limit=3
        )
        if not candidate_params or not race_payloads:
            return []

        findings: list[FuzzResult] = []
        for param in candidate_params:
            for payload in race_payloads:

                async def _single() -> tuple[httpx.Response | None, float]:
                    req_data = {param: payload}
                    if self.method == "GET":
                        return await self._probe_request(
                            method=self.method,
                            params=req_data,
                            use_rate_limiter=False,
                        )
                    return await self._probe_request(
                        method=self.method,
                        data=req_data,
                        use_rate_limiter=False,
                    )

                bursts = await asyncio.gather(
                    *[_single() for _ in range(6)], return_exceptions=True
                )
                responses: list[httpx.Response] = []
                timings: list[float] = []
                for item in bursts:
                    if isinstance(item, BaseException):
                        continue
                    resp, elapsed = item
                    if resp is None:
                        continue
                    responses.append(resp)
                    timings.append(elapsed)
                if len(responses) < 3:
                    continue

                status_set = {r.status_code for r in responses}
                sig_set = {response_signature(r.status_code, r.text) for r in responses}
                if len(status_set) > 1 or len(sig_set) > 1:
                    divergence = max(
                        (len(status_set) - 1) / 4.0, (len(sig_set) - 1) / 6.0
                    )
                    confidence = min(0.86, 0.64 + (divergence * 0.25))
                    findings.append(
                        self._build_finding(
                            param=param,
                            payload=payload,
                            vuln_type="race_condition_possible",
                            confidence=confidence,
                            evidence=(
                                f"Concurrent requests diverged for {param}={payload} "
                                f"(statuses={sorted(status_set)}, unique_signatures={len(sig_set)})"
                            ),
                            response=responses[0],
                            time_ms=sum(timings) / max(1, len(timings)),
                        )
                    )
                    break

        return findings

    async def _run_second_order_detection(
        self,
        store_params: list[str] | None,
        trigger_paths: list[str] | None,
    ) -> list[FuzzResult]:
        candidates = (
            store_params[:]
            if store_params
            else self._candidate_params_for_type("SQLi_XSS", max_items=3)
        )
        if not candidates:
            return []

        parsed = urlparse(self.target)
        base = (
            f"{parsed.scheme}://{parsed.netloc}"
            if parsed.scheme and parsed.netloc
            else self.target
        )
        base_path = parsed.path if parsed.path else "/"
        indicator_paths = []
        pattern = _ZERODAY_PATTERNS.get("second_order_injection", {})
        for indicator in pattern.get("indicators", []):
            normalized = "/" + str(indicator).strip("/ ")
            indicator_paths.append(normalized)
        for step_text in self._collect_attack_chain_step_texts(
            ["second-order", "stored"]
        ):
            for candidate in ("profile", "admin", "export", "report"):
                if candidate in step_text.lower():
                    indicator_paths.append("/" + candidate)
        default_trigger_paths = [base_path, "/profile", "/dashboard", "/admin"]
        if trigger_paths:
            trigger_candidates = trigger_paths
        else:
            trigger_candidates = default_trigger_paths + indicator_paths[:3]
        trigger_urls = []
        for path in trigger_candidates:
            p = str(path).strip()
            if not p:
                continue
            if p.startswith("http://") or p.startswith("https://"):
                trigger_urls.append(p)
            else:
                trigger_urls.append(base.rstrip("/") + "/" + p.lstrip("/"))
        trigger_urls = self._dedupe_payloads(trigger_urls, limit=5)

        findings: list[FuzzResult] = []
        for param in candidates:
            marker = f"AIRECON_SO_{uuid.uuid4().hex[:10]}"
            payload = f"{marker}'\"<x>"
            req_data = {param: payload}
            if self.method == "GET":
                store_resp, store_ms = await self._probe_request(
                    method=self.method, params=req_data
                )
            else:
                store_resp, store_ms = await self._probe_request(
                    method=self.method, data=req_data
                )
            if store_resp is None:
                continue
            immediate_contains = marker.lower() in store_resp.text.lower()

            for trigger_url in trigger_urls:
                trigger_resp, trigger_ms = await self._probe_request(
                    url=trigger_url, method="GET"
                )
                if trigger_resp is None:
                    continue
                trigger_body_lower = trigger_resp.text.lower()
                if marker.lower() not in trigger_body_lower:
                    continue

                sql_markers = ("sql syntax", "mysql", "postgres", "sqlite", "ora-")
                if any(token in trigger_body_lower for token in sql_markers):
                    findings.append(
                        self._build_finding(
                            param=param,
                            payload=payload,
                            vuln_type="second_order_sql_injection",
                            confidence=0.86,
                            evidence=(
                                f"Stored marker triggered SQL error context at {trigger_url}; indicates second-order SQLi path"
                            ),
                            response=trigger_resp,
                            time_ms=trigger_ms,
                        )
                    )
                    break

                if not immediate_contains:
                    findings.append(
                        self._build_finding(
                            param=param,
                            payload=payload,
                            vuln_type="second_order_reflection",
                            confidence=0.78,
                            evidence=(
                                f"Stored marker not reflected immediately but appears in follow-up view at {trigger_url}"
                            ),
                            response=trigger_resp,
                            time_ms=store_ms + trigger_ms,
                        )
                    )
                    break

                findings.append(
                    self._build_finding(
                        param=param,
                        payload=payload,
                        vuln_type="stored_input_flow",
                        confidence=0.64,
                        evidence=f"Marker persisted across requests and contexts ({trigger_url}); verify execution sink",
                        response=trigger_resp,
                        time_ms=store_ms + trigger_ms,
                    )
                )
                break

        return findings

    async def _run_http_desync_cache_testing(self) -> list[FuzzResult]:
        findings: list[FuzzResult] = []
        baseline_resp, baseline_ms = await self._probe_request(method="GET")
        if baseline_resp is None:
            return findings
        baseline_body = baseline_resp.text
        baseline_status = baseline_resp.status_code
        baseline_cache_headers = {
            k.lower(): v
            for k, v in baseline_resp.headers.items()
            if _CACHE_HEADER_RE.match(k)
        }

        marker = f"airecon-cache-{uuid.uuid4().hex[:8]}"
        poison_headers_set = [
            {"X-Forwarded-Host": f"{marker}.invalid"},
            {"X-Original-URL": "/admin"},
            {"X-Host": marker},
        ]
        for poison_headers in poison_headers_set:
            probe_resp, probe_ms = await self._probe_request(
                method="GET", headers=poison_headers
            )
            follow_resp, follow_ms = await self._probe_request(method="GET")
            if probe_resp is None or follow_resp is None:
                continue
            follow_body = follow_resp.text
            if marker in follow_body and marker not in baseline_body:
                findings.append(
                    self._build_finding(
                        param="header",
                        payload=json.dumps(poison_headers, sort_keys=True),
                        vuln_type="cache_poisoning_candidate",
                        confidence=0.87,
                        evidence="Marker from unkeyed header appeared in follow-up response; cache poisoning signal",
                        response=follow_resp,
                        time_ms=probe_ms + follow_ms,
                    )
                )
                break

            follow_cache_headers = {
                k.lower(): v
                for k, v in follow_resp.headers.items()
                if _CACHE_HEADER_RE.match(k)
            }
            if (
                baseline_cache_headers
                and follow_cache_headers
                and follow_resp.status_code != baseline_status
                and follow_cache_headers != baseline_cache_headers
            ):
                findings.append(
                    self._build_finding(
                        param="header",
                        payload=json.dumps(poison_headers, sort_keys=True),
                        vuln_type="cache_key_anomaly",
                        confidence=0.66,
                        evidence="Cache-related headers changed with poisoned request and altered follow-up status",
                        response=follow_resp,
                        time_ms=probe_ms + follow_ms,
                    )
                )
                break

        smuggle_headers = {
            "Content-Length": "4",
            "Transfer-Encoding": "chunked",
            "Connection": "keep-alive",
        }
        smuggle_resp, smuggle_ms = await self._probe_request(
            method="POST",
            headers=smuggle_headers,
            content="0\r\n\r\n",
        )
        check_resp, check_ms = await self._probe_request(method="GET")
        if check_resp is not None:
            if (
                smuggle_resp is None
                and smuggle_ms >= (self.timeout * 1000.0)
                and check_resp.status_code != baseline_status
            ):
                findings.append(
                    self._build_finding(
                        param="request",
                        payload="cl_te_probe",
                        vuln_type="http_desync_candidate",
                        confidence=0.74,
                        evidence="Ambiguous CL/TE probe timed out and shifted subsequent response status",
                        response=check_resp,
                        time_ms=smuggle_ms + check_ms,
                    )
                )
            elif (
                smuggle_resp is not None
                and smuggle_resp.status_code in (200, 201, 202, 204)
                and check_resp.status_code != baseline_status
            ):
                findings.append(
                    self._build_finding(
                        param="request",
                        payload="cl_te_probe",
                        vuln_type="http_desync_candidate",
                        confidence=0.77,
                        evidence="CL/TE ambiguous request accepted and changed subsequent response behavior",
                        response=check_resp,
                        time_ms=smuggle_ms + check_ms,
                    )
                )

        return findings

    def get_high_priority_targets(self) -> list[str]:
        priority: list[str] = []
        seen: set[str] = set()

        categories = [
            ["password", "token", "auth", "session"],
            ["_id", "uid", "user_id", "order_id", "account_id"],
            ["file", "path", "template"],
            ["price", "amount", "discount", "coupon"],
        ]

        for category_keywords in categories:
            for p in self.wordlist:
                if p not in seen and any(x in p.lower() for x in category_keywords):
                    priority.append(p)
                    seen.add(p)

        return priority


class MutationEngine:
    @staticmethod
    def mutate_payload(payload: str, technique: str) -> list[str]:
        mutations = [payload]

        if technique == "encoding":
            mutations.append(payload.replace("/", "%2F"))
            mutations.append(payload.replace(" ", "%20"))
            mutations.append(payload.replace("'", "%27"))
            mutations.append(payload.replace('"', "%22"))

            mutations.append(payload.replace("/", "%252F"))

        elif technique == "case":
            mutations.append(payload.upper())
            mutations.append(payload.lower())
            mutations.append(payload.capitalize())

            mutations.append(
                "".join(
                    c.upper() if i % 2 == 0 else c.lower()
                    for i, c in enumerate(payload)
                )
            )

        elif technique == "comment":
            if " " in payload:
                base = payload.split()[0]
                mutations.append(f"{base}--")
                mutations.append(f"{base}#")
                mutations.append(f"{base}/*")
                mutations.append(f"{base}/*!*/")

        elif technique == "padding":
            mutations.append(f"{payload} " * 5)
            mutations.append(f"{payload}\n" * 3)
            mutations.append(f"{payload}\t" * 3)

        elif technique == "nullbyte":
            mutations.append(f"{payload}%00")
            mutations.append(f"{payload}\x00")
            mutations.append(f"{payload}%00.jpg")
            mutations.append(f"{payload}\x00.png")

        elif technique == "unicode":
            mutations.append(payload.replace("'", "\u02bc"))
            mutations.append(payload.replace("<", "\uff1c"))
            mutations.append(payload.replace(">", "\uff1e"))

        return mutations

    @staticmethod
    def generate_wordlist_combinations(
        base_words: list[str],
        max_size: int = 500,
    ) -> list[str]:
        _PRIVILEGE_SUFFIXES = [
            "admin",
            "root",
            "superuser",
            "administrator",
            "super",
            "owner",
            "master",
            "privileged",
            "god",
            "system",
        ]
        _ENV_SUFFIXES = [
            "test",
            "dev",
            "debug",
            "staging",
            "prod",
            "local",
            "backup",
            "old",
            "new",
            "temp",
            "tmp",
            "internal",
            "hidden",
        ]
        _NUMERIC_SUFFIXES = [
            "1",
            "2",
            "0",
            "01",
            "123",
            "1234",
            "12345",
            "0x1",
            "null",
            "none",
            "true",
            "false",
            "undefined",
            "empty",
        ]
        _KEY_SUFFIXES = [
            "_id",
            "_key",
            "_token",
            "_secret",
            "_hash",
            "_code",
            "_api",
            "_flag",
            "_data",
            "_info",
            "_val",
            "_value",
            "_param",
            "_field",
            "_attr",
        ]
        _DEMO_SUFFIXES = ["demo", "sample", "example", "mock", "dummy", "fake"]

        seen: set[str] = set()
        combinations: list[str] = []

        def _add(item: str) -> bool:
            if item not in seen:
                seen.add(item)
                combinations.append(item)
            return len(combinations) < max_size

        for suffix in _PRIVILEGE_SUFFIXES + _ENV_SUFFIXES + _DEMO_SUFFIXES:
            for word in base_words:
                if not _add(f"{word}_{suffix}"):
                    return combinations
                if not _add(f"{word}{suffix}"):
                    return combinations
                if not _add(f"{suffix}_{word}"):
                    return combinations

        for suffix in _KEY_SUFFIXES:
            for word in base_words:
                if not _add(f"{word}{suffix}"):
                    return combinations

        for suffix in _NUMERIC_SUFFIXES:
            for word in base_words:
                if not _add(f"{word}{suffix}"):
                    return combinations
                if not _add(f"{word}_{suffix}"):
                    return combinations

        for word in base_words:
            for suffix in _PRIVILEGE_SUFFIXES[:5] + ["Id", "Key", "Token", "Secret"]:
                camel = f"{word}{suffix[0].upper()}{suffix[1:]}"
                if not _add(camel):
                    return combinations

        for w1 in base_words:
            for w2 in base_words:
                if w1 != w2:
                    if not _add(f"{w1}_{w2}"):
                        return combinations
                    if not _add(f"{w1}-{w2}"):
                        return combinations

        return combinations


class ExpertHeuristics:
    @staticmethod
    def analyze_response(response: str) -> dict[str, Any]:
        analysis: dict[str, Any] = {
            "is_vulnerable": False,
            "vuln_types": [],
            "confidence": 0.0,
            "indicators": [],
        }
        seen_vulns: set[str] = set()
        response_lower = response.lower()

        def _add(vuln: str, indicator: str, score: float) -> None:
            analysis["indicators"].append(indicator)
            analysis["confidence"] += score
            if vuln not in seen_vulns:
                analysis["vuln_types"].append(vuln)
                seen_vulns.add(vuln)

        sql_hit = False
        for pattern in VULNERABLE_PATTERNS["sql_error"]:
            if pattern in response_lower and not sql_hit:
                _add("sql_injection", f"SQL error pattern: {pattern}", 0.4)
                sql_hit = True

        for pattern in VULNERABLE_PATTERNS["generic_error"]:
            if pattern in response_lower:
                _add("error_disclosure", f"Server error: {pattern}", 0.2)
                break

        code_hit = False
        for pattern in VULNERABLE_PATTERNS["code_execution"]:
            if pattern in response_lower and not code_hit:
                _add("rce", f"Code execution indicator: {pattern}", 0.45)
                code_hit = True

        specific_sensitive = ["/etc/passwd", "root:x:", "c:\\windows\\", "db_password="]
        for pattern in specific_sensitive:
            if pattern in response_lower:
                _add("information_disclosure", f"Sensitive data: {pattern}", 0.5)
                break

        analysis["confidence"] = min(analysis["confidence"], 1.0)
        analysis["is_vulnerable"] = analysis["confidence"] > 0.5
        return analysis

    @staticmethod
    def analyze_response_differential(
        baseline_body: str,
        baseline_status: int,
        baseline_time_ms: float,
        fuzz_body: str,
        fuzz_status: int,
        fuzz_time_ms: float,
        payload: str,
        vuln_type: str,
        baseline_length_variance: int = 0,
        baseline_sig: str = "",
        fuzz_sig: str = "",
    ) -> dict[str, Any]:
        result: dict[str, Any] = {
            "vuln_confirmed": False,
            "confidence": 0.0,
            "evidence": [],
            "vuln_type": vuln_type,
        }
        confidence = 0.0
        evidence: list[str] = []

        if payload and len(payload) > 3 and payload in fuzz_body:
            if payload not in baseline_body:
                confidence += 0.6
                evidence.append(f"Payload reflected in response: {payload[:40]!r}")
                if any(
                    tag in payload for tag in ["<script", "<img", "<svg", "javascript:"]
                ):
                    result["vuln_type"] = "xss"
                elif any(t in payload for t in ["{{", "${", "<%= ", "#{"]):
                    result["vuln_type"] = "ssti"

        if (
            baseline_time_ms > 0
            and fuzz_time_ms > baseline_time_ms * 3
            and fuzz_time_ms > 3000
        ):
            confidence += 0.65
            evidence.append(
                f"Time anomaly: baseline={baseline_time_ms:.0f}ms fuzz={fuzz_time_ms:.0f}ms"
            )
            result["vuln_type"] = f"time_based_{vuln_type}"

        elif baseline_time_ms == 0 and fuzz_time_ms > 5000:
            confidence += 0.40
            evidence.append(
                f"Time anomaly (no baseline): fuzz={fuzz_time_ms:.0f}ms exceeded 5s absolute threshold"
            )
            result["vuln_type"] = f"time_based_{vuln_type}"

        if fuzz_status != baseline_status:
            if baseline_status == 200 and fuzz_status == 500:
                confidence += 0.4
                evidence.append("Status change 200→500 (server error on payload)")
            elif fuzz_status == 403:
                confidence += 0.1
                evidence.append("WAF/403 triggered by payload")
            elif baseline_status == 200 and fuzz_status in (301, 302):
                confidence += 0.3
                evidence.append(
                    f"Redirect triggered (possible open redirect/SSRF): {fuzz_status}"
                )
                result["vuln_type"] = "open_redirect"

        baseline_len = len(baseline_body)
        fuzz_len = len(fuzz_body)
        if baseline_len > 0:
            delta_ratio = (fuzz_len - baseline_len) / baseline_len
            noise_floor = max(200, baseline_length_variance * 3)
            if delta_ratio > 0.5 and fuzz_len > baseline_len + noise_floor:
                confidence += 0.25
                evidence.append(
                    f"Response significantly larger (+{fuzz_len - baseline_len}B) — possible data leak"
                )
            elif delta_ratio < -0.5 and baseline_len > noise_floor:
                confidence += 0.15
                evidence.append(
                    "Response significantly smaller — possible truncation/filter"
                )

        fuzz_lower = fuzz_body.lower()
        baseline_lower = baseline_body.lower()
        for pattern in VULNERABLE_PATTERNS["sql_error"]:
            if pattern in fuzz_lower and pattern not in baseline_lower:
                confidence += 0.5
                evidence.append(
                    f"SQL error in fuzz response (not in baseline): {pattern!r}"
                )
                result["vuln_type"] = "sql_injection"
                break

        for pattern in VULNERABLE_PATTERNS["code_execution"]:
            if pattern in fuzz_lower and pattern not in baseline_lower:
                confidence += 0.45
                evidence.append(f"Code execution indicator (new in fuzz): {pattern!r}")
                result["vuln_type"] = "rce"
                break

        lfi_signatures = ["/etc/passwd", "root:x:", "c:\\windows\\", "[boot loader]"]
        for sig in lfi_signatures:
            if sig in fuzz_lower and sig not in baseline_lower:
                confidence += 0.8
                evidence.append(
                    f"LFI/path traversal signature in fuzz response: {sig!r}"
                )
                result["vuln_type"] = "path_traversal"
                break

        if baseline_sig and fuzz_sig and baseline_sig != fuzz_sig and not evidence:
            b_status, b_len, _ = baseline_sig.split(":", 2)
            f_status, f_len, _ = fuzz_sig.split(":", 2)
            change_parts: list[str] = []
            if b_status != f_status:
                change_parts.append(f"status {b_status}→{f_status}")
            if b_len != f_len:
                change_parts.append(f"body size {b_len}→{f_len} bytes")
            if not change_parts:
                change_parts.append("content fingerprint changed")
            confidence += 0.15
            evidence.append(f"Behavioral signature changed ({', '.join(change_parts)})")

        result["confidence"] = min(confidence, 1.0)
        result["vuln_confirmed"] = result["confidence"] > 0.55
        result["evidence"] = evidence
        return result

    @staticmethod
    def get_priority_parameters(url: str, method: str = "GET") -> list[str]:
        priority: list[str] = []

        # First matching context wins (preserves the original precedence). The
        # url-keyword → params mapping is data-driven (PRIORITY_PARAM_HINTS in
        # fuzzer_data.json), so contexts/params are tuned in data, not code.
        for hint in PRIORITY_PARAM_HINTS:
            if any(kw in url for kw in hint.get("url_keywords", [])):
                priority.extend(hint.get("params", []))
                break

        return list(dict.fromkeys(priority))

    # ── Data-driven attack surface heuristics ─────────────────────────
    # Loads ALL expert patterns, tech correlations, and business logic
    # patterns from data files at module level. Detection is indicator-based —
    # no hardcoded vulnerability types. New data files automatically surface.

    _EXPERT_PATTERNS: dict[str, Any] = {}
    _TECH_CORRELATIONS: dict[str, Any] = {}
    _BUSINESS_LOGIC: dict[str, Any] = {}
    _heuristic_patterns_compiled: list[tuple[re.Pattern, dict, str]] = []
    _heuristic_tech_compiled: list[tuple[re.Pattern | str, dict]] = []
    _heuristic_data_loaded: bool = False

    @classmethod
    def _load_heuristic_data(cls) -> None:
        """Load all pattern data files once at runtime."""
        if cls._heuristic_data_loaded:
            return

        from .data_loader import load_vuln_patterns

        # Load unified pattern catalog (merged from patterns.json,
        # business_logic_patterns.json, zeroday_patterns.json)
        unified = load_vuln_patterns()
        cls._EXPERT_PATTERNS = {
            k: v for k, v in unified.items() if not k.startswith("_")
        }

        # Load technology correlations
        data_dir = Path(__file__).parent / "data"
        try:
            cls._TECH_CORRELATIONS = json.loads(
                (data_dir / "tech_correlations.json").read_text(encoding="utf-8")
            )
        except Exception as exc:
            logger.debug("Could not load tech_correlations.json: %s", exc)

        # Business logic patterns are now part of unified catalog
        cls._BUSINESS_LOGIC = {
            k: v for k, v in unified.items()
            if not k.startswith("_") and any(
                term in k.lower()
                for term in ["business", "workflow", "checkout", "payment", "coupon", "subscription", "race", "loyalty"]
            )
        }
        # Compile expert patterns into efficient matching tables
        for pattern_name, pattern_data in cls._EXPERT_PATTERNS.items():
            indicators = pattern_data.get("indicators", [])
            if not indicators:
                continue
            regex_parts = [
                re.escape(ind) for ind in sorted(indicators, key=len, reverse=True)
            ]
            compiled = re.compile(
                rf"(?:{'|'.join(regex_parts)})", re.IGNORECASE
            )
            cls._heuristic_patterns_compiled.append(
                (compiled, pattern_data, pattern_name)
            )
        # Compile tech correlations for header-based detection
        for tech_name, tech_data in cls._TECH_CORRELATIONS.items():
            tech_indicators: list[str] = []
            tech_indicators.append(tech_name)
            for path in tech_data.get("paths", []):
                tech_indicators.append(path)
            for ind in tech_indicators:
                if ind:
                    cls._heuristic_tech_compiled.append(
                        (ind.lower(), tech_data)
                    )
        cls._heuristic_data_loaded = True

    @staticmethod
    def get_attack_surface_heuristics(
        url: str,
        params: dict[str, str],
        request_headers: dict[str, str],
        response_headers: dict[str, str],
    ) -> list[ExpertGuidance]:
        guidance: list[ExpertGuidance] = []
        resp_lower = {k.lower(): v.lower() for k, v in response_headers.items()}
        req_lower = {k.lower(): v.lower() for k, v in request_headers.items()}

        # Build unified scan context from all observable signals
        scan_text = " ".join([
            url.lower(),
            " ".join(params.keys()).lower(),
            " ".join(params.values()).lower(),
            " ".join(resp_lower.values()),
            " ".join(req_lower.values()),
            resp_lower.get("server", ""),
            resp_lower.get("x-powered-by", ""),
            resp_lower.get("x-generator", ""),
            req_lower.get("authorization", ""),
        ])

        # ── Phase 1: Match against expert patterns (36 patterns) ──
        matched_patterns: set[str] = set()
        for compiled, pdata, pname in Fuzzer._heuristic_patterns_compiled:
            if compiled.search(scan_text):
                matched_patterns.add(pname)
                vuln_desc = pdata.get("description", pname)
                actions = pdata.get("suggested_actions", [])
                severity = pdata.get("severity", "MEDIUM").lower()
                top_action = actions[0] if actions else vuln_desc

                guidance.append(ExpertGuidance(
                    recommendation=top_action,
                    reason=f"[{pname}] {vuln_desc}",
                    priority=severity,
                    tools_suggested=[],
                    confidence=0.7 + (0.05 if severity == "critical" else
                                     0.03 if severity == "high" else 0.0),
                ))
                # Include additional actions as separate guidance entries
                for action in actions[1:]:
                    guidance.append(ExpertGuidance(
                        recommendation=action,
                        reason=f"[{pname}] Additional test vector",
                        priority=severity,
                        tools_suggested=[],
                        confidence=0.55,
                    ))

        # ── Phase 2: Match against tech correlations (header-based) ──
        # Detect technologies from Server header, X-Powered-By, X-Generator
        # and URL paths
        for indicator, tdata in Fuzzer._heuristic_tech_compiled:
            detected = False
            if indicator in scan_text:
                detected = True
            # Also check Server header for server names
            server_hdr = resp_lower.get("server", "")
            if indicator in server_hdr:
                detected = True
            # Check X-Powered-By for frameworks
            powered = resp_lower.get("x-powered-by", "")
            if indicator in powered:
                detected = True

            if detected:
                tech_key = next(
                    (k for k, v in Fuzzer._TECH_CORRELATIONS.items() if v is tdata),
                    "unknown"
                ).upper()
                vulns = tdata.get("vulns", [])
                tools = tdata.get("tools", [])

                if vulns:
                    top_vuln = vulns[0]
                    guidance.append(ExpertGuidance(
                        recommendation=(
                            f"Audit for known {tech_key} vulnerabilities: "
                            f"{top_vuln}"
                        ),
                        reason=f"Technology detected: {tech_key} via {indicator}",
                        priority="medium",
                        tools_suggested=list(tools)[:3],
                        confidence=0.75 if tools else 0.65,
                    ))
                    for v in vulns[1:3]:
                        guidance.append(ExpertGuidance(
                            recommendation=f"Check: {v}",
                            reason=f"{tech_key} additional vulnerability surface",
                            priority="medium",
                            tools_suggested=[],
                            confidence=0.5,
                        ))

        # ── Phase 3: Business logic patterns (8 patterns) ──
        for bl_name, bl_data in Fuzzer._BUSINESS_LOGIC.items():
            indicators = bl_data.get("indicators", [])
            if any(ind.lower() in scan_text for ind in indicators):
                bl_desc = bl_data.get("description", bl_name)
                actions = bl_data.get("suggested_actions", [])
                severity = bl_data.get("severity", "MEDIUM").lower()

                for action in actions[:2]:
                    guidance.append(ExpertGuidance(
                        recommendation=action,
                        reason=f"[{bl_name}] {bl_desc}",
                        priority=severity,
                        tools_suggested=[],
                        confidence=0.7 if severity in ("critical", "high") else 0.55,
                    ))

        return guidance

    @classmethod
    def _build_vuln_suggestions_from_patterns(cls, vuln_type: str) -> list[str]:
        """Generate testing suggestions dynamically from data files.

        Falls back to patterns.json expert patterns, business logic patterns,
        and tech correlations — all driven by the vuln_type keyword.
        """
        suggestions: list[str] = []

        # 1. Look up matching expert patterns by indicator overlap
        for pname, pdata in cls._EXPERT_PATTERNS.items():
            if vuln_type.replace("_", "") in pname.replace("_", "").lower():
                for action in pdata.get("suggested_actions", []):
                    if action not in suggestions:
                        suggestions.append(action)
            indicators = pdata.get("indicators", [])
            if any(
                ind.lower().replace("_", "") in vuln_type.lower()
                for ind in indicators
            ):
                for action in pdata.get("suggested_actions", []):
                    if action not in suggestions:
                        suggestions.append(action)

        # 2. Look up matching business logic patterns
        for bl_name, bl_data in cls._BUSINESS_LOGIC.items():
            if vuln_type.replace("_", "") in bl_name.replace("_", "").lower():
                for action in bl_data.get("suggested_actions", []):
                    if action not in suggestions:
                        suggestions.append(action)

        # 3. Look up matching tech correlations (known vulns for a tech)
        for tech_name, tdata in cls._TECH_CORRELATIONS.items():
            if tech_name in vuln_type.lower():
                for vuln in tdata.get("vulns", []):
                    if vuln not in suggestions:
                        suggestions.append(vuln)

        # 4. If no pattern matched, provide generic exploration guidance
        suggestions.extend([
            f"Test {vuln_type} with alternative payloads from "
            f"waf_bypass and exploit strategy data files",
            "Check other endpoints for same vulnerability class",
            "Test with different HTTP methods and content types",
        ])

        return suggestions

    @classmethod
    def suggest_next_tests(cls, vuln_type: str) -> list[str]:
        cls._load_heuristic_data()
        return cls._build_vuln_suggestions_from_patterns(vuln_type)


class ExploitChainEngine:
    def __init__(self, fuzzer: Fuzzer):
        self.fuzzer = fuzzer
        self.discovered_chains: list[ExploitChain] = []
        self._special_probe_cache: dict[str, list[FuzzResult]] = {}

    async def discover_chains(
        self,
        initial_findings: list[FuzzResult],
    ) -> list[ExploitChain]:
        chains: list[ExploitChain] = []

        for finding in initial_findings:
            follow_ons = list(CHAIN_RULES.get(finding.vuln_type, []))

            # Family-based follow-ons are data-driven (CHAIN_FAMILY_FOLLOWONS in
            # fuzzer_data.json) — no hardcoded family membership in code.
            for _fam in CHAIN_FAMILY_FOLLOWONS:
                if finding.vuln_type in (_fam.get("members") or []):
                    follow_ons.extend(_fam.get("follow_ons") or [])
            follow_ons = list(dict.fromkeys(follow_ons))
            if not follow_ons:
                continue

            steps: list[ChainLink] = []
            for chain_vuln in follow_ons:
                link = await self._test_chain_step(finding, chain_vuln)
                if link:
                    steps.append(link)

            if steps:
                chain = self._build_chain(finding, steps)
                chains.append(chain)

        self.discovered_chains = self.prioritize_chains(chains)
        return self.discovered_chains

    async def _test_chain_step(
        self,
        parent: FuzzResult,
        chain_vuln: str,
    ) -> ChainLink | None:
        specialized = await self._test_special_chain_step(parent, chain_vuln)
        if specialized is not None:
            return specialized

        payloads = CHAIN_PAYLOADS.get(chain_vuln, [])
        if not payloads:
            return ChainLink(
                vuln_type=chain_vuln,
                parameter=parent.parameter,
                payload="[theoretical — no active test payload]",
                prerequisite=parent.vuln_type,
                impact_description=_chain_impact(parent.vuln_type, chain_vuln),
                confidence=0.45,
            )

        for payload in payloads[:2]:
            result = await self.fuzzer._fuzz_single(
                parent.parameter, payload, chain_vuln
            )
            if result and result.confidence > 0.5:
                return ChainLink(
                    vuln_type=chain_vuln,
                    parameter=parent.parameter,
                    payload=payload,
                    prerequisite=parent.vuln_type,
                    impact_description=_chain_impact(parent.vuln_type, chain_vuln),
                    confidence=result.confidence,
                )
        return None

    async def _cached_probe(
        self,
        cache_key: str,
        producer: Callable[
            [],
            (
                Awaitable[
                    list[FuzzResult]
                    | AsyncIterator[FuzzResult]
                    | Iterable[FuzzResult]
                    | None
                ]
                | AsyncIterator[FuzzResult]
                | Iterable[FuzzResult]
                | None
            ),
        ],
    ) -> list[FuzzResult]:
        if cache_key in self._special_probe_cache:
            return self._special_probe_cache[cache_key]
        produced = producer()
        if asyncio.iscoroutine(produced):
            produced = await cast(
                Awaitable[
                    list[FuzzResult]
                    | AsyncIterator[FuzzResult]
                    | Iterable[FuzzResult]
                    | None
                ],
                produced,
            )
        if produced is None:
            results: list[FuzzResult] = []
        elif isinstance(produced, list):
            results = produced
        elif isinstance(produced, AsyncIteratorABC):
            results = [item async for item in produced]
        elif isinstance(produced, Iterable):
            results = list(produced)
        else:
            results = []
        self._special_probe_cache[cache_key] = results
        return results

    async def _test_special_chain_step(
        self,
        parent: FuzzResult,
        chain_vuln: str,
    ) -> ChainLink | None:
        findings: list[FuzzResult] = []

        if parent.vuln_type in {"ssrf", "xxe"} or chain_vuln == "ssrf":
            findings = await self._cached_probe(
                f"ssrf::{parent.parameter}",
                lambda: self.fuzzer._run_cloud_ssrf_exploitation([parent.parameter]),
            )
            findings = [f for f in findings if f.vuln_type.startswith("ssrf_")]

        elif parent.vuln_type == "graphql" or chain_vuln in {
            "information_disclosure",
            "idor",
            "dos_via_complex_query",
        }:
            findings = await self._cached_probe(
                f"graphql::{parent.target}",
                lambda: self.fuzzer._run_graphql_automation([parent.target]),
            )
            if chain_vuln == "information_disclosure":
                findings = [
                    f
                    for f in findings
                    if f.vuln_type == "graphql_introspection_exposed"
                ]
            elif chain_vuln == "idor":
                findings = [
                    f for f in findings if f.vuln_type == "graphql_idor_candidate"
                ]
            elif chain_vuln == "dos_via_complex_query":
                findings = [
                    f for f in findings if f.vuln_type == "graphql_batching_enabled"
                ]

        elif parent.vuln_type == "race_condition" or chain_vuln in {
            "double_spend",
            "quota_bypass",
            "auth_bypass",
        }:
            findings = await self._cached_probe(
                f"race::{parent.parameter}",
                lambda: self.fuzzer._run_race_condition_testing([parent.parameter]),
            )
            findings = [f for f in findings if f.vuln_type == "race_condition_possible"]

        elif chain_vuln == "second_order_injection":
            findings = await self._cached_probe(
                f"second_order::{parent.parameter}",
                lambda: self.fuzzer._run_second_order_detection(
                    [parent.parameter], None
                ),
            )
            findings = [
                f
                for f in findings
                if f.vuln_type.startswith("second_order")
                or f.vuln_type == "stored_input_flow"
            ]

        elif chain_vuln == "http_desync_cache":
            findings = await self._cached_probe(
                "desync_cache::global",
                self.fuzzer._run_http_desync_cache_testing,
            )
            findings = [
                f
                for f in findings
                if f.vuln_type
                in {
                    "cache_poisoning_candidate",
                    "cache_key_anomaly",
                    "http_desync_candidate",
                }
            ]

        if not findings:
            return None

        best = max(findings, key=lambda item: item.confidence)
        return ChainLink(
            vuln_type=chain_vuln,
            parameter=best.parameter or parent.parameter,
            payload=best.payload,
            prerequisite=parent.vuln_type,
            impact_description=f"{_chain_impact(parent.vuln_type, chain_vuln)} ({best.vuln_type})",
            confidence=max(0.60, best.confidence),
        )

    def _build_chain(
        self,
        trigger: FuzzResult,
        steps: list[ChainLink],
    ) -> ExploitChain:
        trigger_link = ChainLink(
            vuln_type=trigger.vuln_type,
            parameter=trigger.parameter,
            payload=trigger.payload,
            prerequisite=None,
            impact_description=f"Initial {trigger.vuln_type} vulnerability",
            confidence=trigger.confidence,
        )
        all_steps = [trigger_link] + steps
        severity = self._compute_chain_severity(all_steps)
        total_conf = _geometric_mean([s.confidence for s in all_steps])
        chain_steps = " → ".join(s.vuln_type for s in steps)
        return ExploitChain(
            name=f"{trigger.vuln_type} → {chain_steps}",
            trigger_vuln=trigger.vuln_type,
            steps=all_steps,
            total_confidence=total_conf,
            combined_severity=severity,
            narrative=self.generate_chain_report_from_steps(all_steps, trigger.target),
        )

    def prioritize_chains(self, chains: list[ExploitChain]) -> list[ExploitChain]:
        _sev_lower = [s.lower() for s in _SEVERITY_ORDER]

        def _sort_key(c: ExploitChain) -> tuple[int, float]:
            sev = (c.combined_severity or "").lower()
            sev_score = _sev_lower.index(sev) if sev in _sev_lower else -1
            return (-sev_score, -c.total_confidence)

        return sorted(chains, key=_sort_key)

    def generate_chain_report(self, chain: ExploitChain) -> str:
        return self.generate_chain_report_from_steps(chain.steps, self.fuzzer.target)

    @staticmethod
    def generate_chain_report_from_steps(
        steps: list[ChainLink],
        target: str,
    ) -> str:
        lines = [f"Exploit Chain — Target: {target}", "=" * 60]
        for i, step in enumerate(steps, 1):
            prereq = f" (requires: {step.prerequisite})" if step.prerequisite else ""
            lines.append(
                f"Step {i}: [{step.vuln_type.upper()}]{prereq}\n"
                f"  Parameter : {step.parameter}\n"
                f"  Payload   : {step.payload[:80]}\n"
                f"  Impact    : {step.impact_description}\n"
                f"  Confidence: {step.confidence:.0%}"
            )
        return "\n".join(lines)

    @staticmethod
    def _compute_chain_severity(steps: list[ChainLink]) -> str:
        critical_types = {
            "rce",
            "rce_via_outfile",
            "rce_via_log_poison",
            "reverse_shell",
            "data_exfiltration",
        }
        high_types = {"auth_bypass", "privilege_escalation", "account_takeover", "ssrf"}

        all_types = {s.vuln_type for s in steps}

        if all_types & critical_types:
            return "critical"
        if all_types & high_types:
            return "high"
        if len(steps) >= 3:
            return "high"
        return "medium"


class InteractiveRealTimeTester:
    def __init__(
        self,
        target: str,
        threads: int = 5,
        timeout: int = 10,
        on_finding: Callable[[FuzzResult], None] | None = None,
        headers: dict[str, str] | None = None,
        auth_login_url: str | None = None,
    ):
        self.target = target
        self.fuzzer = Fuzzer(
            target=target,
            threads=threads,
            timeout=timeout,
            headers=headers,
            auth_login_url=auth_login_url,
        )
        self.chain_engine = ExploitChainEngine(self.fuzzer)
        self.on_finding = on_finding
        self._stop_event = asyncio.Event()
        self._findings: list[FuzzResult] = []
        self._chains: list[ExploitChain] = []

    async def probe_baseline(self, params: list[str]) -> dict[str, Any]:
        probe_fn = getattr(self.fuzzer, "probe", None)
        tasks: list[Awaitable[dict[str, Any]]]
        if callable(probe_fn):
            typed_probe = cast(Callable[[str], Awaitable[dict[str, Any]]], probe_fn)
            tasks = [typed_probe(p) for p in params]
        else:
            tasks = [self.fuzzer._fetch_baseline(p) for p in params]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return {
            p: r for p, r in zip(params, results) if not isinstance(r, BaseException)
        }

    async def stream_fuzz(
        self,
        params: list[str] | None = None,
        vuln_types: list[str] | None = None,
    ) -> AsyncIterator[RealTimeEvent]:
        params = params or self.fuzzer.get_high_priority_targets()[:10]
        vuln_types = vuln_types or list(FUZZ_PAYLOADS.keys())
        fuzz_fn = getattr(self.fuzzer, "fuzz", None)
        is_native_fuzz = (
            getattr(fuzz_fn, "__self__", None) is self.fuzzer
            and getattr(fuzz_fn, "__func__", None) is Fuzzer.fuzz
        )

        yield RealTimeEvent(
            event_type="progress",
            data={
                "phase": "baseline",
                "params": params,
                "message": "Probing baseline responses...",
            },
        )
        if is_native_fuzz:
            await self.probe_baseline(params)
        else:
            logger.debug("Skipping baseline probe for custom fuzz provider")

        total = sum(len(FUZZ_PAYLOADS.get(vt, [])) for vt in vuln_types) * len(params)
        done = 0

        yield RealTimeEvent(
            event_type="progress",
            data={
                "phase": "fuzzing",
                "total_tests": total,
                "message": f"Starting {total} fuzz tests...",
            },
        )

        try:
            if is_native_fuzz:
                finding_stream = self.fuzzer.fuzz(
                    params=params,
                    vuln_types=vuln_types,
                    skip_baseline=True,
                )
            else:
                try:
                    finding_stream = self.fuzzer.fuzz(
                        params=params,
                        vuln_types=vuln_types,
                    )
                except TypeError:
                    finding_stream = self.fuzzer.fuzz(params, vuln_types)

            if asyncio.iscoroutine(finding_stream):
                finding_stream = await finding_stream

            if not hasattr(finding_stream, "__aiter__"):
                raise TypeError("fuzzer.fuzz must return an async iterator")

            async for raw_finding in finding_stream:
                if self._stop_event.is_set():
                    break

                done += 1
                result = self._coerce_fuzz_result(raw_finding)
                if result is None:
                    continue

                self._findings.append(result)
                if self.on_finding:
                    try:
                        self.on_finding(result)
                    except Exception as e:
                        logger.debug("Expected failure in on_finding callback: %s", e)

                yield RealTimeEvent(
                    event_type="finding",
                    data={
                        "vuln_type": result.vuln_type,
                        "parameter": result.parameter,
                        "payload": result.payload,
                        "severity": result.severity,
                        "confidence": result.confidence,
                        "evidence": result.evidence,
                        "response_code": result.response_code,
                        "time_ms": result.time_ms,
                    },
                )

                if done % 20 == 0:
                    bounded_done = min(done, total)
                    yield RealTimeEvent(
                        event_type="progress",
                        data={
                            "phase": "fuzzing",
                            "done": bounded_done,
                            "total": total,
                            "findings_so_far": len(self._findings),
                            "pct": round(bounded_done / total * 100, 1) if total else 0,
                        },
                    )
        except Exception as exc:
            yield RealTimeEvent(
                event_type="error",
                data={"phase": "fuzzing", "message": str(exc)},
            )
            yield RealTimeEvent(
                event_type="complete",
                data=self.get_summary(),
            )
            return

        if self._findings:
            yield RealTimeEvent(
                event_type="progress",
                data={
                    "phase": "chaining",
                    "message": f"Discovering exploit chains from {len(self._findings)} findings...",
                },
            )
            discover_fn = getattr(self.chain_engine, "find_chains", None)
            if not callable(discover_fn):
                discover_fn = getattr(self.chain_engine, "discover_chains", None)
            if callable(discover_fn):
                self._chains = await discover_fn(self._findings)
            else:
                self._chains = []
            for chain in self._chains:
                yield RealTimeEvent(
                    event_type="chain_discovered",
                    data={
                        "name": getattr(
                            chain, "name", getattr(chain, "chain_id", "chain")
                        ),
                        "trigger_vuln": getattr(chain, "trigger_vuln", "unknown"),
                        "steps": len(getattr(chain, "steps", [])),
                        "severity": getattr(chain, "combined_severity", "medium"),
                        "confidence": getattr(chain, "total_confidence", 0.0),
                        "narrative": getattr(chain, "narrative", ""),
                    },
                )

        yield RealTimeEvent(
            event_type="complete",
            data=self.get_summary(),
        )

    async def stop(self) -> None:
        self._stop_event.set()
        await self.fuzzer.close()

    @staticmethod
    def _coerce_fuzz_result(raw: Any) -> FuzzResult | None:
        if isinstance(raw, FuzzResult):
            return raw
        if not isinstance(raw, dict):
            return None

        parameter = raw.get("parameter", raw.get("param", ""))
        payload = raw.get("payload", "")
        if not parameter:
            return None

        severity = str(raw.get("severity", "medium")).lower()
        try:
            confidence = float(raw.get("confidence", 0.7))
        except (TypeError, ValueError):
            confidence = 0.7

        response_code = raw.get("response_code", raw.get("status_code", 0))
        response_length = raw.get("response_length", raw.get("body_length", 0))
        time_ms = raw.get("time_ms", 0.0)

        return FuzzResult(
            target=str(raw.get("target", "")),
            parameter=str(parameter),
            payload=str(payload),
            vuln_type=str(raw.get("vuln_type", "unknown")),
            severity=severity,
            evidence=str(raw.get("evidence", "")),
            confidence=confidence,
            response_code=int(response_code or 0),
            response_length=int(response_length or 0),
            time_ms=float(time_ms or 0.0),
        )

    def get_summary(self) -> dict[str, Any]:
        sev_counts: dict[str, int] = {}
        for f in self._findings:
            sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1

        return {
            "target": self.target,
            "total_findings": len(self._findings),
            "total_chains": len(self._chains),
            "severity_breakdown": sev_counts,
            "vuln_types": list({f.vuln_type for f in self._findings}),
            "chains": [
                {
                    "name": c.name,
                    "severity": c.combined_severity,
                    "confidence": c.total_confidence,
                }
                for c in self._chains
            ],
        }


def _confidence_to_severity(confidence: float) -> str:
    if confidence >= 0.85:
        return "critical"
    if confidence >= 0.70:
        return "high"
    if confidence >= 0.50:
        return "medium"
    if confidence >= 0.30:
        return "low"
    return "info"


def _geometric_mean(values: list[float]) -> float:
    if not values:
        return 0.0
    return math.exp(sum(math.log(max(v, 1e-9)) for v in values) / len(values))


def _chain_impact(trigger: str, follow_on: str) -> str:
    impact_map = {
        (
            "xss",
            "csrf",
        ): "Attacker can forge state-changing requests from victim's browser",
        (
            "xss",
            "session_hijacking",
        ): "Attacker can steal session cookies and take over accounts",
        (
            "xss",
            "account_takeover",
        ): "Full account takeover via scripted credential change",
        (
            "sql_injection",
            "auth_bypass",
        ): "Attacker can log in as any user without credentials",
        (
            "sql_injection",
            "data_exfiltration",
        ): "Full database dump including credentials possible",
        (
            "sql_injection",
            "rce_via_outfile",
        ): "Remote code execution via SQL INTO OUTFILE webshell",
        (
            "idor",
            "privilege_escalation",
        ): "Access admin-level functions as regular user",
        ("idor", "data_exfiltration"): "Read other users' private data at scale",
        ("ssti", "rce"): "Execute arbitrary OS commands via template injection",
        ("path_traversal", "lfi"): "Read arbitrary local files including /etc/shadow",
        (
            "path_traversal",
            "rce_via_log_poison",
        ): "RCE via log file poisoning + path traversal",
        ("xxe", "ssrf"): "Internal network access and metadata service disclosure",
        ("xxe", "rce"): "Arbitrary file write leading to code execution",
        (
            "race_condition",
            "double_spend",
        ): "Financial fraud — purchase items at no cost",
        ("command_injection", "rce"): "Full remote code execution on the server",
        ("command_injection", "reverse_shell"): "Interactive shell access to server",
    }
    return impact_map.get(
        (trigger, follow_on), f"Chained {trigger} enables {follow_on} exploitation"
    )


async def quick_fuzz_url(
    url: str,
    params: list[str] | None = None,
    headers: dict[str, str] | None = None,
    max_payloads_per_type: int | None = None,
    timeout_seconds: float | None = None,
    threads: int | None = None,
    per_request_timeout: int | None = None,
) -> list[FuzzResult]:
    from .config import get_config

    cfg = get_config()
    max_payloads_per_type = (
        max_payloads_per_type or cfg.fuzzer_quick_max_payloads_per_type
    )
    timeout_seconds = timeout_seconds or cfg.fuzzer_quick_timeout_seconds
    threads = threads or cfg.fuzzer_threads
    per_request_timeout = per_request_timeout or cfg.fuzzer_timeout
    params = params or ["q", "search", "id", "page"]
    async with Fuzzer(
        url, threads=threads, timeout=per_request_timeout, headers=headers
    ) as fuzzer:
        return await asyncio.wait_for(
            fuzzer.fuzz_parameters(
                params=params,
                vuln_types=["sql_injection", "xss", "path_traversal", "ssti"],
                max_payloads_per_type=max_payloads_per_type,
            ),
            timeout=timeout_seconds,
        )


def generate_fuzz_wordlist(
    max_combinations: int = 300,
    vuln_types: list[str] | None = None,
) -> list[str]:
    all_payloads: dict[str, list[str]] = _fuzzer_data.get("FUZZ_PAYLOADS", {})
    categories = vuln_types if vuln_types else list(all_payloads.keys())

    seen: set[str] = set()
    result: list[str] = []

    def _add(item: str) -> None:
        if item not in seen:
            seen.add(item)
            result.append(item)

    for cat in categories:
        for payload in all_payloads.get(cat, []):
            _add(payload)

    for param in FUZZ_POINTS:
        _add(param)

    for combo in MutationEngine.generate_wordlist_combinations(
        FUZZ_POINTS, max_size=max_combinations
    ):
        _add(combo)

    return result

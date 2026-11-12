from __future__ import annotations

import asyncio
import logging
import random
from collections import deque
from typing import Any
from urllib.parse import urlparse

import httpx

from ..config import get_config

logger = logging.getLogger("airecon.proxy.agent.rate_limiter")
rng = random.SystemRandom()


class AdaptiveRateLimiter:
    _RESPONSE_EWMA_ALPHA = 0.3
    _CONGESTION_EWMA_ALPHA = 0.4
    _SUCCESS_WINDOW = 30
    _CONNECT_ERROR_ABORT_THRESHOLD = 5

    def __init__(
        self,
        base_delay: float | None = None,
        max_delay: float | None = None,
        max_retries: int | None = None,
        timeout: int | None = None,
        rate_limit_abort_threshold: int | None = None,
    ):
        config = get_config()
        self.base_delay = (
            base_delay if base_delay is not None else config.rate_limiter_base_delay
        )
        self.max_delay = (
            max_delay if max_delay is not None else config.rate_limiter_max_delay
        )
        self.max_retries = (
            max_retries if max_retries is not None else config.rate_limiter_max_retries
        )
        self.http_timeout = (
            timeout if timeout is not None else config.rate_limiter_http_timeout
        )
        self.rate_limit_abort_threshold = (
            rate_limit_abort_threshold
            if rate_limit_abort_threshold is not None
            else config.rate_limiter_abort_threshold
        )

        self.client = httpx.AsyncClient(
            timeout=self.http_timeout,
            follow_redirects=True,
        )

        self.domain_delays: dict[str, float] = {}
        self.last_request_time: dict[str, float] = {}
        self.rate_limit_hits: dict[str, int] = {}
        self.consecutive_rate_limits: dict[str, int] = {}
        self.consecutive_connect_errors: dict[str, int] = {}
        self.aborted_domains: set[str] = set()

        self._response_latency_ewma: dict[str, float] = {}
        self._congestion_signal: dict[str, float] = {}
        self._success_log: dict[str, deque[bool]] = {}
        self._consecutive_successes: dict[str, int] = {}
        self._baseline_latency_ms: dict[str, float] = {}
        self._slow_start_done: dict[str, bool] = {}

        self.domain_locks: dict[str, asyncio.Lock] = {}

    async def close(self) -> None:
        await self.client.aclose()

    async def __aenter__(self) -> "AdaptiveRateLimiter":
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.close()

    async def request(
        self,
        method: str,
        url: str,
        **kwargs: Any,
    ) -> httpx.Response | None:
        domain = urlparse(url).netloc

        if domain in self.aborted_domains:
            logger.warning(
                "Skipping request to aborted domain %s (rate limit storm)", domain
            )
            return None

        for attempt in range(self.max_retries):
            try:
                await self._apply_rate_limit(domain)

                loop = asyncio.get_running_loop()
                request_started = loop.time()
                response = await self.client.request(method, url, **kwargs)
                request_elapsed_ms = (loop.time() - request_started) * 1000.0
                response.extensions["airecon_request_ms"] = request_elapsed_ms

                self.last_request_time[domain] = loop.time()
                self._record_response(domain, response.status_code, request_elapsed_ms)

                if response.status_code == 429:
                    logger.warning("Rate limit hit (429) on %s", domain)
                    await self._handle_rate_limit(response, domain)
                    continue

                if response.status_code == 503:
                    logger.warning("Service unavailable (503) on %s", domain)
                    await self._handle_503(response, domain)
                    continue

                self.consecutive_rate_limits[domain] = 0
                self.consecutive_connect_errors[domain] = 0

                return response

            except httpx.TimeoutException:
                logger.warning("Request timeout on attempt %d", attempt + 1)
                self._record_timeout(domain)
                if attempt < self.max_retries - 1:
                    await asyncio.sleep(self._get_backoff_delay(domain, attempt))
                    continue
                return None

            except httpx.ConnectError:
                self._record_error(domain)
                conn_errors = self.consecutive_connect_errors.get(domain, 0) + 1
                self.consecutive_connect_errors[domain] = conn_errors
                if conn_errors >= self._CONNECT_ERROR_ABORT_THRESHOLD:
                    self.aborted_domains.add(domain)
                    logger.error(
                        "Domain %s aborted: %d consecutive connection failures "
                        "(DNS resolution failed). Skipping further requests.",
                        domain, conn_errors,
                    )
                    return None
                logger.debug(
                    "Connection failed for %s (%d/%d consecutive errors)",
                    domain, conn_errors, self._CONNECT_ERROR_ABORT_THRESHOLD,
                )
                return None

            except Exception as e:
                logger.error("Request error: %s", e)
                self._record_error(domain)
                if attempt < self.max_retries - 1:
                    await asyncio.sleep(self.base_delay)
                    continue
                return None

        logger.error("All %d retries exhausted for %s", self.max_retries, url)
        return None

    async def get(self, url: str, **kwargs: Any) -> httpx.Response | None:
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs: Any) -> httpx.Response | None:
        return await self.request("POST", url, **kwargs)

    async def _apply_rate_limit(self, domain: str) -> None:
        if domain not in self.domain_locks:
            self.domain_locks[domain] = asyncio.Lock()
        async with self.domain_locks[domain]:
            current_time = asyncio.get_running_loop().time()
            last_time = self.last_request_time.get(domain, 0)

            delay = self.domain_delays.get(domain, self.base_delay)
            elapsed = current_time - last_time

            if elapsed < delay:
                wait_time = delay - elapsed
                logger.debug("Rate limiting: waiting %.2fs for %s", wait_time, domain)
                await asyncio.sleep(wait_time)

            self.last_request_time[domain] = asyncio.get_running_loop().time()

    async def _handle_rate_limit(
        self,
        response: httpx.Response,
        domain: str,
    ) -> None:
        consecutive = self.consecutive_rate_limits.get(domain, 0) + 1
        self.consecutive_rate_limits[domain] = consecutive

        if consecutive >= self.rate_limit_abort_threshold:
            self.aborted_domains.add(domain)
            logger.error(
                "Domain %s aborted: %d consecutive rate limits (threshold: %d). "
                "Skipping further requests to prevent stuck state.",
                domain,
                consecutive,
                self.rate_limit_abort_threshold,
            )
            return

        retry_after = response.headers.get("Retry-After")
        if retry_after:
            try:
                delay = float(retry_after)
                logger.info("Retry-After header: %.1fs", delay)
            except ValueError:
                delay = self.base_delay * (2 ** consecutive)
        else:
            hit_count = self.rate_limit_hits.get(domain, 0) + 1
            self.rate_limit_hits[domain] = hit_count

            ewma = self._response_latency_ewma.get(domain, 100.0)
            latency_factor = max(1.0, ewma / 200.0)
            delay = min(
                self.base_delay * (2 ** hit_count) * latency_factor,
                self.max_delay,
            )

        jitter = rng.uniform(0.8, 1.4)
        delay *= jitter

        self._slow_start_done[domain] = True

        logger.info("Rate limit delay: %.2fs for %s (consecutive=%d)", delay, domain, consecutive)
        await asyncio.sleep(delay)

    async def _handle_503(
        self,
        response: httpx.Response,
        domain: str,
    ) -> None:
        hit_count = self.rate_limit_hits.get(domain, 0) + 1
        self.rate_limit_hits[domain] = hit_count

        delay = min(self.base_delay * (2 ** hit_count), self.max_delay)
        jitter = rng.uniform(0.5, 1.5)
        delay *= jitter

        logger.info("503 backoff delay: %.2fs for %s", delay, domain)
        await asyncio.sleep(delay)

    def _record_response(
        self, domain: str, status_code: int, elapsed_ms: float
    ) -> None:
        is_success = 200 <= status_code < 400 and status_code != 429

        log = self._success_log.setdefault(domain, deque(maxlen=self._SUCCESS_WINDOW))
        log.append(is_success)

        alpha = self._RESPONSE_EWMA_ALPHA
        prev = self._response_latency_ewma.get(domain, elapsed_ms)
        self._response_latency_ewma[domain] = alpha * elapsed_ms + (1 - alpha) * prev

        current_min = self._baseline_latency_ms.get(domain, float("inf"))
        if elapsed_ms < current_min:
            self._baseline_latency_ms[domain] = elapsed_ms

        baseline = self._baseline_latency_ms.get(domain, elapsed_ms)
        if baseline > 0:
            raw_congestion = min(1.0, self._response_latency_ewma[domain] / (baseline * 3.0))
            c = self._CONGESTION_EWMA_ALPHA
            prev_c = self._congestion_signal.get(domain, 0.0)
            self._congestion_signal[domain] = c * raw_congestion + (1 - c) * prev_c

        if is_success:
            consec = self._consecutive_successes.get(domain, 0) + 1
            self._consecutive_successes[domain] = consec

            if consec >= 5:
                congestion = self._congestion_signal.get(domain, 0.0)
                if congestion < 0.3:
                    current_delay = self.domain_delays.get(domain, self.base_delay)
                    new_delay = max(current_delay * 0.8, self.base_delay * 0.5)
                    self.domain_delays[domain] = new_delay
                    self._consecutive_successes[domain] = 0
                    logger.debug(
                        "Rate probe: lowered delay for %s to %.2fs (congestion=%.2f)",
                        domain,
                        new_delay,
                        congestion,
                    )
        else:
            self._consecutive_successes[domain] = 0
            if status_code == 429:
                self._apply_congestion_penalty(domain, factor=2.0)

    def _record_timeout(self, domain: str) -> None:
        self._success_log.setdefault(domain, deque(maxlen=self._SUCCESS_WINDOW)).append(False)
        self._consecutive_successes[domain] = 0
        self._apply_congestion_penalty(domain, factor=1.5)

    def _record_error(self, domain: str) -> None:
        self._success_log.setdefault(domain, deque(maxlen=self._SUCCESS_WINDOW)).append(False)
        self._consecutive_successes[domain] = 0

    def _apply_congestion_penalty(self, domain: str, factor: float) -> None:
        current = self.domain_delays.get(domain, self.base_delay)
        new_delay = min(current * factor, self.max_delay)
        self.domain_delays[domain] = new_delay
        self._congestion_signal[domain] = min(
            1.0, self._congestion_signal.get(domain, 0.0) + 0.15
        )

    def _get_backoff_delay(self, domain: str, attempt: int) -> float:
        ewma = self._response_latency_ewma.get(domain, self.base_delay * 1000)
        base = max(self.base_delay, ewma / 1000.0)
        backoff = min(base * (2 ** attempt), self.max_delay)
        jitter = rng.uniform(0.5, 1.5)
        return backoff * jitter

    def get_domain_stats(self, domain: str) -> dict[str, Any]:
        log = self._success_log.get(domain, deque())
        successes = sum(1 for x in log if x) if log else 0
        total = len(log) if log else 0
        return {
            "domain": domain,
            "current_delay": self.domain_delays.get(domain, self.base_delay),
            "ewma_latency_ms": self._response_latency_ewma.get(domain, 0),
            "baseline_latency_ms": self._baseline_latency_ms.get(domain, 0),
            "congestion_signal": self._congestion_signal.get(domain, 0.0),
            "success_rate": successes / total if total else 0.0,
            "total_requests": total,
            "rate_limit_hits": self.rate_limit_hits.get(domain, 0),
            "consecutive_rate_limits": self.consecutive_rate_limits.get(domain, 0),
            "aborted": domain in self.aborted_domains,
        }

    def get_all_stats(self) -> dict[str, dict[str, Any]]:
        return {k: self.get_domain_stats(k) for k in set(list(self.domain_delays.keys()) + list(self._success_log.keys()))}

    def set_rate_limit(self, domain: str, requests_per_second: float) -> None:
        if requests_per_second > 0:
            delay = 1.0 / requests_per_second
            self.domain_delays[domain] = delay
            self._slow_start_done[domain] = True
            logger.info("Rate limit set for %s: %s req/s → delay %.3fs", domain, requests_per_second, delay)

    def reset_rate_limit(self, domain: str) -> None:
        if domain in self.domain_delays:
            del self.domain_delays[domain]
        if domain in self.rate_limit_hits:
            del self.rate_limit_hits[domain]
        if domain in self.consecutive_rate_limits:
            del self.consecutive_rate_limits[domain]
        if domain in self.aborted_domains:
            self.aborted_domains.discard(domain)
            logger.info("Domain %s removed from aborted list", domain)
        logger.info("Rate limit reset for %s", domain)

    def configure_proxy(self, proxy_url: str) -> None:
        old_client = self.client
        self.client = httpx.AsyncClient(
            proxy=proxy_url,
            timeout=self.http_timeout,
            follow_redirects=True,
        )

        try:
            loop = asyncio.get_running_loop()
            loop.create_task(old_client.aclose())
        except RuntimeError:
            try:
                asyncio.run(old_client.aclose())
            except Exception as e:
                logger.debug("Expected failure closing old httpx client: %s", e)
        logger.info("Proxy configured: %s", proxy_url)

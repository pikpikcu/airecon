from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
import time
from pathlib import Path
from typing import Any

logger = logging.getLogger("airecon.web_search")

_CACHE_DIR = Path.home() / ".airecon" / "cache" / "search"
_CACHE_TTL = 3600

_DDG_MIN_INTERVAL = 2.0
_last_ddg_search_time: float = 0.0

_ddg_lock: asyncio.Lock | None = None
_ddg_lock_init_lock = __import__("threading").Lock()

def _get_ddg_lock() -> asyncio.Lock:
    global _ddg_lock
    if _ddg_lock is None:
        with _ddg_lock_init_lock:
            if _ddg_lock is None:
                _ddg_lock = asyncio.Lock()
    return _ddg_lock

async def _searxng_search(
    query: str,
    max_results: int,
    base_url: str,
    engines: str,
) -> dict[str, Any]:
    import aiohttp

    url = f"{base_url.rstrip('/')}/search"
    params = {
        "q": query,
        "format": "json",
        "engines": engines,
        "language": "en",
        "safesearch": "0",
    }

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, params=params, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                if resp.status != 200:
                    return {
                        "success": False,
                        "error": f"SearXNG returned HTTP {resp.status}",
                    }
                data = await resp.json(content_type=None)
    except aiohttp.ClientConnectorError as e:
        return {
            "success": False,
            "error": f"Cannot connect to SearXNG at {base_url}: {e}. "
            "Check that the SearXNG container is running.",
        }
    except asyncio.TimeoutError:
        return {
            "success": False,
            "error": f"SearXNG request timed out at {base_url}.",
        }

    results = data.get("results", [])[:max_results]

    if not results:
        return {
            "success": True,
            "result": f"No results found for: {query}\n"
            f"(SearXNG queried engines: {engines})",
        }

    lines: list[str] = []
    for i, r in enumerate(results, 1):
        title = r.get("title", "No title")
        href = r.get("url", "")
        body = r.get("content", "")
        engine = r.get("engine", "")
        lines.append(f"{i}. [{engine}] **{title}**\n   URL: {href}\n   {body}")

    return {"success": True, "result": "\n\n".join(lines)}

async def _ddg_search(query: str, max_results: int) -> dict[str, Any]:
    global _last_ddg_search_time

    try:
        from duckduckgo_search import DDGS
        from duckduckgo_search.exceptions import (
            DuckDuckGoSearchException,
            RatelimitException,
        )
    except ImportError:
        return {
            "success": False,
            "error": "duckduckgo-search not installed. Run: pip install duckduckgo-search",
        }

    def _search() -> list[dict[str, Any]]:
        with DDGS() as ddgs:
            return list(ddgs.text(query, max_results=max_results))

    last_err: Exception | None = None
    for attempt in range(3):
        try:
            async with _get_ddg_lock():
                now = time.monotonic()
                wait = _DDG_MIN_INTERVAL - (now - _last_ddg_search_time)
                if wait > 0:
                    await asyncio.sleep(wait)
                _last_ddg_search_time = time.monotonic()
                results = await asyncio.to_thread(_search)
            break
        except RatelimitException as e:
            last_err = e
            wait_time = 5.0 * (attempt + 1)
            logger.warning(
                f"DDG rate limit attempt {attempt + 1}, waiting {wait_time:.0f}s"
            )
            await asyncio.sleep(wait_time)
        except DuckDuckGoSearchException as e:
            last_err = e
            logger.warning(f"DDG error attempt {attempt + 1}: {e}")
            await asyncio.sleep(3.0 * (attempt + 1))
    else:
        return {
            "success": False,
            "error": f"DuckDuckGo rate limited after 3 attempts: {last_err}. "
            "Configure searxng_url in ~/.airecon/config.yaml for better results.",
        }

    if not results:
        hint = ""
        if "site:*." in query or "ext:" in query:
            hint = (
                " NOTE: DuckDuckGo does not support wildcard site: or ext: operators. "
                "Configure SearXNG (searxng_url in config) to enable full Google dork support, "
                "or use execute: curl 'https://crt.sh/?q=%25.target.com&output=json'"
            )
        return {"success": True, "result": f"No results found for: {query}{hint}"}

    lines: list[str] = []
    for i, r in enumerate(results, 1):
        title = r.get("title", "No title")
        href = r.get("href", "")
        body = r.get("body", "")
        lines.append(f"{i}. [ddg] **{title}**\n   URL: {href}\n   {body}")

    return {"success": True, "result": "\n\n".join(lines)}

def _is_target_specific_query(query: str) -> bool:
    q = query.lower()

    if re.search(r"\bsite:\S+\b", q):
        return True

    if re.search(r"\b[a-z0-9\-]+\.[a-z]{2,}\b", q):
        return True

    if re.search(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", q):
        return True
    return False

async def web_search(query: str, max_results: int = 10, use_cache: bool = True) -> dict[str, Any]:
    effective_cache = use_cache and not _is_target_specific_query(query)

    try:
        from .config import get_config
        cfg = get_config()
        searxng_url = cfg.searxng_url.strip()
        engines = cfg.searxng_engines.strip() or "google,bing,duckduckgo,brave"
        youcom_enabled = bool(getattr(cfg, "youcom_search", False))
        youcom_url = (getattr(cfg, "youcom_url", "") or "").strip()
    except Exception:
        searxng_url = ""
        engines = "google,bing,duckduckgo,brave"
        youcom_enabled = False
        youcom_url = ""

    max_results = min(int(max_results), 50)

    if effective_cache:
        cached = _get_cached_results(query, max_results, engines)
        if cached:
            cached["from_cache"] = True
            return cached

    if youcom_enabled:
        from .web_search_youcom import youcom_search

        youcom_result = await youcom_search(
            query, max_results, youcom_url or "https://api.you.com/mcp?profile=free"
        )
        if youcom_result.get("success"):
            if effective_cache:
                _cache_results(query, max_results, youcom_result, engines)
            return youcom_result
        logger.warning(
            "You.com web search failed (%s) — falling back to SearXNG/DuckDuckGo",
            youcom_result.get("error"),
        )

    if searxng_url:

        try:
            from .searxng import get_shared_manager
            searxng_mgr = get_shared_manager()
            if not await searxng_mgr._is_running():
                logger.info("SearXNG not running — auto-starting on first web_search use")

                await asyncio.wait_for(
                    searxng_mgr.ensure_running(),
                    timeout=60.0
                )
        except asyncio.TimeoutError:
            logger.error("SearXNG auto-start timed out after 60s — using DDG fallback")
        except Exception as _start_err:
            logger.debug("SearXNG auto-start failed: %s — will use error recovery path", _start_err)

        result = await _searxng_search(query, max_results, searxng_url, engines)

        if result.get("success") and effective_cache:
            _cache_results(query, max_results, result, engines)

        _searxng_error = result.get("error", "")
        _searxng_unreachable = not result.get("success") and (
            "Cannot connect" in _searxng_error
            or "timed out" in _searxng_error
            or "Connection" in _searxng_error
        )
        if _searxng_unreachable:
            logger.warning("SearXNG unreachable (%s) — attempting recovery before DDG fallback", _searxng_error)
            try:
                from .searxng import ensure_searxng_running

                recovered = await asyncio.wait_for(
                    ensure_searxng_running(),
                    timeout=60.0
                )
            except asyncio.TimeoutError:
                logger.error("SearXNG recovery timed out after 60s — using DDG fallback")
                recovered = False
            except Exception as _rec_err:
                logger.debug("SearXNG recovery attempt raised: %s", _rec_err)
                recovered = False
            if recovered:

                result = await _searxng_search(query, max_results, searxng_url, engines)
                if result.get("success"):
                    if effective_cache:
                        _cache_results(query, max_results, result, engines)
                    return result

            logger.warning("SearXNG recovery unsuccessful — falling back to DuckDuckGo")
            ddg_result = await _ddg_search(query, max_results)
            ddg_result["result"] = (
                "[SearXNG unavailable — using DuckDuckGo fallback]\n\n"
                + ddg_result.get("result", "")
            )
            if ddg_result.get("success") and effective_cache:
                _cache_results(query, max_results, ddg_result, "")
            return ddg_result
        return result

    result = await _ddg_search(query, max_results)

    if result.get("success") and effective_cache:
        _cache_results(query, max_results, result, "")

    return result

def _get_cache_key(query: str, max_results: int, engines: str = "") -> str:
    return hashlib.md5(
        f"{query}:{max_results}:{engines}".encode(), usedforsecurity=False).hexdigest()

def _get_cached_results(query: str, max_results: int, engines: str = "") -> dict[str, Any] | None:
    try:
        cache_key = _get_cache_key(query, max_results, engines)
        import gzip
        cache_file = _CACHE_DIR / f"{cache_key}.json.gz"

        if not cache_file.exists():
            return None

        if time.time() - cache_file.stat().st_mtime > _CACHE_TTL:
            return None

        with gzip.open(cache_file, "rt") as f:
            return json.load(f)
    except Exception as e:
        logger.debug(f"Cache read failed: {e}")
        return None

def _cache_results(query: str, max_results: int, results: dict[str, Any], engines: str = "") -> None:
    try:
        import gzip
        _CACHE_DIR.mkdir(parents=True, exist_ok=True)
        cache_key = _get_cache_key(query, max_results, engines)
        cache_file = _CACHE_DIR / f"{cache_key}.json.gz"

        with gzip.open(cache_file, "wt") as f:
            json.dump(results, f)
    except Exception as e:
        logger.debug(f"Cache write failed: {e}")

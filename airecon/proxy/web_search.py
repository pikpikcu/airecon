"""Web search tool using DuckDuckGo."""

from __future__ import annotations

import asyncio
import logging
from typing import Any

logger = logging.getLogger("airecon.web_search")


async def web_search(query: str, max_results: int = 5) -> dict[str, Any]:
    """Search the web using DuckDuckGo and return formatted results.

    Args:
        query: Search query string.
        max_results: Maximum number of results to return (default 5, max 10).

    Returns:
        dict with 'success' bool and 'result' string (formatted results).
    """
    try:
        from duckduckgo_search import DDGS

        max_results = min(int(max_results), 10)

        def _search() -> list[dict[str, Any]]:
            with DDGS() as ddgs:
                return list(ddgs.text(query, max_results=max_results))

        results = await asyncio.to_thread(_search)

        if not results:
            return {"success": True, "result": f"No results found for: {query}"}

        lines: list[str] = []
        for i, r in enumerate(results, 1):
            title = r.get("title", "No title")
            href = r.get("href", "")
            body = r.get("body", "")
            lines.append(f"{i}. **{title}**\n   URL: {href}\n   {body}")

        return {"success": True, "result": "\n\n".join(lines)}

    except ImportError:
        return {
            "success": False,
            "error": "duckduckgo-search package not installed. Run: pip install duckduckgo-search",
        }
    except Exception as e:
        logger.error(f"Web search error for query '{query}': {e}")
        return {"success": False, "error": str(e)}

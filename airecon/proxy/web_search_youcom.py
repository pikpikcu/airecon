"""Optional keyless You.com web search (MCP free profile).

Used by ``web_search`` only when ``youcom_search`` is enabled in
``~/.airecon/config.yaml`` (off by default). No API key is required —
the free MCP profile provides search without any credentials.
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

logger = logging.getLogger("airecon.web_search_youcom")

DEFAULT_YOUCOM_URL = "https://api.you.com/mcp?profile=free"

_HEADERS = {
    "Content-Type": "application/json",
    "Accept": "application/json, text/event-stream",
}


def _parse_sse(text: str) -> dict[str, Any] | None:
    """Extract the first JSON-RPC result object from an SSE response body."""
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("data:"):
            continue
        payload = line[len("data:"):].strip()
        if not payload:
            continue
        try:
            obj = json.loads(payload)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict) and "result" in obj:
            return obj
    return None


def _snippet(item: dict[str, Any]) -> str:
    """Best-effort snippet: first snippet/highlight, else the description."""
    snippets: list[Any] = item.get("snippets") or []
    if not snippets:
        contents = item.get("contents")
        if isinstance(contents, dict):
            highlights = contents.get("highlights")
            if isinstance(highlights, list):
                snippets = highlights
    snippet = snippets[0] if snippets else item.get("description", "")
    snippet = (snippet or item.get("description", "") or "No description").strip()
    if len(snippet) > 300:
        snippet = snippet[:297] + "..."
    return snippet


def format_results(web: list[dict[str, Any]]) -> str:
    """Render You.com web items in the same layout as the DDG/SearXNG paths."""
    lines: list[str] = []
    for i, r in enumerate(web, 1):
        title = r.get("title", "No title")
        href = r.get("url", "")
        lines.append(f"{i}. [youcom] **{title}**\n   URL: {href}\n   {_snippet(r)}")
    return "\n\n".join(lines)


async def youcom_search(
    query: str,
    max_results: int,
    url: str = DEFAULT_YOUCOM_URL,
) -> dict[str, Any]:
    """Query the keyless You.com MCP free profile and format the results.

    Returns the same ``{"success": ..., "result"/"error": ...}`` contract as
    the SearXNG and DuckDuckGo paths; never raises.
    """
    import aiohttp

    headers = dict(_HEADERS)

    async def _post(session, payload: dict[str, Any]) -> tuple[str, str]:
        async with session.post(
            url, json=payload, headers=headers, timeout=aiohttp.ClientTimeout(total=30)
        ) as resp:
            if resp.status not in (200, 202):
                return "", f"You.com MCP returned HTTP {resp.status}"
            return await resp.text(), ""

    try:
        async with aiohttp.ClientSession() as session:
            body, err = await _post(
                session,
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2025-03-26",
                        "capabilities": {},
                        "clientInfo": {"name": "airecon", "version": "1.0"},
                    },
                },
            )
            if err:
                return {"success": False, "error": err}
            init = _parse_sse(body)
            if init is None:
                return {
                    "success": False,
                    "error": "You.com MCP did not return an initialize result.",
                }

            # Best-effort session-id passthrough (free profile is stateless).
            session_id = init["result"].get("_meta", {}).get("session_id")
            if session_id:
                headers["Mcp-Session-Id"] = str(session_id)

            await _post(
                session, {"jsonrpc": "2.0", "method": "notifications/initialized"}
            )

            body, err = await _post(
                session,
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {
                        "name": "you-search",
                        "arguments": {"query": query, "count": max_results},
                    },
                },
            )
            if err:
                return {"success": False, "error": err}
            response = _parse_sse(body)
            if response is None:
                return {
                    "success": False,
                    "error": "You.com MCP did not return a you-search result.",
                }
            result_blocks = response["result"].get("content", [])
            if not result_blocks or result_blocks[0].get("type") != "text":
                return {
                    "success": False,
                    "error": "You.com MCP returned an unexpected content payload.",
                }
            data = json.loads(result_blocks[0]["text"])
            web = data.get("results", {}).get("web", [])[:max_results]
    except asyncio.TimeoutError:
        return {"success": False, "error": "You.com request timed out."}
    except aiohttp.ClientConnectorError as e:
        return {"success": False, "error": f"Cannot connect to You.com MCP: {e}"}
    except (json.JSONDecodeError, KeyError, TypeError) as e:
        return {"success": False, "error": f"Unexpected You.com response shape: {e}"}

    if not web:
        return {"success": True, "result": f"No results found for: {query}"}

    return {"success": True, "result": format_results(web)}

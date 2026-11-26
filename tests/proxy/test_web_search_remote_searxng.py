"""web_search with a remote searxng_url must not start or recover the local container."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from airecon.proxy import web_search as ws

OK = {"success": True, "result": "1. [specstream] **Title**\n   URL: https://example.com\n   body"}
DOWN = {"success": False, "error": "Cannot connect to SearXNG at https://search.example: refused"}


def _cfg(url: str) -> SimpleNamespace:
    return SimpleNamespace(searxng_url=url, searxng_engines="google,bing")


def _manager(running: bool = False) -> MagicMock:
    mgr = MagicMock()
    mgr._is_running = AsyncMock(return_value=running)
    mgr.ensure_running = AsyncMock(return_value="http://localhost:8080")
    return mgr


@pytest.mark.parametrize(
    ("url", "local"),
    [
        ("http://localhost:8080", True),
        ("http://127.0.0.1:8888/", True),
        ("https://searx.example.org", False),
        ("https://api.specstream.ai/searxng/ss_key", False),
    ],
)
def test_is_local_searxng(url: str, local: bool) -> None:
    assert ws._is_local_searxng(url) is local


@pytest.mark.asyncio
async def test_remote_url_skips_container_autostart() -> None:
    mgr = _manager(running=False)
    search = AsyncMock(return_value=OK)
    with patch("airecon.proxy.config.get_config", return_value=_cfg("https://searx.example.org")), \
         patch("airecon.proxy.searxng.get_shared_manager", return_value=mgr), \
         patch.object(ws, "_searxng_search", search):
        result = await ws.web_search("xz backdoor", max_results=5, use_cache=False)

    assert result == OK
    mgr._is_running.assert_not_awaited()
    mgr.ensure_running.assert_not_awaited()
    search.assert_awaited_once_with("xz backdoor", 5, "https://searx.example.org", "google,bing")


@pytest.mark.asyncio
async def test_remote_url_unreachable_goes_to_ddg_without_recovery() -> None:
    recover = AsyncMock(return_value=True)
    ddg = AsyncMock(return_value={"success": True, "result": "1. [ddg] **T**"})
    with patch("airecon.proxy.config.get_config", return_value=_cfg("https://searx.example.org")), \
         patch("airecon.proxy.searxng.get_shared_manager", return_value=_manager()), \
         patch("airecon.proxy.searxng.ensure_searxng_running", recover), \
         patch.object(ws, "_searxng_search", AsyncMock(return_value=DOWN)), \
         patch.object(ws, "_ddg_search", ddg):
        result = await ws.web_search("xz backdoor", use_cache=False)

    recover.assert_not_awaited()
    ddg.assert_awaited_once()
    assert result["result"].startswith("[SearXNG unavailable")


@pytest.mark.asyncio
async def test_local_url_still_autostarts_container() -> None:
    mgr = _manager(running=False)
    with patch("airecon.proxy.config.get_config", return_value=_cfg("http://localhost:8080")), \
         patch("airecon.proxy.searxng.get_shared_manager", return_value=mgr), \
         patch.object(ws, "_searxng_search", AsyncMock(return_value=OK)):
        result = await ws.web_search("xz backdoor", use_cache=False)

    assert result == OK
    mgr.ensure_running.assert_awaited_once()

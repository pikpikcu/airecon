"""Regression test for the Ctrl+C -> 'yes' quit hang.

action_quit must: cancel the SSE stream worker before closing HTTP, bound the
network calls, and ALWAYS reach self.exit() even if a step stalls/raises.
"""

from __future__ import annotations

import asyncio
import types
from unittest.mock import MagicMock

import pytest

from airecon.tui.app import AIReconApp


def _stub():
    s = types.SimpleNamespace()
    s.exit = MagicMock()
    s._status_task = None
    s._copy_toast_task = None
    order: list[str] = []

    worker = MagicMock()
    worker.is_running = True
    worker.cancel = MagicMock(side_effect=lambda: order.append("cancel_worker"))
    s._chat_worker = worker

    http = MagicMock()

    async def _post(*a, **k):
        order.append("post_stop")

    async def _aclose(*a, **k):
        order.append("aclose")

    http.post = _post
    http.aclose = _aclose
    s._http = http
    s._order = order
    return s


@pytest.mark.asyncio
async def test_quit_cancels_worker_then_closes_and_exits():
    s = _stub()
    await AIReconApp.action_quit(s)
    # stream worker cancelled before HTTP is closed
    assert s._order.index("cancel_worker") < s._order.index("aclose")
    assert "post_stop" in s._order
    s.exit.assert_called_once()


@pytest.mark.asyncio
async def test_quit_still_exits_when_stop_post_hangs():
    s = _stub()

    async def _hang(*a, **k):
        await asyncio.sleep(60)  # simulate a stuck server

    s._http.post = _hang
    # Must not hang: bounded internally; whole call well under the sleep.
    await asyncio.wait_for(AIReconApp.action_quit(s), timeout=10)
    s.exit.assert_called_once()


@pytest.mark.asyncio
async def test_quit_still_exits_when_aclose_hangs():
    s = _stub()

    async def _hang(*a, **k):
        await asyncio.sleep(60)

    s._http.aclose = _hang
    await asyncio.wait_for(AIReconApp.action_quit(s), timeout=10)
    s.exit.assert_called_once()

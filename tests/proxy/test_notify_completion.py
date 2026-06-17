"""Tests for completion notification (webhook + workspace flag)."""

from __future__ import annotations

import json
import os
import tempfile

import pytest

from airecon.proxy import notify


@pytest.mark.asyncio
async def test_writes_flag_file(monkeypatch):
    ws = tempfile.mkdtemp()

    class _Cfg:
        notify_webhook_url = ""
        notify_completion_flag = True

    monkeypatch.setattr(notify, "get_config", lambda: _Cfg())
    monkeypatch.setattr(notify, "get_workspace_root", lambda: __import__("pathlib").Path(ws))

    await notify.notify_completion("acme.test", {"findings": 2, "iterations": 10})
    flag = os.path.join(ws, "acme.test", "COMPLETE.json")
    assert os.path.exists(flag)
    data = json.load(open(flag))
    assert data["event"] == "airecon.scan.complete"
    assert data["findings"] == 2


@pytest.mark.asyncio
async def test_no_flag_when_disabled(monkeypatch):
    ws = tempfile.mkdtemp()

    class _Cfg:
        notify_webhook_url = ""
        notify_completion_flag = False

    monkeypatch.setattr(notify, "get_config", lambda: _Cfg())
    monkeypatch.setattr(notify, "get_workspace_root", lambda: __import__("pathlib").Path(ws))
    await notify.notify_completion("acme.test", {"findings": 0})
    assert not os.path.exists(os.path.join(ws, "acme.test", "COMPLETE.json"))


@pytest.mark.asyncio
async def test_never_raises_on_bad_target(monkeypatch):
    class _Cfg:
        notify_webhook_url = ""
        notify_completion_flag = True

    monkeypatch.setattr(notify, "get_config", lambda: _Cfg())
    monkeypatch.setattr(notify, "get_workspace_root", lambda: __import__("pathlib").Path(tempfile.mkdtemp()))
    # Weird target must be sanitized, not crash.
    await notify.notify_completion("../../etc/passwd", {"findings": 0})

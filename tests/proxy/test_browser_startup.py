import asyncio
from concurrent.futures import TimeoutError as FutureTimeout
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from airecon.proxy import browser


@pytest.fixture
def browser_state(monkeypatch):
    state = browser._BrowserState()
    monkeypatch.setattr(browser, "_state", state)
    monkeypatch.setattr(browser, "get_config", lambda: SimpleNamespace(
        browser_connect_timeout_ms=3000, browser_action_timeout=120,
        browser_cdp_port=9222, browser_cdp_bind_address="127.0.0.1",
    ))
    return state


def test_startup_wait_covers_retry_and_fallback_budget(browser_state, monkeypatch):
    result = MagicMock()
    future = MagicMock()

    def wait(timeout):
        assert 63 <= timeout < 120
        browser_state.browser = result
        return result

    future.result.side_effect = wait

    def schedule(coroutine, loop):
        inner = coroutine.cr_frame.f_locals.get("fut")
        if inner is not None:
            inner.close()
        coroutine.close()
        return future

    browser_state.event_loop = MagicMock()
    monkeypatch.setattr(browser, "_ensure_event_loop", lambda: None)
    monkeypatch.setattr(browser.asyncio, "run_coroutine_threadsafe", schedule)
    assert browser._get_browser() is result


def test_startup_timeout_cancels_the_scheduled_initialization(browser_state, monkeypatch):
    future = MagicMock()
    future.result.side_effect = FutureTimeout()

    def schedule(coroutine, loop):
        inner = coroutine.cr_frame.f_locals.get("fut")
        if inner is not None:
            inner.close()
        coroutine.close()
        return future

    browser_state.event_loop = MagicMock()
    monkeypatch.setattr(browser, "_ensure_event_loop", lambda: None)
    monkeypatch.setattr(browser.asyncio, "run_coroutine_threadsafe", schedule)
    with pytest.raises(RuntimeError, match="startup timed out"):
        browser._get_browser()
    future.cancel.assert_called_once()


@pytest.mark.asyncio
async def test_cancelled_browser_creation_stops_the_driver(browser_state, monkeypatch):
    entered = asyncio.Event()
    playwright = SimpleNamespace(chromium=SimpleNamespace(), stop=AsyncMock())

    async def connect(*args, **kwargs):
        entered.set()
        await asyncio.Future()

    playwright.chromium.connect_over_cdp = connect
    monkeypatch.setattr(browser, "async_playwright", lambda: SimpleNamespace(start=AsyncMock(return_value=playwright)))
    task = asyncio.create_task(browser._create_browser())
    await asyncio.wait_for(entered.wait(), timeout=1)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    playwright.stop.assert_awaited_once()
    assert browser_state.playwright is None and browser_state.browser is None


@pytest.mark.asyncio
@pytest.mark.parametrize("cancel", [False, True])
async def test_docker_chromium_start_reaps_exec_on_timeout_or_cancel(browser_state, monkeypatch, cancel):
    import sys

    original_create = asyncio.create_subprocess_exec
    original_wait = asyncio.wait_for
    created = asyncio.Event()
    processes = []

    async def create(*args, **kwargs):
        process = await original_create(sys.executable, "-c", "import time; time.sleep(60)", **kwargs)
        processes.append(process)
        created.set()
        return process

    async def bounded(awaitable, timeout):
        return await original_wait(awaitable, timeout=0.02 if timeout == 5.0 else timeout)

    monkeypatch.setattr(browser.asyncio, "create_subprocess_exec", create)
    monkeypatch.setattr(browser.asyncio, "wait_for", bounded)
    try:
        task = asyncio.create_task(browser._start_docker_chromium())
        await original_wait(created.wait(), timeout=2)
        if cancel:
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
        else:
            assert await task is False
        assert processes[0].returncode is not None
    finally:
        for process in processes:
            if process.returncode is None:
                process.kill()
                await process.wait()


def test_overlapping_startups_share_the_same_failure(browser_state, monkeypatch):
    import threading
    from concurrent.futures import ThreadPoolExecutor

    entered = threading.Event()
    both_waiting = threading.Event()
    release = threading.Event()
    count = 0
    count_lock = threading.Lock()

    class Future:
        def result(self, timeout):
            nonlocal count
            with count_lock:
                count += 1
                if count == 2:
                    both_waiting.set()
            entered.set()
            assert release.wait(2)
            raise FutureTimeout()

        def cancel(self):
            return True

        def done(self):
            return False

    scheduled = []

    def schedule(coroutine, loop):
        inner = coroutine.cr_frame.f_locals.get("fut")
        if inner is not None:
            inner.close()
        coroutine.close()
        scheduled.append(True)
        return Future()

    browser_state.event_loop = MagicMock()
    monkeypatch.setattr(browser, "_ensure_event_loop", lambda: None)
    monkeypatch.setattr(browser.asyncio, "run_coroutine_threadsafe", schedule)
    with ThreadPoolExecutor(max_workers=2) as workers:
        first = workers.submit(browser._get_browser)
        assert entered.wait(1)
        second = workers.submit(browser._get_browser)
        try:
            assert both_waiting.wait(0.25)
        finally:
            release.set()
        for future in (first, second):
            with pytest.raises(RuntimeError):
                future.result(timeout=2)
    assert len(scheduled) == 1

import pytest
from unittest.mock import AsyncMock, MagicMock
from airecon.proxy.browser import BrowserInstance, _generate_totp, browser_action


def test_generate_totp():
    # standard generation with sample secret
    secret = "JBSWY3DPEHPK3PXP"  # Base32 for "Hello!\xDE\xAD\xBE\xEF"
    code = _generate_totp(secret)
    assert len(code) == 6
    assert code.isdigit()


@pytest.fixture
def browser():
    b = BrowserInstance()
    # Mock internal async loops
    b._loop = AsyncMock()
    # Instead of threadsafe launching, pretend run_async resolves instantly

    async def mock_run_async(coro):
        return await coro

    b._run_async = mock_run_async
    return b


class SyncMock:
    """Mock that returns sync results (not async) for Playwright Page."""

    def __init__(self):
        # Use MagicMock for sync operations
        self._mock = MagicMock()

    def __getattr__(self, name):
        # Return MagicMock for all attributes (sync)
        attr = getattr(self._mock, name)
        if name in ("on", "remove_event_listener"):
            # These should be sync and return None
            return lambda *args, **kwargs: None
        return attr

    def __setattr__(self, name, value):
        if name.startswith("_mock"):
            super().__setattr__(name, value)
        else:
            setattr(self._mock, name, value)


@pytest.mark.asyncio
async def test_view_source_truncation(browser, mocker):
    # Setup mock page
    mock_page = MagicMock()
    mock_page.content = AsyncMock(return_value="<html>test</html>")

    # Create very long source code
    long_source = "<html>" + ("A" * 30000) + "</html>"
    mock_page.content = AsyncMock(return_value=long_source)

    browser.pages = {"tab_1": mock_page}

    # Mock getting the state to just return our injected components
    async def mock_state(*args):
        return {}

    mocker.patch.object(browser, "_get_page_state", new=mock_state)

    state = await browser._view_source("tab_1")

    assert "page_source" in state
    assert len(state["page_source"]) < len(long_source)
    assert "TRUNCATED" in state["page_source"]
    assert len(state["full_page_source"]) == len(long_source)


@pytest.mark.asyncio
async def test_tab_management(browser, mocker):
    # mock context entirely
    mock_context = AsyncMock()
    browser.context = mock_context

    mock_page_1 = AsyncMock()
    mock_page_2 = AsyncMock()

    # new_tab execution mock setup
    mock_context.new_page = AsyncMock(side_effect=[mock_page_1, mock_page_2])

    # Make on(), remove_event_listener() return None (sync)
    # and goto return None (sync)
    mock_page_1.on = lambda *args, **kwargs: None
    mock_page_1.remove_event_listener = lambda *args, **kwargs: None
    mock_page_1.goto = AsyncMock(return_value=None)
    mock_page_1.content = AsyncMock(return_value="<html>test</html>")

    mock_page_2.on = lambda *args, **kwargs: None
    mock_page_2.remove_event_listener = lambda *args, **kwargs: None
    mock_page_2.goto = AsyncMock(return_value=None)
    mock_page_2.content = AsyncMock(return_value="<html>test</html>")

    async def mock_state(tab_id):
        return {"tab_id": tab_id}

    mocker.patch.object(browser, "_get_page_state", new=mock_state)
    mocker.patch.object(browser, "_setup_console_logging", new_callable=AsyncMock)

    # Open tab 1
    state1 = await browser._new_tab("http://1.com")
    assert state1["tab_id"] == "tab_1"
    assert "tab_1" in browser.pages

    # Open tab 2
    state2 = await browser._new_tab("http://2.com")
    assert state2["tab_id"] == "tab_2"
    assert browser.current_page_id == "tab_2"

    # Switch tab back
    await browser._switch_tab("tab_1")
    assert browser.current_page_id == "tab_1"

    # Close tab 2
    await browser._close_tab("tab_2")
    assert "tab_2" not in browser.pages

    # Disallow closing last tab
    with pytest.raises(ValueError, match="Cannot close the last tab"):
        await browser._close_tab("tab_1")


@pytest.mark.asyncio
async def test_execute_js_parallel(browser, mocker):
    mock_page_1 = MagicMock()
    mock_page_1.evaluate = AsyncMock(return_value="Result 1")
    mock_page_1.is_closed = mocker.MagicMock(return_value=False)

    mock_page_2 = MagicMock()
    mock_page_2.evaluate = AsyncMock(side_effect=Exception("JS Error"))
    mock_page_2.is_closed = mocker.MagicMock(return_value=False)

    browser.pages = {"tab_1": mock_page_1, "tab_2": mock_page_2}

    async def mock_state(tab_id):
        return {}

    mocker.patch.object(browser, "_get_page_state", new=mock_state)

    state = await browser._execute_js("console.log()", parallel=True)

    res = state["js_result"]
    assert "Result 1" in str(res)
    assert "'error': 'JS Error'" in str(res)


@pytest.mark.asyncio
async def test_execute_js_parallel_skips_closed_tab_ids_in_result_mapping(
    browser, mocker
):
    mock_closed_page = MagicMock()
    mock_closed_page.is_closed = mocker.MagicMock(return_value=True)

    mock_open_page = MagicMock()
    mock_open_page.evaluate = AsyncMock(return_value="Open Result")
    mock_open_page.is_closed = mocker.MagicMock(return_value=False)
    mock_open_page.url = "https://open.example"

    browser.pages = {"tab_closed": mock_closed_page, "tab_open": mock_open_page}
    browser.current_page_id = "tab_open"

    async def mock_state(tab_id):
        return {"tab_id": tab_id}

    mocker.patch.object(browser, "_get_page_state", new=mock_state)

    state = await browser._execute_js("1+1", parallel=True)
    parallel_results = state["js_result"]["parallel_results"]

    assert "tab_open" in parallel_results
    assert parallel_results["tab_open"]["result"] == "Open Result"
    assert "tab_closed" not in parallel_results


def test_browser_action_execute_js_parallel_contract(mocker):
    execute_js = mocker.patch(
        "airecon.proxy.browser._manager.execute_js",
        return_value={"ok": True, "message": "parallel ok"},
    )

    result = browser_action(
        action="execute_js",
        js_code="return document.title",
        parallel=True,
    )

    execute_js.assert_called_once_with("return document.title", None, parallel=True)
    assert result["ok"] is True


def test_solve_captcha_schedules_bypass_on_browser_loop(monkeypatch):
    from airecon.proxy.browser import BrowserTabManager

    instance = BrowserTabManager()
    page = MagicMock()

    async def screenshot(**kwargs):
        return b"png"

    async def content():
        return "<html></html>"

    async def evaluate(js):
        return {"success": True, "js": js}

    page.screenshot = screenshot
    page.content = content
    page.evaluate = evaluate
    launched = MagicMock()
    launched.current_page_id = "tab1"
    launched.pages = {"tab1": page}
    launched._loop = object()
    instance._ensure_launched = MagicMock(return_value=launched)

    async def solve_from_page(**kwargs):
        return {"bypass_js": "return 1", "success": False}

    solver = MagicMock()
    solver.timeout = 1
    solver.solve_from_page = solve_from_page
    monkeypatch.setattr(
        "airecon.proxy.browser.get_config",
        lambda: MagicMock(
            openai_base_url="http://fixture.invalid",
            openai_model="fixture",
            openai_api_key="",
            llm_timeout=1,
        ),
    )
    monkeypatch.setattr(
        "airecon.proxy.agent.captcha_solver.CaptchaSolver",
        lambda **kwargs: solver,
    )
    scheduled = []

    def fake_threadsafe(coro, loop):
        scheduled.append(getattr(getattr(coro, "cr_code", None), "co_name", ""))
        fut = MagicMock()
        name = scheduled[-1]
        if name == "screenshot":
            fut.result.return_value = b"png"
        elif name == "content":
            fut.result.return_value = "<html></html>"
        elif name == "evaluate":
            fut.result.return_value = {"success": True}
        else:
            fut.result.return_value = {"bypass_js": "return 1", "success": False}
        coro.close()
        return fut

    monkeypatch.setattr("asyncio.run_coroutine_threadsafe", fake_threadsafe)
    result = instance.solve_captcha("fixture")
    assert "evaluate" in scheduled
    assert result.get("success") is True
    assert "solved" in result.get("message", "")

import asyncio
import base64
import contextlib
import logging
import threading
from pathlib import Path
from typing import Any, cast, Literal, NoReturn
import atexit

from playwright.async_api import Browser, BrowserContext, Page, Playwright, async_playwright
from .config import get_workspace_root, get_config

logger = logging.getLogger("airecon.proxy.browser")

MAX_PAGE_SOURCE_LENGTH = 20_000
MAX_CONSOLE_LOG_LENGTH = 30_000
MAX_INDIVIDUAL_LOG_LENGTH = 1_000
MAX_CONSOLE_LOGS_COUNT = 200
MAX_JS_RESULT_LENGTH = 5_000

# Type definitions
BrowserAction = Literal[
    "launch", "goto", "click", "type", "scroll_down", "scroll_up",
    "back", "forward", "new_tab", "switch_tab", "close_tab",
    "wait", "execute_js", "double_click", "hover", "press_key",
    "save_pdf", "get_console_logs", "view_source", "close", "list_tabs"
]

class _BrowserState:
    """Singleton state for the shared browser instance."""
    lock = threading.Lock()
    event_loop: asyncio.AbstractEventLoop | None = None
    event_loop_thread: threading.Thread | None = None
    playwright: Playwright | None = None
    browser: Browser | None = None

_state = _BrowserState()

def _ensure_event_loop() -> None:
    if _state.event_loop is not None:
        return

    def run_loop() -> None:
        _state.event_loop = asyncio.new_event_loop()
        asyncio.set_event_loop(_state.event_loop)
        _state.event_loop.run_forever()

    _state.event_loop_thread = threading.Thread(target=run_loop, daemon=True)
    _state.event_loop_thread.start()

    while _state.event_loop is None:
        threading.Event().wait(0.01)

async def _create_browser() -> Browser:
    if _state.browser is not None and _state.browser.is_connected():
        return _state.browser

    if _state.browser is not None:
        with contextlib.suppress(Exception):
            await _state.browser.close()
        _state.browser = None
    if _state.playwright is not None:
        with contextlib.suppress(Exception):
            await _state.playwright.stop()
        _state.playwright = None

    _state.playwright = await async_playwright().start()
    
    # Connect to the Chromium CDP server running inside the Docker sandbox
    try:
        _state.browser = await _state.playwright.chromium.connect_over_cdp("http://localhost:9222")
    except Exception as e:
        logger.error(f"Failed to connect to Docker CDP server. Is the sandbox running? Error: {e}")
        # Cleanup if connection fails
        if _state.playwright is not None:
            await _state.playwright.stop()
            _state.playwright = None
        raise RuntimeError(f"Could not connect to browser in Docker Sandbox: {e}")
        
    return _state.browser

def _get_browser() -> tuple[asyncio.AbstractEventLoop, Browser]:
    with _state.lock:
        _ensure_event_loop()
        assert _state.event_loop is not None

        if _state.browser is None or not _state.browser.is_connected():
            future = asyncio.run_coroutine_threadsafe(_create_browser(), _state.event_loop)
            future.result(timeout=30)

        assert _state.browser is not None
        return _state.event_loop, _state.browser

class BrowserInstance:
    def __init__(self) -> None:
        self.is_running = True
        self._execution_lock = threading.Lock()
        self._loop: asyncio.AbstractEventLoop | None = None
        self._browser: Browser | None = None
        self.context: BrowserContext | None = None
        self.pages: dict[str, Page] = {}
        self.current_page_id: str | None = None
        self._next_tab_id = 1
        self.console_logs: dict[str, list[dict[str, Any]]] = {}

    def _run_async(self, coro: Any) -> dict[str, Any]:
        if not self._loop or not self.is_running:
            raise RuntimeError("Browser instance is not running")
        future = asyncio.run_coroutine_threadsafe(coro, self._loop)
        return cast("dict[str, Any]", future.result(timeout=30))

    async def _setup_console_logging(self, page: Page, tab_id: str) -> None:
        self.console_logs[tab_id] = []
        def handle_console(msg: Any) -> None:
            text = msg.text
            if len(text) > MAX_INDIVIDUAL_LOG_LENGTH:
                text = text[:MAX_INDIVIDUAL_LOG_LENGTH] + "... [TRUNCATED]"
            log_entry = {
                "type": msg.type,
                "text": text,
                "location": msg.location,
                "timestamp": asyncio.get_event_loop().time(),
            }
            self.console_logs[tab_id].append(log_entry)
            if len(self.console_logs[tab_id]) > MAX_CONSOLE_LOGS_COUNT:
                self.console_logs[tab_id] = self.console_logs[tab_id][-MAX_CONSOLE_LOGS_COUNT:]
        page.on("console", handle_console)

    async def _create_context(self, url: str | None = None) -> dict[str, Any]:
        assert self._browser is not None
        self.context = await self._browser.new_context(
            viewport={"width": 1280, "height": 720},
            user_agent="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        )
        page = await self.context.new_page()
        tab_id = f"tab_{self._next_tab_id}"
        self._next_tab_id += 1
        self.pages[tab_id] = page
        self.current_page_id = tab_id
        await self._setup_console_logging(page, tab_id)
        if url:
            await page.goto(url, wait_until="domcontentloaded")
        return await self._get_page_state(tab_id)

    async def _get_page_state(self, tab_id: str | None = None) -> dict[str, Any]:
        if not tab_id:
            tab_id = self.current_page_id
        if not tab_id or tab_id not in self.pages:
            raise ValueError(f"Tab '{tab_id}' not found")
        page = self.pages[tab_id]
        delay = get_config().browser_page_load_delay
        await asyncio.sleep(delay)
        screenshot_bytes = await page.screenshot(type="png", full_page=False)
        screenshot_b64 = base64.b64encode(screenshot_bytes).decode("utf-8")
        url = page.url
        title = await page.title()
        viewport = page.viewport_size
        all_tabs = {}
        for tid, tab_page in self.pages.items():
            all_tabs[tid] = {
                "url": tab_page.url,
                "title": await tab_page.title() if not tab_page.is_closed() else "Closed",
            }
        return {
            "screenshot": screenshot_b64,
            "url": url,
            "title": title,
            "viewport": viewport,
            "tab_id": tab_id,
            "all_tabs": all_tabs,
        }

    def launch(self, url: str | None = None) -> dict[str, Any]:
        with self._execution_lock:
            if self.context is not None:
                raise ValueError("Browser is already launched")
            self._loop, self._browser = _get_browser()
            return self._run_async(self._create_context(url))

    def goto(self, url: str, tab_id: str | None = None) -> dict[str, Any]:
        with self._execution_lock:
            return self._run_async(self._goto(url, tab_id))

    async def _goto(self, url: str, tab_id: str | None = None) -> dict[str, Any]:
        if not tab_id: tab_id = self.current_page_id
        if not tab_id or tab_id not in self.pages: raise ValueError(f"Tab '{tab_id}' not found")
        page = self.pages[tab_id]
        await page.goto(url, wait_until="domcontentloaded")
        return await self._get_page_state(tab_id)

    def click(self, coordinate: str, tab_id: str | None = None) -> dict[str, Any]:
        with self._execution_lock: return self._run_async(self._click(coordinate, tab_id))

    async def _click(self, coordinate: str, tab_id: str | None = None) -> dict[str, Any]:
        if not tab_id: tab_id = self.current_page_id
        if not tab_id or tab_id not in self.pages: raise ValueError(f"Tab '{tab_id}' not found")
        try: x, y = map(int, coordinate.split(","))
        except ValueError as e: raise ValueError(f"Invalid coordinate format: {coordinate}. Use 'x,y'") from e
        page = self.pages[tab_id]
        await page.mouse.click(x, y)
        return await self._get_page_state(tab_id)

    def type_text(self, text: str, tab_id: str | None = None) -> dict[str, Any]:
        with self._execution_lock: return self._run_async(self._type_text(text, tab_id))

    async def _type_text(self, text: str, tab_id: str | None = None) -> dict[str, Any]:
        if not tab_id: tab_id = self.current_page_id
        if not tab_id or tab_id not in self.pages: raise ValueError(f"Tab '{tab_id}' not found")
        page = self.pages[tab_id]
        await page.keyboard.type(text)
        return await self._get_page_state(tab_id)

    def scroll(self, direction: str, tab_id: str | None = None) -> dict[str, Any]:
        with self._execution_lock: return self._run_async(self._scroll(direction, tab_id))

    async def _scroll(self, direction: str, tab_id: str | None = None) -> dict[str, Any]:
        if not tab_id: tab_id = self.current_page_id
        if not tab_id or tab_id not in self.pages: raise ValueError(f"Tab '{tab_id}' not found")
        page = self.pages[tab_id]
        if direction == "down": await page.keyboard.press("PageDown")
        elif direction == "up": await page.keyboard.press("PageUp")
        else: raise ValueError(f"Invalid scroll direction: {direction}")
        return await self._get_page_state(tab_id)

    def back(self, tab_id: str | None = None) -> dict[str, Any]:
        with self._execution_lock: return self._run_async(self._back(tab_id))

    async def _back(self, tab_id: str | None = None) -> dict[str, Any]:
        if not tab_id: tab_id = self.current_page_id
        if not tab_id or tab_id not in self.pages: raise ValueError(f"Tab '{tab_id}' not found")
        page = self.pages[tab_id]
        await page.go_back(wait_until="domcontentloaded")
        return await self._get_page_state(tab_id)

    def forward(self, tab_id: str | None = None) -> dict[str, Any]:
        with self._execution_lock: return self._run_async(self._forward(tab_id))

    async def _forward(self, tab_id: str | None = None) -> dict[str, Any]:
        if not tab_id: tab_id = self.current_page_id
        if not tab_id or tab_id not in self.pages: raise ValueError(f"Tab '{tab_id}' not found")
        page = self.pages[tab_id]
        await page.go_forward(wait_until="domcontentloaded")
        return await self._get_page_state(tab_id)

    def new_tab(self, url: str | None = None) -> dict[str, Any]:
        with self._execution_lock: return self._run_async(self._new_tab(url))

    async def _new_tab(self, url: str | None = None) -> dict[str, Any]:
        if not self.context: raise ValueError("Browser not launched")
        page = await self.context.new_page()
        tab_id = f"tab_{self._next_tab_id}"
        self._next_tab_id += 1
        self.pages[tab_id] = page
        self.current_page_id = tab_id
        await self._setup_console_logging(page, tab_id)
        if url: await page.goto(url, wait_until="domcontentloaded")
        return await self._get_page_state(tab_id)

    def switch_tab(self, tab_id: str) -> dict[str, Any]:
        with self._execution_lock: return self._run_async(self._switch_tab(tab_id))

    async def _switch_tab(self, tab_id: str) -> dict[str, Any]:
        if tab_id not in self.pages: raise ValueError(f"Tab '{tab_id}' not found")
        self.current_page_id = tab_id
        return await self._get_page_state(tab_id)

    def close_tab(self, tab_id: str) -> dict[str, Any]:
        with self._execution_lock: return self._run_async(self._close_tab(tab_id))

    async def _close_tab(self, tab_id: str) -> dict[str, Any]:
        if tab_id not in self.pages: raise ValueError(f"Tab '{tab_id}' not found")
        if len(self.pages) == 1: raise ValueError("Cannot close the last tab")
        page = self.pages.pop(tab_id)
        await page.close()
        if tab_id in self.console_logs: del self.console_logs[tab_id]
        if self.current_page_id == tab_id: self.current_page_id = next(iter(self.pages.keys()))
        return await self._get_page_state(self.current_page_id)

    def wait(self, duration: float, tab_id: str | None = None) -> dict[str, Any]:
        with self._execution_lock: return self._run_async(self._wait(duration, tab_id))

    async def _wait(self, duration: float, tab_id: str | None = None) -> dict[str, Any]:
        await asyncio.sleep(duration)
        return await self._get_page_state(tab_id)

    def execute_js(self, js_code: str, tab_id: str | None = None) -> dict[str, Any]:
        with self._execution_lock: return self._run_async(self._execute_js(js_code, tab_id))

    async def _execute_js(self, js_code: str, tab_id: str | None = None) -> dict[str, Any]:
        if not tab_id: tab_id = self.current_page_id
        if not tab_id or tab_id not in self.pages: raise ValueError(f"Tab '{tab_id}' not found")
        page = self.pages[tab_id]
        try: result = await page.evaluate(js_code)
        except Exception as e: result = {"error": True, "error_type": type(e).__name__, "error_message": str(e)}
        result_str = str(result)
        if len(result_str) > MAX_JS_RESULT_LENGTH: result = result_str[:MAX_JS_RESULT_LENGTH] + "... [JS result truncated]"
        state = await self._get_page_state(tab_id)
        state["js_result"] = result
        return state

    def get_console_logs(self, tab_id: str | None = None, clear: bool = False) -> dict[str, Any]:
        with self._execution_lock: return self._run_async(self._get_console_logs(tab_id, clear))

    async def _get_console_logs(self, tab_id: str | None = None, clear: bool = False) -> dict[str, Any]:
        if not tab_id: tab_id = self.current_page_id
        if not tab_id or tab_id not in self.pages: raise ValueError(f"Tab '{tab_id}' not found")
        logs = self.console_logs.get(tab_id, [])
        if len(str(logs)) > MAX_CONSOLE_LOG_LENGTH: logs = logs[-MAX_CONSOLE_LOGS_COUNT:] # Simple truncation
        if clear: self.console_logs[tab_id] = []
        state = await self._get_page_state(tab_id)
        state["console_logs"] = logs
        return state

    def view_source(self, tab_id: str | None = None) -> dict[str, Any]:
        with self._execution_lock: return self._run_async(self._view_source(tab_id))

    async def _view_source(self, tab_id: str | None = None) -> dict[str, Any]:
        if not tab_id: tab_id = self.current_page_id
        if not tab_id or tab_id not in self.pages: raise ValueError(f"Tab '{tab_id}' not found")
        page = self.pages[tab_id]
        source = await page.content()
        if len(source) > MAX_PAGE_SOURCE_LENGTH:
             source = source[:10000] + "\n... [TRUNCATED] ...\n" + source[-10000:]
        state = await self._get_page_state(tab_id)
        state["page_source"] = source
        return state

    def double_click(self, coordinate: str, tab_id: str | None = None) -> dict[str, Any]:
        with self._execution_lock: return self._run_async(self._double_click(coordinate, tab_id))

    async def _double_click(self, coordinate: str, tab_id: str | None = None) -> dict[str, Any]:
        if not tab_id: tab_id = self.current_page_id
        if not tab_id or tab_id not in self.pages: raise ValueError(f"Tab '{tab_id}' not found")
        try: x, y = map(int, coordinate.split(","))
        except ValueError as e: raise ValueError(f"Invalid coordinate format: {coordinate}. Use 'x,y'") from e
        page = self.pages[tab_id]
        await page.mouse.dblclick(x, y)
        return await self._get_page_state(tab_id)

    def hover(self, coordinate: str, tab_id: str | None = None) -> dict[str, Any]:
        with self._execution_lock: return self._run_async(self._hover(coordinate, tab_id))

    async def _hover(self, coordinate: str, tab_id: str | None = None) -> dict[str, Any]:
        if not tab_id: tab_id = self.current_page_id
        if not tab_id or tab_id not in self.pages: raise ValueError(f"Tab '{tab_id}' not found")
        try: x, y = map(int, coordinate.split(","))
        except ValueError as e: raise ValueError(f"Invalid coordinate format: {coordinate}. Use 'x,y'") from e
        page = self.pages[tab_id]
        await page.mouse.move(x, y)
        return await self._get_page_state(tab_id)

    def press_key(self, key: str, tab_id: str | None = None) -> dict[str, Any]:
        with self._execution_lock: return self._run_async(self._press_key(key, tab_id))

    async def _press_key(self, key: str, tab_id: str | None = None) -> dict[str, Any]:
        if not tab_id: tab_id = self.current_page_id
        if not tab_id or tab_id not in self.pages: raise ValueError(f"Tab '{tab_id}' not found")
        page = self.pages[tab_id]
        await page.keyboard.press(key)
        return await self._get_page_state(tab_id)

    def save_pdf(self, file_path: str, tab_id: str | None = None) -> dict[str, Any]:
        with self._execution_lock: return self._run_async(self._save_pdf(file_path, tab_id))

    async def _save_pdf(self, file_path: str, tab_id: str | None = None) -> dict[str, Any]:
        if not tab_id: tab_id = self.current_page_id
        if not tab_id or tab_id not in self.pages: raise ValueError(f"Tab '{tab_id}' not found")
        if not Path(file_path).is_absolute(): file_path = str(get_workspace_root() / file_path)
        page = self.pages[tab_id]
        await page.pdf(path=file_path)
        state = await self._get_page_state(tab_id)
        state["pdf_saved"] = file_path
        return state

    def list_tabs(self) -> dict[str, Any]:
        with self._execution_lock:
            tabs = {}
            for tid, page in self.pages.items():
                try:
                    url = page.url  # sync property in playwright-python
                except Exception:
                    url = "unknown"
                tabs[tid] = {"url": url}
            return {
                "tabs": tabs,
                "current_tab": self.current_page_id,
                "count": len(tabs),
            }

    def close(self) -> None:
        with self._execution_lock:
            self.is_running = False
            if self._loop and self.context:
                future = asyncio.run_coroutine_threadsafe(self._close_context(), self._loop)
                with contextlib.suppress(Exception): future.result(timeout=5)
            self.pages.clear()
            self.console_logs.clear()
            self.current_page_id = None
            self.context = None

    async def _close_context(self) -> None:
        try:
            if self.context: await self.context.close()
        except (OSError, RuntimeError) as e: logger.warning(f"Error closing context: {e}")

    def is_alive(self) -> bool:
        return self.is_running and self.context is not None and self._browser is not None and self._browser.is_connected()

# Singleton Manager
class BrowserTabManager:
    def __init__(self) -> None:
        self._browser: BrowserInstance | None = None
        self._lock = threading.Lock()
        atexit.register(self.close)

    def _get_browser(self) -> BrowserInstance:
        with self._lock:
            if self._browser is None or not self._browser.is_alive():
                self._browser = BrowserInstance()
            return self._browser

    def launch_browser(self, url: str | None = None) -> dict[str, Any]:
        browser = self._get_browser()
        try:
            result = browser.launch(url)
            result["message"] = "Browser launched successfully"
            return result
        except ValueError as e:
            if "already launched" in str(e):
                # Browser already running — navigate to URL if given, else return current state
                if url:
                    return self.goto_url(url)
                return {"message": "Browser already running", "success": True}
            raise

    def goto_url(self, url: str, tab_id: str | None = None) -> dict[str, Any]:
        result = self._get_browser().goto(url, tab_id)
        result["message"] = f"Navigated to {url}"
        return result

    def click(self, coordinate: str, tab_id: str | None = None) -> dict[str, Any]:
        result = self._get_browser().click(coordinate, tab_id)
        result["message"] = f"Clicked at {coordinate}"
        return result

    def type_text(self, text: str, tab_id: str | None = None) -> dict[str, Any]:
        result = self._get_browser().type_text(text, tab_id)
        result["message"] = f"Typed text"
        return result

    def scroll(self, direction: str, tab_id: str | None = None) -> dict[str, Any]:
        result = self._get_browser().scroll(direction, tab_id)
        result["message"] = f"Scrolled {direction}"
        return result

    def back(self, tab_id: str | None = None) -> dict[str, Any]:
        result = self._get_browser().back(tab_id)
        result["message"] = "Navigated back"
        return result

    def forward(self, tab_id: str | None = None) -> dict[str, Any]:
        result = self._get_browser().forward(tab_id)
        result["message"] = "Navigated forward"
        return result

    def new_tab(self, url: str | None = None) -> dict[str, Any]:
        result = self._get_browser().new_tab(url)
        result["message"] = f"Created new tab {result.get('tab_id', '')}"
        return result

    def switch_tab(self, tab_id: str) -> dict[str, Any]:
        result = self._get_browser().switch_tab(tab_id)
        result["message"] = f"Switched to tab {tab_id}"
        return result

    def close_tab(self, tab_id: str) -> dict[str, Any]:
        result = self._get_browser().close_tab(tab_id)
        result["message"] = f"Closed tab {tab_id}"
        return result

    def wait_browser(self, duration: float, tab_id: str | None = None) -> dict[str, Any]:
        result = self._get_browser().wait(duration, tab_id)
        result["message"] = f"Waited {duration}s"
        return result

    def execute_js(self, js_code: str, tab_id: str | None = None) -> dict[str, Any]:
        result = self._get_browser().execute_js(js_code, tab_id)
        result["message"] = "JavaScript executed successfully"
        return result

    def double_click(self, coordinate: str, tab_id: str | None = None) -> dict[str, Any]:
        result = self._get_browser().double_click(coordinate, tab_id)
        result["message"] = f"Double clicked at {coordinate}"
        return result

    def hover(self, coordinate: str, tab_id: str | None = None) -> dict[str, Any]:
        result = self._get_browser().hover(coordinate, tab_id)
        result["message"] = f"Hovered at {coordinate}"
        return result

    def press_key(self, key: str, tab_id: str | None = None) -> dict[str, Any]:
        result = self._get_browser().press_key(key, tab_id)
        result["message"] = f"Pressed key {key}"
        return result

    def save_pdf(self, file_path: str, tab_id: str | None = None) -> dict[str, Any]:
        result = self._get_browser().save_pdf(file_path, tab_id)
        result["message"] = f"Page saved as PDF: {file_path}"
        return result

    def get_console_logs(self, tab_id: str | None = None, clear: bool = False) -> dict[str, Any]:
        result = self._get_browser().get_console_logs(tab_id, clear)
        result["message"] = "Console logs retrieved"
        return result

    def view_source(self, tab_id: str | None = None) -> dict[str, Any]:
        result = self._get_browser().view_source(tab_id)
        result["message"] = "Page source retrieved"
        return result
    
    def list_tabs(self) -> dict[str, Any]:
        if not self._browser:
            return {"tabs": {}, "count": 0}
        return self._browser.list_tabs()

    def close(self) -> None:
        if self._browser:
            self._browser.close()
            self._browser = None

_manager = BrowserTabManager()

def browser_action(
    action: BrowserAction,
    url: str | None = None,
    coordinate: str | None = None,
    text: str | None = None,
    tab_id: str | None = None,
    js_code: str | None = None,
    duration: float | None = None,
    key: str | None = None,
    file_path: str | None = None,
    clear: bool = False,
) -> dict[str, Any]:
    try:
        if action == "launch": return _manager.launch_browser(url)
        elif action == "goto": return _manager.goto_url(url, tab_id)
        elif action == "click": return _manager.click(coordinate, tab_id)
        elif action == "type": return _manager.type_text(text, tab_id)
        elif action == "scroll_down": return _manager.scroll("down", tab_id)
        elif action == "scroll_up": return _manager.scroll("up", tab_id)
        elif action == "back": return _manager.back(tab_id)
        elif action == "forward": return _manager.forward(tab_id)
        elif action == "new_tab": return _manager.new_tab(url)
        elif action == "switch_tab": return _manager.switch_tab(tab_id)
        elif action == "close_tab": return _manager.close_tab(tab_id)
        elif action == "wait": return _manager.wait_browser(duration, tab_id)
        elif action == "execute_js": return _manager.execute_js(js_code, tab_id)
        elif action == "double_click": return _manager.double_click(coordinate, tab_id)
        elif action == "hover": return _manager.hover(coordinate, tab_id)
        elif action == "press_key": return _manager.press_key(key, tab_id)
        elif action == "save_pdf": return _manager.save_pdf(file_path, tab_id)
        elif action == "get_console_logs": return _manager.get_console_logs(tab_id, clear)
        elif action == "view_source": return _manager.view_source(tab_id)
        elif action == "close":
             _manager.close()
             return {"message": "Browser closed"}
        elif action == "list_tabs": return _manager.list_tabs()
        else: return {"error": f"Unknown action: {action}"}
    except Exception as e:
        logger.error(f"Browser action failed: {e}")
        return {"error": str(e)}

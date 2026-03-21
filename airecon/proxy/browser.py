import asyncio
import atexit
import base64
import contextlib
import hashlib
import hmac
import logging
import struct
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Literal, cast

from playwright.async_api import (
    Browser,
    BrowserContext,
    Page,
    Playwright,
    async_playwright,
)

from .config import get_config, get_workspace_root

logger = logging.getLogger("airecon.proxy.browser")

MAX_PAGE_SOURCE_LENGTH = 20_000
MAX_CONSOLE_LOG_LENGTH = 30_000
MAX_INDIVIDUAL_LOG_LENGTH = 1_000
MAX_CONSOLE_LOGS_COUNT = 200
MAX_JS_RESULT_LENGTH = 5_000
MAX_NETWORK_REQUESTS = 500
MAX_RESPONSE_BODY_LENGTH = 3_000

# Type definitions
BrowserAction = Literal[
    "launch", "goto", "click", "type", "scroll_down", "scroll_up",
    "back", "forward", "new_tab", "switch_tab", "close_tab",
    "wait", "execute_js", "double_click", "hover", "press_key",
    "save_pdf", "get_console_logs", "get_network_logs", "view_source", "close", "list_tabs",
    # Auth actions
    "login_form", "handle_totp", "save_auth_state", "inject_cookies", "oauth_authorize",
]


def _generate_totp(secret: str, period: int = 30, digits: int = 6) -> str:
    """Generate TOTP code per RFC 6238 (no external dependency)."""
    # Pad base32 secret to valid length
    padded = secret.upper().replace(" ", "")
    padding = (8 - len(padded) % 8) % 8
    padded += "=" * padding
    key = base64.b32decode(padded)
    counter = int(time.time()) // period
    msg = struct.pack(">Q", counter)
    h = hmac.new(key, msg, hashlib.sha1).digest()
    offset = h[-1] & 0x0F
    code = struct.unpack(">I", h[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(code % (10 ** digits)).zfill(digits)


class _BrowserState:
    """Singleton state for the shared browser instance."""
    lock = threading.Lock()
    event_loop: asyncio.AbstractEventLoop | None = None
    event_loop_thread: threading.Thread | None = None
    playwright: Playwright | None = None
    browser: Browser | None = None


_state = _BrowserState()


_event_loop_ready = threading.Event()


def _ensure_event_loop() -> None:
    if _state.event_loop is not None:
        return

    def run_loop() -> None:
        _state.event_loop = asyncio.new_event_loop()
        asyncio.set_event_loop(_state.event_loop)
        _event_loop_ready.set()
        _state.event_loop.run_forever()

    _state.event_loop_thread = threading.Thread(target=run_loop, daemon=True)
    _state.event_loop_thread.start()

    if not _event_loop_ready.wait(timeout=5.0):
        raise RuntimeError("Timeout waiting for generic event loop to start")


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

    # Try connecting to the Chromium CDP server inside Docker first
    retries = 3
    for attempt in range(retries):
        try:
            _state.browser = await _state.playwright.chromium.connect_over_cdp(
                "http://localhost:9222",
                timeout=3000,
            )
            return _state.browser
        except Exception as e:
            if attempt == retries - 1:
                logger.warning(
                    f"Could not connect to browser in Docker Sandbox after {retries} attempts. "
                    f"Falling back to local host browser. Error: {e}")
                try:
                    _state.browser = await _state.playwright.chromium.launch(
                        headless=True,
                        args=[
                            '--no-sandbox',
                            '--disable-setuid-sandbox',
                            # Allow TLS 1.0/1.1 and legacy ciphers on pentest targets
                            '--ignore-certificate-errors',  # nosec B501
                        ]
                    )
                    return _state.browser
                except Exception as e2:
                    if _state.playwright:
                        await _state.playwright.stop()
                        _state.playwright = None
                    raise RuntimeError(
                        f"Failed to launch both Docker and fallback browsers: {e2}")
            await asyncio.sleep(1)
            continue

    raise RuntimeError("Browser creation failed after retries")


def _get_browser() -> Browser:
    with _state.lock:
        _ensure_event_loop()
        if _state.event_loop is None:
            raise RuntimeError("Event loop not initialized")

        if _state.browser is None or not _state.browser.is_connected():
            future = asyncio.run_coroutine_threadsafe(
                _create_browser(), _state.event_loop)
            future.result(timeout=30)

        if _state.browser is None:
            raise RuntimeError("Browser failed to initialize")
        return _state.browser


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
        self.network_requests: dict[str, list[dict[str, Any]]] = {}

    def _run_async(self, coro: Any) -> dict[str, Any]:
        if not self._loop or not self.is_running:
            raise RuntimeError("Browser instance is not running")
        timeout = get_config().browser_action_timeout
        future = asyncio.run_coroutine_threadsafe(coro, self._loop)
        try:
            return cast("dict[str, Any]", future.result(timeout=timeout))
        except TimeoutError:
            future.cancel()
            raise RuntimeError(f"Browser action timed out after {timeout}s")

    def _resolve_tab_id(self, tab_id: str | None) -> str:
        """Resolve tab_id, falling back to current tab if given id not found."""
        if tab_id and tab_id in self.pages:
            return tab_id
        if tab_id and tab_id not in self.pages:
            logger.warning(
                f"Tab '{tab_id}' not found — falling back to current tab '{self.current_page_id}'")
        if self.current_page_id and self.current_page_id in self.pages:
            return self.current_page_id
        raise ValueError("No active browser tab available")

    async def _navigate_with_fallback(self, page: Any, url: str, timeout_ms: int = 60000) -> None:
        """Navigate to URL, falling back to wait_until='commit' on domcontentloaded timeout."""
        try:
            await page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
        except Exception as e:
            if "timeout" in str(e).lower():
                logger.warning(
                    f"domcontentloaded timed out for {url!r}, retrying with wait_until='commit'")
                await page.goto(url, wait_until="commit", timeout=timeout_ms)
            else:
                raise

    async def _setup_console_logging(self, page: Page, tab_id: str) -> None:
        self.console_logs[tab_id] = []
        self.network_requests[tab_id] = []

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

        # Network request capture
        def handle_request(request: Any) -> None:
            reqs = self.network_requests.get(tab_id, [])
            if len(reqs) >= MAX_NETWORK_REQUESTS:
                return
            post_data = None
            try:
                post_data = request.post_data
            except Exception:  # nosec B110 - post_data access is optional
                pass
            reqs.append({
                "type": "request",
                "url": request.url,
                "method": request.method,
                "resource_type": request.resource_type,
                "headers": dict(request.headers),
                "post_data": post_data,
            })
        page.on("request", handle_request)

        async def handle_response(response: Any) -> None:
            reqs = self.network_requests.get(tab_id, [])
            if len(reqs) >= MAX_NETWORK_REQUESTS:
                return
            content_type = response.headers.get("content-type", "")
            body: str | None = None
            # Only capture text-based response bodies
            if any(t in content_type for t in (
                    "json", "text/plain", "javascript", "xml", "html")):
                try:
                    body = await response.text()
                    if body is not None and len(body) > MAX_RESPONSE_BODY_LENGTH:
                        body = body[:MAX_RESPONSE_BODY_LENGTH] + \
                            "... [TRUNCATED]"
                except Exception:
                    body = None
            reqs.append({
                "type": "response",
                "url": response.url,
                "status": response.status,
                "content_type": content_type,
                "headers": dict(response.headers),
                "body": body,
            })
        page.on("response", handle_response)

    async def _create_context(self, url: str | None = None, auth_cookies: list[dict] | None = None) -> dict[str, Any]:
        if self._browser is None:
            raise RuntimeError("Browser not initialized")
        self.context = await self._browser.new_context(
            viewport={"width": 1280, "height": 720},
            user_agent="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            ignore_https_errors=True,  # nosec B501 — intentional for pentest targets with expired/self-signed certs
        )

        # Restore authentication cookies if provided (from resumed session)
        if auth_cookies:
            try:
                await self.context.add_cookies(auth_cookies)  # type: ignore[arg-type]
                logger.info(
                    f"Restored {len(auth_cookies)} auth cookies from session")
            except Exception as e:
                logger.warning(f"Failed to restore auth cookies: {e}")

        page = await self.context.new_page()
        tab_id = f"tab_{self._next_tab_id}"
        self._next_tab_id += 1
        self.pages[tab_id] = page
        self.current_page_id = tab_id
        await self._setup_console_logging(page, tab_id)
        if url:
            await self._navigate_with_fallback(page, url)
        return await self._get_page_state(tab_id)

    async def _get_page_state(
            self, tab_id: str | None = None) -> dict[str, Any]:
        tab_id = self._resolve_tab_id(tab_id)
        page = self.pages[tab_id]
        delay = get_config().browser_page_load_delay
        await asyncio.sleep(delay)
        try:
            screenshot_bytes = await page.screenshot(type="png", full_page=False, timeout=5000)
            screenshot_b64 = base64.b64encode(screenshot_bytes).decode("utf-8")
        except Exception as e:
            logger.warning(f"Screenshot failed: {e}")
            screenshot_b64 = ""
        url = page.url
        title = await page.title()
        viewport = page.viewport_size

        # Extract text content for the LLM
        try:
            text_content = await page.evaluate("() => document.body ? document.body.innerText : ''")
            if len(text_content) > 3000:
                text_content = text_content[:3000] + \
                    "... [TRUNCATED, use execute_js or view_source for more]"
        except Exception:
            text_content = "Failed to extract text content"

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
            "text_content": text_content,
            "viewport": viewport,
            "tab_id": tab_id,
            "all_tabs": all_tabs,
        }

    def launch(self, url: str | None = None) -> dict[str, Any]:
        with self._execution_lock:
            if self.context is not None:
                raise ValueError("Browser is already launched")
            self._browser = _get_browser()
            self._loop = _state.event_loop
            return self._run_async(self._create_context(url))

    def goto(self, url: str, tab_id: str | None = None) -> dict[str, Any]:
        with self._execution_lock:
            return self._run_async(self._goto(url, tab_id))

    async def _goto(self, url: str, tab_id: str |
                    None = None) -> dict[str, Any]:
        tab_id = self._resolve_tab_id(tab_id)
        page = self.pages[tab_id]
        await self._navigate_with_fallback(page, url)
        return await self._get_page_state(tab_id)

    def click(self, coordinate: str, tab_id: str |
              None = None) -> dict[str, Any]:
        with self._execution_lock:
            return self._run_async(self._click(coordinate, tab_id))

    async def _click(self, coordinate: str, tab_id: str |
                     None = None) -> dict[str, Any]:
        tab_id = self._resolve_tab_id(tab_id)
        try:
            x, y = map(int, coordinate.split(","))
        except ValueError as e:
            raise ValueError(
                f"Invalid coordinate format: {coordinate}. Use 'x,y'") from e
        # Bounds validation to prevent clicks outside viewport.
        # The lower bound (0 <=) also covers negative coordinates.
        page = self.pages[tab_id]
        viewport = page.viewport_size or {"width": 1920, "height": 1080}
        max_x = viewport.get("width", 1920) * 2  # Allow scroll overflow
        max_y = viewport.get("height", 1080) * 2

        if not (0 <= x <= max_x and 0 <= y <= max_y):
            raise ValueError(
                f"Coordinates ({x}, {y}) out of bounds. "
                f"Max allowed: ({max_x}, {max_y}). "
                f"Current viewport: {viewport.get('width', 1920)}x{viewport.get('height', 1080)}"
            )
        await page.mouse.click(x, y)
        return await self._get_page_state(tab_id)

    def type_text(self, text: str, tab_id: str |
                  None = None) -> dict[str, Any]:
        with self._execution_lock:
            return self._run_async(self._type_text(text, tab_id))

    async def _type_text(self, text: str, tab_id: str |
                         None = None) -> dict[str, Any]:
        tab_id = self._resolve_tab_id(tab_id)
        page = self.pages[tab_id]
        await page.keyboard.type(text)
        return await self._get_page_state(tab_id)

    def scroll(self, direction: str, tab_id: str |
               None = None) -> dict[str, Any]:
        with self._execution_lock:
            return self._run_async(self._scroll(direction, tab_id))

    async def _scroll(self, direction: str, tab_id: str |
                      None = None) -> dict[str, Any]:
        tab_id = self._resolve_tab_id(tab_id)
        page = self.pages[tab_id]
        if direction == "down":
            await page.keyboard.press("PageDown")
        elif direction == "up":
            await page.keyboard.press("PageUp")
        else:
            raise ValueError(f"Invalid scroll direction: {direction}")
        return await self._get_page_state(tab_id)

    def back(self, tab_id: str | None = None) -> dict[str, Any]:
        with self._execution_lock:
            return self._run_async(self._back(tab_id))

    async def _back(self, tab_id: str | None = None) -> dict[str, Any]:
        tab_id = self._resolve_tab_id(tab_id)
        page = self.pages[tab_id]
        try:
            await page.go_back(wait_until="domcontentloaded", timeout=60000)
        except Exception as e:
            if "timeout" in str(e).lower():
                logger.warning("go_back domcontentloaded timed out, falling back to 'commit'")
                await page.go_back(wait_until="commit", timeout=60000)
            else:
                raise
        return await self._get_page_state(tab_id)

    def forward(self, tab_id: str | None = None) -> dict[str, Any]:
        with self._execution_lock:
            return self._run_async(self._forward(tab_id))

    async def _forward(self, tab_id: str | None = None) -> dict[str, Any]:
        tab_id = self._resolve_tab_id(tab_id)
        page = self.pages[tab_id]
        try:
            await page.go_forward(wait_until="domcontentloaded", timeout=60000)
        except Exception as e:
            if "timeout" in str(e).lower():
                logger.warning("go_forward domcontentloaded timed out, falling back to 'commit'")
                await page.go_forward(wait_until="commit", timeout=60000)
            else:
                raise
        return await self._get_page_state(tab_id)

    def new_tab(self, url: str | None = None) -> dict[str, Any]:
        with self._execution_lock:
            return self._run_async(self._new_tab(url))

    async def _new_tab(self, url: str | None = None) -> dict[str, Any]:
        if not self.context:
            raise ValueError("Browser not launched")
        page = await self.context.new_page()
        tab_id = f"tab_{self._next_tab_id}"
        self._next_tab_id += 1
        self.pages[tab_id] = page
        self.current_page_id = tab_id
        await self._setup_console_logging(page, tab_id)
        if url:
            await self._navigate_with_fallback(page, url)
        return await self._get_page_state(tab_id)

    def switch_tab(self, tab_id: str) -> dict[str, Any]:
        with self._execution_lock:
            return self._run_async(self._switch_tab(tab_id))

    async def _switch_tab(self, tab_id: str) -> dict[str, Any]:
        if tab_id not in self.pages:
            raise ValueError(f"Tab '{tab_id}' not found")
        self.current_page_id = tab_id
        return await self._get_page_state(tab_id)

    def close_tab(self, tab_id: str) -> dict[str, Any]:
        with self._execution_lock:
            return self._run_async(self._close_tab(tab_id))

    async def _close_tab(self, tab_id: str) -> dict[str, Any]:
        if tab_id not in self.pages:
            raise ValueError(f"Tab '{tab_id}' not found")
        if len(self.pages) == 1:
            raise ValueError("Cannot close the last tab")
        page = self.pages.pop(tab_id)
        await page.close()
        if tab_id in self.console_logs:
            del self.console_logs[tab_id]
        if tab_id in self.network_requests:
            del self.network_requests[tab_id]
        if self.current_page_id == tab_id:
            self.current_page_id = next(iter(self.pages.keys()))
        return await self._get_page_state(self.current_page_id)

    def wait(self, duration: float, tab_id: str |
             None = None) -> dict[str, Any]:
        with self._execution_lock:
            return self._run_async(self._wait(duration, tab_id))

    async def _wait(self, duration: float, tab_id: str |
                    None = None) -> dict[str, Any]:
        if duration is None or duration < 0:
            duration = 1.0
        await asyncio.sleep(duration)
        return await self._get_page_state(tab_id)

    def execute_js(self, js_code: str, tab_id: str |
                   None = None) -> dict[str, Any]:
        with self._execution_lock:
            return self._run_async(self._execute_js(js_code, tab_id))

    async def _execute_js(self, js_code: str, tab_id: str | None = None,
                          parallel: bool = False) -> dict[str, Any]:
        """Execute JavaScript code in a tab, optionally in parallel across all tabs."""
        if not js_code:
            raise ValueError("js_code is required for execute_js action")

        if not parallel:
            tab_id = self._resolve_tab_id(tab_id)
            page = self.pages[tab_id]
            try:
                result = await page.evaluate(js_code)
            except Exception as e:
                result = {
                    "error": True,
                    "error_type": type(e).__name__,
                    "error_message": str(e)}
        else:
            # Execute in all tabs concurrently
            tasks = []
            for tid, page in self.pages.items():
                if not page.is_closed():
                    tasks.append(self._execute_js_single(page, js_code, tid))
            results = await asyncio.gather(*tasks, return_exceptions=True)
            result = {
                "parallel_results": {
                    tid: res if not isinstance(res, Exception) else {
                        "error": str(res)}
                    for tid, res in zip(self.pages.keys(), results)
                }
            }
        result_str = str(result)
        if len(result_str) > MAX_JS_RESULT_LENGTH:
            result = result_str[:MAX_JS_RESULT_LENGTH] + \
                "... [JS result truncated]"
        state = await self._get_page_state(tab_id)
        state["js_result"] = result
        return state

    async def _execute_js_single(self, page: Any, js_code: str,
                                 tab_id: str) -> dict[str, Any]:
        """Execute JS in a single tab - helper for parallel execution."""
        try:
            result = await page.evaluate(js_code)
            return {
                "success": True,
                "result": str(result)[:MAX_JS_RESULT_LENGTH],
                "tab_id": tab_id,
                "url": page.url
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "tab_id": tab_id
            }

    def get_console_logs(self, tab_id: str | None = None,
                         clear: bool = False) -> dict[str, Any]:
        with self._execution_lock:
            return self._run_async(self._get_console_logs(tab_id, clear))

    async def _get_network_logs(
            self, tab_id: str | None = None, clear: bool = False) -> dict[str, Any]:
        tab_id = self._resolve_tab_id(tab_id)
        reqs = self.network_requests.get(tab_id, [])
        if clear:
            self.network_requests[tab_id] = []
        state = await self._get_page_state(tab_id)
        state["network_requests"] = reqs
        state["network_summary"] = {
            "total": len(reqs),
            "requests": sum(1 for r in reqs if r["type"] == "request"),
            "responses": sum(1 for r in reqs if r["type"] == "response"),
            "api_calls": [r["url"] for r in reqs if r["type"] == "request" and r.get("resource_type") in ("xhr", "fetch")],
        }
        return state

    def get_network_logs(self, tab_id: str | None = None,
                         clear: bool = False) -> dict[str, Any]:
        with self._execution_lock:
            return self._run_async(self._get_network_logs(tab_id, clear))

    async def _get_console_logs(
            self, tab_id: str | None = None, clear: bool = False) -> dict[str, Any]:
        tab_id = self._resolve_tab_id(tab_id)
        logs = self.console_logs.get(tab_id, [])
        if len(str(logs)) > MAX_CONSOLE_LOG_LENGTH:
            logs = logs[-MAX_CONSOLE_LOGS_COUNT:]  # Simple truncation
        if clear:
            self.console_logs[tab_id] = []
        state = await self._get_page_state(tab_id)
        state["console_logs"] = logs
        return state

    def view_source(self, tab_id: str | None = None) -> dict[str, Any]:
        with self._execution_lock:
            return self._run_async(self._view_source(tab_id))

    async def _view_source(self, tab_id: str | None = None) -> dict[str, Any]:
        tab_id = self._resolve_tab_id(tab_id)
        page = self.pages[tab_id]
        source = await page.content()
        full_source = source  # preserve full source for file saving
        if len(source) > MAX_PAGE_SOURCE_LENGTH:
            source = source[:10000] + \
                "\n... [TRUNCATED — full source in output/source_*.txt] ...\n" + \
                source[-10000:]
        state = await self._get_page_state(tab_id)
        state["page_source"] = source
        # used by executor for file saving, stripped before LLM context
        state["full_page_source"] = full_source
        return state

    def double_click(self, coordinate: str, tab_id: str |
                     None = None) -> dict[str, Any]:
        with self._execution_lock:
            return self._run_async(self._double_click(coordinate, tab_id))

    async def _double_click(self, coordinate: str,
                            tab_id: str | None = None) -> dict[str, Any]:
        tab_id = self._resolve_tab_id(tab_id)
        try:
            x, y = map(int, coordinate.split(","))
        except ValueError as e:
            raise ValueError(
                f"Invalid coordinate format: {coordinate}. Use 'x,y'") from e
        page = self.pages[tab_id]
        await page.mouse.dblclick(x, y)
        return await self._get_page_state(tab_id)

    def hover(self, coordinate: str, tab_id: str |
              None = None) -> dict[str, Any]:
        with self._execution_lock:
            return self._run_async(self._hover(coordinate, tab_id))

    async def _hover(self, coordinate: str, tab_id: str |
                     None = None) -> dict[str, Any]:
        tab_id = self._resolve_tab_id(tab_id)
        try:
            x, y = map(int, coordinate.split(","))
        except ValueError as e:
            raise ValueError(
                f"Invalid coordinate format: {coordinate}. Use 'x,y'") from e
        # Bounds validation to prevent hovers outside viewport.
        # The lower bound (0 <=) also covers negative coordinates.
        page = self.pages[tab_id]
        viewport = page.viewport_size or {"width": 1920, "height": 1080}
        max_x = viewport.get("width", 1920) * 2  # Allow scroll overflow
        max_y = viewport.get("height", 1080) * 2

        if not (0 <= x <= max_x and 0 <= y <= max_y):
            raise ValueError(
                f"Coordinates ({x}, {y}) out of bounds. "
                f"Max allowed: ({max_x}, {max_y}). "
                f"Current viewport: {viewport.get('width', 1920)}x{viewport.get('height', 1080)}"
            )
        await page.mouse.move(x, y)
        return await self._get_page_state(tab_id)

    def press_key(self, key: str, tab_id: str | None = None) -> dict[str, Any]:
        with self._execution_lock:
            return self._run_async(self._press_key(key, tab_id))

    async def _press_key(self, key: str, tab_id: str |
                         None = None) -> dict[str, Any]:
        tab_id = self._resolve_tab_id(tab_id)
        page = self.pages[tab_id]
        await page.keyboard.press(key)
        return await self._get_page_state(tab_id)

    def save_pdf(self, file_path: str, tab_id: str |
                 None = None) -> dict[str, Any]:
        with self._execution_lock:
            return self._run_async(self._save_pdf(file_path, tab_id))

    async def _save_pdf(self, file_path: str, tab_id: str |
                        None = None) -> dict[str, Any]:
        if not file_path:
            raise ValueError("file_path is required for save_pdf action")
        tab_id = self._resolve_tab_id(tab_id)
        if not Path(file_path).is_absolute():
            file_path = str(get_workspace_root() / file_path)
        page = self.pages[tab_id]
        await page.pdf(path=file_path)
        state = await self._get_page_state(tab_id)
        state["pdf_saved"] = file_path
        return state

    # ── Auth helpers ─────────────────────────────────────────────────────────

    def login_form(
        self,
        url: str,
        username: str,
        password: str,
        username_selector: str = 'input[type="email"],input[name="username"],input[name="email"],#username,#email',
        password_selector: str = 'input[type="password"]',  # nosec B107 - CSS selector, not a password
        submit_selector: str = 'button[type="submit"],input[type="submit"]',
        tab_id: str | None = None,
    ) -> dict[str, Any]:
        with self._execution_lock:
            return self._run_async(
                self._login_form(
                    url,
                    username,
                    password,
                    username_selector,
                    password_selector,
                    submit_selector,
                    tab_id)
            )

    async def _login_form(
        self,
        url: str,
        username: str,
        password: str,
        username_selector: str,
        password_selector: str,
        submit_selector: str,
        tab_id: str | None,
    ) -> dict[str, Any]:
        # Navigate first
        if not self.pages:
            await self._create_context(url)
            tab_id = self.current_page_id
        else:
            tab_id = self._resolve_tab_id(tab_id)
            await self._goto(url, tab_id)
        page = self.pages[tab_id]  # type: ignore[index]
        # Fill credentials using first matching selector
        username_filled = False
        for sel in username_selector.split(","):
            try:
                await page.fill(sel.strip(), username, timeout=3000)
                username_filled = True
                break
            except Exception:  # nosec B112 - try next selector
                continue
        if not username_filled:
            logger.warning(
                f"login_form: no username selector matched ({username_selector}). Auth may fail.")

        await asyncio.sleep(0.3)
        password_filled = False
        for sel in password_selector.split(","):
            try:
                await page.fill(sel.strip(), password, timeout=3000)
                password_filled = True
                break
            except Exception:  # nosec B112 - try next selector
                continue
        if not password_filled:
            logger.warning(
                f"login_form: no password selector matched ({password_selector}). Auth may fail.")
        await asyncio.sleep(0.3)
        # Submit
        submitted = False
        for sel in submit_selector.split(","):
            try:
                await page.click(sel.strip(), timeout=3000)
                submitted = True
                break
            except Exception:  # nosec B112 - try next selector
                continue
        if not submitted:
            await page.keyboard.press("Enter")
        try:
            await page.wait_for_load_state("domcontentloaded", timeout=10000)
        except Exception:  # nosec B110 - fallback to sleep
            await asyncio.sleep(2)
        state = await self._get_page_state(tab_id)  # type: ignore[arg-type]
        if self.context:
            state["auth_cookies"] = await self.context.cookies()
            state["auth_captured"] = True
        return state

    def handle_totp(
        self,
        totp_secret: str,
        field_selector: str = 'input[name="totp"],input[name="otp"],input[name="code"],input[placeholder*="code" i],input[placeholder*="OTP" i]',
        tab_id: str | None = None,
    ) -> dict[str, Any]:
        with self._execution_lock:
            return self._run_async(self._handle_totp(
                totp_secret, field_selector, tab_id))

    async def _handle_totp(
            self, totp_secret: str, field_selector: str, tab_id: str | None) -> dict[str, Any]:
        try:
            import pyotp  # type: ignore[import]
            code = pyotp.TOTP(totp_secret).now()
        except ImportError:
            code = _generate_totp(totp_secret)
        tab_id = self._resolve_tab_id(tab_id)
        page = self.pages[tab_id]
        for sel in field_selector.split(","):
            try:
                await page.fill(sel.strip(), code, timeout=3000)
                break
            except Exception:  # nosec B112 - try next selector
                continue
        await asyncio.sleep(0.3)
        submitted = False
        for sel in ('button[type="submit"]', 'input[type="submit"]'):
            try:
                await page.click(sel, timeout=3000)
                submitted = True
                break
            except Exception:  # nosec B112 - try next selector
                continue
        if not submitted:
            await page.keyboard.press("Enter")
        try:
            await page.wait_for_load_state("domcontentloaded", timeout=10000)
        except Exception:
            await asyncio.sleep(2)
        state = await self._get_page_state(tab_id)
        if self.context:
            state["auth_cookies"] = await self.context.cookies()
            state["auth_captured"] = True
        return state

    def save_auth_state(self) -> dict[str, Any]:
        with self._execution_lock:
            return self._run_async(self._save_auth_state())

    async def _save_auth_state(self) -> dict[str, Any]:
        if not self.context:
            raise ValueError("Browser not launched")
        cookies = await self.context.cookies()
        tab_id = self._resolve_tab_id(None)
        page = self.pages[tab_id]
        try:
            local_storage = await page.evaluate("() => Object.fromEntries(Object.entries(localStorage))")
        except Exception:
            local_storage = {}
        return {
            "auth_state": {
                "cookies": cookies,
                "local_storage": local_storage,
                "captured_at": datetime.now().isoformat(),
            },
            "cookie_count": len(cookies),
            "local_storage_keys": list(local_storage.keys()),
            "message": f"Captured {len(cookies)} cookies and {len(local_storage)} localStorage items",
        }

    def inject_cookies(
            self, cookies: list[dict[str, Any]], tab_id: str | None = None) -> dict[str, Any]:
        with self._execution_lock:
            return self._run_async(self._inject_cookies(cookies, tab_id))

    async def _inject_cookies(
            self, cookies: list[dict[str, Any]], tab_id: str | None) -> dict[str, Any]:
        if not self.context:
            raise ValueError("Browser not launched")
        await self.context.add_cookies(cookies)  # type: ignore[arg-type]
        state = await self._get_page_state(tab_id)
        state["injected_cookie_count"] = len(cookies)
        state["message"] = f"Injected {len(cookies)} cookies into browser context"
        return state

    def oauth_authorize(
        self,
        oauth_url: str,
        callback_prefix: str = "",
        tab_id: str | None = None,
    ) -> dict[str, Any]:
        with self._execution_lock:
            return self._run_async(self._oauth_authorize(
                oauth_url, callback_prefix, tab_id))

    async def _oauth_authorize(
            self, oauth_url: str, callback_prefix: str, tab_id: str | None) -> dict[str, Any]:
        if not self.pages:
            await self._create_context(oauth_url)
            tab_id = self.current_page_id
        else:
            tab_id = self._resolve_tab_id(tab_id)
            await self._goto(oauth_url, tab_id)
        page = self.pages[tab_id]  # type: ignore[index]
        captured_token: str | None = None
        captured_url: str | None = None
        try:
            if callback_prefix:
                await page.wait_for_url(f"{callback_prefix}**", timeout=15000)
            else:
                await page.wait_for_load_state("networkidle", timeout=15000)
            current_url = page.url
            if callback_prefix and current_url.startswith(callback_prefix):
                from urllib.parse import parse_qs, urlparse
                parsed = urlparse(current_url)
                params = parse_qs(parsed.query)
                frag = parse_qs(parsed.fragment)
                captured_token = (
                    params.get("code", [None])[0]
                    or params.get("access_token", [None])[0]
                    or frag.get("access_token", [None])[0]
                    or frag.get("code", [None])[0]
                )
                captured_url = current_url
        except Exception as e:
            logger.warning(f"OAuth wait timed out or failed: {e}")
        state = await self._get_page_state(tab_id)  # type: ignore[arg-type]
        if self.context:
            state["auth_cookies"] = await self.context.cookies()
        if captured_token:
            state["oauth_token"] = captured_token
        if captured_url:
            state["oauth_callback_url"] = captured_url
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
                future = asyncio.run_coroutine_threadsafe(
                    self._close_context(), self._loop)
                with contextlib.suppress(Exception):
                    future.result(timeout=5)
            self.pages.clear()
            self.console_logs.clear()
            self.network_requests.clear()
            self.current_page_id = None
            self.context = None

    async def _close_context(self) -> None:
        try:
            if self.context:
                await self.context.close()
        except (OSError, RuntimeError) as e:
            logger.warning(f"Error closing context: {e}")

    def is_alive(self) -> bool:
        return self.is_running and self.context is not None and self._browser is not None and self._browser.is_connected()

# Singleton Manager


class BrowserTabManager:
    MAX_TABS = 3  # Prevent Ollama from opening too many tabs

    def __init__(self) -> None:
        self._browser: BrowserInstance | None = None
        self._lock = threading.Lock()
        self._restart_count = 0
        atexit.register(self.close)

    def _get_browser(self) -> BrowserInstance:
        with self._lock:
            if self._browser is None or not self._browser.is_alive():
                if self._browser is not None:
                    logger.warning("Browser died — auto-restarting...")
                    self._restart_count += 1
                    try:
                        self._browser.close()
                    except Exception:  # nosec B110 - best-effort cleanup before restart
                        pass
                self._browser = BrowserInstance()
            return self._browser

    def _ensure_launched(self) -> BrowserInstance:
        """Get browser instance, auto-launching if context not yet initialized."""
        browser = self._get_browser()
        if browser.context is None:
            logger.info(
                "Browser not yet launched — auto-launching on first use")
            try:
                browser.launch()
            except ValueError as e:
                if "already launched" not in str(e):
                    raise RuntimeError(
                        f"Browser auto-launch failed: {e}") from e
        return browser

    def _safe_action(self, action_name: str, fn, *
                     args, **kwargs) -> dict[str, Any]:
        """Wrapper that catches all browser errors, auto-restarts on crash."""
        try:
            result = fn(*args, **kwargs)
            if not isinstance(result, dict):
                result = {"result": result}
            return result
        except Exception as e:
            error_str = str(e).lower()
            is_crash = any(k in error_str for k in (
                "target closed", "browser has been closed", "connection refused",
                "execution context was destroyed", "page crashed",
                "navigation failed", "session closed",
            ))
            if is_crash:
                # Atomically check and increment restart count under the lock
                # to prevent a race where two threads both pass the count < 5
                # check and both increment beyond the cap.
                with self._lock:
                    _can_restart = self._restart_count < 5
                    if _can_restart:
                        self._restart_count += 1
                    try:
                        if self._browser:
                            self._browser.close()
                    except Exception:  # nosec B110 - best-effort cleanup on crash
                        pass
                    self._browser = None
                if not _can_restart:
                    logger.error(
                        f"Browser action '{action_name}' failed (max restarts reached): {e}")
                    return {"error": f"Browser action failed: {e}"}
                logger.warning(
                    f"Browser crashed during '{action_name}': {e}. Auto-restarting...")
                # Retry once after restart with fresh browser
                try:
                    fresh = self._ensure_launched()
                    # Re-bind fn to the new instance by name lookup
                    method = getattr(fresh, fn.__name__, None)
                    if method is None:
                        return {
                            "error": f"Browser crashed and could not rebind method '{fn.__name__}' after restart"}
                    result = method(*args, **kwargs)
                    if not isinstance(result, dict):
                        result = {"result": result}
                    result["warning"] = "Browser was auto-restarted after crash"
                    return result
                except Exception as e2:
                    return {"error": f"Browser crashed and retry failed: {e2}"}
            else:
                logger.error(f"Browser action '{action_name}' failed (non-crash): {e}")
                return {"error": f"Browser action failed: {e}"}

    def launch_browser(self, url: str | None = None) -> dict[str, Any]:
        browser = self._get_browser()
        try:
            result = browser.launch(url)
            result["message"] = "Browser launched successfully"
            return result
        except ValueError as e:
            if "already launched" in str(e):
                if url:
                    return self.goto_url(url)
                return {"message": "Browser already running", "success": True}
            raise

    def goto_url(self, url: str, tab_id: str | None = None) -> dict[str, Any]:
        result = self._safe_action(
            "goto", self._ensure_launched().goto, url, tab_id)
        result.setdefault("message", f"Navigated to {url}")
        return result

    def click(self, coordinate: str, tab_id: str |
              None = None) -> dict[str, Any]:
        result = self._safe_action(
            "click",
            self._ensure_launched().click,
            coordinate,
            tab_id)
        result.setdefault("message", f"Clicked at {coordinate}")
        return result

    def type_text(self, text: str, tab_id: str |
                  None = None) -> dict[str, Any]:
        result = self._safe_action(
            "type", self._ensure_launched().type_text, text, tab_id)
        result.setdefault("message", "Typed text")
        return result

    def scroll(self, direction: str, tab_id: str |
               None = None) -> dict[str, Any]:
        result = self._safe_action(
            "scroll",
            self._ensure_launched().scroll,
            direction,
            tab_id)
        result.setdefault("message", f"Scrolled {direction}")
        return result

    def back(self, tab_id: str | None = None) -> dict[str, Any]:
        result = self._safe_action(
            "back", self._ensure_launched().back, tab_id)
        result.setdefault("message", "Navigated back")
        return result

    def forward(self, tab_id: str | None = None) -> dict[str, Any]:
        result = self._safe_action(
            "forward", self._ensure_launched().forward, tab_id)
        result.setdefault("message", "Navigated forward")
        return result

    def new_tab(self, url: str | None = None) -> dict[str, Any]:
        # Enforce tab limit
        browser = self._ensure_launched()
        tabs = browser.list_tabs()
        tab_count = tabs.get("count", 0)
        if tab_count >= self.MAX_TABS:
            return {
                "error": f"Tab limit reached ({self.MAX_TABS}). Close an existing tab first.",
                "tabs": tabs.get("tabs", {}),
            }
        result = self._safe_action("new_tab", browser.new_tab, url)
        result.setdefault(
            "message",
            f"Created new tab {result.get('tab_id', '')}"
        )
        return result

    def switch_tab(self, tab_id: str) -> dict[str, Any]:
        result = self._safe_action(
            "switch_tab",
            self._ensure_launched().switch_tab,
            tab_id)
        result.setdefault("message", f"Switched to tab {tab_id}")
        return result

    def close_tab(self, tab_id: str) -> dict[str, Any]:
        result = self._safe_action(
            "close_tab", self._ensure_launched().close_tab, tab_id)
        result.setdefault("message", f"Closed tab {tab_id}")
        return result

    def wait_browser(self, duration: float, tab_id: str |
                     None = None) -> dict[str, Any]:
        result = self._safe_action(
            "wait", self._ensure_launched().wait, duration, tab_id)
        result.setdefault("message", f"Waited {duration}s")
        return result

    def execute_js(self, js_code: str, tab_id: str |
                   None = None) -> dict[str, Any]:
        result = self._safe_action(
            "execute_js",
            self._ensure_launched().execute_js,
            js_code,
            tab_id)
        result.setdefault("message", "JavaScript executed successfully")
        return result

    def double_click(self, coordinate: str, tab_id: str |
                     None = None) -> dict[str, Any]:
        result = self._safe_action(
            "double_click",
            self._ensure_launched().double_click,
            coordinate,
            tab_id)
        result.setdefault("message", f"Double clicked at {coordinate}")
        return result

    def hover(self, coordinate: str, tab_id: str |
              None = None) -> dict[str, Any]:
        result = self._safe_action(
            "hover",
            self._ensure_launched().hover,
            coordinate,
            tab_id)
        result.setdefault("message", f"Hovered at {coordinate}")
        return result

    def press_key(self, key: str, tab_id: str | None = None) -> dict[str, Any]:
        result = self._safe_action(
            "press_key",
            self._ensure_launched().press_key,
            key,
            tab_id)
        result.setdefault("message", f"Pressed key {key}")
        return result

    def save_pdf(self, file_path: str, tab_id: str |
                 None = None) -> dict[str, Any]:
        result = self._safe_action(
            "save_pdf",
            self._ensure_launched().save_pdf,
            file_path,
            tab_id)
        result.setdefault("message", f"Page saved as PDF: {file_path}")
        return result

    def get_console_logs(self, tab_id: str | None = None,
                         clear: bool = False) -> dict[str, Any]:
        result = self._safe_action(
            "get_console_logs",
            self._ensure_launched().get_console_logs,
            tab_id,
            clear)
        result.setdefault("message", "Console logs retrieved")
        return result

    def get_network_logs(self, tab_id: str | None = None,
                         clear: bool = False) -> dict[str, Any]:
        result = self._safe_action(
            "get_network_logs",
            self._ensure_launched().get_network_logs,
            tab_id,
            clear)
        result.setdefault("message", "Network logs retrieved")
        return result

    def view_source(self, tab_id: str | None = None) -> dict[str, Any]:
        result = self._safe_action(
            "view_source",
            self._ensure_launched().view_source,
            tab_id)
        result.setdefault("message", "Page source retrieved")
        return result

    # ── Auth wrappers ────────────────────────────────────────────────────────

    def login_form(
        self,
        url: str,
        username: str,
        password: str,
        username_selector: str = 'input[type="email"],input[name="username"],input[name="email"],#username,#email',
        password_selector: str = 'input[type="password"]',  # nosec B107 - CSS selector, not a password
        submit_selector: str = 'button[type="submit"],input[type="submit"]',
        tab_id: str | None = None,
    ) -> dict[str, Any]:
        result = self._safe_action(
            "login_form",
            self._ensure_launched().login_form,
            url, username, password, username_selector, password_selector, submit_selector, tab_id,
        )
        result.setdefault("message", f"Logged in via form at {url}")
        return result

    def handle_totp(
        self,
        totp_secret: str,
        field_selector: str = 'input[name="totp"],input[name="otp"],input[name="code"]',
        tab_id: str | None = None,
    ) -> dict[str, Any]:
        result = self._safe_action(
            "handle_totp",
            self._ensure_launched().handle_totp,
            totp_secret, field_selector, tab_id,
        )
        result.setdefault("message", "TOTP code submitted")
        return result

    def save_auth_state(self) -> dict[str, Any]:
        result = self._safe_action(
            "save_auth_state",
            self._ensure_launched().save_auth_state)
        result.setdefault("message", "Auth state captured")
        return result

    def inject_cookies(
            self, cookies: list[dict[str, Any]], tab_id: str | None = None) -> dict[str, Any]:
        result = self._safe_action(
            "inject_cookies",
            self._ensure_launched().inject_cookies,
            cookies, tab_id,
        )
        result.setdefault("message", f"Injected {len(cookies)} cookies")
        return result

    def oauth_authorize(self, oauth_url: str, callback_prefix: str = "",
                        tab_id: str | None = None) -> dict[str, Any]:
        result = self._safe_action(
            "oauth_authorize",
            self._ensure_launched().oauth_authorize,
            oauth_url, callback_prefix, tab_id,
        )
        result.setdefault("message", f"OAuth authorization at {oauth_url}")
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
    # Auth parameters
    username: str | None = None,
    password: str | None = None,
    username_selector: str = 'input[type="email"],input[name="username"],input[name="email"],#username,#email',
    password_selector: str = 'input[type="password"]',
    submit_selector: str = 'button[type="submit"],input[type="submit"]',
    totp_secret: str | None = None,
    field_selector: str = 'input[name="totp"],input[name="otp"],input[name="code"]',
    cookies: list[dict[str, Any]] | None = None,
    callback_prefix: str = "",
) -> dict[str, Any]:
    try:
        if action == "launch":
            return _manager.launch_browser(url)  # type: ignore[arg-type]
        elif action == "goto":
            return _manager.goto_url(url, tab_id)  # type: ignore[arg-type]
        elif action == "click":
            return _manager.click(coordinate, tab_id)  # type: ignore[arg-type]
        elif action == "type":
            return _manager.type_text(text, tab_id)  # type: ignore[arg-type]
        elif action == "scroll_down":
            return _manager.scroll("down", tab_id)
        elif action == "scroll_up":
            return _manager.scroll("up", tab_id)
        elif action == "back":
            return _manager.back(tab_id)
        elif action == "forward":
            return _manager.forward(tab_id)
        elif action == "new_tab":
            return _manager.new_tab(url)  # type: ignore[arg-type]
        elif action == "switch_tab":
            return _manager.switch_tab(tab_id)  # type: ignore[arg-type]
        elif action == "close_tab":
            return _manager.close_tab(tab_id)  # type: ignore[arg-type]
        elif action == "wait":
            return _manager.wait_browser(duration, tab_id)  # type: ignore[arg-type]
        elif action == "execute_js":
            return _manager.execute_js(js_code, tab_id)  # type: ignore[arg-type]
        elif action == "double_click":
            return _manager.double_click(coordinate, tab_id)  # type: ignore[arg-type]
        elif action == "hover":
            return _manager.hover(coordinate, tab_id)  # type: ignore[arg-type]
        elif action == "press_key":
            return _manager.press_key(key, tab_id)  # type: ignore[arg-type]
        elif action == "save_pdf":
            return _manager.save_pdf(file_path, tab_id)  # type: ignore[arg-type]
        elif action == "get_console_logs":
            return _manager.get_console_logs(tab_id, clear)
        elif action == "get_network_logs":
            return _manager.get_network_logs(tab_id, clear)
        elif action == "view_source":
            return _manager.view_source(tab_id)
        elif action == "close":
            _manager.close()
            return {"message": "Browser closed"}
        elif action == "list_tabs":
            return _manager.list_tabs()
        # ── Auth actions ─────────────────────────────────────────────────────
        elif action == "login_form":
            if not url or not username or not password:
                return {"error": "login_form requires: url, username, password"}
            return _manager.login_form(
                url, username, password, username_selector, password_selector, submit_selector, tab_id)
        elif action == "handle_totp":
            if not totp_secret:
                return {"error": "handle_totp requires: totp_secret"}
            return _manager.handle_totp(totp_secret, field_selector, tab_id)
        elif action == "save_auth_state":
            return _manager.save_auth_state()
        elif action == "inject_cookies":
            if not cookies:
                return {
                    "error": "inject_cookies requires: cookies (list of cookie dicts)"}
            return _manager.inject_cookies(cookies, tab_id)
        elif action == "oauth_authorize":
            if not url:
                return {
                    "error": "oauth_authorize requires: url (OAuth authorization URL)"}
            return _manager.oauth_authorize(url, callback_prefix, tab_id)
        else:
            return {"error": f"Unknown action: {action}"}
    except Exception as e:
        logger.error(f"Browser action failed: {e}")
        return {"error": str(e)}

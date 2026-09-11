from __future__ import annotations

import asyncio
import atexit
import base64
import contextlib
import hashlib
import hmac
import json
import logging
import re
import struct
import threading
import time
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse
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

_DEAD_HOST_MARKERS: tuple[str, ...] = (
    "err_name_not_resolved",
    "err_address_unreachable",
    "err_connection_refused",
    "err_internet_disconnected",
    "name or service not known",
    "nodename nor servname provided",
    "temporary failure in name resolution",
    "no such host",
    "could not resolve host",
    "getaddrinfo failed",
    "failed to resolve",
)

_AUTH_ERROR_MARKERS: tuple[str, ...] = (
    "err_invalid_auth_credentials",
    "invalid auth credentials",
    "authentication required",
)

_BROWSER_ERROR_PAGE_MARKERS: tuple[str, ...] = (
    "chrome-error://chromewebdata/",
    "chromewebdata",
)

_STATIC_EXTS_PATH = Path(__file__).parent / "data" / "file_extensions.json"
try:
    _ext_data = json.loads(_STATIC_EXTS_PATH.read_text(encoding="utf-8"))
    _STATIC_ASSET_EXTS = {
        str(ext).lower()
        for ext in _ext_data.get("static", [])
        if isinstance(ext, str)
    }
except Exception as _ext_err:
    logger.debug("Failed to load file_extensions.json: %s", _ext_err)
    _STATIC_ASSET_EXTS = set()

_RETRYABLE_NAV_MARKERS: tuple[str, ...] = (
    "timeout",
    "timed out",
    "err_connection_reset",
    "err_connection_closed",
    "err_connection_aborted",
    "err_network_changed",
    "err_http2_protocol_error",
    "err_timed_out",
)


def _classify_dead_reason(err: str) -> str:
    e = err.lower()
    if (
        "name_not_resolved" in e
        or "resolve" in e
        or "nodename" in e
        or "no such host" in e
    ):
        return "DNS_NXDOMAIN"
    if "connection_refused" in e or "refused" in e:
        return "CONNECTION_REFUSED"
    if "address_unreachable" in e or "unreachable" in e:
        return "ADDRESS_UNREACHABLE"
    if "connection_reset" in e:
        return "CONNECTION_RESET"
    return "UNREACHABLE"


def _is_dead_host_error(err_lower: str) -> bool:
    if "err_connection_reset" in err_lower:
        return False
    return any(m in err_lower for m in _DEAD_HOST_MARKERS)


def _is_auth_error(err_lower: str) -> bool:
    return any(m in err_lower for m in _AUTH_ERROR_MARKERS)


def _is_browser_error_page(err_lower: str) -> bool:
    return any(m in err_lower for m in _BROWSER_ERROR_PAGE_MARKERS)


def _is_static_asset_url(url: str) -> bool:
    try:
        path = urlparse(url).path
        ext = Path(path).suffix.lstrip(".").lower()
        return bool(ext) and ext in _STATIC_ASSET_EXTS
    except Exception:
        return False


def _is_retryable_navigation_error(err_lower: str) -> bool:
    return any(m in err_lower for m in _RETRYABLE_NAV_MARKERS)


_TRACKING_PATTERNS: tuple[str, ...] = (
    "cdn-cgi/rum",
    "cdn-cgi/challenge-platform",
    "cdn-cgi/trace",
    "__ptq.gif",
    "hubspot.com/__ptq",
    "linkedin.com/px/li_sync",
    "px.ads.linkedin.com",
    "app.clearbit.com",
    "google-analytics.com/collect",
    "facebook.com/tr/",
    "facebook.com/privacy_sandbox/pixel",
    "facebook.com/ads/pixel",
    "facebook.com/plugins/",
    ".facebook.com/",
    ".fbcdn.net/",
    ".connect.facebook.net/",
    "doubleclick.net",
    "adservice.google.",
    "googletagmanager.com/gtm.js",
    "googlesyndication.com",
    "adservice.googleadservices.com",
    "bat.bing.com",
    "mc.yandex.ru",
    "hotjar.com",
    "fullstory.com",
    "mixpanel.com/track",
    "segment.io",
    "api.segment.io",
    "rum.cloudflare.com",
    "browser-intake-datadoghq.com",
    "logs.browser-intake-datadoghq.com",
    "pixel-config.reddit.com",
    "sc-analytics.appspot.com",
    "pinterest.com/log/",
    "ads.twitter.com/",
    "advertising.com/",
    "criteo.net",
    "outbrain.com",
    "taboola.com",
    "sentry.",
    "sentry_key=",
)


def _is_tracking_url(url: str) -> bool:
    """Check if a URL matches known tracking/analytics patterns."""
    url_lower = url.lower()
    return any(p in url_lower for p in _TRACKING_PATTERNS)


BrowserAction = Literal[
    "launch",
    "goto",
    "click",
    "type",
    "scroll_down",
    "scroll_up",
    "back",
    "forward",
    "new_tab",
    "switch_tab",
    "close_tab",
    "wait",
    "execute_js",
    "double_click",
    "hover",
    "press_key",
    "save_pdf",
    "get_console_logs",
    "get_network_logs",
    "view_source",
    "close",
    "list_tabs",
    "screenshot",
    "login_form",
    "handle_totp",
    "save_auth_state",
    "inject_cookies",
    "oauth_authorize",
    "check_auth_status",
    "wait_for_element",
    "solve_captcha",
]

_DEFAULT_USERNAME_SEL: str = (
    'input[type="email"],'
    'input[name="username"],'
    'input[name="email"],'
    'input[name="user"],'
    'input[name="login"],'
    'input[name="mail"],'
    'input[autocomplete="username"],'
    'input[autocomplete="email"],'
    "#username,#email,#user,#login,#mail"
)

_DEFAULT_PASSWORD_SEL: str = 'input[type="password"]'

_DEFAULT_SUBMIT_SEL: str = (
    'button[type="submit"],'
    'input[type="submit"],'
    'button:has-text("Log in"),'
    'button:has-text("Login"),'
    'button:has-text("Sign in"),'
    'button:has-text("Sign In"),'
    'button:has-text("Continue"),'
    'button:has-text("Next"),'
    'button:has-text("Submit")'
)

_DEFAULT_TOTP_FIELD_SEL: str = (
    'input[autocomplete="one-time-code"],'
    'input[name="totp"],'
    'input[name="otp"],'
    'input[name="code"],'
    'input[name="mfa_code"],'
    'input[name="verification_code"],'
    'input[name="verify_code"],'
    'input[name="auth_code"],'
    'input[name="token"],'
    'input[inputmode="numeric"],'
    'input[type="number"][maxlength="6"],'
    'input[maxlength="6"],'
    'input[placeholder*="TOTP" i],'
    'input[placeholder*="OTP" i],'
    'input[placeholder*="authenticator" i],'
    'input[placeholder*="verify" i],'
    'input[placeholder*="code" i]'
)


def _generate_totp(secret: str, period: int = 30, digits: int = 6) -> str:
    padded = secret.upper().replace(" ", "")
    padding = (8 - len(padded) % 8) % 8
    padded += "=" * padding
    key = base64.b32decode(padded)
    counter = int(time.time()) // period
    msg = struct.pack(">Q", counter)
    h = hmac.new(key, msg, hashlib.sha1).digest()
    offset = h[-1] & 0x0F
    code = struct.unpack(">I", h[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(code % (10**digits)).zfill(digits)


class DeadHostError(Exception):
    def __init__(self, url: str, original_error: str) -> None:
        from urllib.parse import urlparse

        parsed = urlparse(url)
        self.host = parsed.netloc or url
        self.url = url
        self.original_error = original_error
        super().__init__(f"Dead host: {self.host} — {original_error}")


class _BrowserState:
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


async def _start_docker_chromium() -> bool:
    _CONTAINER = "airecon-sandbox-active"
    _cfg = get_config()
    _CHROMIUM_CMD = (
        "chromium "
        "--headless=new "
        "--no-sandbox "
        "--disable-dev-shm-usage "
        "--disable-gpu "
        f"--remote-debugging-port={_cfg.browser_cdp_port} "
        f"--remote-debugging-address={_cfg.browser_cdp_bind_address} "
        "--disable-web-security "
        '--remote-allow-origins="*" '
        "--ignore-certificate-errors "
        ">/dev/null 2>&1 &"
    )
    try:
        proc = await asyncio.create_subprocess_exec(
            "docker",
            "exec",
            _CONTAINER,
            "bash",
            "-c",
            _CHROMIUM_CMD,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        await asyncio.wait_for(proc.wait(), timeout=5.0)
        if proc.returncode not in (0, None):
            logger.debug(
                "docker exec to start Chromium exited %s — container may not be running",
                proc.returncode,
            )
            return False
        logger.info("Chromium CDP server started in Docker container (lazy start)")

        await asyncio.sleep(3.0)
        return True
    except asyncio.TimeoutError:
        logger.warning("Timed out waiting for docker exec to start Chromium")
        return False
    except Exception as exc:
        logger.debug("Could not start Docker Chromium: %s", exc)
        return False


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

    playwright = await async_playwright().start()
    _state.playwright = playwright

    _cfg = get_config()
    _CDP_URL = f"http://localhost:{_cfg.browser_cdp_port}"
    _docker_chromium_started = False

    for attempt in range(4):
        try:
            _state.browser = await playwright.chromium.connect_over_cdp(
                _CDP_URL,
                timeout=get_config().browser_connect_timeout_ms,
            )
            return _state.browser
        except Exception as _cdp_err:
            if attempt == 0 and not _docker_chromium_started:
                logger.info(
                    "Chromium CDP not available (%s) — starting it in Docker sandbox...",
                    _cdp_err,
                )
                _docker_chromium_started = await _start_docker_chromium()
                if not _docker_chromium_started:
                    break
                continue
            elif attempt < 3:
                await asyncio.sleep(0.5 * (2**attempt))
                continue

            logger.warning(
                "Could not connect to Docker Chromium after %d attempts — "
                "falling back to local browser. Last error: %s",
                attempt + 1,
                _cdp_err,
            )

    try:
        _state.browser = await playwright.chromium.launch(
            headless=True,
            args=[
                "--no-sandbox",
                "--disable-setuid-sandbox",
                "--ignore-certificate-errors",
            ],
        )
        return _state.browser
    except Exception as e2:
        if _state.playwright:
            await _state.playwright.stop()
            _state.playwright = None
        raise RuntimeError(
            f"Failed to launch both Docker and fallback browsers: {e2}"
        ) from e2


def _get_browser() -> Browser:
    with _state.lock:
        _ensure_event_loop()
        if _state.event_loop is None:
            raise RuntimeError("Event loop not initialized")

        if _state.browser is None or not _state.browser.is_connected():
            future = asyncio.run_coroutine_threadsafe(
                _create_browser(), _state.event_loop
            )
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
        except TimeoutError as exc:
            future.cancel()
            raise RuntimeError(
                f"Browser action timed out after {timeout}s"
            ) from exc

    def _resolve_tab_id(self, tab_id: str | None) -> str:
        if tab_id and tab_id in self.pages:
            return tab_id
        if tab_id and tab_id not in self.pages:
            logger.warning(
                f"Tab '{tab_id}' not found — falling back to current tab '{self.current_page_id}'"
            )
        if self.current_page_id and self.current_page_id in self.pages:
            return self.current_page_id
        raise ValueError("No active browser tab available")

    async def _navigate_with_fallback(
        self, page: Any, url: str, timeout_ms: int | None = None
    ) -> None:
        """Navigate with redirect loop detection and shorter timeout."""
        if timeout_ms is None:
            timeout_ms = get_config().browser_navigation_timeout_ms
        max_attempts = 2
        last_error: Exception | None = None

        for attempt in range(1, max_attempts + 1):
            redirect_count = 0
            last_url = url
            seen_urls: set[str] = {url}
            max_redirects = 10  # modern sites often chain 5-8 redirects

            def check_redirect(
                request: Any,
                seen_urls: set[str] = seen_urls,
                max_redirects: int = max_redirects,
            ) -> None:
                nonlocal redirect_count, last_url
                current_url = request.url
                if current_url != last_url:
                    redirect_count += 1
                    last_url = current_url

                    # Detect actual loops (same URL visited twice) vs long chains
                    if current_url in seen_urls:
                        logger.warning(
                            f"Detected redirect loop ({redirect_count} redirects, "
                            f"revisited {current_url!r}) for {url!r}"
                        )
                        raise RuntimeError(
                            f"Redirect loop detected — revisited same URL after {redirect_count} redirects"
                        )
                    seen_urls.add(current_url)

                    if _is_static_asset_url(current_url) and current_url != url:
                        logger.warning(
                            "Redirected to static asset during navigation: %s",
                            current_url[:200],
                        )
                        raise RuntimeError(
                            f"Redirected to static asset — final URL: {current_url[:120]}"
                        )

                    if redirect_count > max_redirects:
                        logger.warning(
                            f"Exceeded redirect limit ({redirect_count} > {max_redirects}) for {url!r}"
                        )
                        raise RuntimeError(
                            f"Too many redirects ({redirect_count} > {max_redirects}) — "
                            f"final URL: {current_url[:120]}"
                        )

            try:
                page.on("request", check_redirect)
                await page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
                return
            except Exception as e:
                last_error = e
                err_str = str(e)
                err_lower = err_str.lower()
                if _is_dead_host_error(err_lower):
                    raise DeadHostError(url, err_str) from e
                if _is_auth_error(err_lower):
                    raise RuntimeError(
                        "Authentication required or invalid credentials for this URL"
                    ) from e
                if "interrupted by another navigation" in err_lower:
                    # Page itself triggered a redirect (SSO/OAuth) mid-goto.
                    # The page is actually navigating somewhere — wait for it
                    # to settle and report the final URL rather than failing.
                    try:
                        await page.wait_for_load_state(
                            "domcontentloaded", timeout=min(timeout_ms, 15000)
                        )
                    except Exception as wait_err:
                        logger.debug(
                            "wait_for_load_state after navigation-interrupt failed: %s",
                            wait_err,
                        )
                    final_url = ""
                    try:
                        final_url = page.url or ""
                    except Exception as url_err:
                        logger.debug("page.url lookup failed: %s", url_err)
                    logger.info(
                        "Navigation to %s was superseded by redirect to %s — treating as soft-redirect",
                        url[:120],
                        final_url[:200] or "<unknown>",
                    )
                    return
                if "timeout" in err_lower:
                    logger.warning(
                        "domcontentloaded timed out for %r, retrying with wait_until='commit'",
                        url,
                    )
                    try:
                        await page.goto(url, wait_until="commit", timeout=timeout_ms)
                        return
                    except Exception as e2:
                        last_error = e2
                        err_lower = str(e2).lower()
                        if _is_dead_host_error(err_lower):
                            raise DeadHostError(url, str(e2)) from e2
                        if _is_auth_error(err_lower):
                            raise RuntimeError(
                                "Authentication required or invalid credentials for this URL"
                            ) from e2

                if attempt < max_attempts and _is_retryable_navigation_error(err_lower):
                    backoff = min(0.6 * attempt, 1.8)
                    logger.info(
                        "Navigation retry %d/%d for %s after %.1fs (error=%s)",
                        attempt,
                        max_attempts,
                        url[:120],
                        backoff,
                        err_lower[:120],
                    )
                    await asyncio.sleep(backoff)
                    continue
                raise
            finally:
                try:
                    off_result = page.off("request", check_redirect)
                    if asyncio.iscoroutine(off_result):
                        await off_result
                except Exception as exc:
                    logger.debug("Failed to detach redirect handler: %s", exc)

        if last_error:
            raise last_error

    async def _setup_tracking_blocker(self, page: Page) -> None:
        """Abort tracking/analytics requests at the network layer before they
        are ever sent. This prevents redirect loops caused by third-party pixels
        loaded inside normal pages."""
        async def _route_handler(route: Any) -> None:
            if _is_tracking_url(route.request.url):
                logger.debug("Network route blocked (tracking): %s", route.request.url[:120])
                await route.abort()
            else:
                await route.continue_()

        await page.route("**/*", _route_handler)

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
                "timestamp": time.monotonic(),
            }
            self.console_logs[tab_id].append(log_entry)
            if len(self.console_logs[tab_id]) > MAX_CONSOLE_LOGS_COUNT:
                self.console_logs[tab_id] = self.console_logs[tab_id][
                    -MAX_CONSOLE_LOGS_COUNT:
                ]

        page.on("console", handle_console)

        def handle_request(request: Any) -> None:
            reqs = self.network_requests.get(tab_id, [])
            if len(reqs) >= MAX_NETWORK_REQUESTS:
                return
            post_data = None
            try:
                post_data = request.post_data
            except Exception as e:
                logger.debug("Expected failure reading request post_data: %s", e)
            reqs.append(
                {
                    "type": "request",
                    "url": request.url,
                    "method": request.method,
                    "resource_type": request.resource_type,
                    "headers": dict(request.headers),
                    "post_data": post_data,
                }
            )

        page.on("request", handle_request)

        async def handle_response(response: Any) -> None:
            reqs = self.network_requests.get(tab_id, [])
            if len(reqs) >= MAX_NETWORK_REQUESTS:
                return
            content_type = response.headers.get("content-type", "")
            body: str | None = None

            if any(
                t in content_type
                for t in ("json", "text/plain", "javascript", "xml", "html")
            ):
                try:
                    body = await response.text()
                    if body is not None and len(body) > MAX_RESPONSE_BODY_LENGTH:
                        body = body[:MAX_RESPONSE_BODY_LENGTH] + "... [TRUNCATED]"
                except Exception:
                    body = None
            reqs.append(
                {
                    "type": "response",
                    "url": response.url,
                    "status": response.status,
                    "content_type": content_type,
                    "headers": dict(response.headers),
                    "body": body,
                }
            )

        page.on("response", handle_response)

    async def _create_context(
        self, url: str | None = None, auth_cookies: list[dict] | None = None
    ) -> dict[str, Any]:
        if self._browser is None:
            raise RuntimeError("Browser not initialized")
        context = await self._browser.new_context(
            viewport={"width": 1280, "height": 720},
            user_agent="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            ignore_https_errors=True,
        )
        self.context = context
        try:
            nav_timeout = int(get_config().browser_navigation_timeout_ms)
            if nav_timeout > 0:
                context.set_default_navigation_timeout(nav_timeout)
            action_timeout = int(get_config().browser_action_timeout * 1000)
            if action_timeout > 0:
                context.set_default_timeout(action_timeout)
        except Exception as e:
            logger.debug("Failed to set browser timeouts on context: %s", e)

        if auth_cookies:
            try:
                await context.add_cookies(auth_cookies)  # type: ignore[arg-type]
                logger.info(f"Restored {len(auth_cookies)} auth cookies from session")
            except Exception as e:
                logger.warning(f"Failed to restore auth cookies: {e}")

        page = await context.new_page()
        tab_id = f"tab_{self._next_tab_id}"
        self._next_tab_id += 1
        self.pages[tab_id] = page
        self.current_page_id = tab_id
        await self._setup_tracking_blocker(page)
        await self._setup_console_logging(page, tab_id)
        if url:
            try:
                await self._navigate_with_fallback(page, url)
            except DeadHostError as e:
                logger.warning("Dead host in _create_context: %s", e.host)
                state = await self._get_page_state(tab_id)
                state.update(
                    {
                        "success": False,
                        "domain_dead": True,
                        "host": e.host,
                        "url": url,
                        "reason": _classify_dead_reason(e.original_error),
                        "error": f"Host unreachable: {e.host}",
                        "next_action": (
                            f"SKIP: {e.host} does not resolve or is unreachable "
                            f"({_classify_dead_reason(e.original_error)}). "
                            "Move on to the next target."
                        ),
                    }
                )
                return state
        return await self._get_page_state(tab_id)

    async def _get_page_state(
        self, tab_id: str | None = None, include_screenshot: bool = False
    ) -> dict[str, Any]:
        try:
            tab_id = self._resolve_tab_id(tab_id)
        except Exception as e:
            return {
                "error": f"No active tab available: {e}",
                "screenshot": "",
                "url": "",
                "title": "",
                "text_content": "",
                "viewport": None,
                "tab_id": None,
                "all_tabs": {},
            }

        page = self.pages[tab_id]
        delay = get_config().browser_page_load_delay
        await asyncio.sleep(delay)

        screenshot_b64 = ""
        screenshot_failure = None
        if include_screenshot:
            try:
                screenshot_bytes = await page.screenshot(
                    type="png",
                    full_page=False,
                    timeout=get_config().browser_screenshot_timeout_ms,
                )
                screenshot_b64 = base64.b64encode(screenshot_bytes).decode("utf-8")
            except Exception as e:
                screenshot_failure = f"Screenshot failed: {type(e).__name__}: {e}"
                logger.debug(screenshot_failure)

        url = page.url
        title = await page.title()
        viewport = page.viewport_size

        try:
            text_content = await page.evaluate(
                "() => document.body ? document.body.innerText : ''"
            )
            if len(text_content) > 3000:
                text_content = (
                    text_content[:3000]
                    + "... [TRUNCATED, use execute_js or view_source for more]"
                )
        except Exception:
            text_content = "Failed to extract text content"

        all_tabs = {}
        for tid, tab_page in self.pages.items():
            is_closed = tab_page.is_closed()
            if asyncio.iscoroutine(is_closed):
                is_closed = await is_closed
            all_tabs[tid] = {
                "url": tab_page.url,
                "title": await tab_page.title()
                if not is_closed
                else "Closed",
            }

        result = {
            "screenshot": screenshot_b64,
            "url": url,
            "title": title,
            "text_content": text_content,
            "viewport": viewport,
            "tab_id": tab_id,
            "all_tabs": all_tabs,
        }

        if screenshot_failure:
            result["screenshot_failure"] = screenshot_failure

        return result

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

    async def _goto(self, url: str, tab_id: str | None = None) -> dict[str, Any]:
        if _is_tracking_url(url):
            logger.info("Browser: skipping tracking/analytics URL: %s", url[:120])
            return {
                "success": False,
                "tracking_url": True,
                "url": url,
                "message": "Skipped tracking/analytics URL (would cause redirect loop)",
                "next_action": "Skip this URL — it is a third-party analytics/tracking pixel, not a target endpoint.",
            }
        if _is_static_asset_url(url):
            logger.info("Browser: skipping static asset URL: %s", url[:120])
            return {
                "success": False,
                "static_asset": True,
                "url": url,
                "message": "Skipped static asset URL (use httpx/curl instead of browser).",
                "next_action": (
                    "Skip static assets in browser automation. Use httpx or read_file "
                    "if you need the content."
                ),
            }

        tab_id = self._resolve_tab_id(tab_id)
        page = self.pages[tab_id]
        try:
            await self._navigate_with_fallback(page, url)
            state = await self._get_page_state(tab_id)
            return state
        except DeadHostError as e:
            logger.warning(
                "Dead host detected via goto: %s (%s)", e.host, e.original_error
            )
            return {
                "success": False,
                "domain_dead": True,
                "host": e.host,
                "url": url,
                "reason": _classify_dead_reason(e.original_error),
                "error": f"Host unreachable: {e.host}",
                "next_action": (
                    f"SKIP: {e.host} does not resolve or is unreachable "
                    f"({_classify_dead_reason(e.original_error)}). "
                    "Mark this host as dead and move on to the next target."
                ),
            }
        except RuntimeError as e:
            # Handle redirect loops consistently with _safe_action pattern
            err_str = str(e)
            if "Too many redirects" in err_str or "redirect loop" in err_str.lower():
                redirected_url = ""
                m = re.search(r"final URL:\s*(\S+)", err_str)
                if m:
                    redirected_url = m.group(1)
                logger.warning(
                    "Browser redirect loop on %s — final: %s",
                    url[:120],
                    redirected_url[:120] if redirected_url else "unknown",
                )
                return {
                    "success": False,
                    "redirect_loop": True,
                    "error": err_str[:500],
                    "message": (
                        "The page redirect chain exceeded 10 hops. This is usually caused by "
                        "tracking pixels, ad blockers, or SSO redirect chains — not a real page."
                    ),
                    "final_url": redirected_url[:200],
                    "next_action": (
                        "Do NOT retry the same URL. If it redirected to a third-party domain "
                        "(ads, analytics, SSO, or CDN), skip it and test the next endpoint. "
                        "If you need to see this page, try with JavaScript disabled or "
                        "use curl --head to inspect redirects manually."
                    ),
                }
            raise

    def click(self, coordinate: str, tab_id: str | None = None) -> dict[str, Any]:
        with self._execution_lock:
            return self._run_async(self._click(coordinate, tab_id))

    async def _click(
        self, coordinate: str, tab_id: str | None = None
    ) -> dict[str, Any]:
        tab_id = self._resolve_tab_id(tab_id)
        try:
            x, y = map(int, coordinate.split(","))
        except ValueError as e:
            raise ValueError(
                f"Invalid coordinate format: {coordinate}. Use 'x,y'"
            ) from e

        page = self.pages[tab_id]
        viewport = page.viewport_size or {"width": 1920, "height": 1080}
        max_x = viewport.get("width", 1920) * 2
        max_y = viewport.get("height", 1080) * 2

        if not (0 <= x <= max_x and 0 <= y <= max_y):
            raise ValueError(
                f"Coordinates ({x}, {y}) out of bounds. "
                f"Max allowed: ({max_x}, {max_y}). "
                f"Current viewport: {viewport.get('width', 1920)}x{viewport.get('height', 1080)}"
            )
        await page.mouse.click(x, y)
        return await self._get_page_state(tab_id)

    def type_text(self, text: str, tab_id: str | None = None) -> dict[str, Any]:
        with self._execution_lock:
            return self._run_async(self._type_text(text, tab_id))

    async def _type_text(self, text: str, tab_id: str | None = None) -> dict[str, Any]:
        tab_id = self._resolve_tab_id(tab_id)
        page = self.pages[tab_id]
        await page.keyboard.type(text)
        return await self._get_page_state(tab_id)

    def scroll(self, direction: str, tab_id: str | None = None) -> dict[str, Any]:
        with self._execution_lock:
            return self._run_async(self._scroll(direction, tab_id))

    async def _scroll(
        self, direction: str, tab_id: str | None = None
    ) -> dict[str, Any]:
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
            await page.go_back(
                wait_until="domcontentloaded",
                timeout=get_config().browser_navigation_timeout_ms,
            )
        except Exception as e:
            if "timeout" in str(e).lower():
                logger.warning(
                    "go_back domcontentloaded timed out, falling back to 'commit'"
                )
                await page.go_back(
                    wait_until="commit",
                    timeout=get_config().browser_navigation_timeout_ms,
                )
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
            await page.go_forward(
                wait_until="domcontentloaded",
                timeout=get_config().browser_navigation_timeout_ms,
            )
        except Exception as e:
            if "timeout" in str(e).lower():
                logger.warning(
                    "go_forward domcontentloaded timed out, falling back to 'commit'"
                )
                await page.go_forward(
                    wait_until="commit",
                    timeout=get_config().browser_navigation_timeout_ms,
                )
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
        await self._setup_tracking_blocker(page)
        await self._setup_console_logging(page, tab_id)
        if url:
            try:
                await self._navigate_with_fallback(page, url)
            except DeadHostError as e:
                logger.warning("Dead host in _new_tab: %s", e.host)
                state = await self._get_page_state(tab_id)
                state.update(
                    {
                        "success": False,
                        "domain_dead": True,
                        "host": e.host,
                        "url": url,
                        "reason": _classify_dead_reason(e.original_error),
                        "error": f"Host unreachable: {e.host}",
                        "next_action": (
                            f"SKIP: {e.host} is unreachable. Move on to the next target."
                        ),
                    }
                )
                return state
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

    def wait(self, duration: float, tab_id: str | None = None) -> dict[str, Any]:
        with self._execution_lock:
            return self._run_async(self._wait(duration, tab_id))

    async def _wait(self, duration: float, tab_id: str | None = None) -> dict[str, Any]:
        if duration is None or duration < 0:
            duration = 1.0
        await asyncio.sleep(duration)
        return await self._get_page_state(tab_id)

    def execute_js(
        self,
        js_code: str,
        tab_id: str | None = None,
        parallel: bool = False,
    ) -> dict[str, Any]:
        with self._execution_lock:
            return self._run_async(self._execute_js(js_code, tab_id, parallel=parallel))

    async def _execute_js(
        self, js_code: str, tab_id: str | None = None, parallel: bool = False
    ) -> dict[str, Any]:
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
                    "error_message": str(e),
                }
        else:
            tasks = []
            task_tab_ids: list[str] = []
            for tid, page in self.pages.items():
                if not page.is_closed():
                    task_tab_ids.append(tid)
                    tasks.append(self._execute_js_single(page, js_code, tid))
            results = await asyncio.gather(*tasks, return_exceptions=True)
            result = {
                "parallel_results": {
                    tid: res
                    if not isinstance(res, BaseException)
                    else {"error": str(res)}
                    for tid, res in zip(task_tab_ids, results)
                }
            }
        result_str = str(result)
        if len(result_str) > MAX_JS_RESULT_LENGTH:
            result = result_str[:MAX_JS_RESULT_LENGTH] + "... [JS result truncated]"
        state = await self._get_page_state(tab_id)
        state["js_result"] = result
        return state

    async def _execute_js_single(
        self, page: Any, js_code: str, tab_id: str
    ) -> dict[str, Any]:
        try:
            result = await page.evaluate(js_code)
            return {
                "success": True,
                "result": str(result)[:MAX_JS_RESULT_LENGTH],
                "tab_id": tab_id,
                "url": page.url,
            }
        except Exception as e:
            return {"success": False, "error": str(e), "tab_id": tab_id}

    def get_console_logs(
        self, tab_id: str | None = None, clear: bool = False
    ) -> dict[str, Any]:
        with self._execution_lock:
            return self._run_async(self._get_console_logs(tab_id, clear))

    async def _get_network_logs(
        self, tab_id: str | None = None, clear: bool = False
    ) -> dict[str, Any]:
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
            "api_calls": [
                r["url"]
                for r in reqs
                if r["type"] == "request" and r.get("resource_type") in ("xhr", "fetch")
            ],
        }
        return state

    def get_network_logs(
        self, tab_id: str | None = None, clear: bool = False
    ) -> dict[str, Any]:
        with self._execution_lock:
            return self._run_async(self._get_network_logs(tab_id, clear))

    async def _get_console_logs(
        self, tab_id: str | None = None, clear: bool = False
    ) -> dict[str, Any]:
        tab_id = self._resolve_tab_id(tab_id)
        logs = self.console_logs.get(tab_id, [])
        if len(str(logs)) > MAX_CONSOLE_LOG_LENGTH:
            logs = logs[-MAX_CONSOLE_LOGS_COUNT:]
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
        full_source = source
        if len(source) > MAX_PAGE_SOURCE_LENGTH:
            half_len = MAX_PAGE_SOURCE_LENGTH // 2
            source = (
                source[:half_len]
                + "\n... [TRUNCATED — full source in output/source_*.txt] ...\n"
                + source[-half_len:]
            )
        state = await self._get_page_state(tab_id)
        state["page_source"] = source

        state["full_page_source"] = full_source
        return state

    def screenshot(self, tab_id: str | None = None) -> dict[str, Any]:
        with self._execution_lock:
            return self._run_async(self._screenshot(tab_id))

    async def _screenshot(self, tab_id: str | None = None) -> dict[str, Any]:
        try:
            tab_id = self._resolve_tab_id(tab_id)
        except Exception as e:
            return {"success": False, "error": f"No active tab: {e}"}

        if tab_id not in self.pages:
            return {"success": False, "error": f"Tab {tab_id} not found"}

        page = self.pages[tab_id]
        try:
            workspace = get_workspace_root()
        except Exception as e:
            return {"success": False, "error": f"Cannot determine workspace: {e}"}

        screenshots_dir = workspace / "screenshots"
        screenshots_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"screenshot_{ts}.png"
        filepath = screenshots_dir / filename
        screenshot_timeout_ms = get_config().browser_screenshot_timeout_ms
        await page.screenshot(
            path=str(filepath), full_page=False, timeout=screenshot_timeout_ms
        )
        state = await self._get_page_state(tab_id)
        state["screenshot_path"] = str(filepath)
        state["message"] = f"Screenshot saved to {filepath}"
        return state

    def double_click(
        self, coordinate: str, tab_id: str | None = None
    ) -> dict[str, Any]:
        with self._execution_lock:
            return self._run_async(self._double_click(coordinate, tab_id))

    async def _double_click(
        self, coordinate: str, tab_id: str | None = None
    ) -> dict[str, Any]:
        tab_id = self._resolve_tab_id(tab_id)
        try:
            x, y = map(int, coordinate.split(","))
        except ValueError as e:
            raise ValueError(
                f"Invalid coordinate format: {coordinate}. Use 'x,y'"
            ) from e
        page = self.pages[tab_id]
        await page.mouse.dblclick(x, y)
        return await self._get_page_state(tab_id)

    def hover(self, coordinate: str, tab_id: str | None = None) -> dict[str, Any]:
        with self._execution_lock:
            return self._run_async(self._hover(coordinate, tab_id))

    async def _hover(
        self, coordinate: str, tab_id: str | None = None
    ) -> dict[str, Any]:
        tab_id = self._resolve_tab_id(tab_id)
        try:
            x, y = map(int, coordinate.split(","))
        except ValueError as e:
            raise ValueError(
                f"Invalid coordinate format: {coordinate}. Use 'x,y'"
            ) from e

        page = self.pages[tab_id]
        viewport = page.viewport_size or {"width": 1920, "height": 1080}
        max_x = viewport.get("width", 1920) * 2
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

    async def _press_key(self, key: str, tab_id: str | None = None) -> dict[str, Any]:
        tab_id = self._resolve_tab_id(tab_id)
        page = self.pages[tab_id]
        await page.keyboard.press(key)
        return await self._get_page_state(tab_id)

    def save_pdf(self, file_path: str, tab_id: str | None = None) -> dict[str, Any]:
        with self._execution_lock:
            return self._run_async(self._save_pdf(file_path, tab_id))

    async def _save_pdf(
        self, file_path: str, tab_id: str | None = None
    ) -> dict[str, Any]:
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

    def login_form(
        self,
        url: str,
        username: str,
        password: str,
        username_selector: str | None = None,
        password_selector: str | None = None,
        submit_selector: str | None = None,
        tab_id: str | None = None,
        multi_step: bool = False,
    ) -> dict[str, Any]:
        with self._execution_lock:
            return self._run_async(
                self._login_form(
                    url,
                    username,
                    password,
                    username_selector or _DEFAULT_USERNAME_SEL,
                    password_selector or _DEFAULT_PASSWORD_SEL,
                    submit_selector or _DEFAULT_SUBMIT_SEL,
                    tab_id,
                    multi_step,
                )
            )

    _LOGIN_RESULT_JS = """() => {
        const qs = (s) => document.querySelector(s);
        // Error messages — common across Bootstrap, Tailwind, custom frameworks
        const ERR_SELECTORS = [
            '[class*="error"]:not(script):not(style):not(link)',
            '[role="alert"]',
            '[class*="alert-danger"]','[class*="alert-error"]',
            '[class*="invalid-feedback"]','[class*="form-error"]',
            '.flash-error','.notification-error','[data-error]',
            '.help-block','.invalid-feedback'
        ].join(',');
        let errorText = null;
        try {
            const errEl = qs(ERR_SELECTORS);
            if (errEl) {
                const t = (errEl.innerText || errEl.textContent || '').trim();
                if (t.length > 0 && t.length < 500) errorText = t;
            }
        } catch(e) {}
        // Login form still visible = probably NOT logged in yet
        const loginFormVisible = !!qs('form input[type="password"]');
        // Logout/dashboard links = almost certainly logged in
        const hasLogout = !!qs(
            'a[href*="logout"],a[href*="signout"],a[href*="sign-out"],a[href*="log-out"],' +
            'button[class*="logout"],form[action*="logout"],[data-action*="logout"],' +
            'a[href*="dashboard"],a[href*="account"],a[href*="profile"]'
        );
        // CAPTCHA detection
        const captchaEl = qs(
            'iframe[src*="recaptcha"],div.g-recaptcha,' +
            'iframe[src*="hcaptcha"],.h-captcha,' +
            '[class*="captcha"],[id*="captcha"],' +
            'img[src*="captcha"],img[alt*="captcha" i],' +
            '.cf-turnstile,[data-sitekey]'
        );
        let captchaType = null;
        if (captchaEl) {
            const src = (captchaEl.src || '').toLowerCase();
            const cls = (captchaEl.className || '').toLowerCase();
            const id  = (captchaEl.id || '').toLowerCase();
            if (src.includes('recaptcha') || cls.includes('g-recaptcha') || id.includes('recaptcha'))
                captchaType = 'recaptcha';
            else if (src.includes('hcaptcha') || cls.includes('h-captcha') || id.includes('hcaptcha'))
                captchaType = 'hcaptcha';
            else if (cls.includes('turnstile') || id.includes('turnstile'))
                captchaType = 'cloudflare_turnstile';
            else
                captchaType = 'unknown';
        }
        // 2FA/MFA field detected = need handle_totp or request_user_input
        const mfaDetected = !!(
            qs('input[autocomplete="one-time-code"]') ||
            qs('input[name="totp"],input[name="otp"],input[name="mfa_code"]') ||
            qs('input[placeholder*="code" i],input[placeholder*="OTP" i]')
        );
        return { errorText, loginFormVisible, hasLogout, captchaType, mfaDetected };
    }"""

    async def _fill_selectors(
        self,
        page: Any,
        selectors: str,
        value: str,
        timeout_ms: int | None = None,
    ) -> bool:
        if timeout_ms is None:
            timeout_ms = get_config().browser_totp_fill_timeout_ms
        for sel in selectors.split(","):
            try:
                await page.fill(sel.strip(), value, timeout=timeout_ms)
                return True
            except Exception as e:
                logger.debug("Fill selector failed (%s): %s", sel.strip(), e)
        return False

    async def _click_selectors(
        self,
        page: Any,
        selectors: str | tuple[str, ...],
        timeout_ms: int | None = None,
    ) -> bool:
        if timeout_ms is None:
            timeout_ms = get_config().browser_totp_fill_timeout_ms
        sel_list = (
            selectors.split(",") if isinstance(selectors, str) else list(selectors)
        )
        for sel in sel_list:
            try:
                await page.click(sel.strip(), timeout=timeout_ms)
                return True
            except Exception as e:
                logger.debug("Click selector failed (%s): %s", sel.strip(), e)
        return False

    async def _login_form(
        self,
        url: str,
        username: str,
        password: str,
        username_selector: str,
        password_selector: str,
        submit_selector: str,
        tab_id: str | None,
        multi_step: bool = False,
    ) -> dict[str, Any]:

        if not self.pages:
            await self._create_context(url)
            tab_id = self.current_page_id
        else:
            tab_id = self._resolve_tab_id(tab_id)
            await self._goto(url, tab_id)
        page = self.pages[tab_id]  # type: ignore[index]
        login_url = page.url

        if multi_step:
            if not await self._fill_selectors(page, username_selector, username):
                logger.warning("login_form(multi_step): username selector not found")
            await asyncio.sleep(0.3)

            _step1_submit = (
                'button:has-text("Next"),button:has-text("Continue"),'
                'button:has-text("Sign in"),button[type="submit"],'
                'input[type="submit"]'
            )
            if not await self._click_selectors(page, _step1_submit):
                await page.keyboard.press("Enter")

            try:
                await page.wait_for_load_state(
                    "networkidle", timeout=get_config().browser_login_form_wait_ms
                )
            except Exception as e:
                logger.debug(
                    "Expected failure waiting for networkidle in multi-step login: %s",
                    e,
                )

            try:
                await page.wait_for_selector(
                    'input[type="password"]',
                    state="visible",
                    timeout=get_config().browser_login_form_wait_ms,
                )
            except Exception:
                await asyncio.sleep(2)

            if not await self._fill_selectors(page, password_selector, password):
                logger.warning(
                    "login_form(multi_step): password selector not found after step 1"
                )
            await asyncio.sleep(0.3)
            if not await self._click_selectors(page, submit_selector):
                await page.keyboard.press("Enter")
        else:
            if not await self._fill_selectors(page, username_selector, username):
                logger.warning(
                    "login_form: username selector not found (%s)", username_selector
                )
            await asyncio.sleep(0.3)
            if not await self._fill_selectors(page, password_selector, password):
                logger.warning(
                    "login_form: password selector not found (%s)", password_selector
                )
            await asyncio.sleep(0.3)
            if not await self._click_selectors(page, submit_selector):
                await page.keyboard.press("Enter")

        try:
            await page.wait_for_load_state(
                "domcontentloaded", timeout=get_config().browser_page_load_timeout_ms
            )
        except Exception:
            await asyncio.sleep(2)

        state = await self._get_page_state(tab_id)
        if self.context:
            state["auth_cookies"] = await self.context.cookies()
            state["auth_captured"] = True

        try:
            r = await page.evaluate(self._LOGIN_RESULT_JS)
            captcha_detected = r.get("captchaType") is not None
            mfa_detected = bool(r.get("mfaDetected"))
            error_text = r.get("errorText")
            url_changed = page.url != login_url

            login_success = (
                (url_changed or not r.get("loginFormVisible") or r.get("hasLogout"))
                and not error_text
                and not captcha_detected
                and not mfa_detected
            )
            state["login_success"] = login_success
            state["login_error"] = error_text
            state["captcha_detected"] = captcha_detected
            state["captcha_type"] = r.get("captchaType")
            state["mfa_required"] = mfa_detected
            state["url_changed"] = url_changed

            if captcha_detected:
                _captcha_screenshot: str | None = None
                try:
                    _ss = await self._screenshot(tab_id)
                    _captcha_screenshot = _ss.get("screenshot_path")
                    if _captcha_screenshot:
                        from pathlib import Path as _Path

                        if not _Path(_captcha_screenshot).exists():
                            logger.debug(
                                "CAPTCHA screenshot file not found: %s",
                                _captcha_screenshot,
                            )
                            _captcha_screenshot = None
                    state["captcha_screenshot"] = _captcha_screenshot
                except Exception as _ss_err:
                    logger.debug("Auto-screenshot on CAPTCHA failed: %s", _ss_err)

                # Auto-solve CAPTCHA via LLM vision + DOM bypass
                _capt_type = r.get("captchaType") or "unknown"
                _captcha_bypass_applied = False
                try:
                    from .agent.captcha_solver import CaptchaSolver

                    _cfg = get_config()
                    _captcha_model_cfg = _cfg.openai_model
                    _solver = CaptchaSolver(
                        base_url=_cfg.openai_base_url,
                        captcha_model=_captcha_model_cfg,
                        api_key=_cfg.openai_api_key,
                        timeout=_cfg.llm_timeout,
                    )

                    # Always try DOM bypass first for widget-type CAPTCHAs
                    _bypass_js = _solver._get_dom_bypass_js(_capt_type)
                    if _captcha_screenshot:
                        # Send screenshot to LLM vision for text CAPTCHA solving
                        _solve_result = await _solver.solve_from_page(
                            page_screenshot_b64=base64.b64encode(
                                await page.screenshot(type="png", full_page=False)
                            ).decode("utf-8"),
                            page_html=await page.evaluate("() => document.documentElement.outerHTML"),
                            captcha_type=_capt_type,
                        )
                        if _solve_result.get("success"):
                            state["captcha_bypass_applied"] = True
                            state["captcha_solution"] = _solve_result.get("solution")
                            state["captcha_method"] = _solve_result.get("method")
                            _captcha_bypass_applied = True
                            logger.info(
                                "CAPTCHA solved: type=%s method=%s solution=%r",
                                _capt_type,
                                _solve_result.get("method"),
                                _solve_result.get("solution"),
                            )
                    elif _bypass_js:
                        # No screenshot available — try DOM bypass only
                        _dom_result = await page.evaluate(_bypass_js)
                        if isinstance(_dom_result, dict) and _dom_result.get("success"):
                            state["captcha_bypass_applied"] = True
                            _captcha_bypass_applied = True
                            logger.info(
                                "CAPTCHA DOM bypass success: type=%s",
                                _capt_type,
                            )
                except Exception as _bypass_err:
                    logger.debug("CAPTCHA auto-solve failed: %s", _bypass_err)

                _captcha_strategy_msg = ""
                if _captcha_bypass_applied:
                    _captcha_strategy_msg = (
                        f" Auto-solved via {state.get('captcha_method', 'DOM bypass')}."
                        if state.get("captcha_method")
                        else " Auto DOM bypass applied."
                    )
                elif _captcha_model_cfg:
                    _captcha_strategy_msg = (
                        f" LLM vision model configured ({_captcha_model_cfg}) but failed."
                    )

                _captcha_hint = (
                    f"CAPTCHA detected ({_capt_type})."
                    + (
                        f" Screenshot saved: {_captcha_screenshot}."
                        if _captcha_screenshot
                        else ""
                    )
                    + _captcha_strategy_msg
                    + " If auto-solve failed: call request_user_input(input_type='captcha', prompt='Solve the CAPTCHA"
                    + (
                        f" shown in {_captcha_screenshot}"
                        if _captcha_screenshot
                        else ""
                    )
                    + "') to ask the user."
                )
                state["next_action"] = _captcha_hint
            elif mfa_detected:
                state["next_action"] = (
                    "MFA/2FA field detected. If you have the TOTP secret: call "
                    "handle_totp(totp_secret=...). Otherwise: call "
                    "request_user_input(input_type='totp') to ask the user."
                )
            elif not login_success and error_text:
                state["next_action"] = f"Login failed: {error_text}"
            elif login_success:
                state["next_action"] = (
                    "Login succeeded. Call save_auth_state to capture session."
                )

            logger.info(
                "login_form result: success=%s url_changed=%s captcha=%s mfa=%s error=%s",
                login_success,
                url_changed,
                captcha_detected,
                mfa_detected,
                error_text,
            )
        except Exception as e:
            logger.debug("login_form result detection failed (non-fatal): %s", e)

        return state

    def handle_totp(
        self,
        totp_secret: str,
        field_selector: str | None = None,
        tab_id: str | None = None,
        totp_digits: int = 6,
        totp_period: int = 30,
    ) -> dict[str, Any]:
        with self._execution_lock:
            return self._run_async(
                self._handle_totp(
                    totp_secret,
                    field_selector or _DEFAULT_TOTP_FIELD_SEL,
                    tab_id,
                    totp_digits,
                    totp_period,
                )
            )

    async def _handle_totp(
        self,
        totp_secret: str,
        field_selector: str,
        tab_id: str | None,
        totp_digits: int = 6,
        totp_period: int = 30,
    ) -> dict[str, Any]:
        try:
            import base64

            padded = totp_secret.upper().replace(" ", "")
            padding = (8 - len(padded) % 8) % 8
            base64.b32decode(padded + "=" * padding)
        except Exception:
            return {
                "error": (
                    f"Invalid TOTP secret format. Must be Base32 (A-Z, 2-7, = padding). "
                    f"Got: '{totp_secret[:20]}{'...' if len(totp_secret) > 20 else ''}'"
                ),
                "totp_success": False,
                "next_action": "Provide a valid Base32 TOTP secret or use request_user_input(input_type='totp') to enter code manually.",
            }

        try:
            import pyotp

            code = pyotp.TOTP(
                totp_secret, digits=totp_digits, interval=totp_period
            ).now()
        except ImportError:
            code = _generate_totp(totp_secret, period=totp_period, digits=totp_digits)

        tab_id = self._resolve_tab_id(tab_id)
        page = self.pages[tab_id]
        totp_url = page.url

        otp_filled = False
        for sel in field_selector.split(","):
            filled = False
            try:
                await page.fill(
                    sel.strip(), code, timeout=get_config().browser_totp_fill_timeout_ms
                )
                filled = True
            except Exception as e:
                logger.debug("handle_totp: fill failed for %s: %s", sel.strip(), e)
            if filled:
                otp_filled = True
                logger.debug("handle_totp: filled field %s with code", sel.strip())
                break
        if not otp_filled:
            logger.warning("handle_totp: no OTP field matched (%s)", field_selector)

        await asyncio.sleep(0.3)

        _submit_selectors = (
            'button[type="submit"]',
            'input[type="submit"]',
            'button:has-text("Verify")',
            'button:has-text("Validate")',
            'button:has-text("Authenticate")',
            'button:has-text("Continue")',
            'button:has-text("Submit")',
            'button:has-text("Confirm")',
            'button:has-text("Next")',
            'button:has-text("Log in")',
            'button:has-text("Sign in")',
            'button[class*="submit"]',
            'button[class*="verify"]',
        )
        submitted = False
        for sel in _submit_selectors:
            clicked = False
            try:
                await page.click(sel, timeout=2000)
                clicked = True
            except Exception as e:
                logger.debug("handle_totp: submit click failed for %s: %s", sel, e)
            if clicked:
                submitted = True
                break
        if not submitted:
            await page.keyboard.press("Enter")

        try:
            await page.wait_for_load_state(
                "domcontentloaded", timeout=get_config().browser_page_load_timeout_ms
            )
        except Exception:
            await asyncio.sleep(2)

        state = await self._get_page_state(tab_id)
        if self.context:
            state["auth_cookies"] = await self.context.cookies()
            state["auth_captured"] = True

        try:
            r = await page.evaluate(self._LOGIN_RESULT_JS)
            error_text = r.get("errorText")
            url_changed = page.url != totp_url
            totp_field_gone = not bool(
                await page.query_selector(
                    'input[autocomplete="one-time-code"],'
                    'input[name="totp"],input[name="otp"],input[name="code"]'
                )
            )
            totp_success = (url_changed or totp_field_gone) and not error_text
            state["totp_success"] = totp_success
            state["totp_error"] = error_text
            state["totp_code_used"] = code
            if not totp_success and error_text:
                state["next_action"] = (
                    f"TOTP verification failed: {error_text}. "
                    "The code may have expired — try calling handle_totp again with a fresh code, "
                    "or use request_user_input(input_type='totp') to ask the user."
                )
            elif totp_success:
                state["next_action"] = (
                    "TOTP verified. Call save_auth_state to capture session."
                )
            logger.info(
                "handle_totp result: success=%s url_changed=%s field_gone=%s error=%s",
                totp_success,
                url_changed,
                totp_field_gone,
                error_text,
            )
        except Exception as e:
            logger.debug("handle_totp result detection failed (non-fatal): %s", e)

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
            local_storage = await page.evaluate(
                "() => Object.fromEntries(Object.entries(localStorage))"
            )
        except Exception:
            local_storage = {}
        try:
            session_storage = await page.evaluate(
                "() => Object.fromEntries(Object.entries(sessionStorage))"
            )
        except Exception:
            session_storage = {}
        return {
            "auth_state": {
                "cookies": cookies,
                "local_storage": local_storage,
                "session_storage": session_storage,
                "captured_at": datetime.now().isoformat(),
            },
            "cookie_count": len(cookies),
            "local_storage_keys": list(local_storage.keys()),
            "session_storage_keys": list(session_storage.keys()),
            "message": (
                f"Captured {len(cookies)} cookies, "
                f"{len(local_storage)} localStorage items, "
                f"{len(session_storage)} sessionStorage items"
            ),
        }

    def inject_cookies(
        self, cookies: list[dict[str, Any]], tab_id: str | None = None
    ) -> dict[str, Any]:
        with self._execution_lock:
            return self._run_async(self._inject_cookies(cookies, tab_id))

    async def _inject_cookies(
        self, cookies: list[dict[str, Any]], tab_id: str | None
    ) -> dict[str, Any]:
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
            return self._run_async(
                self._oauth_authorize(oauth_url, callback_prefix, tab_id)
            )

    async def _oauth_authorize(
        self, oauth_url: str, callback_prefix: str, tab_id: str | None
    ) -> dict[str, Any]:
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
                await page.wait_for_url(
                    f"{callback_prefix}**",
                    timeout=get_config().browser_oauth_callback_timeout_ms,
                )
            else:
                await page.wait_for_load_state(
                    "networkidle",
                    timeout=get_config().browser_oauth_callback_timeout_ms,
                )
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
        state = await self._get_page_state(tab_id)
        if self.context:
            state["auth_cookies"] = await self.context.cookies()
        if captured_token:
            state["oauth_token"] = captured_token
        if captured_url:
            state["oauth_callback_url"] = captured_url
        return state

    _AUTH_STATUS_JS = """() => {
        const qs = (s) => { try { return document.querySelector(s); } catch(e) { return null; } };
        const qsa = (s) => { try { return document.querySelectorAll(s); } catch(e) { return []; } };

        // Positive signals (authenticated)
        const logoutEl = qs(
            'a[href*="logout"],a[href*="signout"],a[href*="sign-out"],a[href*="log-out"],' +
            'button[class*="logout"],form[action*="logout"],[data-action*="logout"]'
        );
        const profileEl = qs(
            '.user-menu,.user-avatar,.avatar,.profile-picture,' +
            '[data-user-id],[data-username],[data-user],' +
            'a[href*="/profile"],a[href*="/account"],a[href*="/settings"],' +
            '[aria-label*="account" i],[aria-label*="profile" i],' +
            '.UserAvatar,.gh-header-nav,.account-switcher'
        );
        const usernameEl = qs(
            '.username,.user-name,[data-username],.profile-name,' +
            '[class*="user-login"],[class*="account-name"],' +
            '.login,.viewer-login,strong[itemprop="name"]'
        );
        const usernameDisplay = usernameEl
            ? (usernameEl.textContent || '').trim().substring(0, 80)
            : null;

        // Negative signals (not authenticated)
        const loginFormEl = qs('form input[type="password"]');
        const loginLinkEl = qs(
            'a[href*="/login"],a[href*="/signin"],a[href*="/sign-in"],' +
            'a[href*="/auth/login"],a[href*="/users/sign_in"]'
        );

        // Score
        let score = 0;
        if (logoutEl) score += 3;
        if (profileEl) score += 2;
        if (usernameDisplay) score += 2;
        if (loginFormEl) score -= 3;
        if (loginLinkEl) score -= 1;

        const isAuthenticated = score > 0;
        const confidence = Math.min(Math.abs(score) / 5.0, 1.0);

        // Collect visible session cookies info
        const cookieCount = document.cookie.split(';').filter(c => c.trim()).length;

        return {
            isAuthenticated, confidence, score,
            hasLogout: !!logoutEl,
            hasProfile: !!profileEl,
            hasLoginForm: !!loginFormEl,
            hasLoginLink: !!loginLinkEl,
            usernameDisplay,
            cookieCount
        };
    }"""

    def check_auth_status(self, tab_id: str | None = None) -> dict[str, Any]:
        with self._execution_lock:
            return self._run_async(self._check_auth_status(tab_id))

    async def _check_auth_status(self, tab_id: str | None) -> dict[str, Any]:
        if not self.pages:
            return {"error": "No browser tab open. Call launch first."}
        tab_id = self._resolve_tab_id(tab_id)
        page = self.pages[tab_id]
        try:
            r = await page.evaluate(self._AUTH_STATUS_JS)
        except Exception as e:
            return {"error": f"Auth status check failed: {e}"}

        if not isinstance(r, dict) or "isAuthenticated" not in r:
            return {
                "error": "Auth status JS returned unexpected result — page may have blocked script execution.",
                "is_authenticated": None,
                "confidence": 0.0,
                "score": 0,
                "next_action": "Auth check inconclusive. Try view_source or screenshot to inspect the page manually.",
            }
        state = await self._get_page_state(tab_id)

        normalized: dict[str, Any] = {
            "is_authenticated": r.get("isAuthenticated", False),
            "confidence": r.get("confidence", 0.0),
            "score": r.get("score", 0),
            "has_logout": r.get("hasLogout", False),
            "has_profile": r.get("hasProfile", False),
            "has_login_form": r.get("hasLoginForm", False),
            "has_login_link": r.get("hasLoginLink", False),
            "username_display": r.get("usernameDisplay"),
            "cookie_count": r.get("cookieCount", 0),
        }
        state.update(normalized)
        if normalized["is_authenticated"]:
            msg = f"AUTHENTICATED (confidence {normalized['confidence']:.0%}, score {normalized['score']})"
            if normalized.get("username_display"):
                msg += f" — user: {normalized['username_display']}"
        else:
            msg = f"NOT AUTHENTICATED (confidence {normalized['confidence']:.0%}, score {normalized['score']})"
            if normalized["has_login_form"]:
                msg += " — login form present"
            elif normalized["has_login_link"]:
                msg += " — login link present"
        state["message"] = msg
        logger.info("check_auth_status: %s", msg)
        return state

    def wait_for_element(
        self,
        wait_selector: str,
        timeout: float = 10.0,
        state: str = "visible",
        tab_id: str | None = None,
    ) -> dict[str, Any]:
        with self._execution_lock:
            return self._run_async(
                self._wait_for_element(wait_selector, timeout, state, tab_id)
            )

    async def _wait_for_element(
        self,
        wait_selector: str,
        timeout: float,
        state: str,
        tab_id: str | None,
    ) -> dict[str, Any]:
        if not self.pages:
            return {"error": "No browser tab open. Call launch first."}
        tab_id = self._resolve_tab_id(tab_id)
        page = self.pages[tab_id]
        try:
            await page.wait_for_selector(
                wait_selector,
                state=state,  # type: ignore[arg-type]
                timeout=int(timeout * 1000),
            )
            result = await self._get_page_state(tab_id)
            result["element_found"] = True
            result["wait_selector"] = wait_selector
            result["message"] = f"Element '{wait_selector}' is now {state}"
            return result
        except Exception as e:
            return {
                "element_found": False,
                "wait_selector": wait_selector,
                "error": f"Timeout waiting for '{wait_selector}' to be {state} after {timeout}s: {e}",
            }

    def list_tabs(self) -> dict[str, Any]:
        with self._execution_lock:
            tabs = {}
            for tid, page in self.pages.items():
                try:
                    url = page.url
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
                    self._close_context(), self._loop
                )
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
        return (
            self.is_running
            and self.context is not None
            and self._browser is not None
            and self._browser.is_connected()
        )


class BrowserTabManager:
    MAX_TABS = 3

    def __init__(
        self,
    ) -> None:
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
                    except Exception as e:
                        logger.debug(
                            "Expected failure closing dead browser during restart: %s",
                            e,
                        )
                self._browser = BrowserInstance()
            return self._browser

    def _ensure_launched(self) -> BrowserInstance:
        browser = self._get_browser()
        if browser.context is None:
            logger.info("Browser not yet launched — auto-launching on first use")
            try:
                browser.launch()
            except ValueError as e:
                if "already launched" not in str(e):
                    raise RuntimeError(f"Browser auto-launch failed: {e}") from e
        return browser

    _RESTARTABLE_ERRORS = (
        "target closed",
        "browser has been closed",
        "connection refused",
        "execution context was destroyed",
        "page crashed",
        "navigation failed",
        "session closed",
        "browser instance is not running",
    )

    def _safe_action(self, action_name: str, fn, *args, **kwargs) -> dict[str, Any]:
        try:
            result = fn(*args, **kwargs)
            if not isinstance(result, dict):
                result = {"result": result}
            return result
        except DeadHostError as e:
            logger.warning("Dead host in _safe_action(%s): %s", action_name, e.host)
            return {
                "success": False,
                "domain_dead": True,
                "host": e.host,
                "url": e.url,
                "reason": _classify_dead_reason(e.original_error),
                "error": f"Host unreachable: {e.host}",
                "next_action": (
                    f"SKIP: {e.host} is unreachable "
                    f"({_classify_dead_reason(e.original_error)}). Move on to next target."
                ),
            }
        except Exception as e:
            error_str = str(e)
            error_lower = error_str.lower()

            # Auth errors should not trigger a browser restart; return guidance.
            if _is_auth_error(error_lower):
                logger.info("Browser auth error during %s: %s", action_name, error_str)
                return {
                    "success": False,
                    "auth_required": True,
                    "auth_error": True,
                    "error": error_str[:500],
                    "message": (
                        "Authentication required or invalid credentials. "
                        "This is often HTTP Basic/Auth or a protected gateway."
                    ),
                    "next_action": (
                        "Provide valid credentials or switch to a different auth flow. "
                        "If this is HTTP Basic/Auth, try `curl -u user:pass <url>` or "
                        "use browser_action login_form only if a login page exists."
                    ),
                }

            # Redirect loops are server-side — restarting the browser never helps.
            # Return a structured result immediately so the AI can pivot.
            is_redirect_loop = (
                "too many redirects" in error_lower
                or "redirect loop" in error_lower
                or "redirected to static asset" in error_lower
            )
            if is_redirect_loop:
                # Extract the final URL from the error if present
                redirected_url = ""
                _final_m = re.search(r"final URL:\s*(\S+)", error_str)
                if _final_m:
                    redirected_url = _final_m.group(1)
                logger.warning(
                    "Browser redirect loop on %s — skipping restart (%s)",
                    action_name,
                    error_str[:200],
                )
                result = {
                    "success": False,
                    "redirect_loop": True,
                    "error": error_str[:500],
                    "message": (
                        "The page redirect chain exceeded 10 hops. This is usually caused by "
                        "tracking pixels, ad blockers, or SSO redirect chains — not a real page."
                    ),
                    "final_url": redirected_url[:200],
                    "next_action": (
                        "Do NOT retry the same URL. If it redirected to a third-party domain "
                        "(ads, analytics, SSO, or CDN), skip it and test the next endpoint. "
                        "If you need to see this page, try with JavaScript disabled or "
                        "use curl --head to inspect redirects manually."
                    ),
                }
                return result

            if _is_browser_error_page(error_lower):
                logger.info(
                    "Browser error page during %s: %s", action_name, error_str[:200]
                )
                return {
                    "success": False,
                    "browser_error_page": True,
                    "error": error_str[:500],
                    "message": (
                        "Navigation failed and Chromium showed an internal error page."
                    ),
                    "next_action": (
                        "Check for auth requirements, TLS/SSL issues, or proxy restrictions. "
                        "Try http_observe/curl to see the raw HTTP response, or retry after "
                        "setting valid credentials."
                    ),
                }

            if action_name == "goto" and "timeout" in error_lower:
                try:
                    inst = self._ensure_launched()
                    tab_id = inst.current_page_id
                    if tab_id:
                        try:
                            inst._run_async(
                                inst._execute_js("window.stop()", tab_id)  # type: ignore[arg-type]
                            )
                        except Exception as stop_err:
                            logger.debug("window.stop() failed after timeout: %s", stop_err)
                        state = inst._run_async(inst._get_page_state(tab_id))
                        state.update(
                            {
                                "success": False,
                                "timed_out": True,
                                "warning": "Navigation timed out; partial page state returned.",
                                "next_action": (
                                    "If this is an auth/SSO endpoint, use browser_action login_form "
                                    "or switch to http_observe for headers/cookies."
                                ),
                            }
                        )
                        logger.warning(
                            "Browser goto timed out; returning partial state (%s)",
                            error_str[:200],
                        )
                        return state
                except Exception as salvage_err:
                    logger.debug(
                        "Failed to salvage page state after timeout: %s", salvage_err
                    )
                logger.warning(
                    "Browser goto timed out; returning fallback response (%s)",
                    error_str[:200],
                )
                url = ""
                if args:
                    url = str(args[0])
                elif "url" in kwargs:
                    url = str(kwargs.get("url", ""))
                return {
                    "success": False,
                    "timed_out": True,
                    "url": url[:200] if url else "",
                    "error": error_str[:500],
                    "message": "Navigation timed out; target may be slow or blocked.",
                    "next_action": (
                        "Switch to http_observe/httpx for headers or retry later with a shorter timeout. "
                        "Avoid repeated browser goto on the same host."
                    ),
                }

            is_crash = any(
                k in error_lower
                for k in self._RESTARTABLE_ERRORS
            )
            if is_crash:
                with self._lock:
                    _can_restart = self._restart_count < 5
                    if _can_restart:
                        self._restart_count += 1
                    try:
                        if self._browser:
                            self._browser.close()
                    except Exception as e:
                        logger.debug("Expected failure closing crashed browser: %s", e)
                    self._browser = None
                if not _can_restart:
                    logger.error(
                        f"Browser action '{action_name}' failed (max restarts reached): {e}"
                    )
                    return {"error": f"Browser action failed: {e}"}
                logger.warning(
                    f"Browser crash during '{action_name}': {e}. Auto-restarting..."
                )

                try:
                    fresh = self._ensure_launched()
                    method = getattr(fresh, fn.__name__, None)
                    if method is None:
                        return {
                            "error": f"Browser crashed and could not rebind method '{fn.__name__}' after restart"
                        }
                    result = method(*args, **kwargs)
                    if not isinstance(result, dict):
                        result = {"result": result}
                    result["warning"] = "Browser was auto-restarted after crash"
                    return result
                except Exception as e2:
                    return {"error": f"Browser crashed and retry failed: {e2}"}
            else:
                e_str = str(e)
                error_str = f"Browser action failed: {e}"
                if "ERR_INVALID_AUTH_CREDENTIALS" in e_str:
                    error_str += (
                        " — This appears to be an authentication error. "
                        "Check that your credentials are valid, clear browser cookies/session data, "
                        "or try a different authentication approach."
                    )
                elif "timed out" in e_str.lower() and action_name in ("goto", "launch"):
                    # Extract URL from args for a targeted advisory
                    _url_hint = str(args[0]) if args else "target"
                    error_str += (
                        f" — {_url_hint} may be WAF-blocked, unreachable, or very slow. "
                        "PIVOT: use `http_observe` for lightweight HTTP probing, "
                        "or `execute: curl -sI -m 10 <url>` to check reachability without a browser. "
                        "Do NOT retry browser_action goto on the same URL."
                    )
                logger.error(f"Browser action '{action_name}' failed (non-crash): {e}")
                return {"error": error_str}

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
        result = self._safe_action("goto", self._ensure_launched().goto, url, tab_id)
        result.setdefault("message", f"Navigated to {url}")
        return result

    def click(self, coordinate: str, tab_id: str | None = None) -> dict[str, Any]:
        result = self._safe_action(
            "click", self._ensure_launched().click, coordinate, tab_id
        )
        result.setdefault("message", f"Clicked at {coordinate}")
        return result

    def type_text(self, text: str, tab_id: str | None = None) -> dict[str, Any]:
        result = self._safe_action(
            "type", self._ensure_launched().type_text, text, tab_id
        )
        result.setdefault("message", "Typed text")
        return result

    def scroll(self, direction: str, tab_id: str | None = None) -> dict[str, Any]:
        result = self._safe_action(
            "scroll", self._ensure_launched().scroll, direction, tab_id
        )
        result.setdefault("message", f"Scrolled {direction}")
        return result

    def back(self, tab_id: str | None = None) -> dict[str, Any]:
        result = self._safe_action("back", self._ensure_launched().back, tab_id)
        result.setdefault("message", "Navigated back")
        return result

    def forward(self, tab_id: str | None = None) -> dict[str, Any]:
        result = self._safe_action("forward", self._ensure_launched().forward, tab_id)
        result.setdefault("message", "Navigated forward")
        return result

    def new_tab(self, url: str | None = None) -> dict[str, Any]:

        browser = self._ensure_launched()
        tabs = browser.list_tabs()
        tab_count = tabs.get("count", 0)
        if tab_count >= self.MAX_TABS:
            return {
                "error": f"Tab limit reached ({self.MAX_TABS}). Close an existing tab first.",
                "tabs": tabs.get("tabs", {}),
            }
        result = self._safe_action("new_tab", browser.new_tab, url)
        result.setdefault("message", f"Created new tab {result.get('tab_id', '')}")
        return result

    def switch_tab(self, tab_id: str) -> dict[str, Any]:
        result = self._safe_action(
            "switch_tab", self._ensure_launched().switch_tab, tab_id
        )
        result.setdefault("message", f"Switched to tab {tab_id}")
        return result

    def close_tab(self, tab_id: str) -> dict[str, Any]:
        result = self._safe_action(
            "close_tab", self._ensure_launched().close_tab, tab_id
        )
        result.setdefault("message", f"Closed tab {tab_id}")
        return result

    def wait_browser(
        self, duration: float, tab_id: str | None = None
    ) -> dict[str, Any]:
        result = self._safe_action(
            "wait", self._ensure_launched().wait, duration, tab_id
        )
        result.setdefault("message", f"Waited {duration}s")
        return result

    def execute_js(
        self,
        js_code: str,
        tab_id: str | None = None,
        parallel: bool = False,
    ) -> dict[str, Any]:
        result = self._safe_action(
            "execute_js", self._ensure_launched().execute_js, js_code, tab_id, parallel
        )
        if parallel:
            result.setdefault(
                "message", "JavaScript executed in parallel across all open tabs"
            )
        else:
            result.setdefault("message", "JavaScript executed successfully")
        return result

    def double_click(
        self, coordinate: str, tab_id: str | None = None
    ) -> dict[str, Any]:
        result = self._safe_action(
            "double_click", self._ensure_launched().double_click, coordinate, tab_id
        )
        result.setdefault("message", f"Double clicked at {coordinate}")
        return result

    def hover(self, coordinate: str, tab_id: str | None = None) -> dict[str, Any]:
        result = self._safe_action(
            "hover", self._ensure_launched().hover, coordinate, tab_id
        )
        result.setdefault("message", f"Hovered at {coordinate}")
        return result

    def press_key(self, key: str, tab_id: str | None = None) -> dict[str, Any]:
        result = self._safe_action(
            "press_key", self._ensure_launched().press_key, key, tab_id
        )
        result.setdefault("message", f"Pressed key {key}")
        return result

    def save_pdf(self, file_path: str, tab_id: str | None = None) -> dict[str, Any]:
        result = self._safe_action(
            "save_pdf", self._ensure_launched().save_pdf, file_path, tab_id
        )
        result.setdefault("message", f"Page saved as PDF: {file_path}")
        return result

    def get_console_logs(
        self, tab_id: str | None = None, clear: bool = False
    ) -> dict[str, Any]:
        result = self._safe_action(
            "get_console_logs", self._ensure_launched().get_console_logs, tab_id, clear
        )
        result.setdefault("message", "Console logs retrieved")
        return result

    def get_network_logs(
        self, tab_id: str | None = None, clear: bool = False
    ) -> dict[str, Any]:
        result = self._safe_action(
            "get_network_logs", self._ensure_launched().get_network_logs, tab_id, clear
        )
        result.setdefault("message", "Network logs retrieved")
        return result

    def view_source(self, tab_id: str | None = None) -> dict[str, Any]:
        result = self._safe_action(
            "view_source", self._ensure_launched().view_source, tab_id
        )
        result.setdefault("message", "Page source retrieved")
        return result

    def screenshot(self, tab_id: str | None = None) -> dict[str, Any]:
        result = self._safe_action(
            "screenshot", self._ensure_launched().screenshot, tab_id
        )
        result.setdefault("message", "Screenshot taken")
        return result

    def login_form(
        self,
        url: str,
        username: str,
        password: str,
        username_selector: str = 'input[type="email"],input[name="username"],input[name="email"],#username,#email',
        password_selector: str = 'input[type="password"]',  # nosec B107
        submit_selector: str = 'button[type="submit"],input[type="submit"]',
        tab_id: str | None = None,
        multi_step: bool = False,
    ) -> dict[str, Any]:
        result = self._safe_action(
            "login_form",
            self._ensure_launched().login_form,
            url,
            username,
            password,
            username_selector,
            password_selector,
            submit_selector,
            tab_id,
            multi_step,
        )
        result.setdefault("message", f"Logged in via form at {url}")
        return result

    def handle_totp(
        self,
        totp_secret: str,
        field_selector: str = 'input[name="totp"],input[name="otp"],input[name="code"],input[placeholder*="code" i],input[placeholder*="OTP" i],input[placeholder*="authenticator" i]',
        tab_id: str | None = None,
        totp_digits: int = 6,
        totp_period: int = 30,
    ) -> dict[str, Any]:
        result = self._safe_action(
            "handle_totp",
            self._ensure_launched().handle_totp,
            totp_secret,
            field_selector,
            tab_id,
            totp_digits,
            totp_period,
        )
        result.setdefault("message", "TOTP code submitted")
        return result

    def solve_captcha(
        self,
        captcha_type: str,
        page_url: str = "",
        sitekey: str = "",
        tab_id: str | None = None,
    ) -> dict[str, Any]:
        """Auto-solve CAPTCHA using LLM vision or DOM bypass."""
        from .agent.captcha_solver import CaptchaSolver

        cfg = get_config()

        solver = CaptchaSolver(
            base_url=cfg.openai_base_url,
            captcha_model=cfg.openai_model,
            api_key=cfg.openai_api_key,
            timeout=cfg.llm_timeout,
        )

        try:
            browser = self._ensure_launched()
            tab_id = tab_id or browser.current_page_id
            if tab_id is None or tab_id not in browser.pages:
                return {"error": "No browser page available for CAPTCHA solving"}

            page = browser.pages[tab_id]

            # Build result using async event loop
            loop = browser._loop
            if loop is None:
                return {"error": "No event loop available for async CAPTCHA solving"}

            import asyncio

            # Run async page methods on the browser's event loop
            ss_future = asyncio.run_coroutine_threadsafe(
                page.screenshot(type="png", full_page=False),
                loop,
            )
            ss_bytes = ss_future.result(timeout=solver.timeout)
            ss_b64 = base64.b64encode(ss_bytes).decode("utf-8")

            content_future = asyncio.run_coroutine_threadsafe(
                page.content(), loop
            )
            page_html = content_future.result(timeout=solver.timeout)

            future = asyncio.run_coroutine_threadsafe(
                solver.solve_from_page(
                    page_screenshot_b64=ss_b64,
                    page_html=page_html,
                    captcha_type=captcha_type,
                ),
                loop,
            )
            solve_result = future.result(timeout=solver.timeout)

            # If DOM bypass was provided, execute it on the page
            if solve_result.get("bypass_js"):
                dom_result = page.evaluate(solve_result["bypass_js"])
                solve_result["dom_result"] = dom_result
                if isinstance(dom_result, dict) and dom_result.get("success"):
                    solve_result["success"] = True

            return {
                "captcha_type": captcha_type,
                "method": solve_result.get("method"),
                "success": solve_result.get("success", False),
                "solution": solve_result.get("solution"),
                "message": (
                    f"CAPTCHA solved via {solve_result.get('method', 'unknown')} ({captcha_type})"
                    if solve_result.get("success")
                    else f"CAPTCHA auto-solve failed for {captcha_type}"
                ),
            }

        except Exception as e:
            return {
                "captcha_type": captcha_type,
                "error": f"CAPTCHA solve failed: {e}",
            }

    def save_auth_state(self) -> dict[str, Any]:
        result = self._safe_action(
            "save_auth_state", self._ensure_launched().save_auth_state
        )
        result.setdefault("message", "Auth state captured")
        return result

    def inject_cookies(
        self, cookies: list[dict[str, Any]], tab_id: str | None = None
    ) -> dict[str, Any]:
        result = self._safe_action(
            "inject_cookies",
            self._ensure_launched().inject_cookies,
            cookies,
            tab_id,
        )
        result.setdefault("message", f"Injected {len(cookies)} cookies")
        return result

    def oauth_authorize(
        self, oauth_url: str, callback_prefix: str = "", tab_id: str | None = None
    ) -> dict[str, Any]:
        result = self._safe_action(
            "oauth_authorize",
            self._ensure_launched().oauth_authorize,
            oauth_url,
            callback_prefix,
            tab_id,
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
    timeout: float | None = None,
    url: str | None = None,
    coordinate: str | None = None,
    text: str | None = None,
    tab_id: str | None = None,
    js_code: str | None = None,
    parallel: bool = False,
    duration: float | None = None,
    wait: float | None = None,
    key: str | None = None,
    file_path: str | None = None,
    clear: bool = False,
    username: str | None = None,
    password: str | None = None,
    username_selector: str | None = None,
    password_selector: str | None = None,
    submit_selector: str | None = None,
    totp_secret: str | None = None,
    field_selector: str | None = None,
    cookies: list[dict[str, Any]] | None = None,
    oauth_url: str | None = None,
    callback_prefix: str = "",
    multi_step: bool = False,
    totp_digits: int = 6,
    totp_period: int = 30,
    wait_selector: str | None = None,
    wait_timeout: float = 10.0,
    wait_state: str = "visible",
    captcha_type: str | None = None,
    sitekey: str | None = None,
) -> dict[str, Any]:
    try:
        if wait is not None:
            if duration is None:
                duration = wait
            if wait_timeout == 10.0:
                wait_timeout = wait
        if url is None and oauth_url:
            url = oauth_url
        if action == "launch":
            return _manager.launch_browser(url)
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
            return _manager.new_tab(url)
        elif action == "switch_tab":
            return _manager.switch_tab(tab_id)  # type: ignore[arg-type]
        elif action == "close_tab":
            return _manager.close_tab(tab_id)  # type: ignore[arg-type]
        elif action == "wait":
            return _manager.wait_browser(duration, tab_id)  # type: ignore[arg-type]
        elif action == "execute_js":
            return _manager.execute_js(js_code, tab_id, parallel=parallel)  # type: ignore[arg-type]
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
        elif action == "screenshot":
            return _manager.screenshot(tab_id)

        elif action == "login_form":
            if not url or not username or not password:
                return {"error": "login_form requires: url, username, password"}
            return _manager.login_form(
                url,
                username,
                password,
                username_selector=username_selector or _DEFAULT_USERNAME_SEL,
                password_selector=password_selector or _DEFAULT_PASSWORD_SEL,
                submit_selector=submit_selector or _DEFAULT_SUBMIT_SEL,
                tab_id=tab_id,
                multi_step=multi_step,
            )
        elif action == "handle_totp":
            if not totp_secret:
                return {"error": "handle_totp requires: totp_secret"}
            return _manager.handle_totp(
                totp_secret,
                field_selector=field_selector or _DEFAULT_TOTP_FIELD_SEL,
                tab_id=tab_id,
                totp_digits=totp_digits,
                totp_period=totp_period,
            )
        elif action == "solve_captcha":
            if not captcha_type:
                return {
                    "error": "solve_captcha requires: captcha_type (recaptcha/hcaptcha/cloudflare_turnstile/unknown)"
                }
            return _manager.solve_captcha(
                captcha_type=captcha_type,
                page_url=url or "",
                sitekey=sitekey or "",
                tab_id=tab_id,
            )
        elif action == "save_auth_state":
            return _manager.save_auth_state()
        elif action == "inject_cookies":
            if not cookies:
                return {
                    "error": "inject_cookies requires: cookies (list of cookie dicts)"
                }
            return _manager.inject_cookies(cookies, tab_id)
        elif action == "oauth_authorize":
            if not url:
                return {
                    "error": "oauth_authorize requires: url (OAuth authorization URL)"
                }
            return _manager.oauth_authorize(url, callback_prefix, tab_id)
        elif action == "check_auth_status":
            return _manager.check_auth_status(tab_id)
        elif action == "wait_for_element":
            if not wait_selector:
                return {
                    "error": "wait_for_element requires: wait_selector (CSS selector)"
                }
            return _manager.wait_for_element(
                wait_selector, wait_timeout, wait_state, tab_id
            )
        else:
            return {"error": f"Unknown action: {action}"}
    except Exception as e:
        logger.error("Browser action failed: %s", e)
        return {"error": str(e)}

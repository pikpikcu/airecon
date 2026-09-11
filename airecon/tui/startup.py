from __future__ import annotations

import asyncio
import json
import logging
import tempfile
import threading
import time
import urllib.request
from pathlib import Path
from typing import Any

from textual.app import ComposeResult
from textual.containers import Vertical
from textual.screen import Screen
from textual.widgets import Label, Static

logger = logging.getLogger("airecon.startup")

_MAX_PROXY_RESTARTS: int = 3
_MIN_STABLE_SECONDS: float = 30.0
_PROXY_POLL_INTERVAL_SECONDS_FAST: float = 0.1
_PROXY_POLL_INTERVAL_SECONDS_MEDIUM: float = 0.2
_PROXY_POLL_INTERVAL_SECONDS_SLOW: float = 0.3
_PROXY_STATUS_TIMEOUT_SECONDS: float = 1.2
_PROXY_START_TIMEOUT_SECONDS: float = 35.0
_PROXY_START_TIMEOUT_RESUME_SECONDS: float = 60.0
_PROXY_START_EXTRA_GRACE_SECONDS: float = 25.0

_proxy_thread: threading.Thread | None = None
_proxy_fatal_error: list[str] = []

# Single source of truth for the crash-log location so error messages can show
# the FULL path (users were told to "check airecon_proxy_crash.log" without
# knowing which temp dir it lives in — on macOS/Windows that is not /tmp).
_CRASH_LOG_PATH: Path = Path(tempfile.gettempdir()) / "airecon_proxy_crash.log"


def get_crash_log_path() -> str:
    return str(_CRASH_LOG_PATH)


def _write_crash_log(header: str) -> None:
    """Append the current exception traceback to the crash log (best-effort)."""
    import traceback as _tb

    try:
        with open(_CRASH_LOG_PATH, "a", encoding="utf-8") as f:
            f.write(f"\n=== {header} ===\n")
            _tb.print_exc(file=f)
    except Exception as e:
        logger.debug("could not write crash log: %s", e)


def is_proxy_alive() -> bool:
    return _proxy_thread is not None and _proxy_thread.is_alive()


def get_proxy_fatal_error() -> str | None:
    return _proxy_fatal_error[0] if _proxy_fatal_error else None


def _proxy_thread_body() -> None:
    import os as _os
    import logging as _log

    _debug_mode = bool(_os.environ.get("AIRECON_DEBUG"))
    if _debug_mode:
        from airecon.logger import setup_logging as _setup_logging

        _setup_logging(is_tui=True)

    if not _debug_mode:
        _log.getLogger("airecon").setLevel(_log.CRITICAL)
        _log.getLogger("uvicorn.access").setLevel(_log.CRITICAL)
    for _n in ("uvicorn", "uvicorn.error", "httpx", "httpcore"):
        _log.getLogger(_n).setLevel(_log.CRITICAL)

    # Import inside the guarded body: an import-time failure (missing dependency,
    # bad config, syntax error in a proxy module) is the most common reason the
    # thread dies WITHOUT a crash log being written. Capture it so the user gets
    # both a log file and a visible reason instead of a silent "thread stopped".
    try:
        from airecon.proxy.server import run_server
    except BaseException as exc:  # noqa: BLE001 - must surface any startup failure
        logger.error("Proxy failed to import/start: %s", exc)
        _write_crash_log(f"Proxy import/startup failure: {exc!r}")
        _proxy_fatal_error.append(
            f"Proxy failed to start: {exc} (see {_CRASH_LOG_PATH})"
        )
        return

    _restart_count = 0
    _restart_delay = 2.0

    while True:
        _t0 = time.monotonic()
        try:
            run_server()
            # run_server returning normally (e.g. uvicorn exited because the port
            # was already in use) is also a failure to keep serving — record it.
            _proxy_fatal_error.append(
                f"Proxy server exited unexpectedly without an error "
                f"(possible port conflict on the proxy port). See {_CRASH_LOG_PATH}"
            )
            break
        except KeyboardInterrupt:
            break
        except Exception as exc:
            _elapsed = time.monotonic() - _t0
            logger.error(
                "Proxy server crashed after %.1fs (restart #%d): %s",
                _elapsed,
                _restart_count,
                exc,
            )
            _write_crash_log(
                f"Crash (elapsed={_elapsed:.1f}s, attempt #{_restart_count}): {exc!r}"
            )

            if _elapsed >= _MIN_STABLE_SECONDS:
                _restart_count = 0

            if _restart_count >= _MAX_PROXY_RESTARTS:
                _proxy_fatal_error.append(
                    f"Proxy crashed {_MAX_PROXY_RESTARTS + 1} times: {exc} "
                    f"(see {_CRASH_LOG_PATH})"
                )
                logger.error(
                    "Proxy exhausted %d restart attempts — giving up. "
                    "Check airecon_proxy_crash.log for details.",
                    _MAX_PROXY_RESTARTS,
                )
                break

            _restart_count += 1
            logger.warning(
                "Restarting proxy in %.0fs (attempt %d/%d)…",
                _restart_delay,
                _restart_count,
                _MAX_PROXY_RESTARTS,
            )
            time.sleep(_restart_delay)
            _restart_delay = min(_restart_delay * 1.5, 10.0)


def _start_proxy_thread() -> None:
    global _proxy_thread, _proxy_fatal_error
    _proxy_fatal_error.clear()
    _proxy_thread = threading.Thread(
        target=_proxy_thread_body,
        daemon=True,
        name="airecon-proxy",
    )
    _proxy_thread.start()
    logger.debug("Proxy daemon thread started")


_SPINNER = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
_STEP_IDS = [
    "step-docker",
    "step-searxng",
    "step-proxy",
    "step-llm",
    "step-engine",
]

_STEP_LABELS: dict[str, str] = {
    "step-docker": "Docker Sandbox",
    "step-searxng": "SearXNG",
    "step-proxy": "Proxy Server",
    "step-llm": "LLM",
    "step-engine": "Docker Engine",
}


def _write_config_value(key: str, value: str) -> None:
    import yaml
    from pathlib import Path

    config_file = Path.home() / ".airecon" / "config.yaml"
    try:
        current: dict = {}
        if config_file.exists():
            with open(config_file) as f:
                loaded = yaml.safe_load(f)
                if isinstance(loaded, dict):
                    current = loaded
        current[key] = value
        with open(config_file, "w") as f:
            yaml.dump(current, f, indent=2, default_flow_style=False)
        from airecon.proxy.config import reload_config

        reload_config()
    except Exception as e:
        logger.warning("Could not persist config %s: %s", key, e)


class StartupScreen(Screen[bool]):
    DEFAULT_CSS = ""

    def __init__(
        self,
        proxy_url: str,
        no_proxy: bool = False,
        session_id: str | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(**kwargs)
        self.proxy_url = proxy_url.rstrip("/")
        self.no_proxy = no_proxy
        self.session_id = session_id
        self._step_states: dict[str, tuple[str, str]] = {}
        self._spinner_frame: int = 0

    def compose(self) -> ComposeResult:
        from airecon._version import __version__ as _ver

        with Vertical(id="startup-box"):
            yield Static(
                "[bold #00d4aa]  ▄▖▄▖▄▖[/]\n"
                "[bold #00d4aa]  ▌▌▐ ▙▘█▌▛▘▛▌▛▌[/]\n"
                "[bold #00d4aa]  ▛▌▟▖▌▌▙▖▙▖▙▌▌▌[/]\n"
                f"  [#8b949e]AI-Powered Security Reconnaissance[/]"
                f"  [#484f58]v{_ver}[/]",
                id="startup-logo",
            )
            yield Static(
                "[#21262d]  " + "─" * 46 + "[/]",
                id="startup-divider",
            )
            for sid in _STEP_IDS:
                yield Label("", id=sid, classes="startup-step")
            yield Static("", id="startup-status")
            if self.session_id:
                yield Static(
                    f"  [#f59e0b]↺  Resuming session:[/] [#484f58]{self.session_id}[/]",
                    id="startup-session",
                )

    def on_mount(self) -> None:
        for sid in _STEP_IDS:
            self._step_states[sid] = ("pending", "")
            self._render_step(sid)
        self.set_interval(0.1, self._tick_spinner)
        startup_task = self._run_startup()
        if asyncio.iscoroutine(startup_task):
            self.run_worker(startup_task, exclusive=True)

    def _render_step(self, step_id: str) -> None:
        state, detail = self._step_states.get(step_id, ("pending", ""))
        label = _STEP_LABELS.get(step_id, step_id)
        if step_id == "step-llm":
            label = "LLM (OpenAI-compatible)"
        spinner_char = _SPINNER[self._spinner_frame % len(_SPINNER)]
        icons = {
            "pending": "[#484f58]○[/]",
            "running": f"[#f59e0b]{spinner_char}[/]",
            "ok": "[bold #00d4aa]✓[/]",
            "fail": "[bold #ef4444]✗[/]",
            "warn": "[bold #f59e0b]⚠[/]",
            "skip": "[#484f58]—[/]",
        }
        colors = {
            "pending": "#484f58",
            "running": "#f59e0b",
            "ok": "#00d4aa",
            "fail": "#ef4444",
            "warn": "#f59e0b",
            "skip": "#484f58",
        }
        icon = icons.get(state, "○")
        color = colors.get(state, "#8b949e")
        text = detail if detail else ("waiting" if state == "pending" else "")
        try:
            self.query_one(f"#{step_id}", Label).update(
                f"  {icon}  [bold]{label:<24}[/] [{color}]{text}[/]"
            )
        except Exception as e:
            logger.debug("Expected failure in _render_step update label: %s", e)

    def _set_step(self, step_id: str, state: str, detail: str = "") -> None:
        self._step_states[step_id] = (state, detail)
        self._render_step(step_id)

    def _tick_spinner(self) -> None:
        self._spinner_frame += 1
        for sid in _STEP_IDS:
            if self._step_states.get(sid, ("", ""))[0] == "running":
                self._render_step(sid)

    def _set_status(self, markup: str) -> None:
        try:
            self.query_one("#startup-status", Static).update(f"\n  {markup}")
        except Exception as e:
            logger.debug("Expected failure in _set_status: %s", e)

    def _proxy_start_timeout_seconds(self) -> float:
        return (
            _PROXY_START_TIMEOUT_RESUME_SECONDS
            if self.session_id
            else _PROXY_START_TIMEOUT_SECONDS
        )

    def _proxy_poll_interval_seconds(self, elapsed_seconds: float) -> float:
        if elapsed_seconds < 8.0:
            return _PROXY_POLL_INTERVAL_SECONDS_FAST
        if elapsed_seconds < 25.0:
            return _PROXY_POLL_INTERVAL_SECONDS_MEDIUM
        return _PROXY_POLL_INTERVAL_SECONDS_SLOW

    async def _run_startup(self) -> None:
        from airecon.proxy.config import get_config

        cfg = get_config()

        self._set_step("step-docker", "running", "checking image…")
        self._set_status(
            "[#8b949e]Building Docker sandbox (first run may take a few minutes)…[/]"
        )
        from airecon.proxy.docker import DockerEngine

        engine = DockerEngine()
        if cfg.docker_auto_build:
            ok = await engine.ensure_image()
            if not ok:
                self._set_step("step-docker", "fail", "image build failed")
                self._set_status(
                    "[#ef4444]✗ Docker image build failed.[/] "
                    "[#484f58]Run: docker build -t airecon-sandbox .[/]"
                )
                return
        else:
            # Auto-build disabled: never trigger a heavy build implicitly.
            if not await engine.image_exists():
                self._set_step("step-docker", "fail", "image missing")
                self._set_status(
                    "[#ef4444]✗ Sandbox image not found and auto-build is off.[/] "
                    "[#484f58]Run: docker build -t airecon-sandbox .[/]"
                )
                return
        self._set_step("step-docker", "ok", "ready")

        _should_manage = (
            not cfg.searxng_url
            or "localhost" in cfg.searxng_url
            or "127.0.0.1" in cfg.searxng_url
        )
        if _should_manage:
            self._set_step("step-searxng", "running", "starting container…")
            self._set_status("[#8b949e]Starting SearXNG search engine…[/]")
            from airecon.proxy.searxng import get_shared_manager

            _mgr = get_shared_manager()
            _url = await _mgr.ensure_running()
            if _url:
                if not cfg.searxng_url:
                    _write_config_value("searxng_url", _url)
                self._set_step("step-searxng", "ok", "ready")
            else:
                self._set_step("step-searxng", "warn", "fallback: DuckDuckGo")
        else:
            self._set_step("step-searxng", "ok", "external")

        if self.no_proxy:
            self._set_step("step-proxy", "skip", "skipped (--no-proxy)")
            self._set_step("step-llm", "skip", "—")
            self._set_step("step-engine", "skip", "—")
        else:
            self._set_step("step-proxy", "running", "starting…")
            self._set_status("[#8b949e]Starting proxy server…[/]")

            _start_proxy_thread()

            proxy_ok = False
            docker_ok = False
            llm_ok = False
            _poll_timeout = _PROXY_STATUS_TIMEOUT_SECONDS
            _startup_started = time.monotonic()
            _startup_deadline = _startup_started + self._proxy_start_timeout_seconds()
            _attempt = 0
            while time.monotonic() < _startup_deadline:
                _attempt += 1
                _fatal = get_proxy_fatal_error()
                if _fatal:
                    self._set_step("step-proxy", "fail", _fatal[:44])
                    self._set_status(
                        f"[#ef4444]✗ Proxy crashed:[/] [#8b949e]{_fatal[:200]}[/]\n"
                        f"[#484f58]Log: {get_crash_log_path()}[/]"
                    )
                    return

                if not is_proxy_alive():
                    _why = get_proxy_fatal_error() or "no recorded error"
                    self._set_step("step-proxy", "fail", "thread stopped")
                    self._set_status(
                        "[#ef4444]✗ Proxy thread stopped before responding.[/] "
                        f"[#8b949e]{_why[:200]}[/]\n"
                        f"[#484f58]Log: {get_crash_log_path()}[/]"
                    )
                    return

                try:
                    req = urllib.request.urlopen(
                        f"{self.proxy_url}/api/status", timeout=_poll_timeout
                    )  # nosec B310 - self.proxy_url is localhost http://127.0.0.1:8000, not user-controlled
                    data = json.loads(req.read())
                    docker_ok = data.get("docker", {}).get("connected", False)
                    llm_ok = data.get("llm", {}).get("connected", False)
                    proxy_ok = True
                    break
                except Exception as e:
                    logger.debug("Proxy poll attempt %d failed: %s", _attempt, e)
                    _elapsed_f = max(0.0, time.monotonic() - _startup_started)
                    _sleep_for = self._proxy_poll_interval_seconds(_elapsed_f)
                    await asyncio.sleep(_sleep_for)
                    _elapsed = int(_elapsed_f)
                    self._set_step("step-proxy", "running", f"warming up… {_elapsed}s")

            if not proxy_ok and is_proxy_alive() and not get_proxy_fatal_error():
                logger.warning(
                    "Proxy still warming up after %.0fs — entering extra grace window %.0fs",
                    self._proxy_start_timeout_seconds(),
                    _PROXY_START_EXTRA_GRACE_SECONDS,
                )
                self._set_status(
                    "[#f59e0b]Proxy still warming up…[/] "
                    "[#8b949e]Waiting extra grace window for backend readiness.[/]"
                )
                _grace_started = time.monotonic()
                _grace_deadline = _grace_started + _PROXY_START_EXTRA_GRACE_SECONDS
                while time.monotonic() < _grace_deadline:
                    try:
                        req = urllib.request.urlopen(
                            f"{self.proxy_url}/api/status", timeout=_poll_timeout
                        )  # nosec B310
                        data = json.loads(req.read())
                        docker_ok = data.get("docker", {}).get("connected", False)
                        llm_ok = data.get("llm", {}).get("connected", False)
                        proxy_ok = True
                        break
                    except Exception as e:
                        logger.debug("Proxy grace poll failed: %s", e)
                        _grace_elapsed_f = max(0.0, time.monotonic() - _grace_started)
                        _sleep_for = self._proxy_poll_interval_seconds(_grace_elapsed_f)
                        await asyncio.sleep(_sleep_for)
                        _grace_elapsed = int(_grace_elapsed_f)
                        self._set_step(
                            "step-proxy", "running", f"extra warm-up… {_grace_elapsed}s"
                        )

            if not proxy_ok:
                self._set_step("step-proxy", "fail", "no response (startup timeout)")
                self._set_status(
                    "[#ef4444]✗ Proxy did not start in time.[/] "
                    f"[#484f58]Check port conflicts and {get_crash_log_path()}[/]"
                )
                return

            self._set_step("step-proxy", "ok", "ready")
            self._set_step(
                "step-llm",
                "ok" if llm_ok else "warn",
                "connected" if llm_ok else "unavailable",
            )
            self._set_step(
                "step-engine",
                "ok" if docker_ok else "warn",
                "connected" if docker_ok else "initializing…",
            )

        self._set_status(
            "[bold #00d4aa]✓ All systems ready.[/]  [#484f58]Launching interface…[/]"
        )
        await asyncio.sleep(0.7)
        self.dismiss(True)

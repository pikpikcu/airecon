"""Startup screen — shown while AIRecon services initialize inside the TUI."""

from __future__ import annotations

import asyncio
import json
import logging
import threading
import urllib.request
from typing import Any

from textual.app import ComposeResult
from textual.containers import Vertical
from textual.screen import Screen
from textual.widgets import Label, Static
from textual import work

logger = logging.getLogger("airecon.startup")

_SPINNER = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"

_STEP_IDS = [
    "step-docker",
    "step-searxng",
    "step-proxy",
    "step-ollama",
    "step-engine",
]

_STEP_LABELS: dict[str, str] = {
    "step-docker":  "Docker Sandbox",
    "step-searxng": "SearXNG",
    "step-proxy":   "Proxy Server",
    "step-ollama":  "Ollama",
    "step-engine":  "Docker Engine",
}


def _write_config_value(key: str, value: str) -> None:
    """Persist a single key into ~/.airecon/config.json."""
    import json as _json
    from pathlib import Path
    config_file = Path.home() / ".airecon" / "config.json"
    try:
        current: dict = {}
        if config_file.exists():
            with open(config_file) as f:
                current = _json.load(f)
        current[key] = value
        with open(config_file, "w") as f:
            _json.dump(current, f, indent=4)
        from airecon.proxy.config import reload_config
        reload_config()
    except Exception as e:
        logger.warning("Could not persist config %s: %s", key, e)


class StartupScreen(Screen[bool]):
    """Full-screen TUI startup with live per-service progress indicators."""

    DEFAULT_CSS = ""  # Styles defined in styles.tcss

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
        # state per step: (state, detail)
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
        self._run_startup()

    # ── Rendering helpers ──────────────────────────────────────────

    def _render_step(self, step_id: str) -> None:
        state, detail = self._step_states.get(step_id, ("pending", ""))
        label = _STEP_LABELS.get(step_id, step_id)
        spinner_char = _SPINNER[self._spinner_frame % len(_SPINNER)]
        icons = {
            "pending": "[#484f58]○[/]",
            "running": f"[#f59e0b]{spinner_char}[/]",
            "ok":      "[bold #00d4aa]✓[/]",
            "fail":    "[bold #ef4444]✗[/]",
            "warn":    "[bold #f59e0b]⚠[/]",
            "skip":    "[#484f58]—[/]",
        }
        colors = {
            "pending": "#484f58",
            "running": "#f59e0b",
            "ok":      "#00d4aa",
            "fail":    "#ef4444",
            "warn":    "#f59e0b",
            "skip":    "#484f58",
        }
        icon = icons.get(state, "○")
        color = colors.get(state, "#8b949e")
        text = detail if detail else ("waiting" if state == "pending" else "")
        try:
            self.query_one(f"#{step_id}", Label).update(
                f"  {icon}  [bold]{label:<24}[/] [{color}]{text}[/]"
            )
        except Exception:  # nosec B110
            pass

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
            self.query_one("#startup-status", Static).update(
                f"\n  {markup}"
            )
        except Exception:  # nosec B110
            pass

    # ── Startup worker ─────────────────────────────────────────────

    @work(exclusive=True)
    async def _run_startup(self) -> None:
        """Run all service checks sequentially, updating the UI live."""
        from airecon.proxy.config import get_config
        cfg = get_config()

        # ── 1. Docker Sandbox ──────────────────────────────────────
        self._set_step("step-docker", "running", "checking image…")
        self._set_status(
            "[#8b949e]Building Docker sandbox (first run may take a few minutes)…[/]"
        )
        from airecon.proxy.docker import DockerEngine
        engine = DockerEngine()
        ok = await engine.ensure_image()
        if not ok:
            self._set_step("step-docker", "fail", "image build failed")
            self._set_status(
                "[#ef4444]✗ Docker image build failed.[/] "
                "[#484f58]Run: docker build -t airecon-sandbox .[/]"
            )
            return
        self._set_step("step-docker", "ok", "ready")

        # ── 2. SearXNG ────────────────────────────────────────────
        _should_manage = (
            not cfg.searxng_url
            or "localhost" in cfg.searxng_url
            or "127.0.0.1" in cfg.searxng_url
        )
        if _should_manage:
            self._set_step("step-searxng", "running", "starting container…")
            self._set_status("[#8b949e]Starting SearXNG search engine…[/]")
            from airecon.proxy.searxng import SearXNGManager
            _mgr = SearXNGManager()
            _url = await _mgr.ensure_running()
            if _url:
                if not cfg.searxng_url:
                    _write_config_value("searxng_url", _url)
                self._set_step("step-searxng", "ok", "ready")
            else:
                self._set_step("step-searxng", "warn", "fallback: DuckDuckGo")
        else:
            self._set_step("step-searxng", "ok", "external")

        # ── 3. Proxy Server ───────────────────────────────────────
        if self.no_proxy:
            self._set_step("step-proxy", "skip", "skipped (--no-proxy)")
            self._set_step("step-ollama", "skip", "—")
            self._set_step("step-engine", "skip", "—")
        else:
            self._set_step("step-proxy", "running", "starting…")
            self._set_status("[#8b949e]Starting proxy server…[/]")

            proxy_error: list[str] = []

            def _start_proxy() -> None:
                import logging as _log
                for _n in (
                    "airecon", "uvicorn", "uvicorn.access",
                    "uvicorn.error", "httpx", "httpcore",
                ):
                    _log.getLogger(_n).setLevel(_log.CRITICAL)
                try:
                    from airecon.proxy.server import run_server
                    run_server()
                except Exception as e:
                    proxy_error.append(str(e))
                    import traceback
                    with open("airecon_proxy_crash.log", "w") as f:
                        traceback.print_exc(file=f)

            threading.Thread(target=_start_proxy, daemon=True).start()

            proxy_ok = False
            docker_ok = False
            ollama_ok = False
            for attempt in range(60):
                if proxy_error:
                    self._set_step("step-proxy", "fail", proxy_error[0][:44])
                    self._set_status(
                        "[#ef4444]✗ Proxy crashed — check airecon_proxy_crash.log[/]"
                    )
                    return
                try:
                    req = urllib.request.urlopen(  # nosec B310
                        f"{self.proxy_url}/api/status", timeout=2
                    )
                    data = json.loads(req.read())
                    docker_ok = data.get("docker", {}).get("connected", False)
                    ollama_ok = data.get("ollama", {}).get("connected", False)
                    proxy_ok = True
                    break
                except Exception:
                    await asyncio.sleep(0.4)
                    dots = "." * ((attempt % 3) + 1)
                    self._set_step("step-proxy", "running", f"starting{dots}")

            if not proxy_ok:
                self._set_step("step-proxy", "fail", "no response (port conflict?)")
                self._set_status(
                    "[#ef4444]✗ Proxy did not start.[/] "
                    "[#484f58]Check for port conflicts.[/]"
                )
                return

            self._set_step("step-proxy", "ok", "ready")
            self._set_step(
                "step-ollama",
                "ok" if ollama_ok else "warn",
                "connected" if ollama_ok else "unavailable",
            )
            self._set_step(
                "step-engine",
                "ok" if docker_ok else "warn",
                "connected" if docker_ok else "initializing…",
            )

        # ── Done ──────────────────────────────────────────────────
        self._set_status(
            "[bold #00d4aa]✓ All systems ready.[/]  "
            "[#484f58]Launching interface…[/]"
        )
        await asyncio.sleep(0.7)
        self.dismiss(True)

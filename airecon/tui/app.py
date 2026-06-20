from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import time
import uuid
from pathlib import Path
from functools import lru_cache
from typing import Any

import httpx
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, DirectoryTree, Header, Input, Label, Static

from airecon.proxy.config import get_workspace_root

from .widgets.chat import ChatPanel, ToolMessageSelected
from .widgets.file_preview import FilePreviewScreen
from .widgets.input import CommandInput, SlashCompleter
from .widgets.path_completer import PathCompleter
from .widgets.status import SkillsModal, StatusBar
from .widgets.workspace import WorkspacePanel, WorkspaceTree

logger = logging.getLogger("airecon.tui")


class QuitConfirmScreen(ModalScreen[bool]):
    DEFAULT_CSS = ""

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Label("  Quit AIRecon?", id="title")
            yield Label("Active sessions will be saved.", id="msg")
            with Horizontal():
                yield Button("Yes, quit", variant="error", id="yes")
                yield Button("No, stay", variant="success", id="no")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(event.button.id == "yes")

    def on_key(self, event) -> None:
        if event.key == "escape":
            self.dismiss(False)
        elif event.key == "enter":
            self.dismiss(False)
        elif event.key == "y":
            self.dismiss(True)
        elif event.key == "n":
            self.dismiss(False)


class UserInputModal(ModalScreen[str | None]):
    _TYPE_META: dict[str, tuple[str, str, str, bool]] = {
        "totp": (
            "🔐",
            "TOTP / 2FA Code",
            "⏱  Code expires every 30s — enter it quickly after seeing this dialog.",
            True,
        ),
        "captcha": (
            "🤖",
            "CAPTCHA Answer",
            "Look at the CAPTCHA image (path shown below) and type the text you see.",
            False,
        ),
        "password": (
            "🔑",
            "Password",
            "Input is masked. Press Enter or click Submit when done.",
            True,
        ),
        "otp": (
            "📱",
            "One-Time Password (SMS / Email)",
            "Check your phone or email for the OTP code. It may expire in 60–120s.",
            True,
        ),
        "text": (
            "✏️ ",
            "Input Required",
            "",
            False,
        ),
    }

    def __init__(self, prompt: str, input_type: str = "text") -> None:
        super().__init__()
        self._prompt_text = prompt
        self._input_type = input_type

    def _extract_screenshot_path(self) -> str | None:
        import re

        m = re.search(r"(/[\w/.\-_]+\.png)", self._prompt_text)
        return m.group(1) if m else None

    def compose(self) -> ComposeResult:
        icon, label, hint, mask = self._TYPE_META.get(
            self._input_type, self._TYPE_META["text"]
        )
        with Vertical():
            yield Label(f" {icon}  {label} ", id="modal-title")

            if hint:
                yield Label(hint, id="modal-hint")

            if self._input_type == "captcha":
                _path = self._extract_screenshot_path()
                if _path:
                    yield Label(f"📸 Screenshot: {_path}", id="modal-screenshot")

            yield Label(self._prompt_text, id="modal-prompt")

            _placeholder = {
                "totp": "Enter 6-digit code (e.g. 123456)…",
                "captcha": "Type CAPTCHA text here…",
                "password": "Enter password…",
                "otp": "Enter OTP code…",
            }.get(self._input_type, "Type here and press Enter…")

            yield Input(
                placeholder=_placeholder,
                password=mask,
                id="modal-input",
            )
            with Horizontal():
                yield Button("  Submit  ", variant="primary", id="submit")
                yield Button("  Cancel  ", variant="default", id="cancel")

    def on_mount(self) -> None:
        self.query_one("#modal-input", Input).focus()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "submit":
            value = self.query_one("#modal-input", Input).value
            self.dismiss(value or None)
        else:
            self.dismiss(None)

    def on_input_submitted(self, event: Input.Submitted) -> None:
        self.dismiss(event.value or None)

    def on_key(self, event) -> None:
        if event.key == "escape":
            self.dismiss(None)


class AIReconApp(App):
    TITLE = "AIRecon"
    SUB_TITLE = "AI Security Reconnaissance"
    CSS_PATH = "styles.tcss"
    _LLM_DEGRADED_SECONDS = 45.0
    BINDINGS = [
        Binding("ctrl+c", "request_quit", "Quit", show=True, priority=True),
        Binding("ctrl+q", "request_quit", "Quit", show=False, priority=True),
        Binding("ctrl+l", "clear", "Clear Chat", show=True),
        Binding("ctrl+r", "reset", "Reset", show=True),
        Binding("pageup", "scroll_chat_up", "Scroll Up", show=False),
        Binding("pagedown", "scroll_chat_down", "Scroll Down", show=False),
        Binding("escape", "cancel_generation", "Stop AI", show=True, priority=True),
    ]

    def action_scroll_chat_up(self) -> None:
        self.query_one("#chat-panel", ChatPanel).scroll_up()

    def action_scroll_chat_down(self) -> None:
        self.query_one("#chat-panel", ChatPanel).scroll_down()

    @staticmethod
    def _default_ctx_limit() -> int:
        try:
            from airecon.proxy.config import get_config

            ctx = int(get_config().llm_context_window)
            if ctx > 0:
                return ctx
        except Exception as e:
            logger.debug("Expected failure in _default_ctx_limit: %s", e)
        return 65536

    @staticmethod
    @lru_cache(maxsize=1)
    def _load_ui_tool_kinds() -> tuple[dict[str, str], set[str]]:
        kinds: dict[str, str] = {}
        fuzz_shells: set[str] = set()
        try:
            meta_path = Path(__file__).resolve().parents[1] / "proxy" / "data" / "tools_meta.json"
            data = json.loads(meta_path.read_text(encoding="utf-8"))
            raw_kinds = data.get("ui_tool_kinds", {})
            if isinstance(raw_kinds, dict):
                kinds = {str(k).lower(): str(v).lower() for k, v in raw_kinds.items()}
            categories = data.get("categories", {})
            vuln_scan = categories.get("vulnerability_scanning", {})
            if isinstance(vuln_scan, dict):
                for tools in vuln_scan.values():
                    if isinstance(tools, list):
                        fuzz_shells.update(str(t).lower() for t in tools)
        except Exception as e:
            logger.debug("Expected failure in _load_ui_tool_kinds: %s", e)
        return kinds, fuzz_shells

    @staticmethod
    def _classify_tool_kind(tool_name: str, arguments: dict | None = None) -> str | None:
        name = tool_name.lower()
        kind_map, fuzz_shells = AIReconApp._load_ui_tool_kinds()
        if name in kind_map:
            return kind_map[name]
        if name == "execute" and arguments:
            try:
                from airecon.proxy.agent.command_parse import extract_primary_binary

                cmd = str(arguments.get("command", ""))
                primary = extract_primary_binary(cmd)
                if primary and primary.lower() in fuzz_shells:
                    return "fuzz"
            except Exception as e:
                logger.debug("Expected failure in _classify_tool_kind: %s", e)
        return None

    def on_status_bar_skills_clicked(self, event: StatusBar.SkillsClicked) -> None:
        status_bar = self.query_one(StatusBar)
        if status_bar.skills_used:
            self.push_screen(SkillsModal(status_bar.skills_used))

    def __init__(
        self,
        proxy_url: str = "http://127.0.0.1:3000",
        no_proxy: bool = False,
        session_id: str | None = None,
        show_startup_screen: bool = True,
        auto_poll_services: bool = True,
        **kwargs,
    ) -> None:
        super().__init__(**kwargs)
        self.proxy_url = proxy_url.rstrip("/")
        self._no_proxy = no_proxy
        self._session_id = session_id
        self._show_startup_screen = show_startup_screen
        self._auto_poll_services = auto_poll_services
        _sse_timeout = httpx.Timeout(connect=10.0, read=None, write=10.0, pool=10.0)
        self._http = httpx.AsyncClient(base_url=self.proxy_url, timeout=_sse_timeout)
        self._processing = False
        self._chat_worker: asyncio.Task | None = None
        self._current_tool_id: str | None = None
        self._status_task: asyncio.Task | None = None
        self._health_check_task: asyncio.Task | None = None
        self._user_input_poll_task: asyncio.Task | None = None
        self._active_user_input_request_id: str = ""
        self._handled_user_input_request_ids: set[str] = set()
        self.current_context_path: Path | None = None
        self.active_file_content: str | None = None
        self.active_file_path: Path | None = None
        self._last_workspace_reload: float = 0.0
        self._last_scroll_time: float = 0.0
        self._last_sse_activity: float = 0.0
        self._copy_toast_task: asyncio.Task | None = None
        self._recon_frame: int = 0
        self._file_agents_running: int = 0
        self._llm_degraded_until: float = 0.0

    @staticmethod
    def _history_content_to_text(content: Any) -> str:
        if content is None:
            return ""
        if isinstance(content, str):
            return content
        if isinstance(content, (dict, list)):
            try:
                return json.dumps(content, ensure_ascii=False, indent=2)
            except Exception as e:
                logger.debug(
                    "Expected failure in _history_content_to_text json.dumps: %s", e
                )
                return str(content)
        return str(content)

    @classmethod
    def _history_entries_to_render(
        cls, messages: list[dict[str, Any]], limit: int = 250
    ) -> list[tuple[str, str]]:
        rendered: list[tuple[str, str]] = []
        for msg in (messages or [])[-limit:]:
            if not isinstance(msg, dict):
                continue

            role = str(msg.get("role") or "assistant").strip().lower()
            content = cls._history_content_to_text(msg.get("content")).strip()

            # Restore assistant tool-call intents even when content is empty.
            if role == "assistant" and not content and msg.get("tool_calls"):
                for call in msg.get("tool_calls", []):
                    if not isinstance(call, dict):
                        continue
                    fn = call.get("function") or {}
                    name = fn.get("name") or "tool"
                    args = fn.get("arguments")
                    args_text = cls._history_content_to_text(args).strip()
                    rendered.append(("tool", f"{name} {args_text}".strip()))
                continue

            if content:
                rendered.append((role, content))

        return rendered

    async def _restore_history_if_resumed(self, chat: ChatPanel) -> None:
        if not self._session_id:
            return

        try:
            resp = await self._http.get("/api/history", timeout=8.0)
            if resp.status_code != 200:
                return
            payload = resp.json() if isinstance(resp.json(), dict) else {}
            messages = payload.get("messages") or []
            entries = self._history_entries_to_render(messages)
            if not entries:
                return

            for role, content in entries:
                if role == "user":
                    chat.add_user_message(content)
                elif role == "assistant":
                    chat.add_assistant_message(content)
                elif role == "tool":
                    chat.add_tool_message(content)
                elif role == "error":
                    chat.add_error_message(content)
                else:
                    chat.add_system_message(content)

            source = payload.get("source") or "history"
            chat.add_system_message(
                f"↺ Restored {len(entries)} messages from `{source}` for session `{self._session_id}`"
            )
        except Exception as e:
            logger.debug("Failed to restore session history: %s", e)

    @staticmethod
    def _is_llm_recovery_marker(text: str) -> bool:
        lowered = (text or "").lower()
        return (
            "auto-recovery" in lowered
            or "vram crash" in lowered
            or "out of memory" in lowered
            or "cuda out of memory" in lowered
        )

    def _is_llm_degraded_active(self) -> bool:
        return self._llm_degraded_until > time.monotonic()

    def _should_show_llm_degraded(self, llm_ok: bool) -> bool:
        return bool(
            llm_ok and self._processing and self._is_llm_degraded_active()
        )

    def _mark_llm_degraded(self, reason: str = "") -> None:
        if not self._processing:
            return
        self._llm_degraded_until = max(
            self._llm_degraded_until,
            time.monotonic() + self._LLM_DEGRADED_SECONDS,
        )
        if reason:
            logger.warning(
                "Marking LLM status degraded due to recovery event: %s", reason
            )
        try:
            self.query_one("#status-bar", StatusBar).set_status(llm_degraded=True)
        except Exception as e:
            logger.debug("Expected failure in _mark_llm_degraded set_status: %s", e)

    def compose(self) -> ComposeResult:
        yield Header()

        with Container(id="copy-toast-wrap"):
            yield Static("", id="copy-toast-msg")

        yield WorkspacePanel(get_workspace_root(), id="workspace-panel")

        yield Static("", id="separator")

        with Container(id="chat-area"):
            yield ChatPanel(id="chat-panel")
            yield Static("", id="recon-bar")
            yield SlashCompleter(id="slash-completer")
            yield PathCompleter(id="path-completer")
            yield CommandInput(id="command-input")

        yield StatusBar(id="status-bar")

    async def on_mount(self) -> None:
        self.set_interval(0.1, self._tick_recon_spinner)

        try:
            self.query_one("#copy-toast-wrap", Container).display = False
        except Exception as e:
            logger.debug("Expected failure in on_mount hide copy toast: %s", e)

        try:
            self.query_one("#workspace-panel", WorkspacePanel).reload()
        except Exception as e:
            logger.debug("Expected failure in on_mount reload workspace: %s", e)

        chat = self.query_one("#chat-panel", ChatPanel)
        chat.add_assistant_message(
            "\n"
            "[bold #00d4aa]  ▄▖▄▖▄▖[/bold #00d4aa]\n"
            "[bold #00d4aa]  ▌▌▐ ▙▘█▌▛▘▛▌▛▌[/bold #00d4aa]\n"
            "[bold #00d4aa]  ▛▌▟▖▌▌▙▖▙▖▙▌▌▌[/bold #00d4aa]\n"
            "\n"
            "[#484f58]  Docker Sandbox (Kali Linux) · Outputs → ./workspace/<target>/[/#484f58]\n"
            "\n"
            "[bold #c9d1d9]Commands[/bold #c9d1d9]  "
            "[#58a6ff]/help[/#58a6ff] [#484f58]·[/#484f58] "
            "[#58a6ff]/skills[/#58a6ff] [#484f58]·[/#484f58] "
            "[#58a6ff]/mcp[/#58a6ff] [#484f58]·[/#484f58] "
            "[#58a6ff]/models[/#58a6ff] [#484f58]·[/#484f58] "
            "[#58a6ff]/think[/#58a6ff] [#484f58]·[/#484f58] "
            "[#58a6ff]/shell[/#58a6ff] [#484f58]·[/#484f58] "
            "[#58a6ff]/status[/#58a6ff] [#484f58]·[/#484f58] "
            "[#58a6ff]/clear[/#58a6ff]\n"
            "\n"
            "[bold #c9d1d9]Examples[/bold #c9d1d9]\n"
            "  [#00d4aa]›[/#00d4aa] full recon on [#f59e0b]example.com[/#f59e0b]\n"
            "  [#00d4aa]›[/#00d4aa] do a pentest on this target\n"
            "  [#00d4aa]›[/#00d4aa] review this code [#00d4aa]@/path/file[/#00d4aa]"
            " [#8b949e]or[/#8b949e] [#00d4aa]@/path/dir[/#00d4aa]\n"
            "  [#00d4aa]›[/#00d4aa] bug bounty on [#f59e0b]example.com[/#f59e0b]"
            " [#8b949e]— find everything[/#8b949e]\n",
            markup=True,
        )

        self.query_one("#command-input", CommandInput).focus()

        if self._show_startup_screen:
            from .startup import StartupScreen

            def _on_startup_done(success: bool | None) -> None:
                if self._auto_poll_services:
                    self._status_task = asyncio.create_task(self._poll_services())

            self.push_screen(
                StartupScreen(
                    proxy_url=self.proxy_url,
                    no_proxy=self._no_proxy,
                    session_id=self._session_id,
                ),
                _on_startup_done,
            )
        elif self._auto_poll_services:
            self._status_task = asyncio.create_task(self._poll_services())

    async def on_unmount(self) -> None:
        if hasattr(self, "_session_id") and self._session_id:
            try:
                from airecon.proxy.agent.session import load_session, save_session

                session = load_session(self._session_id)
                if session and session.target:
                    save_session(session)
            except Exception as e:
                logger.debug("Expected failure in on_unmount save_session: %s", e)

        if self._status_task and not self._status_task.done():
            self._status_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._status_task

        if self._chat_worker and self._chat_worker.is_running:
            self._chat_worker.cancel()

        if self._copy_toast_task and not self._copy_toast_task.done():
            self._copy_toast_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._copy_toast_task

        with contextlib.suppress(Exception):
            await self._http.aclose()

    _SPINNER_CHARS = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]

    def _tick_recon_spinner(self) -> None:
        if not self._processing and not self._file_agents_running:
            return
        self._recon_frame = (self._recon_frame + 1) % len(self._SPINNER_CHARS)
        try:
            char = self._SPINNER_CHARS[self._recon_frame]
            self.query_one("#recon-bar", Static).update(
                f"[bold #3b82f6]{char}[/]  [#8b949e]esc  interrupt[/]"
            )
        except Exception as e:
            logger.debug(
                "Expected failure in _tick_recon_spinner update recon-bar: %s", e
            )

    def _show_recon_spinner(self) -> None:
        try:
            bar = self.query_one("#recon-bar", Static)
            bar.update(
                f"[bold #3b82f6]{self._SPINNER_CHARS[0]}[/]  [#8b949e]esc  interrupt[/]"
            )
            bar.styles.height = 1
        except Exception as e:
            logger.debug("Expected failure in _show_recon_spinner: %s", e)

    def _hide_recon_spinner(self) -> None:
        try:
            self.query_one("#recon-bar", Static).styles.height = 0
        except Exception as e:
            logger.debug("Expected failure in _hide_recon_spinner: %s", e)

    async def on_workspace_tree_file_selected(
        self, event: WorkspaceTree.FileSelected
    ) -> None:
        chat = self.query_one(ChatPanel)
        try:
            file_path = event.path

            try:
                workspace_root = get_workspace_root()
                abs_path = file_path.resolve()

                if workspace_root in abs_path.parents:
                    rel = abs_path.relative_to(workspace_root)
                    if len(rel.parts) > 1:
                        search_path = abs_path
                        target_path = None

                        while search_path != workspace_root:
                            if any(
                                (search_path / folder).is_dir()
                                for folder in [
                                    "vulnerabilities",
                                    "output",
                                    "command",
                                    "tools",
                                ]
                            ):
                                target_path = search_path
                                break
                            search_path = search_path.parent

                        if not target_path:
                            target_path = (
                                abs_path if abs_path.is_dir() else abs_path.parent
                            )

                        self.query_one(
                            "#workspace-panel", WorkspacePanel
                        ).update_vulnerabilities_path(target_path)
                    else:
                        self.query_one(
                            "#workspace-panel", WorkspacePanel
                        ).clear_vulnerabilities_view()
            except Exception as e:
                logger.debug(
                    "Expected failure in on_workspace_tree_file_selected clear vuln view: %s",
                    e,
                )

            def _read_file_sync() -> str:
                try:
                    if file_path.stat().st_size > 50_000:
                        with open(
                            file_path, "r", encoding="utf-8", errors="replace"
                        ) as f:
                            return f.read(50_000) + "\n... [TRUNCATED CONTEXT] ..."
                    return file_path.read_text(encoding="utf-8", errors="replace")
                except Exception as exc:
                    return f"Error reading file: {exc}"

            import asyncio

            content = await asyncio.to_thread(_read_file_sync)

            self.active_file_path = file_path
            self.active_file_content = content

            chat.add_system_message(
                f"File context loaded: [bold green]{file_path.name}[/bold green]. "
                "Use 'this file' or 'the loaded file' in your next prompt."
            )

            self._open_file_preview(str(file_path))

        except Exception as e:
            chat.add_error_message(f"Error reading file for context: {e}")
            self.active_file_path = None
            self.active_file_content = None

    def on_workspace_tree_directory_selected(
        self, event: WorkspaceTree.DirectorySelected
    ) -> None:
        if event.control is not None and event.control.id != "workspace-tree":
            return

        self.current_context_path = event.path
        chat = self.query_one(ChatPanel)
        chat.add_system_message(f"Context set to: {event.path}")

        try:
            workspace_root = get_workspace_root().resolve()
            abs_path = event.path.resolve()

            if workspace_root in abs_path.parents or abs_path == workspace_root:
                if abs_path == workspace_root:
                    self.query_one(
                        "#workspace-panel", WorkspacePanel
                    ).clear_vulnerabilities_view()
                    return

                rel = abs_path.relative_to(workspace_root)
                if len(rel.parts) >= 1:
                    search_path = abs_path
                    target_path = None

                    while search_path != workspace_root:
                        if any(
                            (search_path / folder).is_dir()
                            for folder in [
                                "vulnerabilities",
                                "output",
                                "command",
                                "tools",
                            ]
                        ):
                            target_path = search_path
                            break
                        search_path = search_path.parent

                    if not target_path:
                        target_path = abs_path if abs_path.is_dir() else abs_path.parent

                    self.query_one(
                        "#workspace-panel", WorkspacePanel
                    ).update_vulnerabilities_path(target_path)
        except Exception as e:
            logger.debug(
                "Expected failure in on_workspace_tree_directory_selected update vuln path: %s",
                e,
            )

    async def _poll_services(self) -> None:
        status_bar = self.query_one("#status-bar", StatusBar)
        chat = self.query_one("#chat-panel", ChatPanel)

        max_retries = 40
        connected = False
        proxy_reachable = False

        for attempt in range(max_retries):
            try:
                resp = await self._http.get("/api/status", timeout=3.0)
                if resp.status_code == 200:
                    data = resp.json()
                    llm_ok = data.get("llm", {}).get("connected", False)
                    docker_ok = data.get("docker", {}).get("connected", False)
                    model = data.get("llm", {}).get("model", "—")
                    backend_label = data.get("llm", {}).get("backend", "LLM")
                    agent_stats = data.get("agent", {})
                    tool_counts = agent_stats.get("tool_counts", {})
                    exec_used = tool_counts.get("exec", 0)
                    subagents = tool_counts.get("subagents", 0)
                    token_info = agent_stats.get("token_usage", {})
                    tokens_used = token_info.get(
                        "cumulative", token_info.get("used", 0)
                    )
                    tokens_current = token_info.get("used", tokens_used)
                    tokens_limit = token_info.get("limit")
                    if not tokens_limit or tokens_limit <= 0:
                        tokens_limit = self._default_ctx_limit()
                    skills_info = agent_stats.get("skills_used", [])
                    caido_data = agent_stats.get("caido", {})

                    proxy_reachable = True
                    status_bar.set_status(
                        llm="online" if llm_ok else "offline",
                        llm_degraded=self._should_show_llm_degraded(llm_ok),
                        backend_label=backend_label,
                        docker="online" if docker_ok else "offline",
                        model=model,
                        tokens=tokens_used,
                        token_limit=tokens_limit,
                        exec_used=exec_used,
                        subagents=subagents,
                        skills=skills_info,
                        caido_active=caido_data.get("active", False),
                        caido_findings=caido_data.get("findings_count", 0),
                    )

                    if llm_ok and docker_ok:
                        connected = True
                        chat.add_assistant_message(
                            f"✅ Connected — **{model}** via {backend_label} "
                            "ready with Docker sandbox"
                        )
                        try:
                            sess_resp = await self._http.get(
                                "/api/session/current", timeout=3.0
                            )
                            if sess_resp.status_code == 200:
                                sess = sess_resp.json().get("session")
                                if (
                                    sess
                                    and self._session_id
                                    and sess.get("session_id") == self._session_id
                                ):
                                    sid = sess.get("session_id", "?")
                                    target = sess.get("target") or "no target yet"
                                    scans = sess.get("scan_count", 0)
                                    chat.add_system_message(
                                        f"🔖 Active session: `{sid}` — {target}"
                                        + (f" ({scans} scans)" if scans else "")
                                    )
                        except Exception as e:
                            error_str = str(e).strip()
                            if error_str:
                                logger.debug(
                                    "Expected failure in _poll_services show session info: %s",
                                    e,
                                )

                        await self._restore_history_if_resumed(chat)
                        break
            except Exception as e:
                error_str = str(e).strip()
                if error_str:
                    logger.debug(
                        "Expected failure in _poll_services status check: %s", e
                    )

            await asyncio.sleep(1.0)

        if not connected:
            if proxy_reachable:
                data = {}
                try:
                    resp = await self._http.get("/api/status", timeout=3.0)
                    data = resp.json()
                except Exception as e:
                    error_str = str(e).strip()
                    if error_str:
                        logger.debug(
                            "Expected failure in _poll_services get status data: %s", e
                        )
                llm_ok = data.get("llm", {}).get("connected", False)
                docker_ok = data.get("docker", {}).get("connected", False)
                backend_label = data.get("llm", {}).get("backend", "LLM")
                issues = []
                if not llm_ok:
                    issues.append(
                        f"{backend_label} backend offline "
                        "(check the gateway URL / API key in config.yaml)"
                    )
                if not docker_ok:
                    issues.append("Docker sandbox not running (check Docker daemon)")
                detail = " · ".join(issues) if issues else "services not ready"
                chat.add_error_message(
                    f"⚠️ Proxy is running but services are not ready: {detail}\n"
                    "Use `/status` for details."
                )
            else:
                chat.add_error_message(
                    "Cannot reach proxy server. Run `airecon proxy` "
                    "in a separate terminal, then type `/status` to retry."
                )
            return

        while True:
            await asyncio.sleep(5.0)

            try:
                self.query_one("#workspace-panel", WorkspacePanel).reload()
            except Exception as e:
                logger.debug(
                    "Expected failure in _poll_services loop reload workspace: %s", e
                )

            try:
                resp = await self._http.get("/api/status", timeout=3.0)
                if resp.status_code == 200:
                    data = resp.json()
                    llm_ok = data.get("llm", {}).get("connected", False)
                    docker_ok = data.get("docker", {}).get("connected", False)
                    model = data.get("llm", {}).get("model", "—")
                    tool_counts = data.get("agent", {}).get("tool_counts", {})
                    exec_used = tool_counts.get("exec", 0)
                    subagents = (
                        tool_counts.get("subagents", 0) + self._file_agents_running
                    )
                    token_info = data.get("agent", {}).get("token_usage", {})
                    tokens_used = token_info.get(
                        "cumulative", token_info.get("used", 0)
                    )
                    tokens_current = token_info.get("used", tokens_used)
                    tokens_limit = token_info.get("limit")
                    if not tokens_limit or tokens_limit <= 0:
                        tokens_limit = self._default_ctx_limit()
                    phase = data.get("agent", {}).get("phase")
                    skills_info = data.get("agent", {}).get("skills_used", [])
                    caido_data = data.get("agent", {}).get("caido", {})
                    caido_active = caido_data.get("active", False)
                    caido_findings = caido_data.get("findings_count", 0)

                    self.query_one("#status-bar", StatusBar).set_status(
                        llm="online" if llm_ok else "offline",
                        llm_degraded=self._should_show_llm_degraded(llm_ok),
                        docker="online" if docker_ok else "offline",
                        model=model,
                        tokens=tokens_used,
                        token_limit=tokens_limit,
                        exec_used=exec_used,
                        subagents=subagents,
                        skills=skills_info,
                        caido_active=caido_active,
                        caido_findings=caido_findings,
                    )

                    chat = self.query_one("#chat-panel", ChatPanel)
                    token_ratio = None
                    if tokens_limit and tokens_limit > 0:
                        token_ratio = float(tokens_current) / float(tokens_limit)
                    chat.update_buddy_context(phase=phase, token_ratio=token_ratio)
            except Exception as e:
                error_str = str(e).strip()
                if error_str:
                    logger.debug(
                        "Expected failure in _poll_services loop set_status: %s", e
                    )

    async def _check_services(self, verbose: bool = False) -> None:
        status_bar = self.query_one("#status-bar", StatusBar)
        chat = self.query_one("#chat-panel", ChatPanel)
        try:
            resp = await self._http.get("/api/status", timeout=5.0)
            if resp.status_code == 200:
                data = resp.json()
                llm = data.get("llm", {})
                docker = data.get("docker", {})
                agent = data.get("agent", {})

                llm_ok = llm.get("connected", False)
                docker_ok = docker.get("connected", False)
                model = llm.get("model", "—")
                backend_label = llm.get("backend", "LLM")

                tool_counts = agent.get("tool_counts", {})
                exec_used = tool_counts.get("exec", 0)
                subagents = tool_counts.get("subagents", 0)
                caido = agent.get("caido", {})
                caido_active = caido.get("active", False)
                caido_findings = caido.get("findings_count", 0)
                token_info = agent.get("token_usage", {})
                tokens_used = token_info.get("cumulative", token_info.get("used", 0))
                tokens_current = token_info.get("used", tokens_used)
                tokens_limit = token_info.get("limit")
                if not tokens_limit or tokens_limit <= 0:
                    tokens_limit = self._default_ctx_limit()
                phase = agent.get("phase")

                status_bar.set_status(
                    llm="online" if llm_ok else "offline",
                    llm_degraded=self._should_show_llm_degraded(llm_ok),
                    backend_label=backend_label,
                    docker="online" if docker_ok else "offline",
                    model=model,
                    exec_used=exec_used,
                    subagents=subagents,
                    caido_active=caido_active,
                    caido_findings=caido_findings,
                )
                token_ratio = None
                if tokens_limit and tokens_limit > 0:
                    token_ratio = float(tokens_current) / float(tokens_limit)
                chat.update_buddy_context(phase=phase, token_ratio=token_ratio)

                if verbose:
                    status_md = f"""## 🟢 AIRecon Status Report

- **{backend_label} backend**: {"✅ Online" if llm_ok else "❌ Offline"}
  - URL: `{llm.get("url", "Unknown")}`
  - Model: `{model}`
- **Docker Sandbox**: {"✅ Running" if docker_ok else "❌ Stopped"}
  - Image: `{docker.get("image", "airecon-sandbox")}`

- **Messages**: {agent.get("message_count", 0)}
- **Commands Executed**: **{exec_used}**
"""
                    chat.add_assistant_message(status_md)
                else:
                    pass

            else:
                status_bar.set_status(llm="offline", docker="offline")
                if verbose:
                    chat.add_error_message(
                        f"Status check failed: HTTP {resp.status_code}"
                    )
        except Exception as e:
            status_bar.set_status(llm="offline", docker="offline")
            if verbose:
                chat.add_error_message(f"Status check error: {e}")

    async def _docker_health_monitor(self) -> None:
        from airecon.tui.startup import get_proxy_fatal_error, is_proxy_alive

        _DOCKER_FAILURE_THRESHOLD = 3
        _HTTP_WARN_THRESHOLD = 5
        _HTTP_HARD_THRESHOLD = 18
        _HTTP_TIMEOUT_IDLE = 12.0
        _HTTP_TIMEOUT_ACTIVE = 25.0
        _SSE_RECENT_WINDOW = 120.0

        consecutive_docker_failures = 0
        consecutive_http_failures = 0
        _warned_recovering = False

        while self._processing:
            try:
                await asyncio.sleep(5.0)

                if not self._processing:
                    break

                _status_timeout = (
                    _HTTP_TIMEOUT_ACTIVE if self._processing else _HTTP_TIMEOUT_IDLE
                )
                resp = await self._http.get("/api/health", timeout=_status_timeout)
                if resp.status_code == 200:
                    data = resp.json()
                    docker_ok = data.get("docker", {}).get("connected", False)

                    if not docker_ok:
                        consecutive_docker_failures += 1
                        if consecutive_docker_failures >= _DOCKER_FAILURE_THRESHOLD:
                            logger.error(
                                "Docker sandbox disconnected for %d consecutive checks — declaring dead",
                                consecutive_docker_failures,
                            )
                            chat = self.query_one("#chat-panel", ChatPanel)
                            if chat:
                                chat.add_error_message(
                                    "⚠️ **Docker Sandbox Disconnected!**\n\n"
                                    "The sandbox container has crashed or stopped. "
                                    "Recon cannot continue.\n\n"
                                    "**What happened:**\n"
                                    "- Container may have crashed due to resource limits\n"
                                    "- Docker daemon may have stopped\n"
                                    "- Container was manually stopped\n\n"
                                    "**Next steps:**\n"
                                    "1. Check Docker: `docker ps -a | grep airecon`\n"
                                    "2. Restart container or AIRecon\n"
                                    "3. Review logs: `docker logs airecon-sandbox-active`"
                                )
                            self._processing = False
                            self._hide_recon_spinner()
                            try:
                                chat.end_streaming()
                                chat.end_thinking()
                            except Exception as e:
                                logger.debug(
                                    "Expected failure in _docker_health_monitor end streaming: %s",
                                    e,
                                )
                            break
                        else:
                            logger.warning(
                                "Docker reported disconnected (check %d/%d) — waiting for auto-recovery",
                                consecutive_docker_failures,
                                _DOCKER_FAILURE_THRESHOLD,
                            )
                    else:
                        if consecutive_docker_failures > 0:
                            logger.info(
                                "Docker reconnected after %d failed check(s)",
                                consecutive_docker_failures,
                            )
                        consecutive_docker_failures = 0

                    if consecutive_http_failures > 0:
                        logger.info(
                            "Proxy recovered after %d failed check(s)",
                            consecutive_http_failures,
                        )
                        _warned_recovering = False
                    consecutive_http_failures = 0
                else:
                    sse_age = time.monotonic() - self._last_sse_activity
                    _EXTENDED_SSE_WINDOW = (
                        180.0 if self._processing else _SSE_RECENT_WINDOW
                    )
                    if sse_age < _EXTENDED_SSE_WINDOW and is_proxy_alive():
                        logger.debug(
                            "Health endpoint returned HTTP %s but SSE is recent (%.0fs) and proxy thread is alive — treating as transient",
                            resp.status_code,
                            sse_age,
                        )
                        consecutive_http_failures = 0
                    else:
                        consecutive_http_failures += 1

            except httpx.ConnectError:
                sse_age = time.monotonic() - self._last_sse_activity

                _EXTENDED_SSE_WINDOW = 180.0 if self._processing else _SSE_RECENT_WINDOW

                if sse_age < _EXTENDED_SSE_WINDOW and is_proxy_alive():
                    logger.debug(
                        "Proxy port closed (ConnectError) but thread alive + SSE %.0fs ago — "
                        "likely mid-restart or event loop saturation, not counting as failure",
                        sse_age,
                    )
                    consecutive_http_failures = 0
                    consecutive_docker_failures = 0
                else:
                    consecutive_http_failures += 1
            except httpx.TimeoutException:
                sse_age = time.monotonic() - self._last_sse_activity

                _EXTENDED_SSE_WINDOW = 180.0 if self._processing else _SSE_RECENT_WINDOW

                if sse_age < _EXTENDED_SSE_WINDOW:
                    if (
                        consecutive_http_failures > 0
                        and consecutive_http_failures % 3 == 0
                    ):
                        logger.debug(
                            "Health check timeout (SSE age=%.0fs) — event loop saturated, skipping (count=%d)",
                            sse_age,
                            consecutive_http_failures,
                        )
                    consecutive_http_failures = 0
                    consecutive_docker_failures = 0
                else:
                    logger.warning(
                        "Health check timeout AND SSE inactive (%.0fs) — proxy may be truly stuck",
                        sse_age,
                    )
                    consecutive_http_failures += 1
            except Exception as e:
                logger.debug("Health check error: %s", e)
                consecutive_http_failures += 1

            if consecutive_http_failures < _HTTP_WARN_THRESHOLD:
                continue

            proxy_thread_alive = is_proxy_alive()
            proxy_fatal = get_proxy_fatal_error()
            sse_age = time.monotonic() - self._last_sse_activity

            if (
                consecutive_http_failures == _HTTP_WARN_THRESHOLD
                and not _warned_recovering
            ):
                _warned_recovering = True
                if proxy_thread_alive and not proxy_fatal:
                    logger.warning(
                        "Proxy unreachable for %ds — thread alive, waiting for recovery "
                        "(SSE age=%.0fs)",
                        consecutive_http_failures * 5,
                        sse_age,
                    )

                    if sse_age >= 180.0:
                        try:
                            chat = self.query_one("#chat-panel", ChatPanel)
                            if chat and self._processing:
                                chat.add_system_message(
                                    "Proxy temporarily unreachable; auto-recovery in progress (up to 90s)."
                                )
                        except Exception as e:
                            logger.debug(
                                "Expected failure in _docker_health_monitor show system message: %s",
                                e,
                            )
                    continue

            if (
                not proxy_thread_alive
                or proxy_fatal
                or consecutive_http_failures >= _HTTP_HARD_THRESHOLD
            ):
                if (
                    proxy_thread_alive
                    and not proxy_fatal
                    and self._processing
                    and consecutive_http_failures >= _HTTP_HARD_THRESHOLD
                ):
                    _MAX_STALE_SSE_GRACE = 240.0
                    if sse_age < _MAX_STALE_SSE_GRACE:
                        logger.warning(
                            "Proxy still unreachable for %ds but thread alive and no fatal error "
                            "(SSE age=%.0fs) — extending grace window",
                            consecutive_http_failures * 5,
                            sse_age,
                        )
                        continue

                    logger.error(
                        "Proxy thread alive but SSE stale for %.0fs (>=%.0fs) and /api/status unreachable — forcing abort",
                        sse_age,
                        _MAX_STALE_SSE_GRACE,
                    )

                logger.error(
                    "Proxy unreachable for %ds (thread_alive=%s, fatal=%r, SSE age=%.0fs) — aborting",
                    consecutive_http_failures * 5,
                    proxy_thread_alive,
                    proxy_fatal,
                    sse_age,
                )
                try:
                    chat = self.query_one("#chat-panel", ChatPanel)
                    if chat and self._processing:
                        _detail = proxy_fatal or "proxy thread stopped responding"
                        chat.add_error_message(
                            "⚠️ **Connection Lost!**\n\n"
                            f"Cannot reach AIRecon proxy: {_detail}\n\n"
                            "Please restart AIRecon."
                        )
                        self._processing = False
                except Exception as e:
                    logger.debug(
                        "Expected failure in _docker_health_monitor show error: %s", e
                    )
                break

    def _start_health_monitor(self) -> None:
        if not self._health_check_task:
            self._health_check_task = asyncio.create_task(
                self._docker_health_monitor(), name="docker-health-monitor"
            )
            logger.debug("Started Docker health monitor")

    def _stop_health_monitor(self) -> None:
        if self._health_check_task:
            self._health_check_task.cancel()
            self._health_check_task = None
            logger.debug("Stopped Docker health monitor")

    def on_tool_message_selected(self, message: ToolMessageSelected) -> None:
        logger.debug(f"App received selection: {message.output_file}")
        self._open_file_preview(message.output_file)

    def on_directory_tree_file_selected(
        self, event: DirectoryTree.FileSelected
    ) -> None:
        self._open_file_preview(str(event.path))

    def _open_file_preview(self, file_path: str) -> None:
        try:
            p = Path(file_path)
            if not p.exists():
                p = Path.cwd() / file_path

            if p.exists():
                if p.is_dir():
                    return
                self.push_screen(FilePreviewScreen(str(p)), self.on_preview_result)
            else:
                self.query_one(ChatPanel).add_error_message(
                    f"File not found: {file_path}"
                )
        except Exception as e:
            self.query_one(ChatPanel).add_error_message(f"Failed to open file: {e}")

    async def on_preview_result(self, result: Any) -> None:
        if isinstance(result, FilePreviewScreen.Submitted):
            abs_path = os.path.abspath(result.file_path)
            _abs = Path(abs_path)
            _cwd = Path(os.getcwd())
            display_path = (
                str(_abs.relative_to(_cwd)) if _abs.is_relative_to(_cwd) else abs_path
            )

            chat = self.query_one(ChatPanel)
            chat.add_user_message(
                f"[FILE ANALYSIS: {display_path}]\n{result.user_prompt}"
            )
            chat.add_system_message(
                "[dim]Running as background sub-agent — main recon continues uninterrupted.[/dim]"
            )

            def _read_file_sync() -> str:
                try:
                    if _abs.stat().st_size > 100_000:
                        return _abs.read_text(errors="replace")[:100_000]
                    return _abs.read_text(errors="replace")
                except Exception as e:
                    return f"[Could not read file: {e}]"

            content = await asyncio.to_thread(_read_file_sync)

            self.run_worker(
                self._stream_file_analysis(abs_path, content, result.user_prompt)
            )

    def _clear_active_file_context(self) -> None:
        self.active_file_path = None
        self.active_file_content = None

    def on_command_input_at_path_changed(
        self, event: CommandInput.AtPathChanged
    ) -> None:
        try:
            completer = self.query_one("#path-completer", PathCompleter)
            if event.fragment is None:
                completer.hide()
            else:
                completer.show_for(event.fragment)
        except Exception as e:
            logger.debug("Expected failure in on_command_input_at_path_changed: %s", e)

    def on_command_input_tab_pressed(self, event: CommandInput.TabPressed) -> None:
        try:
            slash_completer = self.query_one("#slash-completer", SlashCompleter)
            if slash_completer.display:
                cmd = slash_completer.get_first_command()
                if cmd:
                    cmd_input = self.query_one("#command-input", CommandInput)
                    cmd_input.do_slash_completion(cmd)
                    slash_completer.hide()
                return
        except Exception as e:
            logger.debug(
                "Expected failure in on_command_input_tab_pressed slash completer: %s",
                e,
            )

        try:
            completer = self.query_one("#path-completer", PathCompleter)
            if not completer.display:
                return
            path = completer.get_first_path()
            if not path:
                return
            cmd_input = self.query_one("#command-input", CommandInput)
            cmd_input.do_completion(path)
            if path.endswith("/"):
                completer.show_for(path)
            else:
                completer.hide()
        except Exception as e:
            logger.debug(
                "Expected failure in on_command_input_tab_pressed path completer: %s", e
            )

    def on_command_input_escape_completion(
        self, event: CommandInput.EscapeCompletion
    ) -> None:
        try:
            slash_completer = self.query_one("#slash-completer", SlashCompleter)
            if slash_completer.display:
                slash_completer.hide()
        except Exception as e:
            logger.debug(
                "Expected failure in on_command_input_escape_completion slash completer: %s",
                e,
            )
        try:
            completer = self.query_one("#path-completer", PathCompleter)
            if completer.display:
                completer.hide()
        except Exception as e:
            logger.debug(
                "Expected failure in on_command_input_escape_completion path completer: %s",
                e,
            )

    def on_command_input_slash_changed(self, event: CommandInput.SlashChanged) -> None:
        try:
            completer = self.query_one("#slash-completer", SlashCompleter)
            if event.fragment is None:
                completer.hide()
            else:
                completer.show_for(event.fragment)
        except Exception as e:
            logger.debug("Expected failure in on_command_input_slash_changed: %s", e)

    def on_slash_completer_completed(self, event: SlashCompleter.Completed) -> None:
        try:
            cmd_input = self.query_one("#command-input", CommandInput)
            cmd_input.do_slash_completion(event.command)
            self.query_one("#slash-completer", SlashCompleter).hide()
            cmd_input.focus()
        except Exception as e:
            logger.debug("Expected failure in on_slash_completer_completed: %s", e)

    def on_path_completer_completed(self, event: PathCompleter.Completed) -> None:
        try:
            cmd_input = self.query_one("#command-input", CommandInput)
            cmd_input.do_completion(event.path)
            completer = self.query_one("#path-completer", PathCompleter)
            if event.path.endswith("/"):
                completer.show_for(event.path)
            else:
                completer.hide()
            cmd_input.focus()
        except Exception as e:
            logger.debug("Expected failure in on_path_completer_completed: %s", e)

    async def on_command_input_submitted(self, message: CommandInput.Submitted) -> None:
        user_input = message.value.strip()
        if not user_input:
            return

        try:
            self.query_one("#slash-completer", SlashCompleter).hide()
        except Exception as e:
            logger.debug(
                "Expected failure in on_command_input_submitted hide slash completer: %s",
                e,
            )
        try:
            self.query_one("#path-completer", PathCompleter).hide()
        except Exception as e:
            logger.debug(
                "Expected failure in on_command_input_submitted hide path completer: %s",
                e,
            )

        if user_input.startswith("/"):
            await self._handle_slash_command(user_input)
            return

        if self._processing:
            self.notify(
                "⏳ Agent is still working. Wait for it to finish.",
                severity="warning",
                timeout=3,
            )
            return

        chat = self.query_one("#chat-panel", ChatPanel)

        prompt = user_input
        if self.current_context_path:
            prompt = f"[CONTEXT: Focus on {self.current_context_path}]\n{user_input}"

        chat.add_user_message(user_input)

        chat.start_thinking()
        self._show_recon_spinner()

        self._chat_worker = self.run_worker(self._stream_chat_response(prompt))

    async def _stream_chat_response(
        self, prompt: str, inject_context: bool = True
    ) -> None:
        logger.debug(f"Starting chat stream for prompt: {prompt[:50]}...")
        self._processing = True
        chat = self.query_one("#chat-panel", ChatPanel)

        self._start_health_monitor()

        try:
            if inject_context and self.active_file_content and self.active_file_path:
                file_ext = self.active_file_path.suffix.lower()
                file_path_str = str(self.active_file_path.resolve())

                file_context_message_parts = []

                if file_ext == ".json":
                    try:
                        parsed_content = json.loads(self.active_file_content)
                        if (
                            isinstance(parsed_content, dict)
                            and "result" in parsed_content
                        ):
                            result_data = parsed_content["result"]
                            if (
                                isinstance(result_data, dict)
                                and "stdout" in result_data
                            ):
                                stdout_content = result_data["stdout"].strip()
                                domains = [
                                    d.strip()
                                    for d in stdout_content.split("\n")
                                    if d.strip()
                                ]
                                count = len(domains)

                                file_context_message_parts.append(
                                    f"User loaded file: {file_path_str}\n"
                                    f"Type: Tool Output (JSON)\n"
                                    f"Content Summary: Contains {count} subdomains/targets.\n"
                                    f"Top 20 Targets: {', '.join(domains[:20])}...\n"
                                    f"INSTRUCTION: This file contains the target list. If the user asks to probe or scan these, use the file path '{file_path_str}' if the tool supports file input, or iterate through the high-value targets."
                                )
                            else:
                                file_context_message_parts.append(
                                    f"User loaded file: {file_path_str} (JSON Result). "
                                    f"Content snippet: {str(parsed_content)[:500]}..."
                                )
                        else:
                            file_context_message_parts.append(
                                f"User loaded file: {file_path_str} (JSON). Content snippet: {self.active_file_content[:500]}..."
                            )

                    except json.JSONDecodeError:
                        file_context_message_parts.append(
                            f"User loaded file: {file_path_str} (Raw Content). Snippet: {self.active_file_content[:500]}..."
                        )
                else:
                    file_context_message_parts.append(
                        f"User loaded file: {file_path_str}. Content snippet: {self.active_file_content[:500]}..."
                    )

                context_str = "\n".join(file_context_message_parts)
                prompt_with_context = f"[SYSTEM: ACTIVE FILE CONTEXT]\n{context_str}\n\n[USER PROMPT]\n{prompt}"

                _ctx_file_name = (
                    self.active_file_path.name if self.active_file_path else "file"
                )
                self._clear_active_file_context()
                chat.add_system_message(
                    f"[dim]Sent context from {_ctx_file_name}[/dim]"
                )
            else:
                prompt_with_context = prompt

            _chat_request_id = uuid.uuid4().hex[:12]
            logger.info("chat_trace_tui id=%s phase=preflight_start", _chat_request_id)
            _preflight_ok = False
            for _attempt in range(3):
                try:
                    _status_resp = await self._http.get("/api/status", timeout=2.5)
                    if _status_resp.status_code == 200:
                        _preflight_ok = True
                        logger.info(
                            "chat_trace_tui id=%s phase=preflight_ok attempt=%d",
                            _chat_request_id,
                            _attempt + 1,
                        )
                        break
                except Exception as _e:
                    logger.debug(
                        "Chat preflight attempt %d failed (id=%s): %s",
                        _attempt + 1,
                        _chat_request_id,
                        _e,
                    )

                if _attempt < 2:
                    await asyncio.sleep(0.4 * (2**_attempt))

            if not _preflight_ok:
                logger.warning(
                    "Chat preflight could not confirm proxy readiness after retries (id=%s); attempting stream anyway",
                    _chat_request_id,
                )

            logger.info("chat_trace_tui id=%s phase=stream_connect", _chat_request_id)
            logger.debug(f"Connecting to proxy at {self.proxy_url}/api/chat")
            async with self._http.stream(
                "POST",
                "/api/chat",
                json={
                    "message": prompt_with_context,
                    "stream": True,
                    "request_id": _chat_request_id,
                },
                headers={"Accept": "text/event-stream"},
                timeout=httpx.Timeout(30.0, read=None),
            ) as resp:
                logger.debug(f"Proxy response status: {resp.status_code}")

                if resp.status_code != 200:
                    body = await resp.aread()
                    error_msg = (
                        f"Proxy error ({resp.status_code}): {body.decode()[:500]}"
                    )
                    logger.error(error_msg)
                    chat.add_error_message(error_msg)
                    return

                streaming_started = False
                logger.debug("Start reading SSE stream...")

                async for line in resp.aiter_lines():
                    if not line:
                        continue

                    if line.startswith("event:"):
                        continue

                    if line.startswith("data: "):
                        data_str = line[6:]
                    elif line.startswith("data:"):
                        data_str = line[5:]
                    else:
                        continue

                    try:
                        event = json.loads(data_str)
                    except json.JSONDecodeError as e:
                        logger.warning(
                            f"Failed to parse SSE JSON: {data_str[:100]} - {e}"
                        )
                        continue

                    self._last_sse_activity = time.monotonic()

                    event_type = str(event.get("type", "") or "").strip()
                    
                    if event_type.startswith("subagent_"):
                        logger.info("TUI SSE event: type=%s, keys=%s", event_type, list(event.keys())[:10])
                    
                    event_req_id = str(
                        event.get("request_id", _chat_request_id) or _chat_request_id
                    )
                    if not event_type:
                        logger.debug(
                            "Received SSE payload without event type; ignoring"
                        )
                        continue

                    if event_type == "ping":
                        continue

                    if event_type in {
                        "tool_start",
                        "tool_end",
                        "error",
                        "done",
                        "progress",
                        "user_input_required",
                    }:
                        logger.info(
                            "chat_trace_tui id=%s phase=%s", event_req_id, event_type
                        )
                    else:
                        logger.debug("Received event: %s", event_type)

                    if event_type == "text":
                        content = event.get("content", "")
                        if content:
                            if self._is_llm_recovery_marker(content):
                                self._mark_llm_degraded(content[:120])
                            if not streaming_started:
                                chat.start_streaming()
                                streaming_started = True
                            chat.append_to_stream(content)
                            _now = time.monotonic()
                            if _now - self._last_scroll_time >= 0.3:
                                chat.scroll_end(animate=False)
                                self._last_scroll_time = _now

                    elif event_type == "thinking":
                        content = event.get("content", "")
                        if content:
                            chat.append_to_thinking(content)
                            _now = time.monotonic()
                            if _now - self._last_scroll_time >= 0.3:
                                chat.scroll_end(animate=False)
                                self._last_scroll_time = _now

                    elif event_type == "tool_start":
                        tool_id = str(event.get("tool_id", "0"))
                        tool_name = event.get("tool", "unknown")
                        arguments = event.get("arguments", {})
                        logger.info(f"Tool Start: {tool_name} args={arguments}")
                        chat.end_streaming()
                        tool_kind = self._classify_tool_kind(tool_name, arguments)
                        chat.set_buddy_state(
                            "tool",
                            tool_name=str(tool_name),
                            tool_kind=tool_kind,
                        )
                        streaming_started = False
                        chat.add_tool_start(tool_id, tool_name, arguments)

                    elif event_type == "tool_output":
                        tool_id = str(event.get("tool_id", "0"))
                        content = event.get("content", "")
                        if content:
                            _now = time.monotonic()
                            chat.append_tool_output(tool_id, content)
                            if _now - self._last_scroll_time >= 0.3:
                                chat.scroll_end(animate=False)
                                self._last_scroll_time = _now

                    elif event_type == "tool_end":
                        tool_id = str(event.get("tool_id", "0"))
                        success = event.get("success", False)
                        duration = event.get("duration", 0.0)
                        output_file = event.get("output_file", "")
                        result_preview = event.get("result_preview", "")
                        tool_counts = event.get("tool_counts", {}) or {}
                        token_info = event.get("token_usage", {}) or {}
                        skills_info = event.get("skills_used", []) or []
                        caido_data = event.get("caido", {}) or {}

                        logger.info(f"Tool End: success={success} duration={duration}")
                        _token_ratio = None
                        try:
                            _tok_used = token_info.get("used", token_info.get("cumulative", 0))
                            _tok_limit = token_info.get("limit") or self._default_ctx_limit()
                            if _tok_limit and _tok_limit > 0:
                                _token_ratio = float(_tok_used) / float(_tok_limit)
                        except Exception:
                            _token_ratio = None

                        if not hasattr(chat, "_active_tools"):
                            chat._active_tools = {}
                        captured_tool_msg = chat._active_tools.pop(tool_id, None)

                        def update_ui_on_tool_end(
                            _msg=captured_tool_msg,
                            _s=success,
                            _d=duration,
                            _r=result_preview,
                            _o=output_file,
                            _tc=tool_counts,
                            _ti=token_info,
                            _sk=skills_info,
                            _cd=caido_data,
                            _tr=_token_ratio,
                        ):
                            if _msg:
                                _msg.update_result(_s, _d, _r, _o)
                            chat.scroll_end(animate=False)
                            if _tr is not None:
                                chat.update_buddy_context(token_ratio=_tr)
                            chat.set_buddy_state("thinking" if _s else "error")

                            try:
                                status_bar = self.query_one("#status-bar", StatusBar)
                                status_update_kwargs = {}

                                if _tc:
                                    status_update_kwargs["exec_used"] = _tc.get(
                                        "exec", 0
                                    )
                                    status_update_kwargs["subagents"] = _tc.get(
                                        "subagents", 0
                                    )

                                if _ti:
                                    status_update_kwargs["tokens"] = _ti.get(
                                        "cumulative", _ti.get("used", 0)
                                    )
                                    _limit = _ti.get("limit")
                                    if not _limit or _limit <= 0:
                                        _limit = self._default_ctx_limit()
                                    status_update_kwargs["token_limit"] = _limit

                                if _sk:
                                    status_update_kwargs["skills"] = _sk

                                if _cd:
                                    status_update_kwargs["caido_active"] = _cd.get(
                                        "active", False
                                    )
                                    status_update_kwargs["caido_findings"] = _cd.get(
                                        "findings_count", 0
                                    )

                                if status_update_kwargs:
                                    status_bar.set_status(**status_update_kwargs)
                            except Exception as e:
                                logger.debug(
                                    "Expected failure in update_ui_on_tool_end set_status: %s",
                                    e,
                                )

                            try:
                                import time as _time

                                now = _time.monotonic()
                                if now - self._last_workspace_reload >= 10.0:
                                    self._last_workspace_reload = now
                                    self.query_one(
                                        "#workspace-panel", WorkspacePanel
                                    ).reload()
                            except Exception as e:
                                logger.debug(
                                    "Expected failure in update_ui_on_tool_end reload workspace: %s",
                                    e,
                                )

                        self.call_later(update_ui_on_tool_end)

                    elif event_type == "subagent_text":
                        subagent_id = event.get("target", "") or event.get("subagent_id", "")
                        content = event.get("content", "")
                        if content and subagent_id:
                            if subagent_id not in chat._active_subagents:
                                label = "Orchestrator" if subagent_id == "orchestrator" else f"Target: {subagent_id}"
                                chat.add_subagent_block(subagent_id, label)
                            chat.subagent_append_text(subagent_id, content)
                            _now = time.monotonic()
                            if _now - self._last_scroll_time >= 0.3:
                                chat.scroll_end(animate=False)
                                self._last_scroll_time = _now

                    elif event_type == "subagent_tool_start":
                        subagent_id = event.get("target", "") or event.get("subagent_id", "")
                        tool_id = str(event.get("tool_id", "0"))
                        tool_name = event.get("tool", "unknown")
                        arguments = event.get("arguments", {})

                        if subagent_id:
                            if subagent_id not in chat._active_subagents:
                                label = "Orchestrator" if subagent_id == "orchestrator" else f"Target: {subagent_id}"
                                chat.add_subagent_block(subagent_id, label)
                            chat.subagent_add_tool(subagent_id, tool_id, tool_name, arguments)
                            logger.debug(f"SubAgent Tool Start: {subagent_id}::{tool_name}")

                    elif event_type == "subagent_tool_output":
                        subagent_id = event.get("target", "") or event.get("subagent_id", "")
                        tool_id = str(event.get("tool_id", "0"))
                        content = event.get("content", "")
                        
                        if content and subagent_id:
                            chat.subagent_append_tool_output(subagent_id, tool_id, content)
                            _now = time.monotonic()
                            if _now - self._last_scroll_time >= 0.3:
                                chat.scroll_end(animate=False)
                                self._last_scroll_time = _now

                    elif event_type == "subagent_tool_end":
                        subagent_id = event.get("target", "") or event.get("subagent_id", "")
                        tool_id = str(event.get("tool_id", "0"))
                        success = event.get("success", False)
                        duration = event.get("duration", 0.0)
                        
                        if subagent_id:
                            chat.subagent_update_tool_end(
                                subagent_id, tool_id, success, duration, "", ""
                            )
                            logger.debug(f"SubAgent Tool End: {subagent_id}::{tool_id}")

                    elif event_type == "subagent_complete":
                        subagent_id = event.get("target", "") or event.get("subagent_id", "")
                        if subagent_id and subagent_id in chat._active_subagents:
                            block = chat._active_subagents[subagent_id]
                            block.finish(success=True)
                            logger.debug(f"SubAgent Complete: {subagent_id}")

                    elif event_type == "error":
                        error_msg = event.get("message", "Unknown error")
                        if self._is_llm_recovery_marker(str(error_msg)):
                            self._mark_llm_degraded(str(error_msg)[:120])
                        logger.error(f"Agent Error Event: {error_msg}")
                        chat.set_buddy_state("error")

                        def show_error_safely(msg: str = error_msg) -> None:
                            chat.add_error_message(msg)

                        self.call_later(show_error_safely)
                        logger.error(f"Error event received: {error_msg}")

                    elif event_type == "user_input_required":
                        _req_id = event.get("request_id", "")
                        _prompt = event.get("prompt", "Input required")
                        _inp_type = event.get("input_type", "text")
                        logger.info(
                            "user_input_required: id=%s type=%s", _req_id, _inp_type
                        )
                        chat.set_buddy_state("wait")

                        async def _handle_user_input_modal(
                            req_id: str = _req_id,
                            inp_type: str = _inp_type,
                            prompt_txt: str = _prompt,
                        ) -> None:
                            value: str | None = await self.push_screen_wait(
                                UserInputModal(prompt_txt, inp_type)
                            )
                            cancelled = value is None

                            _submit_success = False
                            for _attempt in range(3):
                                try:
                                    resp = await self._http.post(
                                        "/api/user-input",
                                        json={
                                            "request_id": req_id,
                                            "value": value or "",
                                            "cancelled": cancelled,
                                        },
                                    )
                                    if resp.status_code == 200:
                                        _submit_success = True
                                        break
                                    logger.warning(
                                        "user-input submit attempt %d failed: %s",
                                        _attempt + 1,
                                        resp.text,
                                    )
                                except Exception as _e:
                                    logger.error(
                                        "user-input submit attempt %d failed: %s",
                                        _attempt + 1,
                                        _e,
                                    )

                                if _attempt < 2:
                                    await asyncio.sleep(0.5 * (2**_attempt))

                            if not _submit_success:
                                logger.error(
                                    "user-input submit failed after 3 attempts. "
                                    "The agent may timeout waiting for response."
                                )
                            else:
                                chat.set_buddy_state("thinking")

                        self.call_later(_handle_user_input_modal)

                    elif event_type == "done":
                        logger.debug("Stream done")
                        if streaming_started:
                            chat.end_streaming()
                        chat.clear_buddy()
                        break

            if streaming_started:
                chat.end_streaming()

        except httpx.ConnectError as e:
            msg = f"Cannot connect to proxy: {e}"
            logger.error(msg)
            chat.add_error_message(
                "Cannot connect to proxy. Make sure AIRecon proxy is running on "
                f"`{self.proxy_url}`"
            )
        except httpx.ReadTimeout as e:
            msg = f"Read timeout: {e}"
            logger.error(msg)
            chat.add_error_message("Request timed out. The operation took too long.")
        except Exception as e:
            msg = f"Unexpected error in stream worker: {e}"
            logger.exception(msg)
            chat.add_error_message(f"Error: {str(e)}")
        finally:
            self._processing = False
            self._stop_health_monitor()
            try:
                chat.end_streaming()
                chat.clear_buddy()
            except Exception as e:
                logger.debug(
                    "Expected failure in finally end streaming/thinking: %s", e
                )
            if not self._file_agents_running:
                self._hide_recon_spinner()
            logger.debug("Stream worker finished")

    async def _stream_file_analysis(
        self, file_path: str, content: str, task: str
    ) -> None:
        chat = self.query_one("#chat-panel", ChatPanel)
        agent_id = str(uuid.uuid4())
        success = True

        chat.add_subagent_block(agent_id, task)
        self._file_agents_running += 1
        self._show_recon_spinner()

        self._start_health_monitor()

        try:
            self.query_one("#status-bar", StatusBar).subagents_spawned += 1
        except Exception as e:
            logger.debug(
                "Expected failure in _stream_file_analysis increment subagents: %s", e
            )

        try:
            async with self._http.stream(
                "POST",
                "/api/file-analyze",
                json={
                    "file_path": file_path,
                    "file_content": content,
                    "task": task,
                    "max_iterations": 30,
                },
                headers={"Accept": "text/event-stream"},
                timeout=None,
            ) as resp:
                if resp.status_code != 200:
                    body = await resp.aread()
                    chat.add_error_message(
                        f"File analysis error ({resp.status_code}): "
                        f"{body.decode()[:300]}"
                    )
                    success = False
                    return

                async for line in resp.aiter_lines():
                    if not line:
                        continue
                    if line.startswith("data: "):
                        data_str = line[6:]
                    elif line.startswith("data:"):
                        data_str = line[5:]
                    else:
                        continue

                    try:
                        event = json.loads(data_str)
                    except json.JSONDecodeError:
                        continue

                    event_type = event.get("type", "")

                    if event_type == "text":
                        text = event.get("content", "")
                        if text:
                            chat.subagent_append_text(agent_id, text)
                            _now = time.monotonic()
                            if _now - self._last_scroll_time >= 0.3:
                                chat.scroll_end(animate=False)
                                self._last_scroll_time = _now

                    elif event_type == "tool_start":
                        tool_id = str(event.get("tool_id", "0"))
                        tool_name = event.get("tool", "unknown")
                        arguments = event.get("arguments", {})
                        chat.subagent_add_tool(agent_id, tool_id, tool_name, arguments)

                    elif event_type == "tool_output":
                        tool_id = str(event.get("tool_id", "0"))
                        output = event.get("content", "")
                        if output:
                            chat.subagent_append_tool_output(agent_id, tool_id, output)

                    elif event_type == "tool_end":
                        tool_id = str(event.get("tool_id", "0"))
                        chat.subagent_update_tool_end(
                            agent_id,
                            tool_id,
                            event.get("success", False),
                            event.get("duration", 0.0),
                            event.get("result_preview", ""),
                            event.get("output_file", ""),
                        )

                    elif event_type in ("done", "complete"):
                        break

        except Exception as e:
            logger.exception("File analysis stream error: %s", e)
            success = False
            chat.add_error_message(f"File analysis failed: {e}")
        finally:
            if self._file_agents_running <= 1 and not self._processing:
                self._stop_health_monitor()
            chat.subagent_finish(agent_id, success)
            self._file_agents_running = max(0, self._file_agents_running - 1)
            if not self._processing and not self._file_agents_running:
                self._hide_recon_spinner()
            try:
                status_bar = self.query_one("#status-bar", StatusBar)
                status_bar.subagents_spawned = max(0, status_bar.subagents_spawned - 1)
            except Exception as e:
                logger.debug(
                    "Expected failure in _stream_file_analysis finally decrement subagents: %s",
                    e,
                )

    async def _refresh_mcp_until_ready(self, show_tools: bool = False) -> None:
        chat = self.query_one("#chat-panel", ChatPanel)
        for _ in range(40):
            await asyncio.sleep(2.0)
            try:
                resp = await self._http.get("/api/mcp/list", timeout=8.0)
                if resp.status_code != 200:
                    continue
                data = resp.json()
                servers = data.get("servers", [])
                init_count = int(data.get("initializing", 0) or 0)
                if init_count > 0:
                    continue

                lines: list[str] = [
                    f"MCP Servers ({len(servers)})",
                    "",
                    "Configured MCP servers:",
                ]
                any_ready = False
                for s in servers:
                    name = s.get("name", "?")
                    status = str(s.get("status") or "unknown")
                    tool_count = s.get("tool_count")
                    tools = s.get("tools") or []
                    tool_error = s.get("tool_error")
                    if status == "ready":
                        any_ready = True
                        lines.append("")
                        lines.append(f"🟢 {name} - Ready ({tool_count or 0} tools)")
                        if show_tools and tools:
                            lines.append("  Tools:")
                            for t in tools:
                                lines.append(f"  - {t}")
                    elif status == "error":
                        lines.append("")
                        lines.append(
                            f"🔴 {name} - Error ({tool_error or 'unknown error'})"
                        )

                if any_ready:
                    chat.add_assistant_message("\n".join(lines))
                return
            except Exception as e:
                logger.debug("Expected failure in _refresh_mcp_until_ready: %s", e)
                continue

    @staticmethod
    def _parse_bool_arg(value: str) -> bool | None:
        normalized = value.strip().lower()
        if normalized in {"true", "1", "yes", "y", "on", "enable", "enabled"}:
            return True
        if normalized in {"false", "0", "no", "n", "off", "disable", "disabled"}:
            return False
        return None

    @staticmethod
    def _format_models_response(data: dict[str, Any]) -> str:
        current = str(data.get("current_model") or "").strip()
        source_url = str(data.get("source_url") or data.get("openai_base_url") or "")
        models = [str(m) for m in (data.get("models") or []) if str(m).strip()]

        lines: list[str] = [f"Available models ({len(models)})"]
        if current:
            lines.append(f"Current: {current}")
        if source_url:
            lines.append(f"Source: {source_url}")
        lines.append("")

        if not models:
            lines.append("(No models returned by the configured /models endpoint.)")
        else:
            if current and current not in set(models):
                lines.append(
                    "Current model was not returned by the configured /models endpoint."
                )
                lines.append("")
            for model in models:
                marker = "*" if model == current else " "
                lines.append(f"{marker} {model}")

        lines.append("")
        lines.append("Switch with: /models <model>")
        return "\n".join(lines)

    @staticmethod
    def _format_thinking_response(data: dict[str, Any]) -> str:
        enabled = bool(data.get("enabled", False))
        mode = str(data.get("mode") or "unknown")
        request_mode = str(data.get("request_mode") or "unknown")
        supports = data.get("supports_thinking")
        support_text = "unknown" if supports is None else str(bool(supports)).lower()
        return (
            "Thinking mode\n"
            f"Enabled: {str(enabled).lower()}\n"
            f"Mode: {mode}\n"
            f"Request mode: {request_mode}\n"
            f"Runtime support: {support_text}"
        )

    async def _handle_slash_command(self, cmd: str) -> None:
        chat = self.query_one("#chat-panel", ChatPanel)

        if cmd in ("/help", "/h"):
            chat.add_assistant_message(
                "AIRecon Commands\n\n"
                "- /help                 Show this help\n"
                "- /info                 Show AIRecon information\n"
                "- /status               Check service status\n"
                "- /tools                List available tools\n"
                "- /skills               Show AI skills\n"
                "- /mcp                  Manage MCP servers\n"
                "- /models               List available OpenAI-compatible models\n"
                "- /models <model>       Switch active model\n"
                "- /think true|false     Enable/disable thinking\n"
                "- /shell <command>      Run command in AIRecon Kali Docker shell\n"
                "- /scope ...            Scope guard: allow/deny <hosts>, mode <off|warn|block>, show, clear\n"
                "- /reset                Reset conversation\n"
                "- /clear                Clear chat display\n\n"
                "Note: For authenticated MCP endpoint, use auth:user/pass or auth:apikey:<token> after URL."
            )
        elif cmd == "/status":
            await self._check_services(verbose=True)
        elif cmd == "/skills":
            try:
                resp = await self._http.get("/api/skills")
                if resp.status_code == 200:
                    data = resp.json()
                    skills = data.get("skills", [])

                    from collections import Counter

                    cat_counts: Counter = Counter(
                        s.get("category", "uncategorized") for s in skills
                    )
                    lines = [
                        f"AI Skills & Capabilities — {len(skills)} skills loaded\n"
                    ]
                    for cat, count in sorted(cat_counts.items()):
                        lines.append(f"  {cat:<22} {count} skills")
                    lines.append(
                        "\nSkills are auto-loaded per phase. "
                        "Active skills shown in status bar."
                    )
                    chat.add_assistant_message("\n".join(lines))
                else:
                    chat.add_error_message("Failed to fetch skills.")
            except Exception as e:
                chat.add_error_message(f"Error: {e}")

        elif cmd == "/models" or cmd.startswith("/models "):
            model_arg = cmd[len("/models") :].strip()
            if not model_arg:
                try:
                    resp = await self._http.get("/api/models", timeout=15.0)
                    try:
                        data = resp.json() if resp.content else {}
                    except Exception:
                        data = {"error": resp.text}
                    if resp.status_code == 200:
                        chat.add_assistant_message(
                            self._format_models_response(data), markup=False
                        )
                    else:
                        err = str(data.get("error", "Failed to fetch models"))
                        chat.add_error_message(f"Model list failed: {err}")
                except Exception as e:
                    chat.add_error_message(f"Model list request failed: {e}")
                return

            try:
                chat.add_system_message(f"Switching model to {model_arg}")
                resp = await self._http.post(
                    "/api/models",
                    json={"model": model_arg},
                    timeout=30.0,
                )
                try:
                    data = resp.json() if resp.content else {}
                except Exception:
                    data = {"error": resp.text}
                if resp.status_code == 200:
                    model = str(data.get("current_model") or data.get("model") or model_arg)
                    thinking = data.get("thinking") if isinstance(data, dict) else {}
                    enabled = (
                        bool(thinking.get("enabled"))
                        if isinstance(thinking, dict)
                        else False
                    )
                    chat.add_assistant_message(
                        "Model switched\n"
                        f"Current: {model}\n"
                        f"Thinking: {str(enabled).lower()}",
                        markup=False,
                    )
                else:
                    err = str(data.get("error", "Model switch failed"))
                    chat.add_error_message(f"Model switch failed: {err}")
            except Exception as e:
                chat.add_error_message(f"Model switch request failed: {e}")
            return

        elif cmd == "/think" or cmd.startswith("/think "):
            arg = cmd[len("/think") :].strip()
            if not arg:
                try:
                    resp = await self._http.get("/api/think", timeout=10.0)
                    try:
                        data = resp.json() if resp.content else {}
                    except Exception:
                        data = {"error": resp.text}
                    if resp.status_code == 200:
                        chat.add_assistant_message(
                            self._format_thinking_response(data), markup=False
                        )
                    else:
                        err = str(data.get("error", "Failed to read thinking mode"))
                        chat.add_error_message(f"Thinking status failed: {err}")
                except Exception as e:
                    chat.add_error_message(f"Thinking status request failed: {e}")
                return

            enabled = self._parse_bool_arg(arg)
            if enabled is None:
                chat.add_assistant_message(
                    "Usage: /think true|false\n"
                    "Also accepted: on/off, yes/no, 1/0.",
                    markup=False,
                )
                return

            try:
                resp = await self._http.post(
                    "/api/think",
                    json={"enabled": enabled},
                    timeout=30.0,
                )
                try:
                    data = resp.json() if resp.content else {}
                except Exception:
                    data = {"error": resp.text}
                if resp.status_code == 200:
                    chat.add_assistant_message(
                        self._format_thinking_response(data), markup=False
                    )
                else:
                    err = str(data.get("error", "Failed to update thinking mode"))
                    chat.add_error_message(f"Thinking update failed: {err}")
            except Exception as e:
                chat.add_error_message(f"Thinking update request failed: {e}")
            return

        elif cmd.startswith("/shell"):
            shell_cmd = cmd[len("/shell") :].strip()
            if not shell_cmd:
                chat.add_assistant_message(
                    "Usage: /shell <command>\n"
                    "Runs command inside AIRecon Kali Docker sandbox, not host shell.\n"
                    "Blocked interactive multiplexers: tmux, screen, byobu, zellij, abduco, dtach."
                )
                return
            try:
                chat.add_system_message(f"$ {shell_cmd}")
                resp = await self._http.post(
                    "/api/shell",
                    json={"command": shell_cmd},
                    timeout=180.0,
                )
                try:
                    data = resp.json() if resp.content else {}
                except Exception:
                    data = {"error": resp.text}
                if resp.status_code == 200:
                    stdout = str(data.get("stdout", "") or "")
                    stderr = str(data.get("stderr", "") or "")
                    exit_code = data.get("exit_code")
                    success = bool(data.get("success", False))

                    def _indent_block(text: str) -> list[str]:
                        if not text.strip():
                            return ["  (empty)"]
                        return [f"  {line}" for line in text.rstrip().splitlines()]

                    body_lines: list[str] = [f"[shell] $ {shell_cmd}"]
                    if exit_code is not None:
                        body_lines.append(f"exit_code: {exit_code}")
                    body_lines.append(f"success: {success}")
                    body_lines.append("")
                    body_lines.append("stdout:")
                    body_lines.extend(_indent_block(stdout))
                    if stderr.strip():
                        body_lines.append("")
                        body_lines.append("stderr:")
                        body_lines.extend(_indent_block(stderr))
                    body = "\n".join(body_lines)
                    chat.add_assistant_message(body, markup=False)
                else:
                    err = str(data.get("error", "Shell command failed"))
                    blocked = data.get("blocked")
                    body_lines = [f"[shell] $ {shell_cmd}", "error:"]
                    body_lines.append(f"  {err}")
                    if blocked is not None:
                        body_lines.append(f"blocked: {blocked}")
                    chat.add_assistant_message("\n".join(body_lines), markup=False)
            except Exception as e:
                chat.add_error_message(f"Shell request failed: {e}")
            return

        elif cmd == "/scope" or cmd.startswith("/scope "):
            parts = cmd.split()
            sub = parts[1].lower() if len(parts) >= 2 else "show"
            payload: dict[str, Any] = {"action": sub}
            if sub in ("allow", "deny", "remove"):
                hosts = parts[2:]
                if not hosts:
                    chat.add_assistant_message(
                        f"Usage: /scope {sub} <host1> <host2> ...\n"
                        "Patterns match the host and its subdomains; '*.example.com' matches subdomains only."
                    )
                    return
                payload["hosts"] = hosts
            elif sub == "mode":
                if len(parts) < 3 or parts[2].lower() not in ("off", "warn", "block"):
                    chat.add_assistant_message("Usage: /scope mode <off|warn|block>")
                    return
                payload["mode"] = parts[2].lower()
            elif sub not in ("show", "clear"):
                chat.add_assistant_message(
                    "Usage:\n"
                    "  /scope                      show current scope\n"
                    "  /scope allow <hosts...>     add to allowlist\n"
                    "  /scope deny <hosts...>      add to denylist\n"
                    "  /scope remove <hosts...>    remove from both lists\n"
                    "  /scope mode <off|warn|block>\n"
                    "  /scope clear                clear both lists"
                )
                return
            try:
                resp = await self._http.post("/api/scope", json=payload, timeout=10.0)
                data = resp.json() if resp.content else {}
                if resp.status_code == 200 and data.get("success"):
                    lines = [
                        "[scope]",
                        f"  mode:      {data.get('mode', '?')}",
                        f"  allowlist: {', '.join(data.get('allowlist') or []) or '(empty — all hosts allowed)'}",
                        f"  denylist:  {', '.join(data.get('denylist') or []) or '(empty)'}",
                        f"  audit log: {'on' if data.get('audit_log_enabled') else 'off'}",
                    ]
                    if data.get("mode") == "warn" and (data.get("allowlist") or data.get("denylist")):
                        lines.append(
                            "  note: mode is 'warn' (advisory). Use /scope mode block to ENFORCE."
                        )
                    chat.add_assistant_message("\n".join(lines), markup=False)
                else:
                    chat.add_error_message(
                        f"Scope update failed: {data.get('error', resp.text)}"
                    )
            except Exception as e:
                chat.add_error_message(f"Scope request failed: {e}")
            return

        elif cmd.startswith("/mcp"):
            parts = cmd.split()

            if len(parts) == 1 or (
                len(parts) >= 2 and parts[1] in {"help", "-h", "--help"}
            ):
                chat.add_assistant_message(
                    "MCP command usage:\n"
                    "- /mcp add http://mcp_url auth:user/pass|auth:apikey:<token> [name]\n"
                    "- /mcp list\n"
                    "- /mcp list <name>\n"
                    "- /mcp enable <name>\n"
                    "- /mcp disable <name>"
                )
                return

            sub = parts[1] if len(parts) >= 2 else "help"

            if sub == "list":
                show_tools = "--tools" in parts or "-v" in parts
                if len(parts) >= 3 and not parts[2].startswith("-"):
                    target_name = parts[2].strip()
                    try:
                        resp = await self._http.get(
                            f"/api/mcp/tools/{target_name}", timeout=30.0
                        )
                        if resp.status_code == 200:
                            data = resp.json()
                            tools = data.get("tools", [])
                            total_tools = data.get("total_tools", 0)
                            truncated = bool(data.get("truncated", False))
                            display_tools = tools[:15]
                            lines = [f"MCP Tools: {target_name}"]
                            if truncated:
                                lines.append(
                                    f"Showing {len(display_tools)} of {total_tools} tools"
                                )
                            else:
                                lines.append(f"Total tools: {total_tools}")
                            lines.append("")
                            for t in display_tools:
                                tool_name = (
                                    t.get("name", "?")
                                    if isinstance(t, dict)
                                    else str(t)
                                )
                                lines.append(f"- {tool_name}")
                            if truncated and len(tools) > 15:
                                rest_count = len(tools) - 15
                                lines.append(
                                    f"... {rest_count} more tools omitted. Use `action='search_tools'` in mcp_* tool with a keyword to find specific tools."
                                )
                            chat.add_assistant_message("\n".join(lines))
                        else:
                            chat.add_error_message(
                                f"MCP list {target_name} failed ({resp.status_code}): {resp.text[:300]}"
                            )
                    except Exception as e:
                        chat.add_error_message(f"MCP list {target_name} failed: {e}")
                    return

                try:
                    resp = await self._http.get("/api/mcp/list", timeout=8.0)
                    if resp.status_code == 200:
                        data = resp.json()
                        servers = data.get("servers", [])
                        init_count = int(data.get("initializing", 0) or 0)
                        if not servers:
                            chat.add_assistant_message(
                                "MCP: no servers are configured yet.\n"
                                "Use `/mcp add http://mcp_url_sse auth:user/pass|auth:apikey:<token> [name]`."
                            )
                        else:
                            lines: list[str] = [f"MCP Servers ({len(servers)})\n"]
                            if init_count > 0:
                                lines.append(
                                    f"⏳ MCP servers are starting up ({init_count} initializing)..."
                                )
                                lines.append(
                                    "Note: First startup may take longer. Tool availability will update automatically.\n"
                                )

                            lines.append("Configured MCP servers:")
                            for s in servers:
                                name = s.get("name", "?")
                                status = str(s.get("status") or "initializing")
                                enabled = bool(s.get("enabled", True))
                                tool_count = s.get("tool_count") or 0
                                total_tools = s.get("total_tools")
                                tools = s.get("tools") or []
                                tool_error = s.get("tool_error")

                                if total_tools is not None and total_tools > 0:
                                    display_text = f"{total_tools}"
                                    if total_tools > tool_count:
                                        display_text = f"{total_tools}"
                                    else:
                                        display_text = f"{total_tools}"
                                else:
                                    display_text = f"{tool_count}"

                                if not enabled:
                                    lines.append(f"⚪ {name} - Disabled")
                                elif status == "ready":
                                    lines.append(
                                        f"🟢 {name} - Ready ({display_text} tools)"
                                    )
                                    if show_tools and tools:
                                        lines.append("  Tools:")
                                        for t in tools:
                                            lines.append(f"  - {t}")
                                elif status == "error":
                                    lines.append(
                                        f"🔴 {name} - Error ({tool_error or 'unknown error'})"
                                    )
                                else:
                                    init_for = int(s.get("initializing_for") or 0)
                                    lines.append(
                                        f"🟡 {name} - Initializing... ({init_for}s)"
                                    )

                            chat.add_assistant_message("\n".join(lines))

                            if init_count > 0:
                                self.run_worker(
                                    self._refresh_mcp_until_ready(
                                        show_tools=show_tools
                                    ),
                                    exclusive=False,
                                )
                    else:
                        chat.add_error_message(
                            f"MCP list failed ({resp.status_code}): {resp.text[:300]}"
                        )
                except Exception as e:
                    chat.add_error_message(
                        f"MCP list request failed or timed out. Details: {e}"
                    )
                return

            if sub == "add" and len(parts) >= 3:
                mcp_url = parts[2].strip()
                mcp_name = None
                mcp_auth = None
                for p in parts[3:]:
                    if p.startswith("auth:"):
                        auth_val = p[len("auth:") :]
                        mcp_auth = auth_val
                    elif mcp_name is None:
                        mcp_name = p.strip()

                try:
                    resp = await self._http.post(
                        "/api/mcp/add",
                        json={"url": mcp_url, "auth": mcp_auth, "name": mcp_name},
                    )
                    if resp.status_code == 200:
                        data = resp.json()
                        name = data.get("name", "?")
                        chat.add_assistant_message(
                            f"MCP server added: {name}\n"
                            "Use `/mcp enable <name>` or `/mcp disable <name>` to toggle.\n"
                            "Tool registry refreshed automatically."
                        )
                    else:
                        chat.add_error_message(
                            f"MCP add failed ({resp.status_code}): {resp.text[:300]}"
                        )
                except Exception as e:
                    chat.add_error_message(f"Error MCP add: {e}")
                return

            if sub in {"enable", "disable"} and len(parts) >= 3:
                mcp_name = parts[2].strip()
                endpoint = "/api/mcp/enable" if sub == "enable" else "/api/mcp/disable"
                try:
                    resp = await self._http.post(endpoint, json={"name": mcp_name})
                    if resp.status_code == 200:
                        chat.add_assistant_message(
                            f"MCP server '{mcp_name}' {sub}d successfully."
                        )
                    else:
                        chat.add_error_message(
                            f"MCP {sub} failed ({resp.status_code}): {resp.text[:300]}"
                        )
                except Exception as e:
                    chat.add_error_message(f"MCP {sub} failed: {e}")
                return

            chat.add_error_message(
                "Invalid /mcp format. Use:\n"
                "- /mcp add http://mcp_url auth:user/pass|auth:apikey:<token> [name]\n"
                "- /mcp list\n"
                "- /mcp list <name>\n"
                "- /mcp enable <name>\n"
                "- /mcp disable <name>"
            )

        elif cmd == "/tools":
            try:
                resp = await self._http.get("/api/tools")
                if resp.status_code == 200:
                    data = resp.json()
                    tools = data.get("tools", [])

                    lines = [f"Available Tools ({len(tools)})", ""]

                    for t in tools:
                        if "function" in t:
                            fn = t["function"]
                            name = str(fn.get("name", "?")).strip()
                            desc = str(fn.get("description", "")).strip()
                        else:
                            name = str(t.get("name", "?")).strip()
                            desc = str(t.get("description", "")).strip()

                        desc = desc.split("\n")[0].strip()
                        if len(desc) > 100:
                            desc = desc[:97].rstrip() + "..."
                        lines.append(f"- {name}: {desc or '-'}")

                    chat.add_assistant_message("\n".join(lines), markup=False)
                else:
                    chat.add_error_message("Failed to fetch tools")
            except Exception as e:
                chat.add_error_message(f"Error: {e}")

        elif cmd == "/info":
            info_text = """## ℹ️ AIRecon Information

**Key Bindings:**
- ESC: Stop current generation/thinking.
- Ctrl+C: Quit the application.
- Ctrl+L: Clear chat history.
- Ctrl+R: Reset conversation (clears context).
- PgUp/PgDn: Scroll chat.

**Commands:**
- /help: Show this help message.
- /info: Show AIRecon information.
- /status: Check service status.
- /tools: List available tools.
- /skills: Show AI skills.
- /mcp: Manage MCP servers.
- /models: List/switch OpenAI-compatible models.
- /think true|false: Enable/disable thinking.
- /shell <command>: Run command in AIRecon Kali Docker shell.
- /reset: Reset conversation.
- /clear: Clear chat history.

**Tips:**
- You can ask the AI to run scans, search the web, or browse pages.
- Click a file in the workspace panel to load it as context for your next prompt."""
            chat.add_assistant_message(info_text)

        elif cmd == "/reset":
            await self.action_reset()
        elif cmd == "/clear":
            self.action_clear()
        else:
            chat.add_error_message(
                f"Unknown command: `{cmd}`. Type `/help` for available commands."
            )

    def action_clear(self) -> None:
        self.query_one("#chat-panel", ChatPanel).clear_messages()

    async def action_reset(self) -> None:
        chat = self.query_one("#chat-panel", ChatPanel)
        workspace = self.query_one("#workspace-panel", WorkspacePanel)

        try:
            await self._http.post("/api/reset")
            chat.clear_messages()
            workspace.reload()
            chat.add_assistant_message("Conversation reset. Ready for a new session.")
            self._clear_active_file_context()
        except Exception as e:
            chat.add_error_message(f"Reset failed: {e}")

    async def action_cancel_generation(self) -> None:
        if self._chat_worker and self._chat_worker.is_running:
            self._chat_worker.cancel()

        self._processing = False

        chat = self.query_one("#chat-panel", ChatPanel)
        chat.add_system_message(
            "🛑 User stopped progress (killing running tools, agent stays active)..."
        )
        self.notify(
            "Tools stopped - agent ready for next command.", severity="information"
        )

        chat.end_streaming()
        chat.end_thinking()

        try:
            await self._http.post("/api/stop", timeout=2.0)
        except Exception as e:
            logger.error(f"Failed to send stop signal: {e}")

    def action_request_quit(self) -> None:
        def _on_dismiss(confirmed: bool | None) -> None:
            if confirmed:
                self.run_worker(self.action_quit(), exclusive=True)

        self.push_screen(QuitConfirmScreen(), _on_dismiss)

    async def action_quit(self) -> None:
        # Always reach self.exit(), even if a cleanup step stalls — otherwise the
        # app can hang on quit (the reported Ctrl+C → "yes" freeze).
        try:
            # 1) Stop the local SSE stream worker FIRST so it releases the HTTP
            #    connection. Closing self._http below while a stream is still
            #    in-flight on the same client can block indefinitely.
            try:
                if self._chat_worker and self._chat_worker.is_running:
                    self._chat_worker.cancel()
            except Exception as e:
                logger.debug("Expected failure cancelling chat worker on quit: %s", e)

            # 2) Tell the server to stop the agent — hard-bounded so a slow/stuck
            #    server can never freeze the UI.
            try:
                await asyncio.wait_for(self._http.post("/api/stop"), timeout=2.0)
            except Exception as e:
                logger.debug("Expected failure in action_quit send stop: %s", e)

            if self._status_task and not self._status_task.done():
                self._status_task.cancel()

            # Remote OpenAI-compatible backends (LiteLLM/vLLM/hosted) are
            # stateless — there is no local model in VRAM to unload on quit.

            # 3) Close the HTTP client, bounded so a lingering connection can't
            #    block the shutdown.
            try:
                await asyncio.wait_for(self._http.aclose(), timeout=2.0)
            except Exception as e:
                logger.debug("Expected failure in action_quit http close: %s", e)
        finally:
            self.exit()

    def on_text_selected(self) -> None:
        """Fires on mouse-up after a drag-selection in the terminal.
        See textual.screen → `post_message(events.TextSelected())`.
        Covers chat, tool-output, and any other text panels without
        per-widget instrumentation."""
        try:
            selected = (self.screen.get_selected_text() or "").strip()
        except Exception as e:
            logger.debug("on_text_selected: get_selected_text failed: %s", e)
            return
        if not selected:
            return
        if getattr(self, "_last_autocopied_chat_selection", None) == selected:
            return
        self._last_autocopied_chat_selection = selected
        self.copy_to_clipboard(selected)

    async def _hide_copy_toast_after_delay(self, seconds: float = 1.2) -> None:
        await asyncio.sleep(seconds)
        try:
            self.query_one("#copy-toast-wrap", Container).display = False
        except Exception as e:
            logger.debug("Expected failure in _hide_copy_toast_after_delay: %s", e)

    def _show_copy_toast(self, message: str = "Copied to clipboard") -> None:
        try:
            wrap = self.query_one("#copy-toast-wrap", Container)
            msg = self.query_one("#copy-toast-msg", Static)
            msg.update(message)
            wrap.display = True
            if self._copy_toast_task and not self._copy_toast_task.done():
                self._copy_toast_task.cancel()
            self._copy_toast_task = asyncio.create_task(
                self._hide_copy_toast_after_delay(1.2)
            )
        except Exception as e:
            logger.debug("Expected failure in _show_copy_toast: %s", e)

    def copy_to_clipboard(self, content: str) -> None:
        copied = False

        try:
            super().copy_to_clipboard(content)
            if getattr(self, "_driver", None) is not None:
                copied = True
        except Exception as e:
            logger.debug("Expected failure in OSC52 clipboard: %s", e)

        try:
            import pyperclip

            pyperclip.copy(content)
            copied = True
        except ImportError:
            if not copied:
                self.notify(
                    "Clipboard unavailable: install pyperclip or use an OSC52-capable terminal.",
                    severity="warning",
                )
        except Exception as e:
            if copied:
                logger.debug("Expected failure in pyperclip.copy: %s", e)
            else:
                self.notify(f"Clipboard error: {e}", severity="error")

        if not copied:
            try:
                import shutil
                import subprocess  # nosec B404

                clipboard_cmds: list[list[str]] = []
                if shutil.which("wl-copy"):
                    clipboard_cmds.append(["wl-copy"])
                if shutil.which("xclip"):
                    clipboard_cmds.append(["xclip", "-selection", "clipboard"])
                if shutil.which("xsel"):
                    clipboard_cmds.append(["xsel", "--clipboard", "--input"])
                if shutil.which("pbcopy"):
                    clipboard_cmds.append(["pbcopy"])
                if shutil.which("clip"):
                    clipboard_cmds.append(["clip"])

                for cmd in clipboard_cmds:
                    try:
                        subprocess.run(  # nosec B603
                            cmd,
                            input=content.encode(),
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                            check=False,
                            timeout=2,
                        )
                        copied = True
                        break
                    except Exception as cmd_err:
                        logger.debug(
                            "Clipboard helper failed (%s): %s", " ".join(cmd), cmd_err
                        )
            except Exception as e:
                logger.debug("Clipboard helper init failed: %s", e)

        if copied:
            self._show_copy_toast("Copied to clipboard")
        else:
            self.notify(
                "Clipboard unavailable: enable OSC52 or install wl-copy/xclip/xsel/pyperclip.",
                severity="warning",
            )

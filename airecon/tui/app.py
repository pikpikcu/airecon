"""AIRecon Textual TUI Application."""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import time
import uuid
from pathlib import Path
from typing import Any

import httpx
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, DirectoryTree, Header, Label, Static

from airecon.proxy.config import get_workspace_root

from .widgets.chat import ChatPanel, ToolMessageSelected
from .widgets.file_preview import FilePreviewScreen
from .widgets.input import CommandInput, SlashCompleter
from .widgets.path_completer import PathCompleter
from .widgets.status import SkillsModal, StatusBar
from .widgets.workspace import WorkspacePanel, WorkspaceTree

logger = logging.getLogger("airecon.tui")


class QuitConfirmScreen(ModalScreen[bool]):
    """Confirmation dialog shown when user presses Ctrl+C."""

    DEFAULT_CSS = ""  # Styles defined in styles.tcss

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
            # Default to "No" on Enter so accidental Enter doesn't quit
            self.dismiss(False)
        elif event.key == "y":
            self.dismiss(True)
        elif event.key == "n":
            self.dismiss(False)


class AIReconApp(App):
    """AIRecon Terminal User Interface."""

    TITLE = "AIRecon"
    SUB_TITLE = "AI Security Reconnaissance"
    CSS_PATH = "styles.tcss"
    BINDINGS = [
        Binding("ctrl+c", "request_quit", "Quit", show=True, priority=True),
        Binding("ctrl+q", "request_quit", "Quit", show=False, priority=True),
        Binding("ctrl+l", "clear", "Clear Chat", show=True),
        Binding("ctrl+r", "reset", "Reset", show=True),
        Binding("pageup", "scroll_chat_up", "Scroll Up", show=False),
        Binding("pagedown", "scroll_chat_down", "Scroll Down", show=False),
        Binding(
            "escape",
            "cancel_generation",
            "Stop AI",
            show=True,
            priority=True),
    ]

    def action_scroll_chat_up(self) -> None:
        """Scroll chat up."""
        self.query_one("#chat-panel", ChatPanel).scroll_up()

    def action_scroll_chat_down(self) -> None:
        """Scroll chat down."""
        self.query_one("#chat-panel", ChatPanel).scroll_down()

    def on_status_bar_skills_clicked(self, event: StatusBar.SkillsClicked) -> None:
        """Show the modal listing all loaded skills."""
        status_bar = self.query_one(StatusBar)
        if status_bar.skills_used:
            self.push_screen(SkillsModal(status_bar.skills_used))

    def __init__(
        self,
        proxy_url: str = "http://127.0.0.1:3000",
        no_proxy: bool = False,
        session_id: str | None = None,
        **kwargs,
    ) -> None:
        super().__init__(**kwargs)
        self.proxy_url = proxy_url.rstrip("/")
        self._no_proxy = no_proxy
        self._session_id = session_id
        # SSE streaming requires no read timeout; connect still has a limit
        _sse_timeout = httpx.Timeout(connect=10.0, read=None, write=10.0, pool=10.0)
        self._http = httpx.AsyncClient(base_url=self.proxy_url, timeout=_sse_timeout)
        self._processing = False
        self._chat_worker: asyncio.Task | None = None
        self._current_tool_id: str | None = None
        self._status_task: asyncio.Task | None = None
        self.current_context_path: Path | None = None
        self.active_file_content: str | None = None
        self.active_file_path: Path | None = None
        self._last_workspace_reload: float = 0.0
        self._last_scroll_time: float = 0.0   # scroll debounce, init here not lazily
        self._recon_frame: int = 0
        self._file_agents_running: int = 0  # active file-analyze sub-agents

    def compose(self) -> ComposeResult:
        yield Header()

        # 1. Dock Workspace Panel to the Right (Sticks to edge)
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
        """Initialize on mount."""
        self.set_interval(0.1, self._tick_recon_spinner)

        try:
            self.query_one("#workspace-panel", WorkspacePanel).reload()
        except Exception:  # nosec B110 - widget may not exist yet
            pass

        chat = self.query_one("#chat-panel", ChatPanel)
        chat.add_assistant_message(
            "\n"
            "  ▄▖▄▖▄▖\n"
            "  ▌▌▐ ▙▘█▌▛▘▛▌▛▌\n"
            "  ▛▌▟▖▌▌▙▖▙▖▙▌▌▌\n"
            "\n"
            "Docker Sandbox (Kali Linux) · Outputs → ./workspace/<target>/\n"
            "Commands: /help · /skills · /status · /clear\n"
            "Examples:\n"
            "- full recon on example.com\n"
            "- do a pentest on this target\n"
            "- review this code @/path/file or @/path/dir\n"
            "- bug bounty on example.com — find everything\n"
        )

        # Focus input
        self.query_one("#command-input", CommandInput).focus()

        # Push startup screen — status polling starts only after it dismisses
        from .startup import StartupScreen

        def _on_startup_done(success: bool) -> None:
            self._status_task = asyncio.create_task(self._poll_services())

        self.push_screen(
            StartupScreen(
                proxy_url=self.proxy_url,
                no_proxy=self._no_proxy,
                session_id=self._session_id,
            ),
            _on_startup_done,
        )

    async def on_unmount(self) -> None:
        """Best-effort cleanup for test/exit paths that bypass action_quit."""
        if self._status_task and not self._status_task.done():
            self._status_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._status_task

        if self._chat_worker and self._chat_worker.is_running:
            self._chat_worker.cancel()

        with contextlib.suppress(Exception):  # nosec B110 - cleanup is best-effort
            await self._http.aclose()

    _SPINNER_CHARS = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]

    def _tick_recon_spinner(self) -> None:
        """Advance spinner animation frame when LLM is active."""
        if not self._processing and not self._file_agents_running:
            return
        self._recon_frame = (self._recon_frame + 1) % len(self._SPINNER_CHARS)
        try:
            char = self._SPINNER_CHARS[self._recon_frame]
            self.query_one("#recon-bar", Static).update(
                f"[bold #3b82f6]{char}[/]  [#8b949e]esc  interrupt[/]"
            )
        except Exception:  # nosec B110 - spinner update is best-effort
            pass

    def _show_recon_spinner(self) -> None:
        """Show the recon spinner immediately."""
        try:
            bar = self.query_one("#recon-bar", Static)
            bar.update(
                f"[bold #3b82f6]{self._SPINNER_CHARS[0]}[/]  [#8b949e]esc  interrupt[/]"
            )
            bar.styles.height = 1
        except Exception:  # nosec B110 - spinner update is best-effort
            pass

    def _hide_recon_spinner(self) -> None:
        """Hide the recon spinner."""
        try:
            self.query_one("#recon-bar", Static).styles.height = 0
        except Exception:  # nosec B110 - spinner update is best-effort
            pass

    async def on_workspace_tree_file_selected(
            self, event: WorkspaceTree.FileSelected) -> None:
        """Handle file selection to show preview and set as active context."""
        chat = self.query_one(ChatPanel)
        try:
            file_path = event.path

            # Update vulnerabilities view if file is within a target
            try:
                # Assume workspace structure: workspace/<target>/...
                # We can try to derive target from path relative to workspace
                # root
                workspace_root = get_workspace_root()
                abs_path = file_path.resolve()

                if workspace_root in abs_path.parents:
                    rel = abs_path.relative_to(workspace_root)
                    if len(
                            # Must be nested under a target folder (target/...)
                            rel.parts) > 1:
                        search_path = abs_path
                        target_path = None

                        while search_path != workspace_root:
                            if any((search_path / folder).is_dir()
                                   for folder in ['vulnerabilities', 'output', 'command', 'tools']):
                                target_path = search_path
                                break
                            search_path = search_path.parent

                        if not target_path:
                            target_path = abs_path if abs_path.is_dir() else abs_path.parent

                        self.query_one(
                            "#workspace-panel",
                            WorkspacePanel).update_vulnerabilities_path(target_path)
                    else:
                        # File is in root workspace, clear vulnerabilities view
                        self.query_one(
                            "#workspace-panel",
                            WorkspacePanel).clear_vulnerabilities_view()
            except Exception:  # nosec B110 - vulnerability view update is best-effort
                pass

            # Limit context reading — offload to thread to avoid blocking TUI
            def _read_file_sync() -> str:
                try:
                    if file_path.stat().st_size > 50_000:
                        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                            return f.read(50_000) + "\n... [TRUNCATED CONTEXT] ..."
                    return file_path.read_text(encoding="utf-8", errors="replace")
                except Exception as exc:
                    return f"Error reading file: {exc}"

            import asyncio
            content = await asyncio.to_thread(_read_file_sync)

            # Set active file context
            self.active_file_path = file_path
            self.active_file_content = content

            chat.add_system_message(
                f"File context loaded: [bold green]{file_path.name}[/bold green]. "
                "Use 'this file' or 'the loaded file' in your next prompt."
            )

            # Preview using optimized screen
            self._open_file_preview(str(file_path))

        except Exception as e:
            chat.add_error_message(f"Error reading file for context: {e}")
            self.active_file_path = None
            self.active_file_content = None

    # NOTE: on_directory_tree_file_selected is defined once below (near L319)
    # to avoid duplicate handler.

    def on_workspace_tree_directory_selected(
            self, event: WorkspaceTree.DirectorySelected) -> None:
        """Update context and vulnerabilities view."""
        if event.control is not None and event.control.id != "workspace-tree":
            return

        self.current_context_path = event.path
        chat = self.query_one(ChatPanel)
        chat.add_system_message(f"Context set to: {event.path}")

        # Update vulnerabilities view if directory is a target or within one
        try:
            workspace_root = get_workspace_root().resolve()
            abs_path = event.path.resolve()

            # Check if path is under workspace (it should be)
            if workspace_root in abs_path.parents or abs_path == workspace_root:
                # If it is the workspace root itself, clear view
                if abs_path == workspace_root:
                    self.query_one(
                        "#workspace-panel",
                        WorkspacePanel).clear_vulnerabilities_view()
                    return

                rel = abs_path.relative_to(workspace_root)
                if len(rel.parts) >= 1:
                    search_path = abs_path
                    target_path = None

                    while search_path != workspace_root:
                        if any((search_path / folder).is_dir()
                               for folder in ['vulnerabilities', 'output', 'command', 'tools']):
                            target_path = search_path
                            break
                        search_path = search_path.parent

                    if not target_path:
                        target_path = abs_path if abs_path.is_dir() else abs_path.parent

                    self.query_one(
                        "#workspace-panel",
                        WorkspacePanel).update_vulnerabilities_path(target_path)
        except Exception:  # nosec B110 - vulnerability view update is best-effort
            pass

    async def _poll_services(self) -> None:
        """Poll proxy status with retries until connected."""
        status_bar = self.query_one("#status-bar", StatusBar)
        chat = self.query_one("#chat-panel", ChatPanel)

        max_retries = 40  # up to 40 seconds
        connected = False
        proxy_reachable = False

        for attempt in range(max_retries):
            try:
                resp = await self._http.get("/api/status", timeout=3.0)
                if resp.status_code == 200:
                    data = resp.json()
                    ollama_ok = data.get("ollama", {}).get("connected", False)
                    docker_ok = data.get("docker", {}).get("connected", False)
                    model = data.get("ollama", {}).get("model", "—")
                    agent_stats = data.get("agent", {})
                    tool_counts = agent_stats.get("tool_counts", {})
                    exec_used = tool_counts.get("exec", 0)
                    subagents = tool_counts.get("subagents", 0)
                    token_info = agent_stats.get("token_usage", {})
                    tokens_used = token_info.get("cumulative", token_info.get("used", 0))
                    tokens_limit = token_info.get("limit", 65536)
                    skills_info = agent_stats.get("skills_used", [])
                    caido_data = agent_stats.get("caido", {})

                    proxy_reachable = True
                    status_bar.set_status(
                        ollama="online" if ollama_ok else "offline",
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

                    if ollama_ok and docker_ok:
                        connected = True
                        chat.add_assistant_message(
                            f"✅ Connected — **{model}** ready with Docker sandbox"
                        )
                        # Show current session info
                        try:
                            sess_resp = await self._http.get("/api/session/current", timeout=3.0)
                            if sess_resp.status_code == 200:
                                sess = sess_resp.json().get("session")
                                if sess:
                                    sid = sess.get("session_id", "?")
                                    target = sess.get(
                                        "target") or "no target yet"
                                    scans = sess.get("scan_count", 0)
                                    chat.add_system_message(
                                        f"🔖 Active session: `{sid}` — {target}"
                                        + (f" ({scans} scans)" if scans else "")
                                    )
                        except Exception:  # nosec B110 - session display is best-effort
                            pass
                        break
            except Exception:  # nosec B110 - poll retry on connection error
                pass

            await asyncio.sleep(1.0)

        if not connected:
            if proxy_reachable:
                # Proxy is running but Ollama/Docker aren't ready
                data = {}
                try:
                    resp = await self._http.get("/api/status", timeout=3.0)
                    data = resp.json()
                except Exception:  # nosec B110 - status fetch is best-effort
                    pass
                ollama_ok = data.get("ollama", {}).get("connected", False)
                docker_ok = data.get("docker", {}).get("connected", False)
                issues = []
                if not ollama_ok:
                    issues.append("Ollama offline (check `ollama serve`)")
                if not docker_ok:
                    issues.append(
                        "Docker sandbox not running (check Docker daemon)")
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

        # After initial connection, keep status alive with longer interval to
        # avoid CPU pressure
        while True:
            await asyncio.sleep(5.0)

            # Refresh workspace tree automatically
            try:
                self.query_one("#workspace-panel", WorkspacePanel).reload()
            except Exception:  # nosec B110 - reload is best-effort
                pass

            try:
                resp = await self._http.get("/api/status", timeout=3.0)
                if resp.status_code == 200:
                    data = resp.json()
                    ollama_ok = data.get("ollama", {}).get("connected", False)
                    docker_ok = data.get("docker", {}).get("connected", False)
                    model = data.get("ollama", {}).get("model", "—")
                    tool_counts = data.get("agent", {}).get("tool_counts", {})
                    exec_used = tool_counts.get("exec", 0)
                    subagents = tool_counts.get("subagents", 0) + self._file_agents_running
                    token_info = data.get("agent", {}).get("token_usage", {})
                    tokens_used = token_info.get("cumulative", token_info.get("used", 0))
                    tokens_limit = token_info.get("limit", 65536)
                    skills_info = data.get("agent", {}).get("skills_used", [])
                    caido_data = data.get("agent", {}).get("caido", {})
                    caido_active = caido_data.get("active", False)
                    caido_findings = caido_data.get("findings_count", 0)

                    self.query_one("#status-bar", StatusBar).set_status(
                        ollama="online" if ollama_ok else "offline",
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
            except Exception:  # nosec B110 - status bar update is best-effort
                pass

    async def _check_services(self, verbose: bool = False) -> None:
        """Check services status. verbose=True prints full report to chat."""
        status_bar = self.query_one("#status-bar", StatusBar)
        chat = self.query_one("#chat-panel", ChatPanel)
        try:
            resp = await self._http.get("/api/status", timeout=5.0)
            if resp.status_code == 200:
                data = resp.json()
                ollama = data.get("ollama", {})
                docker = data.get("docker", {})
                agent = data.get("agent", {})

                ollama_ok = ollama.get("connected", False)
                docker_ok = docker.get("connected", False)
                model = ollama.get("model", "—")

                tool_counts = agent.get("tool_counts", {})
                exec_used = tool_counts.get("exec", 0)
                subagents = tool_counts.get("subagents", 0)

                status_bar.set_status(
                    ollama="online" if ollama_ok else "offline",
                    docker="online" if docker_ok else "offline",
                    model=model,
                    exec_used=exec_used,
                    subagents=subagents,
                )

                if verbose:
                    # Comprehensive Status Report
                    status_md = f"""## 🟢 AIRecon Status Report

### **Core Services**
- **Ollama**: {'✅ Online' if ollama_ok else '❌ Offline'}
  - URL: `{ollama.get("url", "Unknown")}`
  - Model: `{model}`
- **Docker Sandbox**: {'✅ Running' if docker_ok else '❌ Stopped'}
  - Image: `{docker.get("image", "airecon-sandbox")}`

### **Agent Statistics**
- **Messages**: {agent.get("message_count", 0)}
- **Commands Executed**: **{exec_used}**
"""
                    chat.add_assistant_message(status_md)
                else:
                    # Brief update for auto-checks
                    pass

            else:
                status_bar.set_status(ollama="offline", docker="offline")
                if verbose:
                    chat.add_error_message(
                        f"Status check failed: HTTP {resp.status_code}"
                    )
        except Exception as e:
            status_bar.set_status(ollama="offline", docker="offline")
            if verbose:
                chat.add_error_message(f"Status check error: {e}")

    # ToolMessageSelected imported at top-level

    def on_tool_message_selected(self, message: ToolMessageSelected) -> None:
        """Handle click on a tool message result."""
        logger.debug(f"App received selection: {message.output_file}")
        self._open_file_preview(message.output_file)

    def on_directory_tree_file_selected(
            self, event: DirectoryTree.FileSelected) -> None:
        """Handle file selection from workspace tree."""
        # Reuse the logic for opening files
        # We can just construct a dummy message or call a shared helper
        # But for now, let's duplicate the logic slightly or better, refactor.
        # Refactoring to shared method _open_file_preview
        self._open_file_preview(str(event.path))

    def _open_file_preview(self, file_path: str) -> None:
        """Open a file in preview modal."""
        try:
            p = Path(file_path)
            if not p.exists():
                # Try finding it relative to cwd
                p = Path.cwd() / file_path

            if p.exists():
                if p.is_dir():
                    return
                # Pass path only, let FilePreviewScreen handle lazy/smart
                # loading
                self.push_screen(
                    FilePreviewScreen(
                        str(p)), self.on_preview_result)
            else:
                self.query_one(ChatPanel).add_error_message(
                    f"File not found: {file_path}")
        except Exception as e:
            self.query_one(ChatPanel).add_error_message(
                f"Failed to open file: {e}")

    async def on_preview_result(self, result: Any) -> None:
        """Handle result from FilePreviewScreen dismissal.

        Instead of sending the prompt to the main recon agent (which would
        interrupt ongoing reconnaissance), this spawns an independent mini-agent
        via /api/file-analyze.  Both agents run concurrently.
        """
        if isinstance(result, FilePreviewScreen.Submitted):
            abs_path = os.path.abspath(result.file_path)
            _abs = Path(abs_path)
            _cwd = Path(os.getcwd())
            display_path = (
                str(_abs.relative_to(_cwd))
                if _abs.is_relative_to(_cwd) else abs_path
            )

            chat = self.query_one(ChatPanel)
            chat.add_user_message(
                f"[FILE ANALYSIS: {display_path}]\n{result.user_prompt}"
            )
            chat.add_system_message(
                "[dim]Running as background sub-agent — main recon continues uninterrupted.[/dim]"
            )

            # Read file content in a thread to avoid blocking the TUI event loop
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
        """Clear active file context after use/reset."""
        self.active_file_path = None
        self.active_file_content = None

    # ── @/path Autocomplete Handlers ────────────────────────────────────────

    def on_command_input_at_path_changed(
            self, event: CommandInput.AtPathChanged) -> None:
        """Show or update the path completer when user types @/..."""
        try:
            completer = self.query_one("#path-completer", PathCompleter)
            if event.fragment is None:
                completer.hide()
            else:
                completer.show_for(event.fragment)
        except Exception:  # nosec B110
            pass

    def on_command_input_tab_pressed(
            self, event: CommandInput.TabPressed) -> None:
        """Complete with the first/highlighted entry on Tab."""
        try:
            slash_completer = self.query_one("#slash-completer", SlashCompleter)
            if slash_completer.display:
                cmd = slash_completer.get_first_command()
                if cmd:
                    cmd_input = self.query_one("#command-input", CommandInput)
                    cmd_input.do_slash_completion(cmd)
                    slash_completer.hide()
                return
        except Exception:  # nosec B110
            pass

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
                # Directory selected — refresh list for the new path
                completer.show_for(path)
            else:
                completer.hide()
        except Exception:  # nosec B110
            pass

    def on_command_input_escape_completion(
            self, event: CommandInput.EscapeCompletion) -> None:
        """Dismiss completers on Escape."""
        try:
            slash_completer = self.query_one("#slash-completer", SlashCompleter)
            if slash_completer.display:
                slash_completer.hide()
        except Exception:  # nosec B110
            pass
        try:
            completer = self.query_one("#path-completer", PathCompleter)
            if completer.display:
                completer.hide()
        except Exception:  # nosec B110
            pass

    # ── /slash Command Autocomplete Handlers ────────────────────────────────

    def on_command_input_slash_changed(
            self, event: CommandInput.SlashChanged) -> None:
        """Show or update the slash completer when user types /..."""
        try:
            completer = self.query_one("#slash-completer", SlashCompleter)
            if event.fragment is None:
                completer.hide()
            else:
                completer.show_for(event.fragment)
        except Exception:  # nosec B110
            pass

    def on_slash_completer_completed(
            self, event: SlashCompleter.Completed) -> None:
        """User clicked/selected a slash command entry."""
        try:
            cmd_input = self.query_one("#command-input", CommandInput)
            cmd_input.do_slash_completion(event.command)
            self.query_one("#slash-completer", SlashCompleter).hide()
            cmd_input.focus()
        except Exception:  # nosec B110
            pass

    # ── @/path Autocomplete Handlers ────────────────────────────────────────

    def on_path_completer_completed(
            self, event: PathCompleter.Completed) -> None:
        """User clicked/selected an entry from the path completer."""
        try:
            cmd_input = self.query_one("#command-input", CommandInput)
            cmd_input.do_completion(event.path)
            completer = self.query_one("#path-completer", PathCompleter)
            if event.path.endswith("/"):
                completer.show_for(event.path)
            else:
                completer.hide()
            cmd_input.focus()
        except Exception:  # nosec B110
            pass

    # ────────────────────────────────────────────────────────────────────────

    async def on_command_input_submitted(
            self, message: CommandInput.Submitted) -> None:
        """Handle user input submission."""
        user_input = message.value.strip()
        if not user_input:
            return

        # Dismiss completers on submit
        try:
            self.query_one("#slash-completer", SlashCompleter).hide()
        except Exception:  # nosec B110
            pass
        try:
            self.query_one("#path-completer", PathCompleter).hide()
        except Exception:  # nosec B110
            pass

        # Handle slash commands (always allowed even during processing)
        if user_input.startswith("/"):
            await self._handle_slash_command(user_input)
            return

        # Block new prompts while agent is working
        if self._processing:
            self.notify(
                "⏳ Agent is still working. Wait for it to finish.",
                severity="warning",
                timeout=3,
            )
            return

        chat = self.query_one("#chat-panel", ChatPanel)

        # Inject context if available
        prompt = user_input
        if self.current_context_path:
            prompt = f"[CONTEXT: Focus on {self.current_context_path}]\n{user_input}"

        # Add user message
        chat.add_user_message(user_input)

        # Show thinking spinner IMMEDIATELY (before SSE stream starts)
        chat.start_thinking()
        self._show_recon_spinner()

        # Run chat stream in background worker
        self._chat_worker = self.run_worker(self._stream_chat_response(prompt))

    async def _stream_chat_response(
            self, prompt: str, inject_context: bool = True) -> None:
        """Stream chat response from proxy (runs in worker)."""
        logger.debug(f"Starting chat stream for prompt: {prompt[:50]}...")
        self._processing = True
        chat = self.query_one("#chat-panel", ChatPanel)

        try:

            # Add active file context if available and requested
            if inject_context and self.active_file_content and self.active_file_path:
                file_ext = self.active_file_path.suffix.lower()
                file_path_str = str(self.active_file_path.resolve())

                # Try to parse specific file types for better context injection
                file_context_message_parts = []

                if file_ext == ".json":
                    try:
                        parsed_content = json.loads(self.active_file_content)
                        # Detect subfinder/tool output structure
                        if isinstance(parsed_content,
                                      dict) and "result" in parsed_content:
                            result_data = parsed_content["result"]
                            # Case: Subfinder or similar tool outputting
                            # newline-separated domains in stdout
                            if isinstance(result_data,
                                          dict) and "stdout" in result_data:
                                stdout_content = result_data["stdout"].strip()
                                domains = [
                                    d.strip() for d in stdout_content.split("\n") if d.strip()]
                                count = len(domains)

                                # Inject summary and instructions
                                file_context_message_parts.append(
                                    f"User loaded file: {file_path_str}\n"
                                    f"Type: Tool Output (JSON)\n"
                                    f"Content Summary: Contains {count} subdomains/targets.\n"
                                    f"Top 20 Targets: {', '.join(domains[:20])}...\n"
                                    f"INSTRUCTION: This file contains the target list. If the user asks to probe or scan these, use the file path '{file_path_str}' if the tool supports file input, or iterate through the high-value targets."
                                )
                            else:
                                # Generic JSON result
                                file_context_message_parts.append(
                                    f"User loaded file: {file_path_str} (JSON Result). "
                                    f"Content snippet: {str(parsed_content)[:500]}..."
                                )
                        else:
                            # Generic JSON
                            file_context_message_parts.append(
                                f"User loaded file: {file_path_str} (JSON). Content snippet: {self.active_file_content[:500]}...")

                    except json.JSONDecodeError:
                        file_context_message_parts.append(
                            f"User loaded file: {file_path_str} (Raw Content). Snippet: {self.active_file_content[:500]}...")
                else:
                    # Text/Other files
                    file_context_message_parts.append(
                        f"User loaded file: {file_path_str}. Content snippet: {self.active_file_content[:500]}...")

                # Construct the final prompt with context
                context_str = "\n".join(file_context_message_parts)
                prompt_with_context = f"[SYSTEM: ACTIVE FILE CONTEXT]\n{context_str}\n\n[USER PROMPT]\n{prompt}"

                # Clear active file context after injection
                _ctx_file_name = self.active_file_path.name if self.active_file_path else "file"
                self._clear_active_file_context()
                chat.add_system_message(
                    f"[dim]Sent context from {_ctx_file_name}[/dim]")
            else:
                prompt_with_context = prompt

            logger.debug(f"Connecting to proxy at {self.proxy_url}/api/chat")
            # Send to proxy with SSE streaming
            async with self._http.stream(
                "POST",
                "/api/chat",
                # Use "message" key with concatenated string
                json={"message": prompt_with_context, "stream": True},
                headers={"Accept": "text/event-stream"},
                # connect+write timeout 30s; read=None so long-running streams
                # don't time out between chunks, but a dead proxy is detected
                # at the connection stage rather than hanging forever.
                timeout=httpx.Timeout(30.0, read=None),
            ) as resp:
                logger.debug(f"Proxy response status: {resp.status_code}")

                if resp.status_code != 200:
                    body = await resp.aread()
                    error_msg = f"Proxy error ({resp.status_code}): {body.decode()[:500]}"
                    logger.error(error_msg)
                    chat.add_error_message(error_msg)
                    return

                streaming_started = False
                logger.debug("Start reading SSE stream...")

                async for line in resp.aiter_lines():
                    if not line:
                        continue

                    # Parse SSE format: look for "event:" and "data:" lines
                    if line.startswith("event:"):
                        continue  # event type line, we get type from data

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
                            f"Failed to parse SSE JSON: {data_str[:100]} - {e}")
                        continue

                    event_type = event.get("type", "")
                    logger.debug(f"Received event: {event_type}")

                    if event_type == "text":
                        content = event.get("content", "")
                        if content:
                            if not streaming_started:
                                chat.start_streaming()
                                streaming_started = True
                            chat.append_to_stream(content)
                            # Debounce scroll: at most once per 300ms
                            _now = time.monotonic()
                            if _now - self._last_scroll_time >= 0.3:
                                chat.scroll_end(animate=False)
                                self._last_scroll_time = _now

                    elif event_type == "thinking":
                        content = event.get("content", "")
                        if content:
                            chat.append_to_thinking(content)
                            # Same debounce for thinking
                            _now = time.monotonic()
                            if _now - self._last_scroll_time >= 0.3:
                                chat.scroll_end(animate=False)
                                self._last_scroll_time = _now

                    elif event_type == "tool_start":
                        tool_id = str(event.get("tool_id", "0"))
                        tool_name = event.get("tool", "unknown")
                        arguments = event.get("arguments", {})
                        logger.info(
                            f"Tool Start: {tool_name} args={arguments}")
                        chat.end_streaming()
                        chat.end_thinking()
                        streaming_started = False
                        chat.add_tool_start(tool_id, tool_name, arguments)

                    elif event_type == "tool_output":
                        tool_id = str(event.get("tool_id", "0"))
                        content = event.get("content", "")
                        if content:
                            # Debounce scroll: at most once per 300ms
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

                        logger.info(
                            f"Tool End: success={success} duration={duration}")

                        # Retrieve specific ToolMessage reference by ID
                        if not hasattr(chat, "_active_tools"):
                            chat._active_tools = {}
                        captured_tool_msg = chat._active_tools.pop(
                            tool_id, None)

                        # Schedule UI updates safely on the main thread
                        def update_ui_on_tool_end(
                            _msg=captured_tool_msg,
                            _s=success, _d=duration, _r=result_preview, _o=output_file,
                            _tc=tool_counts,
                            _ti=token_info,
                            _sk=skills_info,
                            _cd=caido_data,
                        ):
                            # 1. Update the specific tool card
                            if _msg:
                                _msg.update_result(_s, _d, _r, _o)
                            chat.scroll_end(animate=False)

                            # 2. Update Status Bar
                            try:
                                status_bar = self.query_one(
                                    "#status-bar", StatusBar)
                                status_update_kwargs = {}

                                if _tc:
                                    status_update_kwargs["exec_used"] = _tc.get(
                                        "exec", 0)
                                    status_update_kwargs["subagents"] = _tc.get(
                                        "subagents", 0)

                                if _ti:
                                    status_update_kwargs["tokens"] = _ti.get(
                                        "cumulative", _ti.get("used", 0))
                                    status_update_kwargs["token_limit"] = _ti.get(
                                        "limit", 65536)

                                if _sk:
                                    status_update_kwargs["skills"] = _sk

                                if _cd:
                                    status_update_kwargs["caido_active"] = _cd.get(
                                        "active", False)
                                    status_update_kwargs["caido_findings"] = _cd.get(
                                        "findings_count", 0)

                                if status_update_kwargs:
                                    status_bar.set_status(
                                        **status_update_kwargs)
                            except Exception:  # nosec B110 - status update is best-effort
                                pass

                            # 3. Reload Workspace (debounced: at most once
                            # every 10s)
                            try:
                                import time as _time
                                now = _time.monotonic()
                                if now - self._last_workspace_reload >= 10.0:
                                    self._last_workspace_reload = now
                                    self.query_one(
                                        "#workspace-panel", WorkspacePanel).reload()
                            except Exception:  # nosec B110 - workspace reload is best-effort
                                pass

                        self.call_later(update_ui_on_tool_end)

                    elif event_type == "error":
                        error_msg = event.get("message", "Unknown error")
                        logger.error(f"Agent Error Event: {error_msg}")

                        def show_error_safely():
                            chat.add_error_message(error_msg)

                        self.call_later(show_error_safely)

                        logger.error(f"Error event received: {error_msg}")

                    elif event_type == "done":
                        logger.debug("Stream done")
                        if streaming_started:
                            chat.end_streaming()
                        break

            # Ensure streaming message is closed if loop finishes
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
            chat.add_error_message(
                "Request timed out. The operation took too long.")
        except Exception as e:
            msg = f"Unexpected error in stream worker: {e}"
            logger.exception(msg)
            chat.add_error_message(f"Error: {str(e)}")
        finally:
            self._processing = False
            # Always finalize any hanging stream/thinking bubbles
            try:
                chat.end_streaming()
                chat.end_thinking()
            except Exception:  # nosec B110 - cleanup is best-effort
                pass
            # Hide recon spinner only when no file-analysis subagents are still active
            if not self._file_agents_running:
                self._hide_recon_spinner()
            logger.debug("Stream worker finished")

    async def _stream_file_analysis(
        self, file_path: str, content: str, task: str
    ) -> None:
        """Stream results from the file-analysis mini-agent into a SubAgentBlock.

        Uses /api/file-analyze which creates a fresh AgentLoop independent of
        the main recon agent, so both can run concurrently.
        """
        chat = self.query_one("#chat-panel", ChatPanel)
        agent_id = str(uuid.uuid4())
        success = True

        # Mount the collapsible block and update status bar
        chat.add_subagent_block(agent_id, task)
        self._file_agents_running += 1
        self._show_recon_spinner()
        try:
            self.query_one("#status-bar", StatusBar).subagents_spawned += 1
        except Exception:  # nosec B110 - best-effort
            pass

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
                            agent_id, tool_id,
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
            chat.subagent_finish(agent_id, success)
            self._file_agents_running = max(0, self._file_agents_running - 1)
            # Hide spinner only when no other agent is active
            if not self._processing and not self._file_agents_running:
                self._hide_recon_spinner()
            try:
                status_bar = self.query_one("#status-bar", StatusBar)
                status_bar.subagents_spawned = max(
                    0, status_bar.subagents_spawned - 1
                )
            except Exception:  # nosec B110 - best-effort
                pass

    async def _handle_slash_command(self, cmd: str) -> None:
        """Handle slash commands."""
        chat = self.query_one("#chat-panel", ChatPanel)

        if cmd in ("/help", "/h"):
            chat.add_assistant_message(
                "## Commands\n\n"
                "| Command | Description |\n"
                "|---------|------------|\n"
                "| `/help` | Show this help |\n"
                "| `/info` | Show AIRecon information |\n"
                "| `/status` | Check service status |\n"
                "| `/tools` | List available tools |\n"
                "| `/skills` | Show AI skills |\n"
                "| `/reset` | Reset conversation |\n"
                "| `/clear` | Clear chat display |\n\n"
            )
        elif cmd == "/status":
            await self._check_services(verbose=True)
        elif cmd == "/skills":
            try:
                resp = await self._http.get("/api/skills")
                if resp.status_code == 200:
                    data = resp.json()
                    skills = data.get("skills", [])

                    # Group by category — count only, no per-skill dump.
                    # Rendering 109+ lines in a Static widget blocks Textual layout.
                    from collections import Counter
                    cat_counts: Counter = Counter(
                        s.get("category", "uncategorized") for s in skills
                    )
                    lines = [f"AI Skills & Capabilities — {len(skills)} skills loaded\n"]
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
            self._processing = False

        elif cmd == "/tools":
            try:
                resp = await self._http.get("/api/tools")
                if resp.status_code == 200:
                    data = resp.json()
                    tools = data.get("tools", [])
                    tools_md = f"## Available Tools ({len(tools)})\n\n"
                    for t in tools:
                        if "function" in t:
                            fn = t["function"]
                            name = fn.get("name", "?")
                            desc = fn.get("description", "")
                        else:
                            name = t.get("name", "?")
                            desc = t.get("description", "")

                        desc = desc.split("\n")[0][:80]
                        tools_md += f"- **{name}** — {desc}\n"
                    chat.add_assistant_message(tools_md)
                else:
                    chat.add_error_message("Failed to fetch tools")
            except Exception as e:
                chat.add_error_message(f"Error: {e}")
            self._processing = False

        elif cmd == "/info":
            info_text = """## ℹ️ AIRecon Information

**Key Bindings:**
- `ESC`: Stop current generation/thinking.
- `Ctrl+C`: Quit the application.
- `Ctrl+L`: Clear chat history.
- `Ctrl+R`: Reset conversation (clears context).
- `PgUp`/`PgDn`: Scroll chat.

**Commands:**
- `/help`: Show this help message.
- `/info`: Show AIRecon information.
- `/status`: Check service status.
- `/tools`: List available tools.
- `/skills`: Show AI skills.
- `/reset`: Reset conversation.
- `/clear`: Clear chat history.

**Tips:**
- You can ask the AI to run scans, search the web, or browse pages.
- Click a file in the workspace panel to load it as context for your next prompt."""
            chat.add_assistant_message(info_text)
            self._processing = False

        elif cmd == "/reset":
            await self.action_reset()
        elif cmd == "/clear":
            self.action_clear()
        else:
            chat.add_error_message(
                f"Unknown command: `{cmd}`. Type `/help` for available commands.")

    def action_clear(self) -> None:
        """Clear chat messages."""
        self.query_one("#chat-panel", ChatPanel).clear_messages()

    async def action_reset(self) -> None:
        """Reset conversation."""
        chat = self.query_one("#chat-panel", ChatPanel)
        workspace = self.query_one("#workspace-panel", WorkspacePanel)

        try:
            await self._http.post("/api/reset")
            chat.clear_messages()
            workspace.reload()
            chat.add_assistant_message(
                "Conversation reset. Ready for a new session.")
            self._clear_active_file_context()  # Clear file context on reset
        except Exception as e:
            chat.add_error_message(f"Reset failed: {e}")

    async def action_cancel_generation(self) -> None:
        """Cancel the current chat generation."""
        # 1. Cancel local worker first
        if self._chat_worker and self._chat_worker.is_running:
            self._chat_worker.cancel()

        self._processing = False

        chat = self.query_one("#chat-panel", ChatPanel)
        chat.add_system_message(
            "🛑 User stopped progress (sending stop signal to agent)...")
        self.notify("Generation cancelled.", severity="warning")

        # Ensure streams are closed in chat widget
        chat.end_streaming()
        chat.end_thinking()

        # 2. Send remote STOP signal to kill running tools (Nuclei, etc.)
        try:
            # Short timeout, fire and forget-ish
            await self._http.post("/api/stop", timeout=2.0)
        except Exception as e:
            logger.error(f"Failed to send stop signal: {e}")

    def action_request_quit(self) -> None:
        """Show confirmation dialog before quitting."""
        def _on_dismiss(confirmed: bool) -> None:
            if confirmed:
                self.run_worker(self.action_quit(), exclusive=True)
        self.push_screen(QuitConfirmScreen(), _on_dismiss)

    async def action_quit(self) -> None:
        """Force quit — cancel tasks, unload model, and close."""
        # 0. Send remote STOP signal to kill running tools
        try:
            await self._http.post("/api/stop", timeout=2.0)
        except Exception:  # nosec B110 - stop signal is best-effort
            pass

        # Cancel any in-progress status polling
        if self._status_task and not self._status_task.done():
            self._status_task.cancel()

        # Try to unload model from Ollama DIRECTLY (release VRAM)
        # Using subprocess curl for robustness against event loop shutdown
        try:
            import json
            import subprocess  # nosec B404

            from airecon.proxy.config import get_config

            cfg = get_config()
            ollama_url = cfg.ollama_url.rstrip("/")
            model = cfg.ollama_model

            # Fire and forget (almost) - short timeout
            cmd = [
                "curl", "-s", "-X", "POST", f"{ollama_url}/api/generate",
                "-d", json.dumps({"model": model, "keep_alive": 0})
            ]

            # Run in thread to not strictly block, but we want to ensure it sends
            # Since we are exiting, blocking for 0.5s is fine
            subprocess.run(  # nosec B603
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=2)

        except Exception:  # nosec B110 - model unload is best-effort on exit
            pass

        # Close http client
        try:
            await self._http.aclose()
        except Exception:  # nosec B110 - cleanup is best-effort
            pass

        self.exit()

    def copy_to_clipboard(self, content: str) -> None:
        """Copy content to system clipboard."""
        try:
            import pyperclip
            pyperclip.copy(content)
        except ImportError:
            self.notify(
                "pyperclip not installed. Clipboard disabled.",
                severity="warning")
        except Exception as e:
            self.notify(f"Clipboard error: {e}", severity="error")

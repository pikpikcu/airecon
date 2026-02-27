"""AIRecon Textual TUI Application."""

from __future__ import annotations

import asyncio
import json
import logging
import os
from pathlib import Path
from typing import Any

import httpx
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, Container
from textual.widgets import Header, Static, Footer, DirectoryTree

from .widgets.chat import ChatPanel, ToolMessageSelected
from .widgets.workspace import WorkspacePanel, WorkspaceTree
from .widgets.file_preview import FilePreviewScreen
from .widgets.input import CommandInput
from .widgets.status import StatusBar
from airecon.proxy.config import get_workspace_root

logger = logging.getLogger("airecon.tui")


class AIReconApp(App):
    """AIRecon Terminal User Interface."""

    TITLE = "AIRecon"
    SUB_TITLE = "AI Security Reconnaissance"
    CSS_PATH = "styles.tcss"
    BINDINGS = [
        Binding("ctrl+c", "quit", "Quit", show=True, priority=True),
        Binding("ctrl+q", "quit", "Quit", show=False, priority=True),
        Binding("ctrl+l", "clear", "Clear Chat", show=True),
        Binding("ctrl+r", "reset", "Reset", show=True),
        Binding("pageup", "scroll_chat_up", "Scroll Up", show=False),
        Binding("pagedown", "scroll_chat_down", "Scroll Down", show=False),
        Binding("escape", "cancel_generation", "Stop AI", show=True, priority=True),
    ]

    def action_scroll_chat_up(self) -> None:
        """Scroll chat up."""
        self.query_one("#chat-panel", ChatPanel).scroll_up()

    def action_scroll_chat_down(self) -> None:
        """Scroll chat down."""
        self.query_one("#chat-panel", ChatPanel).scroll_down()

    def __init__(self, proxy_url: str = "http://127.0.0.1:3000", **kwargs) -> None:
        super().__init__(**kwargs)
        self.proxy_url = proxy_url.rstrip("/")
        self._http = httpx.AsyncClient(base_url=self.proxy_url, timeout=None)
        self._processing = False
        self._chat_worker: asyncio.Task | None = None
        self._current_tool_id: str | None = None
        self._status_task: asyncio.Task | None = None
        self.current_context_path: Path | None = None
        self.active_file_content: str | None = None # Attribute for file content context
        self.active_file_path: Path | None = None # Attribute for file path context
        self._last_workspace_reload: float = 0.0  # debounce: track last refresh time

    def compose(self) -> ComposeResult:
        # Layout: Workspace (Right), Separator (Right), Chat (Fills)
        yield Header()
        
        # 1. Dock Workspace Panel to the Right (Sticks to edge)
        yield WorkspacePanel(get_workspace_root(), id="workspace-panel")
        
        # 2. Dock Separator next to it
        yield Static("", id="separator")
        
        # 3. Main Chat Area fills remaining space
        # We don't need a horizontal container wrapper for docking to work
        with Container(id="chat-area"):
            yield ChatPanel(id="chat-panel")
            yield CommandInput(id="command-input")
            
        yield StatusBar(id="status-bar")

    async def on_mount(self) -> None:
        """Initialize on mount."""
        # Ensure workspace exists (get_workspace_root() already creates it)
        workspace_path = get_workspace_root()
        # Reload tree just in case
        try:
            self.query_one("#workspace-panel", WorkspacePanel).reload()
        except Exception:
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
            "- scan example.com\n"
            "- enumerate subdomains for example.com\n"
            "- run nuclei on https://example.com\n"
        )

        # Focus input
        self.query_one("#command-input", CommandInput).focus()

        # Start background status polling (retries until connected)
        self._status_task = asyncio.create_task(self._poll_services())

    def on_workspace_tree_file_selected(self, event: WorkspaceTree.FileSelected) -> None:
        """Handle file selection to show preview and set as active context."""
        chat = self.query_one(ChatPanel)
        try:
            file_path = event.path
            
            # Update vulnerabilities view if file is within a target
            try:
                # Assume workspace structure: workspace/<target>/...
                # We can try to derive target from path relative to workspace root
                workspace_root = get_workspace_root()
                abs_path = file_path.resolve()
                
                if workspace_root in abs_path.parents:
                    rel = abs_path.relative_to(workspace_root)
                    if len(rel.parts) > 1: # Must be nested under a target folder (target/...)
                        target = rel.parts[0]
                        target_path = workspace_root / target
                        self.query_one("#workspace-panel", WorkspacePanel).update_vulnerabilities_path(target_path)
                    else:
                        # File is in root workspace, clear vulnerabilities view
                         self.query_one("#workspace-panel", WorkspacePanel).clear_vulnerabilities_view()
            except Exception:
                pass

            # Limit context reading to avoid hangs
            try:
                if file_path.stat().st_size > 50_000:
                    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                        content = f.read(50_000) + "\n... [TRUNCATED CONTEXT] ..."
                else:
                    content = file_path.read_text(encoding="utf-8", errors="replace")
            except Exception as e:
                content = f"Error reading file: {e}"

            # Set active file context
            self.active_file_path = file_path
            self.active_file_content = content
            
            chat.add_system_message(f"File context loaded: [bold green]{file_path.name}[/bold green]. Use 'this file' or 'the loaded file' in your next prompt.")
            
            # Preview using optimized screen
            self._open_file_preview(str(file_path))

        except Exception as e:
            chat.add_error_message(f"Error reading file for context: {e}")
            self.active_file_path = None
            self.active_file_content = None

    # NOTE: on_directory_tree_file_selected is defined once below (near L319) to avoid duplicate handler.

    def on_workspace_tree_directory_selected(self, event: WorkspaceTree.DirectorySelected) -> None:
        """Update context and vulnerabilities view."""
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
                     self.query_one("#workspace-panel", WorkspacePanel).clear_vulnerabilities_view()
                     return

                 rel = abs_path.relative_to(workspace_root)
                 if len(rel.parts) >= 1:
                     target = rel.parts[0]
                     target_path = workspace_root / target
                     self.query_one("#workspace-panel", WorkspacePanel).update_vulnerabilities_path(target_path)
        except Exception:
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

                    proxy_reachable = True
                    status_bar.set_status(
                        ollama="online" if ollama_ok else "offline",
                        docker="online" if docker_ok else "offline",
                        model=model,
                        exec_used=exec_used,
                    )

                    if ollama_ok and docker_ok:
                        connected = True
                        chat.add_assistant_message(
                            f"✅ Connected — **{model}** ready with Docker sandbox"
                        )
                        break
            except Exception:
                pass

            await asyncio.sleep(1.0)

        if not connected:
            if proxy_reachable:
                # Proxy is running but Ollama/Docker aren't ready
                data = {}
                try:
                    resp = await self._http.get("/api/status", timeout=3.0)
                    data = resp.json()
                except Exception:
                    pass
                ollama_ok = data.get("ollama", {}).get("connected", False)
                docker_ok = data.get("docker", {}).get("connected", False)
                issues = []
                if not ollama_ok:
                    issues.append("Ollama offline (check `ollama serve`)")
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

        # After initial connection, keep status alive with longer interval to avoid CPU pressure
        while True:
            await asyncio.sleep(5.0)
            try:
                resp = await self._http.get("/api/status", timeout=3.0)
                if resp.status_code == 200:
                    data = resp.json()
                    ollama_ok = data.get("ollama", {}).get("connected", False)
                    docker_ok = data.get("docker", {}).get("connected", False)
                    model = data.get("ollama", {}).get("model", "—")
                    tool_counts = data.get("agent", {}).get("tool_counts", {})
                    exec_used = tool_counts.get("exec", 0)
                    self.query_one("#status-bar", StatusBar).set_status(
                        ollama="online" if ollama_ok else "offline",
                        docker="online" if docker_ok else "offline",
                        model=model,
                        exec_used=exec_used,
                    )
            except Exception:
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

                status_bar.set_status(
                    ollama="online" if ollama_ok else "offline",
                    docker="online" if docker_ok else "offline",
                    model=model,
                    exec_used=exec_used,
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
                    chat.add_error_message(f"Status check failed: HTTP {resp.status_code}")
        except Exception as e:
            status_bar.set_status(ollama="offline", docker="offline")
            if verbose:
                chat.add_error_message(f"Status check error: {e}")

    # ToolMessageSelected imported at top-level

    def on_tool_message_selected(self, message: ToolMessageSelected) -> None:
        """Handle click on a tool message result."""
        logger.debug(f"App received selection: {message.output_file}")
        self._open_file_preview(message.output_file)

    def on_directory_tree_file_selected(self, event: DirectoryTree.FileSelected) -> None:
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
                # Pass path only, let FilePreviewScreen handle lazy/smart loading
                self.push_screen(FilePreviewScreen(str(p)), self.on_preview_result)
            else:
                self.query_one(ChatPanel).add_error_message(f"File not found: {file_path}")
        except Exception as e:
            self.query_one(ChatPanel).add_error_message(f"Failed to open file: {e}")

    def on_preview_result(self, result: Any) -> None:
        """Handle result from FilePreviewScreen dismissal."""
        # result corresponds to what was passed to dismiss()
        # It should be a FilePreviewScreen.Submitted object
        if isinstance(result, FilePreviewScreen.Submitted):
            # Construct context-aware prompt
            # We treat this similar to loading a file from tree
            # Resolve absolute path for clarity
            import os
            abs_path = os.path.abspath(result.file_path)
            cwd = os.getcwd()
            
            chat = self.query_one(ChatPanel)
            # Display relative path to user for brevity
            display_path = os.path.relpath(abs_path, cwd) if abs_path.startswith(cwd) else abs_path
            chat.add_user_message(f"[CONTEXT: {display_path}]\n{result.user_prompt}")
            
            full_prompt = (
                f"[SYSTEM: ACTIVE RESULT CONTEXT]\n"
                f"Current Working Directory (PWD): {cwd}\n"
                f"Target File: {abs_path}\n"
                f"INSTRUCTION: The user is referring to the file at '{abs_path}'. "
                f"You must use this absolute path for any file operations. "
                f"If the user asks to read it, use the 'read_file' tool with this exact path.\n"
                f"USER PROMPT: {result.user_prompt}"
            )
            
            self.run_worker(self._stream_chat_response(full_prompt, inject_context=False))

    def _clear_active_file_context(self) -> None:
        """Clear active file context after use/reset."""
        self.active_file_path = None
        self.active_file_content = None

    async def on_command_input_submitted(self, message: CommandInput.Submitted) -> None:
        """Handle user input submission."""
        user_input = message.value.strip()
        if not user_input:
            return

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
        # This gives instant feedback that the system is working,
        # even if Ollama takes 5-30 seconds to respond.
        chat.start_thinking()

        # Run chat stream in background worker
        self._chat_worker = self.run_worker(self._stream_chat_response(prompt))

    async def _stream_chat_response(self, prompt: str, inject_context: bool = True) -> None:
        """Stream chat response from proxy (runs in worker)."""
        logger.debug(f"Starting chat stream for prompt: {prompt[:50]}...")
        self._processing = True
        chat = self.query_one("#chat-panel", ChatPanel)

        try:
            # Set processing state
            self.query_one("#status-bar", StatusBar).update_status_indicator("Thinking...")
            
            messages_to_send = []

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
                        if isinstance(parsed_content, dict) and "result" in parsed_content:
                            result_data = parsed_content["result"]
                            # Case: Subfinder or similar tool outputting newline-separated domains in stdout
                            if isinstance(result_data, dict) and "stdout" in result_data:
                                stdout_content = result_data["stdout"].strip()
                                domains = [d.strip() for d in stdout_content.split("\n") if d.strip()]
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
                                file_context_message_parts.append(f"User loaded file: {file_path_str} (JSON Result). Content snippet: {str(parsed_content)[:500]}...")
                        else:
                            # Generic JSON
                            file_context_message_parts.append(f"User loaded file: {file_path_str} (JSON). Content snippet: {self.active_file_content[:500]}...")
                            
                    except json.JSONDecodeError:
                        file_context_message_parts.append(f"User loaded file: {file_path_str} (Raw Content). Snippet: {self.active_file_content[:500]}...")
                else:
                    # Text/Other files
                    file_context_message_parts.append(f"User loaded file: {file_path_str}. Content snippet: {self.active_file_content[:500]}...")
                
                # Construct the final prompt with context
                context_str = "\n".join(file_context_message_parts)
                prompt_with_context = f"[SYSTEM: ACTIVE FILE CONTEXT]\n{context_str}\n\n[USER PROMPT]\n{prompt}"
                
                # Clear active file context after injection
                _ctx_file_name = self.active_file_path.name if self.active_file_path else "file"
                self._clear_active_file_context()
                chat.add_system_message(f"[dim]Sent context from {_ctx_file_name}[/dim]")
            else:
                prompt_with_context = prompt

            logger.debug(f"Connecting to proxy at {self.proxy_url}/api/chat")
            # Send to proxy with SSE streaming
            async with self._http.stream(
                "POST",
                "/api/chat",
                json={"message": prompt_with_context, "stream": True}, # Use "message" key with concatenated string
                headers={"Accept": "text/event-stream"},
                timeout=None  # Disable timeout for long-running streams
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
                        logger.warning(f"Failed to parse SSE JSON: {data_str[:100]} - {e}")
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
                            import time as _tmod
                            _now = _tmod.monotonic()
                            if not hasattr(self, '_last_scroll_time'):
                                self._last_scroll_time = 0.0
                            if _now - self._last_scroll_time >= 0.3:
                                chat.scroll_end(animate=False)
                                self._last_scroll_time = _now

                    elif event_type == "thinking":
                        content = event.get("content", "")
                        if content:
                            chat.append_to_thinking(content)
                            # Same debounce for thinking
                            import time as _tmod
                            _now = _tmod.monotonic()
                            if not hasattr(self, '_last_scroll_time'):
                                self._last_scroll_time = 0.0
                            if _now - self._last_scroll_time >= 0.3:
                                chat.scroll_end(animate=False)
                                self._last_scroll_time = _now

                    elif event_type == "tool_start":
                        tool_name = event.get("tool", "unknown")
                        arguments = event.get("arguments", {})
                        logger.info(f"Tool Start: {tool_name} args={arguments}")
                        # Explicitly close any open streaming/thinking bubble first
                        # so the green spinner dot doesn't keep spinning while tool runs
                        chat.end_streaming()
                        chat.end_thinking()
                        streaming_started = False
                        chat.add_tool_start(tool_name, arguments)
                        chat.scroll_end(animate=False)

                    elif event_type == "tool_end":
                        success = event.get("success", False)
                        duration = event.get("duration", 0.0)
                        output_file = event.get("output_file", "")
                        result_preview = event.get("result_preview", "")
                        tool_counts = event.get("tool_counts", {}) or {}
                        
                        logger.info(f"Tool End: success={success} duration={duration}")

                        # CRITICAL: Capture the specific ToolMessage reference NOW,
                        # before the next tool_start overwrites _active_tool_msg.
                        captured_tool_msg = chat._active_tool_msg
                        chat._active_tool_msg = None  # Release immediately

                        # Schedule UI updates safely on the main thread
                        def update_ui_on_tool_end(
                            _msg=captured_tool_msg,
                            _s=success, _d=duration, _r=result_preview, _o=output_file,
                            _tc=tool_counts,
                        ):
                            # 1. Update the specific tool card (not _active_tool_msg)
                            if _msg:
                                _msg.update_result(_s, _d, _r, _o)
                            chat.scroll_end(animate=False)
                            
                            # 2. Update Status Bar
                            if _tc:
                                try:
                                    status_bar = self.query_one("#status-bar", StatusBar)
                                    status_bar.set_status(
                                        exec_used=_tc.get("exec", 0),
                                    )
                                except Exception:
                                    pass
                            
                            # 3. Reload Workspace (debounced: at most once every 10s)
                            try:
                                import time as _time
                                now = _time.monotonic()
                                if now - self._last_workspace_reload >= 10.0:
                                    self._last_workspace_reload = now
                                    self.query_one("#workspace-panel", WorkspacePanel).reload()
                            except Exception:
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
            chat.add_error_message("Request timed out. The operation took too long.")
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
            except Exception:
                pass
            # Clear thinking status bar
            try:
                self.query_one("#status-bar", StatusBar).update_status_indicator("")
            except Exception:
                pass
            logger.debug("Stream worker finished")



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
                    
                    skills_md = "## 🧠 AI Skills & Capabilities\n\n"
                    for s in skills:
                        name = s.get("name", "Unknown")
                        desc = s.get("description", "")
                        active_tools = s.get("active_tools", [])
                        
                        skills_md += f"### {name}\n{desc}\n"
                        if active_tools:
                            tools_str = ", ".join(f"`{t}`" for t in active_tools)
                            skills_md += f"> **Tools:** {tools_str}\n"
                        else:
                            skills_md += "> *No tools loaded for this skill.*\n"
                        skills_md += "\n"
                        
                    chat.add_assistant_message(skills_md)
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
                        # Handle both raw MCP format and OpenAI format
                        if "function" in t:
                            # OpenAI format
                            fn = t["function"]
                            name = fn.get("name", "?")
                            desc = fn.get("description", "")
                        else:
                            # Raw MCP format
                            name = t.get("name", "?")
                            desc = t.get("description", "")
                            
                        # Truncate desc
                        desc = desc.split("\n")[0][:80]
                        tools_md += f"- **{name}** — {desc}\n"
                    chat.add_assistant_message(tools_md)
                else:
                    chat.add_error_message("Failed to fetch tools")
            except Exception as e:
                chat.add_error_message(f"Error: {e}")
            # Clear processing state
            self._processing = False
            try:
                self.query_one("#status-bar", StatusBar).update_status_indicator("")
            except Exception:
                pass

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
            chat.add_error_message(f"Unknown command: `{cmd}`. Type `/help` for available commands.")

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
            chat.add_assistant_message("Conversation reset. Ready for a new session.")
            self._clear_active_file_context() # Clear file context on reset
        except Exception as e:
            chat.add_error_message(f"Reset failed: {e}")

    async def action_cancel_generation(self) -> None:
        """Cancel the current chat generation."""
        # 1. Cancel local worker first
        if self._chat_worker and self._chat_worker.is_running:
            self._chat_worker.cancel()
            
        self._processing = False
        
        chat = self.query_one("#chat-panel", ChatPanel)
        status_bar = self.query_one("#status-bar", StatusBar)
        
        chat.add_system_message("🛑 User stopped progress (sending stop signal to agent)...")
        status_bar.update_status_indicator("")
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


    async def action_quit(self) -> None:
        """Force quit — cancel tasks, unload model, and close."""
        # 0. Send remote STOP signal to kill running tools
        try:
            await self._http.post("/api/stop", timeout=2.0)
        except Exception:
            pass

        # Cancel any in-progress status polling
        if self._status_task and not self._status_task.done():
            self._status_task.cancel()

        # Try to unload model from Ollama DIRECTLY (release VRAM)
        # Using subprocess curl for robustness against event loop shutdown
        try:
            from airecon.proxy.config import get_config
            import subprocess
            import json
            
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
            subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2)
            
        except Exception:
            pass

        # Close http client
        try:
            await self._http.aclose()
        except Exception:
            pass
        
        self.exit()

    def copy_to_clipboard(self, content: str) -> None:
        """Copy content to system clipboard."""
        try:
            import pyperclip
            pyperclip.copy(content)
        except ImportError:
            self.notify("pyperclip not installed. Clipboard disabled.", severity="warning")
        except Exception as e:
            self.notify(f"Clipboard error: {e}", severity="error")

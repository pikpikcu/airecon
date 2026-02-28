"""Chat widget: displays conversation with clean CLI-style rendering."""

from __future__ import annotations

from textual.widgets import Static, LoadingIndicator, RichLog
from textual.containers import VerticalScroll, Vertical
from textual.reactive import reactive
from textual.message import Message
from rich.text import Text
import re


# ── ANSI Stripper ──
_ANSI_RE = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')


def _strip_ansi(text: str) -> str:
    return _ANSI_RE.sub('', text)


# ═══════════════════════════════════════════════════════════════
#  ChatMessage — A single chat message (user, assistant, error…)
# ═══════════════════════════════════════════════════════════════

class ChatMessage(Static):
    """A single chat message rendered as clean text (no Markdown widget)."""

    DEFAULT_CSS = ""  # Defer to styles.tcss

    BINDINGS = [("c", "copy", "Copy Message")]
    can_focus = True

    def __init__(
        self,
        content: str,
        role: str = "assistant",
        **kwargs,
    ) -> None:
        super().__init__(**kwargs)
        self.role = role
        self.message_content = content
        self.add_class(f"{role}-message")

    def compose(self):
        # Role label with icon
        role_config = {
            "user":      ("❯", "role-label-user"),
            "assistant": ("◆", "role-label-assistant"),
            "tool":      ("⚙", "role-label-tool"),
            "thinking":  ("◇", "role-label-thinking"),
            "error":     ("✖", "role-label-error"),
            "system":    ("─", "role-label-system"),
        }
        icon, css_class = role_config.get(self.role, ("•", "role-label"))
        
        role_names = {
            "user": "You",
            "assistant": "AIRecon",
            "tool": "Tool",
            "thinking": "Thinking",
            "error": "Error",
            "system": "System",
        }
        name = role_names.get(self.role, self.role.title())
        yield Static(f"{icon} {name}", classes=f"role-label {css_class}")
        
        # Content as clean Static text (NOT Markdown)
        yield Static(self.message_content, classes="msg-body")

    def action_copy(self) -> None:
        """Copy message content to clipboard."""
        self.app.copy_to_clipboard(self.message_content)
        self.notify("Copied!", severity="information")


# ═══════════════════════════════════════════════════════════════
#  ToolMessage — Tool execution card with status
# ═══════════════════════════════════════════════════════════════

class ToolMessageSelected(Message):
    """Message sent when the tool message is clicked."""
    def __init__(self, output_file: str, tool_name: str) -> None:
        self.output_file = output_file
        self.tool_name = tool_name
        super().__init__()


class ToolMessage(Vertical):
    """A compact tool execution card."""

    DEFAULT_CSS = ""  # Defer to styles.tcss

    BINDINGS = [("c", "copy", "Copy Output")]

    def __init__(
        self,
        tool_name: str,
        args: dict | str,
        **kwargs,
    ) -> None:
        super().__init__(**kwargs)
        self.tool_name = tool_name
        self.args = args
        self.output: str | None = None
        self.status = "running"
        self.duration = 0.0
        self.output_file = ""
        self.add_class("running")

    def compose(self):
        # Header line: ⚙ TOOL_NAME  {args_preview}
        header = Text()
        header.append("⚙ ", style="bold #58a6ff")
        header.append(self.tool_name, style="bold #c9d1d9")
        header.append("  ", style="")

        # Sanitize args for display
        try:
            if isinstance(self.args, str):
                args_str = self.args
            elif isinstance(self.args, dict):
                # Show command if it's an execute tool, otherwise key=value pairs
                if "command" in self.args:
                    args_str = self.args["command"]
                else:
                    args_str = " ".join(f"{k}={v}" for k, v in self.args.items())
            else:
                args_str = f"[{type(self.args).__name__}]"
        except Exception:
            args_str = "[args]"

        if len(args_str) > 120:
            args_str = args_str[:117] + "..."
        header.append(args_str, style="#484f58")
        yield Static(header, classes="tool-header")

        # Spinner while running
        if self.status == "running":
            yield LoadingIndicator()
            self._live_output = RichLog(markup=False, highlight=False, auto_scroll=True, classes="tool-live-output")
            yield self._live_output

    def append_output(self, text: str) -> None:
        if not hasattr(self, "_live_output_buffer"):
            self._live_output_buffer = ""
        self._live_output_buffer += text
        
        if hasattr(self, "_live_output"):
            while "\n" in self._live_output_buffer:
                line, self._live_output_buffer = self._live_output_buffer.split("\n", 1)
                clean_line = _strip_ansi(line).rstrip("\r")
                self._live_output.write(clean_line)

    def update_result(self, success: bool, duration: float, output: str, output_file: str = ""):
        self.status = "done" if success else "error"
        self.duration = duration
        self.output = output
        self.output_file = output_file

        self.remove_class("running")
        self.add_class(self.status)

        if self.status == "done":
            # ── SUCCESS: Collapse to a clean one-liner ──
            summary = Text()
            summary.append("✓ ", style="bold #00d4aa")
            summary.append(self.tool_name, style="bold #8b949e")
            summary.append(f"  {self.duration:.1f}s", style="#484f58")
            if self.output_file:
                display_path = self.output_file
                if len(display_path) > 45:
                    display_path = "…" + display_path[-42:]
                summary.append(f"  → {display_path}", style="underline #3b82f6")
            self._summary_text = summary
            self.call_after_refresh(self._collapse_to_summary)
        else:
            # ── ERROR: Keep expanded so user can see the error ──
            self.call_after_refresh(self._show_error_details)

    def _collapse_to_summary(self) -> None:
        """Success: remove all children and show one-liner."""
        try:
            for child in list(self.children):
                child.remove()
        except Exception:
            pass
        self.mount(Static(self._summary_text, classes="tool-summary"))

    def _show_error_details(self) -> None:
        """Error: remove spinner but keep header, add error output."""
        # Remove only the spinner, keep the header
        try:
            for child in list(self.children):
                if isinstance(child, LoadingIndicator):
                    child.remove()
        except Exception:
            pass

        # Show error output
        if self.output:
            clean = _strip_ansi(self.output)
            lines = clean.strip().splitlines()
            if len(lines) > 10:
                preview = "\n".join(lines[:10])
                preview += f"\n  ⋮ {len(lines) - 10} more lines"
            else:
                preview = "\n".join(lines)
            self.mount(Static(preview, classes="tool-output"))

        # Error footer
        footer = Text()
        footer.append("✗ ", style="bold #ef4444")
        footer.append(f"{self.duration:.1f}s", style="#ef4444")
        if self.output_file:
            display_path = self.output_file
            if len(display_path) > 45:
                display_path = "…" + display_path[-42:]
            footer.append(f"  → {display_path}", style="underline #3b82f6")
        self.mount(Static(footer, classes="tool-footer"))

    can_focus = True

    def action_copy(self) -> None:
        content = self.output if self.output else str(self.args)
        self.app.copy_to_clipboard(content)
        self.notify("Copied!", severity="information")

    def on_click(self) -> None:
        if self.output_file:
            self.post_message(ToolMessageSelected(self.output_file, self.tool_name))
        else:
            self.app.notify("No output file.", severity="warning")


# ═══════════════════════════════════════════════════════════════
#  StreamingMessage — Live streaming text (assistant only)
# ═══════════════════════════════════════════════════════════════

class StreamingMessage(Static):
    """Message that updates incrementally during streaming."""

    DEFAULT_CSS = ""  # Defer to styles.tcss

    content_text = reactive("", layout=True)

    def __init__(self, role: str = "assistant", **kwargs) -> None:
        super().__init__(**kwargs)
        self.role = role
        self._text_widget: Static | None = None
        self._initial_label_yielded = False
        self._last_flush_len = 0

    def compose(self):
        if not self._initial_label_yielded:
            yield Static("◆ AIRecon", classes="role-label role-label-assistant")
            self._initial_label_yielded = True
        self._text_widget = Static("", classes="streaming-content")
        yield self._text_widget
        yield Static("●", classes="streaming-indicator")

    def append_text(self, text: str) -> None:
        """Append text (batched: flush every 50 chars for performance)."""
        self.content_text += text
        if self._text_widget and (len(self.content_text) - self._last_flush_len >= 50):
            self._text_widget.update(self.content_text)
            self._last_flush_len = len(self.content_text)

    def finalize(self) -> None:
        """Remove streaming indicator and flush remaining text."""
        if self._text_widget and len(self.content_text) > self._last_flush_len:
            self._text_widget.update(self.content_text)
        try:
            self.query_one(".streaming-indicator", Static).remove()
        except Exception:
            pass


# ═══════════════════════════════════════════════════════════════
#  ThinkingSpinner — Animated spinner (hides thinking content)
# ═══════════════════════════════════════════════════════════════

from textual.containers import Horizontal

class ThinkingSpinner(Horizontal):
    """Compact spinner shown while the model is thinking.
    Replaces itself with nothing when thinking ends."""

    DEFAULT_CSS = ""  # Defer to styles.tcss

    def compose(self):
        yield LoadingIndicator(id="thinking-spinner")
        yield Static("  Thinking…", classes="thinking-label")


# ═══════════════════════════════════════════════════════════════
#  ChatPanel — Scrollable container for all messages
# ═══════════════════════════════════════════════════════════════

class ChatPanel(VerticalScroll):
    """Scrollable chat panel containing messages."""

    DEFAULT_CSS = ""  # Defer to styles.tcss

    can_focus = True

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self._streaming_msg: StreamingMessage | None = None
        self._thinking_msg: ThinkingSpinner | None = None
        self._active_tool_msg: ToolMessage | None = None
        self._pending: list = []  # widgets buffered before on_mount

    def on_mount(self) -> None:
        """Flush any widgets that were queued before the panel was attached."""
        if self._pending:
            for widget in self._pending:
                self.mount(widget)
            self._pending.clear()
            self.scroll_end(animate=False)

    def _safe_mount(self, widget) -> None:
        """Mount a widget, or queue it if the panel is not yet attached."""
        if self.is_attached:
            self.mount(widget)
        else:
            self._pending.append(widget)

    def add_user_message(self, content: str) -> None:
        self.end_streaming()
        self.end_thinking()
        self._safe_mount(ChatMessage(content, role="user"))
        self.scroll_end(animate=False)

    def add_assistant_message(self, content: str) -> None:
        self.end_streaming()
        self.end_thinking()
        self._safe_mount(ChatMessage(content, role="assistant"))
        self.scroll_end(animate=False)

    def add_tool_message(self, tool_name: str, content: str) -> None:
        self.end_streaming()
        self.end_thinking()
        self._safe_mount(ChatMessage(f"{tool_name}: {content}", role="tool"))
        self.scroll_end(animate=False)

    def add_tool_start(self, tool_id: str, tool_name: str, args: dict | str) -> None:
        self.end_streaming()
        self.end_thinking()
        msg = ToolMessage(tool_name, args)
        self._safe_mount(msg)
        if not hasattr(self, "_active_tools"):
            self._active_tools = {}
        self._active_tools[tool_id] = msg
        self.scroll_end(animate=False)

    def update_tool_end(self, tool_id: str, success: bool, duration: float, output: str, output_file: str = "") -> None:
        if not hasattr(self, "_active_tools"):
            self._active_tools = {}
        msg = self._active_tools.pop(tool_id, None)
        if msg:
            msg.update_result(success, duration, output, output_file)
            self.scroll_end(animate=False)

    def append_tool_output(self, tool_id: str, text: str) -> None:
        if hasattr(self, "_active_tools"):
            msg = self._active_tools.get(tool_id)
            if msg:
                msg.append_output(text)
                self.scroll_end(animate=False)

    def add_thinking_message(self, content: str) -> None:
        self.end_streaming()
        self.end_thinking()
        self._safe_mount(ChatMessage(content, role="thinking"))
        self.scroll_end(animate=False)

    def add_error_message(self, content: str) -> None:
        self.end_streaming()
        self.end_thinking()
        self._safe_mount(ChatMessage(content, role="error"))
        self.scroll_end(animate=False)

    def add_system_message(self, content: str) -> None:
        self.end_streaming()
        self.end_thinking()
        self._safe_mount(ChatMessage(content, role="system"))
        self.scroll_end(animate=False)

    def start_streaming(self) -> StreamingMessage:
        self.end_thinking()
        if not self._streaming_msg:
            self._streaming_msg = StreamingMessage(role="assistant")
            self._safe_mount(self._streaming_msg)
            self.scroll_end(animate=False)
        return self._streaming_msg

    def append_to_stream(self, text: str) -> None:
        if not self._streaming_msg:
            self.start_streaming()
        if self._streaming_msg:
            self._streaming_msg.append_text(text)
            self.scroll_end(animate=False)

    def end_streaming(self) -> None:
        if self._streaming_msg:
            self._streaming_msg.finalize()
            self._streaming_msg = None

    def start_thinking(self) -> None:
        """Show a spinner while the model thinks."""
        self.end_streaming()
        if not self._thinking_msg:
            self._thinking_msg = ThinkingSpinner()
            self._safe_mount(self._thinking_msg)
            self.scroll_end(animate=False)

    def append_to_thinking(self, text: str) -> None:
        """Silently absorb thinking text (hidden from user)."""
        # Just keep the spinner alive, don't display text
        if not self._thinking_msg:
            self.start_thinking()

    def end_thinking(self) -> None:
        """Remove the thinking spinner entirely."""
        if self._thinking_msg:
            self._thinking_msg.remove()
            self._thinking_msg = None

    def clear_messages(self) -> None:
        self.query("ChatMessage, StreamingMessage, ToolMessage, ThinkingSpinner").remove()
        self._active_tool_msg = None
        self._streaming_msg = None
        self._thinking_msg = None

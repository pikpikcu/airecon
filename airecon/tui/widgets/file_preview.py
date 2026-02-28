"""File preview modal: displays file content with follow-up prompt."""

from pathlib import Path
from textual.app import ComposeResult
from textual.containers import Vertical, VerticalScroll, Horizontal
from textual.screen import ModalScreen
from textual.widgets import Button, Static, Input
from textual.message import Message
from rich.text import Text
import re

# Strip ANSI VT100 escape sequences
_ANSI_ESCAPE_RE = re.compile(r'\x1b(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')


class FilePreviewScreen(ModalScreen):
    """Modal to show file content and accept follow-up prompts with [CONTEXT]."""

    DEFAULT_CSS = ""  # Defer to styles.tcss

    class Submitted(Message):
        """Event sent when user submits a prompt contextually."""
        def __init__(self, file_path: str, user_prompt: str) -> None:
            self.file_path = file_path
            self.user_prompt = user_prompt
            super().__init__()

    def __init__(self, path: str, content: str = None) -> None:
        self.file_path = path
        self.content = content
        super().__init__()

    BINDINGS = [
        ("escape", "dismiss", "Close"),
        ("c", "copy", "Copy Content"),
    ]

    def compose(self) -> ComposeResult:
        with Vertical(id="preview-dialog"):
            # Header with file path — wrapped in Text() to prevent markup parsing
            display_path = self.file_path
            if len(display_path) > 60:
                display_path = "…" + display_path[-57:]
            yield Static(Text(f"  {display_path}"), id="preview-header")

            # Content area: use Text() so square brackets in tool output
            # (HTTP headers, nmap output, etc.) are never parsed as Rich markup
            with VerticalScroll(id="preview-area"):
                yield Static(
                    Text(self.content or "Loading…"),
                    id="preview-content",
                )

            # Footer: prompt input + action buttons
            with Vertical(id="preview-footer"):
                yield Input(
                    placeholder="Ask about this file… (Enter to send with [CONTEXT])",
                    id="prompt-input",
                )
                with Horizontal(id="action-bar"):
                    yield Button("Close [Esc]", id="close-preview", classes="btn-close")
                    yield Button("Copy", id="copy-content", classes="btn-copy")
                    yield Button("Run with Context", id="run-context", classes="btn-run")

    def on_mount(self) -> None:
        """Load content if not provided."""
        if self.content is None:
            self._load_file_content()

    def _load_file_content(self) -> None:
        try:
            p = Path(self.file_path)
            if not p.exists():
                self._set_content(f"✗ File not found: {self.file_path}")
                return

            size = p.stat().st_size
            MAX_SIZE = 1 * 1024 * 1024  # 1MB limit

            if size > MAX_SIZE:
                with open(p, 'r', errors='replace') as f:
                    head = f.read(5000)
                    f.seek(max(0, size - 500000))
                    tail = f.read()
                msg = (
                    f"\n\n  ⋮ LARGE FILE TRUNCATED ({size / 1024 / 1024:.2f} MB)\n"
                    f"  ⋮ Showing first 5KB and last 500KB\n\n"
                )
                content = _ANSI_ESCAPE_RE.sub('', head) + msg + _ANSI_ESCAPE_RE.sub('', tail)
            else:
                raw = p.read_text(errors='replace')
                content = _ANSI_ESCAPE_RE.sub('', raw)

            self.content = content
            self._set_content(content)

        except Exception as e:
            self._set_content(f"✗ Error loading file: {e}")

    def _set_content(self, text: str) -> None:
        """Update the preview content Static widget as plain text (no markup parsing)."""
        try:
            self.query_one("#preview-content", Static).update(Text(text))
        except Exception:
            pass

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "close-preview":
            self.dismiss()
        elif event.button.id == "copy-content":
            self.action_copy()
        elif event.button.id == "run-context":
            self._submit()

    def action_copy(self) -> None:
        """Copy content to clipboard."""
        val = self.content or ""
        self.app.copy_to_clipboard(val)
        self.notify("Copied!", severity="information")

    def on_input_submitted(self, event: Input.Submitted) -> None:
        """Handle Enter key in the prompt input."""
        self._submit()

    def _submit(self) -> None:
        """Submit the prompt with file context."""
        inp = self.query_one("#prompt-input", Input)
        val = inp.value.strip()
        if val:
            self.dismiss(self.Submitted(self.file_path, val))
        else:
            self.notify("Enter an instruction first.", severity="warning")

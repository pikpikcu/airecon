"""Input widget: multi-line input with command history, @/path autocomplete, and /slash command autocomplete."""

from __future__ import annotations

import logging

from textual.app import ComposeResult
from textual.binding import Binding
from textual.message import Message
from textual.widget import Widget
from textual.widgets import Label, ListItem, ListView, TextArea

logger = logging.getLogger("airecon.tui.input")

# Master list of slash commands — keep in sync with _handle_slash_command() in app.py
_SLASH_COMMANDS: list[tuple[str, str]] = [
    ("/help",   "Show help and available commands"),
    ("/info",   "Show AIRecon information and key bindings"),
    ("/status", "Check Ollama / Docker service status"),
    ("/tools",  "List all available agent tools"),
    ("/skills", "Browse AI skill knowledge base"),
    ("/reset",  "Reset conversation context"),
    ("/clear",  "Clear the chat display"),
]


class SlashCompleter(Widget):
    """Slash command completion panel that appears above CommandInput.

    Lifecycle:
      show_for(fragment) → filter commands matching fragment, display widget
      hide()             → clear + hide widget
      get_first_command()→ used by Tab completion in the app

    Fires SlashCompleter.Completed(command) when user clicks/selects an entry.
    """

    DEFAULT_CSS = ""  # Defined in styles.tcss

    class Completed(Message):
        """Emitted when the user selects a completion entry."""

        def __init__(self, command: str) -> None:
            self.command = command
            super().__init__()

    def compose(self) -> ComposeResult:
        yield ListView(id="slash-list")

    def on_mount(self) -> None:
        self.display = False

    def show_for(self, fragment: str) -> None:
        """Update completions for the slash fragment (including leading '/')."""
        matches = [(cmd, desc) for cmd, desc in _SLASH_COMMANDS if cmd.startswith(fragment)]
        lv = self.query_one("#slash-list", ListView)
        lv.clear()
        if not matches:
            self.display = False
            return
        for cmd, desc in matches:
            lv.append(ListItem(Label(f" {cmd}  {desc}"), name=cmd))
        self.display = True
        lv.index = 0

    def hide(self) -> None:
        """Hide the completer and clear its list."""
        self.display = False
        try:
            self.query_one("#slash-list", ListView).clear()
        except Exception:  # nosec B110
            pass

    def get_first_command(self) -> str | None:
        """Return the command of the first (or highlighted) item — for Tab completion."""
        try:
            lv = self.query_one("#slash-list", ListView)
            items = list(lv.query(ListItem))
            if not items:
                return None
            idx = lv.index if lv.index is not None else 0
            if 0 <= idx < len(items):
                return items[idx].name
            return items[0].name
        except Exception:  # nosec B110
            return None

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        """User pressed Enter or clicked on a list item."""
        if event.item.name:
            self.post_message(self.Completed(event.item.name))
        event.stop()


class CommandInput(TextArea):
    """Enhanced input with command history, @/path autocomplete, and multi-line support."""

    DEFAULT_CSS = ""  # Defer to styles.tcss

    BINDINGS = [
        Binding("enter", "submit", "Submit Command", priority=True),
        Binding("up", "history_up", "History Up", show=False),
        Binding("down", "history_down", "History Down", show=False),
    ]

    class Submitted(Message):
        """Fired when user submits a command."""

        def __init__(self, value: str) -> None:
            self.value = value
            super().__init__()

    class AtPathChanged(Message):
        """Fired when the @/path fragment at the cursor changes.

        fragment=None means no active @ pattern at cursor.
        """

        def __init__(self, fragment: str | None) -> None:
            self.fragment = fragment
            super().__init__()

    class TabPressed(Message):
        """Fired when Tab is pressed — used to trigger path autocomplete."""

    class EscapeCompletion(Message):
        """Fired when Escape is pressed — used to dismiss autocomplete."""

    class SlashChanged(Message):
        """Fired when the /command fragment at the cursor changes.

        fragment=None means no active slash pattern at cursor.
        """

        def __init__(self, fragment: str | None) -> None:
            self.fragment = fragment
            super().__init__()

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self.show_line_numbers = False
        self._history: list[str] = []
        self._history_index: int = -1
        self._last_at_fragment: str | None = None
        self._last_slash_fragment: str | None = None

    # ── Key Handling ─────────────────────────────────────────────────────────

    def on_key(self, event) -> None:
        """Handle special keys."""
        if event.key == "tab":
            self.post_message(self.TabPressed())
            event.prevent_default()
            event.stop()
            return

        if event.key == "escape":
            # Let the app know so it can dismiss the completer.
            # Don't stop() — escape also cancels AI generation.
            self.post_message(self.EscapeCompletion())
            return

        if event.key in ("shift+enter", "ctrl+enter"):
            self.insert("\n")
            event.prevent_default()
            event.stop()

    def on_text_area_changed(self, event: TextArea.Changed) -> None:
        """Detect @/path and /command pattern changes and notify the app."""
        fragment = self._get_at_fragment()
        if fragment != self._last_at_fragment:
            self._last_at_fragment = fragment
            self.post_message(self.AtPathChanged(fragment))

        slash_fragment = self._get_slash_fragment()
        if slash_fragment != self._last_slash_fragment:
            self._last_slash_fragment = slash_fragment
            self.post_message(self.SlashChanged(slash_fragment))

    # ── Actions ──────────────────────────────────────────────────────────────

    def action_submit(self) -> None:
        """Submit the current input."""
        value = self.text.strip()
        if value:
            self._history.insert(0, value)
            self._history_index = -1
            self._last_at_fragment = None
            self._last_slash_fragment = None
            self.post_message(self.Submitted(value))
            self.text = ""
            self.cursor_location = (0, 0)

    def action_history_up(self) -> None:
        """Navigate history up."""
        if self._history:
            if self._history_index < len(self._history) - 1:
                self._history_index += 1
            self.text = self._history[self._history_index]
            self._move_cursor_to_end()

    def action_history_down(self) -> None:
        """Navigate history down."""
        if self._history_index > 0:
            self._history_index -= 1
            self.text = self._history[self._history_index]
        elif self._history_index == 0:
            self._history_index = -1
            self.text = ""
        self._move_cursor_to_end()

    # ── Autocomplete API ─────────────────────────────────────────────────────

    def do_slash_completion(self, command: str) -> None:
        """Replace the current /fragment with the full slash command.

        Args:
            command: full slash command string, e.g. '/help'.
        """
        text = self.text
        row, col = self.cursor_location
        lines = text.split("\n")
        cursor_offset = sum(len(lines[i]) + 1 for i in range(row)) + col
        text_to_cursor = text[:cursor_offset]

        slash_pos = text_to_cursor.rfind("/")
        if slash_pos == -1:
            return

        new_text = text[:slash_pos] + command + text[cursor_offset:]
        self.text = new_text

        # Move cursor to end of inserted command
        new_offset = slash_pos + len(command)
        lines_new = new_text.split("\n")
        char_count = 0
        for r, line in enumerate(lines_new):
            end = char_count + len(line)
            if end >= new_offset:
                self.cursor_location = (r, new_offset - char_count)
                break
            char_count = end + 1

        # Mark as already-seen so on_text_area_changed doesn't re-fire SlashChanged
        # (setting None would cause it to re-show the completer immediately)
        self._last_slash_fragment = command

    def do_completion(self, path: str) -> None:
        """Replace the current @/fragment in the input with @path.

        Args:
            path: absolute path string (with trailing '/' if directory).
        """
        text = self.text
        row, col = self.cursor_location
        lines = text.split("\n")
        cursor_offset = sum(len(lines[i]) + 1 for i in range(row)) + col
        text_to_cursor = text[:cursor_offset]

        at_pos = text_to_cursor.rfind("@")
        if at_pos == -1:
            return

        replacement = "@" + path
        new_text = text[:at_pos] + replacement + text[cursor_offset:]
        self.text = new_text

        # Move cursor to end of inserted path
        new_offset = at_pos + len(replacement)
        lines_new = new_text.split("\n")
        char_count = 0
        for r, line in enumerate(lines_new):
            end = char_count + len(line)
            if end >= new_offset:
                self.cursor_location = (r, new_offset - char_count)
                break
            char_count = end + 1

        # Keep tracking the new fragment (if dir, completer stays open)
        self._last_at_fragment = path if path.endswith("/") else None

    # ── Helpers ──────────────────────────────────────────────────────────────

    def _get_at_fragment(self) -> str | None:
        """Extract the @/... path fragment immediately before the cursor.

        Returns None if the cursor is not positioned after an active @ pattern.
        """
        text = self.text
        row, col = self.cursor_location
        lines = text.split("\n")
        cursor_offset = sum(len(lines[i]) + 1 for i in range(row)) + col
        text_to_cursor = text[:cursor_offset]

        at_pos = text_to_cursor.rfind("@")
        if at_pos == -1:
            return None

        fragment = text_to_cursor[at_pos + 1:]

        # Whitespace inside fragment means the @ token was already "closed"
        if any(c in fragment for c in (" ", "\t", "\n")):
            return None

        # Fragment must start with / (or be empty — just typed @)
        if fragment and not fragment.startswith("/"):
            return None

        return fragment

    def _get_slash_fragment(self) -> str | None:
        """Extract the /command fragment immediately before the cursor.

        Returns None if the cursor is not positioned right after a leading
        slash (i.e. slash must be the first non-whitespace character on the
        line and there must be no spaces in the fragment yet).
        """
        text = self.text
        row, col = self.cursor_location
        lines = text.split("\n")
        cursor_offset = sum(len(lines[i]) + 1 for i in range(row)) + col
        text_to_cursor = text[:cursor_offset]

        # Only activate when slash is at position 0 (or after only whitespace)
        stripped = text_to_cursor.lstrip()
        if not stripped.startswith("/"):
            return None

        # Fragment must have no spaces (slash command is a single token)
        fragment = stripped
        if any(c in fragment for c in (" ", "\t", "\n")):
            return None

        return fragment

    def _move_cursor_to_end(self) -> None:
        """Move cursor to the end of the current text."""
        lines = self.text.splitlines() or [""]
        self.cursor_location = (len(lines) - 1, len(lines[-1]))

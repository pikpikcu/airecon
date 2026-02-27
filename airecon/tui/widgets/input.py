"""Input widget: multi-line input with command history."""

from __future__ import annotations

from textual.widgets import TextArea
from textual.message import Message
from textual.binding import Binding

class CommandInput(TextArea):
    """Enhanced input with command history and multi-line support."""

    DEFAULT_CSS = "" # Defer to styles.tcss

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

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self.show_line_numbers = False
        self._history: list[str] = []
        self._history_index: int = -1

    def on_key(self, event) -> None:
        """Handle specific keys for newline insertion."""
        if event.key in ("shift+enter", "ctrl+enter"):
            # Insert newline at cursor
            self.insert("\n")
            event.prevent_default()
            event.stop()

    def action_submit(self) -> None:
        """Submit the current input."""
        # Use text property
        value = self.text.strip()
        if value:
            self._history.insert(0, value)
            self._history_index = -1
            self.post_message(self.Submitted(value))
            self.text = ""
            # Reset cursor
            self.cursor_location = (0, 0)

    def action_history_up(self) -> None:
        """Navigate history up."""
        if self._history:
            if self._history_index < len(self._history) - 1:
                self._history_index += 1
            self.text = self._history[self._history_index]
            self.cursor_location = (len(self.text.splitlines()) - 1, len(self.text.splitlines()[-1]))

    def action_history_down(self) -> None:
        """Navigate history down."""
        if self._history_index > 0:
            self._history_index -= 1
            self.text = self._history[self._history_index]
        elif self._history_index == 0:
            self._history_index = -1
            self.text = ""
        self.cursor_location = (len(self.text.splitlines()) - 1, len(self.text.splitlines()[-1]))

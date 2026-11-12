from __future__ import annotations

import logging
from pathlib import Path

from textual.app import ComposeResult
from textual.message import Message
from textual.widget import Widget
from textual.widgets import Label, ListItem, ListView

logger = logging.getLogger("airecon.tui.path_completer")

_MAX_COMPLETIONS = 15

class PathCompleter(Widget):
    DEFAULT_CSS = ""

    class Completed(Message):
        def __init__(self, path: str) -> None:
            self.path = path
            super().__init__()

    def compose(self) -> ComposeResult:
        yield ListView(id="path-list")

    def on_mount(self) -> None:
        self.display = False

    def show_for(self, fragment: str) -> None:
        entries = _list_entries(fragment)
        lv = self.query_one("#path-list", ListView)
        lv.clear()

        if not entries:
            self.display = False
            return

        for abs_path, is_dir in entries:
            name = Path(abs_path).name
            suffix = "/" if is_dir else ""
            icon = "▸" if is_dir else " "

            full = abs_path + ("/" if is_dir else "")
            lv.append(ListItem(Label(f" {icon} {name}{suffix}"), name=full))

        self.display = True
        lv.index = 0

    def hide(self) -> None:
        self.display = False
        try:
            self.query_one("#path-list", ListView).clear()
        except Exception as _e:
            logger.debug("PathCompleter.hide: could not clear list: %s", _e)

    def get_first_path(self) -> str | None:
        try:
            lv = self.query_one("#path-list", ListView)
            items = list(lv.query(ListItem))
            if not items:
                return None

            idx = lv.index if lv.index is not None else 0
            if 0 <= idx < len(items):
                return items[idx].name
            return items[0].name
        except Exception as _e:
            logger.debug("PathCompleter.get_first_path: %s", _e)
            return None

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        if event.item.name:
            self.post_message(self.Completed(event.item.name))
        event.stop()

def _list_entries(fragment: str) -> list[tuple[str, bool]]:
    if not fragment:
        base = Path.home()
        prefix = ""
    elif fragment == "/":
        base = Path("/")
        prefix = ""
    else:
        p = Path(fragment)
        if fragment.endswith("/"):
            base = p
            prefix = ""
        else:
            base = p.parent
            prefix = p.name

    try:
        all_entries = sorted(
            base.iterdir(),
            key=lambda e: (not e.is_dir(), e.name.lower()),
        )
    except (PermissionError, OSError, NotADirectoryError):
        return []

    show_hidden = prefix.startswith(".")
    result: list[tuple[str, bool]] = []
    for entry in all_entries:
        name = entry.name
        if prefix and not name.startswith(prefix):
            continue
        if not show_hidden and name.startswith("."):
            continue
        result.append((str(entry), entry.is_dir()))
        if len(result) >= _MAX_COMPLETIONS:
            break

    return result

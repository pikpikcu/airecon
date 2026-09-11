from types import SimpleNamespace

import pytest
from textual.app import App, ComposeResult

from pathlib import Path

from airecon.tui.buddy import AVAILABLE_SPECIES
from airecon.tui.widgets.chat import ChatPanel, ThinkingSpinner
from airecon.tui.widgets.status import StatusBar


class ChatWidgetTestApp(App):
    def compose(self) -> ComposeResult:
        yield ChatPanel(id="chat")


class StatusWidgetTestApp(App):
    def compose(self) -> ComposeResult:
        yield StatusBar(id="status")


@pytest.mark.asyncio
async def test_chat_panel_add_messages():
    async with ChatWidgetTestApp().run_test() as pilot:
        chat = pilot.app.query_one("#chat", ChatPanel)

        chat.add_user_message("Test user message")
        chat.add_assistant_message("Test AI message")
        chat.add_error_message("System error")
        chat.add_system_message("System notification")

        assert len(list(chat.query(".user-message"))) > 0
        assert len(list(chat.query(".assistant-message"))) > 0


@pytest.mark.asyncio
async def test_chat_panel_tool_lifecycle():
    async with ChatWidgetTestApp().run_test() as pilot:
        chat = pilot.app.query_one("#chat", ChatPanel)

        chat.add_tool_start("tool-123", "execute", {"command": "ls"})
        await pilot.pause()

        assert "tool-123" in chat._active_tools
        tool_widget = chat._active_tools["tool-123"]

        chat.append_tool_output("tool-123", "file1.txt ")
        await pilot.pause()
        assert "file1.txt" in tool_widget._live_output_buffer

        chat.update_tool_end("tool-123", True, 0.5, "output content")
        await pilot.pause()

        assert "tool-123" not in chat._active_tools


@pytest.mark.asyncio
async def test_thinking_spinner_shows_full_buddy_rows_without_remount_churn():
    async with ChatWidgetTestApp().run_test() as pilot:
        chat = pilot.app.query_one("#chat", ChatPanel)
        chat.start_thinking()
        await pilot.pause(0.1)

        spinner = chat.query_one(ThinkingSpinner)
        assert spinner._buddy_row_count == 5
        assert len(spinner._buddy_rows) == 5
        assert len(spinner._buddy_parts) == 5
        assert all(len(list(row.children)) == 1 for row in spinner._buddy_rows)

        await pilot.pause(0.8)
        assert all(len(list(row.children)) == 1 for row in spinner._buddy_rows)



def test_stylesheet_keeps_thinking_spinner_multiline_height():
    css = Path("airecon/tui/styles.tcss").read_text(encoding="utf-8")
    assert "ThinkingSpinner {" in css
    assert "min-height: 6;" in css
    assert "align: left top;" in css


def test_stylesheet_has_orange_buddy_spinner_accent():
    css = Path("airecon/tui/styles.tcss").read_text(encoding="utf-8")
    assert "ThinkingSpinner .buddy-part" in css
    assert "color: #f59e0b;" in css


def test_buddy_species_synced_with_openclaude_sprite_pack():
    assert "goose" in AVAILABLE_SPECIES
    assert "axolotl" in AVAILABLE_SPECIES
    assert "frog" not in AVAILABLE_SPECIES


def test_on_text_selected_copies_selection_and_dedupes(monkeypatch):
    """App-level `on_text_selected` fires on mouse-up (Textual 8.1+).
    Verify: copies non-empty selection, skips empty, dedupes repeats."""
    from airecon.tui.app import AIReconApp

    copied: list[str] = []
    current_selection = {"text": "copy this text"}

    app = AIReconApp.__new__(AIReconApp)
    monkeypatch.setattr(
        AIReconApp,
        "screen",
        property(lambda _self: SimpleNamespace(get_selected_text=lambda: current_selection["text"])),
    )
    app.copy_to_clipboard = lambda value: copied.append(value)

    app.on_text_selected()
    assert copied == ["copy this text"]

    app.on_text_selected()
    assert copied == ["copy this text"]

    current_selection["text"] = "different text"
    app.on_text_selected()
    assert copied == ["copy this text", "different text"]

    current_selection["text"] = ""
    app.on_text_selected()
    assert copied == ["copy this text", "different text"]


@pytest.mark.asyncio
async def test_status_bar_updates():
    async with StatusWidgetTestApp().run_test() as pilot:
        status_bar = pilot.app.query_one("#status", StatusBar)

        status_bar.set_status(llm="online", docker="offline", exec_used=5)
        await pilot.pause()

        metrics_content = str(status_bar.query_one("#status-metrics").render())
        assert "online" in metrics_content or "●" in metrics_content
        assert "offline" in metrics_content or "○" in metrics_content

        exec_content = str(status_bar.query_one("#status-caido-exec").render())
        assert "5" in exec_content


def test_status_bar_formats_million_tokens_as_int_unit():
    status_bar = StatusBar()
    assert status_bar._format_token_count(1_250_000) == "1M"


def test_status_bar_formats_thousand_tokens_as_int_unit():
    status_bar = StatusBar()
    assert status_bar._format_token_count(987_654) == "987K"


def test_status_bar_set_status_coerces_numeric_fields():
    status_bar = StatusBar()
    status_bar.set_status(
        tokens="abc",
        token_limit="xyz",
        exec_used="7",
        subagents="2",
        caido_findings="9",
    )

    assert status_bar.token_count == 0
    assert status_bar.token_limit == 65_536
    assert status_bar.exec_used == 7
    assert status_bar.subagents_spawned == 2
    assert status_bar.caido_findings == 9


@pytest.mark.asyncio
async def test_status_bar_caido_active_shows_indicator():
    async with StatusWidgetTestApp().run_test() as pilot:
        status_bar = pilot.app.query_one("#status", StatusBar)
        status_bar.set_status(caido_active=True, caido_findings=5)
        await pilot.pause()
        content = str(status_bar.query_one("#status-caido-exec").render())
        assert "Caido" in content
        assert "ON" in content
        assert "5" in content


@pytest.mark.asyncio
async def test_status_bar_caido_inactive_shows_off_state():
    async with StatusWidgetTestApp().run_test() as pilot:
        status_bar = pilot.app.query_one("#status", StatusBar)
        status_bar.set_status(caido_active=False)
        await pilot.pause()
        content = str(status_bar.query_one("#status-caido-exec").render())
        assert "Caido" in content
        assert "OFF" in content


def test_status_bar_caido_active_reactive_default_false():
    status_bar = StatusBar()
    assert status_bar.caido_active is False
    assert status_bar.caido_findings == 0


def test_status_bar_caido_findings_negative_clamped():
    status_bar = StatusBar()
    status_bar.set_status(caido_findings="-3")
    assert status_bar.caido_findings == 0


def test_status_bar_token_color_low():
    assert StatusBar._token_color_for_cumulative(500_000) == "#00d4aa"


def test_status_bar_token_color_medium():
    assert StatusBar._token_color_for_cumulative(2_000_000) == "#f59e0b"


def test_status_bar_token_color_high():
    assert StatusBar._token_color_for_cumulative(10_000_000) == "#ef4444"


def test_status_bar_format_token_billion():
    status_bar = StatusBar()
    result = status_bar._format_token_count(1_500_000_000)
    assert result == "1B"


def test_status_bar_format_token_zero():
    status_bar = StatusBar()
    assert status_bar._format_token_count(0) == "0"

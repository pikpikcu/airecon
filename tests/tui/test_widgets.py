import pytest
import tempfile
from pathlib import Path
from textual.app import App, ComposeResult
from airecon.tui.widgets.chat import ChatPanel
from airecon.tui.widgets.workspace import WorkspacePanel
from airecon.tui.widgets.status import StatusBar

# A dummy Textual app to host isolated widgets

_WORKSPACE_DIR = Path(tempfile.mkdtemp(prefix="airecon_test_"))


class WidgetTestApp(App):
    def compose(self) -> ComposeResult:
        yield ChatPanel(id="chat")
        yield WorkspacePanel(_WORKSPACE_DIR, id="workspace")
        yield StatusBar(id="status")


@pytest.mark.asyncio
async def test_chat_panel_add_messages():
    async with WidgetTestApp().run_test() as pilot:
        chat = pilot.app.query_one("#chat", ChatPanel)

        chat.add_user_message("Test user message")
        chat.add_assistant_message("Test AI message")
        chat.add_error_message("System error")
        chat.add_system_message("System notification")

        # We verify that standard messages were mounted to the ChatPanel
        assert len(list(chat.query(".user-message"))) > 0
        assert len(list(chat.query(".assistant-message"))) > 0


@pytest.mark.asyncio
async def test_chat_panel_tool_lifecycle():
    async with WidgetTestApp().run_test() as pilot:
        chat = pilot.app.query_one("#chat", ChatPanel)

        # Start a mock tool call
        chat.add_tool_start("tool-123", "execute", {"command": "ls"})
        await pilot.pause()

        assert "tool-123" in chat._active_tools
        tool_widget = chat._active_tools["tool-123"]

        # Append output without newlines to ensure it stays in buffer
        chat.append_tool_output("tool-123", "file1.txt ")
        await pilot.pause()
        # Verify text was buffered
        assert "file1.txt" in tool_widget._live_output_buffer

        # End tool call
        chat.update_tool_end("tool-123", True, 0.5, "output content")
        await pilot.pause()

        # Ensure it was popped from active tool tracking
        assert "tool-123" not in chat._active_tools


@pytest.mark.asyncio
async def test_status_bar_updates():
    async with WidgetTestApp().run_test() as pilot:
        status_bar = pilot.app.query_one("#status", StatusBar)

        # Update metrics
        status_bar.set_status(ollama="online", docker="offline", exec_used=5)
        await pilot.pause()

        # Assert against the new separated labels
        metrics_content = str(status_bar.query_one("#status-metrics").render())
        assert "online" in metrics_content or "●" in metrics_content
        assert "offline" in metrics_content or "○" in metrics_content

        exec_content = str(status_bar.query_one("#status-caido-exec").render())
        assert "5" in exec_content


def test_status_bar_formats_million_tokens():
    status_bar = StatusBar()
    assert status_bar._format_token_count(1_250_000).endswith("M")


def test_status_bar_set_status_coerces_numeric_fields():
    status_bar = StatusBar()
    status_bar.set_status(
        tokens="1000000",
        token_limit="65536",
        exec_used="7",
        subagents="2",
        caido_findings="9",
    )

    assert status_bar.token_count == 1_000_000
    assert status_bar.token_limit == 65_536
    assert status_bar.exec_used == 7
    assert status_bar.subagents_spawned == 2
    assert status_bar.caido_findings == 9


# ── StatusBar caido rendering ─────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_status_bar_caido_active_shows_indicator():
    async with WidgetTestApp().run_test() as pilot:
        status_bar = pilot.app.query_one("#status", StatusBar)
        status_bar.set_status(caido_active=True, caido_findings=5)
        await pilot.pause()
        content = str(status_bar.query_one("#status-caido-exec").render())
        assert "Caido" in content
        assert "5" in content


@pytest.mark.asyncio
async def test_status_bar_caido_inactive_hides_indicator():
    async with WidgetTestApp().run_test() as pilot:
        status_bar = pilot.app.query_one("#status", StatusBar)
        status_bar.set_status(caido_active=False)
        await pilot.pause()
        content = str(status_bar.query_one("#status-caido-exec").render())
        assert "Caido" not in content


def test_status_bar_caido_active_reactive_default_false():
    status_bar = StatusBar()
    assert status_bar.caido_active is False
    assert status_bar.caido_findings == 0


def test_status_bar_caido_findings_negative_clamped():
    status_bar = StatusBar()
    status_bar.set_status(caido_findings="-3")
    assert status_bar.caido_findings == 0


# ── StatusBar token color scale ───────────────────────────────────────────────

def test_status_bar_token_color_low():
    assert StatusBar._token_color_for_cumulative(500_000) == "#00d4aa"


def test_status_bar_token_color_medium():
    assert StatusBar._token_color_for_cumulative(2_000_000) == "#f59e0b"


def test_status_bar_token_color_high():
    assert StatusBar._token_color_for_cumulative(10_000_000) == "#ef4444"


def test_status_bar_format_token_billion():
    status_bar = StatusBar()
    result = status_bar._format_token_count(1_500_000_000)
    assert result.endswith("B")


def test_status_bar_format_token_zero():
    status_bar = StatusBar()
    assert status_bar._format_token_count(0) == "0"

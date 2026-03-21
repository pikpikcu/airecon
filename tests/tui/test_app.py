import pytest
from unittest.mock import patch, MagicMock, AsyncMock
from airecon.tui.app import AIReconApp, QuitConfirmScreen
from airecon.tui.startup import StartupScreen, _write_config_value
from airecon.tui.widgets.input import CommandInput
from textual.app import App, ComposeResult


@pytest.fixture(autouse=True)
def isolated_workspace(tmp_path, monkeypatch):
    """Keep TUI tests isolated from large real workspace trees."""
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    monkeypatch.setattr("airecon.tui.app.get_workspace_root", lambda: workspace)


@pytest.mark.asyncio
async def test_app_initialization():
    async with AIReconApp().run_test() as pilot:
        assert pilot.app.title == "AIRecon"
        assert pilot.app.sub_title == "AI Security Reconnaissance"

        # Check initial widgets
        assert pilot.app.query_one("#command-input") is not None
        assert pilot.app.query_one("#chat-panel") is not None
        assert pilot.app.query_one("#workspace-panel") is not None


@pytest.mark.asyncio
async def test_app_send_message_triggers_worker():
    with patch.object(AIReconApp, 'run_worker') as mock_run_worker:
        async with AIReconApp().run_test() as pilot:
            command_input = pilot.app.query_one("#command-input", CommandInput)

            # Fill inputs
            command_input.value = "scan server"

            # Submit chat directly via the on_command_input_submitted handler
            class MockSubmitted:
                value = "scan server"
            await pilot.app.on_command_input_submitted(MockSubmitted())
            await pilot.pause()

            # Assert run_worker was called to spawn the SSE streaming thread
            mock_run_worker.assert_called()


@pytest.mark.asyncio
async def test_app_status_polling_connection():
    with patch('httpx.AsyncClient.get') as mock_get:
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "ollama": {"connected": True, "model": "test-model"},
            "docker": {"connected": True},
            "agent": {"tool_counts": {"exec": 5, "subagents": 1}}
        }
        mock_get.return_value = mock_response

        async with AIReconApp().run_test() as pilot:
            # Manually trigger a single poll check rather than waiting for the background task
            await pilot.app._check_services(verbose=False)
            await pilot.pause()

            # Ensure status logic executed successfully without crashing
            mock_get.assert_called_with("/api/status", timeout=5.0)


# ── AIReconApp new init params ────────────────────────────────────────────────

def test_app_init_default_params():
    app = AIReconApp()
    assert app.proxy_url == "http://127.0.0.1:3000"
    assert app._no_proxy is False
    assert app._session_id is None


def test_app_init_no_proxy_flag():
    app = AIReconApp(no_proxy=True)
    assert app._no_proxy is True


def test_app_init_session_id():
    app = AIReconApp(session_id="1234_abcd")
    assert app._session_id == "1234_abcd"


def test_app_init_proxy_url_stripped():
    app = AIReconApp(proxy_url="http://localhost:3000/")
    assert app.proxy_url == "http://localhost:3000"


# ── QuitConfirmScreen ─────────────────────────────────────────────────────────

class _QuitTestApp(App):
    def compose(self) -> ComposeResult:
        return iter([])

    async def action_show_quit(self):
        await self.push_screen(QuitConfirmScreen())


@pytest.mark.asyncio
async def test_quit_confirm_yes_button():
    results = []
    async with _QuitTestApp().run_test() as pilot:
        screen = QuitConfirmScreen()
        pilot.app.push_screen(screen, lambda v: results.append(v))
        await pilot.pause()
        await pilot.click("#yes")
        await pilot.pause()
    assert results == [True]


@pytest.mark.asyncio
async def test_quit_confirm_no_button():
    results = []
    async with _QuitTestApp().run_test() as pilot:
        screen = QuitConfirmScreen()
        pilot.app.push_screen(screen, lambda v: results.append(v))
        await pilot.pause()
        await pilot.click("#no")
        await pilot.pause()
    assert results == [False]


@pytest.mark.asyncio
async def test_quit_confirm_key_y():
    results = []
    async with _QuitTestApp().run_test() as pilot:
        screen = QuitConfirmScreen()
        pilot.app.push_screen(screen, lambda v: results.append(v))
        await pilot.pause()
        await pilot.press("y")
        await pilot.pause()
    assert results == [True]


@pytest.mark.asyncio
async def test_quit_confirm_key_n():
    results = []
    async with _QuitTestApp().run_test() as pilot:
        screen = QuitConfirmScreen()
        pilot.app.push_screen(screen, lambda v: results.append(v))
        await pilot.pause()
        await pilot.press("n")
        await pilot.pause()
    assert results == [False]


@pytest.mark.asyncio
async def test_quit_confirm_key_escape():
    results = []
    async with _QuitTestApp().run_test() as pilot:
        screen = QuitConfirmScreen()
        pilot.app.push_screen(screen, lambda v: results.append(v))
        await pilot.pause()
        await pilot.press("escape")
        await pilot.pause()
    assert results == [False]


@pytest.mark.asyncio
async def test_quit_confirm_key_enter_defaults_no():
    results = []
    async with _QuitTestApp().run_test() as pilot:
        screen = QuitConfirmScreen()
        pilot.app.push_screen(screen, lambda v: results.append(v))
        await pilot.pause()
        await pilot.press("enter")
        await pilot.pause()
    assert results == [False]


# ── StartupScreen unit tests (no worker) ─────────────────────────────────────

class _StartupTestApp(App):
    """Host a StartupScreen with the worker patched out."""

    def compose(self) -> ComposeResult:
        return iter([])

    def on_mount(self) -> None:
        screen = StartupScreen(proxy_url="http://127.0.0.1:3000", no_proxy=True)
        # Patch worker so it does not actually run startup tasks
        screen._run_startup = lambda: None  # type: ignore[method-assign]
        self.push_screen(screen)


@pytest.mark.asyncio
async def test_startup_screen_renders_step_labels():
    async with _StartupTestApp().run_test() as pilot:
        await pilot.pause()
        screen = pilot.app.screen
        assert isinstance(screen, StartupScreen)
        # All 5 step labels should exist
        for sid in ("step-docker", "step-searxng", "step-proxy", "step-ollama", "step-engine"):
            label = screen.query_one(f"#{sid}")
            assert label is not None


@pytest.mark.asyncio
async def test_startup_screen_set_step_ok():
    async with _StartupTestApp().run_test() as pilot:
        await pilot.pause()
        screen = pilot.app.screen
        assert isinstance(screen, StartupScreen)
        screen._set_step("step-docker", "ok", "ready")
        await pilot.pause()
        state, detail = screen._step_states["step-docker"]
        assert state == "ok"
        assert detail == "ready"


@pytest.mark.asyncio
async def test_startup_screen_set_step_fail():
    async with _StartupTestApp().run_test() as pilot:
        await pilot.pause()
        screen = pilot.app.screen
        assert isinstance(screen, StartupScreen)
        screen._set_step("step-proxy", "fail", "port conflict")
        await pilot.pause()
        state, detail = screen._step_states["step-proxy"]
        assert state == "fail"
        assert detail == "port conflict"


@pytest.mark.asyncio
async def test_startup_screen_set_status():
    async with _StartupTestApp().run_test() as pilot:
        await pilot.pause()
        screen = pilot.app.screen
        assert isinstance(screen, StartupScreen)
        screen._set_status("All systems ready.")
        await pilot.pause()
        content = str(screen.query_one("#startup-status").render())
        assert "All systems ready." in content


@pytest.mark.asyncio
async def test_startup_screen_pending_state_on_mount():
    async with _StartupTestApp().run_test() as pilot:
        await pilot.pause()
        screen = pilot.app.screen
        assert isinstance(screen, StartupScreen)
        # All steps should start as pending
        for sid in ("step-docker", "step-searxng", "step-proxy", "step-ollama", "step-engine"):
            state, _ = screen._step_states[sid]
            assert state == "pending"


@pytest.mark.asyncio
async def test_startup_screen_session_label_shown():
    """Session label should appear when session_id is provided."""
    async with _StartupTestApp().run_test() as pilot:
        await pilot.pause()
        # A screen with session_id would render the #startup-session label
        screen = StartupScreen(
            proxy_url="http://127.0.0.1:3000",
            no_proxy=True,
            session_id="1740842400_abc",
        )
        screen._run_startup = lambda: None  # type: ignore[method-assign]
        pilot.app.push_screen(screen)
        await pilot.pause()
        label = screen.query_one("#startup-session")
        assert label is not None


# ── _write_config_value unit test ─────────────────────────────────────────────

def test_write_config_value_creates_file(tmp_path):
    """_write_config_value should write key into ~/.airecon/config.json."""
    import json as _json
    import pathlib

    airecon_dir = tmp_path / ".airecon"
    airecon_dir.mkdir()

    with patch("pathlib.Path.home", return_value=tmp_path), \
         patch("airecon.proxy.config.reload_config"):
        _write_config_value("searxng_url", "http://localhost:4000")

    config_file = airecon_dir / "config.json"
    assert config_file.exists()
    result = _json.loads(config_file.read_text())
    assert result.get("searxng_url") == "http://localhost:4000"


def test_write_config_value_preserves_existing_keys(tmp_path):
    """_write_config_value should not overwrite other existing keys."""
    import json as _json

    airecon_dir = tmp_path / ".airecon"
    airecon_dir.mkdir()
    (airecon_dir / "config.json").write_text(_json.dumps({"ollama_model": "llama3"}))

    with patch("pathlib.Path.home", return_value=tmp_path), \
         patch("airecon.proxy.config.reload_config"):
        _write_config_value("searxng_url", "http://localhost:4000")

    result = _json.loads((airecon_dir / "config.json").read_text())
    assert result["ollama_model"] == "llama3"
    assert result["searxng_url"] == "http://localhost:4000"

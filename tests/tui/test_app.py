import asyncio
import pytest
from unittest.mock import patch, MagicMock, AsyncMock
from airecon.tui.app import AIReconApp, QuitConfirmScreen, UserInputModal
from airecon.tui.startup import StartupScreen, _write_config_value
from textual.app import App, ComposeResult


@pytest.fixture(autouse=True)
def isolated_workspace(tmp_path, monkeypatch):
    """Keep TUI tests isolated from large real workspace trees."""
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    monkeypatch.setattr("airecon.tui.app.get_workspace_root", lambda: workspace)


def test_app_initialization():
    app = AIReconApp(show_startup_screen=False, auto_poll_services=False)
    assert app.title == "AIRecon"
    assert app.sub_title == "AI Security Reconnaissance"
    assert app._show_startup_screen is False
    assert app._auto_poll_services is False


@pytest.mark.asyncio
async def test_app_send_message_triggers_worker():
    def _run_worker_side_effect(coro, *args, **kwargs):
        if asyncio.iscoroutine(coro):
            coro.close()
        return MagicMock()

    with patch.object(
        AIReconApp, "run_worker", side_effect=_run_worker_side_effect
    ) as mock_run_worker:
        app = AIReconApp(show_startup_screen=False, auto_poll_services=False)
        chat = MagicMock()
        slash = MagicMock()
        path = MagicMock()
        app.query_one = MagicMock(
            side_effect=lambda selector, *args: {
                "#slash-completer": slash,
                "#path-completer": path,
                "#chat-panel": chat,
            }[selector]
        )  # type: ignore[method-assign]
        app._show_recon_spinner = MagicMock()  # type: ignore[method-assign]

        class MockSubmitted:
            value = "scan server"

        await app.on_command_input_submitted(MockSubmitted())

        mock_run_worker.assert_called()
        chat.add_user_message.assert_called_once_with("scan server")
        chat.start_thinking.assert_called_once()


@pytest.mark.asyncio
async def test_handle_shell_command_calls_api_shell_and_renders_output():
    app = AIReconApp(show_startup_screen=False, auto_poll_services=False)
    chat = MagicMock()
    app.query_one = MagicMock(return_value=chat)  # type: ignore[method-assign]

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.content = b"x"
    mock_resp.json.return_value = {
        "success": True,
        "stdout": "installed",
        "stderr": "",
        "exit_code": 0,
    }
    app._http = MagicMock()
    app._http.post = AsyncMock(return_value=mock_resp)

    await app._handle_slash_command("/shell apt update")

    app._http.post.assert_awaited_once_with(
        "/api/shell",
        json={"command": "apt update"},
        timeout=180.0,
    )
    chat.add_system_message.assert_called_once()
    chat.add_assistant_message.assert_called()


@pytest.mark.asyncio
async def test_handle_shell_command_without_args_shows_usage():
    app = AIReconApp(show_startup_screen=False, auto_poll_services=False)
    chat = MagicMock()
    app.query_one = MagicMock(return_value=chat)  # type: ignore[method-assign]

    await app._handle_slash_command("/shell")

    chat.add_assistant_message.assert_called_once()
    assert "Usage: /shell <command>" in chat.add_assistant_message.call_args.args[0]


@pytest.mark.asyncio
async def test_handle_models_command_lists_models():
    app = AIReconApp(show_startup_screen=False, auto_poll_services=False)
    chat = MagicMock()
    app.query_one = MagicMock(return_value=chat)  # type: ignore[method-assign]

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.content = b"x"
    mock_resp.json.return_value = {
        "current_model": "gpt-4o",
        "source_url": "http://llm.test/v1/models",
        "models": ["gpt-4o", "gpt-4o-mini"],
    }
    app._http = MagicMock()
    app._http.get = AsyncMock(return_value=mock_resp)

    await app._handle_slash_command("/models")

    app._http.get.assert_awaited_once_with("/api/models", timeout=15.0)
    rendered = chat.add_assistant_message.call_args.args[0]
    assert "Current: gpt-4o" in rendered
    assert "* gpt-4o" in rendered
    assert "  gpt-4o-mini" in rendered


def test_format_models_response_does_not_truncate_long_model_lists():
    models = [f"model-{idx}" for idx in range(105)]

    rendered = AIReconApp._format_models_response(
        {
            "current_model": "model-104",
            "source_url": "http://llm.test/v1/models",
            "models": models,
        }
    )

    assert "Available models (105)" in rendered
    assert "* model-104" in rendered
    assert "... 25 more" not in rendered


def test_format_models_response_notes_current_model_missing_from_list():
    rendered = AIReconApp._format_models_response(
        {
            "current_model": "oc/big-pickle",
            "source_url": "http://llm.test/v1/models",
            "models": ["local", "gh/gpt-4o"],
        }
    )

    assert "Available models (2)" in rendered
    assert "Current: oc/big-pickle" in rendered
    assert "Current model was not returned" in rendered


@pytest.mark.asyncio
async def test_handle_models_command_switches_model():
    app = AIReconApp(show_startup_screen=False, auto_poll_services=False)
    chat = MagicMock()
    app.query_one = MagicMock(return_value=chat)  # type: ignore[method-assign]

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.content = b"x"
    mock_resp.json.return_value = {
        "current_model": "gpt-4o-mini",
        "thinking": {"enabled": True},
    }
    app._http = MagicMock()
    app._http.post = AsyncMock(return_value=mock_resp)

    await app._handle_slash_command("/models gpt-4o-mini")

    app._http.post.assert_awaited_once_with(
        "/api/models",
        json={"model": "gpt-4o-mini"},
        timeout=30.0,
    )
    rendered = chat.add_assistant_message.call_args.args[0]
    assert "Current: gpt-4o-mini" in rendered
    assert "Thinking: true" in rendered


@pytest.mark.asyncio
async def test_handle_think_command_toggles_thinking():
    app = AIReconApp(show_startup_screen=False, auto_poll_services=False)
    chat = MagicMock()
    app.query_one = MagicMock(return_value=chat)  # type: ignore[method-assign]

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.content = b"x"
    mock_resp.json.return_value = {
        "enabled": False,
        "mode": "low",
        "request_mode": "auto",
        "supports_thinking": False,
    }
    app._http = MagicMock()
    app._http.post = AsyncMock(return_value=mock_resp)

    await app._handle_slash_command("/think false")

    app._http.post.assert_awaited_once_with(
        "/api/think",
        json={"enabled": False},
        timeout=30.0,
    )
    rendered = chat.add_assistant_message.call_args.args[0]
    assert "Enabled: false" in rendered
    assert "Request mode: auto" in rendered


@pytest.mark.asyncio
async def test_app_status_polling_connection():
    with patch("httpx.AsyncClient.get") as mock_get:
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "llm": {"connected": True, "model": "test-model"},
            "docker": {"connected": True},
            "agent": {"tool_counts": {"exec": 5, "subagents": 1}},
        }
        mock_get.return_value = mock_response

        app = AIReconApp(show_startup_screen=False, auto_poll_services=False)
        status = MagicMock()
        chat = MagicMock()
        app.query_one = MagicMock(
            side_effect=lambda selector, *args: {
                "#status-bar": status,
                "#chat-panel": chat,
            }[selector]
        )  # type: ignore[method-assign]

        # Manually trigger a single poll check rather than waiting for background tasks
        await app._check_services(verbose=False)

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


def test_llm_recovery_marker_detection():
    assert (
        AIReconApp._is_llm_recovery_marker("[AUTO-RECOVERY #1] VRAM crash") is True
    )
    assert (
        AIReconApp._is_llm_recovery_marker("CUDA out of memory while generating")
        is True
    )
    assert AIReconApp._is_llm_recovery_marker("normal assistant response") is False


def test_mark_llm_degraded_updates_status_bar():
    app = AIReconApp(show_startup_screen=False, auto_poll_services=False)
    status = MagicMock()
    app.query_one = MagicMock(return_value=status)  # type: ignore[method-assign]
    app._processing = True

    app._mark_llm_degraded("[AUTO-RECOVERY #2] VRAM crash")

    assert app._is_llm_degraded_active() is True
    status.set_status.assert_called_with(llm_degraded=True)


def test_mark_llm_degraded_ignored_when_idle():
    app = AIReconApp(show_startup_screen=False, auto_poll_services=False)
    status = MagicMock()
    app.query_one = MagicMock(return_value=status)  # type: ignore[method-assign]
    app._processing = False

    app._mark_llm_degraded("[AUTO-RECOVERY #2] VRAM crash")

    assert app._is_llm_degraded_active() is False
    status.set_status.assert_not_called()


def test_history_entries_to_render_supports_tool_calls_and_tool_role():
    messages = [
        {"role": "user", "content": "scan example.com"},
        {
            "role": "assistant",
            "content": "",
            "tool_calls": [
                {
                    "function": {
                        "name": "terminal",
                        "arguments": {"command": "nmap -sV example.com"},
                    }
                }
            ],
        },
        {"role": "tool", "content": {"output": "open ports: 80,443"}},
        {"role": "assistant", "content": "Recon selesai."},
    ]

    rendered = AIReconApp._history_entries_to_render(messages)

    assert rendered[0] == ("user", "scan example.com")
    assert rendered[1][0] == "tool"
    assert "terminal" in rendered[1][1]
    assert rendered[2][0] == "tool"
    assert "open ports" in rendered[2][1]
    assert rendered[3] == ("assistant", "Recon selesai.")


def test_history_content_to_text_handles_non_string_payloads():
    text = AIReconApp._history_content_to_text({"a": 1, "b": [2, 3]})
    assert '"a": 1' in text
    assert '"b": [' in text


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


# ── UserInputModal ────────────────────────────────────────────────────────────


class _UserInputTestApp(App):
    def compose(self) -> ComposeResult:
        return iter([])


@pytest.mark.asyncio
async def test_user_input_modal_totp_submit():
    results = []
    async with _UserInputTestApp().run_test() as pilot:
        screen = UserInputModal("Enter 2FA code", input_type="totp")
        pilot.app.push_screen(screen, lambda v: results.append(v))
        await pilot.pause()
        await pilot.click("#modal-input")
        await pilot.press("1", "2", "3", "4", "5", "6")
        await pilot.press("enter")
        await pilot.pause()
    assert results == ["123456"]


@pytest.mark.asyncio
async def test_user_input_modal_escape_cancel():
    results = []
    async with _UserInputTestApp().run_test() as pilot:
        screen = UserInputModal("Solve CAPTCHA", input_type="captcha")
        pilot.app.push_screen(screen, lambda v: results.append(v))
        await pilot.pause()
        await pilot.press("escape")
        await pilot.pause()
    assert results == [None]


def test_user_input_modal_extracts_captcha_screenshot_path():
    modal = UserInputModal(
        "Please solve captcha from /tmp/airecon/captcha_abc.png",
        input_type="captcha",
    )
    assert modal._extract_screenshot_path() == "/tmp/airecon/captcha_abc.png"


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
        for sid in (
            "step-docker",
            "step-searxng",
            "step-proxy",
            "step-llm",
            "step-engine",
        ):
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
        for sid in (
            "step-docker",
            "step-searxng",
            "step-proxy",
            "step-llm",
            "step-engine",
        ):
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


def test_startup_screen_proxy_timeout_default():
    screen = StartupScreen(proxy_url="http://127.0.0.1:3000", no_proxy=False)
    assert screen._proxy_start_timeout_seconds() == 35.0


def test_startup_screen_proxy_timeout_resume_mode():
    screen = StartupScreen(
        proxy_url="http://127.0.0.1:3000",
        no_proxy=False,
        session_id="1740842400_abc",
    )
    assert screen._proxy_start_timeout_seconds() == 60.0


# ── _write_config_value unit test ─────────────────────────────────────────────


def test_write_config_value_creates_file(tmp_path):
    """_write_config_value should write key into ~/.airecon/config.yaml."""
    import yaml

    airecon_dir = tmp_path / ".airecon"
    airecon_dir.mkdir()

    with (
        patch("pathlib.Path.home", return_value=tmp_path),
        patch("airecon.proxy.config.reload_config"),
    ):
        _write_config_value("searxng_url", "http://localhost:4000")

    config_file = airecon_dir / "config.yaml"
    assert config_file.exists()
    result = yaml.safe_load(config_file.read_text())
    assert result.get("searxng_url") == "http://localhost:4000"


def test_write_config_value_preserves_existing_keys(tmp_path):
    """_write_config_value should not overwrite other existing keys."""
    import yaml

    airecon_dir = tmp_path / ".airecon"
    airecon_dir.mkdir()
    (airecon_dir / "config.yaml").write_text(yaml.dump({"openai_model": "llama3"}))

    with (
        patch("pathlib.Path.home", return_value=tmp_path),
        patch("airecon.proxy.config.reload_config"),
    ):
        _write_config_value("searxng_url", "http://localhost:4000")

    result = yaml.safe_load((airecon_dir / "config.yaml").read_text())
    assert result["openai_model"] == "llama3"
    assert result["searxng_url"] == "http://localhost:4000"

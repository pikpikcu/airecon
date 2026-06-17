"""Tests for __main__.py - CLI entry point."""

import argparse
import sys
from unittest.mock import MagicMock, patch

import pytest

from airecon.__main__ import (
    _run_clean,
    _run_list_sessions,
    _run_proxy,
    _run_tui,
    _unload_model_safely,
    main,
)


class TestMainCLI:
    """Test CLI argument parsing and command routing."""

    def test_version_flag(self) -> None:
        """Test --version flag shows version."""

        with pytest.raises(SystemExit) as exc_info:
            sys.argv = ["airecon", "--version"]
            main()

        assert exc_info.value.code == 0

    def test_list_command(self) -> None:
        """Test --list command routes to list sessions."""
        with patch("airecon.__main__._run_list_sessions") as mock_list:
            sys.argv = ["airecon", "--list"]
            with pytest.raises(SystemExit) as exc_info:
                main()

            mock_list.assert_called_once()
            assert exc_info.value.code == 0

    def test_proxy_command(self) -> None:
        """Test proxy command routes correctly."""
        with (
            patch("airecon.__main__._run_proxy") as mock_proxy,
            patch("airecon.proxy.config.get_config"),
        ):
            sys.argv = ["airecon", "proxy"]
            main()

            mock_proxy.assert_called_once()
            args = mock_proxy.call_args[0][0]
            assert args.command == "proxy"

    def test_start_command(self) -> None:
        """Test start (TUI) command routes correctly."""
        with (
            patch("airecon.__main__._run_tui") as mock_tui,
            patch("airecon.proxy.config.get_config"),
        ):
            sys.argv = ["airecon", "start"]
            main()

            mock_tui.assert_called_once()
            args = mock_tui.call_args[0][0]
            assert args.command == "start"

    def test_status_command(self) -> None:
        """Test status command routes correctly."""
        with (
            patch("airecon.__main__._run_status") as mock_status,
            patch("airecon.proxy.config.get_config"),
        ):
            sys.argv = ["airecon", "status"]
            main()

            mock_status.assert_called_once()

    def test_clean_command(self) -> None:
        """Test clean command routes correctly."""
        with (
            patch("airecon.__main__._run_clean") as mock_clean,
            patch("airecon.proxy.config.get_config"),
        ):
            sys.argv = ["airecon", "clean"]
            main()

            mock_clean.assert_called_once()
            args = mock_clean.call_args[0][0]
            assert args.command == "clean"

    def test_no_command_shows_help(self, capsys: pytest.CaptureFixture[str]) -> None:
        """Test no command shows banner hint and exits with code 1."""
        sys.argv = ["airecon"]
        with pytest.raises(SystemExit) as exc_info:
            main()

        captured = capsys.readouterr()
        assert "see all options:" in captured.out.lower()
        assert "airecon -h" in captured.out.lower()
        assert exc_info.value.code == 1

    def test_custom_config_flag(self) -> None:
        """Test --config flag is accepted."""
        with (
            patch("airecon.proxy.config.get_config") as mock_config,
            patch("airecon.__main__._run_status"),
        ):
            mock_config.return_value = MagicMock()
            sys.argv = ["airecon", "--config", "/tmp/test.json", "status"]
            main()

            # Config should be called
            assert mock_config.called


class TestRunProxy:
    """Test proxy command execution."""

    def test_run_proxy_basic(self) -> None:
        """Test proxy starts server."""
        args = argparse.Namespace(host=None, port=None, config=None)

        with patch("airecon.proxy.server.run_server"):
            _run_proxy(args)

    def test_run_proxy_with_host(self) -> None:
        """Test proxy with custom host."""
        args = argparse.Namespace(host="0.0.0.0", port=None, config=None)

        with patch.dict("os.environ", {}, clear=True):
            with patch("airecon.proxy.server.run_server"):
                with patch("airecon.proxy.config._config", None):
                    _run_proxy(args)
                    # Host env var should be set
                    import os

                    assert os.environ.get("AIRECON_PROXY_HOST") == "0.0.0.0"

    def test_run_proxy_with_port(self) -> None:
        """Test proxy with custom port."""
        args = argparse.Namespace(host=None, port=8080, config=None)

        with patch.dict("os.environ", {}, clear=True):
            with patch("airecon.proxy.server.run_server"):
                with patch("airecon.proxy.config._config", None):
                    _run_proxy(args)
                    # Port env var should be set
                    import os

                    assert os.environ.get("AIRECON_PROXY_PORT") == "8080"

    def test_run_proxy_registers_exit_handler(self) -> None:
        """Test proxy registers model unload on exit."""
        args = argparse.Namespace(host=None, port=None, config=None)

        with patch("airecon.proxy.server.run_server"):
            with patch("atexit.register") as mock_register:
                _run_proxy(args)
                # Should register unload handler
                mock_register.assert_called()


class TestRunTUI:
    """Test TUI command execution."""

    def test_run_tui_basic(self) -> None:
        """Test TUI starts app."""
        args = argparse.Namespace(
            no_proxy=False, proxy_url="http://127.0.0.1:3000", config=None, session=None
        )

        with patch("airecon.tui.app.AIReconApp") as mock_app_class:
            mock_app = MagicMock()
            mock_app_class.return_value = mock_app

            _run_tui(args)

            mock_app_class.assert_called_once()
            mock_app.run.assert_called_once()

    def test_run_tui_with_session(self) -> None:
        """Test TUI with session resume."""
        args = argparse.Namespace(
            no_proxy=False,
            proxy_url="http://127.0.0.1:3000",
            config=None,
            session="test_session_123",
        )

        with patch.dict("os.environ", {}, clear=True):
            with patch("airecon.tui.app.AIReconApp"):
                _run_tui(args)
                # Session env var should be set
                import os

                assert os.environ.get("AIRECON_SESSION_ID") == "test_session_123"

    def test_run_tui_without_session_clears_stale_env(self) -> None:
        """New session mode must clear inherited AIRECON_SESSION_ID."""
        args = argparse.Namespace(
            no_proxy=False,
            proxy_url="http://127.0.0.1:3000",
            config=None,
            session=None,
        )

        with patch.dict(
            "os.environ", {"AIRECON_SESSION_ID": "old_session"}, clear=True
        ):
            with patch("airecon.tui.app.AIReconApp"):
                _run_tui(args)
                import os

                assert os.environ.get("AIRECON_SESSION_ID") is None

    def test_run_tui_no_proxy_flag(self) -> None:
        """Test TUI with --no-proxy flag."""
        args = argparse.Namespace(
            no_proxy=True, proxy_url="http://127.0.0.1:3000", config=None, session=None
        )

        with patch("airecon.tui.app.AIReconApp") as mock_app_class:
            mock_app = MagicMock()
            mock_app_class.return_value = mock_app

            _run_tui(args)

            # Should pass no_proxy=True to app
            call_kwargs = mock_app_class.call_args[1]
            assert call_kwargs["no_proxy"] is True

    def test_run_tui_crash_handling(self) -> None:
        """Test TUI crash writes log file."""
        args = argparse.Namespace(
            no_proxy=False, proxy_url="http://127.0.0.1:3000", config=None, session=None
        )

        with patch("airecon.tui.app.AIReconApp") as mock_app_class:
            mock_app = MagicMock()
            mock_app.run.side_effect = Exception("Crash!")
            mock_app_class.return_value = mock_app

            with patch("builtins.open") as mock_open:
                with pytest.raises(SystemExit) as exc_info:
                    _run_tui(args)

                # Should write crash log to temp directory
                call_args = mock_open.call_args
                assert call_args is not None
                assert call_args[0][0].name == "airecon_crash.log"
                assert call_args[0][1] == "w"
                assert exc_info.value.code == 1


class TestRunStatus:
    """Test status command execution."""

    def test_run_status_all_services_up(self) -> None:
        """Test status check when all services are up."""
        args = argparse.Namespace(config=None)

        with (
            patch("airecon.proxy.config.get_config") as mock_cfg,
            patch("httpx.AsyncClient.get") as mock_get,
            patch("shutil.which", return_value="/usr/bin/docker"),
            patch("subprocess.run") as mock_sp,
        ):
            mock_cfg.return_value = MagicMock(
                proxy_host="127.0.0.1", proxy_port=8084, openai_model="test"
            )
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {
                "status": "ok",
                "llm": {"connected": True},
                "docker": {"connected": True},
            }
            mock_get.return_value = mock_response
            mock_sp.return_value = MagicMock(stdout="Up 2 hours", returncode=0)

            # Should not raise
            from airecon.__main__ import _run_status

            _run_status(args)

    def test_run_status_llm_down(self) -> None:
        """Test status check when LLM is down."""
        args = argparse.Namespace(config=None)

        with (
            patch("airecon.proxy.config.get_config") as mock_cfg,
            patch("httpx.AsyncClient.get") as mock_get,
            patch("shutil.which", return_value=None),
        ):
            mock_cfg.return_value = MagicMock(
                proxy_host="127.0.0.1", proxy_port=8084, openai_model="test"
            )
            import httpx

            mock_get.side_effect = httpx.ConnectError("Connection refused")

            # Should not raise, just print status
            from airecon.__main__ import _run_status

            _run_status(args)


class TestRunClean:
    """Test clean command execution."""

    def test_run_clean_basic(self) -> None:
        """Test clean without --all flag."""
        args = argparse.Namespace(all=False, keep_storage="3gb")

        with (
            patch("subprocess.run") as mock_run,
            patch("shutil.which", return_value="/usr/bin/docker"),
        ):
            mock_run.return_value = MagicMock(returncode=0, stdout=b"")
            _run_clean(args)
            assert mock_run.called

    def test_run_clean_all_flag(self) -> None:
        """Test clean with --all flag removes image."""
        args = argparse.Namespace(all=True, keep_storage="3gb")

        with (
            patch("subprocess.run") as mock_run,
            patch("shutil.which", return_value="/usr/bin/docker"),
        ):
            mock_run.return_value = MagicMock(returncode=0, stdout=b"")
            _run_clean(args)
            calls = [str(c) for c in mock_run.call_args_list]
            assert any("rmi" in c for c in calls)

    def test_run_clean_keep_storage_zero(self) -> None:
        """Test clean with --keep-storage=0 removes all cache."""
        args = argparse.Namespace(all=False, keep_storage="0")

        with (
            patch("subprocess.run") as mock_run,
            patch("shutil.which", return_value="/usr/bin/docker"),
        ):
            mock_run.return_value = MagicMock(returncode=0, stdout=b"")
            _run_clean(args)
            calls = [str(c) for c in mock_run.call_args_list]
            assert any("-f" in c for c in calls)


class TestUnloadModelSafely:
    """Test model unload on exit."""

    def test_unload_model_safely_no_model(self) -> None:
        """Test unload when no model loaded."""
        mock_cfg = MagicMock(openai_model=None, proxy_host="127.0.0.1", proxy_port=8084)
        with (
            patch("airecon.proxy.config.get_config", return_value=mock_cfg),
            patch("urllib.request.urlopen", side_effect=Exception("no server")),
            patch("shutil.which", return_value="/usr/bin/docker"),
        ):
            # Should not raise
            _unload_model_safely()

    def test_unload_model_safely_with_model(self) -> None:
        """Exit banner runs cleanly when a model is configured."""
        mock_cfg = MagicMock(
            openai_model="qwen3.5:122b",
            proxy_host="127.0.0.1",
            proxy_port=8084,
            searxng_url=None,
        )
        with (
            patch("airecon.proxy.config.get_config", return_value=mock_cfg),
            patch("urllib.request.urlopen", side_effect=Exception("no server")),
            patch("shutil.which", return_value="/usr/bin/docker"),
            patch("subprocess.run"),
        ):
            # Remote backend: nothing to unload, banner must not raise.
            _unload_model_safely()


class TestRunListSessions:
    """Test list sessions command."""

    def test_list_sessions_with_sessions(self) -> None:
        """Test listing when sessions exist."""
        mock_sessions = [
            {
                "session_id": "session1",
                "target": "example.com",
                "created_at": "2024-01-01",
                "subdomains": 10,
                "live_hosts": 5,
                "vulnerabilities": 2,
                "scan_count": 3,
            }
        ]

        with patch(
            "airecon.proxy.agent.session.list_sessions", return_value=mock_sessions
        ):
            with patch("builtins.print") as mock_print:
                _run_list_sessions()

                # Should print session info
                assert mock_print.call_count > 0

    def test_list_sessions_no_sessions(self) -> None:
        """Test listing when no sessions exist."""
        with patch("airecon.proxy.agent.session.list_sessions", return_value=[]):
            # Should not raise
            _run_list_sessions()

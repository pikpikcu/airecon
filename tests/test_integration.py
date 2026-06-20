"""Integration tests — real component interactions (minimal mocking)."""

from __future__ import annotations

import time
from unittest.mock import patch



class TestConfigHotReloadIntegration:
    """Test config file hot-reload with real file operations."""

    def test_config_reloads_on_file_change(self, tmp_path):
        """Verify config detects file mtime change and reloads."""
        from airecon.proxy.config import Config

        config_file = tmp_path / "config.yaml"
        config_file.write_text("openai_model: llama3\nllm_context_window: 8192\n")

        cfg1 = Config.load(str(config_file))
        assert cfg1.openai_model == "llama3"

        time.sleep(0.1)
        config_file.write_text("openai_model: mistral\nllm_context_window: 4096\n")

        cfg2 = Config.load(str(config_file))
        assert cfg2.openai_model == "mistral"
        assert cfg2.llm_context_window == 4096

    def test_config_handles_corrupt_yaml(self, tmp_path):
        """Verify config handles corrupt YAML gracefully."""
        from airecon.proxy.config import Config

        config_file = tmp_path / "config.yaml"
        config_file.write_text("{{{{invalid yaml::::")

        cfg = Config.load(str(config_file))
        assert cfg is not None
        assert cfg.openai_model is not None

    def test_config_handles_empty_file(self, tmp_path):
        """Verify config handles empty file gracefully."""
        from airecon.proxy.config import Config

        config_file = tmp_path / "config.yaml"
        config_file.write_text("")

        cfg = Config.load(str(config_file))
        assert cfg is not None


class TestSessionPersistenceIntegration:
    """Test session save/load roundtrip with real filesystem."""

    def test_session_save_load_roundtrip(self, tmp_path):
        """Verify session data survives save/load cycle."""
        from airecon.proxy.agent.session import SessionData, load_session, save_session

        with patch("airecon.proxy.agent.session.SESSIONS_DIR", tmp_path):
            session = SessionData(target="example.com")
            session.subdomains = ["sub1.example.com", "sub2.example.com"]
            session.live_hosts = ["http://example.com"]
            session.open_ports = {"80": "http", "443": "https"}
            session.urls = ["http://example.com/login"]
            session.technologies = {"nginx": "1.18"}
            session.vulnerabilities = [
                {"title": "XSS", "severity": "High", "url": "http://example.com/search"}
            ]
            session.token_total = 15000

            save_session(session)

            loaded = load_session(session.session_id)
            assert loaded is not None
            assert loaded.target == "example.com"
            assert len(loaded.subdomains) == 2
            assert len(loaded.live_hosts) == 1
            assert len(loaded.vulnerabilities) == 1
            assert loaded.token_total == 15000

    def test_session_lists_all_sessions(self, tmp_path):
        """Verify session listing works with multiple sessions."""
        from airecon.proxy.agent.session import SessionData, list_sessions, save_session

        with patch("airecon.proxy.agent.session.SESSIONS_DIR", tmp_path):
            for i in range(3):
                session = SessionData(target=f"target{i}.com")
                session.scan_count = i + 1
                save_session(session)

            sessions = list_sessions()
            assert len(sessions) == 3


class TestFilesystemIntegration:
    """Test filesystem operations with real disk."""

    def test_create_and_read_file_roundtrip(self, tmp_path):
        """Verify file creation and reading works end-to-end."""
        from airecon.proxy.filesystem import create_file, read_file

        workspace = tmp_path / "workspace" / "example.com"
        workspace.mkdir(parents=True)
        (workspace / "output").mkdir()

        result = create_file("output/test.txt", "Hello, World!\nLine 2\nLine 3")
        assert result.get("success") is True

        read_result = read_file("output/test.txt")
        assert "Hello, World!" in (
            read_result.get("content", "") or read_result.get("result", "")
        )
        assert read_result.get("total_lines") == 3

    def test_create_file_writes_to_disk(self, tmp_path):
        """Verify create_file writes content to disk."""
        from airecon.proxy.filesystem import create_file

        workspace = tmp_path / "workspace" / "example.com"
        workspace.mkdir(parents=True)
        (workspace / "output").mkdir()

        with patch(
            "airecon.proxy.filesystem.get_workspace_root", return_value=workspace.parent
        ):
            result = create_file("example.com/output/test.txt", "Hello, World!")
            assert result.get("success") is True

        actual_file = workspace / "output" / "test.txt"
        assert actual_file.exists()
        assert actual_file.read_text() == "Hello, World!"

    def test_path_traversal_blocked(self, tmp_path):
        """Verify path traversal attempts are blocked."""
        from airecon.proxy.filesystem import read_file

        workspace = tmp_path / "workspace" / "example.com"
        workspace.mkdir(parents=True)

        with patch(
            "airecon.proxy.filesystem.get_workspace_root", return_value=workspace.parent
        ):
            result = read_file("../../../etc/passwd")
            assert result.get("success") is False
            err = result.get("error", "").lower()
            assert "traversal" in err or "outside" in err


class TestCorrelationIntegration:
    """Test correlation engine with realistic data."""

    def test_run_correlation_returns_list(self):
        """Test that run_correlation returns a list."""
        from airecon.proxy.agent.session import SessionData
        from airecon.proxy.correlation import run_correlation

        session = SessionData(target="example.com")
        session.subdomains = ["api.example.com"]
        session.live_hosts = ["https://api.example.com"]
        session.open_ports = {"api.example.com": [443]}
        session.technologies = {"nginx": "1.18.0"}
        session.vulnerabilities = []
        session.injection_points = []
        session.urls = ["https://api.example.com/"]
        session.attack_chains = []

        result = run_correlation(session)
        assert isinstance(result, list)


class TestMemoryPersistenceIntegration:
    """Test memory DB with real SQLite."""

    def test_memory_db_persists_across_connections(self, tmp_path):
        """Verify memory DB survives reconnect."""
        from airecon.proxy.memory import get_memory_db

        test_dir = tmp_path / "memory"
        test_dir.mkdir()
        test_db = test_dir / "airecon.db"

        with (
            patch("airecon.proxy.memory.MEMORY_DIR", test_dir),
            patch("airecon.proxy.memory.MEMORY_DB", test_db),
        ):
            # First connection: save data
            conn1 = get_memory_db()
            cursor = conn1.cursor()
            cursor.execute(
                "INSERT INTO sessions (session_id, target, phase) VALUES (?, ?, ?)",
                ("sess_001", "example.com", "RECON"),
            )
            conn1.commit()
            conn1.close()

            # Second connection: read data
            conn2 = get_memory_db()
            cursor = conn2.cursor()
            cursor.execute(
                "SELECT target FROM sessions WHERE session_id = ?", ("sess_001",)
            )
            row = cursor.fetchone()
            assert row is not None
            assert row["target"] == "example.com"
            conn2.close()

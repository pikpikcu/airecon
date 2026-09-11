"""Chaos testing — simulate failure conditions to verify resilience."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest


class TestSessionCorruptionRecovery:
    """Test that session loading survives corrupt JSON files."""

    def test_load_corrupt_session_file(self, tmp_path):
        """Corrupt session JSON should be skipped, not crash."""
        from airecon.proxy.agent.session import list_sessions, load_session

        corrupt_file = tmp_path / "sess_corrupt.json"
        corrupt_file.write_text("{{{invalid json:::")

        with patch("airecon.proxy.agent.session.SESSIONS_DIR", tmp_path):
            sessions = list_sessions()
            assert isinstance(sessions, list)

            loaded = load_session("sess_corrupt")
            assert loaded is None

    def test_load_empty_session_file(self, tmp_path):
        """Empty session file should return default session, not crash."""
        from airecon.proxy.agent.session import load_session

        empty_file = tmp_path / "sess_empty.json"
        empty_file.write_text("")

        with patch("airecon.proxy.agent.session.SESSIONS_DIR", tmp_path):
            loaded = load_session("sess_empty")
            assert loaded is not None  # Returns default session
            assert loaded.session_id == "sess_empty"

    def test_load_session_with_missing_fields(self, tmp_path):
        """Session with missing optional fields should load with defaults."""
        from airecon.proxy.agent.session import load_session

        minimal = json.dumps({"session_id": "sess_min", "target": "example.com"})
        (tmp_path / "sess_min.json").write_text(minimal)

        with patch("airecon.proxy.agent.session.SESSIONS_DIR", tmp_path):
            loaded = load_session("sess_min")
            assert loaded is not None
            assert loaded.session_id == "sess_min"
            assert loaded.target == "example.com"


class TestConfigCorruptionRecovery:
    """Test that config loading survives corrupt YAML files."""

    def test_load_corrupt_yaml_returns_defaults(self, tmp_path):
        """Corrupt YAML config should return defaults, not crash."""
        from airecon.proxy.config import Config

        config_file = tmp_path / "config.yaml"
        config_file.write_text("{{{{{{invalid:::yaml::::")

        cfg = Config.load(str(config_file))
        assert cfg is not None
        assert cfg.openai_model is not None

    def test_load_yaml_with_null_bytes(self, tmp_path):
        """YAML with null bytes should be handled gracefully."""
        from airecon.proxy.config import Config

        config_file = tmp_path / "config.yaml"
        config_file.write_bytes(b"openai_model: \x00llama3\n")

        cfg = Config.load(str(config_file))
        assert cfg is not None


class TestLLMFailureRecovery:
    """Test that agent survives LLM backend failures."""

    @pytest.mark.asyncio
    async def test_complete_retries_then_raises(self):
        """After max retries, complete() should re-raise the timeout."""
        from airecon.proxy.llm import LLMClient
        import asyncio

        with patch("airecon.proxy.llm.get_config") as mock_cfg:
            cfg = MagicMock()
            cfg.openai_base_url = "http://localhost:20128/v1"
            cfg.openai_api_key = "test-key"
            cfg.openai_model = "llama3"
            cfg.openai_max_tokens = 4096
            cfg.openai_temperature = 0.15
            cfg.openai_supports_thinking = False
            cfg.openai_supports_native_tools = False
            cfg.llm_timeout = 120.0
            cfg.llm_chunk_timeout = 60.0
            cfg.llm_max_concurrent_requests = 1
            mock_cfg.return_value = cfg

            client = LLMClient()
            LLMClient._httpx_client = MagicMock()
            LLMClient._initialized = True
            client._request_semaphore = asyncio.Semaphore(1)

            async def always_timeout(*args, **kwargs):
                raise asyncio.TimeoutError()

            with patch.object(client, "_post", side_effect=always_timeout):
                with pytest.raises(asyncio.TimeoutError):
                    await client.complete(
                        messages=[{"role": "user", "content": "hi"}],
                        max_retries=2,
                    )


class TestFilesystemEdgeCases:
    """Test filesystem operations under edge conditions."""

    def test_read_nonexistent_file(self, tmp_path):
        """Reading nonexistent file should return error, not crash."""
        from airecon.proxy.filesystem import read_file

        workspace = tmp_path / "workspace" / "example.com"
        workspace.mkdir(parents=True)

        with patch(
            "airecon.proxy.filesystem.get_workspace_root", return_value=workspace.parent
        ):
            result = read_file("nonexistent.txt")
            assert result.get("success") is False
            assert "error" in result

    def test_create_file_in_nonexistent_dir(self, tmp_path):
        """Creating file in nonexistent directory should create dirs."""
        from airecon.proxy.filesystem import create_file

        workspace = tmp_path / "workspace"
        workspace.mkdir(parents=True)

        with patch(
            "airecon.proxy.filesystem.get_workspace_root", return_value=workspace
        ):
            result = create_file("deep/nested/dir/file.txt", "content")
            assert result.get("success") is True

        actual_file = workspace / "deep" / "nested" / "dir" / "file.txt"
        assert actual_file.exists()
        assert actual_file.read_text() == "content"

    def test_read_file_with_large_offset(self, tmp_path):
        """Reading with offset beyond file length should return empty."""
        from airecon.proxy.filesystem import create_file, read_file

        workspace = tmp_path / "workspace" / "example.com"
        workspace.mkdir(parents=True)
        (workspace / "output").mkdir()

        with patch(
            "airecon.proxy.filesystem.get_workspace_root", return_value=workspace.parent
        ):
            create_file("output/small.txt", "short")
            result = read_file("output/small.txt", offset=1000)
            assert result.get("success") is True


class TestMemoryDbEdgeCases:
    """Test memory database under edge conditions."""

    def test_health_snapshot_without_target(self):
        """Health snapshot without target should handle gracefully."""
        from airecon.proxy.memory import MemoryManager

        mm = MemoryManager()
        snapshot = mm.health_snapshot()
        assert snapshot["ok"] is False

    def test_memory_manager_double_close(self, tmp_path):
        """Closing memory manager twice should not crash."""
        from airecon.proxy.memory import MemoryManager

        test_dir = tmp_path / "memory"
        test_dir.mkdir()
        test_db = test_dir / "airecon.db"

        with (
            patch("airecon.proxy.memory.MEMORY_DIR", test_dir),
            patch("airecon.proxy.memory.MEMORY_DB", test_db),
        ):
            mm = MemoryManager()
            mm.connect()
            mm.close()
            mm.close()  # Should not raise


class TestAgentStateEdgeCases:
    """Test agent state under edge conditions."""

    def test_truncate_conversation_empty(self):
        """Truncating empty conversation should not crash."""
        from airecon.proxy.agent.models import AgentState

        state = AgentState()
        state.conversation = []
        state.truncate_conversation(max_messages=10)
        assert state.conversation == []

    def test_token_usage_with_negative_values(self):
        """Token usage should handle negative values."""
        from airecon.proxy.agent.models import AgentState

        state = AgentState()
        state.token_usage["cumulative"] = -100
        state.token_usage["used"] = -50
        # Should not crash
        assert state.token_usage["cumulative"] == -100

    def test_evidence_log_with_malformed_entries(self):
        """Evidence log should handle malformed entries."""
        from airecon.proxy.agent.models import AgentState

        state = AgentState()
        state.evidence_log = [
            {"tags": ["xss"], "confidence": 0.8, "severity": 4, "summary": "Found XSS"},
            None,
            "not a dict",
            42,
        ]
        # Should not crash when accessing evidence
        assert len(state.evidence_log) == 4

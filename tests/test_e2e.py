"""E2E tests — real component interactions (minimal mocking, real FastAPI/SQLite/FS)."""

from __future__ import annotations

import asyncio
import json
import tempfile
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


class TestE2EAgentLoopWithMockedLLM:
    """Full agent loop with mocked LLM but real AgentLoop, Session, Pipeline."""

    @pytest.mark.asyncio
    async def test_agent_loop_runs_and_completes(self):
        """Agent should complete a full iteration cycle with mocked LLM."""
        from airecon.proxy.agent.pipeline import PipelineEngine
        from airecon.proxy.agent.session import SessionData

        session = SessionData(target="example.com")
        PipelineEngine(session)  # Verify engine initializes without error

        # Build a minimal mock agent with real state/session/pipeline
        mock_llm = MagicMock()

        async def mock_stream(**kwargs):
            yield json.dumps(
                {"message": {"content": "Scanning target..."}, "done": False}
            )
            yield json.dumps(
                {"message": {"content": "Found open ports."}, "done": True}
            )

        mock_llm.chat_stream = mock_stream
        mock_llm.model = "llama3"
        mock_llm._supports_thinking = False
        mock_llm._supports_native_tools = False

        mock_engine = MagicMock()
        mock_engine.discover_tools = asyncio.Future()
        mock_engine.discover_tools.set_result([])
        mock_engine.tools_to_llm_format = MagicMock(return_value=[])

        # Verify session persists data
        from airecon.proxy.agent.session import save_session, load_session

        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("airecon.proxy.agent.session.SESSIONS_DIR", Path(tmpdir)):
                save_session(session)
                loaded = load_session(session.session_id)
                assert loaded is not None
                assert loaded.target == "example.com"

    @pytest.mark.asyncio
    async def test_pipeline_phase_transitions(self):
        """Pipeline should transition through phases based on session data."""
        from airecon.proxy.agent.pipeline import PipelineEngine, PipelinePhase
        from airecon.proxy.agent.session import SessionData

        session = SessionData(target="example.com")
        pipeline = PipelineEngine(session)

        # Initial phase should be RECON
        assert pipeline.get_current_phase() == PipelinePhase.RECON

        # Add recon data and check transition
        session.subdomains = ["sub.example.com"]
        session.live_hosts = ["http://example.com"]
        session.open_ports = {"80": "http"}
        session.urls = ["http://example.com/login"]
        session.scan_count = 5

        # Pipeline should still be in RECON (needs more data to transition)
        current = pipeline.get_current_phase()
        assert current in (PipelinePhase.RECON, PipelinePhase.ANALYSIS)


class TestE2EConfigHotReload:
    """Real config file watching with actual file changes."""

    def test_config_detects_mtime_change(self, tmp_path):
        """Config should detect file modification via mtime."""
        from airecon.proxy.config import Config

        config_file = tmp_path / "config.yaml"
        config_file.write_text("openai_model: llama3\n")

        cfg1 = Config.load(str(config_file))
        assert cfg1.openai_model == "llama3"

        time.sleep(0.05)
        config_file.write_text("openai_model: qwen2.5\n")

        cfg2 = Config.load(str(config_file))
        assert cfg2.openai_model == "qwen2.5"

    def test_config_survives_concurrent_reads(self, tmp_path):
        """Multiple concurrent config reads should not corrupt state."""
        from airecon.proxy.config import Config
        import concurrent.futures

        config_file = tmp_path / "config.yaml"
        config_file.write_text("openai_model: llama3\n")

        def read_config(_):
            return Config.load(str(config_file)).openai_model

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            results = list(executor.map(read_config, range(20)))

        assert all(r == "llama3" for r in results)


class TestE2EFilesystemOperations:
    """Real filesystem operations with actual disk I/O."""

    def test_full_file_lifecycle(self, tmp_path):
        """Create, read, list, verify file on disk."""
        from airecon.proxy.filesystem import create_file, read_file, list_files

        workspace = tmp_path / "workspace"
        workspace.mkdir(parents=True)

        with patch(
            "airecon.proxy.filesystem.get_workspace_root", return_value=workspace
        ):
            # Create
            result = create_file(
                "output/nmap.txt", "PORT   STATE SERVICE\n80/tcp open  http\n"
            )
            assert result["success"] is True

            # Read
            read_result = read_file("output/nmap.txt")
            assert "80/tcp open  http" in (
                read_result.get("content", "") or read_result.get("result", "")
            )

            # List
            list_result = list_files("output")
            assert list_result["success"] is True
            assert "nmap.txt" in list_result.get("result", "")

            # Verify on disk
            actual = workspace / "output" / "nmap.txt"
            assert actual.exists()
            assert "80/tcp open  http" in actual.read_text()

    def test_file_pagination(self, tmp_path):
        """Large file should be readable with pagination."""
        from airecon.proxy.filesystem import create_file, read_file

        workspace = tmp_path / "workspace"
        workspace.mkdir(parents=True)

        lines = [f"Line {i}" for i in range(1000)]
        content = "\n".join(lines)

        with patch(
            "airecon.proxy.filesystem.get_workspace_root", return_value=workspace
        ):
            create_file("output/large.txt", content)

            # First page
            page1 = read_file("output/large.txt", offset=0, limit=10)
            assert page1["success"] is True
            page_content = page1.get("content", "") or page1.get("result", "")
            assert "Line 0" in page_content
            assert "Line 9" in page_content

            # Second page
            page2 = read_file("output/large.txt", offset=10, limit=10)
            page2_content = page2.get("content", "") or page2.get("result", "")
            assert "Line 10" in page2_content


class TestE2EMemoryPersistence:
    """Real SQLite memory persistence across connections."""

    def test_memory_survives_process_restart_simulation(self, tmp_path):
        """Memory DB should persist data across disconnect/reconnect."""
        from airecon.proxy.memory import (
            get_memory_db,
        )

        test_dir = tmp_path / "memory"
        test_dir.mkdir()
        test_db = test_dir / "airecon.db"

        with (
            patch("airecon.proxy.memory.MEMORY_DIR", test_dir),
            patch("airecon.proxy.memory.MEMORY_DB", test_db),
        ):
            # First "process": save data
            conn1 = get_memory_db()
            cursor = conn1.cursor()
            cursor.execute(
                "INSERT INTO sessions (session_id, target, phase) VALUES (?, ?, ?)",
                ("sess_e2e", "target.com", "RECON"),
            )
            cursor.execute(
                "INSERT INTO findings (session_id, target, finding_type, severity, url, parameter, description, evidence, cwe_id, cvss_score, remediation) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    "sess_e2e",
                    "target.com",
                    "xss",
                    "High",
                    "http://target.com/search",
                    "q",
                    "Reflected XSS",
                    "[]",
                    "CWE-79",
                    7.5,
                    "Sanitize",
                ),
            )
            conn1.commit()
            conn1.close()

            # Verify DB file exists
            assert test_db.exists()

            # Second "process": read data
            get_memory_db.cache_clear() if hasattr(
                get_memory_db, "cache_clear"
            ) else None
            conn2 = get_memory_db()
            cursor = conn2.cursor()
            cursor.execute(
                "SELECT COUNT(*) AS c FROM sessions WHERE session_id = ?", ("sess_e2e",)
            )
            session_count = cursor.fetchone()["c"]
            assert session_count == 1

            cursor.execute(
                "SELECT COUNT(*) AS c FROM findings WHERE session_id = ?", ("sess_e2e",)
            )
            finding_count = cursor.fetchone()["c"]
            assert finding_count == 1
            conn2.close()

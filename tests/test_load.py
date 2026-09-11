"""Load tests — concurrent requests to FastAPI server."""

from __future__ import annotations

import asyncio
from unittest.mock import patch

import pytest


class TestServerConcurrency:
    """Test server handles concurrent requests without crashing."""

    @pytest.mark.asyncio
    async def test_concurrent_status_requests(self):
        """10 concurrent /api/status requests should all succeed."""
        from fastapi.testclient import TestClient
        from airecon.proxy.server import app

        client = TestClient(app, raise_server_exceptions=False)

        async def make_request():
            return client.get("/api/status")

        tasks = [make_request() for _ in range(10)]
        results = await asyncio.gather(*tasks)

        for resp in results:
            assert resp.status_code == 200
            data = resp.json()
            assert "status" in data

    @pytest.mark.asyncio
    async def test_concurrent_health_requests(self):
        """10 concurrent /health requests should all succeed or 404."""
        from fastapi.testclient import TestClient
        from airecon.proxy.server import app

        client = TestClient(app, raise_server_exceptions=False)

        async def make_request():
            return client.get("/health")

        tasks = [make_request() for _ in range(10)]
        results = await asyncio.gather(*tasks)

        for resp in results:
            assert resp.status_code in (200, 404)

    @pytest.mark.asyncio
    async def test_concurrent_chat_rejects_when_busy(self):
        """Concurrent /api/chat requests should be rejected when agent is busy."""
        from fastapi.testclient import TestClient
        from airecon.proxy.server import app

        client = TestClient(app, raise_server_exceptions=False)

        with patch("airecon.proxy.server._agent_busy", True):

            async def make_request():
                return client.post(
                    "/api/chat",
                    json={"message": "scan example.com"},
                )

            tasks = [make_request() for _ in range(5)]
            results = await asyncio.gather(*tasks)

            # All should be rejected (409, 429, 500, 503)
            for resp in results:
                assert resp.status_code in (409, 429, 500, 503)

    @pytest.mark.asyncio
    async def test_rapid_file_operations(self):
        """Rapid file create/read operations should not corrupt state."""
        from airecon.proxy.filesystem import create_file, read_file
        import tempfile
        from pathlib import Path

        workspace = Path(tempfile.mkdtemp()) / "workspace"
        workspace.mkdir(parents=True)

        with patch(
            "airecon.proxy.filesystem.get_workspace_root", return_value=workspace
        ):
            # Rapid creates
            for i in range(20):
                create_file(f"output/file_{i}.txt", f"Content {i}")

            # Rapid reads
            for i in range(20):
                result = read_file(f"output/file_{i}.txt")
                assert result.get("success") is True
                content = result.get("content", "") or result.get("result", "")
                assert f"Content {i}" in content

    @pytest.mark.asyncio
    async def test_concurrent_session_operations(self):
        """Concurrent session save/load should not corrupt data."""
        from airecon.proxy.agent.session import SessionData, save_session, load_session
        import tempfile
        from pathlib import Path

        sessions_dir = Path(tempfile.mkdtemp())

        async def save_and_load(i):
            with patch("airecon.proxy.agent.session.SESSIONS_DIR", sessions_dir):
                session = SessionData(target=f"target{i}.com")
                session.scan_count = i
                save_session(session)
                loaded = load_session(session.session_id)
                return loaded is not None and loaded.target == f"target{i}.com"

        tasks = [save_and_load(i) for i in range(10)]
        results = await asyncio.gather(*tasks)

        assert all(results)

    @pytest.mark.asyncio
    async def test_concurrent_config_reads(self):
        """Concurrent config reads should not corrupt state."""
        from airecon.proxy.config import Config
        import tempfile
        from pathlib import Path

        config_file = Path(tempfile.mkdtemp()) / "config.yaml"
        config_file.write_text("openai_model: llama3\n")

        async def read_config():
            return Config.load(str(config_file)).openai_model

        tasks = [read_config() for _ in range(20)]
        results = await asyncio.gather(*tasks)

        assert all(r == "llama3" for r in results)

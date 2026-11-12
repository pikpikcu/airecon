import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest

from airecon.proxy.docker import DockerEngine


@pytest.mark.asyncio
async def test_timeout_keeps_streamed_output_and_only_kills_own_job(monkeypatch):
    engine = DockerEngine()
    engine._connected = True
    engine._container_name = "fixture-container"
    process = MagicMock()
    process.returncode = None
    process.pid = 1234
    process.stdout = asyncio.StreamReader()
    process.stderr = asyncio.StreamReader()
    process.stdout.feed_data(b"partial stdout\n")
    process.stderr.feed_data(b"partial stderr\n")
    killed = asyncio.Event()

    async def wait():
        await killed.wait()
        return process.returncode

    def kill():
        process.returncode = -9
        killed.set()

    process.wait = wait
    process.kill = kill
    cleanup = MagicMock(wait=AsyncMock(return_value=0))
    spawn = AsyncMock(side_effect=[process, cleanup])
    monkeypatch.setattr(asyncio, "create_subprocess_exec", spawn)
    result = await engine.execute("echo fixture", timeout=0.02)
    assert result["exit_code"] == -1
    assert result["stdout"] == "partial stdout\n"
    assert result["stderr"] == "partial stderr\n"
    cleanup_command = spawn.call_args_list[1].args[-1]
    assert "AIRECON_JOB_ID=" in cleanup_command
    assert "pkill" not in cleanup_command
    assert "grep -rlZ" not in cleanup_command

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from airecon.proxy import server


@pytest.fixture
def lifecycle(monkeypatch):
    monkeypatch.delenv("AIRECON_TEST_MODE", raising=False)
    monkeypatch.setattr("airecon.proxy.memory.get_memory_manager", lambda: None)
    monkeypatch.setattr(server, "_USE_CACHE", False)
    monkeypatch.setattr(server, "get_config", lambda: SimpleNamespace(
        proxy_host="127.0.0.1", proxy_port=8000, openai_base_url="http://127.0.0.1/v1",
        openai_model="fixture", docker_image="fixture-image", docker_auto_build=False,
    ))
    llm = SimpleNamespace(_async_init=AsyncMock(), health_check=AsyncMock(return_value=True), close=AsyncMock())
    engine = SimpleNamespace(start_container=AsyncMock(return_value=True), close=AsyncMock())
    agent = SimpleNamespace(initialize=AsyncMock(), stop=AsyncMock())
    monkeypatch.setattr(server, "create_llm_client", lambda: llm)
    monkeypatch.setattr(server, "DockerEngine", lambda: engine)
    monkeypatch.setattr(server, "AgentLoop", lambda **kwargs: agent)
    monkeypatch.setattr(server, "_prewarm_mcp_servers", AsyncMock())
    for name in ("llm_client", "engine", "agent", "_mcp_prewarm_task"):
        monkeypatch.setattr(server, name, None)
    return llm, engine, agent


@pytest.mark.asyncio
async def test_partial_startup_failure_closes_created_resources(lifecycle):
    llm, engine, agent = lifecycle
    engine.start_container.side_effect = RuntimeError("fixture startup failure")
    async with server.lifespan(server.app):
        pass
    llm.close.assert_awaited_once()
    engine.close.assert_awaited_once()
    agent.stop.assert_awaited_once()


@pytest.mark.asyncio
async def test_exception_while_serving_does_not_skip_shutdown(lifecycle):
    llm, engine, agent = lifecycle
    with pytest.raises(RuntimeError, match="fixture serving failure"):
        async with server.lifespan(server.app):
            raise RuntimeError("fixture serving failure")
    llm.close.assert_awaited_once()
    engine.close.assert_awaited_once()
    agent.stop.assert_awaited_once()


@pytest.mark.asyncio
async def test_one_cleanup_failure_does_not_skip_other_resources(lifecycle, caplog):
    llm, engine, agent = lifecycle
    llm.close.side_effect = RuntimeError("fixture cleanup failure")
    async with server.lifespan(server.app):
        pass
    engine.close.assert_awaited_once()
    assert "fixture cleanup failure" in caplog.text


@pytest.mark.asyncio
async def test_cancelled_initialization_closes_resources(lifecycle):
    import asyncio

    llm, engine, agent = lifecycle
    entered = asyncio.Event()

    async def initialize():
        entered.set()
        await asyncio.Future()

    agent.initialize.side_effect = initialize

    async def serve():
        async with server.lifespan(server.app):
            pass

    task = asyncio.create_task(serve())
    await asyncio.wait_for(entered.wait(), timeout=1)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    llm.close.assert_awaited_once()
    engine.close.assert_awaited_once()
    agent.stop.assert_awaited_once()

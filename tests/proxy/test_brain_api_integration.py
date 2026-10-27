"""Local API contracts for imported brain and runtime provenance; no lifespan/network."""
from types import SimpleNamespace
from pathlib import Path
import httpx
import pytest
from airecon.proxy import server
from airecon.proxy.config import DEFAULT_CONFIG


@pytest.fixture
def isolated(monkeypatch):
    cfg = SimpleNamespace(**DEFAULT_CONFIG)
    monkeypatch.setattr(server, "get_config", lambda: cfg)
    for name in ("agent", "llm_client", "engine"):
        monkeypatch.setattr(server, name, None)
    return cfg


async def get(path):
    async with httpx.AsyncClient(transport=httpx.ASGITransport(server.app), base_url="http://fixture") as client:
        return await client.get(path)


@pytest.mark.asyncio
async def test_diagnostics_reports_actual_loaded_source(isolated):
    response = await get("/api/diagnostics")
    assert response.status_code == 200
    runtime = response.json()["runtime"]
    assert Path(runtime["source"]).resolve() == Path(server.__file__).resolve()
    assert runtime["pid"] > 0
    assert runtime["context_budget"] is True


@pytest.mark.asyncio
async def test_brain_uninitialized_returns_503(isolated):
    assert (await get("/api/brain")).status_code == 503


@pytest.mark.asyncio
async def test_brain_renders_real_utility_and_actual_retrieval_mode(isolated, monkeypatch):
    insight = SimpleNamespace(insight_id="a", category="tool_tech", title="fixture", recommendation="fixture advice", conditions={}, confidence=.7, observation_count=5, last_updated=1)
    engine = SimpleNamespace(learned_insights=[insight], _semantic_recall=True, _embedding_model="fixture", _last_recall_mode="lexical")
    engine.get_learning_summary = lambda: {"total_insights": 1}
    engine._utility_map = lambda: {"a": {"recalls": 3, "hits": 3}}
    monkeypatch.setattr(server, "agent", SimpleNamespace(_ensure_adaptive_learning_engine=lambda: engine))
    response = await get("/api/brain")
    assert response.status_code == 200
    data = response.json()
    assert data["retrieval_mode"] == "lexical"
    assert data["insights"][0]["recalls"] == data["insights"][0]["hits"] == 3

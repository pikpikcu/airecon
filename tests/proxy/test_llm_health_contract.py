from types import SimpleNamespace

import httpx
import pytest

from airecon.proxy import llm
from airecon.proxy.config import DEFAULT_CONFIG


@pytest.mark.asyncio
@pytest.mark.parametrize("status,body,expected", [
    (200, {"data": [{"id": "fixture-model"}]}, True),
    (200, {"data": []}, True),
    (200, {"error": "fixture error"}, False),
    (401, {"error": "fixture auth failure"}, False),
    (401, {"data": []}, False),
    (403, {"error": "fixture forbidden"}, False),
    (404, {"error": "fixture missing endpoint"}, False),
    (429, {"error": "fixture quota exceeded"}, False),
    (503, {"error": "fixture unavailable"}, False),
    (503, {"data": []}, False),
])
async def test_health_check_requires_a_successful_models_response(monkeypatch, status, body, expected):
    cfg = SimpleNamespace(**(DEFAULT_CONFIG | {"openai_api_key": "", "openai_model": "fixture-model"}))
    monkeypatch.setattr(llm, "get_config", lambda: cfg)
    transport = httpx.MockTransport(lambda request: httpx.Response(status, json=body))
    async with httpx.AsyncClient(transport=transport) as client:
        monkeypatch.setattr(llm.LLMClient, "_httpx_client", client)
        backend = llm.LLMClient(base_url="http://127.0.0.1/v1", model="fixture-model")
        assert await backend.health_check() is expected


@pytest.mark.asyncio
async def test_health_check_rejects_an_html_proxy_fallback(monkeypatch):
    cfg = SimpleNamespace(**(DEFAULT_CONFIG | {"openai_api_key": "", "openai_model": "fixture-model"}))
    monkeypatch.setattr(llm, "get_config", lambda: cfg)
    transport = httpx.MockTransport(lambda request: httpx.Response(200, text="<html>fixture proxy</html>"))
    async with httpx.AsyncClient(transport=transport) as client:
        monkeypatch.setattr(llm.LLMClient, "_httpx_client", client)
        backend = llm.LLMClient(base_url="http://127.0.0.1/v1", model="fixture-model")
        assert await backend.health_check() is False

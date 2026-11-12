"""Capability negotiation is bounded, cached, and independent of retries."""
import asyncio
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest

from airecon.proxy.config import DEFAULT_CONFIG
from airecon.proxy.llm import LLMBackendHTTPError, LLMClient

MESSAGES = [{"role": "user", "content": "ping"}]
OPTIONS = {"num_ctx": 65536, "num_keep": 512, "repeat_penalty": 1.05}


@pytest.fixture
def backend(monkeypatch):
    cfg = SimpleNamespace(**(DEFAULT_CONFIG | {"openai_model": "negotiation-fixture", "llm_enable_thinking": False}))
    monkeypatch.setattr("airecon.proxy.llm.get_config", lambda: cfg)
    monkeypatch.setattr(LLMClient, "_unsupported_params", {})
    monkeypatch.setattr(LLMClient, "_reasoning_unsupported", set())
    monkeypatch.setattr(LLMClient, "_global_semaphore", asyncio.Semaphore(1))
    monkeypatch.setattr(LLMClient, "_record_model_performance", lambda *args, **kwargs: None)
    sleep = AsyncMock()
    monkeypatch.setattr("airecon.proxy.llm.asyncio.sleep", sleep)
    return sleep


def response(payload):
    if payload["stream"]:
        return httpx.Response(200, text='data: {"choices":[{"delta":{"content":"ok"}}]}\n\ndata: [DONE]\n\n')
    return httpx.Response(200, json={"choices": [{"message": {"content": "ok"}}]})


async def call(client, stream=True, retries=0, tools=None):
    if stream:
        chunks = [c async for c in client._chat_stream_impl(MESSAGES, tools=tools, options=OPTIONS, max_retries=retries)]
        assert chunks[-1]["done"] is True
        return "".join(c["message"].get("content", "") for c in chunks)
    return await client.complete(MESSAGES, max_retries=retries, options=OPTIONS)


@pytest.mark.asyncio
@pytest.mark.parametrize("stream", [True, False])
async def test_negotiation_does_not_consume_retries_and_is_cached(backend, monkeypatch, stream):
    requests = []
    rejected = ["num_ctx", "num_keep", "repeat_penalty", "temperature", "stream_options"]
    def handle(request):
        payload = json.loads(request.content)
        requests.append(payload)
        for key in rejected:
            if key in payload:
                return httpx.Response(400, json={"error": {"message": f"Unsupported parameter: '{key}'"}})
        return response(payload)
    async with httpx.AsyncClient(transport=httpx.MockTransport(handle)) as http:
        monkeypatch.setattr(LLMClient, "_httpx_client", http)
        assert await call(LLMClient(), stream) == "ok"
        count = len(requests)
        assert count == (6 if stream else 5)
        assert await call(LLMClient(), stream) == "ok"
        assert len(requests) == count + 1
        assert not any(k in requests[-1] for k in rejected)
    backend.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("stream", [True, False])
async def test_unsupported_max_tokens_keeps_output_limit(backend, monkeypatch, stream):
    requests = []
    def handle(request):
        payload = json.loads(request.content)
        requests.append(payload)
        if "max_tokens" in payload:
            return httpx.Response(400, json={"error": {"message": "Unsupported parameter: 'max_tokens'. Use 'max_completion_tokens' instead."}})
        assert payload["max_completion_tokens"] == DEFAULT_CONFIG["openai_max_tokens"]
        return response(payload)
    async with httpx.AsyncClient(transport=httpx.MockTransport(handle)) as http:
        monkeypatch.setattr(LLMClient, "_httpx_client", http)
        assert await call(LLMClient(), stream) == "ok"
        assert await call(LLMClient(), stream) == "ok"
    assert len(requests) == 3


@pytest.mark.asyncio
@pytest.mark.parametrize("message", ["Unsupported parameter: 'tools'", "Invalid value for 'temperature': must be positive"])
async def test_required_tools_and_invalid_values_are_not_silently_removed(backend, monkeypatch, message):
    requests = []
    def handle(request):
        requests.append(json.loads(request.content))
        if len(requests) > 3:
            pytest.fail("Unbounded negotiation")
        return httpx.Response(400, json={"error": {"message": message}})
    async with httpx.AsyncClient(transport=httpx.MockTransport(handle)) as http:
        monkeypatch.setattr(LLMClient, "_httpx_client", http)
        with pytest.raises(LLMBackendHTTPError, match="HTTP 400"):
            await call(LLMClient(), tools=[{"type": "function", "function": {"name": "execute"}}])
    assert len(requests) == 1


@pytest.mark.asyncio
async def test_transient_retry_budget_survives_negotiation(backend, monkeypatch):
    requests = []
    def handle(request):
        payload = json.loads(request.content)
        requests.append(payload)
        if "num_ctx" in payload:
            return httpx.Response(400, text="Unsupported parameter: 'num_ctx'")
        if len(requests) == 2:
            return httpx.Response(503, text="temporarily unavailable")
        return response(payload)
    async with httpx.AsyncClient(transport=httpx.MockTransport(handle)) as http:
        monkeypatch.setattr(LLMClient, "_httpx_client", http)
        assert await call(LLMClient(), retries=1) == "ok"
    assert len(requests) == 3
    backend.assert_awaited_once()

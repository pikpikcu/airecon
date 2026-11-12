"""Ollama context truncation must not be retried as a transient HTTP 500."""
from __future__ import annotations

import asyncio
import copy
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest

from airecon.proxy.config import DEFAULT_CONFIG
from airecon.proxy.llm import LLMBackendHTTPError, LLMClient


@pytest.fixture
def backend(monkeypatch):
    cfg = SimpleNamespace(**(DEFAULT_CONFIG | {"openai_model": "context-fixture"}))
    monkeypatch.setattr("airecon.proxy.llm.get_config", lambda: cfg)
    monkeypatch.setattr(LLMClient, "_global_semaphore", asyncio.Semaphore(1))
    monkeypatch.setattr(LLMClient, "_unsupported_params", {})
    monkeypatch.setattr(LLMClient, "_record_model_performance", lambda *a, **kw: None)
    sleep = AsyncMock()
    monkeypatch.setattr("airecon.proxy.llm.asyncio.sleep", sleep)
    return sleep


@pytest.mark.asyncio
@pytest.mark.parametrize("stream", [True, False])
async def test_missing_user_context_error_fails_once_with_actionable_advice(
    backend, monkeypatch, stream
):
    messages = [
        {"role": "system", "content": "Synthetic context fixture."},
        {"role": "user", "content": "Read the fixture."},
        {
            "role": "assistant",
            "content": "",
            "tool_calls": [{
                "id": "call_fixture",
                "function": {"name": "read_fixture", "arguments": {}},
            }],
        },
        {
            "role": "tool",
            "tool_call_id": "call_fixture",
            "content": "Synthetic tool output.",
        },
    ]
    original = copy.deepcopy(messages)
    requests = []

    def handle(request):
        requests.append(json.loads(request.content))
        return httpx.Response(500, json={
            "error": {"message": "no user query found in messages", "type": "api_error"}
        })

    async with httpx.AsyncClient(transport=httpx.MockTransport(handle)) as http:
        monkeypatch.setattr(LLMClient, "_httpx_client", http)
        client = LLMClient()
        with pytest.raises(LLMBackendHTTPError, match="no user query found") as error:
            if stream:
                _ = [chunk async for chunk in client.chat_stream(messages)]
            else:
                await client.complete(messages)

    assert len(requests) == 1
    backend.assert_not_awaited()
    assert messages == original
    assert any(m["role"] == "user" for m in requests[0]["messages"])
    assert "OLLAMA_CONTEXT_LENGTH" in str(error.value)
    assert "llm_context_window" in str(error.value)
    assert "num_ctx" in str(error.value)


@pytest.mark.asyncio
@pytest.mark.parametrize("stream", [True, False])
async def test_unrelated_server_error_still_retries(backend, monkeypatch, stream):
    requests = []

    def handle(request):
        payload = json.loads(request.content)
        requests.append(payload)
        if len(requests) == 1:
            return httpx.Response(500, json={"error": {"message": "temporarily unavailable"}})
        if payload["stream"]:
            return httpx.Response(200, text=(
                'data: {"choices":[{"delta":{"content":"healthy"}}]}\n\n'
                'data: [DONE]\n\n'
            ))
        return httpx.Response(200, json={"choices": [{"message": {"content": "healthy"}}]})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handle)) as http:
        monkeypatch.setattr(LLMClient, "_httpx_client", http)
        client = LLMClient()
        messages = [{"role": "user", "content": "Synthetic probe."}]
        if stream:
            chunks = [chunk async for chunk in client.chat_stream(messages)]
            result = "".join(c["message"].get("content", "") for c in chunks)
        else:
            result = await client.complete(messages)

    assert result == "healthy"
    assert len(requests) == 2
    backend.assert_awaited_once()


@pytest.mark.parametrize("status,message", [
    (400, "maximum context length is 8192 tokens"),
    (400, "context_length_exceeded"),
    (413, "input is too long"),
    (500, "prompt is too long"),
])
def test_context_rejection_is_provider_independent(status, message):
    error = LLMBackendHTTPError(status, message)
    assert error.is_context_error
    assert not error.retryable

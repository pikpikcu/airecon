"""Tests for the OpenAI-compatible LLM client stream parsing.

These guard the regression that caused "Empty response from model after 4
retries": reasoning-only / refusal / content-filtered responses were dropped
because the client only read ``delta.content``.
"""

import asyncio
from unittest.mock import MagicMock, patch

import pytest


def _make_client(monkeypatch_lines):
    from airecon.proxy.llm import LLMClient

    with patch("airecon.proxy.llm.get_config") as mock_cfg:
        cfg = MagicMock()
        cfg.openai_base_url = "http://localhost:20128/v1"
        cfg.openai_api_key = "test-key"
        cfg.openai_model = "claude-sonnet-4"
        cfg.openai_max_tokens = 4096
        cfg.openai_temperature = 0.15
        cfg.openai_supports_thinking = False
        cfg.openai_supports_native_tools = True
        cfg.llm_timeout = 120.0
        cfg.llm_chunk_timeout = 60.0
        cfg.llm_max_concurrent_requests = 1
        mock_cfg.return_value = cfg
        client = LLMClient()

    client._request_semaphore = asyncio.Semaphore(1)

    class _FakeStreamResponse:
        status_code = 200

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def aiter_lines(self):
            for line in monkeypatch_lines:
                yield line

    class _FakeHttpClient:
        def stream(self, *args, **kwargs):
            return _FakeStreamResponse()

    return client, LLMClient, _FakeHttpClient


async def _collect(client, LLMClient, FakeHttpClient):
    with patch("airecon.proxy.llm.get_config") as mock_cfg:
        cfg = MagicMock()
        cfg.openai_max_tokens = 4096
        cfg.llm_timeout = 120.0
        cfg.llm_chunk_timeout = 60.0
        mock_cfg.return_value = cfg
        old = LLMClient._httpx_client
        try:
            LLMClient._httpx_client = FakeHttpClient()
            return [
                chunk
                async for chunk in client.chat_stream(
                    messages=[{"role": "user", "content": "ping"}],
                    max_retries=0,
                    operation="recon",
                )
            ]
        finally:
            LLMClient._httpx_client = old


def test_reasoning_only_stream_yields_thinking():
    """A reasoning-only response must surface as a `thinking` chunk, not empty."""
    lines = [
        'data: {"choices":[{"delta":{"reasoning_content":"let me think"}}]}',
        'data: {"choices":[{"delta":{},"finish_reason":"stop"}]}',
        "data: [DONE]",
    ]
    client, LLMClient, FakeHttpClient = _make_client(lines)
    chunks = asyncio.run(_collect(client, LLMClient, FakeHttpClient))
    thinking = [c for c in chunks if c.get("message", {}).get("thinking")]
    assert thinking, f"expected a thinking chunk, got {chunks!r}"
    assert thinking[0]["message"]["thinking"] == "let me think"


def test_refusal_field_surfaced_as_content():
    lines = [
        'data: {"choices":[{"delta":{"refusal":"I can\'t help with that."}}]}',
        'data: {"choices":[{"delta":{},"finish_reason":"stop"}]}',
        "data: [DONE]",
    ]
    client, LLMClient, FakeHttpClient = _make_client(lines)
    chunks = asyncio.run(_collect(client, LLMClient, FakeHttpClient))
    content = [c for c in chunks if c.get("message", {}).get("content")]
    assert content, f"expected refusal surfaced as content, got {chunks!r}"
    assert "can't help" in content[0]["message"]["content"]


def test_content_filter_empty_raises_clear_error():
    lines = [
        'data: {"choices":[{"delta":{},"finish_reason":"content_filter"}]}',
        "data: [DONE]",
    ]
    client, LLMClient, FakeHttpClient = _make_client(lines)
    with pytest.raises(RuntimeError) as exc:
        asyncio.run(_collect(client, LLMClient, FakeHttpClient))
    assert "content_filter" in str(exc.value)
    assert "safety block" in str(exc.value)


def test_normal_content_still_works():
    lines = [
        'data: {"choices":[{"delta":{"content":"hello"}}]}',
        'data: {"choices":[{"delta":{},"finish_reason":"stop"}]}',
        "data: [DONE]",
    ]
    client, LLMClient, FakeHttpClient = _make_client(lines)
    chunks = asyncio.run(_collect(client, LLMClient, FakeHttpClient))
    content = [c for c in chunks if c.get("message", {}).get("content")]
    assert content and content[0]["message"]["content"] == "hello"

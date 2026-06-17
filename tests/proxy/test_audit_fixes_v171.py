"""Regression tests for the v1.7.1-beta code-audit fixes.

Covers findings confirmed against the source during the laporan.md review:
- F-006: LLMClient.close() must reset shared class state so re-init rebuilds.
- F-007: transient HTTP 5xx from the backend must be retried; 4xx must not.
- F-009: numeric bounds must reference the real `model_max_tool_result_chars`
  field key (previously a typo left it unvalidated).
- F-011: fast conversation compression must repair severed tool-call pairs.
- F-001: DockerEngine must expose a `close()` lifecycle method.
"""

from __future__ import annotations

import asyncio
from unittest.mock import MagicMock, patch

import pytest


def _make_client():
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
    return client, LLMClient


# ── F-006: close() resets shared state ────────────────────────────────────────

@pytest.mark.asyncio
async def test_close_resets_shared_state():
    from airecon.proxy.llm import LLMClient

    client, _ = _make_client()

    closed = {"n": 0}

    class _FakeClient:
        async def aclose(self):
            closed["n"] += 1

    LLMClient._httpx_client = _FakeClient()
    LLMClient._initialized = True

    await client.close()

    assert closed["n"] == 1
    assert LLMClient._httpx_client is None
    assert LLMClient._initialized is False


# ── F-007: 5xx retried, 4xx not ───────────────────────────────────────────────

class _FakeResp:
    def __init__(self, status_code, payload=None, text=""):
        self.status_code = status_code
        self._payload = payload or {}
        self.text = text

    def json(self):
        return self._payload


def _ok_payload():
    return {"choices": [{"message": {"content": "pong"}}]}


@pytest.mark.asyncio
async def test_complete_retries_on_5xx():
    from airecon.proxy.llm import LLMClient

    client, _ = _make_client()
    calls = {"n": 0}

    async def fake_request(method, url, **kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            return _FakeResp(503, text="upstream unavailable")
        return _FakeResp(200, _ok_payload())

    fake_http = MagicMock()
    fake_http.request = fake_request
    LLMClient._httpx_client = fake_http

    with patch.object(client, "_get_dynamic_timeout", return_value=5.0), \
         patch("airecon.proxy.llm.asyncio.sleep", new=_noop_sleep):
        out = await client._complete_impl(
            [{"role": "user", "content": "ping"}],
            max_retries=2,
            options=None,
            operation="recon",
        )

    assert out == "pong"
    assert calls["n"] == 2  # first 503 retried, second 200 succeeded


@pytest.mark.asyncio
async def test_complete_does_not_retry_on_4xx():
    from airecon.proxy.llm import LLMBackendHTTPError, LLMClient

    client, _ = _make_client()
    calls = {"n": 0}

    async def fake_request(method, url, **kwargs):
        calls["n"] += 1
        return _FakeResp(400, text="bad model")

    fake_http = MagicMock()
    fake_http.request = fake_request
    LLMClient._httpx_client = fake_http

    with patch.object(client, "_get_dynamic_timeout", return_value=5.0), \
         patch("airecon.proxy.llm.asyncio.sleep", new=_noop_sleep):
        with pytest.raises(LLMBackendHTTPError) as ei:
            await client._complete_impl(
                [{"role": "user", "content": "ping"}],
                max_retries=3,
                options=None,
                operation="recon",
            )

    assert ei.value.status_code == 400
    assert calls["n"] == 1  # 4xx is non-retryable -> exactly one attempt


async def _noop_sleep(*_a, **_k):
    return None


# ── F-009: bounds key fixed ───────────────────────────────────────────────────

def test_model_max_tool_result_chars_has_bounds():
    import airecon.proxy.config as cfg_mod

    src = (cfg_mod.__file__)
    with open(src, encoding="utf-8") as f:
        text = f.read()
    # The corrected bounds key must be present; the typo'd one must be gone.
    assert '"model_max_tool_result_chars": (5000, 200000)' in text
    assert '"model_tool_result_chars": (5000, 200000)' not in text


# ── F-011: fast compression repairs tool pairs ────────────────────────────────

def test_repair_tool_pairs_drops_orphan_tool_results():
    from airecon.proxy.agent.models import AgentState

    # A tool result whose assistant tool_call was sliced away (orphan).
    convo = [
        {"role": "system", "content": "sys"},
        {"role": "user", "content": "u"},
        {"role": "tool", "tool_call_id": "abc", "content": "orphan result"},
        {"role": "assistant", "content": "done"},
    ]
    repaired = AgentState._repair_tool_pairs(convo)
    # No tool message may remain without a preceding assistant tool_call.
    for i, m in enumerate(repaired):
        if m.get("role") == "tool":
            prior_calls = any(
                p.get("role") == "assistant" and p.get("tool_calls")
                for p in repaired[:i]
            )
            assert prior_calls, "orphan tool result survived repair"


# ── F-001: DockerEngine.close exists ──────────────────────────────────────────

def test_docker_engine_has_close():
    from airecon.proxy.docker import DockerEngine

    assert hasattr(DockerEngine, "close")
    assert asyncio.iscoroutinefunction(DockerEngine.close)

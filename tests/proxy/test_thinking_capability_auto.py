"""Tests for automatic (non-hardcoded) reasoning-capability handling.

There is NO model-name list anywhere. The client uses the OpenAI-standard
`reasoning_effort` parameter in `auto` mode and detects, at runtime, when a
backend rejects it (HTTP 400 "unsupported parameter") — then strips the param,
remembers the model, and retries. These tests prove that behavior.
"""

from __future__ import annotations

import asyncio
from unittest.mock import MagicMock, patch

import pytest

from airecon.proxy.llm import LLMClient


def _make_client(model="any-model-xyz", request_mode="auto", enable=True):
    with patch("airecon.proxy.llm.get_config") as mock_cfg:
        cfg = MagicMock()
        cfg.openai_base_url = "http://localhost:20128/v1"
        cfg.openai_api_key = "k"
        cfg.openai_model = model
        cfg.openai_max_tokens = 4096
        cfg.openai_temperature = 0.15
        cfg.openai_supports_thinking = False
        cfg.openai_supports_native_tools = True
        cfg.llm_timeout = 120.0
        cfg.llm_chunk_timeout = 60.0
        cfg.llm_max_concurrent_requests = 1
        cfg.llm_enable_thinking = enable
        cfg.llm_thinking_mode = "low"
        cfg.llm_thinking_request_mode = request_mode
        mock_cfg.return_value = cfg
        c = LLMClient()
    c._request_semaphore = asyncio.Semaphore(1)
    return c


# ── No model-name guessing: auto always resolves to the standard param ────────

def test_no_name_list_auto_resolves_reasoning_effort():
    R = LLMClient._resolve_thinking_strategy
    # Wildly different model names ALL resolve the same in auto — no per-name list.
    for name in ["gpt-4o", "claude-sonnet-4-6", "qwen3-30b", "totally-new-model-2027"]:
        assert R(name, "auto") == "reasoning_effort"


def test_explicit_mode_is_honored():
    R = LLMClient._resolve_thinking_strategy
    assert R("anything", "off") == "off"
    assert R("anything", "enable_thinking") == "enable_thinking"
    assert R("anything", "reasoning_effort") == "reasoning_effort"


# ── Runtime detection of the 400 "unsupported parameter" error ────────────────

@pytest.mark.parametrize(
    "body,expected",
    [
        ("Unsupported parameter: 'reasoning_effort'", True),
        ("'reasoning.effort' is not supported with this model.", True),
        ("Unrecognized request argument supplied: reasoning_effort", True),
        ("rate limit exceeded", False),          # unrelated 400
        ("invalid api key", False),               # no reasoning mention
        ("temperature must be <= 2", False),      # different param
    ],
)
def test_unsupported_reasoning_error_detection(body, expected):
    assert LLMClient._is_unsupported_reasoning_error(400, body) is expected


def test_non_400_is_never_reasoning_error():
    assert LLMClient._is_unsupported_reasoning_error(500, "reasoning_effort unsupported") is False


def test_maybe_degrade_strips_params_and_remembers_model():
    LLMClient._reasoning_unsupported.discard("model-A")
    c = _make_client(model="model-A")
    payload = {"model": "model-A", "reasoning_effort": "medium"}
    degraded = c._maybe_degrade_reasoning(
        payload, 400, "Unsupported parameter: 'reasoning_effort'"
    )
    assert degraded is True
    assert "reasoning_effort" not in payload
    assert "model-A" in LLMClient._reasoning_unsupported
    LLMClient._reasoning_unsupported.discard("model-A")


def test_maybe_degrade_noop_on_unrelated_error():
    c = _make_client(model="model-B")
    payload = {"model": "model-B", "reasoning_effort": "medium"}
    assert c._maybe_degrade_reasoning(payload, 400, "invalid api key") is False
    assert "reasoning_effort" in payload  # untouched


def test_apply_thinking_skips_known_unsupported_model():
    LLMClient._reasoning_unsupported.add("model-C")
    try:
        c = _make_client(model="model-C", request_mode="reasoning_effort")
        payload: dict = {}
        c._apply_thinking(payload, think=True)
        assert "reasoning_effort" not in payload  # not re-sent after probe
    finally:
        LLMClient._reasoning_unsupported.discard("model-C")


def test_apply_thinking_sends_param_for_unprobed_model():
    LLMClient._reasoning_unsupported.discard("model-D")
    c = _make_client(model="model-D", request_mode="reasoning_effort")
    payload: dict = {}
    c._apply_thinking(payload, think=True)
    assert payload.get("reasoning_effort") in ("low", "medium", "high")


# ── End-to-end: stream gets a 400, degrades, retries, succeeds ────────────────

class _FakeResp:
    def __init__(self, status_code, lines=None, text=""):
        self.status_code = status_code
        self._lines = lines or []
        self.text = text

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def aread(self):
        return self.text.encode()

    async def aiter_lines(self):
        for ln in self._lines:
            yield ln


@pytest.mark.asyncio
async def test_stream_degrades_on_400_then_succeeds(monkeypatch):
    LLMClient._reasoning_unsupported.discard("probe-model")
    c = _make_client(model="probe-model", request_mode="reasoning_effort")

    seen_payloads = []
    calls = {"n": 0}

    def fake_stream(method, url, json=None, headers=None, timeout=None):
        calls["n"] += 1
        seen_payloads.append(dict(json or {}))
        if calls["n"] == 1:
            # First attempt carries reasoning_effort -> backend rejects it.
            return _FakeResp(400, text="Unsupported parameter: 'reasoning_effort'")
        # Retry (reasoning stripped) -> stream a normal completion.
        return _FakeResp(
            200,
            lines=[
                'data: {"choices":[{"delta":{"content":"pong"}}]}',
                "data: [DONE]",
            ],
        )

    fake_http = MagicMock()
    fake_http.stream = fake_stream

    with patch("airecon.proxy.llm.get_config") as mock_cfg:
        cfg = MagicMock()
        cfg.openai_max_tokens = 4096
        cfg.llm_timeout = 120.0
        cfg.llm_chunk_timeout = 60.0
        mock_cfg.return_value = cfg
        old = LLMClient._httpx_client
        LLMClient._httpx_client = fake_http
        try:
            chunks = [
                ch
                async for ch in c.chat_stream(
                    messages=[{"role": "user", "content": "ping"}],
                    think=True,
                    max_retries=2,
                    operation="chat",
                )
            ]
        finally:
            LLMClient._httpx_client = old

    # First attempt sent reasoning_effort; retry omitted it.
    assert "reasoning_effort" in seen_payloads[0]
    assert "reasoning_effort" not in seen_payloads[1]
    assert "probe-model" in LLMClient._reasoning_unsupported
    text = "".join(
        (ch.get("message", {}) or {}).get("content", "")
        for ch in chunks
        if isinstance(ch, dict)
    )
    assert "pong" in text
    LLMClient._reasoning_unsupported.discard("probe-model")

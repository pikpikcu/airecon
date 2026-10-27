"""FR1 hardening for the integrated Anthropic protocol (PR #129 + local guards).

All traffic uses httpx.MockTransport with synthetic fixtures; no network.
"""
from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace

import httpx
import pytest

from airecon.proxy.config import DEFAULT_CONFIG
from airecon.proxy.llm import LLMBackendHTTPError, LLMClient, LLMToolCallError
from airecon.proxy.llm_protocol import anthropic_messages

TOOLS = [
    {"type": "function", "function": {"name": "fixture_status", "parameters": {"type": "object", "properties": {}}}},
    {"type": "function", "function": {"name": "fixture_read", "parameters": {
        "type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}}},
]


def _cfg(monkeypatch, **extra):
    cfg = SimpleNamespace(**(DEFAULT_CONFIG | {
        "llm_provider": "anthropic", "openai_model": "fixture", "openai_api_key": "fixture-key",
        "llm_enable_thinking": True, "openai_supports_native_tools": True,
        "openai_max_tokens": 4096,
    } | extra))
    monkeypatch.setattr("airecon.proxy.llm.get_config", lambda: cfg)
    monkeypatch.setattr(LLMClient, "_global_semaphore", asyncio.Semaphore(1))
    monkeypatch.setattr(LLMClient, "_record_model_performance", lambda *a, **kw: None)
    monkeypatch.setattr(LLMClient, "_reasoning_unsupported", set())
    monkeypatch.setattr(LLMClient, "_unsupported_params", {})

    async def no_sleep(*_a, **_kw):
        return None
    monkeypatch.setattr("airecon.proxy.llm.asyncio.sleep", no_sleep)
    return cfg


@pytest.fixture
def cfg(monkeypatch):
    return _cfg(monkeypatch)


def sse(events):
    return "".join("data: " + json.dumps(e) + "\n\n" for e in events)


START = {"type": "message_start", "message": {"usage": {"input_tokens": 10}}}
STOP = {"type": "message_stop"}


def tool_start(index, cid, name):
    return {"type": "content_block_start", "index": index,
            "content_block": {"type": "tool_use", "id": cid, "name": name, "input": {}}}


def json_delta(index, text):
    return {"type": "content_block_delta", "index": index,
            "delta": {"type": "input_json_delta", "partial_json": text}}


def text_block(index, text):
    return [{"type": "content_block_start", "index": index, "content_block": {"type": "text", "text": ""}},
            {"type": "content_block_delta", "index": index, "delta": {"type": "text_delta", "text": text}}]


def stop_reason(reason, out=3):
    return {"type": "message_delta", "delta": {"stop_reason": reason}, "usage": {"output_tokens": out}}


async def run_stream(monkeypatch, handler, messages=None, **kw):
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        monkeypatch.setattr(LLMClient, "_httpx_client", http)
        chunks = []
        agen = LLMClient().chat_stream(messages or [{"role": "user", "content": "fixture"}], **kw)
        try:
            async for chunk in agen:
                chunks.append(chunk)
        except BaseException as exc:  # surface with chunks collected so far
            exc.chunks = chunks
            raise
        return chunks


def counting(body_fn):
    calls = []

    def handle(req):
        calls.append(json.loads(req.content))
        return httpx.Response(200, text=body_fn(len(calls)))
    return calls, handle


# ── history replay ───────────────────────────────────────────────────────────

def test_history_empty_string_arguments_replay_as_empty_object():
    _, wire = anthropic_messages([
        {"role": "user", "content": "fixture"},
        {"role": "assistant", "content": "", "tool_calls": [
            {"id": "call_a", "function": {"name": "fixture_status", "arguments": ""}}]},
        {"role": "tool", "tool_call_id": "call_a", "content": "ok"},
    ])
    assert wire[1]["content"] == [{"type": "tool_use", "id": "call_a", "name": "fixture_status", "input": {}}]


def test_history_malformed_arguments_stay_explicit_error():
    with pytest.raises(ValueError):
        anthropic_messages([{"role": "assistant", "content": "", "tool_calls": [
            {"id": "call_a", "function": {"name": "fixture_status", "arguments": "{\"a\":"}}]}])


def test_signed_blocks_replayed_in_exact_order_with_narration():
    blocks = [{"type": "thinking", "thinking": "t", "signature": "sig"},
              {"type": "text", "text": "narration"},
              {"type": "tool_use", "id": "call_a", "name": "fixture_status", "input": {}},
              {"type": "tool_use", "id": "call_b", "name": "fixture_read", "input": {"path": "x"}}]
    _, wire = anthropic_messages([
        {"role": "user", "content": "fixture"},
        {"role": "assistant", "content": "narration", "_provider_blocks": blocks},
        {"role": "tool", "tool_call_id": "call_a", "content": "a"},
        {"role": "tool", "tool_call_id": "call_b", "content": "b"},
    ])
    assert wire[1]["content"] == blocks
    assert [b["tool_use_id"] for b in wire[2]["content"]] == ["call_a", "call_b"]


# ── streaming: tool batches ─────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_multiple_indexed_tool_calls_including_no_arg(cfg, monkeypatch):
    events = [START, *text_block(0, "narration"),
              tool_start(1, "call_a", "fixture_status"),
              tool_start(2, "call_b", "fixture_read"), json_delta(2, '{"pa'), json_delta(2, 'th": "x"}'),
              stop_reason("tool_use"), STOP]
    calls, handle = counting(lambda _n: sse(events))
    chunks = await run_stream(monkeypatch, handle, tools=TOOLS, max_retries=0)
    final = chunks[-1]
    assert final["done"] is True
    tcs = final["message"]["tool_calls"]
    assert [(t["id"], t["function"]["name"], t["function"]["arguments"]) for t in tcs] == [
        ("call_a", "fixture_status", {}), ("call_b", "fixture_read", {"path": "x"})]
    assert [b["type"] for b in final["message"]["_provider_blocks"]] == ["text", "tool_use", "tool_use"]
    assert final["message"]["_provider_blocks"][2]["input"] == {"path": "x"}
    assert calls[0]["tools"][0]["name"] == "fixture_status"


@pytest.mark.asyncio
async def test_no_tools_plain_answer_is_safe(cfg, monkeypatch):
    calls, handle = counting(lambda _n: sse([START, *text_block(0, "hi"), stop_reason("end_turn"), STOP]))
    chunks = await run_stream(monkeypatch, handle, max_retries=0)
    assert "tools" not in calls[0]
    assert chunks[-1]["done"] and "tool_calls" not in chunks[-1]["message"]


@pytest.mark.asyncio
async def test_invalid_partial_tool_json_never_becomes_empty_object(cfg, monkeypatch):
    events = [START, tool_start(0, "call_b", "fixture_read"), json_delta(0, '{"path": '),
              stop_reason("tool_use"), STOP]
    _, handle = counting(lambda _n: sse(events))
    with pytest.raises(LLMToolCallError) as info:
        await run_stream(monkeypatch, handle, tools=TOOLS, max_retries=0)
    assert not any(c.get("done") for c in info.value.chunks)


@pytest.mark.asyncio
async def test_truncated_stream_without_message_stop_fails(cfg, monkeypatch):
    events = [START, tool_start(0, "call_a", "fixture_status"), stop_reason("tool_use")]
    _, handle = counting(lambda _n: sse(events))
    with pytest.raises(RuntimeError) as info:
        await run_stream(monkeypatch, handle, tools=TOOLS, max_retries=0)
    assert not any(c.get("done") for c in info.value.chunks)


@pytest.mark.asyncio
async def test_max_tokens_truncated_tool_batch_fails(cfg, monkeypatch):
    events = [START, tool_start(0, "call_a", "fixture_status"), stop_reason("max_tokens"), STOP]
    _, handle = counting(lambda _n: sse(events))
    with pytest.raises(LLMToolCallError):
        await run_stream(monkeypatch, handle, tools=TOOLS, max_retries=0)


@pytest.mark.asyncio
async def test_operator_stop_mid_stream_yields_no_executable_batch(cfg, monkeypatch):
    events = [START, tool_start(0, "call_a", "fixture_status"), stop_reason("tool_use"), STOP]
    _, handle = counting(lambda _n: sse(events))
    polls = {"n": 0}

    def stop():
        polls["n"] += 1
        return polls["n"] > 3
    chunks = await run_stream(monkeypatch, handle, tools=TOOLS, max_retries=0, stop_requested_fn=stop)
    assert not any(c.get("done") for c in chunks)


# ── streaming: in-band errors and retry ownership ───────────────────────────

@pytest.mark.asyncio
async def test_in_band_invalid_request_is_not_retried(cfg, monkeypatch):
    err = {"type": "error", "error": {"type": "invalid_request_error", "message": "fixture bad"}}
    calls, handle = counting(lambda _n: sse([START, err]))
    with pytest.raises(LLMBackendHTTPError) as info:
        await run_stream(monkeypatch, handle, max_retries=2)
    assert info.value.status_code == 400 and not info.value.retryable
    assert len(calls) == 1


@pytest.mark.asyncio
async def test_in_band_overloaded_before_output_is_retried_boundedly(cfg, monkeypatch):
    err = {"type": "error", "error": {"type": "overloaded_error", "message": "fixture overloaded"}}
    calls, handle = counting(lambda n: sse([START, err]) if n == 1 else sse(
        [START, *text_block(0, "ok"), stop_reason("end_turn"), STOP]))
    chunks = await run_stream(monkeypatch, handle, max_retries=2)
    assert len(calls) == 2 and chunks[-1]["done"]


@pytest.mark.asyncio
async def test_partial_in_band_error_after_output_is_not_replayed(cfg, monkeypatch):
    err = {"type": "error", "error": {"type": "overloaded_error", "message": "fixture overloaded"}}
    events = [START, *text_block(0, "partial"), tool_start(1, "call_a", "fixture_status"), err]
    calls, handle = counting(lambda _n: sse(events))
    with pytest.raises(LLMBackendHTTPError) as info:
        await run_stream(monkeypatch, handle, tools=TOOLS, max_retries=3)
    assert len(calls) == 1
    assert not any(c.get("done") for c in info.value.chunks)
    assert sum(1 for c in info.value.chunks if c["message"].get("content") == "partial") == 1


@pytest.mark.asyncio
async def test_refusal_is_not_an_empty_success(cfg, monkeypatch):
    _, handle = counting(lambda _n: sse([START, stop_reason("refusal"), STOP]))
    with pytest.raises(RuntimeError, match="content_filter"):
        await run_stream(monkeypatch, handle, max_retries=0)


@pytest.mark.asyncio
async def test_usage_includes_cache_tokens_and_message_delta(cfg, monkeypatch):
    start = {"type": "message_start", "message": {"usage": {
        "input_tokens": 5, "cache_read_input_tokens": 1000, "cache_creation_input_tokens": 20, "output_tokens": 1}}}
    _, handle = counting(lambda _n: sse([start, *text_block(0, "x"), stop_reason("end_turn", out=42), STOP]))
    final = (await run_stream(monkeypatch, handle, max_retries=0))[-1]
    assert final["prompt_eval_count"] == 1025
    assert final["eval_count"] == 42


# ── thinking ─────────────────────────────────────────────────────────────────

def _open_turn(first_block):
    blocks = ([first_block] if first_block else []) + [
        {"type": "tool_use", "id": "call_a", "name": "fixture_status", "input": {}}]
    return [{"role": "user", "content": "fixture"},
            {"role": "assistant", "content": "", "_provider_blocks": blocks,
             "tool_calls": [{"id": "call_a", "function": {"name": "fixture_status", "arguments": {}}}]},
            {"role": "tool", "tool_call_id": "call_a", "content": "ok"}]


@pytest.mark.asyncio
@pytest.mark.parametrize("first,think,expected", [
    ({"type": "thinking", "thinking": "t", "signature": "s"}, False, True),
    ({"type": "redacted_thinking", "data": "opaque"}, False, True),
    (None, True, False),
])
async def test_thinking_mode_is_pinned_inside_open_tool_turn(cfg, monkeypatch, first, think, expected):
    calls, handle = counting(lambda _n: sse([START, *text_block(0, "x"), stop_reason("end_turn"), STOP]))
    await run_stream(monkeypatch, handle, messages=_open_turn(first), tools=TOOLS, think=think, max_retries=0)
    assert ("thinking" in calls[0]) is expected


def test_thinking_budget_below_max_tokens_and_drops_temperature(monkeypatch):
    _cfg(monkeypatch, llm_thinking_mode="high", openai_temperature=0.3)
    c = LLMClient()
    payload = {}
    c._apply_options(payload, {"num_predict": 2000})
    c._apply_thinking(payload, True)
    assert payload["thinking"] == {"type": "enabled", "budget_tokens": 1999}
    assert payload["max_tokens"] == 2000 and "temperature" not in payload


def test_anthropic_never_renames_max_tokens(cfg):
    c = LLMClient()
    payload = {"max_tokens": 100, "temperature": 0.1}
    assert c._maybe_degrade_unsupported_param(payload, 400, "unsupported parameter 'max_tokens'") is False
    assert payload["max_tokens"] == 100


# ── auth: explicit, not heuristic ───────────────────────────────────────────

def test_anthropic_default_auth_is_x_api_key_only(cfg):
    h = LLMClient()._auth_headers()
    assert h["x-api-key"] == "fixture-key" and "Authorization" not in h
    assert h["anthropic-version"] == "2023-06-01"


@pytest.mark.parametrize("mode,has_x,has_bearer", [("bearer", False, True), ("both", True, True)])
def test_anthropic_explicit_auth_modes(monkeypatch, mode, has_x, has_bearer):
    _cfg(monkeypatch, llm_anthropic_auth=mode)
    h = LLMClient()._auth_headers()
    assert ("x-api-key" in h) is has_x and ("Authorization" in h) is has_bearer


def test_anthropic_invalid_auth_mode_rejected(monkeypatch):
    _cfg(monkeypatch, llm_anthropic_auth="guess")
    with pytest.raises(ValueError):
        LLMClient()


def test_openai_auth_unchanged(monkeypatch):
    _cfg(monkeypatch, llm_provider="openai")
    h = LLMClient()._auth_headers()
    assert h["Authorization"] == "Bearer fixture-key" and "x-api-key" not in h


# ── non-stream ───────────────────────────────────────────────────────────────

async def _complete(monkeypatch, body, max_retries=2):
    calls = []

    def handle(req):
        calls.append(req.url.path)
        return httpx.Response(200, json=body)
    async with httpx.AsyncClient(transport=httpx.MockTransport(handle)) as http:
        monkeypatch.setattr(LLMClient, "_httpx_client", http)
        try:
            return await LLMClient().complete([{"role": "user", "content": "fixture"}], max_retries=max_retries), calls
        except BaseException as exc:
            exc.calls = calls
            raise


@pytest.mark.asyncio
async def test_nonstream_thinking_only_is_legal_empty(cfg, monkeypatch):
    text, calls = await _complete(monkeypatch, {"type": "message", "content": [
        {"type": "thinking", "thinking": "t", "signature": "s"}], "stop_reason": "end_turn"})
    assert text == "" and calls == ["/v1/messages"]


@pytest.mark.asyncio
async def test_nonstream_in_band_error_raises_typed(cfg, monkeypatch):
    with pytest.raises(LLMBackendHTTPError) as info:
        await _complete(monkeypatch, {"type": "error", "error": {"type": "authentication_error", "message": "fixture"}})
    assert info.value.status_code == 401 and len(info.value.calls) == 1


# ── OpenAI path keeps the same guards ───────────────────────────────────────

@pytest.mark.asyncio
async def test_openai_invalid_json_event_is_not_skipped(monkeypatch):
    _cfg(monkeypatch, llm_provider="openai")
    body = ('data: {"choices":[{"delta":{"tool_calls":[{"index":0,"id":"c","function":{"name":"fixture_read","arguments":"{\\"path\\":"}}]}}]}\n\n'
            'data: {not json\n\n'
            'data: {"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"arguments":"\\"x\\"}"}}]},"finish_reason":"tool_calls"}]}\n\n'
            'data: [DONE]\n\n')
    with pytest.raises(RuntimeError, match="invalid JSON") as info:
        await run_stream(monkeypatch, lambda req: httpx.Response(200, text=body), tools=TOOLS, max_retries=0)
    assert not any(c.get("done") for c in info.value.chunks)


@pytest.mark.asyncio
async def test_openai_tool_stream_without_finish_reason_is_truncated(monkeypatch):
    _cfg(monkeypatch, llm_provider="openai")
    body = 'data: {"choices":[{"delta":{"tool_calls":[{"index":0,"id":"c","function":{"name":"fixture_status","arguments":"{}"}}]}}]}\n\n'
    with pytest.raises(LLMToolCallError):
        await run_stream(monkeypatch, lambda req: httpx.Response(200, text=body), tools=TOOLS, max_retries=0)


# ── retry ownership: parent passes max_retries=0 ────────────────────────────

@pytest.mark.asyncio
@pytest.mark.parametrize("body,stripped", [
    ('{"type":"error","error":{"type":"invalid_request_error","message":"thinking: unsupported for this model"}}', "thinking"),
    ('{"type":"error","error":{"type":"invalid_request_error","message":"temperature: unsupported parameter"}}', "temperature"),
])
async def test_option_negotiation_survives_max_retries_zero(monkeypatch, body, stripped):
    _cfg(monkeypatch, openai_temperature=0.2)
    calls = []

    def handle(req):
        calls.append(json.loads(req.content))
        if len(calls) == 1:
            return httpx.Response(400, text=body)
        return httpx.Response(200, text=sse([START, *text_block(0, "ok"), stop_reason("end_turn"), STOP]))
    think = stripped == "thinking"
    chunks = await run_stream(monkeypatch, handle, think=think, max_retries=0)
    assert chunks[-1]["done"] and len(calls) == 2
    assert stripped in calls[0] and stripped not in calls[1]


@pytest.mark.asyncio
async def test_transient_error_not_retried_in_client_when_max_retries_zero(cfg, monkeypatch):
    err = {"type": "error", "error": {"type": "overloaded_error", "message": "fixture overloaded"}}
    calls, handle = counting(lambda _n: sse([START, err]))
    with pytest.raises(LLMBackendHTTPError) as info:
        await run_stream(monkeypatch, handle, max_retries=0)
    assert len(calls) == 1 and info.value.retryable and info.value.status_code == 529


# ── embeddings ───────────────────────────────────────────────────────────────

async def _embed(monkeypatch, data, n=2, **extra):
    _cfg(monkeypatch, llm_provider="openai", embedding_model="fixture-embed", **extra)

    def handle(req):
        assert req.url.path.endswith("/embeddings")
        return httpx.Response(200, json={"data": data})
    async with httpx.AsyncClient(transport=httpx.MockTransport(handle)) as http:
        monkeypatch.setattr(LLMClient, "_httpx_client", http)
        monkeypatch.setattr(LLMClient, "_initialized", True)
        return await LLMClient().embed(["a", "b"][:n])


@pytest.mark.asyncio
async def test_embeddings_reordered_by_index(monkeypatch):
    out = await _embed(monkeypatch, [{"index": 1, "embedding": [3, 4]}, {"index": 0, "embedding": [1, 2]}])
    assert out == [[1.0, 2.0], [3.0, 4.0]]


@pytest.mark.asyncio
@pytest.mark.parametrize("data", [
    [{"index": 0, "embedding": [1, 2]}, {"index": 1, "embedding": [3]}],
    [{"index": 0, "embedding": [1, float("nan")]}, {"index": 1, "embedding": [3, 4]}],
    [{"index": 0, "embedding": [1, 2]}],
    [{"index": 0, "embedding": [1, 2]}, {"index": 0, "embedding": [3, 4]}],
])
async def test_embeddings_invalid_are_unavailable(monkeypatch, data):
    assert await _embed(monkeypatch, data) is None


@pytest.mark.asyncio
async def test_anthropic_embeddings_unavailable_without_request(monkeypatch):
    _cfg(monkeypatch, embedding_model="fixture-embed")

    def handle(req):
        raise AssertionError("no embeddings request on native Anthropic")
    async with httpx.AsyncClient(transport=httpx.MockTransport(handle)) as http:
        monkeypatch.setattr(LLMClient, "_httpx_client", http)
        assert await LLMClient().embed(["a"]) is None

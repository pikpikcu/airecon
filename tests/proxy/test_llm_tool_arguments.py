"""Never dispatch invented empty arguments after malformed tool streaming."""
from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest

from airecon.proxy.config import DEFAULT_CONFIG
from airecon.proxy.llm import LLMClient

TOOLS = [{"type": "function", "function": {"name": "execute", "parameters": {
    "type": "object", "properties": {"command": {"type": "string"}}, "required": ["command"],
}}}]


def event(delta, finish=None):
    return {"choices": [{"delta": delta, "finish_reason": finish}]}


def call(arguments, index=0, name="execute"):
    return {"index": index, "id": f"call_{index}", "function": {"name": name, "arguments": arguments}}


async def collect(monkeypatch, events, tools=TOOLS):
    cfg = SimpleNamespace(**(DEFAULT_CONFIG | {"openai_model": "tool-fixture"}))
    monkeypatch.setattr("airecon.proxy.llm.get_config", lambda: cfg)
    monkeypatch.setattr(LLMClient, "_global_semaphore", asyncio.Semaphore(1))
    monkeypatch.setattr(LLMClient, "_unsupported_params", {})
    monkeypatch.setattr(LLMClient, "_record_model_performance", lambda *a, **kw: None)
    sleep = AsyncMock()
    monkeypatch.setattr("airecon.proxy.llm.asyncio.sleep", sleep)
    wire = "".join("data: " + json.dumps(e) + "\n\n" for e in events) + "data: [DONE]\n\n"
    requests = []
    def handle(request):
        requests.append(json.loads(request.content))
        return httpx.Response(200, text=wire)
    async with httpx.AsyncClient(transport=httpx.MockTransport(handle)) as http:
        monkeypatch.setattr(LLMClient, "_httpx_client", http)
        client = LLMClient()
        chunks = [c async for c in client.chat_stream([{"role": "user", "content": "Fixture only."}], tools=tools, max_retries=0)]
    return chunks, requests, sleep


@pytest.mark.asyncio
@pytest.mark.parametrize("arguments", ['{"command": "unfinished', "{}", "", "[]", "null", '{"command":"   "}', '{"command":42}'])
async def test_invalid_execute_arguments_fail_before_any_completed_tool_batch(monkeypatch, arguments):
    with pytest.raises(RuntimeError, match="(?i)tool.*(argument|call)") as error:
        await collect(monkeypatch, [event({"tool_calls": [call(arguments)]}, "tool_calls")])
    assert type(error.value).__name__ == "LLMToolCallError"


@pytest.mark.asyncio
async def test_length_truncated_tool_call_is_not_dispatched_even_with_valid_json(monkeypatch):
    with pytest.raises(RuntimeError, match="(?i)truncat|length"):
        await collect(monkeypatch, [event({"tool_calls": [call('{"command":"printf fixture"}')]}, "length")])


@pytest.mark.asyncio
async def test_fragmented_parallel_tool_calls_retain_exact_distinct_arguments(monkeypatch):
    events = [event({"tool_calls": [call('{"command":"printf A', 0), call('{"command":"printf B', 1)]}),
              event({"tool_calls": [{"index": 1, "function": {"arguments": '"}'}}, {"index": 0, "function": {"arguments": '"}'}}]}, "tool_calls")]
    chunks, requests, sleep = await collect(monkeypatch, events)
    final = chunks[-1]
    assert final["done"]
    assert [t["function"]["arguments"] for t in final["message"]["tool_calls"]] == [{"command": "printf A"}, {"command": "printf B"}]
    assert len(requests) == 1
    sleep.assert_not_awaited()


@pytest.mark.asyncio
async def test_valid_no_argument_tool_is_allowed(monkeypatch):
    tools = [{"type": "function", "function": {"name": "fixture_status", "parameters": {"type": "object", "properties": {}}}}]
    chunks, _, _ = await collect(monkeypatch, [event({"tool_calls": [call("{}", name="fixture_status")]}, "tool_calls")], tools)
    assert chunks[-1]["message"]["tool_calls"][0]["function"]["arguments"] == {}


@pytest.mark.asyncio
async def test_in_band_error_does_not_finalize_partial_tool_call(monkeypatch):
    from airecon.proxy.llm import LLMBackendHTTPError
    with pytest.raises(LLMBackendHTTPError):
        await collect(monkeypatch, [event({"tool_calls": [call('{"command":"partial')]}), {"error": {"message": "fixture unavailable", "type": "server_error"}}])


@pytest.mark.asyncio
async def test_required_string_can_be_empty_when_the_schema_allows_it(monkeypatch):
    tools = [{"type": "function", "function": {"name": "create_file", "parameters": {
        "type": "object", "properties": {"path": {"type": "string"}, "content": {"type": "string"}}, "required": ["path", "content"],
    }}}]
    chunks, _, _ = await collect(monkeypatch, [event({"tool_calls": [call('{"path":"fixture.txt","content":""}', name="create_file")]}, "tool_calls")], tools)
    assert chunks[-1]["message"]["tool_calls"][0]["function"]["arguments"]["content"] == ""

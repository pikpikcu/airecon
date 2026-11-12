"""Replay provider state through the actual HTTP/SSE boundary, without network."""
from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace

import httpx
import pytest

from airecon.proxy.config import DEFAULT_CONFIG
from airecon.proxy.llm import LLMClient


@pytest.mark.asyncio
@pytest.mark.parametrize("provider", ["gemini", "deepseek", "openai-null"])
async def test_provider_state_survives_stream_and_followup_request(monkeypatch, provider):
    base_url = "https://api.deepseek.com/v1" if provider == "deepseek" else "http://fixture.invalid/v1"
    cfg = SimpleNamespace(**(DEFAULT_CONFIG | {
        "llm_provider": "openai", "openai_model": "fixture",
        "openai_base_url": base_url, "openai_api_key": "",
        "llm_thinking_request_mode": "off",
    }))
    monkeypatch.setattr("airecon.proxy.llm.get_config", lambda: cfg)
    monkeypatch.setattr(LLMClient, "_reasoning_replay_models", set())
    monkeypatch.setattr(LLMClient, "_global_semaphore", asyncio.Semaphore(1))
    monkeypatch.setattr(LLMClient, "_record_model_performance", lambda *a, **kw: None)
    requests = []
    call = {"index": 0, "id": "call_fixture", "type": "function",
            "function": {"name": "fixture_status", "arguments": "{}"}}
    if provider == "gemini":
        call["extra_content"] = {"google": {"thought_signature": "fixture-signature"}}
    events = []
    if provider == "openai-null":
        events.append({"choices": [{"delta": {"reasoning_content": None}}]})
    if provider == "deepseek":
        events.extend({"choices": [{"delta": {"reasoning_content": part}}]}
                      for part in ("Inspect ", "fixture state."))
    events.append({"choices": [{"delta": {"tool_calls": [call]}}]})
    if provider == "gemini":
        events.append({"choices": [{"delta": {"tool_calls": [{"index": 0,
            "extra_content": {"google": {"future_extension": "preserved"}}}]}}]})
    events.append({"choices": [{"delta": {}, "finish_reason": "tool_calls"}]})
    response_text = "".join("data: " + json.dumps(event) + "\n\n" for event in events) + "data: [DONE]\n\n"

    def handle(request):
        payload = json.loads(request.content)
        requests.append(payload)
        if len(requests) == 1:
            return httpx.Response(200, text=response_text)
        assistant = next(message for message in payload["messages"] if message["role"] == "assistant")
        if provider == "gemini":
            valid = assistant["tool_calls"][0].get("extra_content") == {
                "google": {"thought_signature": "fixture-signature", "future_extension": "preserved"}}
        elif provider == "deepseek":
            valid = assistant.get("reasoning_content") == "Inspect fixture state."
        else:
            valid = "reasoning_content" not in assistant
        if not valid:
            return httpx.Response(400, json={"error": {"message": "Fixture requires original provider state"}})
        return httpx.Response(200, text='data: {"choices":[{"delta":{"content":"ok"},"finish_reason":"stop"}]}\n\ndata: [DONE]\n\n')

    async with httpx.AsyncClient(transport=httpx.MockTransport(handle)) as http:
        monkeypatch.setattr(LLMClient, "_httpx_client", http)
        client = LLMClient()
        client._request_semaphore = asyncio.Semaphore(1)
        history = [{"role": "user", "content": "Check fixture status."}]
        chunks = [chunk async for chunk in client.chat_stream(history, max_retries=0)]
        final = chunks[-1]["message"]
        history.extend([final, {"role": "tool", "tool_call_id": "call_fixture", "content": "ok"}])
        followup = [chunk async for chunk in client.chat_stream(history, max_retries=0)]
        assert followup[-1]["done"] is True
        assert len(requests) == 2
        if provider == "deepseek":
            assert final["reasoning_content"] == "Inspect fixture state."


@pytest.mark.asyncio
async def test_agent_keeps_provider_reasoning_when_storing_stream_output(monkeypatch, tmp_path):
    from unittest.mock import MagicMock
    from airecon.proxy.agent.loop import AgentLoop

    cfg = SimpleNamespace(**(DEFAULT_CONFIG | {"openai_model": "fixture", "llm_enable_thinking": False}))
    for module in ("loop", "loop_context", "models"):
        monkeypatch.setattr(f"airecon.proxy.agent.{module}.get_config", lambda: cfg)
    monkeypatch.setattr("airecon.proxy.config._workspace_root_cache", tmp_path)

    async def stream(**kwargs):
        yield {"message": {"role": "assistant", "content": "Fixture complete."}, "done": False}
        yield {"message": {"role": "assistant", "content": "", "reasoning_content": "Exact provider state."},
               "done": True, "prompt_eval_count": 10, "eval_count": 4}

    llm = MagicMock(spec=LLMClient)
    llm.model = "fixture"
    llm.supports_thinking = False
    llm.chat_stream = stream
    agent = AgentLoop(llm=llm, engine=MagicMock())
    agent.state.max_iterations = 1
    agent._tools_llm = []
    agent.state.conversation = [{"role": "user", "content": "Return fixture status."}]
    events = [event async for event in agent._run_iteration_loop(cfg)]
    assert not [event.data for event in events if event.type == "error"]
    assistant = next(message for message in agent.state.conversation if message["role"] == "assistant")
    assert assistant["reasoning_content"] == "Exact provider state."

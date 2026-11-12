"""Protocol retention contracts for PR #129 plus local safeguards."""
from __future__ import annotations
import asyncio
import json
from types import SimpleNamespace
import httpx
import pytest
from airecon.proxy.config import DEFAULT_CONFIG
from airecon.proxy.llm import LLMClient, LLMBackendHTTPError

@pytest.fixture
def cfg(monkeypatch):
    cfg = SimpleNamespace(**(DEFAULT_CONFIG | {"llm_provider": "anthropic", "openai_model": "fixture", "llm_enable_thinking": True}))
    monkeypatch.setattr("airecon.proxy.llm.get_config", lambda: cfg)
    monkeypatch.setattr(LLMClient, "_global_semaphore", asyncio.Semaphore(1))
    monkeypatch.setattr(LLMClient, "_record_model_performance", lambda *a, **kw: None)
    return cfg

@pytest.mark.asyncio
async def test_anthropic_stream_signature_usage_and_roundtrip(cfg, monkeypatch):
    events = [
        {"type":"message_start","message":{"usage":{"input_tokens":1234}}},
        {"type":"content_block_start","index":0,"content_block":{"type":"thinking","thinking":"","signature":""}},
        {"type":"content_block_delta","index":0,"delta":{"type":"thinking_delta","thinking":"fixture thought"}},
        {"type":"content_block_delta","index":0,"delta":{"type":"signature_delta","signature":"opaque-fixture"}},
        {"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"call_a","name":"fixture_status","input":{}}},
        {"type":"message_delta","delta":{"stop_reason":"tool_use"},"usage":{"output_tokens":7}},
        {"type":"message_stop"},
    ]
    seen=[]
    def handle(req):
        seen.append(json.loads(req.content))
        assert req.url.path.endswith("/messages")
        return httpx.Response(200,text="".join("data: "+json.dumps(e)+"\n\n" for e in events))
    async with httpx.AsyncClient(transport=httpx.MockTransport(handle)) as http:
        monkeypatch.setattr(LLMClient,"_httpx_client",http)
        c=LLMClient()
        chunks=[x async for x in c.chat_stream([{"role":"user","content":"fixture"}],think=True,max_retries=0)]
        final=chunks[-1]
        assert final["prompt_eval_count"]==1234
        assert final["eval_count"]==7
        blocks=final["message"]["_provider_blocks"]
        assert blocks[0]=={"type":"thinking","thinking":"fixture thought","signature":"opaque-fixture"}
        from airecon.proxy.llm_protocol import anthropic_messages
        _, wire=anthropic_messages([{"role":"user","content":"fixture"}, {**final["message"], "content":"fixture narration"}, {"role":"tool","tool_call_id":"call_a","content":"ok"}])
        assert wire[1]["content"][0]==blocks[0]
        assert wire[1]["content"][-1]["type"]=="tool_use"
        assert "temperature" not in seen[0]

@pytest.mark.asyncio
@pytest.mark.parametrize("event",[{"type":"error","error":{"type":"overloaded_error","message":"fixture overloaded"}}])
async def test_anthropic_in_band_error_cannot_complete(cfg,monkeypatch,event):
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda req:httpx.Response(200,text="data: "+json.dumps(event)+"\n\n"))) as http:
        monkeypatch.setattr(LLMClient,"_httpx_client",http)
        with pytest.raises(LLMBackendHTTPError):
            _=[c async for c in LLMClient().chat_stream([{"role":"user","content":"fixture"}],max_retries=0)]

def test_small_thinking_budget_and_non_native_tools_contract(cfg):
    c=LLMClient()
    payload={}
    c._apply_options(payload,{"num_predict":512})
    c._apply_thinking(payload,True)
    assert "thinking" not in payload


def test_context_budget_counts_anthropic_signed_blocks(cfg,monkeypatch):
    monkeypatch.setattr("airecon.proxy.config.get_config",lambda:cfg)
    from airecon.proxy.context_budget import request_chars
    messages=[{"role":"user","content":"fixture"},{"role":"assistant","content":"", "_provider_blocks":[{"type":"thinking","thinking":"fixture","signature":"opaque"*1000}]}]
    assert request_chars(messages,[])>6000


@pytest.mark.asyncio
async def test_agent_retains_native_blocks_in_history(cfg):
    from airecon.proxy.agent.models import AgentState
    from airecon.proxy.agent.loop_cycle_llm import _CycleLlmMixin
    blocks=[{"type":"thinking","thinking":"fixture","signature":"opaque"},{"type":"tool_use","id":"call_a","name":"fixture_status","input":{}}]
    from types import SimpleNamespace
    agent=SimpleNamespace(state=AgentState(),_pending_provider_blocks=blocks,_session=None,_no_tool_iterations=0,pipeline=None)
    agent._is_text_only_response=lambda _:True
    agent._check_critical_decision_consistency=lambda *a:None
    agent._analyze_llm_output=_CycleLlmMixin._analyze_llm_output.__get__(agent)
    agent._analyze_llm_output(None,"", "fixture",[{"id":"call_a","function":{"name":"fixture_status","arguments":{}}}])
    assert agent.state.conversation[-1]["_provider_blocks"]==blocks

@pytest.mark.asyncio
async def test_anthropic_nonstream_and_embedding_fallback(cfg,monkeypatch):
    calls=[]
    def handle(req):
        calls.append(req.url.path)
        return httpx.Response(200,json={"content":[{"type":"text","text":"fixture answer"}]})
    async with httpx.AsyncClient(transport=httpx.MockTransport(handle)) as http:
        monkeypatch.setattr(LLMClient,"_httpx_client",http)
        c=LLMClient()
        assert await c.complete([{"role":"user","content":"fixture"}],max_retries=0)=="fixture answer"
        assert await c.embed(["fixture"]) is None
    assert calls==["/v1/messages"]

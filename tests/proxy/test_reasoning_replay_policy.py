"""reasoning_content is replayed only where a backend needs it, and budgeted as sent."""
from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace

import httpx
import pytest

from airecon.proxy.config import DEFAULT_CONFIG
from airecon.proxy.context_budget import request_chars
from airecon.proxy.llm import LLMBackendHTTPError, LLMClient, _to_openai_messages

TOOLS = [{"type": "function", "function": {
    "name": "fixture_status", "parameters": {"type": "object", "properties": {}}}}]
REASONING = "Fixture reasoning. " * 200
DEEPSEEK_400 = "The `reasoning_content` in the thinking mode must be passed back to the API."


def _history(with_reasoning: bool = True) -> list[dict]:
    assistant = {"role": "assistant", "content": "", "tool_calls": [{
        "id": "call_fixture", "function": {"name": "fixture_status", "arguments": {}}}]}
    if with_reasoning:
        assistant["reasoning_content"] = REASONING
    return [
        {"role": "user", "content": "Check fixture status."},
        assistant,
        {"role": "tool", "tool_call_id": "call_fixture", "content": "ok"},
    ]


def _config(monkeypatch, **overrides):
    cfg = SimpleNamespace(**(DEFAULT_CONFIG | {
        "llm_provider": "openai", "openai_api_key": "", "llm_thinking_request_mode": "off",
        "openai_base_url": "http://127.0.0.1:8080/v1", "openai_model": "qwen3-fixture",
    } | overrides))
    monkeypatch.setattr("airecon.proxy.llm.get_config", lambda: cfg)
    monkeypatch.setattr("airecon.proxy.config.get_config", lambda: cfg)
    monkeypatch.setattr(LLMClient, "_reasoning_replay_models", set())
    return cfg


def test_local_backend_neither_receives_nor_budgets_stored_reasoning(monkeypatch):
    _config(monkeypatch)
    history = _history()

    wire = _to_openai_messages(history)

    assert "reasoning_content" not in wire[1]
    assert request_chars(history, TOOLS) == request_chars(_history(False), TOOLS)
    assert history[1]["reasoning_content"] == REASONING, "stored state must be kept"


@pytest.mark.parametrize(("base_url", "model"), [
    ("https://api.deepseek.com/v1", "deepseek-v4-pro"),
    ("https://api.deepseek.com", "fixture-alias"),
    ("http://gateway.fixture/v1", "deepseek/deepseek-v4-pro"),
])
def test_deepseek_backend_replays_and_budgets_stored_reasoning(monkeypatch, base_url, model):
    _config(monkeypatch, openai_base_url=base_url, openai_model=model)

    wire = _to_openai_messages(_history())

    assert wire[1]["reasoning_content"] == REASONING
    assert request_chars(_history(), TOOLS) > request_chars(_history(False), TOOLS) + len(REASONING)


@pytest.mark.parametrize(("base_url", "model"), [
    ("http://127.0.0.1:8080/v1", "deepseek-r1-distill-qwen-7b"),
    ("http://localhost:11434/v1", "deepseek-r1:8b"),
    ("http://gateway.fixture/v1", "fixture-deepseek-distill"),
])
def test_deepseek_named_models_elsewhere_are_not_replayed_by_default(monkeypatch, base_url, model):
    _config(monkeypatch, openai_base_url=base_url, openai_model=model)

    assert "reasoning_content" not in _to_openai_messages(_history())[1]
    assert request_chars(_history(), TOOLS) == request_chars(_history(False), TOOLS)


@pytest.mark.parametrize(("mode", "base_url", "expected"), [
    ("always", "http://127.0.0.1:8080/v1", True),
    ("off", "https://api.deepseek.com/v1", False),
])
def test_replay_setting_overrides_detection(monkeypatch, mode, base_url, expected):
    _config(monkeypatch, llm_reasoning_replay=mode, openai_base_url=base_url)

    assert ("reasoning_content" in _to_openai_messages(_history())[1]) is expected


def _client(monkeypatch, handle):
    monkeypatch.setattr(LLMClient, "_global_semaphore", asyncio.Semaphore(1))
    monkeypatch.setattr(LLMClient, "_record_model_performance", lambda *a, **kw: None)
    transport = httpx.AsyncClient(transport=httpx.MockTransport(handle))
    monkeypatch.setattr(LLMClient, "_httpx_client", transport)
    client = LLMClient()
    client._request_semaphore = asyncio.Semaphore(1)
    return client, transport


_OK = 'data: {"choices":[{"delta":{"content":"ok"},"finish_reason":"stop"}]}\n\ndata: [DONE]\n\n'


def _is_replay_signal(error: BaseException) -> bool:
    """The distinct "requirement learned, nothing resent" error, by class name."""
    return type(error).__name__ == "LLMReasoningReplayRequired"


@pytest.mark.asyncio
async def test_gateway_that_requires_reasoning_is_learned_once_and_budgeted(monkeypatch):
    _config(monkeypatch, openai_base_url="http://gateway.fixture/v1", openai_model="omni-fixture")
    sent = []

    def handle(request):
        payload = json.loads(request.content)
        sent.append(payload)
        assert len(sent) <= 3, "the client is retrying the same rejection in a loop"
        assistant = payload["messages"][1]
        if assistant.get("reasoning_content") != REASONING:
            return httpx.Response(400, json={"error": {"message": DEEPSEEK_400}})
        return httpx.Response(200, text=_OK)

    client, transport = _client(monkeypatch, handle)
    async with transport:
        with pytest.raises(LLMBackendHTTPError) as learned:
            [c async for c in client.chat_stream(_history(), tools=TOOLS, max_retries=0)]
        assert len(sent) == 1, "the larger request is the budget owner's to send"
        assert _is_replay_signal(learned.value)
        assert "reasoning_content" not in sent[0]["messages"][1]
        assert request_chars(_history(), TOOLS) > request_chars(_history(False), TOOLS)
        chunks = [c async for c in client.chat_stream(_history(), tools=TOOLS, max_retries=0)]
        assert chunks[-1]["done"] is True
        assert len(sent) == 2
        assert sent[1]["tools"] == TOOLS
        [c async for c in client.chat_stream(_history(), tools=TOOLS, max_retries=0)]
        assert len(sent) == 3, "a learned requirement must not cost another rejection"


@pytest.mark.asyncio
async def test_learned_requirement_is_scoped_to_the_backend_that_reported_it(monkeypatch):
    _config(monkeypatch, openai_base_url="http://gateway.fixture/v1", openai_model="omni-fixture")

    def handle(request):
        payload = json.loads(request.content)
        if payload["messages"][1].get("reasoning_content") != REASONING:
            return httpx.Response(400, json={"error": {"message": DEEPSEEK_400}})
        return httpx.Response(200, text=_OK)

    client, transport = _client(monkeypatch, handle)
    async with transport:
        with pytest.raises(LLMBackendHTTPError):
            [c async for c in client.chat_stream(_history(), tools=TOOLS, max_retries=0)]
    other = LLMClient(base_url="http://other-gateway.fixture/v1", model="omni-fixture")

    learned = _to_openai_messages(_history())[1]
    elsewhere = other._wire_payload(_history(), stream=True)["messages"][1]

    assert learned["reasoning_content"] == REASONING
    assert "reasoning_content" not in elsewhere


@pytest.mark.asyncio
async def test_non_streaming_completion_learns_the_requirement_too(monkeypatch):
    _config(monkeypatch, openai_base_url="http://gateway.fixture/v1", openai_model="omni-fixture")
    sent = []

    def handle(request):
        payload = json.loads(request.content)
        sent.append(payload)
        assert len(sent) <= 3, "the client is retrying the same rejection in a loop"
        if payload["messages"][1].get("reasoning_content") != REASONING:
            return httpx.Response(400, json={"error": {"message": DEEPSEEK_400}})
        return httpx.Response(200, json={"choices": [{"message": {"content": "ok"}}]})

    client, transport = _client(monkeypatch, handle)
    async with transport:
        assert await client.complete(_history(), max_retries=0) == "ok"
    assert len(sent) == 2


@pytest.mark.asyncio
@pytest.mark.parametrize("stored", [True, False])
async def test_replay_requirement_cannot_loop_or_invent_state(monkeypatch, stored):
    _config(monkeypatch, openai_base_url="http://gateway.fixture/v1", openai_model="omni-fixture")
    sent = []

    def handle(request):
        sent.append(json.loads(request.content))
        assert len(sent) <= 2, "the client is retrying the same rejection in a loop"
        return httpx.Response(400, json={"error": {"message": DEEPSEEK_400}})

    client, transport = _client(monkeypatch, handle)
    async with transport:
        with pytest.raises(LLMBackendHTTPError) as first:
            [c async for c in client.chat_stream(_history(stored), tools=TOOLS, max_retries=0)]
        assert len(sent) == 1
        assert _is_replay_signal(first.value) is stored
        with pytest.raises(LLMBackendHTTPError) as second:
            [c async for c in client.chat_stream(_history(stored), tools=TOOLS, max_retries=0)]
        assert len(sent) == 2
        assert not _is_replay_signal(second.value), "the same rejection must not ask for another retry"
    assert "reasoning_content" not in sent[0]["messages"][1]
    assert sent[1]["messages"][1].get("reasoning_content") == (REASONING if stored else None)
    assert bool(LLMClient._reasoning_replay_models) is stored


@pytest.mark.asyncio
async def test_disabled_replay_is_not_overridden_by_learning(monkeypatch):
    _config(monkeypatch, llm_reasoning_replay="off", openai_base_url="http://gateway.fixture/v1",
            openai_model="omni-fixture")
    sent = []

    def handle(request):
        sent.append(json.loads(request.content))
        assert len(sent) <= 2, "the client is retrying the same rejection in a loop"
        return httpx.Response(400, json={"error": {"message": DEEPSEEK_400}})

    client, transport = _client(monkeypatch, handle)
    async with transport:
        with pytest.raises(LLMBackendHTTPError) as rejected:
            [c async for c in client.chat_stream(_history(), tools=TOOLS, max_retries=0)]
    assert len(sent) == 1
    assert not _is_replay_signal(rejected.value)
    assert not LLMClient._reasoning_replay_models


# ── the agent loop owns the request budget, so it sends the larger request ──


def _agent_history(old_groups: int, old_reasoning: int, latest_reasoning: int) -> list[dict]:
    history = [
        {"role": "system", "content": "Only authorized fixture scope."},
        {"role": "user", "content": "Check fixture status."},
    ]
    sizes = [old_reasoning] * old_groups + [latest_reasoning]
    for index, size in enumerate(sizes):
        history += [
            {"role": "assistant", "content": "", "reasoning_content": f"step {index} " + "r" * size,
             "tool_calls": [{"id": f"call_{index}", "function": {"name": "fixture_status", "arguments": {}}}]},
            {"role": "tool", "tool_call_id": f"call_{index}", "content": "ok"},
        ]
    return history


def _wire_chars(payload: dict) -> int:
    """What request_chars measures, taken from the request that reached the backend."""
    body = {"messages": payload["messages"], "tools": payload.get("tools") or []}
    return len(json.dumps(body, ensure_ascii=False).encode("utf-8"))


def _requires_reasoning(sent: list[dict], *, accept: bool = True):
    def handle(request):
        payload = json.loads(request.content)
        sent.append(payload)
        assert len(sent) <= 3, "the agent is retrying the same rejection in a loop"
        assistants = [m for m in payload["messages"] if m["role"] == "assistant"]
        if not accept or any("reasoning_content" not in m for m in assistants):
            return httpx.Response(400, json={"error": {"message": DEEPSEEK_400}})
        return httpx.Response(200, text=_OK)
    return handle


async def _run_agent_iteration(monkeypatch, tmp_path, history, handle):
    """One real loop iteration: budget pass, projection, client, error recovery."""
    from unittest.mock import AsyncMock, MagicMock

    from airecon.proxy.agent.loop import AgentLoop

    cfg = _config(monkeypatch, openai_base_url="http://gateway.fixture/v1",
                  openai_model="omni-fixture", llm_context_window=8192)
    for module in ("loop", "loop_context", "models"):
        monkeypatch.setattr(f"airecon.proxy.agent.{module}.get_config", lambda: cfg)
    monkeypatch.setattr("airecon.proxy.config._workspace_root_cache", tmp_path)
    sleep = AsyncMock()
    monkeypatch.setattr("airecon.proxy.agent.loop_tool_cycle.asyncio.sleep", sleep)
    client, transport = _client(monkeypatch, handle)
    loop = AgentLoop(llm=client, engine=MagicMock())
    loop.state.active_target = "fixture.test"
    loop.state.max_iterations = 1
    loop.state.conversation = list(history)
    loop._tools_llm = list(TOOLS)
    # Periodic housekeeping and advisory injections are not part of this path.
    loop._run_iteration_housekeeping = AsyncMock()
    loop._check_and_reset_context = AsyncMock()
    loop._inject_learned_insights_async = AsyncMock()
    loop._inject_tool_intelligence = lambda: None
    budgets: list[int] = []
    enforce = loop._enforce_char_budget

    async def enforce_and_record(num_ctx, num_predict=None):
        budgets.append((num_ctx - loop._fit_num_predict_to_ctx(num_predict, num_ctx) - 256) * 3)
        await enforce(num_ctx, num_predict)

    loop._enforce_char_budget = enforce_and_record
    events = []
    async with transport:
        stream = loop._run_iteration_loop(cfg)
        async for event in stream:
            events.append(event)
            answered = event.type == "llm_status" and event.data.get("recovered")
            if answered or event.type in ("error", "done"):
                break
        await stream.aclose()
    sleep.assert_not_awaited()
    return events, max(budgets)


@pytest.mark.asyncio
async def test_agent_repacks_before_sending_newly_required_reasoning(monkeypatch, tmp_path):
    history = _agent_history(old_groups=12, old_reasoning=3000, latest_reasoning=200)
    stored = {m["reasoning_content"] for m in history if "reasoning_content" in m}
    sent: list[dict] = []

    events, budget = await _run_agent_iteration(monkeypatch, tmp_path, history, _requires_reasoning(sent))

    sizes = [_wire_chars(payload) for payload in sent]
    assert max(sizes) <= budget, f"sent {sizes} bytes against a {budget}-byte request budget"
    assert len(sent) == 2
    assert all("reasoning_content" not in m for m in sent[0]["messages"])
    replayed = [m["reasoning_content"] for m in sent[1]["messages"] if m["role"] == "assistant"]
    assert replayed[-1] == history[-2]["reasoning_content"], "the latest turn is sent exactly"
    assert set(replayed) <= stored, "reasoning must come from stored state"
    assert sizes[1] > sizes[0], "the fixture must make replay cost context"
    assert not any(event.type == "error" for event in events)


@pytest.mark.asyncio
async def test_agent_stops_when_required_reasoning_cannot_fit_the_budget(monkeypatch, tmp_path):
    history = _agent_history(old_groups=0, old_reasoning=0, latest_reasoning=60_000)
    sent: list[dict] = []

    events, budget = await _run_agent_iteration(monkeypatch, tmp_path, history, _requires_reasoning(sent))

    sizes = [_wire_chars(payload) for payload in sent]
    assert max(sizes) <= budget, f"sent {sizes} bytes against a {budget}-byte request budget"
    assert len(sent) == 1
    assert [event.data.get("reason") for event in events if event.type == "error"] == ["context_budget"]


@pytest.mark.asyncio
async def test_agent_retries_a_learned_requirement_once_then_reports_the_rejection(monkeypatch, tmp_path):
    history = _agent_history(old_groups=2, old_reasoning=200, latest_reasoning=200)
    sent: list[dict] = []

    events, budget = await _run_agent_iteration(
        monkeypatch, tmp_path, history, _requires_reasoning(sent, accept=False))

    assert len(sent) == 2
    assert max(_wire_chars(payload) for payload in sent) <= budget
    assert all("reasoning_content" in m for m in sent[1]["messages"] if m["role"] == "assistant")
    errors = [event.data["message"] for event in events if event.type == "error"]
    assert len(errors) == 1 and "non-retryable" in errors[0]


# ── YAML reads unquoted `off` as a boolean; it must still mean off ──────────


@pytest.mark.parametrize("literal", ["off", '"off"', "false"])
def test_yaml_off_disables_replay_and_thinking_requests(monkeypatch, tmp_path, literal):
    from airecon.proxy.config import Config

    path = tmp_path / "config.yaml"
    path.write_text(
        "openai_base_url: https://api.deepseek.com/v1\nopenai_model: deepseek-v4-pro\n"
        f"llm_reasoning_replay: {literal}\nllm_thinking_request_mode: {literal}\n",
        encoding="utf-8",
    )
    cfg = Config.load(path)
    monkeypatch.setattr("airecon.proxy.llm.get_config", lambda: cfg)
    monkeypatch.setattr("airecon.proxy.config.get_config", lambda: cfg)
    monkeypatch.setattr(LLMClient, "_reasoning_replay_models", set())

    assert "reasoning_content" not in _to_openai_messages(_history())[1]
    assert request_chars(_history(), TOOLS) == request_chars(_history(False), TOOLS)
    payload: dict = {}
    LLMClient()._apply_thinking(payload, True)
    assert payload == {}, "thinking is enabled by default, so only the request mode keeps this empty"

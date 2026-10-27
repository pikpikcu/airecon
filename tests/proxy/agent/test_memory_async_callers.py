"""Memory integration exercises the actual async and synchronous caller seams."""
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock
import pytest
from airecon.proxy.agent.loop_cycle_llm import _CycleLlmMixin
from airecon.proxy.agent.loop_exploration import _ExplorationMixin
from airecon.proxy.agent.models import AgentState
from airecon.proxy.config import DEFAULT_CONFIG


@pytest.mark.asyncio
async def test_iteration_memory_refresh_awaits_same_client_and_queues_distill():
    insight = SimpleNamespace(category="tool_tech", title="fixture", conditions={}, recommendation="advice", confidence=.5, observation_count=3)
    engine = SimpleNamespace(recall_async=AsyncMock(return_value=[insight]), distill_async=AsyncMock(return_value=[]))
    agent = SimpleNamespace(state=AgentState(active_target="fixture.test"), _session=SimpleNamespace(technologies={"nginx": "detected"}), llm=object(), _learning_distill_due=True)
    agent._ensure_adaptive_learning_engine = lambda: engine
    agent._inject_learned_insights = _CycleLlmMixin._inject_learned_insights.__get__(agent)
    await _CycleLlmMixin._inject_learned_insights_async(agent, "RECON")
    engine.distill_async.assert_awaited_once_with(agent.llm)
    engine.recall_async.assert_awaited_once_with(agent.llm, "RECON", ["nginx"], "fixture.test")
    assert agent._learning_distill_due is False
    assert "fixture" in agent.state.conversation[-1]["content"]
    assert "scope" in agent.state.conversation[-1]["content"].lower()


def test_thirtieth_observation_does_not_make_sync_provider_call(monkeypatch):
    cfg = SimpleNamespace(**DEFAULT_CONFIG)
    monkeypatch.setattr("airecon.proxy.agent.loop_exploration.get_config", lambda: cfg)
    engine = SimpleNamespace(observation_log=[{} for _ in range(29)], record_tool_result=MagicMock(), record_strategy_result=MagicMock(), save_state=MagicMock(), distill_insights=MagicMock())
    engine.record_observation = lambda **kw: engine.observation_log.append(kw)
    agent = SimpleNamespace(_session=None, state=SimpleNamespace(tool_history=[]), _ensure_adaptive_learning_engine=lambda: engine, _record_target_memory=MagicMock())
    _ExplorationMixin._record_adaptive_learning(agent, "fixture", {}, {}, False, .1, "RECON")
    assert agent._learning_distill_due is True
    engine.distill_insights.assert_not_called()

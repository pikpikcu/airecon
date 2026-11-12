import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from airecon.proxy.agent.executors_dispatch import _DispatchExecutorMixin


@pytest.mark.asyncio
@pytest.mark.parametrize("cancelled", [False, True])
async def test_parallel_run_restores_existing_tool_blocks(monkeypatch, cancelled):
    agent = _DispatchExecutorMixin()
    agent.engine = MagicMock()
    agent.state = SimpleNamespace(tool_history=[], tool_counts={"total": 0})
    agent._blocked_tools = {"execute", "fixture_tool"}
    agent._save_tool_output = MagicMock()
    runner = MagicMock()
    runner.run_parallel = AsyncMock(
        side_effect=asyncio.CancelledError() if cancelled else None,
        return_value={},
    )
    monkeypatch.setattr(
        "airecon.proxy.agent.subagent.ParallelAgentRunner", lambda **kwargs: runner,
    )
    kwargs = {"tool_name": "run_parallel_agents", "arguments": {"targets": ["example.com"]}}
    if cancelled:
        with pytest.raises(asyncio.CancelledError):
            await agent._execute_run_parallel_agents_tool(**kwargs)
    else:
        assert (await agent._execute_run_parallel_agents_tool(**kwargs))[0] is True
    assert agent._blocked_tools == {"execute", "fixture_tool"}

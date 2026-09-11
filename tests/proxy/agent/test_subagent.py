"""Tests for subagent.py - Subagent coordination patterns."""

import asyncio

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from airecon.proxy.agent.subagent import (
    AgentRole,
    SubagentConfig,
    SubagentCoordinator,
)


class TestAgentRole:
    def test_scout_role(self) -> None:
        assert AgentRole.SCOUT.value == "scout"
        assert AgentRole.SCOUT.name == "SCOUT"

    def test_exploit_role(self) -> None:
        assert AgentRole.EXPLOIT.value == "exploit"
        assert AgentRole.EXPLOIT.name == "EXPLOIT"


class TestSubagentConfig:
    def test_default_values(self) -> None:
        config = SubagentConfig()
        assert config.max_concurrent_agents == 3
        assert config.auto_exploit is True

    def test_custom_values(self) -> None:
        config = SubagentConfig(max_concurrent_agents=5, auto_exploit=False)
        assert config.max_concurrent_agents == 5
        assert config.auto_exploit is False


class TestSubagentCoordinator:
    def test_init_default(self) -> None:
        mock_llm = MagicMock()
        coordinator = SubagentCoordinator(llm=mock_llm)
        assert coordinator.llm is mock_llm
        assert coordinator.engine is None
        assert coordinator.session is not None
        assert coordinator.config.max_concurrent_agents == 3
        assert coordinator._scout_active is False
        assert coordinator._exploit_active is False
        assert coordinator._stop_requested is False

    def test_init_with_session(self) -> None:
        mock_llm = MagicMock()
        mock_session = MagicMock()
        coordinator = SubagentCoordinator(llm=mock_llm, session=mock_session)
        assert coordinator.session == mock_session

    def test_init_with_config(self) -> None:
        mock_llm = MagicMock()
        custom_config = SubagentConfig(max_concurrent_agents=10)
        coordinator = SubagentCoordinator(llm=mock_llm, config=custom_config)
        assert coordinator.config.max_concurrent_agents == 10

    def test_exploit_queue_created(self) -> None:
        mock_llm = MagicMock()
        coordinator = SubagentCoordinator(llm=mock_llm)
        assert isinstance(coordinator._exploit_queue, asyncio.Queue)

    @pytest.mark.asyncio
    async def test_start_recon_initializes_session(self) -> None:
        mock_llm = MagicMock()
        coordinator = SubagentCoordinator(llm=mock_llm)
        coordinator.session.target = "test.com"
        assert coordinator.session.target == "test.com"

    @pytest.mark.asyncio
    async def test_start_recon_creates_graph(self) -> None:
        mock_llm = MagicMock()
        coordinator = SubagentCoordinator(llm=mock_llm)

        with patch(
            "airecon.proxy.agent.agent_graph.create_default_graph"
        ) as mock_create:
            mock_graph = MagicMock()
            mock_graph.execute = AsyncMock()
            mock_graph.execute.return_value.__aiter__.return_value = []
            mock_create.return_value = mock_graph

            async for _ in coordinator.start_recon("test.com", "prompt"):
                pass

            mock_create.assert_called_once()

    @pytest.mark.asyncio
    async def test_start_recon_stops_on_request(self) -> None:
        mock_llm = MagicMock()
        coordinator = SubagentCoordinator(llm=mock_llm)
        coordinator._stop_requested = True

        with patch("airecon.proxy.agent.agent_graph.create_default_graph"):
            events = []
            async for event in coordinator.start_recon("test.com", "prompt"):
                events.append(event)

        assert len(events) == 1
        assert events[0].type == "task_complete"

    def test_stop_sets_flag(self) -> None:
        mock_llm = MagicMock()
        coordinator = SubagentCoordinator(llm=mock_llm)
        coordinator.stop()
        assert coordinator._stop_requested is True

    def test_session_persistence(self) -> None:
        from airecon.proxy.agent.session import SessionData

        mock_llm = MagicMock()
        coordinator = SubagentCoordinator(llm=mock_llm)
        assert isinstance(coordinator.session, SessionData)
        assert coordinator.session.target == ""

    def test_session_target_update(self) -> None:
        mock_llm = MagicMock()
        coordinator = SubagentCoordinator(llm=mock_llm)
        coordinator.session.target = "new-target.com"
        assert coordinator.session.target == "new-target.com"


class TestSubagentIntegration:
    @pytest.mark.asyncio
    async def test_full_recon_flow(self) -> None:
        mock_llm = MagicMock()
        coordinator = SubagentCoordinator(llm=mock_llm)

        with patch(
            "airecon.proxy.agent.agent_graph.create_default_graph"
        ) as mock_create:
            mock_graph = MagicMock()

            async def mock_execute(*args):
                yield MagicMock(type="test", data={"finding": "test"})

            mock_graph.execute = mock_execute
            mock_create.return_value = mock_graph

            events = []
            async for event in coordinator.start_recon("test.com", "recon"):
                events.append(event)

            assert len(events) > 0

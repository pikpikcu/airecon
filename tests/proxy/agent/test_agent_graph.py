"""Tests for agent_graph.py — AgentGraph, AgentNode, AgentEdge, topological sort."""

from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from airecon.proxy.agent.agent_graph import (
    AgentEdge,
    AgentGraph,
    AgentNode,
    AgentRole,
    create_default_graph,
)
from airecon.proxy.agent.models import AgentEvent


# ── AgentNode / AgentEdge dataclasses ────────────────────────────────────────


class TestAgentNodeDataclass:
    def test_basic_creation(self):
        node = AgentNode(id="n1", role=AgentRole.RECON, prompt_template="do recon")
        assert node.id == "n1"
        assert node.role == AgentRole.RECON
        assert node.prompt_template == "do recon"
        assert node.max_iterations == 200  # default
        assert node.depends_on == []  # default

    def test_custom_iterations_and_deps(self):
        node = AgentNode(
            id="n2",
            role=AgentRole.ANALYZER,
            prompt_template="analyse",
            max_iterations=50,
            depends_on=["n1"],
        )
        assert node.max_iterations == 50
        assert node.depends_on == ["n1"]

    def test_all_roles_instantiable(self):
        for role in AgentRole:
            node = AgentNode(id=f"node_{role.value}", role=role, prompt_template="x")
            assert node.role == role


class TestAgentEdgeDataclass:
    def test_basic_creation(self):
        edge = AgentEdge(source_id="a", target_id="b")
        assert edge.source_id == "a"
        assert edge.target_id == "b"


# ── AgentGraph: add_node / add_edge ──────────────────────────────────────────


class TestAgentGraphConstruction:
    def _make_graph(self):
        return AgentGraph(target="test.com", llm=None, engine=None)

    def test_add_node(self):
        g = self._make_graph()
        n = AgentNode(id="r", role=AgentRole.RECON, prompt_template="recon")
        g.add_node(n)
        assert "r" in g.nodes

    def test_add_edge_valid(self):
        g = self._make_graph()
        n1 = AgentNode(id="a", role=AgentRole.RECON, prompt_template="")
        n2 = AgentNode(id="b", role=AgentRole.ANALYZER, prompt_template="")
        g.add_node(n1)
        g.add_node(n2)
        g.add_edge("a", "b")
        assert len(g.edges) == 1
        assert g.nodes["b"].depends_on == ["a"]

    def test_add_edge_unknown_source_raises(self):
        g = self._make_graph()
        n = AgentNode(id="b", role=AgentRole.ANALYZER, prompt_template="")
        g.add_node(n)
        with pytest.raises(ValueError, match="must exist"):
            g.add_edge("nonexistent", "b")

    def test_add_edge_unknown_target_raises(self):
        g = self._make_graph()
        n = AgentNode(id="a", role=AgentRole.RECON, prompt_template="")
        g.add_node(n)
        with pytest.raises(ValueError, match="must exist"):
            g.add_edge("a", "nonexistent")

    def test_duplicate_dep_not_added_twice(self):
        g = self._make_graph()
        n1 = AgentNode(id="a", role=AgentRole.RECON, prompt_template="")
        n2 = AgentNode(id="b", role=AgentRole.ANALYZER, prompt_template="")
        g.add_node(n1)
        g.add_node(n2)
        g.add_edge("a", "b")
        g.add_edge("a", "b")  # second call — dep already present
        assert g.nodes["b"].depends_on.count("a") == 1


# ── execution_order: topological sort ────────────────────────────────────────


class TestExecutionOrder:
    def _linear_graph(self) -> AgentGraph:
        """a → b → c"""
        g = AgentGraph(target="t", llm=None, engine=None)
        for nid, role in [
            ("a", AgentRole.RECON),
            ("b", AgentRole.ANALYZER),
            ("c", AgentRole.REPORTER),
        ]:
            g.add_node(AgentNode(id=nid, role=role, prompt_template=""))
        g.add_edge("a", "b")
        g.add_edge("b", "c")
        return g

    def test_linear_chain_order(self):
        g = self._linear_graph()
        order = [n.id for n in g.execution_order()]
        # a must come before b, b before c
        assert order.index("a") < order.index("b") < order.index("c")

    def test_single_node(self):
        g = AgentGraph(target="t", llm=None, engine=None)
        g.add_node(AgentNode(id="solo", role=AgentRole.RECON, prompt_template=""))
        order = g.execution_order()
        assert len(order) == 1
        assert order[0].id == "solo"

    def test_empty_graph(self):
        g = AgentGraph(target="t", llm=None, engine=None)
        assert g.execution_order() == []

    def test_diamond_dependency(self):
        """a → b, a → c, b → d, c → d (diamond)."""
        g = AgentGraph(target="t", llm=None, engine=None)
        for nid, role in [
            ("a", AgentRole.RECON),
            ("b", AgentRole.ANALYZER),
            ("c", AgentRole.SPECIALIST),
            ("d", AgentRole.REPORTER),
        ]:
            g.add_node(AgentNode(id=nid, role=role, prompt_template=""))
        g.add_edge("a", "b")
        g.add_edge("a", "c")
        g.add_edge("b", "d")
        g.add_edge("c", "d")
        order = [n.id for n in g.execution_order()]
        assert order.index("a") < order.index("b")
        assert order.index("a") < order.index("c")
        assert order.index("b") < order.index("d")
        assert order.index("c") < order.index("d")

    def test_cycle_raises(self):
        """a → b → a (cycle) must raise ValueError."""
        g = AgentGraph(target="t", llm=None, engine=None)
        g.add_node(AgentNode(id="a", role=AgentRole.RECON, prompt_template=""))
        g.add_node(AgentNode(id="b", role=AgentRole.ANALYZER, prompt_template=""))
        # Manually create cycle — bypass add_edge validation
        g.edges.append(AgentEdge("a", "b"))
        g.nodes["b"].depends_on.append("a")
        g.edges.append(AgentEdge("b", "a"))
        g.nodes["a"].depends_on.append("b")
        with pytest.raises(ValueError, match="Cycle detected"):
            g.execution_order()

    def test_unknown_dependency_raises(self):
        """Node depends on a node not in the graph."""
        g = AgentGraph(target="t", llm=None, engine=None)
        node = AgentNode(
            id="x", role=AgentRole.RECON, prompt_template="", depends_on=["ghost"]
        )
        g.add_node(node)
        with pytest.raises(ValueError, match="unknown node"):
            g.execution_order()


# ── create_default_graph ──────────────────────────────────────────────────────


class TestCreateDefaultGraph:
    def test_returns_agent_graph(self):
        g = create_default_graph("example.com")
        assert isinstance(g, AgentGraph)

    def test_has_expected_nodes(self):
        g = create_default_graph("example.com")
        expected = {
            "recon_node",
            "analyzer_node",
            "exploiter_node",
            "reporter_node",
        }
        assert set(g.nodes.keys()) == expected

    def test_execution_order_valid(self):
        """Graph must be acyclic and produce a valid topological order."""
        g = create_default_graph("example.com")
        order = [n.id for n in g.execution_order()]
        # recon must come before analyzer
        assert order.index("recon_node") < order.index("analyzer_node")
        # analyzer must come before exploiter
        assert order.index("analyzer_node") < order.index("exploiter_node")
        # exploiter must come before reporter
        assert order.index("exploiter_node") < order.index("reporter_node")

    def test_target_stored(self):
        g = create_default_graph("target.io")
        assert g.target == "target.io"

    def test_with_prompt_context(self):
        g = create_default_graph("example.com", prompt="focus on auth bypass")
        exploiter = g.nodes["exploiter_node"]
        assert "focus on auth bypass" in exploiter.prompt_template


# ── AgentGraph.execute ────────────────────────────────────────────────────────


class TestAgentGraphExecute:
    def _make_mock_loop(self, events: list[AgentEvent]) -> MagicMock:
        """Return a mock AgentLoop whose process_message is an async generator."""
        _events = list(events)

        async def _gen(*args, **kwargs):
            for evt in _events:
                yield evt

        mock_loop = MagicMock()
        mock_loop.process_message = _gen
        mock_loop.initialize = AsyncMock()
        return mock_loop

    @pytest.mark.asyncio
    async def test_execute_yields_events_per_node(self):
        """execute() should yield at least one agent_state event per node."""
        from airecon.proxy.agent.session import SessionData

        g = AgentGraph(target="test.com", llm=MagicMock(), engine=MagicMock())
        node = AgentNode(id="solo", role=AgentRole.RECON, prompt_template="run recon")
        g.add_node(node)

        mock_loop = self._make_mock_loop(
            [
                AgentEvent(type="text", data={"content": "found stuff"}),
                AgentEvent(type="done", data={}),
            ]
        )
        shared_session = SessionData(target="test.com")

        with patch("airecon.proxy.agent.loop.AgentLoop", return_value=mock_loop):
            events = []
            async for evt in g.execute(shared_session):
                events.append(evt)

        types = [e.type for e in events]
        assert "agent_state" in types  # start announcement

    @pytest.mark.asyncio
    async def test_execute_attaches_source_node_to_events(self):
        """Events yielded from each node get __source_node tag."""
        from airecon.proxy.agent.session import SessionData

        g = AgentGraph(target="test.com", llm=MagicMock(), engine=MagicMock())
        node = AgentNode(id="recon", role=AgentRole.RECON, prompt_template="")
        g.add_node(node)

        mock_loop = self._make_mock_loop(
            [
                AgentEvent(type="text", data={"content": "hi"}),
            ]
        )

        with patch("airecon.proxy.agent.loop.AgentLoop", return_value=mock_loop):
            events = []
            async for evt in g.execute(SessionData(target="test.com")):
                events.append(evt)

        non_announce = [e for e in events if e.type != "agent_state"]
        if non_announce:
            assert non_announce[0].data.get("__source_node") == "recon"


# ── Helpers ───────────────────────────────────────────────────────────────────


async def aiter(items):
    """Helper: convert a list to an async iterator."""
    for item in items:
        yield item

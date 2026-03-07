"""Multi-Agent Graph representation and executor.

Replaces rigid Scout+Exploit pairs with a flexible graph of specialized agents.
Nodes represent specialized agents (Recon, Analyzer, Exploiter, Reporter),
and edges define the data flow/dependencies.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, AsyncIterator

from .agent.models import AgentEvent
from .agent.pipeline import PipelineEngine
from .agent.session import session_to_context

logger = logging.getLogger("airecon.agent.graph")


class AgentRole(Enum):
    """Specialized roles for nodes in the agent graph."""
    RECON = "recon"
    ANALYZER = "analyzer"
    EXPLOITER = "exploit"
    REPORTER = "reporter"
    SPECIALIST = "specialist"


@dataclass
class AgentNode:
    """A single node within the Multi-Agent Graph."""
    id: str
    role: AgentRole
    prompt_template: str
    max_iterations: int = 200
    depends_on: list[str] = field(default_factory=list)


@dataclass
class AgentEdge:
    """Edge connecting two nodes, specifying data transfer behavior."""
    source_id: str
    target_id: str


class AgentGraph:
    """Directed Acyclic Graph orchestrating specialized AIRecon agents."""

    def __init__(self, target: str, ollama: Any, engine: Any):
        self.target = target
        self.ollama = ollama
        self.engine = engine
        self.nodes: dict[str, AgentNode] = {}
        self.edges: list[AgentEdge] = []

    def add_node(self, node: AgentNode) -> None:
        """Add a specialized agent node to the graph."""
        self.nodes[node.id] = node

    def add_edge(self, source_id: str, target_id: str) -> None:
        """Define a dependency/data flow edge between nodes."""
        if source_id not in self.nodes or target_id not in self.nodes:
            raise ValueError("Source and target must exist in the graph")
        self.edges.append(AgentEdge(source_id, target_id))
        if source_id not in self.nodes[target_id].depends_on:
            self.nodes[target_id].depends_on.append(source_id)

    def execution_order(self) -> list[AgentNode]:
        """Return a topological sort of nodes determining execution order."""
        visited = set()
        order = []

        def dfs(node_id: str) -> None:
            if node_id in visited:
                return
            visited.add(node_id)
            for dep in self.nodes[node_id].depends_on:
                dfs(dep)
            order.append(self.nodes[node_id])

        for n_id in self.nodes:
            dfs(n_id)

        return order

    async def execute(self, shared_session: Any) -> AsyncIterator[AgentEvent]:
        """Execute the graph following topological order."""
        from .agent.loop import AgentLoop
        order = self.execution_order()

        for node in order:
            logger.info(
                f"Graph orchestrator starting Node: {node.id} ({node.role.value})")
            yield AgentEvent(type="agent_state", data={"status": f"Starting {node.id}..."})

            # Setup specialized agent loop
            agent = AgentLoop(ollama=self.ollama, engine=self.engine)
            agent._override_max_iterations = node.max_iterations
            # Block sub-agents from spawning infinite graphs
            agent._blocked_tools = {"spawn_agent", "run_parallel_agents"}

            # Share session + pipeline explicitly so subagents:
            # 1. Build on parent findings instead of re-scanning
            # 2. Have phase enforcement and session context checkpoints active
            agent._session = shared_session
            agent.pipeline = PipelineEngine(shared_session)

            # Inject parent session context into prompt so subagent knows what
            # was done
            session_ctx = session_to_context(
                shared_session) if shared_session else ""
            prompt = (
                f"[SUBAGENT NODE: {node.id} | ROLE: {node.role.name}]\n"
                f"[Target: {self.target}]\n\n"
                + (f"{session_ctx}\n\n" if session_ctx else "")
                + "DO NOT re-scan or re-enumerate data already shown above. "
                "Continue from where the parent agent left off.\n\n"
                f"{node.prompt_template}\n\n"
                "When your specialist task is complete, output [TASK_COMPLETE]."
            )

            async for event in agent.process_message(prompt):
                if hasattr(event, "data") and isinstance(event.data, dict):
                    event.data["__source_node"] = node.id
                yield event


def create_default_graph(target: str, prompt: str = "") -> AgentGraph:
    """Create the standard AIRecon Phase 1-to-4 graph structure."""
    g = AgentGraph(target, ollama=None, engine=None)

    n_recon = AgentNode(
        id="recon_node",
        role=AgentRole.RECON,
        prompt_template="Perform surface reconnaissance. Find subdomains, ports, and URLs.",
        max_iterations=150,
    )

    n_analyzer = AgentNode(
        id="analyzer_node",
        role=AgentRole.ANALYZER,
        prompt_template="Analyze the discovered attack surface for vulnerabilities and paths. Run semgrep if code exists.",
        max_iterations=100,
        depends_on=["recon_node"]
    )

    n_exploiter = AgentNode(
        id="exploiter_node",
        role=AgentRole.EXPLOITER,
        prompt_template=(
            "Test and exploit vulnerabilities found. "
            f"Additional context from parent: {prompt}" if prompt else "Focus on high-value exploits."
        ),
        max_iterations=200,
        depends_on=["analyzer_node"]
    )

    n_specialist = AgentNode(
        id="specialist_sqli",
        role=AgentRole.SPECIALIST,
        prompt_template="Focus purely on SQLi payloads against discovered parameters.",
        max_iterations=50,
        depends_on=["analyzer_node"]
    )

    n_reporter = AgentNode(
        id="reporter_node",
        role=AgentRole.REPORTER,
        prompt_template="Create final vulnerability reports for all findings in the session.",
        max_iterations=100,
        depends_on=["exploiter_node", "specialist_sqli"]
    )

    for node in [n_recon, n_analyzer, n_exploiter, n_specialist, n_reporter]:
        g.add_node(node)

    # Direct edges
    g.add_edge("recon_node", "analyzer_node")
    g.add_edge("analyzer_node", "exploiter_node")
    g.add_edge("analyzer_node", "specialist_sqli")
    g.add_edge("exploiter_node", "reporter_node")
    g.add_edge("specialist_sqli", "reporter_node")

    return g

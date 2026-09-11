from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, AsyncIterator

from .constants import AgentRole, MINI_AGENT_BLOCKED_TOOLS
from .models import AgentEvent
from .pipeline import PipelineEngine
from .session import session_to_context

logger = logging.getLogger("airecon.agent.graph")


# Load agent graph max iterations from config.py (was hardcoded)
def _get_agent_graph_max_iters() -> dict[str, int]:
    from ..config import get_config as _get_config

    cfg = _get_config()
    return {
        "recon": getattr(cfg, "agent_graph_max_iterations_recon", 150),
        "analyzer": getattr(cfg, "agent_graph_max_iterations_analyzer", 100),
        "exploiter": getattr(cfg, "agent_graph_max_iterations_exploiter", 200),
        "reporter": getattr(cfg, "agent_graph_max_iterations_reporter", 100),
    }


_AGENT_GRAPH_MAX_ITERS = _get_agent_graph_max_iters()


@dataclass
class AgentNode:
    id: str
    role: AgentRole
    prompt_template: str
    max_iterations: int = 200
    depends_on: list[str] = field(default_factory=list)


@dataclass
class AgentEdge:
    source_id: str
    target_id: str


class AgentGraph:
    def __init__(self, target: str, llm: Any = None, engine: Any = None):
        self.target = target
        self.llm = llm
        self.engine = engine
        self.nodes: dict[str, AgentNode] = {}
        self.edges: list[AgentEdge] = []

    def add_node(self, node: AgentNode) -> None:
        self.nodes[node.id] = node

    def add_edge(self, source_id: str, target_id: str) -> None:
        if source_id not in self.nodes or target_id not in self.nodes:
            raise ValueError("Source and target must exist in the graph")
        self.edges.append(AgentEdge(source_id, target_id))
        if source_id not in self.nodes[target_id].depends_on:
            self.nodes[target_id].depends_on.append(source_id)

    def execution_order(self) -> list[AgentNode]:
        visited: set[str] = set()
        in_stack: set[str] = set()
        order: list[AgentNode] = []

        def dfs(node_id: str) -> None:
            if node_id in in_stack:
                raise ValueError(
                    f"Cycle detected in agent graph involving node: {node_id!r}"
                )
            if node_id in visited:
                return
            in_stack.add(node_id)
            for dep in self.nodes[node_id].depends_on:
                if dep not in self.nodes:
                    raise ValueError(
                        f"Node {node_id!r} depends on unknown node {dep!r}"
                    )
                dfs(dep)
            in_stack.discard(node_id)
            visited.add(node_id)
            order.append(self.nodes[node_id])

        for n_id in self.nodes:
            dfs(n_id)

        return order

    async def execute(
        self, shared_session: Any, parent_context: str = ""
    ) -> AsyncIterator[AgentEvent]:
        from .loop import AgentLoop

        order = self.execution_order()

        for node in order:
            logger.info(
                "Graph orchestrator starting Node: %s (%s)",
                node.id,
                node.role.value,
            )
            yield AgentEvent(
                type="agent_state", data={"status": f"Starting {node.id}..."}
            )

            agent = AgentLoop(llm=self.llm, engine=self.engine)
            await agent.initialize(target=self.target)
            agent._override_max_iterations = node.max_iterations
            agent._blocked_tools = set(MINI_AGENT_BLOCKED_TOOLS)
            agent._session = shared_session
            agent.pipeline = PipelineEngine(shared_session)

            session_ctx = session_to_context(shared_session) if shared_session else ""

            parent_ctx = ""
            if parent_context:
                parent_ctx = (
                    f"[PARENT AGENT CONTEXT — Findings from the parent session]\n"
                    f"{parent_context}\n\n"
                    f"Use the parent's findings above as your starting point. "
                    f"DO NOT repeat work the parent already completed. "
                    f"Focus on deeper analysis, new attack vectors, or untested paths.\n\n"
                )

            prompt = (
                f"[SUBAGENT NODE: {node.id} | ROLE: {node.role.name}]\n"
                f"[Target: {self.target}]\n\n"
                + parent_ctx
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


def create_default_graph(
    target: str, prompt: str = "", recon_mode: str = "full"
) -> AgentGraph:

    g = AgentGraph(target, llm=None, engine=None)
    if recon_mode == "full":
        return _build_full_pipeline(g, target, prompt)

    return _build_single_task_node(g, target, prompt)


def _build_full_pipeline(g: AgentGraph, target: str, prompt: str) -> AgentGraph:
    n_recon = AgentNode(
        id="recon_node",
        role=AgentRole.RECON,
        prompt_template=(
            f"{prompt}\n\nPerform surface reconnaissance. Find subdomains, ports, and URLs."
            if prompt
            else "Perform surface reconnaissance. Find subdomains, ports, and URLs."
        ),
        max_iterations=_AGENT_GRAPH_MAX_ITERS.get("recon", 150),
    )

    n_analyzer = AgentNode(
        id="analyzer_node",
        role=AgentRole.ANALYZER,
        prompt_template=(
            "Analyze the discovered attack surface for vulnerabilities and paths. Run semgrep if code exists."
        ),
        max_iterations=_AGENT_GRAPH_MAX_ITERS.get("analyzer", 100),
        depends_on=["recon_node"],
    )

    n_exploiter = AgentNode(
        id="exploiter_node",
        role=AgentRole.EXPLOITER,
        prompt_template=(
            f"Test and exploit vulnerabilities found. Additional context: {prompt}"
            if prompt
            else "Focus on high-value exploits."
        ),
        max_iterations=_AGENT_GRAPH_MAX_ITERS.get("exploiter", 200),
        depends_on=["analyzer_node"],
    )

    n_reporter = AgentNode(
        id="reporter_node",
        role=AgentRole.REPORTER,
        prompt_template="Create final vulnerability reports for all findings in the session.",
        max_iterations=_AGENT_GRAPH_MAX_ITERS.get("reporter", 100),
        depends_on=["exploiter_node"],
    )

    for node in [n_recon, n_analyzer, n_exploiter, n_reporter]:
        g.add_node(node)

    g.add_edge("recon_node", "analyzer_node")
    g.add_edge("analyzer_node", "exploiter_node")
    g.add_edge("exploiter_node", "reporter_node")

    return g


def _build_single_task_node(g: AgentGraph, target: str, prompt: str) -> AgentGraph:

    if prompt:
        task_description = (
            f"{prompt}\n\n"
            f"IMPORTANT: Your scope is LIMITED to the task above. "
            f"Do NOT expand beyond what was asked. Do NOT proceed to analysis, "
            f"exploitation, or reporting unless explicitly requested. "
            f"Complete the requested task and output [TASK_COMPLETE]."
        )
    else:
        task_description = (
            "Perform surface reconnaissance. Find subdomains, ports, and URLs. "
            "When complete, output [TASK_COMPLETE]."
        )

    n_task = AgentNode(
        id="recon_node",
        role=AgentRole.RECON,
        prompt_template=task_description,
        max_iterations=150,
    )

    g.add_node(n_task)
    return g

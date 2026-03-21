"""Subagent system for airecon.

Implements two patterns:

1. SubagentCoordinator — run the default AgentGraph on a single target,
   streaming AgentEvents and persisting results to a shared SessionData.

2. ParallelAgentRunner — run SubagentCoordinator on multiple targets
   simultaneously, bounded by a semaphore for concurrency control.

For dynamic in-loop subagent spawning (specialist agents triggered by LLM),
see the `spawn_agent` tool in agent/executors.py.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from enum import Enum
from typing import Any, AsyncIterator

from ..config import get_config
from ..ollama import OllamaClient
from .models import AgentEvent
from .session import SessionData, save_session

logger = logging.getLogger("airecon.subagent")


class AgentRole(Enum):
    """Role of an agent in the subagent pipeline."""

    SCOUT = "scout"    # Fast recon and enumeration
    EXPLOIT = "exploit"  # Targeted exploitation and verification


@dataclass
class SubagentConfig:
    """Configuration for the subagent coordinator."""

    max_concurrent_agents: int = 2
    auto_exploit: bool = True


class SubagentCoordinator:
    """Coordinates Scout + Exploit agents for a single target.

    Scout runs first (recon/enumeration), passes findings to Exploit
    agent via an asyncio.Queue. Both run concurrently; exploit blocks
    until scout puts findings on the queue.
    """

    def __init__(
        self,
        engine: Any = None,
        session: SessionData | None = None,
        config: SubagentConfig | None = None,
    ):
        self.engine = engine
        self.session = session or SessionData(target="")
        self.config = config or SubagentConfig()
        self.cfg = get_config()

        # Scout → Exploit handoff channel
        self._exploit_queue: asyncio.Queue[AgentEvent] = asyncio.Queue()

        self._scout_active = False
        self._exploit_active = False
        self._stop_requested = False

    async def start_recon(
        self,
        target: str,
        prompt: str,
    ) -> AsyncIterator[AgentEvent]:
        """Start agent graph execution concurrently on target.

        Constructs an AIRecon default dependency graph (Recon -> Analyzer -> Exploiter ... -> Reporter)
        and streams findings recursively.
        """
        from .agent_graph import create_default_graph  # same package

        self.session.target = target
        logger.info(f"Starting subagent graph on {target}")

        graph = create_default_graph(target, prompt)
        graph.ollama = OllamaClient(model=self.cfg.ollama_model)

        from ..docker import DockerEngine
        graph.engine = self.engine if self.engine else DockerEngine()

        try:
            async for event in graph.execute(self.session):
                if self._stop_requested:
                    break
                # AgentLoop yields AgentEvent(type="done") when a node finishes.
                # Skip re-yielding it — we emit a single "task_complete" at the
                # end.
                if getattr(event, "type", None) == "done":
                    continue
                yield event

        except Exception as e:
            logger.error(f"AgentGraph execution failed on {target}: {e}")

        save_session(self.session)

        yield AgentEvent(
            type="task_complete",
            data={
                "session": self.session.__dict__,
                "source": AgentRole.SCOUT.value},
        )

    def stop(self) -> None:
        """Stop all running agents."""
        self._stop_requested = True
        logger.info("Subagent coordinator stopping")


class ParallelAgentRunner:
    """Run SubagentCoordinator on multiple targets simultaneously.

    Uses a semaphore to bound concurrency. Each target gets its own
    SubagentCoordinator (scout + exploit pair).

    A shared cancellation event ensures that when one agent fails,
    all sibling agents are gracefully stopped via coordinator.stop().
    """

    def __init__(self, max_concurrent: int = 3, engine: Any = None):
        self.max_concurrent = max_concurrent
        self.engine = engine
        self._active_tasks: list[asyncio.Task] = []
        self._results: dict[str, SessionData] = {}
        self._cancel_event: asyncio.Event = asyncio.Event()

    def cancel_all(self) -> None:
        """Cancel all running agent tasks immediately."""
        self._cancel_event.set()
        for task in self._active_tasks:
            task.cancel()
        logger.info(f"Cancelled {len(self._active_tasks)} active agent tasks")

    async def run_parallel(
        self,
        targets: list[str],
        prompt_template: str,
    ) -> dict[str, SessionData]:
        """Run subagent coordinator on all targets, bounded by semaphore.

        If any agent raises an unhandled exception, the shared cancel_event
        is set so that all sibling coordinators stop at their next iteration.
        """
        self._cancel_event.clear()
        self._results = {}  # Reset results so previous run data is not leaked
        semaphore = asyncio.Semaphore(self.max_concurrent)

        async def run_single(
            target: str,
            coordinator: SubagentCoordinator,
        ) -> tuple[str, SessionData]:
            async for _ in coordinator.start_recon(target, prompt_template):
                if self._cancel_event.is_set():
                    coordinator.stop()
                    break
            return target, coordinator.session

        async def bounded_run(target: str) -> tuple[str, SessionData]:
            session = SessionData(target=target)
            coordinator = SubagentCoordinator(engine=self.engine, session=session)
            async with semaphore:
                try:
                    return await run_single(target, coordinator)
                except asyncio.CancelledError:
                    raise  # Never swallow task cancellation
                except Exception as exc:
                    logger.error(
                        "Agent for %s failed: %s — setting cancel event for siblings",
                        target, exc,
                    )
                    self._cancel_event.set()
                    raise

        tasks = [asyncio.create_task(bounded_run(t)) for t in targets]
        self._active_tasks = tasks

        results = await asyncio.gather(*tasks, return_exceptions=True)
        self._active_tasks.clear()

        for result in results:
            if isinstance(result, tuple):
                target, session = result
                self._results[target] = session

        return dict(self._results)  # return a copy so callers cannot mutate internal state

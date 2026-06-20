from __future__ import annotations

import asyncio
import inspect
import logging
from dataclasses import dataclass
from typing import Any, AsyncIterator, Callable

from ..config import get_config
from ..llm import LLMClient, create_llm_client
from .constants import AgentRole
from .models import AgentEvent
from .session import SessionData, save_session

logger = logging.getLogger("airecon.subagent")


@dataclass
class SubagentConfig:
    max_concurrent_agents: int = 3
    auto_exploit: bool = True
    max_iterations_per_node: int = 100


class SubagentCoordinator:
    def __init__(
        self,
        llm: LLMClient,
        engine: Any = None,
        session: SessionData | None = None,
        config: SubagentConfig | None = None,
    ):
        self.llm = llm
        self.engine = engine
        self.session = session or SessionData(target="")
        self.config = config or SubagentConfig()
        self.cfg = get_config()
        self._exploit_queue: asyncio.Queue[AgentEvent] = asyncio.Queue()
        self._scout_active = False
        self._exploit_active = False
        self._stop_requested = False

    async def start_recon(
        self,
        target: str,
        prompt: str,
        parent_context: str = "",
        recon_mode: str = "standard",
    ) -> AsyncIterator[AgentEvent]:
        from .agent_graph import create_default_graph

        self.session.target = target
        logger.info("Starting subagent graph on %s (recon_mode=%s)", target, recon_mode)
        graph = create_default_graph(target, prompt, recon_mode=recon_mode)
        graph.llm = self.llm
        graph.engine = self.engine

        # Inject parent context into the graph's shared session
        self._parent_context = parent_context

        try:
            async for event in self._stream_graph_events(graph):
                if self._stop_requested:
                    break
                if getattr(event, "type", None) == "done":
                    continue
                yield event
        except Exception as e:
            logger.error("AgentGraph execution failed on %s: %s", target, e)
        save_session(self.session)
        yield AgentEvent(
            type="task_complete",
            data={"session": self.session.__dict__, "source": AgentRole.SCOUT.value},
        )

    async def _stream_graph_events(self, graph: Any) -> AsyncIterator[Any]:
        parent_context = getattr(self, "_parent_context", "")
        result = graph.execute(self.session, parent_context=parent_context)
        if inspect.isawaitable(result):
            result = await result
        if hasattr(result, "__aiter__"):
            async for event in result:
                yield event
            return
        if isinstance(result, (list, tuple)):
            for event in result:
                yield event
            return
        raise TypeError("graph.execute must return an async iterable or awaitable")

    def stop(self) -> None:
        self._stop_requested = True
        logger.info("Subagent coordinator stopping")


class ParallelAgentRunner:
    def __init__(
        self,
        max_concurrent: int = 3,
        engine: Any = None,
        llm: LLMClient | None = None,
    ):
        self.max_concurrent = max_concurrent
        self.engine = engine
        self._active_tasks: list[asyncio.Task] = []
        self._results: dict[str, SessionData] = {}
        self._cancel_event: asyncio.Event = asyncio.Event()
        self._llm = llm
        self._progress_callback: Any = None
        self._event_callback: Callable[[str, AgentEvent], None] | None = None

    def set_progress_callback(self, callback: Any) -> None:
        """Callback for text progress: callback(target, message)."""
        self._progress_callback = callback

    def set_event_callback(self, callback: Callable[[str, AgentEvent], None]) -> None:
        """Callback for raw AgentEvent forwarding: callback(target, event)."""
        self._event_callback = callback

    def _report_progress(self, target: str, message: str) -> None:
        if self._progress_callback:
            try:
                self._progress_callback(target, message)
            except Exception as _e:
                logger.debug("Progress callback failed: %s", _e)

    def _forward_event(self, target: str, event: AgentEvent) -> None:
        if self._event_callback:
            try:
                logger.debug(
                    "SubAgent _forward_event: target=%s, type=%s", target, event.type
                )
                self._event_callback(target, event)
            except Exception as _e:
                logger.error("SubAgent _forward_event failed: %s", _e)

    def cancel_all(self) -> None:
        self._cancel_event.set()
        for task in self._active_tasks:
            task.cancel()
        logger.info("Cancelled %d active agent tasks", len(self._active_tasks))

    async def run_parallel(
        self,
        targets: list[str],
        prompt_template: str,
        parent_context: str = "",
        recon_mode: str = "standard",
    ) -> dict[str, SessionData]:
        self._cancel_event.clear()
        self._results = {}

        llm = self._llm
        if llm is None:
            llm = create_llm_client()
            await llm._async_init()

        semaphore = asyncio.Semaphore(self.max_concurrent)
        total = len(targets)

        self._report_progress(
            "orchestrator",
            f"🚀 Launching {total} parallel agent{'s' if total != 1 else ''}...",
        )

        async def run_single(
            target: str, coordinator: SubagentCoordinator
        ) -> tuple[str, SessionData]:
            self._report_progress(target, "⏳ Waiting...")
            event_count = 0
            tool_event_count = 0

            async for event in coordinator.start_recon(
                target,
                prompt_template,
                parent_context=parent_context,
                recon_mode=recon_mode,
            ):
                if self._cancel_event.is_set():
                    coordinator.stop()
                    break
                event_count += 1

                evt_type = getattr(event, "type", "")

                # Forward tool events for TUI card rendering
                if evt_type in ("tool_start", "tool_end", "tool_output"):
                    self._forward_event(target, event)
                    tool_event_count += 1

                # Forward all text events to TUI (no filtering)
                elif evt_type == "text":
                    self._forward_event(target, event)

                elif evt_type == "task_complete":
                    self._forward_event(target, event)

                # Periodic heartbeat (every 15 events)
                # if event_count % 15 == 0:
                #    self._report_progress(target)

            vuln_count = (
                len(coordinator.session.vulnerabilities) if coordinator.session else 0
            )
            subdomain_count = (
                len(coordinator.session.subdomains) if coordinator.session else 0
            )
            url_count = len(coordinator.session.urls) if coordinator.session else 0
            tech_count = (
                len(coordinator.session.technologies) if coordinator.session else 0
            )
            summary_parts = []
            if subdomain_count:
                summary_parts.append(f"{subdomain_count} subdomains")
            if url_count:
                summary_parts.append(f"{url_count} URLs")
            if tech_count:
                summary_parts.append(f"{tech_count} techs")
            if vuln_count:
                summary_parts.append(f"{vuln_count} vulns")
            summary = ", ".join(summary_parts) if summary_parts else "no new findings"
            self._report_progress(target, f"✅ Done — {summary}")

            from .models import AgentEvent

            self._forward_event(
                target,
                AgentEvent(
                    type="task_complete",
                    data={
                        "session": coordinator.session.__dict__
                        if coordinator.session
                        else {}
                    },
                ),
            )

            return (target, coordinator.session)

        async def bounded_run(target: str) -> tuple[str, SessionData]:
            session = SessionData(target=target)
            coordinator = SubagentCoordinator(
                llm=llm, engine=self.engine, session=session
            )
            async with semaphore:
                try:
                    return await run_single(target, coordinator)
                except asyncio.CancelledError:
                    self._report_progress(target, "❌ Cancelled")
                    raise
                except Exception as exc:
                    self._report_progress(target, f"❌ Failed: {exc}")
                    logger.error(
                        "Agent for %s failed: %s — setting cancel event for siblings",
                        target,
                        exc,
                    )
                    self._cancel_event.set()
                    raise

        tasks = [asyncio.create_task(bounded_run(t)) for t in targets]
        self._active_tasks = tasks

        for t in targets:
            self._report_progress(t, "⏳ Waiting for slot...")

        results = await asyncio.gather(*tasks, return_exceptions=True)
        self._active_tasks.clear()

        completed = 0
        failed = 0
        for result in results:
            if isinstance(result, BaseException):
                logger.error("Subagent task raised exception: %s", result)
                failed += 1
                continue
            if isinstance(result, tuple):
                target, session = result
                self._results[target] = session
                completed += 1

        total_subs = sum(len(s.subdomains) for s in self._results.values())
        total_urls = sum(len(s.urls) for s in self._results.values())
        total_vulns = sum(len(s.vulnerabilities) for s in self._results.values())
        summary_parts = []
        if total_subs:
            summary_parts.append(f"{total_subs} subdomains")
        if total_urls:
            summary_parts.append(f"{total_urls} URLs")
        if total_vulns:
            summary_parts.append(f"{total_vulns} vulns")
        total_summary = ", ".join(summary_parts) if summary_parts else "done"
        self._report_progress(
            "orchestrator", f"🏁 {completed}/{total} agents finished — {total_summary}"
        )
        return dict(self._results)

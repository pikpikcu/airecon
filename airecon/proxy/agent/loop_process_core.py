from __future__ import annotations

import logging
from typing import AsyncIterator

from .loop_message_entry import _MessageEntryMixin
from .loop_tool_cycle import _ToolCycleMixin
from .models import AgentEvent

logger = logging.getLogger("airecon.agent")

try:
    from ..server import _trace_chat_event
except (ImportError, ValueError):
    try:
        from airecon.proxy.server import _trace_chat_event
    except (ImportError, ValueError):
        def _trace_chat_event(*args, **kwargs):
            pass


class _ProcessMessageCoreMixin(_MessageEntryMixin, _ToolCycleMixin):
    async def _process_message_core(self, user_message: str) -> AsyncIterator[AgentEvent]:
        trace_id = getattr(self, "_current_trace_id", None)
        if trace_id:
            _trace_chat_event(trace_id, "agent_loop_started", user_message_len=len(user_message))
        try:
            cfg = await self._prepare_message_context(user_message)
            async for event in self._run_iteration_loop(cfg):
                yield event
        except Exception as e:
            if trace_id:
                _trace_chat_event(trace_id, "agent_loop_error", error=str(e))
            logger.exception("Fatal error in agent loop")
            yield AgentEvent(
                type="error", data={"message": f"Fatal Agent Error: {str(e)}"}
            )
            yield AgentEvent(type="done", data={})
        else:
            if trace_id:
                _trace_chat_event(trace_id, "agent_loop_finished")
            # Best-effort completion notification (webhook + workspace flag).
            try:
                from ..notify import notify_completion

                _s = getattr(self, "_session", None)
                _summary = {
                    "findings": len(getattr(_s, "vulnerabilities", []) or []) if _s else 0,
                    "completed_phases": list(getattr(_s, "completed_phases", []) or []) if _s else [],
                    "iterations": getattr(self.state, "iteration", 0),
                    "scan_count": getattr(_s, "scan_count", None) if _s else None,
                }
                _target = (
                    str(getattr(_s, "target", "") or "")
                    or str(getattr(self.state, "active_target", "") or "")
                )
                if _target:
                    await notify_completion(_target, _summary)
            except Exception as _ne:
                logger.debug("completion notification skipped: %s", _ne)

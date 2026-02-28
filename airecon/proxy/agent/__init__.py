"""Agent package.

Public API (unchanged from the old monolithic agent.py):
    from airecon.proxy.agent import AgentLoop
    from airecon.proxy.agent import AgentEvent, AgentState, ToolExecution

Internal layout:
    models.py     — ToolExecution, AgentEvent, AgentState, truncate_conversation
    tool_defs.py  — get_tool_definitions() (all Ollama tool schemas)
    validators.py — _ValidatorMixin (_validate_tool_args, _check_nuclei_gate)
    formatters.py — _FormatterMixin (_smart_format_tool_result, etc.)
    workspace.py  — _WorkspaceMixin (_scan_workspace_state, _save_tool_output, etc.)
    executors.py  — _ExecutorMixin (all _execute_* methods)
    loop.py       — AgentLoop (main loop, combines all mixins)
"""

from .loop import AgentLoop
from .models import AgentEvent, AgentState, ToolExecution

__all__ = ["AgentLoop", "AgentEvent", "AgentState", "ToolExecution"]

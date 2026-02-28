from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger("airecon.agent")

MAX_TOOL_ITERATIONS = 2000


@dataclass
class ToolExecution:
    tool_name: str
    arguments: dict[str, Any]
    result: dict[str, Any] | None = None
    duration: float = 0.0
    status: str = "pending"


@dataclass
class AgentEvent:
    type: str  # "text", "tool_start", "tool_end", "error", "done", "thinking"
    data: dict[str, Any] = field(default_factory=dict)


@dataclass
class AgentState:
    conversation: list[dict[str, Any]] = field(default_factory=list)
    tool_history: list[ToolExecution] = field(default_factory=list)
    tool_counts: dict[str, int] = field(default_factory=lambda: {"exec": 0, "total": 0})
    iteration: int = 0
    max_iterations: int = MAX_TOOL_ITERATIONS
    active_target: str | None = None
    warnings_sent: bool = False
    system_prompt: dict[str, Any] | None = None
    missing_tool_count: int = 0

    def add_message(
        self,
        role: str,
        content: str,
        tool_calls: list[dict[str, Any]] | None = None,
        thinking: str | None = None,
    ) -> None:
        msg = {"role": role, "content": content}
        if tool_calls:
            msg["tool_calls"] = tool_calls
        if thinking:
            msg["thinking"] = thinking
        self.conversation.append(msg)

    def is_approaching_limit(self) -> bool:
        return self.iteration >= (self.max_iterations - 3)

    def increment_iteration(self) -> None:
        self.iteration += 1

    def truncate_conversation(self, max_messages: int = 60) -> None:
        if len(self.conversation) <= max_messages:
            return

        EPHEMERAL_PREFIXES = (
            "[SYSTEM: WORKSPACE",
            "[SYSTEM: ACTIVE_TARGET",
            "[SYSTEM: ADDITIONAL_TARGETS",
            "[SYSTEM: RECENT EXECUTIONS",
        )

        core_system: list[dict] = []
        ephemeral_system: list[dict] = []
        other_messages: list[dict] = []

        for msg in self.conversation:
            if msg.get("role") == "system":
                content = msg.get("content", "")
                if any(content.startswith(p) for p in EPHEMERAL_PREFIXES):
                    ephemeral_system.append(msg)
                else:
                    core_system.append(msg)
            else:
                other_messages.append(msg)

        # Collapse ephemeral messages to most recent only
        if ephemeral_system:
            ephemeral_system = [ephemeral_system[-1]]

        # Drop text-only assistant messages from middle first (least critical)
        assistant_text_only = [
            m for m in other_messages
            if m.get("role") == "assistant" and not m.get("tool_calls")
        ]
        if len(assistant_text_only) > 3:
            dropped_text_ids = set(id(m) for m in assistant_text_only[1:-2])
            other_messages = [m for m in other_messages if id(m) not in dropped_text_ids]

        budget = max_messages - len(core_system) - len(ephemeral_system)
        if len(other_messages) <= budget:
            self.conversation = core_system + ephemeral_system + other_messages
            logger.info(f"Truncated (text-only drop): {len(self.conversation)} messages")
            return

        # Still over budget — keep first user msg + tail of remaining
        must_keep = []
        can_trim = []
        first_user_seen = False

        for msg in other_messages:
            if msg.get("role") == "user" and not first_user_seen:
                must_keep.append(msg)
                first_user_seen = True
            else:
                can_trim.append(msg)

        tail_budget = max(budget - len(must_keep), 10)
        dropped_count = max(0, len(can_trim) - tail_budget)
        trimmed = can_trim[-tail_budget:] if len(can_trim) > tail_budget else can_trim

        separator = {
            "role": "system",
            "content": (
                f"[SYSTEM: {dropped_count} older messages removed to manage context. "
                "Tool results and findings are preserved in the most recent messages below. "
                "The original user request is preserved above.]"
            ),
        }

        rebuilt = must_keep + ([separator] if dropped_count > 0 else []) + trimmed
        self.conversation = core_system + ephemeral_system + rebuilt
        logger.info(
            f"Truncated (evidence-preserving): {len(self.conversation)} messages "
            f"(dropped {dropped_count} older messages)"
        )

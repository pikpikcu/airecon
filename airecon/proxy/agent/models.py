from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger("airecon.agent")

MAX_TOOL_ITERATIONS = 2000
MAX_TOOL_HISTORY = 100


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

        # Cap tool_history to prevent unbounded memory growth
        if len(self.tool_history) > MAX_TOOL_HISTORY:
            self.tool_history = self.tool_history[-MAX_TOOL_HISTORY:]

    def is_approaching_limit(self) -> bool:
        return self.iteration >= (self.max_iterations - 3)

    def increment_iteration(self) -> None:
        self.iteration += 1

    def truncate_conversation(self, max_messages: int = 50) -> None:
        if len(self.conversation) <= max_messages:
            return

        EPHEMERAL_PREFIXES = (
            "[SYSTEM: WORKSPACE",
            "[SYSTEM: ACTIVE_TARGET",
            "[SYSTEM: ADDITIONAL_TARGETS",
            "[SYSTEM: RECENT EXECUTIONS",
            "[SYSTEM: EVALUATION CHECKPOINT",
            "[SYSTEM: MANDATORY PLANNING",
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

        # STEP 1: Compress verbose tool results in older messages
        # Keep last 20 messages uncompressed, compress older ones
        compress_boundary = max(0, len(other_messages) - 20)
        for i in range(compress_boundary):
            msg = other_messages[i]
            content = msg.get("content", "")
            role = msg.get("role", "")

            # Compress tool results to 1-line summaries
            if role == "tool" and len(content) > 200:
                # Extract key info
                if "COMMAND FAILED" in content:
                    first_line = content.split("\n")[0]
                    msg["content"] = f"[COMPRESSED] {first_line}"
                elif "TOTAL:" in content:
                    # Find the TOTAL line
                    for line in content.split("\n"):
                        if "TOTAL:" in line:
                            msg["content"] = f"[COMPRESSED] {line.strip()}"
                            break
                elif "Success" in content[:50]:
                    first_line = content.split("\n")[0]
                    msg["content"] = f"[COMPRESSED] {first_line[:150]}"
                else:
                    msg["content"] = f"[COMPRESSED] Tool result ({len(content)} chars)"

            # Compress verbose assistant text (not tool calls)
            elif role == "assistant" and not msg.get("tool_calls") and len(content) > 500:
                msg["content"] = content[:200] + "... [truncated]"

        # STEP 2: Drop text-only assistant messages from middle (least critical)
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
            logger.info(f"Truncated (compressed + text-drop): {len(self.conversation)} messages")
            return

        # STEP 3: Pair-aware truncation — keep assistant+tool_calls with their tool responses
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
        if len(can_trim) > tail_budget:
            tail = can_trim[-tail_budget:]
            # Ensure we don't start mid-pair: if tail starts with a 'tool' message,
            # include the preceding assistant message to keep the pair intact.
            start_idx = len(can_trim) - tail_budget
            while start_idx > 0 and tail and tail[0].get("role") == "tool":
                start_idx -= 1
                tail = can_trim[start_idx:]
            trimmed = tail
            dropped_count = len(can_trim) - len(trimmed)
        else:
            trimmed = can_trim
            dropped_count = 0

        separator = {
            "role": "system",
            "content": (
                f"[SYSTEM: {dropped_count} older messages compressed/removed to manage context. "
                "Key findings are preserved in the session summary. "
                "The original user request is preserved above.]"
            ),
        }

        rebuilt = must_keep + ([separator] if dropped_count > 0 else []) + trimmed
        self.conversation = core_system + ephemeral_system + rebuilt
        logger.info(
            f"Truncated (pair-preserving): {len(self.conversation)} messages "
            f"(dropped {dropped_count} older messages)"
        )


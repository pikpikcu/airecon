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
    tool_counts: dict[str, int] = field(
        default_factory=lambda: {"exec": 0, "total": 0, "subagents": 0})
    token_usage: dict[str, int] = field(
        default_factory=lambda: {"used": 0, "limit": 65536})
    skills_used: list[str] = field(default_factory=list)
    planned_tools: list[str] = field(
        default_factory=list
    )  # Track tools mentioned in plan
    iteration: int = 0
    max_iterations: int = MAX_TOOL_ITERATIONS
    active_target: str | None = None
    warnings_sent: bool = False
    # system_prompt: dict[str, Any] | None = None
    missing_tool_count: int = 0

    def add_message(
        self,
        role: str,
        content: str,
        tool_calls: list[dict[str, Any]] | None = None,
        thinking: str | None = None,
    ) -> None:
        msg: dict[str, Any] = {"role": role, "content": content}
        if tool_calls:
            msg["tool_calls"] = tool_calls
        if thinking:
            msg["thinking"] = thinking
        self.conversation.append(msg)

        # Cap tool_history to prevent unbounded memory growth
        if len(self.tool_history) > MAX_TOOL_HISTORY:
            self.tool_history = self.tool_history[-MAX_TOOL_HISTORY:]

        # Truncate oversized result strings in the oldest entries to cap memory usage
        _MAX_RESULT_CHARS = 50_000
        for entry in self.tool_history:
            if entry.result and isinstance(entry.result, dict):
                for k, v in entry.result.items():
                    if isinstance(v, str) and len(v) > _MAX_RESULT_CHARS:
                        entry.result[k] = v[:_MAX_RESULT_CHARS] + " ... [TRUNCATED]"

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
            "[SYSTEM: PREVIOUS SESSION DATA",
            "[SYSTEM: CRITICAL FINDINGS",
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
            elif (
                role == "assistant" and not msg.get(
                    "tool_calls") and len(content) > 500
            ):
                msg["content"] = content[:200] + "... [truncated]"

        # STEP 2: Drop text-only assistant messages from middle (least
        # critical)
        assistant_text_only = [
            m
            for m in other_messages
            if m.get("role") == "assistant" and not m.get("tool_calls")
        ]
        if len(assistant_text_only) > 3:
            dropped_text_ids = set(id(m) for m in assistant_text_only[1:-2])
            other_messages = [
                m for m in other_messages if id(m) not in dropped_text_ids
            ]

        budget = max_messages - len(core_system) - len(ephemeral_system)
        if len(other_messages) <= budget:
            self.conversation = core_system + ephemeral_system + other_messages
            logger.info(
                f"Truncated (compressed + text-drop): {len(self.conversation)} messages"
            )
            return

        # STEP 3: Pair-aware truncation — keep assistant+tool_calls with their
        # tool responses
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

        rebuilt = must_keep + \
            ([separator] if dropped_count > 0 else []) + trimmed
        self.conversation = core_system + ephemeral_system + rebuilt
        logger.info(
            f"Truncated (pair-preserving): {len(self.conversation)} messages "
            f"(dropped {dropped_count} older messages)"
        )

    # ------------------------------------------------------------------
    # Smart context compression helper (Priority 5)
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_key_info(content: str, max_chars: int = 500) -> str:
        """Extract high-priority lines from tool output rather than dumb truncation.

        Priority order (all that match are kept, up to max_chars):
          1. FLAG{...} / flag{...} patterns                — always preserved
          2. HTTP status lines (HTTP/1.1 200, etc.)        — discovery evidence
          3. URLs (https?://...)                           — endpoint discovery
          4. Lines containing key security-relevant words  — error/success/token/cred
          5. Remaining content (first N chars)             — fill remaining budget
        """
        import re as _re
        PRIORITY_PATTERNS = [
            _re.compile(r"FLAG\{[^}]+\}", _re.IGNORECASE),
            _re.compile(r"HTTP/[\d.]+ \d+"),
            _re.compile(r"https?://\S+"),
            _re.compile(
                r"(?i)(error|found|success|failed|token|secret|password|key|"
                r"admin|root|flag|credential|auth|login|cookie|session)"
            ),
        ]

        priority_lines: list[str] = []
        seen: set[str] = set()
        for line in content.split("\n"):
            stripped = line.strip()
            if not stripped or stripped in seen:
                continue
            if any(p.search(stripped) for p in PRIORITY_PATTERNS):
                priority_lines.append(stripped)
                seen.add(stripped)

        # Build result: priority lines first, then fallback to raw start
        key_part = "\n".join(priority_lines[:30])  # max 30 priority lines
        if len(key_part) >= max_chars:
            return key_part[:max_chars]

        remaining = max_chars - len(key_part)
        filler = content[:remaining].strip()
        if key_part and filler:
            return key_part + "\n" + filler
        return (key_part or filler)[:max_chars]

    async def compress_with_llm(self, ollama: Any,
                                keep_recent: int = 30) -> None:
        """Compress old messages via LLM summarization when conversation grows large.

        Trigger: conversation > 80 messages (non-system).
        Strategy:
        - Keep all system messages untouched
        - Keep first user message (original task)
        - Keep last `keep_recent` messages verbatim
        - Summarize everything in between in chunks of 10
        - Preserves: URLs, vulns, credentials, tool outputs, phase info
        - Fallback: keeps original chunk if LLM call fails
        """
        non_system = [
            m for m in self.conversation if m.get("role") != "system"]
        if len(non_system) <= keep_recent + 1:
            return  # Not enough messages to compress

        system_msgs = [
            m for m in self.conversation if m.get("role") == "system"]
        first_user = non_system[0]
        to_compress = non_system[1: len(non_system) - keep_recent]
        keep_tail = non_system[len(non_system) - keep_recent:]

        if len(to_compress) < 5:
            return  # Too few to bother compressing

        CHUNK_SIZE = 10
        summaries: list[dict[str, Any]] = []

        for i in range(0, len(to_compress), CHUNK_SIZE):
            chunk = to_compress[i: i + CHUNK_SIZE]
            chunk_text = "\n\n".join(
                f"[{m.get('role', 'unknown').upper()}]: "
                + AgentState._extract_key_info(str(m.get("content", "")), 500)
                for m in chunk
            )
            prompt = [
                {
                    "role": "system",
                    "content": (
                        "You are a memory compressor for an AI security testing agent. "
                        "Summarize the following conversation chunk in 3-5 dense sentences. "
                        "Preserve ALL of: discovered URLs, subdomains, open ports, "
                        "credentials/tokens found, confirmed vulnerability findings, "
                        "key tool outputs, and current testing phase. "
                        "Be specific and technical — no vague descriptions."
                    ),
                },
                {"role": "user", "content": chunk_text},
            ]

            # Extract flags directly to ensure they are never lost
            extracted_flags = []
            for m in chunk:
                content = str(m.get("content", ""))
                import re
                flags = re.findall(r"FLAG\{[^\}]+\}", content)
                flags.extend(re.findall(r"flag\{[^\}]+\}", content))
                if flags:
                    extracted_flags.extend(flags)

            # Deduplicate flags
            extracted_flags = list(set(extracted_flags))

            try:
                summary_text = await ollama.complete(prompt)

                # Append extracted flags to summary to guarantee they survive
                if extracted_flags:
                    summary_text += "\n\n[CRITICAL PRESERVED DATA]\nFlags found: " + \
                        ", ".join(extracted_flags)

                summaries.append({
                    "role": "system",
                    "content": (
                        f"[COMPRESSED MEMORY — {len(chunk)} messages]: {summary_text}"
                    ),
                })
            except Exception as e:
                logger.warning(
                    f"Memory compression LLM call failed, keeping original: {e}")
                summaries.extend(chunk)  # Fallback: keep originals

        before = len(self.conversation)
        self.conversation = system_msgs + [first_user] + summaries + keep_tail
        logger.info(
            f"Memory compressed: {len(to_compress)} messages → {len(summaries)} summaries "
            f"({before} → {len(self.conversation)} total)"
        )

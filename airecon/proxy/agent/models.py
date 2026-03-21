from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger("airecon.agent")

MAX_TOOL_ITERATIONS = 2000
MAX_TOOL_HISTORY = 100
MAX_OBJECTIVES = 64
MAX_EVIDENCE = 200
FLAG_PATTERN = re.compile(r"flag\{[^}]+\}", re.IGNORECASE)

# Jaccard similarity threshold for evidence deduplication.
# Two evidence entries with token-overlap >= this value are treated as duplicates.
# 0.70 is more forgiving than 0.75 — reduces false-negatives where the same
# finding is described with slightly different wording (e.g. word order swap).
_EVIDENCE_SIMILARITY_THRESHOLD: float = 0.70


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
        default_factory=lambda: {
            "used": 0,
            "limit": 65536,
            "cumulative": 0,
            "cumulative_prompt": 0,
            "cumulative_completion": 0,
            "last_prompt": 0,
            "last_completion": 0,
        }
    )
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
    objective_queue: list[dict[str, Any]] = field(default_factory=list)
    evidence_log: list[dict[str, Any]] = field(default_factory=list)
    # Tracks cumulative tool usage per pipeline phase for soft budget enforcement.
    # Structure: {phase_name: {tool_name: call_count}}
    phase_tool_usage: dict[str, dict[str, int]] = field(default_factory=dict)

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

        # Truncate oversized result strings — only scan when history is large enough
        # to matter, and only touch entries that were just pushed into the trim zone.
        if len(self.tool_history) > 50:
            _MAX_RESULT_CHARS = 50_000
            for entry in self.tool_history:
                if entry.result and isinstance(entry.result, dict):
                    for k, v in entry.result.items():
                        if isinstance(v, str) and len(v) > _MAX_RESULT_CHARS:
                            entry.result[k] = v[:_MAX_RESULT_CHARS] + " ... [TRUNCATED]"

    def ensure_phase_objectives(
        self, phase: str, defaults: list[str]
    ) -> None:
        """Ensure default objectives exist for the given phase."""
        if not defaults:
            return

        existing = {
            str(obj.get("title", "")).strip().lower()
            for obj in self.objective_queue
            if str(obj.get("phase", "")).upper() == phase.upper()
        }
        for idx, title in enumerate(defaults):
            key = title.strip().lower()
            if key in existing:
                continue
            self.objective_queue.append(
                {
                    "phase": phase.upper(),
                    "title": title,
                    "status": "pending",
                    "priority": max(1, 100 - (idx * 10)),
                    "updated_iteration": self.iteration,
                    "updated_at": datetime.now(timezone.utc).isoformat(),
                }
            )

        if len(self.objective_queue) > MAX_OBJECTIVES:
            self.objective_queue = self.objective_queue[-MAX_OBJECTIVES:]

    def mark_objective(
        self,
        phase: str,
        title: str,
        status: str = "done",
        note: str | None = None,
    ) -> None:
        """Update an objective status for a given phase/title."""
        norm_phase = phase.upper()
        norm_title = title.strip().lower()
        now = datetime.now(timezone.utc).isoformat()
        for obj in self.objective_queue:
            if (
                str(obj.get("phase", "")).upper() == norm_phase
                and str(obj.get("title", "")).strip().lower() == norm_title
            ):
                obj["status"] = status
                obj["updated_iteration"] = self.iteration
                obj["updated_at"] = now
                if note:
                    obj["note"] = note
                return

    @staticmethod
    def _jaccard_similarity(a: str, b: str) -> float:
        """Token-overlap (Jaccard) similarity between two strings.

        Tokenizes on whitespace and lowercases both strings.
        Returns 0.0 when either input is empty.
        """
        tokens_a = set(a.lower().split())
        tokens_b = set(b.lower().split())
        if not tokens_a or not tokens_b:
            return 0.0
        return len(tokens_a & tokens_b) / len(tokens_a | tokens_b)

    def add_evidence(
        self,
        phase: str,
        source_tool: str,
        summary: str,
        confidence: float = 0.70,
        artifact: str | None = None,
        tags: list[str] | None = None,
    ) -> bool:
        """Record deduplicated evidence from real tool output.

        Returns True if the evidence was added, False if it was rejected as a
        duplicate (exact match or Jaccard similarity >= threshold within the
        same phase).
        """
        clean_summary = " ".join(str(summary).strip().split())
        if not clean_summary:
            return False

        phase_key = phase.upper()
        tags = tags or []
        dedup_key = (
            phase_key,
            source_tool.strip().lower(),
            clean_summary.lower(),
            (artifact or "").strip().lower(),
        )

        summary_lower = clean_summary.lower()
        for existing in self.evidence_log:
            # Fast path: exact tuple match (all fields identical)
            prev_key = (
                str(existing.get("phase", "")).upper(),
                str(existing.get("source_tool", "")).strip().lower(),
                str(existing.get("summary", "")).strip().lower(),
                str(existing.get("artifact", "")).strip().lower(),
            )
            if dedup_key == prev_key:
                return False

            # Semantic path: Jaccard similarity on summary within same phase.
            # Cross-phase entries are allowed (RECON and EXPLOIT can have
            # similar summaries for different reasons).
            if str(existing.get("phase", "")).upper() != phase_key:
                continue
            existing_summary = str(existing.get("summary", "")).strip().lower()
            if self._jaccard_similarity(summary_lower, existing_summary) >= _EVIDENCE_SIMILARITY_THRESHOLD:
                logger.debug(
                    "Evidence dedup (semantic): '%s...' ~ '%s...'",
                    summary_lower[:40],
                    existing_summary[:40],
                )
                return False

        self.evidence_log.append(
            {
                "phase": phase_key,
                "source_tool": source_tool,
                "summary": clean_summary[:600],
                "confidence": max(0.0, min(float(confidence), 1.0)),
                "artifact": artifact,
                "tags": tags,
                "iteration": self.iteration,
                "created_at": datetime.now(timezone.utc).isoformat(),
            }
        )
        if len(self.evidence_log) > MAX_EVIDENCE:
            # Prioritized truncation: keep high-confidence entries regardless of
            # age.  Pure FIFO ([-MAX_EVIDENCE:]) would silently discard early
            # high-value findings (e.g. a confirmed SQLi found at iteration 5)
            # when the evidence log fills up after 200+ iterations.
            # Strategy: use heapq.nlargest to pick top MAX_EVIDENCE by confidence
            # in O(n log k), then restore chronological order so context injection
            # stays coherent. Avoids two full sorts on the whole list.
            import heapq
            kept = heapq.nlargest(
                MAX_EVIDENCE,
                self.evidence_log,
                key=lambda e: float(e.get("confidence", 0.0)),
            )
            kept.sort(key=lambda e: int(e.get("iteration", 0)))
            self.evidence_log = kept
        return True

    def record_tool_use(self, phase: str, tool_name: str) -> None:
        """Increment per-phase tool usage counter for budget tracking."""
        bucket = self.phase_tool_usage.setdefault(phase, {})
        bucket[tool_name] = bucket.get(tool_name, 0) + 1

    def get_phase_tool_count(self, phase: str, tool_name: str) -> int:
        """Return how many times tool_name was used in the given phase."""
        return self.phase_tool_usage.get(phase, {}).get(tool_name, 0)

    def get_phase_context(
        self,
        phase: str,
        max_objectives: int = 4,
        max_evidence: int = 6,
        filter_evidence_by_phase: bool = True,
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
        """Return (pending, completed, evidence) for a given phase."""
        phase_key = phase.upper()

        pending = [
            o for o in self.objective_queue
            if str(o.get("phase", "")).upper() == phase_key
            and str(o.get("status", "pending")).lower() != "done"
        ]
        pending = sorted(
            pending, key=lambda x: int(x.get("priority", 0)), reverse=True
        )[:max_objectives]

        completed = [
            o for o in self.objective_queue
            if str(o.get("phase", "")).upper() == phase_key
            and str(o.get("status", "")).lower() == "done"
        ][:max_objectives]

        # Only surface evidence with meaningful confidence to avoid cluttering
        # the LLM context with low-signal noise (e.g. bare execute traces).
        _CONF_FLOOR = 0.65
        if filter_evidence_by_phase:
            evidence = [
                e for e in reversed(self.evidence_log)
                if str(e.get("phase", "")).upper() == phase_key
                and float(e.get("confidence", 1.0)) >= _CONF_FLOOR
            ][:max_evidence]
        else:
            evidence = [
                e for e in reversed(self.evidence_log)
                if float(e.get("confidence", 1.0)) >= _CONF_FLOOR
            ][:max_evidence]

        return pending, completed, evidence

    def build_focus_context(
        self,
        phase: str,
        max_objectives: int = 4,
        max_evidence: int = 6,
    ) -> str:
        """Create objective+evidence context to keep the LLM execution-focused."""
        phase_key = phase.upper()

        pending, completed, evidence = self.get_phase_context(
            phase_key, max_objectives=max_objectives, max_evidence=max_evidence
        )

        if not pending and not evidence and not completed:
            return ""

        lines = [f"[SYSTEM: OBJECTIVE FOCUS — PHASE {phase_key}]"]
        if pending:
            lines.append("Pending objectives:")
            for obj in pending:
                lines.append(f"- {obj.get('title', '')}")
        if completed:
            lines.append("Completed objectives:")
            for obj in completed:
                lines.append(f"- {obj.get('title', '')}")
        if evidence:
            lines.append("Recent evidence:")
            for ev in evidence:
                src = ev.get("source_tool", "tool")
                summary = ev.get("summary", "")
                artifact = ev.get("artifact")
                artifact_note = f" [{artifact}]" if artifact else ""
                lines.append(f"- [{src}] {summary}{artifact_note}")

        lines.append(
            "MANDATORY: pick one pending objective OR run one high-value novel hypothesis, then call the best next tool now."
        )
        return "\n".join(lines)

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
            "[SYSTEM: OBJECTIVE FOCUS",
            "[SYSTEM: PHASE GATE",
            "[SYSTEM: AGGRESSIVE EXPLORATION",
            "[SYSTEM: QUALITY SCOREBOARD",
        )
        # These prefixes carry recovery/orientation state that must survive
        # across truncations — never collapse them to a single message.
        PROTECTED_PREFIXES = (
            "[SYSTEM: RECOVERY STATE",
            "[SYSTEM: PINNED CONTEXT",
            "[SYSTEM: RECOVERY MODE",
        )

        core_system: list[dict] = []
        ephemeral_system: list[dict] = []
        protected_system: list[dict] = []
        other_messages: list[dict] = []

        for msg in self.conversation:
            if msg.get("role") == "system":
                content = msg.get("content", "")
                if any(content.startswith(p) for p in PROTECTED_PREFIXES):
                    protected_system.append(msg)
                elif any(content.startswith(p) for p in EPHEMERAL_PREFIXES):
                    ephemeral_system.append(msg)
                else:
                    core_system.append(msg)
            else:
                other_messages.append(msg)

        # Collapse ephemeral messages to most recent only (they're regenerated
        # each iteration). Protected messages are kept in full.
        if ephemeral_system:
            ephemeral_system = [ephemeral_system[-1]]
        # Keep at most the 2 most recent protected messages to bound context.
        if len(protected_system) > 2:
            protected_system = protected_system[-2:]

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

        budget = max_messages - len(core_system) - len(ephemeral_system) - len(protected_system)
        if len(other_messages) <= budget:
            self.conversation = core_system + ephemeral_system + protected_system + other_messages
            logger.info("Truncated (compressed + text-drop): %d messages", len(self.conversation))
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
        self.conversation = core_system + ephemeral_system + protected_system + rebuilt
        logger.info(
            "Truncated (pair-preserving): %d messages (dropped %d older messages)",
            len(self.conversation), dropped_count,
        )

    # ------------------------------------------------------------------
    # Smart context compression helper (Priority 5)
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_flags(content: str) -> list[str]:
        """Return unique FLAG{...} values found in content."""
        return list({m.group(0) for m in FLAG_PATTERN.finditer(content)})

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
        PRIORITY_PATTERNS = [
            FLAG_PATTERN,
            re.compile(r"HTTP/[\d.]+ \d+"),
            re.compile(r"https?://\S+"),
            re.compile(
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

    async def compress_with_llm(
        self,
        ollama: Any,
        keep_recent: int = 30,
        num_ctx: int = 8192,
        num_predict: int = 1024,
    ) -> None:
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
            extracted_flags: list[str] = []
            for m in chunk:
                content = str(m.get("content", ""))
                extracted_flags.extend(AgentState._extract_flags(content))

            extracted_flags = list(set(extracted_flags))

            try:
                summary_text = await ollama.complete(
                    prompt,
                    options={"num_ctx": num_ctx, "num_predict": num_predict, "temperature": 0.1},
                )

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
                logger.warning("Memory compression LLM call failed, keeping original: %s", e)
                summaries.extend(chunk)  # Fallback: keep originals

        before = len(self.conversation)
        self.conversation = system_msgs + [first_user] + summaries + keep_tail
        logger.info(
            "Memory compressed: %d messages → %d summaries (%d → %d total)",
            len(to_compress), len(summaries), before, len(self.conversation),
        )

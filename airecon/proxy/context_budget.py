"""Local, recoverable output compression and provider-independent request budgeting.

RTK and Caveman are optional native executables, never command rewriters or LLM
proxies here. Raw evidence is committed before any lossy model-visible preview.
"""
from __future__ import annotations

import copy
import hashlib
import json
import logging
import os
from pathlib import Path
import re
import shutil
import subprocess
from typing import Any

from .llm import _to_openai_messages

logger = logging.getLogger("airecon.compression")
_IMPORTANT = re.compile(
    r"(?i)\b(error|failed|failure|fatal|critical|high|warning|traceback|"
    r"CVE-\d{4}-\d+|vulnerab\w*|injection|sqli|xss|ssrf|rce|flag|exit.code)\b"
)
_ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
_PREVIEW_HEADER = "[Compacted preview; omitted content is NOT a clean scan]\n"


class ContextBudgetError(RuntimeError):
    """The request cannot fit without deleting mandatory instructions/schemas."""


def request_chars(
    messages: list[dict[str, Any]], tools: list[dict] | None,
    *, replay_reasoning: bool | None = None,
) -> int:
    """Serialized UTF-8 bytes, not a claim of exact model tokenization.

    ``replay_reasoning`` selects the reasoning-replay policy of the
    measurement: pass the ACTIVE client's policy (as ``LLMClient._wire_payload``
    resolves it from its own model + host) so the budget matches what is
    actually sent. ``None`` keeps the legacy behavior of resolving the policy
    from the global config for callers that have no client at hand.
    """
    from .config import get_config
    if str(getattr(get_config(), "llm_provider", "openai")).lower() in ("anthropic", "claude"):
        from .llm_protocol import anthropic_messages, anthropic_tools
        system, converted = anthropic_messages(messages)
        body = {"system": system, "messages": converted, "tools": anthropic_tools(tools)}
    else:
        body = {
            "messages": _to_openai_messages(messages, replay_reasoning=replay_reasoning),
            "tools": tools or [],
        }
    return len(json.dumps(
        body,
        ensure_ascii=False,
    ).encode("utf-8"))


def estimate_request_tokens(
    messages: list[dict[str, Any]], tools: list[dict] | None,
    *, replay_reasoning: bool | None = None,
) -> int:
    # Conservative heuristic, including JSON framing, schemas and call arguments.
    if not messages and not tools:
        return 0
    return (request_chars(messages, tools, replay_reasoning=replay_reasoning) + 2) // 3


def _clip(text: str, size: int) -> str:
    return text.encode("utf-8")[:max(0, size)].decode("utf-8", errors="ignore")


class ArtifactCompressor:
    def __init__(
        self, root: Path, session_id: str = "session", *,
        rtk: str | None = None, caveman: str | None = None,
    ) -> None:
        self.root = root.resolve()
        session_key = hashlib.sha256(session_id.encode()).hexdigest()[:16]
        self.directory = Path("output") / "context" / session_key
        self.last_backend = "builtin"
        self.rtk = self._binary(rtk, "rtk", "AIRECON_RTK_BIN")
        self.caveman = self._binary(caveman, "caveman-engine", "AIRECON_CAVEMAN_BIN")

    @staticmethod
    def _binary(explicit: str | None, name: str, env: str) -> str | None:
        if explicit is not None:
            return explicit or None
        configured = os.getenv(env)
        if configured:
            if configured.lower() == "off":
                return None
            return configured
        managed = Path.home() / ".airecon" / "bin" / name
        return str(managed) if managed.is_file() else shutil.which(name)

    def _path(self, reference: str) -> Path:
        path = (self.root / reference).resolve()
        if not path.is_relative_to(self.root) or not Path(reference).is_relative_to(self.directory):
            raise OSError("Compression artifact outside session workspace")
        return path

    def save(self, text: str) -> str:
        raw = text.encode("utf-8")
        digest = hashlib.sha256(raw).hexdigest()
        reference = (self.directory / f"{digest}.txt").as_posix()
        path = self._path(reference)
        path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            if path.read_bytes() != raw:
                raise OSError("Compression artifact checksum mismatch")
        else:
            try:
                with os.fdopen(fd, "wb") as stream:
                    stream.write(raw)
                    stream.flush()
                    os.fsync(stream.fileno())
            except BaseException:
                path.unlink(missing_ok=True)
                raise
        return reference

    def load(self, reference: str) -> str:
        path = self._path(reference)
        raw = path.read_bytes()
        if hashlib.sha256(raw).hexdigest() != path.stem:
            raise OSError("Compression artifact checksum mismatch")
        return raw.decode("utf-8")

    def _external(self, text: str) -> str:
        runtime = self.root / self.directory / ".runtime"
        runtime.mkdir(parents=True, mode=0o700, exist_ok=True)
        (runtime / "caveman").mkdir(mode=0o700, exist_ok=True)
        env = dict(os.environ, DO_NOT_TRACK="1", HOME=str(runtime),
                   XDG_CONFIG_HOME=str(runtime / "config"),
                   XDG_DATA_HOME=str(runtime / "data"),
                   CAVEMAN_HOME=str(runtime / "caveman"),
                   CAVEMAN_CCR_DB=str(runtime / "caveman" / "ccr.db"))
        # RTK's dev-output filters and Caveman's structural engine are alternatives,
        # not two lossy passes over one another's output.
        dev_output = bool(re.search(r"(?i)pytest|test session starts|cargo test|diff --git", text[:2000]))
        candidates = [("rtk", self.rtk, ["pipe"]), ("caveman", self.caveman, ["compress"])]
        if not dev_output:
            candidates.reverse()
        for backend, binary, args in candidates:
            if not binary:
                continue
            try:
                run = subprocess.run(  # nosec B603 — fixed argv, no shell or commands from output
                    [binary, *args], input=text, text=True, encoding="utf-8",
                    errors="strict", capture_output=True, timeout=3,
                    cwd=runtime, env=env,
                )
                if run.returncode == 0 and run.stdout.strip() and len(run.stdout.encode()) < len(text.encode()):
                    self.last_backend = backend
                    return run.stdout
            except (OSError, subprocess.TimeoutExpired, UnicodeError) as exc:
                logger.warning("%s compressor unavailable: %s", backend, type(exc).__name__)
        self.last_backend = "builtin"
        return text

    def preview(
        self, text: str, limit: int, *, reference: str | None = None,
        external: bool = True,
    ) -> tuple[str, str]:
        raw = self.load(reference) if reference else text
        reference = reference or self.save(raw)
        footer = (
            f'\n[Full output: read_file path="{reference}" offset=0 limit=100; '
            f"sha256={Path(reference).stem}]"
        )
        header = _PREVIEW_HEADER
        budget = limit - len((header + footer).encode())
        if budget < 32:
            raise ContextBudgetError("Context budget too small for a recoverable tool result")
        candidate = self._external(raw) if external else raw
        candidate = _ANSI.sub("", candidate)
        if len(candidate.encode()) <= budget and all(
            line in candidate for line in raw.splitlines() if _IMPORTANT.search(line)
        ):
            body = candidate
        else:
            # Findings anywhere in the output get priority over head/tail noise.
            lines = raw.splitlines()
            choices = [line for line in lines if _IMPORTANT.search(line)]
            choices += candidate.splitlines()[:4] + candidate.splitlines()[-4:]
            kept: list[str] = []
            seen: set[str] = set()
            remaining = budget - len("\n... [content omitted; retrieve original]".encode())
            for line in choices:
                if line in seen:
                    continue
                seen.add(line)
                cost = len(line.encode()) + 1
                if cost <= remaining:
                    kept.append(line)
                    remaining -= cost
            if not kept:
                kept.append(_clip(candidate, remaining))
            body = "\n".join(kept) + "\n... [content omitted; retrieve original]"
        return header + body + footer, reference


def _pinned(message: dict[str, Any]) -> bool:
    """`_protected` evidence that must stay in the request.

    Signed assistant turns are stored `_protected` so nothing rewrites their
    provider blocks, but they are history, not instructions: an older one is
    evicted whole with its results and the latest is kept as the latest group.
    """
    signed_turn = message.get("role") == "assistant" and message.get("_provider_blocks")
    return bool(message.get("_protected")) and not signed_turn


def _mandatory_messages(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Instructions and user constraints that must never be dropped or rewritten."""
    return [
        m for m in messages
        if (
            m.get("role") in ("system", "user")
            and not m.get("_tool_result")
            and not m.get("_archive_notice")
        )
        or _pinned(m)
    ]


_ARCHIVE_NOTICE_PREFIX = "[Older tool groups archived under "


def _is_archive_notice(message: dict[str, Any]) -> bool:
    """pack_history's notice, including the assistant-role form older sessions saved."""
    if message.get("_archive_notice"):
        return True
    return (
        message.get("role") == "assistant"
        and not message.get("tool_calls")
        and not message.get("_provider_blocks")
        and str(message.get("content") or "").startswith(_ARCHIVE_NOTICE_PREFIX)
    )


def _latest_real_assistant_index(messages: list[dict[str, Any]]) -> int:
    """Index of the last real assistant turn; archive notices never count.

    Tool-argument reservation must key on the last REAL tool-call turn, or a
    second budget pass would spend its reservation on the wrong message.
    """
    return max(
        (
            i for i, message in enumerate(messages)
            if message.get("role") == "assistant" and not _is_archive_notice(message)
        ),
        default=-1,
    )


def _place_archive_notice(messages: list[dict[str, Any]], content: str) -> list[dict[str, Any]]:
    """One system-role notice, just before the latest real group."""
    notice = {"role": "system", "_archive_notice": True, "content": content}
    insert_at = _latest_real_assistant_index(messages)
    out = list(messages)
    out.insert(insert_at if insert_at >= 0 else len(out), notice)
    return out


# pack_history's preview caps, largest first; the last is the smallest form a
# tool result can take in the request.
_PREVIEW_CAPS: tuple[int, ...] = (3000, 1500, 750, 400)
# Reserved in place of a result pack_history may compact: no string of
# _PREVIEW_CAPS[-1] UTF-8 bytes serializes larger than that many control
# characters (1 byte raw, 6 JSON-escaped).
_SMALLEST_PREVIEW_STAND_IN = "\x00" * _PREVIEW_CAPS[-1]


def _minimum_request_messages(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Reserve the whole latest group before spending space on optional schemas.

    Exact results (read_file, provider blocks, pinned evidence) are reserved as
    they are. Any other result is reserved at the upper bound of its smallest
    preview, whether or not it was compacted yet, so a second budget pass
    reserves the same space and keeps the same schemas.
    """
    mandatory_ids = {id(message) for message in _mandatory_messages(messages)}
    required = {i for i, message in enumerate(messages) if id(message) in mandatory_ids}
    stand_ins: dict[int, dict[str, Any]] = {}
    latest = _latest_real_assistant_index(messages)
    if latest >= 0:
        required.add(latest)  # Tool arguments and signed blocks cannot be rewritten.
        call_ids = {call.get("id") for call in messages[latest].get("tool_calls", [])}
        for i, message in enumerate(messages):
            paired = message.get("role") == "tool" and message.get("tool_call_id") in call_ids
            user_result = i > latest and message.get("_tool_result")
            if not (paired or user_result):
                continue
            content = message.get("content")
            exact = (
                i in required
                or message.get("name") == "read_file"
                or message.get("_provider_blocks")
            )
            if not exact and isinstance(content, str) and (
                content.startswith(_PREVIEW_HEADER)
                or len(content.encode()) > _PREVIEW_CAPS[-1]
            ):
                stand_ins[i] = {**message, "content": _SMALLEST_PREVIEW_STAND_IN}
            required.add(i)
    return [stand_ins.get(i, message) for i, message in enumerate(messages) if i in required]


# Tools the agent needs to keep acting at all. Never pruned, so a tight context
# degrades the breadth of the toolset, never the ability to run and report.
CORE_TOOL_NAMES: tuple[str, ...] = (
    "execute",
    "read_file",
    "web_search",
    "create_note",
    "create_vulnerability_report",
)


def fit_tools_to_budget(
    messages: list[dict[str, Any]],
    tools: list[dict] | None,
    budget: int,
    *,
    core_names: tuple[str, ...] = CORE_TOOL_NAMES,
    replay_reasoning: bool | None = None,
) -> list[dict[str, Any]]:
    """Drop the lowest-ranked optional tool schemas until mandatory content fits.

    `tools` is expected rank-ordered (most relevant first, as produced by
    rank_tools_for_phase), so pruning from the tail sheds the least useful
    schemas first. Two things are never traded away:

    * core tools, so the agent can always run and report, and
    * the last remaining schema — an agent with zero tools cannot act and would
      answer from imagination, so an irreducible schema must fail loudly in
      pack_history instead of being pruned into silence.

    Returns the list unchanged when it already fits or no budget is in force.
    This prunes only what is SENT to the model; the caller's full tool registry
    stays intact for execution and validation.
    """
    if not tools or budget <= 0:
        return list(tools or [])
    mandatory = _minimum_request_messages(messages)
    kept = list(tools)
    if request_chars(mandatory, kept, replay_reasoning=replay_reasoning) <= budget:
        return kept

    def _name(tool: dict) -> str:
        return str((tool.get("function") or {}).get("name") or "")

    while request_chars(mandatory, kept, replay_reasoning=replay_reasoning) > budget and len(kept) > 1:
        index = next(
            (i for i in range(len(kept) - 1, -1, -1) if _name(kept[i]) not in core_names),
            None,
        )
        if index is None:
            break  # Only core schemas left; cannot shrink further.
        kept.pop(index)
    return kept


# read_file pages whole lines up to 7680 JSON-escaped bytes
# (filesystem._READ_CONTENT_WIRE_BYTES); half of that per archive line keeps
# every line pageable with room for at least two per page.
_ARCHIVE_LINE_WIRE_BYTES = 3800
_ARCHIVE_HEADER = "@ "
_ARCHIVE_LINE = "| "
_ARCHIVE_CONT = "\u00bb "  # "» "
_ARCHIVE_LEGEND = (
    "[Archived tool group (exact evidence). Every following line starts with a"
    " 2-character tag: '@ ' = JSON header of the next message (all fields except"
    " text content); '| ' = start of one content line; '\u00bb ' = continuation"
    " of the previous line (join with no separator; lines are split only to stay"
    " readable with read_file). A message's content is its '| ' lines, with"
    " continuations joined, joined by newlines.]"
)


def _char_wire_bytes(ch: str) -> int:
    """Bytes one character occupies inside a JSON string (UTF-8, escaped)."""
    if ch in '"\\':
        return 2
    if ch < " ":
        return 2 if ch in "\b\f\n\r\t" else 6
    return len(ch.encode("utf-8", "surrogatepass"))


def _archive_lines(tag: str, text: str) -> list[str]:
    """Tag each line of ``text``; split lines that would exceed the wire bound."""
    limit = _ARCHIVE_LINE_WIRE_BYTES - 4  # 2-byte tag + escaped newline
    out: list[str] = []
    for raw in text.split("\n"):
        if len(json.dumps(raw, ensure_ascii=False).encode("utf-8", "surrogatepass")) - 2 <= limit:
            out.append(tag + raw)
            continue
        current: list[str] = []
        cost = 0
        prefix = tag
        for ch in raw:
            char_cost = _char_wire_bytes(ch)
            if current and cost + char_cost > limit:
                out.append(prefix + "".join(current))
                current, cost, prefix = [], 0, _ARCHIVE_CONT
            current.append(ch)
            cost += char_cost
        out.append(prefix + "".join(current))
    return out


def _archive_group_text(group: list[dict[str, Any]]) -> str:
    """Serialize an evicted group line-oriented and unambiguously, never as one line.

    ``read_file`` refuses any line over its wire bound, so a single-line
    ``json.dumps`` archive would come back as a ``line_too_large`` advisory
    exactly when the notice points the model at it. Tags make reassembly exact
    whatever the content starts with.
    """
    lines = [_ARCHIVE_LEGEND]
    for message in group:
        content = message.get("content")
        meta = {k: v for k, v in message.items() if k != "content"} if isinstance(content, str) else message
        lines.extend(_archive_lines(_ARCHIVE_HEADER, json.dumps(meta, ensure_ascii=False)))
        if isinstance(content, str):
            lines.extend(_archive_lines(_ARCHIVE_LINE, content))
    return "\n".join(lines)


def pack_history(
    messages: list[dict[str, Any]], tools: list[dict] | None,
    budget: int, compressor: ArtifactCompressor,
    *, replay_reasoning: bool | None = None,
) -> list[dict[str, Any]]:
    """Pack complete tool groups; user/system constraints are never rank-skipped."""
    packed = copy.deepcopy(messages)
    notices = [m for m in packed if _is_archive_notice(m)]
    if notices and (len(notices) > 1 or notices[0].get("role") != "system"):
        # Sessions saved by older versions hold assistant-role (or stacked)
        # notices: keep one, as system text, so no synthetic assistant turn
        # reaches the wire.
        kept = str(notices[-1].get("content") or "")
        packed = _place_archive_notice([m for m in packed if not _is_archive_notice(m)], kept)
    mandatory = _mandatory_messages(packed)
    if request_chars(mandatory, tools, replay_reasoning=replay_reasoning) > budget:
        raise ContextBudgetError("Mandatory instructions and tool schemas exceed the context budget")
    if request_chars(packed, tools, replay_reasoning=replay_reasoning) <= budget:
        return packed
    for cap in _PREVIEW_CAPS:
        for message in packed:
            if (message.get("role") not in ("tool", "assistant") and not message.get("_tool_result")) or message.get("_protected"):
                continue
            # Exact file reads are not transformed: an Edit can depend on them.
            if message.get("name") == "read_file":
                continue
            if message.get("_provider_blocks"):
                continue  # Signed provider blocks must remain byte-exact.
            content = message.get("content") or ""
            if not isinstance(content, str) or len(content.encode()) <= cap:
                continue
            preview, reference = compressor.preview(
                content, cap, reference=message.get("_context_ref"),
                external=not bool(message.get("_context_ref")),
            )
            message["content"] = preview
            message["_context_ref"] = reference
        if request_chars(packed, tools, replay_reasoning=replay_reasoning) <= budget:
            return packed
    # Evict old assistant turns with ALL of their results, never half a pair.
    # A previous pass's notice is dropped first so notices never stack and are
    # never mistaken for the latest real group.
    packed = [m for m in packed if not _is_archive_notice(m)]
    while request_chars(packed, tools, replay_reasoning=replay_reasoning) > budget:
        assistant_indices = [
            i for i, m in enumerate(packed)
            if m.get("role") == "assistant" and not _is_archive_notice(m)
        ]
        removed = False
        for index in assistant_indices[:-1]:
            message = packed[index]
            ids = {tc.get("id") for tc in message.get("tool_calls", [])}
            next_assistant = next(
                (j for j in range(index + 1, len(packed))
                 if packed[j].get("role") == "assistant"),
                len(packed),
            )
            indices = {index}
            for i, m in enumerate(packed):
                if m.get("role") == "tool" and m.get("tool_call_id") in ids:
                    indices.add(i)
                elif index < i < next_assistant and m.get("_tool_result"):
                    # User-role results (tool_response_role=user) belong to
                    # this group; evicting the assistant without them would
                    # leave incompressible orphan pages behind.
                    indices.add(i)
            if any(_pinned(packed[i]) for i in indices):
                continue
            compressor.save(_archive_group_text([packed[i] for i in sorted(indices)]))
            packed = [m for i, m in enumerate(packed) if i not in indices]
            removed = True
            break
        if not removed:
            raise ContextBudgetError("Context budget cannot fit mandatory context and the latest tool group; paginate large file reads")
    # System-role, not a synthetic assistant turn: DeepSeek thinking mode
    # rejects assistant turns without reasoning_content, Anthropic needs signed
    # thinking first in the turn it would merge into, and a trailing assistant
    # turn reads as a prefill. On the wire it joins the system prompt.
    content = (
        f"{_ARCHIVE_NOTICE_PREFIX}{compressor.directory.as_posix()}/; "
        "use list_files/read_file for exact evidence.]"
    )
    with_notice = _place_archive_notice(packed, content)  # never trailing system text
    if request_chars(with_notice, tools, replay_reasoning=replay_reasoning) <= budget:
        packed = with_notice
    return packed

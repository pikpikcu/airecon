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


class ContextBudgetError(RuntimeError):
    """The request cannot fit without deleting mandatory instructions/schemas."""


def request_chars(messages: list[dict[str, Any]], tools: list[dict] | None) -> int:
    """Serialized UTF-8 bytes, not a claim of exact model tokenization."""
    from .config import get_config
    if str(getattr(get_config(), "llm_provider", "openai")).lower() in ("anthropic", "claude"):
        from .llm_protocol import anthropic_messages, anthropic_tools
        system, converted = anthropic_messages(messages)
        body = {"system": system, "messages": converted, "tools": anthropic_tools(tools)}
    else:
        body = {"messages": _to_openai_messages(messages), "tools": tools or []}
    return len(json.dumps(
        body,
        ensure_ascii=False,
    ).encode("utf-8"))


def estimate_request_tokens(messages: list[dict[str, Any]], tools: list[dict] | None) -> int:
    # Conservative heuristic, including JSON framing, schemas and call arguments.
    if not messages and not tools:
        return 0
    return (request_chars(messages, tools) + 2) // 3


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
        header = "[Compacted preview; omitted content is NOT a clean scan]\n"
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


def pack_history(
    messages: list[dict[str, Any]], tools: list[dict] | None,
    budget: int, compressor: ArtifactCompressor,
) -> list[dict[str, Any]]:
    """Pack complete tool groups; user/system constraints are never rank-skipped."""
    packed = copy.deepcopy(messages)
    mandatory = [m for m in packed if (m.get("role") in ("system", "user") and not m.get("_tool_result")) or m.get("_protected")]
    if request_chars(mandatory, tools) > budget:
        raise ContextBudgetError("Mandatory instructions and tool schemas exceed the context budget")
    if request_chars(packed, tools) <= budget:
        return packed
    for cap in (3000, 1500, 750, 400):
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
        if request_chars(packed, tools) <= budget:
            return packed
    # Evict old assistant turns with ALL of their results, never half a pair.
    while request_chars(packed, tools) > budget:
        assistant_indices = [i for i, m in enumerate(packed) if m.get("role") == "assistant"]
        removed = False
        for index in assistant_indices[:-1]:
            message = packed[index]
            ids = {tc.get("id") for tc in message.get("tool_calls", [])}
            indices = {index} | {i for i, m in enumerate(packed) if m.get("role") == "tool" and m.get("tool_call_id") in ids}
            if any(packed[i].get("_protected") for i in indices):
                continue
            compressor.save(json.dumps([packed[i] for i in sorted(indices)], ensure_ascii=False))
            packed = [m for i, m in enumerate(packed) if i not in indices]
            removed = True
            break
        if not removed:
            raise ContextBudgetError("Context budget cannot fit mandatory context and the latest tool group; paginate large file reads")
    notice = {"role": "assistant", "content": f"[Older tool groups archived under {compressor.directory.as_posix()}/; use list_files/read_file for exact evidence.]"}
    if request_chars(packed + [notice], tools) <= budget:
        packed.append(notice)
    return packed

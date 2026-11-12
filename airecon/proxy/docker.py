from __future__ import annotations

import asyncio
import contextlib
import logging
import re
import shutil
import traceback
import uuid
from collections import deque
from pathlib import Path
from typing import Any, Callable

from .config import get_config, get_workspace_root

logger = logging.getLogger("airecon.docker_engine")

EXECUTE_TOOL_DEF = {
    "type": "function",
    "function": {
        "name": "execute",
        "description": (
            "Execute a shell command inside the Kali Linux sandbox. "
            "All recon tools are pre-installed (nmap, subfinder, httpx, nuclei, katana, ffuf, sqlmap, etc). "
            "Use this for any command-line operation. Output files go to /workspace/<target>/output/. "
            "Before using a tool for the first time, run `<tool> -h or --help` to check its flags."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "command": {
                    "type": "string",
                    "description": "Shell command to execute (bash). Supports pipes, redirects. WARNING: You CANNOT escape single quotes inside a single quoted string in bash (e.g. 'don\\'t'). Try using double quotes or ANSI-C quoting $'don\\'t'.",
                },
                "timeout": {
                    "type": "integer",
                    "description": "Timeout in seconds (default: from config, typically 900). Increase for long scans.",
                },
            },
            "required": ["command"],
        },
    },
}


_SANDBOX_WORKSPACE = "/workspace"

# --- Host workspace path normalization -------------------------------------
#
# A convenience mapper, NOT a security boundary: isolation comes from running
# the payload through ``docker exec``, never from this rewrite. A bash payload
# is opaque data plus a few places where a word is known to name a file. Only
# those places are remapped; URLs, request bodies, inline source, patterns,
# comments and heredoc bodies keep their exact bytes. Anything not recognized
# is left alone, so the worst outcome is "No such file" inside the sandbox.

# Commands whose non-option operands are all filesystem paths.
_PATH_OPERAND_COMMANDS = frozenset({
    "cd", "pushd", "ls", "dir", "tree", "stat", "file", "du",
    "cat", "tac", "nl", "head", "tail", "less", "more", "wc", "sort", "uniq",
    "md5sum", "sha1sum", "sha256sum", "xxd", "strings",
    "mkdir", "rmdir", "rm", "cp", "mv", "touch", "ln", "chmod", "chown", "tee",
    "source", ".",
})
# Interpreters: only the word directly after the name is a script path.
_SCRIPT_INTERPRETERS = frozenset({
    "python", "python2", "python3", "bash", "sh", "zsh", "node", "perl", "ruby", "php",
})
# Commands whose arguments are data (text, patterns, expressions): nothing but
# redirection targets is remapped. Their ``-o`` is not an output file.
_OPAQUE_ARGUMENT_COMMANDS = frozenset({
    "echo", "printf", "grep", "egrep", "fgrep", "rg", "ag", "ack", "pgrep", "pkill",
    "sed", "awk", "gawk", "jq", "yq", "tr", "expr", "test", "[",
    "ssh", "ps", "mount", "lsblk", "column", "getopt", "xargs", "env", "export",
    "eval", "exec", "set",
})
# Options whose value is a local file, per command; any other command (the
# recon tools) gets the conventional output/input-list options.
_PATH_OPTIONS_BY_COMMAND: dict[str, frozenset[str]] = {
    "curl": frozenset({
        "-o", "--output", "--output-dir", "-D", "--dump-header",
        "-c", "--cookie-jar", "-T", "--upload-file",
    }),
    "wget": frozenset({
        "-O", "--output-document", "-o", "--output-file",
        "-P", "--directory-prefix", "-i", "--input-file",
    }),
}
_GENERIC_PATH_OPTIONS = frozenset({
    "-o", "--output", "--output-file", "--output-dir",
    "-oA", "-oN", "-oX", "-oG", "-oJ",
    "-l", "--list", "-iL", "-w", "--wordlist",
})
# Leading words that do not change which word is the command name.
_TRANSPARENT_PREFIXES = frozenset({
    "sudo", "time", "nohup", "command",
    "if", "then", "else", "elif", "do", "while", "until", "{", "!",
})
_ASSIGNMENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*=")
_WORD_BREAK = " \t\n;|&()<>"


def _skip_parameter(command: str, i: int) -> int:
    """Index just past a plain ``${...}`` starting at ``i``; -1 if not plain."""
    end = command.find("}", i)
    if end < 0 or any(ch in command[i:end] for ch in "'\"`\\ \t\n") or "$(" in command[i:end]:
        return -1
    return end + 1


def _scan_word(command: str, i: int) -> int:
    """Index just past the shell word starting at ``i``.

    Returns -1 for anything this scanner does not model (command substitution,
    backticks, nested parameter expansion, an unterminated quote): the caller
    then stops and leaves the rest of the payload byte-for-byte.
    """
    n = len(command)
    while i < n:
        c = command[i]
        if c in _WORD_BREAK:
            return i
        if c == "\\":
            i += 2
        elif c == "'":
            close = command.find("'", i + 1)
            if close < 0:
                return -1
            i = close + 1
        elif c == '"':
            i += 1
            while i < n and command[i] != '"':
                if command[i] == "\\":
                    i += 2
                elif command[i] == "`" or command.startswith("$(", i):
                    return -1
                elif command.startswith("${", i):
                    i = _skip_parameter(command, i)
                    if i < 0:
                        return -1
                else:
                    i += 1
            if i >= n:
                return -1
            i += 1
        elif c == "`" or command.startswith("$(", i):
            return -1
        elif command.startswith("$'", i):  # ANSI-C quoting: \' does not close it
            i += 2
            while i < n and command[i] != "'":
                i += 2 if command[i] == "\\" else 1
            if i >= n:
                return -1
            i += 1
        elif command.startswith("${", i):
            i = _skip_parameter(command, i)
            if i < 0:
                return -1
        else:
            i += 1
    return n


def _host_root_span(command: str, start: int, end: int, host_root: str) -> tuple[int, int] | None:
    """Raw span of ``host_root`` when ``command[start:end]`` is a path under it.

    The word must spell the root literally from its first character (quotes
    and backslash escapes are decoded; expansions and globs disqualify it) and
    the root must be followed by ``/`` or the end of the word, so
    ``/archive<root>/x``, ``<root>-backup`` and ``https://h<root>/x`` never
    match. The span opens and closes in the same quoting state, so replacing
    it keeps the surrounding quotes balanced.
    """
    quote = ""
    matched = 0
    span_start = span_end = -1
    start_quote = end_quote = ""
    i = start
    while i < end:
        c = command[i]
        raw = i
        if quote == "'":
            if c == "'":
                quote = ""
                i += 1
                continue
        elif quote == '"':
            if c == '"':
                quote = ""
                i += 1
                continue
            if c in "$`":
                return None
            if c == "\\" and command[i + 1 : i + 2] in ("$", "`", '"', "\\"):
                i += 1
        elif c in "'\"":
            quote = c
            i += 1
            continue
        elif c == "\\":
            i += 1
            if i >= end or command[i] == "\n":
                return None
        elif c in "$`*?[{~":
            return None
        if matched == len(host_root):
            if command[i] == "/" and start_quote == end_quote:
                return span_start, span_end
            return None
        if command[i] != host_root[matched]:
            return None
        if matched == 0:
            span_start, start_quote = raw, quote
        matched += 1
        if matched == len(host_root):
            span_end, end_quote = i + 1, quote
        i += 1
    if matched == len(host_root) and start_quote == end_quote:
        return span_start, span_end
    return None


def _command_operand_spans(
    command: str, words: list[tuple[int, int]], host_root: str
) -> list[tuple[int, int]]:
    """Host-root spans among one simple command's recognized path operands."""
    texts = [command[a:b] for a, b in words]
    first = 0
    while first < len(texts) and (
        texts[first] in _TRANSPARENT_PREFIXES or _ASSIGNMENT_RE.match(texts[first])
    ):
        first += 1
    if first >= len(texts):
        return []
    name = texts[first].rsplit("/", 1)[-1]
    args = words[first + 1 :]
    arg_texts = texts[first + 1 :]

    # The command word itself: ``<root>/tools/run.sh`` names a file to run.
    candidates: list[tuple[int, int]] = [words[first]]
    if name in _PATH_OPERAND_COMMANDS:
        candidates.extend(args)
    elif name == "find":
        # Only the start paths; the expression (-name, -path, -exec ...) is data.
        for arg, text in zip(args, arg_texts):
            if text.startswith(("-", "(", "\\(", "!")):
                break
            candidates.append(arg)
    else:
        if name in _SCRIPT_INTERPRETERS:
            candidates.extend(args[:1])
        if name in _OPAQUE_ARGUMENT_COMMANDS:
            options: frozenset[str] = frozenset()
        else:
            options = _PATH_OPTIONS_BY_COMMAND.get(name, _GENERIC_PATH_OPTIONS)
        for idx, (a, b) in enumerate(args):
            if idx and arg_texts[idx - 1] in options:
                candidates.append((a, b))  # ``-o <path>``
                continue
            option, eq, _ = arg_texts[idx].partition("=")
            if eq and option in options:
                candidates.append((a + len(option) + 1, b))  # ``--output=<path>``

    spans = []
    for a, b in candidates:
        span = _host_root_span(command, a, b, host_root)
        if span:
            spans.append(span)
    return spans


def _host_operand_spans(command: str, host_root: str) -> list[tuple[int, int]]:
    """Spans of ``host_root`` that sit in a recognized filesystem operand.

    A small lexical scan, not a shell parser: it splits the payload into
    simple commands and words, skips comments and heredoc bodies, and stops at
    the first construct it does not model. Nothing is executed or expanded.
    """
    spans: list[tuple[int, int]] = []
    words: list[tuple[int, int]] = []
    heredocs: list[tuple[str, bool]] = []
    expect = ""  # role of the next word: redirect | opaque | heredoc | heredoc-tabs
    i, n = 0, len(command)
    while i < n:
        c = command[i]
        if c in " \t":
            i += 1
        elif command.startswith("\\\n", i):
            i += 2
        elif c == "\n":
            spans.extend(_command_operand_spans(command, words, host_root))
            words = []
            i += 1
            for delimiter, strip_tabs in heredocs:
                while True:  # skip the body: opaque data up to the delimiter line
                    eol = command.find("\n", i)
                    line = command[i:] if eol < 0 else command[i:eol]
                    i = n if eol < 0 else eol + 1
                    if (line.lstrip("\t") if strip_tabs else line) == delimiter:
                        break
                    if eol < 0:
                        return spans  # unterminated heredoc: the rest is data
            heredocs = []
        elif c == "#":
            eol = command.find("\n", i)
            i = n if eol < 0 else eol
        elif command.startswith("&>", i):
            expect = "redirect"
            i += 3 if command.startswith("&>>", i) else 2
        elif c in ";|&()":
            spans.extend(_command_operand_spans(command, words, host_root))
            words = []
            i += 1
        elif c in "<>":
            if command.startswith(("<(", ">("), i):
                break  # process substitution is not modelled
            if command.startswith("<<<", i):
                expect = "opaque"  # here-string: data
                i += 3
            elif command.startswith("<<", i):
                strip_tabs = command.startswith("<<-", i)
                expect = "heredoc-tabs" if strip_tabs else "heredoc"
                i += 3 if strip_tabs else 2
            else:
                i += 1
                while i < n and command[i] in ">&|":
                    i += 1
                expect = "redirect"
        else:
            end = _scan_word(command, i)
            if end < 0 or command[end : end + 1] == "(" or command[i:end] in ("case", "[["):
                # Also not modelled: ``name=(...)`` / ``f()``, case patterns and
                # ``[[ ]]`` expressions, where a leading word is not a command.
                break
            if expect.startswith("heredoc"):
                delimiter = re.sub(r"['\"\\]", "", command[i:end])
                heredocs.append((delimiter, expect == "heredoc-tabs"))
            elif expect == "redirect":
                span = _host_root_span(command, i, end, host_root)
                if span:
                    spans.append(span)
            elif expect == "opaque":
                pass
            elif command[i:end].isdigit() and command[end : end + 1] in ("<", ">"):
                pass  # file-descriptor number of a redirection, e.g. ``2>``
            else:
                words.append((i, end))
            expect = ""
            i = end
    spans.extend(_command_operand_spans(command, words, host_root))
    return spans


def rewrite_host_workspace_paths(command: str, host_root: str | None = None) -> str:
    """Map HOST workspace paths in filesystem operands onto ``/workspace``.

    Single normalization point at the Docker execution boundary: the sandbox
    mounts get_workspace_root() at /workspace, but models routinely emit the
    host absolute path instead (which does not exist inside the container).
    Every ingress path — DockerEngine.execute, execute_tool (the /shell HTTP
    endpoint, semgrep/http_observe callers) and the agent dispatch loop —
    gets identical treatment, with no dependency on an active target.

    Only a word that is recognizably a filesystem operand is rewritten: a
    redirection target, an operand of a file utility (``cd``, ``ls``, ``cat``,
    ``mkdir`` ...), the value of a file option (``-o``, ``--output`` ...), a
    ``find`` start path, a command run by path, or the script given to an
    interpreter. The word must start with the host root as a whole path
    prefix. Everything else — URLs, request bodies, ``python -c`` source,
    patterns, comments, heredoc bodies, unrelated paths that merely contain
    the root — is returned byte-for-byte, as is any payload the scanner does
    not understand. Idempotent.
    """
    if not command:
        return command
    if host_root is None:
        try:
            host_root = str(get_workspace_root()).rstrip("/")
        except Exception as exc:  # pragma: no cover — config unavailable
            logger.debug("Could not resolve workspace root for remap: %s", exc)
            return command
    else:
        host_root = host_root.rstrip("/")
    if not host_root or host_root == "/" or host_root not in command:
        return command
    parts: list[str] = []
    pos = 0
    for a, b in sorted(set(_host_operand_spans(command, host_root))):
        parts.append(command[pos:a])
        parts.append(_SANDBOX_WORKSPACE)
        pos = b
    parts.append(command[pos:])
    return "".join(parts)


def _validate_target_name(target: str) -> bool:

    if not target:
        return False
    if len(target) > 255:
        logger.error("Target name too long: %d chars (max 255)", len(target))
        return False
    if ".." in target:
        logger.error("Target name contains '..': %s", target)
        return False
    if "/" in target or "\\" in target:
        logger.error("Target name contains path separators: %s", target)
        return False
    if not re.match(r"^[a-zA-Z0-9._\-]+$", target):
        logger.error("Target name contains invalid characters: %s", target)
        return False
    return True


class DockerEngine:
    IMAGE_NAME = "airecon-sandbox"
    CONTAINER_PREFIX = "airecon-sandbox"
    DOCKERFILE_DIR = Path(__file__).parent.parent / "containers"
    _HEALTH_CHECK_ATTEMPTS = 10

    def __init__(self) -> None:
        self.cfg = get_config()
        # Honor the configured image name as the source of truth (falls back to
        # the class default). Container naming stays on CONTAINER_PREFIX so this
        # only affects which image is inspected/built/run.
        self.IMAGE_NAME = (self.cfg.docker_image or "").strip() or DockerEngine.IMAGE_NAME
        self._container_id: str | None = None
        self._container_name: str | None = None
        self._connected = False
        self._current_proc: asyncio.subprocess.Process | None = None
        self._proc_lock = asyncio.Lock()
        self._active_procs: set[asyncio.subprocess.Process] = set()
        self._background_tasks: set[asyncio.Task] = set()

        self._recovery_lock = asyncio.Lock()

        self._recent_commands: deque[str] = deque(maxlen=15)

        self._postmortem_fired: bool = False

        self._recovery_generation: int = 0

        self._consecutive_recovery_failures: int = 0

    @property
    def is_connected(self) -> bool:
        return self._connected

    async def image_exists(self) -> bool:
        if not shutil.which("docker"):
            return False
        proc = await asyncio.create_subprocess_exec(
            "docker",
            "image",
            "inspect",
            self.IMAGE_NAME,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        await proc.wait()
        return proc.returncode == 0

    async def ensure_image(self) -> bool:
        docker_bin = shutil.which("docker")
        if not docker_bin:
            logger.error("Docker is not installed or not in PATH")
            return False

        if await self.image_exists():
            logger.info("Docker image '%s' found", self.IMAGE_NAME)
            return True

        logger.info(
            "Building Docker image '%s' — this may take 10-20 minutes...",
            self.IMAGE_NAME,
        )
        dockerfile_dir = self.DOCKERFILE_DIR

        if not dockerfile_dir.exists() or not (dockerfile_dir / "Dockerfile").exists():
            logger.error("Dockerfile not found at %s", dockerfile_dir)
            return False

        import sys

        proc = await asyncio.create_subprocess_exec(
            "docker",
            "build",
            "-t",
            self.IMAGE_NAME,
            str(dockerfile_dir),
            stdout=sys.stdout,
            stderr=sys.stderr,
        )
        await proc.wait()

        if proc.returncode != 0:
            logger.error("Docker build failed.")
            return False

        logger.info("Docker image '%s' built successfully", self.IMAGE_NAME)
        return True

    async def start_container(
        self, target: str | None = None, _recovery: bool = False
    ) -> bool:
        workspace_host = str(get_workspace_root())

        self._container_name = f"{self.CONTAINER_PREFIX}-active"

        await self._stop_existing()

        cmd = [
            "docker",
            "run",
            "-d",
            "--name",
            self._container_name,
            "--network",
            "host",
            "-v",
            f"{workspace_host}:/workspace",
            "--cap-add=NET_RAW",
            "--cap-add=NET_ADMIN",
            f"--memory={self.cfg.docker_memory_limit}",
            f"--memory-swap={self.cfg.docker_memory_limit}",
            self.IMAGE_NAME,
        ]

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=60.0)
        except asyncio.TimeoutError:
            proc.kill()
            logger.error(
                "Container start timed out after 60s — Docker may be hung. "
                "Run: docker ps -a | grep %s and docker rm -f <id> to clean up",
                self._container_name,
            )
            return False

        if proc.returncode != 0:
            err_msg = stderr.decode()

            if "conflict" in err_msg.lower() or "already in use" in err_msg.lower():
                logger.warning(
                    "Container name conflict on start — forcing extra rm and retrying once: %s",
                    err_msg.strip()[:200],
                )
                rm_proc = await asyncio.create_subprocess_exec(
                    "docker",
                    "rm",
                    "-f",
                    self._container_name,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                try:
                    await asyncio.wait_for(rm_proc.wait(), timeout=10.0)
                except asyncio.TimeoutError:
                    rm_proc.kill()
                await asyncio.sleep(1.0)
                retry_proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                try:
                    stdout, stderr = await asyncio.wait_for(
                        retry_proc.communicate(), timeout=60.0
                    )
                except asyncio.TimeoutError:
                    retry_proc.kill()
                    logger.error("Container start retry timed out after 60s")
                    return False
                if retry_proc.returncode != 0:
                    logger.error(
                        "Failed to start container (retry after conflict): %s",
                        stderr.decode(),
                    )
                    return False
            else:
                logger.error("Failed to start container: %s", err_msg)
                return False

        self._container_id = stdout.decode().strip()[:12]
        self._connected = True
        self._postmortem_fired = False
        logger.info(
            "Container started: %s (%s)", self._container_name, self._container_id
        )

        _consecutive_successes = 0
        _required_consecutive = 3
        for _attempt in range(self._HEALTH_CHECK_ATTEMPTS):
            probe = await asyncio.create_subprocess_exec(
                "docker",
                "exec",
                self._container_name,
                "echo",
                "ready",
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            try:
                await asyncio.wait_for(probe.wait(), timeout=2.0)
            except asyncio.TimeoutError:
                probe.kill()
                await probe.wait()
                _consecutive_successes = 0
                logger.debug(
                    "Container health check attempt %d/%d TIMEOUT — waiting…",
                    _attempt + 1,
                    self._HEALTH_CHECK_ATTEMPTS,
                )
                await asyncio.sleep(0.5)
                continue

            if probe.returncode == 0:
                _consecutive_successes += 1
                logger.debug(
                    "Container health check attempt %d/%d OK (success %d/%d) — waiting…",
                    _attempt + 1,
                    self._HEALTH_CHECK_ATTEMPTS,
                    _consecutive_successes,
                    _required_consecutive,
                )
                if _consecutive_successes >= _required_consecutive:
                    logger.info(
                        "Container health check passed (%d/%d consecutive successes)",
                        _consecutive_successes,
                        _required_consecutive,
                    )
                    break
            else:
                _consecutive_successes = 0
                logger.debug(
                    "Container health check attempt %d/%d FAILED (rc=%s) — waiting…",
                    _attempt + 1,
                    self._HEALTH_CHECK_ATTEMPTS,
                    probe.returncode,
                )
            await asyncio.sleep(0.5)
        else:
            if _consecutive_successes == 0:
                self._consecutive_recovery_failures += 1
                _backoff = min(5.0 * self._consecutive_recovery_failures, 30.0)
                logger.error(
                    "Container health check NEVER passed (0/%d consecutive successes) "
                    "— container exited immediately after start. "
                    "Backoff: %.0fs before next recovery attempt. "
                    "Check: docker logs %s  |  dmesg | grep -i oom",
                    _required_consecutive,
                    _backoff,
                    self._container_name or "airecon-sandbox-active",
                )
                if _backoff > 0:
                    await asyncio.sleep(_backoff)
                self._connected = False
                return False
            else:
                self._consecutive_recovery_failures = 0
                logger.warning(
                    "Container health check unstable (%d/%d consecutive successes) — proceeding",
                    _consecutive_successes,
                    _required_consecutive,
                )

        self._consecutive_recovery_failures = 0

        if target:
            if not _validate_target_name(target):
                logger.error(
                    "Invalid target name '%s' — only alphanumeric, dots, hyphens, underscores allowed",
                    target
                )
                return False
            
            await self.execute(
                f"mkdir -p /workspace/{target}/command /workspace/{target}/output "
                f"/workspace/{target}/tools /workspace/{target}/vulnerabilities",
                _retry=True,
            )

        if not _recovery:

            async def _bg_apt_update() -> None:
                try:
                    await self.execute("sudo apt-get update -y -qq", _retry=True)
                except Exception as exc:
                    logger.debug(
                        "Background apt-get update failed (non-fatal): %s", exc
                    )
                finally:
                    current_task = asyncio.current_task()
                    if current_task:
                        self._background_tasks.discard(current_task)

            task = asyncio.create_task(_bg_apt_update())
            self._background_tasks.add(task)

        return True

    async def stop_container(self) -> None:
        logger.info(
            "stop_container() called. Recent commands: %s",
            list(self._recent_commands)[-5:],
        )
        logger.debug(
            "stop_container() caller:\n%s", "".join(traceback.format_stack()[:-1])
        )

        for task in self._background_tasks:
            task.cancel()
        if self._background_tasks:
            await asyncio.gather(*self._background_tasks, return_exceptions=True)
            self._background_tasks.clear()

        if self._container_name:
            proc = await asyncio.create_subprocess_exec(
                "docker",
                "rm",
                "-f",
                self._container_name,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            try:
                await asyncio.wait_for(proc.wait(), timeout=15.0)
            except asyncio.TimeoutError:
                proc.kill()
                logger.warning(
                    "docker rm -f timed out after 15s — Docker daemon may be hung"
                )
            self._connected = False
            self._container_id = None
            logger.info("Container stopped and removed: %s", self._container_name)

    async def _stop_existing(self) -> None:
        for task in self._background_tasks:
            task.cancel()
        if self._background_tasks:
            await asyncio.gather(*self._background_tasks, return_exceptions=True)
            self._background_tasks.clear()

        if self._container_name:
            proc = await asyncio.create_subprocess_exec(
                "docker",
                "rm",
                "-f",
                self._container_name,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            try:
                await asyncio.wait_for(proc.wait(), timeout=15.0)
            except asyncio.TimeoutError:
                proc.kill()
                logger.warning(
                    "docker rm -f timed out after 15s in _stop_existing — Docker daemon may be hung"
                )

            for _i in range(20):
                check = await asyncio.create_subprocess_exec(
                    "docker",
                    "ps",
                    "-aq",
                    "--filter",
                    f"name=^/{self._container_name}$",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                try:
                    out, _ = await asyncio.wait_for(check.communicate(), timeout=3.0)
                except asyncio.TimeoutError:
                    break
                if not out.decode().strip():
                    break
                await asyncio.sleep(0.1)

    async def _register_proc(self, proc: asyncio.subprocess.Process) -> None:
        async with self._proc_lock:
            self._active_procs.add(proc)
            self._current_proc = proc
            if len(self._active_procs) > 1:
                logger.warning(
                    "Concurrent execution detected: %d active processes.",
                    len(self._active_procs),
                )

    async def _unregister_proc(self, proc: asyncio.subprocess.Process) -> None:
        async with self._proc_lock:
            self._active_procs.discard(proc)
            if self._current_proc is proc:
                self._current_proc = next(iter(self._active_procs), None)

    _CONTAINER_GONE_MARKERS: tuple[str, ...] = (
        "no such container",
        "error response from daemon",
        "cannot exec in a stopped container",
        "is not running",
        "connection reset by peer",
        "broken pipe",
        "unexpected EOF",
        "container not found",
        "has been auto-removed",
    )

    def _is_container_gone(self, stderr: str) -> bool:
        lower = stderr.lower()
        for marker in self._CONTAINER_GONE_MARKERS:
            if marker in lower:
                logger.warning(
                    "Container-gone marker detected: %r | stderr snippet: %s",
                    marker,
                    stderr.strip()[:300],
                )
                return True
        return False

    async def _log_container_postmortem(self) -> None:
        if not self._container_name:
            return
        try:
            check_proc = await asyncio.create_subprocess_exec(
                "docker",
                "ps",
                "-a",
                "--filter",
                f"name={self._container_name}",
                "--format",
                "{{.Names}}",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            check_stdout, _ = await asyncio.wait_for(
                check_proc.communicate(), timeout=5.0
            )

            if self._container_name not in check_stdout.decode():
                logger.warning(
                    "CONTAINER POST-MORTEM [%s]: Container already removed — skipping inspect",
                    self._container_name,
                )
                return

            proc = await asyncio.create_subprocess_exec(
                "docker",
                "inspect",
                "--format",
                "Status={{.State.Status}} ExitCode={{.State.ExitCode}} "
                "OOMKilled={{.State.OOMKilled}} Error={{.State.Error}} "
                "StartedAt={{.State.StartedAt}} FinishedAt={{.State.FinishedAt}}",
                self._container_name,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            try:
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=30.0)
                info = stdout.decode(errors="replace").strip()
                logger.error(
                    "CONTAINER POST-MORTEM [%s]: %s | Last 5 cmds: %s",
                    self._container_name,
                    info or "(inspect returned empty)",
                    list(self._recent_commands)[-5:],
                )

                if info:
                    info_lower = info.lower()
                    if "oomkilled=true" in info_lower:
                        logger.critical(
                            "ROOT CAUSE: Container killed by OOM killer (Out Of Memory). "
                            "Fix: Reduce concurrent tool execution or increase Docker memory limit."
                        )
                    elif "exitcode=137" in info_lower:
                        logger.critical(
                            "ROOT CAUSE: Exit code 137 = SIGKILL (usually OOM killer). "
                            "Fix: Check system memory, reduce nmap/sqlmap concurrency."
                        )
                    elif "exitcode=139" in info_lower:
                        logger.critical(
                            "ROOT CAUSE: Exit code 139 = SIGSEGV (segmentation fault). "
                            "Fix: Tool crash (likely nmap/nuclei bug) — report to tool maintainer."
                        )
                    elif "error=" in info_lower and "error=''" not in info_lower:
                        import re

                        error_match = re.search(r"Error=([^\s]+)", info)
                        if error_match:
                            logger.critical(
                                "ROOT CAUSE: Container error: %s", error_match.group(1)
                            )
            except asyncio.TimeoutError:
                logger.error(
                    "CONTAINER POST-MORTEM [%s]: docker inspect timed out (30s) — Docker daemon hung?",
                    self._container_name,
                )
                logger.critical(
                    "ROOT CAUSE: Docker daemon unresponsive — restart Docker: sudo systemctl restart docker"
                )
            except Exception as e:
                logger.debug("Post-mortem inspect failed: %s", e)
        except Exception as e:
            logger.debug("Container post-mortem setup failed: %s", e)

    async def _wait_for_recovery_unlock(self) -> None:
        while self._recovery_lock.locked():
            await asyncio.sleep(0.5)

    async def execute(
        self,
        command: str,
        timeout: float | None = None,
        on_output: Callable[[str], None] | None = None,
        _retry: bool = False,
    ) -> dict[str, Any]:
        # Common-boundary normalization: every caller of execute() — including
        # execute_tool (the /shell endpoint and observer ingress) and direct
        # engine.execute() callers — gets identical host→/workspace remapping,
        # independent of any active target. Pure string rewrite; idempotent.
        command = rewrite_host_workspace_paths(command)

        if not self._connected and self._recovery_lock.locked():
            try:
                await asyncio.wait_for(
                    self._wait_for_recovery_unlock(),
                    timeout=15.0,
                )
            except asyncio.TimeoutError:
                logger.warning(
                    "Recovery lock held for >15s — proceeding anyway to avoid deadlock"
                )

        if not self._connected or not self._container_name:
            return {
                "success": False,
                "error": (
                    "Docker sandbox container is not running. "
                    "AIRecon will attempt to restart it automatically on the next tool call. "
                    "If this persists, restart AIRecon."
                ),
            }

        self._recent_commands.append(command[:200])

        timeout = timeout or self.cfg.command_timeout

        CONTAINER_PATH = (
            "/home/pentester/go/bin"
            ":/home/pentester/.local/bin"
            ":/home/pentester/.cargo/bin"
            ":/home/pentester/.npm-global/bin"
            ":/home/pentester/.gem/bin"
            ":/usr/local/sbin:/usr/local/bin"
            ":/usr/sbin:/usr/bin:/sbin:/bin"
        )

        cmd = [
            "docker",
            "exec",
            "-u",
            "pentester",
            "-w",
            "/workspace",
            "-e",
            f"PATH={CONTAINER_PATH}",
            "-e",
            "GOPATH=/home/pentester/go",
            "-e",
            "GOROOT=/usr/lib/go-1.26",
            "-e",
            "HOME=/home/pentester",
            "-e",
            "USER=pentester",
            "-e",
            "SHELL=/bin/bash",
            "-e",
            "LANG=C.UTF-8",
            "-e",
            "TERM=dumb",
            "-e",
            "PYTHONUNBUFFERED=1",
            "-e",
            "PIPX_HOME=/home/pentester/.local/pipx",
            "-e",
            "NPM_CONFIG_PREFIX=/home/pentester/.npm-global",
            "-e",
            "GEM_HOME=/home/pentester/.gem",
            self._container_name,
            "bash",
            "--login",
            "-c",
            command,
        ]

        _pid_token = uuid.uuid4().hex[:12]
        _job_env = f"AIRECON_JOB_ID={_pid_token}"

        container_idx = cmd.index(self._container_name)
        cmd.insert(container_idx, _job_env)
        cmd.insert(container_idx, "-e")

        proc: asyncio.subprocess.Process | None = None
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await self._register_proc(proc)

            stdout_chunks: list[str] = []
            stderr_chunks: list[str] = []

            stdout_str = ""
            stderr_str = ""

            async def _read_stream(
                stream: asyncio.StreamReader, is_stderr: bool
            ) -> None:

                try:
                    while True:
                        line = await stream.read(1024 * 4)
                        if not line:
                            break
                        text = line.decode(errors="replace")
                        if is_stderr:
                            stderr_chunks.append(text)
                        else:
                            stdout_chunks.append(text)

                        if on_output:
                            on_output(text)
                except asyncio.CancelledError:
                    raise
                except Exception as _stream_err:
                    logger.debug(
                        "Stream read error (container may have died): %s", _stream_err
                    )

            try:
                if proc.stdout is None or proc.stderr is None:
                    logger.error("Process stdout/stderr not initialized")
                    raise RuntimeError("Process streams not available")
                
                await asyncio.wait_for(
                    asyncio.gather(
                        _read_stream(proc.stdout, False),
                        _read_stream(proc.stderr, True),
                        proc.wait(),
                    ),
                    timeout=timeout,
                )
            finally:
                await self._unregister_proc(proc)

            stdout_str = "".join(stdout_chunks)
            stderr_str = "".join(stderr_chunks)

            if self._is_container_gone(stderr_str):
                if _retry:
                    if not self._postmortem_fired:
                        self._postmortem_fired = True
                        await self._log_container_postmortem()

                    logger.error(
                        "Container crashed AGAIN after recovery — sandbox is unstable: %s",
                        stderr_str.strip()[:200],
                    )

                    return {
                        "success": False,
                        "error": (
                            "Docker sandbox crashed again after recovery. "
                            "The current command failed. AIRecon will attempt to restart "
                            "the container automatically on the next tool call."
                        ),
                        "stdout": stdout_str,
                        "stderr": stderr_str,
                        "exit_code": proc.returncode,
                    }

                _my_gen = self._recovery_generation

                recovery_failed = False
                should_retry = False
                already_recovered = False

                async with self._recovery_lock:
                    if self._recovery_generation != _my_gen:
                        logger.info(
                            "Container already recovered by another coroutine "
                            "(gen %d→%d) — retrying: %s",
                            _my_gen,
                            self._recovery_generation,
                            command[:80],
                        )
                        already_recovered = True
                    else:
                        if not self._postmortem_fired:
                            self._postmortem_fired = True
                            await self._log_container_postmortem()
                        logger.warning(
                            "Container gone mid-recon (stderr: %s). Attempting auto-recovery…",
                            stderr_str.strip()[:200],
                        )
                        self._connected = False
                        recovered = await self.start_container(_recovery=True)
                        if recovered:
                            self._recovery_generation += 1

                            await asyncio.sleep(1)
                            logger.info(
                                "Container recovered — retrying command: %s",
                                command[:120],
                            )
                            should_retry = True
                        else:
                            logger.error(
                                "Container recovery failed — sandbox is unavailable."
                            )
                            recovery_failed = True

                if already_recovered:
                    return await self.execute(
                        command, timeout, on_output=on_output, _retry=False
                    )
                elif should_retry:
                    return await self.execute(
                        command, timeout, on_output=on_output, _retry=True
                    )
                elif recovery_failed:
                    return {
                        "success": False,
                        "error": (
                            "CRITICAL: Docker sandbox container crashed and could not be restarted automatically. "
                        ),
                        "stdout": stdout_str,
                        "stderr": stderr_str,
                        "exit_code": proc.returncode,
                    }

            stdout_has_output = bool(stdout_str.strip())
            success = proc.returncode == 0 or (
                proc.returncode == 1 and stdout_has_output
            )

            return {
                "success": success,
                "result": stdout_str if success else None,
                "stdout": stdout_str,
                "stderr": stderr_str,
                "exit_code": proc.returncode,
                "error": stderr_str if not success else None,
            }

        except asyncio.CancelledError:
            try:
                if proc is not None and proc.returncode is None:
                    proc.kill()
                    await proc.wait()
                if proc is not None:
                    await self._unregister_proc(proc)
            except Exception as _e:
                logger.debug("Could not cancel process: %s", _e)
            return {
                "success": False,
                "error": "Command cancelled by user (ESC)",
                "stdout": "",
                "stderr": "",
                "exit_code": -2,
            }

        except asyncio.TimeoutError:
            try:
                if proc is not None and proc.returncode is None:
                    logger.warning(
                        "Command timed out after %ds — killing process (pid=%d)",
                        timeout,
                        proc.pid,
                    )
                    proc.kill()
                    await asyncio.wait_for(proc.wait(), timeout=5.0)
                if proc is not None:
                    await self._unregister_proc(proc)
            except Exception as _e:
                logger.debug("Could not kill Python-side process: %s", _e)

            try:
                kill_cmd = (
                    f"for pid in $(grep -rlZ '{_job_env}' /proc/*/environ 2>/dev/null "
                    f"| sed 's|/proc/||;s|/environ||'); do "
                    f'  kill -KILL -- -"$pid" 2>/dev/null; '
                    f'  kill -KILL "$pid" 2>/dev/null; '
                    f"done; "
                    "pkill -KILL -f 'wpscan|nuclei|nmap|masscan|gobuster|dirsearch|ffuf' 2>/dev/null || true"
                )
                kill_proc = await asyncio.create_subprocess_exec(
                    "docker",
                    "exec",
                    self._container_name,
                    "bash",
                    "-c",
                    kill_cmd,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                await asyncio.wait_for(kill_proc.wait(), timeout=5.0)
                logger.info("Killed container-side processes for timed-out command")
            except Exception as _e:
                logger.warning("Could not kill container-side job processes: %s", _e)

            return {
                "success": False,
                "error": f"Command timed out after {timeout}s: {command[:100]}",
                "stdout": stdout_str if stdout_str else "",
                "stderr": stderr_str if stderr_str else "",
                "exit_code": -1,
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "stdout": "",
                "stderr": "",
                "exit_code": -1,
            }

    async def discover_tools(self) -> list[dict[str, Any]]:
        return [EXECUTE_TOOL_DEF]

    def tools_to_llm_format(
        self, tools: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        return tools

    def has_tool(self, name: str) -> bool:
        return name == "execute"

    async def execute_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        on_output: Callable[[str], None] | None = None,
    ) -> dict[str, Any]:
        if tool_name != "execute":
            return {
                "success": False,
                "error": f"Unknown tool: {tool_name}. Use 'execute' instead.",
            }

        command = arguments.get("command", "")

        cfg = get_config()

        explicit_timeout = arguments.get("timeout", None)
        if explicit_timeout:
            timeout = max(float(explicit_timeout), cfg.command_timeout)
            if timeout != float(explicit_timeout):
                logger.warning(
                    "Model set timeout=%ss, enforcing minimum %ss",
                    explicit_timeout,
                    cfg.command_timeout,
                )
        else:
            timeout = cfg.command_timeout

        return await self.execute(command, timeout, on_output=on_output)

    async def close(self) -> None:
        for task in self._background_tasks:
            task.cancel()
        if self._background_tasks:
            await asyncio.gather(*self._background_tasks, return_exceptions=True)
            self._background_tasks.clear()
        with contextlib.suppress(Exception):
            await self.force_stop()
        self._connected = False

    async def force_stop(self) -> None:
        logger.info(
            "force_stop() called - killing processes but keeping container alive"
        )
        logger.debug("force_stop() caller:\n%s", "".join(traceback.format_stack()[:-1]))

        async with self._proc_lock:
            procs = list(self._active_procs)
            self._active_procs.clear()
            self._current_proc = None

        for proc in procs:
            try:
                if proc.returncode is None:
                    proc.kill()
                    await asyncio.wait_for(proc.wait(), timeout=2.0)
                    logger.info("Killed running process in force_stop()")
                else:
                    logger.debug(
                        "Process already completed (returncode=%d), skip kill",
                        proc.returncode,
                    )
            except ProcessLookupError:
                logger.debug("Process already terminated, nothing to kill")
            except Exception as _e:
                logger.debug("Could not kill cancelled process: %s", _e)

        async with self._proc_lock:
            stragglers = list(self._active_procs)
            self._active_procs.clear()
        for proc in stragglers:
            try:
                if proc.returncode is None:
                    proc.kill()
                    logger.debug(
                        "Killed straggler process registered during force_stop()"
                    )
            except Exception as _e:
                logger.debug("Could not kill straggler process: %s", _e)

        if self._container_name and self._connected:
            try:
                kill_cmd = (
                    "ps -u pentester -o pid,comm --no-headers 2>/dev/null "
                    '| awk \'$2 != "sleep" && $2 != "chromium" {print $1}\' '
                    "| xargs -r kill -TERM 2>/dev/null; "
                    "sleep 0.5; "
                    "ps -u pentester -o pid,comm --no-headers 2>/dev/null "
                    '| awk \'$2 != "sleep" && $2 != "chromium" {print $1}\' '
                    "| xargs -r kill -KILL 2>/dev/null; "
                    "true"
                )
                proc = await asyncio.create_subprocess_exec(
                    "docker",
                    "exec",
                    self._container_name,
                    "bash",
                    "-c",
                    kill_cmd,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                await asyncio.wait_for(proc.wait(), timeout=5.0)
                logger.info(
                    "Force stopped all active tool processes in container "
                    "(sleep/chromium spared to keep container alive)"
                )
            except Exception as e:
                logger.warning("force_stop container kill failed: %s", e)

        logger.info(
            "force_stop() complete - container %s remains running", self._container_name
        )

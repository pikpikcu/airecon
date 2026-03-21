"""Docker-based execution engine — replaces MCP Bridge.

Manages a Kali Linux Docker container for running recon tools.
Ollama interacts with the container via `docker exec`.
"""

from __future__ import annotations

import asyncio
import logging
import shutil
import uuid
from pathlib import Path
from typing import Any, Callable

from .config import get_config, get_workspace_root

logger = logging.getLogger("airecon.docker_engine")

# Tool definition for Ollama — the only Docker tool
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


class DockerEngine:
    """Manages a Docker container for tool execution."""

    IMAGE_NAME = "airecon-sandbox"
    CONTAINER_PREFIX = "airecon-sandbox"
    DOCKERFILE_DIR = Path(__file__).parent.parent / "containers"

    def __init__(self) -> None:
        self.cfg = get_config()
        self._container_id: str | None = None
        self._container_name: str | None = None
        self._connected = False
        self._current_proc: asyncio.subprocess.Process | None = (
            None  # track running exec
        )
        self._proc_lock = asyncio.Lock()  # Protect _current_proc access
        self._active_procs: set[asyncio.subprocess.Process] = set()

    # ── Public properties ──

    @property
    def is_connected(self) -> bool:
        return self._connected

    # ── Image Management ──

    async def ensure_image(self) -> bool:
        """Check if Docker image exists, build if not."""
        docker_bin = shutil.which("docker")
        if not docker_bin:
            logger.error("Docker is not installed or not in PATH")
            return False

        # Check if image exists
        proc = await asyncio.create_subprocess_exec(
            "docker",
            "image",
            "inspect",
            self.IMAGE_NAME,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        await proc.wait()

        if proc.returncode == 0:
            logger.info("Docker image '%s' found", self.IMAGE_NAME)
            return True

        # Image doesn't exist — build it
        logger.info("Building Docker image '%s' — this may take 10-20 minutes...", self.IMAGE_NAME)
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

    # ── Container Lifecycle ──

    async def start_container(self, target: str | None = None) -> bool:
        """Start a sandbox container with /workspace volume mount."""
        # Determine workspace path — CWD/workspace/ (captured at startup via
        # get_workspace_root())
        workspace_host = str(get_workspace_root())

        self._container_name = f"{self.CONTAINER_PREFIX}-active"

        # Stop existing container if any
        await self._stop_existing()

        # Start new container
        cmd = [
            "docker",
            "run",
            "-d",
            "--name",
            self._container_name,
            "--network",
            "host",  # Share host network for scanning
            "-v",
            f"{workspace_host}:/workspace",
            "--cap-add=NET_RAW",
            "--cap-add=NET_ADMIN",
            self.IMAGE_NAME,
        ]

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()

        if proc.returncode != 0:
            logger.error("Failed to start container: %s", stderr.decode())
            return False

        self._container_id = stdout.decode().strip()[:12]
        self._connected = True
        logger.info("Container started: %s (%s)", self._container_name, self._container_id)

        # If we have a target, create workspace dir
        if target:
            await self.execute(
                f"mkdir -p /workspace/{target}/command /workspace/{target}/output "
                f"/workspace/{target}/tools /workspace/{target}/vulnerabilities"
            )

        # Run apt update silently in the background so future "apt install"
        # commands don't fail due to stale repos
        async def _bg_apt_update() -> None:
            try:
                await self.execute("sudo apt-get update -y -qq")
            except Exception as exc:
                logger.debug("Background apt-get update failed (non-fatal): %s", exc)

        asyncio.create_task(_bg_apt_update())

        return True

    async def stop_container(self) -> None:
        """Stop and remove the sandbox container."""
        if self._container_name:
            proc = await asyncio.create_subprocess_exec(
                "docker",
                "rm",
                "-f",
                self._container_name,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            await proc.wait()
            self._connected = False
            self._container_id = None
            logger.info("Container stopped")

    async def _stop_existing(self) -> None:
        """Stop any existing container with our name."""
        if self._container_name:
            proc = await asyncio.create_subprocess_exec(
                "docker",
                "rm",
                "-f",
                self._container_name,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            await proc.wait()

    # ── Process tracking helpers ──

    async def _register_proc(
        self, proc: asyncio.subprocess.Process
    ) -> None:
        """Track active subprocesses for race-free force-stop."""
        async with self._proc_lock:
            self._active_procs.add(proc)
            self._current_proc = proc
            if len(self._active_procs) > 1:
                logger.warning(
                    "Concurrent execution detected: %d active processes.",
                    len(self._active_procs),
                )

    async def _unregister_proc(
        self, proc: asyncio.subprocess.Process
    ) -> None:
        """Remove subprocess from tracking after completion/cancel/timeout."""
        async with self._proc_lock:
            self._active_procs.discard(proc)
            if self._current_proc is proc:
                self._current_proc = next(iter(self._active_procs), None)

    # ── Command Execution ──

    async def execute(
        self,
        command: str,
        timeout: float | None = None,
        on_output: Callable[[str], None] | None = None,
    ) -> dict[str, Any]:
        """Execute a command inside the container.

        Returns: {"success": bool, "stdout": str, "stderr": str, "exit_code": int}
        """
        if not self._connected or not self._container_name:
            return {"success": False, "error": "Container not running"}

        timeout = timeout or self.cfg.command_timeout

        # Full PATH covering all tool installation locations in the container.
        # Order matters: user-installed tools take priority over system tools.
        # - Go tools:    /home/pentester/go/bin  (httpx, katana, subfinder, dnsx, etc.)
        # - pipx tools:  /home/pentester/.local/bin  (arjun, dirsearch, wafw00f, semgrep, etc.)
        # - Rust tools:  /home/pentester/.cargo/bin  (if any cargo installs were done)
        # - npm tools:   /home/pentester/.npm-global/bin  (retire, eslint, jwt-cracker, etc.)
        # - Ruby gems:   /home/pentester/.gem/bin  (user-level gem installs)
        # - system:      /usr/local/bin  (symlinks from Dockerfile for all user tools)
        #                /usr/local/sbin, /usr/sbin, /usr/bin, /sbin, /bin
        CONTAINER_PATH = (
            "/home/pentester/go/bin"
            ":/home/pentester/.local/bin"
            ":/home/pentester/.cargo/bin"
            ":/home/pentester/.npm-global/bin"
            ":/home/pentester/.gem/bin"
            ":/usr/local/sbin:/usr/local/bin"
            ":/usr/sbin:/usr/bin:/sbin:/bin"
        )

        # Wrap in a login shell so /etc/profile and ~/.bash_profile are sourced.
        # This ensures user-level tool installs (pipx, go, npm, cargo) are
        # discoverable even for tools that check $PATH themselves (e.g. via `which`).
        # bash -l = login shell  →  reads /etc/profile → /etc/profile.d/*.sh → ~/.bash_profile
        # The explicit PATH env var above acts as a reliable fallback.
        cmd = [
            "docker",
            "exec",
            "-u",
            "pentester",
            "-w",
            "/workspace",
            # No -i/-t: -t causes "input device is not a TTY" when stdin=DEVNULL.
            # Use PYTHONUNBUFFERED + stdbuf wrapper for unbuffered output
            # instead.
            "-e",
            f"PATH={CONTAINER_PATH}",
            "-e",
            "GOPATH=/home/pentester/go",
            "-e",
            "GOROOT=/usr/local/go",
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

        # Per-execution job token so timeout can kill only THIS process group
        # without affecting sibling parallel tool executions.
        # We add a unique env var to the docker exec so we can identify the
        # process tree via /proc/<pid>/environ on timeout.
        _pid_token = uuid.uuid4().hex[:12]
        _job_env = f"AIRECON_JOB_ID={_pid_token}"
        # Insert -e AIRECON_JOB_ID=<token> before the container name
        container_idx = cmd.index(self._container_name)
        cmd.insert(container_idx, _job_env)
        cmd.insert(container_idx, "-e")

        proc: asyncio.subprocess.Process | None = None
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdin=asyncio.subprocess.DEVNULL,  # prevent docker from reading TUI terminal
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await self._register_proc(proc)

            stdout_chunks = []
            stderr_chunks = []

            async def _read_stream(
                stream: asyncio.StreamReader, is_stderr: bool
            ) -> None:
                while True:
                    line = await stream.read(1024 * 4)  # 4KB chunks
                    if not line:
                        break
                    text = line.decode(errors="replace")
                    if is_stderr:
                        stderr_chunks.append(text)
                    else:
                        stdout_chunks.append(text)

                    if on_output:
                        on_output(text)

            try:
                assert proc.stdout is not None
                assert proc.stderr is not None
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
            # exit_code=1 is returned by grep/find when the last pipeline step
            # finds no match — common in bash for-loops used for pentest
            # enumeration (e.g. curl | grep location over N targets).  If stdout
            # has meaningful content we treat it as a partial success so the LLM
            # can use the output.  Genuine error codes (≥2, timeout, cancelled)
            # are still treated as failures.
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
            # force_stop() cancelled us — clean up proc
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
            # Kill the Python-side process
            try:
                if proc is not None:
                    proc.kill()
                    await proc.wait()
                if proc is not None:
                    await self._unregister_proc(proc)
            except Exception as _e:
                logger.debug("Could not kill timed-out process: %s", _e)
            # Kill only THIS command's process tree via AIRECON_JOB_ID env marker.
            # Using targeted kill avoids terminating sibling parallel tool
            # executions that pkill -u pentester would otherwise wipe out.
            try:
                kill_cmd = (
                    # Find PIDs whose /proc/environ contains our unique job token,
                    # then kill each one and its entire process group.
                    f"for pid in $(grep -rlZ '{_job_env}' /proc/*/environ 2>/dev/null "
                    f"| sed 's|/proc/||;s|/environ||'); do "
                    f"  kill -KILL -- -\"$pid\" 2>/dev/null; "
                    f"  kill -KILL \"$pid\" 2>/dev/null; "
                    f"done"
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
                await asyncio.wait_for(kill_proc.wait(), timeout=3.0)
            except Exception as _e:
                logger.debug("Could not kill container-side job processes: %s", _e)
            return {
                "success": False,
                "error": f"Command timed out after {timeout}s: {command[:100]}",
                "stdout": "",
                "stderr": "",
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

    # ── Compatibility Interface (used by agent_loop.py) ──

    async def discover_tools(self) -> list[dict[str, Any]]:
        """Return our single execute tool."""
        return [EXECUTE_TOOL_DEF]

    def tools_to_ollama_format(
        self, tools: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Tools are already in Ollama format."""
        return tools

    def has_tool(self, name: str) -> bool:
        """We only have 'execute'."""
        return name == "execute"

    async def execute_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        on_output: Callable[[str], None] | None = None,
    ) -> dict[str, Any]:
        """Execute a tool call from the agent loop."""
        if tool_name != "execute":
            return {
                "success": False,
                "error": f"Unknown tool: {tool_name}. Use 'execute' instead.",
            }

        command = arguments.get("command", "")

        cfg = get_config()
        # Use command_timeout as the single source of truth.
        # If model explicitly passes a timeout, honour it but enforce command_timeout as minimum
        # so the model can't accidentally cut long-running scans short.
        explicit_timeout = arguments.get("timeout", None)
        if explicit_timeout:
            timeout = max(float(explicit_timeout), cfg.command_timeout)
            if timeout != float(explicit_timeout):
                logger.warning(
                    "Model set timeout=%ss, enforcing minimum %ss",
                    explicit_timeout, cfg.command_timeout,
                )
        else:
            timeout = cfg.command_timeout

        return await self.execute(command, timeout, on_output=on_output)

    async def force_stop(self) -> None:
        """Force stop all running commands in the container and the local proc."""
        # 1. Kill all Python-side asyncio subprocesses immediately
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

        # Straggler check: a new process may have been registered between the
        # lock release above and the kill loop completing.  Kill any such
        # stragglers before proceeding to the container-level pkill.
        async with self._proc_lock:
            stragglers = list(self._active_procs)
            self._active_procs.clear()
        for proc in stragglers:
            try:
                if proc.returncode is None:
                    proc.kill()
                    logger.debug("Killed straggler process registered during force_stop()")
            except Exception as _e:
                logger.debug("Could not kill straggler process: %s", _e)

        # 2. Kill ALL user processes inside the container (SIGTERM then
        # SIGKILL)
        if self._container_name and self._connected:
            try:
                kill_cmd = (
                    # Kill every process owned by pentester except PID 1
                    # (entrypoint)
                    "pkill -TERM -u pentester 2>/dev/null; "
                    "sleep 0.5; "
                    "pkill -KILL -u pentester 2>/dev/null; "
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
                    "Force stopped all pentester processes in container")
            except Exception as e:
                logger.warning("force_stop container kill failed: %s", e)

    async def close(self) -> None:
        """Shutdown — stop container."""
        await self.stop_container()

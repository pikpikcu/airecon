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
        """Return True if the sandbox image is already built locally."""
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
        """Wait until recovery lock is released — used by execute() to avoid deadlock."""
        while self._recovery_lock.locked():
            await asyncio.sleep(0.5)

    async def execute(
        self,
        command: str,
        timeout: float | None = None,
        on_output: Callable[[str], None] | None = None,
        _retry: bool = False,
    ) -> dict[str, Any]:
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
        """Graceful shutdown hook used by the server lifespan.

        Cancels background tasks and kills any active child processes via
        force_stop(). The container itself is left in place so it can be
        inspected or reused; call stop_container() explicitly to remove it.
        """
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

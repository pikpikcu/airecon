"""Docker-based execution engine — replaces MCP Bridge.

Manages a Kali Linux Docker container for running recon tools.
Ollama interacts with the container via `docker exec`.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
import time
from pathlib import Path
from typing import Any

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
                    "description": "Shell command to execute (bash). Supports pipes, redirects, and chaining.",
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
        self._current_proc: asyncio.subprocess.Process | None = None  # track running exec

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
            "docker", "image", "inspect", self.IMAGE_NAME,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        await proc.wait()

        if proc.returncode == 0:
            logger.info(f"Docker image '{self.IMAGE_NAME}' found")
            return True

        # Image doesn't exist — build it
        print(f"\n[AIRecon] Building Docker image '{self.IMAGE_NAME}' - This may take 10-20 minutes...", flush=True)
        dockerfile_dir = self.DOCKERFILE_DIR

        if not dockerfile_dir.exists() or not (dockerfile_dir / "Dockerfile").exists():
            logger.error(f"Dockerfile not found at {dockerfile_dir}")
            return False

        import sys
        proc = await asyncio.create_subprocess_exec(
            "docker", "build", "-t", self.IMAGE_NAME, str(dockerfile_dir),
            stdout=sys.stdout,
            stderr=sys.stderr,
        )
        await proc.wait()

        if proc.returncode != 0:
            logger.error("Docker build failed.")
            return False

        logger.info(f"Docker image '{self.IMAGE_NAME}' built successfully")
        return True

    # ── Container Lifecycle ──

    async def start_container(self, target: str | None = None) -> bool:
        """Start a sandbox container with /workspace volume mount."""
        # Determine workspace path — CWD/workspace/ (captured at startup via get_workspace_root())
        workspace_host = str(get_workspace_root())

        self._container_name = f"{self.CONTAINER_PREFIX}-active"

        # Stop existing container if any
        await self._stop_existing()

        # Start new container
        cmd = [
            "docker", "run", "-d",
            "--name", self._container_name,
            "--network", "host",  # Share host network for scanning
            "-v", f"{workspace_host}:/workspace",
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
            logger.error(f"Failed to start container: {stderr.decode()}")
            return False

        self._container_id = stdout.decode().strip()[:12]
        self._connected = True
        logger.info(f"Container started: {self._container_name} ({self._container_id})")

        # If we have a target, create workspace dir
        if target:
            await self.execute(f"mkdir -p /workspace/{target}/output /workspace/{target}/tools")

        return True

    async def stop_container(self) -> None:
        """Stop and remove the sandbox container."""
        if self._container_name:
            proc = await asyncio.create_subprocess_exec(
                "docker", "rm", "-f", self._container_name,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            await proc.wait()
            self._connected = False
            self._container_id = None
            logger.info("Container stopped")

    async def _stop_existing(self) -> None:
        """Stop any existing container with our name."""
        proc = await asyncio.create_subprocess_exec(
            "docker", "rm", "-f", self._container_name,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        await proc.wait()

    # ── Command Execution ──

    async def execute(self, command: str, timeout: float | None = None) -> dict[str, Any]:
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
            "docker", "exec",
            "-u", "pentester",
            "-w", "/workspace",
            "-i",
            "-e", f"PATH={CONTAINER_PATH}",
            "-e", "GOPATH=/home/pentester/go",
            "-e", "GOROOT=/usr/local/go",
            "-e", "HOME=/home/pentester",
            "-e", "USER=pentester",
            "-e", "SHELL=/bin/bash",
            "-e", "LANG=C.UTF-8",
            "-e", "TERM=xterm-256color",
            "-e", "PIPX_HOME=/home/pentester/.local/pipx",
            "-e", "NPM_CONFIG_PREFIX=/home/pentester/.npm-global",
            "-e", "GEM_HOME=/home/pentester/.gem",
            self._container_name,
            "bash", "--login", "-c", command,
        ]


        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            self._current_proc = proc  # track for force_stop()
            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(), timeout=timeout
                )
            finally:
                self._current_proc = None  # clear after done

            stdout_str = stdout.decode(errors="replace")
            stderr_str = stderr.decode(errors="replace")
            success = proc.returncode == 0

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
                if self._current_proc:
                    self._current_proc.kill()
                    await self._current_proc.wait()
                    self._current_proc = None
            except Exception:
                pass
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
                proc.kill()
                await proc.wait()
            except Exception:
                pass
            # Also kill container-side processes to prevent zombies
            try:
                kill_proc = await asyncio.create_subprocess_exec(
                    "docker", "exec", self._container_name,
                    "bash", "-c", "pkill -KILL -u pentester 2>/dev/null; true",
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                await asyncio.wait_for(kill_proc.wait(), timeout=3.0)
            except Exception:
                pass
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

    def tools_to_ollama_format(self, tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Tools are already in Ollama format."""
        return tools

    def has_tool(self, name: str) -> bool:
        """We only have 'execute'."""
        return name == "execute"

    def filter_tools(self, *args, **kwargs) -> list[dict[str, Any]]:
        """No filtering needed — we only have one tool."""
        return [EXECUTE_TOOL_DEF]

    async def execute_tool(self, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """Execute a tool call from the agent loop."""
        if tool_name != "execute":
            return {"success": False, "error": f"Unknown tool: {tool_name}. Use 'execute' instead."}

        command = arguments.get("command", "")
        timeout = arguments.get("timeout", None)
        if timeout:
            timeout = float(timeout)

        return await self.execute(command, timeout)

    async def force_stop(self) -> None:
        """Force stop all running commands in the container and the local proc."""
        # 1. Kill the Python-side asyncio subprocess immediately
        if self._current_proc:
            try:
                self._current_proc.kill()
                await asyncio.wait_for(self._current_proc.wait(), timeout=2.0)
            except Exception:
                pass
            self._current_proc = None

        # 2. Kill ALL user processes inside the container (SIGTERM then SIGKILL)
        if self._container_name and self._connected:
            try:
                kill_cmd = (
                    # Kill every process owned by pentester except PID 1 (entrypoint)
                    "pkill -TERM -u pentester 2>/dev/null; "
                    "sleep 0.5; "
                    "pkill -KILL -u pentester 2>/dev/null; "
                    "true"
                )
                proc = await asyncio.create_subprocess_exec(
                    "docker", "exec", self._container_name,
                    "bash", "-c", kill_cmd,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                await asyncio.wait_for(proc.wait(), timeout=5.0)
                logger.info("Force stopped all pentester processes in container")
            except Exception as e:
                logger.warning(f"force_stop container kill failed: {e}")

    async def close(self) -> None:
        """Shutdown — stop container."""
        await self.stop_container()

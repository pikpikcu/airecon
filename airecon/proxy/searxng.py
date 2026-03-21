"""SearXNG container lifecycle manager for AIRecon.

Auto-pulls, configures, and starts a self-hosted SearXNG instance
so the agent can use Google/Bing/DDG dorks via a local JSON API.
"""

from __future__ import annotations

import asyncio
import logging
import secrets
import shutil
import time
from pathlib import Path

logger = logging.getLogger("airecon.searxng")

SEARXNG_IMAGE = "docker.io/searxng/searxng:latest"
CONTAINER_NAME = "airecon-searxng"
INTERNAL_PORT = 8080
HEALTH_TIMEOUT = 30  # seconds to wait for SearXNG to become healthy


def _config_dir() -> Path:
    """~/.airecon/searxng/ — persistent across runs."""
    d = Path.home() / ".airecon" / "searxng"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _write_settings(config_dir: Path) -> None:
    """Copy containers/settings.yml to ~/.airecon/searxng/settings.yml.

    Injects a random secret_key at copy time.
    Will NOT overwrite if the destination already exists (user may have edited it).
    """
    settings_path = config_dir / "settings.yml"
    if settings_path.exists():
        return

    # Source: containers/settings.yml next to the Dockerfile
    source = Path(__file__).parent.parent / "containers" / "settings.yml"
    if not source.exists():
        logger.error(f"Source settings.yml not found at {source}")
        return

    content = source.read_text()

    # Inject a unique secret_key — placeholder comment in source file is
    # replaced
    secret_key = secrets.token_hex(32)
    content = content.replace(
        "  # secret_key is injected at runtime by AIRecon",
        f'  secret_key: "{secret_key}"',
    )

    settings_path.write_text(content)
    logger.info(f"SearXNG settings.yml copied to {settings_path}")


class SearXNGManager:
    """Manages the airecon-searxng Docker container lifecycle."""

    def __init__(self, host_port: int = INTERNAL_PORT) -> None:
        self.host_port = host_port
        self._config_dir = _config_dir()
        self._data_dir = self._config_dir / "data"
        self._data_dir.mkdir(parents=True, exist_ok=True)

    @property
    def url(self) -> str:
        return f"http://localhost:{self.host_port}"

    # ── Public API ──

    async def ensure_running(self) -> str | None:
        """Ensure SearXNG container is up and healthy.

        Returns the URL if running, None if it failed to start.
        """
        if not shutil.which("docker"):
            logger.warning("Docker not found — skipping SearXNG auto-start")
            return None

        if await self._is_running():
            logger.info(f"SearXNG already running at {self.url}")
            return self.url

        _write_settings(self._config_dir)

        if not await self._image_exists():
            logger.info(f"Pulling SearXNG image ({SEARXNG_IMAGE})...")
            if not await self._pull_image():
                return None
        else:
            logger.info("SearXNG image already present locally, skipping pull")

        logger.info("Starting SearXNG container...")
        if not await self._start_container():
            return None

        logger.info("Waiting for SearXNG to be ready...")
        if not await self._wait_healthy():
            logger.error("SearXNG did not become healthy in time")
            return None

        logger.info("SearXNG is ready")
        return self.url

    async def stop_container(self) -> None:
        """Stop and remove the SearXNG container."""
        if not shutil.which("docker"):
            return
        proc = await asyncio.create_subprocess_exec(
            "docker", "rm", "-f", CONTAINER_NAME,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        await proc.wait()
        logger.info("SearXNG container stopped")

    async def is_running(self) -> bool:
        return await self._is_running()

    # ── Private helpers ──

    async def _is_running(self) -> bool:
        """Return True if the container is running AND responding to health check."""
        proc = await asyncio.create_subprocess_exec(
            "docker", "ps",
            "--filter", f"name={CONTAINER_NAME}",
            "--filter", "status=running",
            "--format", "{{.Names}}",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await proc.communicate()
        if CONTAINER_NAME not in stdout.decode():
            return False

        # Container is up — verify it actually responds
        return await self._health_check()

    async def _image_exists(self) -> bool:
        """Return True if the SearXNG image is already present locally."""
        proc = await asyncio.create_subprocess_exec(
            "docker", "images", "-q", SEARXNG_IMAGE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await proc.communicate()
        return bool(stdout.decode().strip())

    async def _pull_image(self) -> bool:
        """Pull the SearXNG Docker image."""
        proc = await asyncio.create_subprocess_exec(
            "docker", "pull", SEARXNG_IMAGE,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        await proc.wait()
        if proc.returncode != 0:
            logger.error(f"Failed to pull {SEARXNG_IMAGE}")
            return False
        return True

    async def _start_container(self) -> bool:
        """Start the SearXNG container."""
        # Remove any stopped container with the same name first
        stop_proc = await asyncio.create_subprocess_exec(
            "docker", "rm", "-f", CONTAINER_NAME,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        await stop_proc.wait()

        cmd = [
            "docker", "run", "-d",
            "--name", CONTAINER_NAME,
            "--restart", "unless-stopped",
            "-p", f"{self.host_port}:{INTERNAL_PORT}",
            "-v", f"{self._config_dir}:/etc/searxng",
            "-v", f"{self._data_dir}:/var/cache/searxng",
            "-e", f"SEARXNG_BASE_URL=http://localhost:{self.host_port}/",
        ]

        # If AIRecon sandbox uses host network, we need SearXNG reachable from it too.
        # Use bridge (default) so SearXNG is reachable on host via
        # localhost:8080.
        cmd.append(SEARXNG_IMAGE)

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()

        if proc.returncode != 0:
            logger.error(f"Failed to start SearXNG: {stderr.decode()}")
            return False

        container_id = stdout.decode().strip()[:12]
        logger.info(
            f"SearXNG container started: {CONTAINER_NAME} ({container_id})")
        return True

    async def _health_check(self) -> bool:
        """Return True if SearXNG responds to a JSON search query."""
        import aiohttp
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"{self.url}/search",
                    params={"q": "test", "format": "json"},
                    timeout=aiohttp.ClientTimeout(total=5),
                ) as resp:
                    return resp.status == 200
        except Exception:
            return False

    async def _wait_healthy(self, timeout: int = HEALTH_TIMEOUT) -> bool:
        """Poll health endpoint until SearXNG responds or timeout."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if await self._health_check():
                return True
            await asyncio.sleep(2)
        return False

from __future__ import annotations

import asyncio
import contextlib
import functools
import ipaddress
import json
import logging
import os
import tempfile
import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, AsyncIterator
from urllib.parse import urlparse

import aiohttp
import yaml

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sse_starlette.sse import EventSourceResponse

import threading

from airecon._version import __version__ as _version
from .agent import AgentLoop
from .agent.command_parse import extract_primary_binary
from .agent.constants import CAIDO_BLOCKED_TOOLS
from .config import APP_DIR_NAME, CONFIG_FILENAME, get_config, reload_config
from .docker import DockerEngine
from .mcp import add_mcp_sse_server, list_mcp_servers, mcp_list_tools, set_mcp_enabled
from .llm import LLMClient, create_llm_client

try:
    import orjson

    _USE_ORJSON = True
except ImportError:
    _USE_ORJSON = False


class ORJSONResponse(JSONResponse):
    def render(self, content: Any) -> bytes:
        if _USE_ORJSON:
            return orjson.dumps(content)
        return json.dumps(content).encode("utf-8")


try:
    from fastapi_cache import FastAPICache
    from fastapi_cache.decorator import cache
    from fastapi_cache.backends.inmemory import InMemoryBackend

    _USE_CACHE = True
except ImportError:
    _USE_CACHE = False
    cache = None
    FastAPICache = None
    InMemoryBackend = None


def _cache_or_noop(expire: int = 5):
    def no_op_decorator(func):
        return func

    if not (_USE_CACHE and cache is not None and FastAPICache is not None):
        return no_op_decorator

    def conditional_cache_decorator(func):
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            try:
                _ = FastAPICache._prefix  # type: ignore[union-attr]

                cached_func = cache(expire=expire)(func)  # type: ignore[union-attr]
                return await cached_func(*args, **kwargs)
            except (AssertionError, AttributeError):
                return await func(*args, **kwargs)

        return wrapper

    return conditional_cache_decorator


logger = logging.getLogger("airecon.server")


def _is_local_or_unspecified_host(hostname: str) -> bool:
    host = (hostname or "").strip().lower()
    if host in {"", "localhost"}:
        return True
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return False
    return bool(addr.is_loopback or addr.is_unspecified)


llm_client: LLMClient | None = None
engine: DockerEngine | None = None
agent: AgentLoop | None = None

_agent_busy: bool = False
_agent_busy_lock = asyncio.Lock()
_agent_done_event: asyncio.Event | None = None
_agent_task: asyncio.Task | None = None

_agent_failure_count: int = 0
_agent_failure_cooldown_until: float = 0.0

_HIGH_PRIORITY_PATHS = {"/api/health", "/api/status", "/api/progress"}
_request_start_time: dict[str, float] = {}

_llm_health_failures: list[bool] = []
_llm_health_cooldown_until: float = 0.0
_llm_last_ok_at: float = 0.0
_llm_last_known_ok: bool = False

_MODEL_LIST_TIMEOUT_SECONDS = 10.0


def _llm_status_timeout() -> float:
    return get_config().llm_status_timeout


def _llm_sticky_ok_seconds() -> float:
    return get_config().llm_status_sticky_ok_seconds


_skills_cache: list[dict] | None = None
_skills_cache_lock: asyncio.Lock | None = None
_skills_cache_lock_init = threading.Lock()

_mcp_probe_cache: dict[str, dict[str, Any]] = {}
_mcp_probe_tasks: dict[str, asyncio.Task] = {}
_mcp_probe_lock: asyncio.Lock | None = None
_mcp_probe_lock_init = threading.Lock()
_mcp_prewarm_task: asyncio.Task | None = None


async def _refresh_agent_tool_registry() -> None:
    if not agent:
        return
    refresh_fn = getattr(agent, "refresh_tool_registry", None)
    if not callable(refresh_fn):
        return
    try:
        result = refresh_fn()
        if asyncio.iscoroutine(result):
            await result
    except Exception as e:
        logger.debug("Agent tool registry refresh skipped: %s", e)


def _config_file_path() -> Path:
    return Path.home() / APP_DIR_NAME / CONFIG_FILENAME


def _write_runtime_config_value(key: str, value: Any) -> None:
    config_file = _config_file_path()
    config_file.parent.mkdir(parents=True, exist_ok=True)

    current: dict[str, Any] = {}
    if config_file.exists():
        with config_file.open("r", encoding="utf-8") as f:
            loaded = yaml.safe_load(f)
            if isinstance(loaded, dict):
                current = loaded

    current[key] = value

    temp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=str(config_file.parent),
            delete=False,
        ) as f:
            yaml.safe_dump(current, f, indent=2, sort_keys=False)
            temp_path = Path(f.name)
        temp_path.replace(config_file)
    finally:
        if temp_path and temp_path.exists():
            with contextlib.suppress(OSError):
                temp_path.unlink()

    reload_config()


def _normalize_model_name(model: str) -> str:
    value = str(model or "").strip()
    if not value:
        raise ValueError("Model name cannot be empty")
    if any(ch in value for ch in ("\x00", "\r", "\n")):
        raise ValueError("Model name cannot contain control characters")
    return value


def _extract_model_ids(payload: Any) -> list[str]:
    raw_items: Any
    if isinstance(payload, dict):
        raw_items = payload.get("data")
        if raw_items is None:
            raw_items = payload.get("models")
    else:
        raw_items = payload

    if not isinstance(raw_items, list):
        return []

    models: list[str] = []
    seen: set[str] = set()
    for item in raw_items:
        model_id: Any
        if isinstance(item, dict):
            model_id = item.get("id") or item.get("name")
        else:
            model_id = item
        model = str(model_id or "").strip()
        if not model or model in seen:
            continue
        models.append(model)
        seen.add(model)
    return models


async def _fetch_openai_models() -> list[str]:
    cfg = get_config()
    base_url = str(cfg.openai_base_url or "").rstrip("/")
    if not base_url:
        raise RuntimeError("openai_base_url is not configured")

    headers: dict[str, str] = {}
    api_key = str(getattr(cfg, "openai_api_key", "") or "").strip()
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    url = f"{base_url}/models"
    timeout = aiohttp.ClientTimeout(total=_MODEL_LIST_TIMEOUT_SECONDS)
    async with aiohttp.ClientSession(headers=headers) as session:
        async with session.get(url, timeout=timeout) as resp:
            text = await resp.text()
            if resp.status >= 400:
                detail = text.strip().replace("\n", " ")[:300]
                raise RuntimeError(
                    f"Model list request failed ({resp.status})"
                    + (f": {detail}" if detail else "")
                )
            try:
                payload = await resp.json(content_type=None)
            except Exception:
                payload = json.loads(text)

    return _extract_model_ids(payload)


async def _reload_llm_runtime(model: str | None = None) -> None:
    global llm_client, agent

    new_client = create_llm_client(model=model)
    await new_client._async_init()
    llm_client = new_client
    if agent is not None:
        setattr(agent, "llm", new_client)


def _runtime_llm_payload() -> dict[str, Any]:
    cfg = get_config()
    active_model = getattr(llm_client, "model", None) or cfg.openai_model
    supports_thinking: bool | None = None
    if llm_client is not None:
        supports = getattr(llm_client, "supports_thinking", None)
        if isinstance(supports, bool):
            supports_thinking = supports

    return {
        "current_model": active_model,
        "openai_base_url": cfg.openai_base_url,
        "thinking": {
            "enabled": bool(cfg.llm_enable_thinking),
            "mode": cfg.llm_thinking_mode,
            "request_mode": cfg.llm_thinking_request_mode,
            "supports_thinking": supports_thinking,
        },
    }


def _get_agent_busy_lock() -> asyncio.Lock:
    return _agent_busy_lock


def _get_skills_cache_lock() -> asyncio.Lock:
    global _skills_cache_lock
    if _skills_cache_lock is None:
        with _skills_cache_lock_init:
            if _skills_cache_lock is None:
                _skills_cache_lock = asyncio.Lock()
    return _skills_cache_lock


def _get_mcp_probe_lock() -> asyncio.Lock:
    global _mcp_probe_lock
    if _mcp_probe_lock is None:
        with _mcp_probe_lock_init:
            if _mcp_probe_lock is None:
                _mcp_probe_lock = asyncio.Lock()
    return _mcp_probe_lock


def _shell_blocklist() -> set[str]:
    raw = os.environ.get(
        "AIRECON_SHELL_BLOCKLIST", "tmux,screen,byobu,zellij,abduco,dtach"
    )
    entries = [x.strip().lower() for x in raw.split(",") if x.strip()]
    return set(entries)


def _find_blocked_shell_command(command: str) -> str | None:
    blocked = _shell_blocklist()
    if not blocked:
        return None
    primary = extract_primary_binary(command)
    if primary and primary in blocked:
        return primary
    tokens = str(command or "").replace("\n", " ").split()
    for tok in tokens:
        base = tok.rsplit("/", 1)[-1].strip().lower()
        if base in blocked:
            return base
    return None


def _should_emit_stuck_warning(
    now: float,
    last_event_at: float,
    last_warn_at: float,
    threshold_seconds: float,
    warn_interval_seconds: float,
) -> bool:
    if now - last_event_at <= threshold_seconds:
        return False
    if last_warn_at <= 0:
        return True
    return (now - last_warn_at) >= warn_interval_seconds


def _trace_chat_event(trace_id: str, phase: str, **fields: Any) -> None:
    payload = {"trace_id": trace_id, "phase": phase, **fields}
    try:
        logger.info(
            "chat_trace %s", json.dumps(payload, ensure_ascii=False, default=str)
        )
    except Exception:
        logger.info("chat_trace trace_id=%s phase=%s", trace_id, phase)


def _mcp_cfg_fingerprint(cfg: dict[str, Any]) -> str:
    try:
        return json.dumps(cfg, sort_keys=True, default=str)
    except Exception:
        return str(cfg)


async def _run_mcp_probe(
    server_name: str, cfg: dict[str, Any], fingerprint: str
) -> None:
    status = "error"
    tools: list[str] = []
    tool_count = 0
    total_tools = 0
    error: str | None = "MCP probe did not complete"

    try:
        ok, info = await asyncio.wait_for(
            mcp_list_tools(server_name), timeout=get_config().mcp_probe_timeout
        )
        if ok:
            raw_tools = info.get("tools", []) if isinstance(info, dict) else []
            tool_names: list[str] = []
            for t in raw_tools:
                if isinstance(t, dict):
                    n = t.get("name")
                    if isinstance(n, str) and n.strip():
                        tool_names.append(n.strip())
            tools = tool_names
            tool_count = len(tool_names)
            total_tools = (
                info.get("total_tools")
                if isinstance(info, dict) and isinstance(info.get("total_tools"), int)
                else tool_count
            )
            status = "ready"
            error = None
        else:
            status = "error"
            error = (
                str(info.get("error", "unknown error"))
                if isinstance(info, dict)
                else "unknown error"
            )
    except asyncio.TimeoutError:
        status = "error"
        error = f"MCP startup timed out (>{get_config().mcp_probe_timeout:.0f}s)"
    except BaseException as e:
        status = "error"
        error = f"MCP probe crashed: {e}"
    finally:
        async with _get_mcp_probe_lock():
            _mcp_probe_cache[server_name] = {
                "fingerprint": fingerprint,
                "status": status,
                "tool_count": tool_count,
                "total_tools": total_tools,
                "tools": tools,
                "tool_error": error,
                "updated_at": time.time(),
            }
            _mcp_probe_tasks.pop(server_name, None)


async def _ensure_mcp_probe(server_name: str, cfg: dict[str, Any]) -> None:
    fingerprint = _mcp_cfg_fingerprint(cfg)
    async with _get_mcp_probe_lock():
        cached = _mcp_probe_cache.get(server_name)
        if cached and cached.get("fingerprint") != fingerprint:
            _mcp_probe_cache.pop(server_name, None)
            cached = None

        task = _mcp_probe_tasks.get(server_name)
        if task and task.done():
            _mcp_probe_tasks.pop(server_name, None)
            task = None

        if cached and cached.get("status") == "ready":
            return

        if task is None:
            _mcp_probe_cache[server_name] = {
                "fingerprint": fingerprint,
                "status": "initializing",
                "tool_count": None,
                "tools": [],
                "tool_error": None,
                "updated_at": time.time(),
            }
            _mcp_probe_tasks[server_name] = asyncio.create_task(
                _run_mcp_probe(server_name, cfg, fingerprint),
                name=f"mcp-probe:{server_name}",
            )


async def _prewarm_mcp_servers(wait_timeout: float = 15.0) -> None:
    servers = list_mcp_servers()
    if not servers:
        return

    for name, cfg in sorted(servers.items()):
        if not bool(cfg.get("enabled", True)):
            continue
        if cfg.get("url") or cfg.get("command"):
            await _ensure_mcp_probe(name, cfg)

    deadline = time.time() + wait_timeout
    while time.time() < deadline:
        async with _get_mcp_probe_lock():
            pending = [t for t in _mcp_probe_tasks.values() if not t.done()]
        if not pending:
            break
        await asyncio.sleep(0.2)

    async with _get_mcp_probe_lock():
        ready = sum(
            1 for v in _mcp_probe_cache.values() if str(v.get("status")) == "ready"
        )
        failed = sum(
            1 for v in _mcp_probe_cache.values() if str(v.get("status")) == "error"
        )
        init_left = sum(
            1
            for v in _mcp_probe_cache.values()
            if str(v.get("status")) == "initializing"
        )
    logger.info(
        "MCP prewarm: ready=%d error=%d initializing=%d", ready, failed, init_left
    )


def _build_skills_cache_sync() -> list[dict]:
    skills_dir = Path(__file__).resolve().parent / "skills"
    if not skills_dir.exists():
        return []
    result: list[dict] = []
    for path in sorted(skills_dir.rglob("*.md")):
        category = path.parent.name
        raw_name = path.stem.replace("_", " ").replace("-", " ")
        name = f"[{category}] {raw_name.title()}"
        description = ""
        try:
            for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
                line = line.strip()
                if line.startswith("#"):
                    description = line.lstrip("#").strip()
                    break
                if line and not line.startswith("<!--"):
                    description = line[:120]
                    break
        except Exception as e:
            logger.debug("Expected failure reading skill file description: %s", e)
        result.append({"name": name, "description": description, "category": category})
    return result


async def _get_skills_cache() -> list[dict]:
    global _skills_cache

    if _skills_cache is not None:
        return _skills_cache

    async with _get_skills_cache_lock():
        if _skills_cache is not None:
            return _skills_cache

        _skills_cache = await asyncio.to_thread(_build_skills_cache_sync)
        logger.info("Skills cache: %d skills loaded", len(_skills_cache))
        return _skills_cache


@asynccontextmanager
async def lifespan(app: FastAPI):
    global llm_client, engine, agent, _mcp_prewarm_task

    if os.getenv("AIRECON_TEST_MODE") == "1":
        yield
        return

    try:
        from .memory import get_memory_manager

        get_memory_manager()
        logger.info("Memory database ready at ~/.airecon/memory/airecon.db")
    except Exception as _mem_err:
        logger.debug("Memory initialization skipped: %s", _mem_err)

    if _USE_CACHE:
        try:
            FastAPICache.init(InMemoryBackend(), prefix="airecon-cache")  # type: ignore[union-attr]
            logger.info("Response caching enabled (InMemoryBackend)")
        except Exception as _cache_err:
            logger.warning("Failed to initialize fastapi-cache2: %s", _cache_err)

    cfg = get_config()
    logger.info(f"Starting AIRecon Proxy on {cfg.proxy_host}:{cfg.proxy_port}")
    logger.info(
        f"  LLM backend: OpenAI-compatible {cfg.openai_base_url} (model: {cfg.openai_model})"
    )
    logger.info(f"  Docker image: {cfg.docker_image}")

    startup_failed = False

    try:
        llm_client = create_llm_client()
        await llm_client._async_init()
        engine = DockerEngine()
        agent = AgentLoop(llm=llm_client, engine=engine)

        llm_ok = await llm_client.health_check()
        logger.info(
            f"  LLM status: {'✓ connected' if llm_ok else '✗ unavailable'}"
        )

        if cfg.docker_auto_build:
            image_ok = await engine.ensure_image()
            logger.info(f"  Docker image: {'✓ ready' if image_ok else '✗ failed'}")

        container_ok = await engine.start_container()
        logger.info(f"  Container: {'✓ running' if container_ok else '✗ failed'}")

        try:
            await agent.initialize()
            try:
                _mcp_prewarm_task = asyncio.create_task(
                    _prewarm_mcp_servers(wait_timeout=20.0),
                    name="mcp-prewarm",
                )
            except Exception as _mcp_err:
                logger.warning("MCP prewarm scheduling failed: %s", _mcp_err)
        except Exception as e:
            logger.error(
                f"Agent initialization failed: {e}. Marking agent unavailable."
            )
            agent = None

    except Exception as e:
        logger.exception("Startup failed: %s", e)
        startup_failed = True

    yield

    if startup_failed:
        logger.info("Skipping shutdown cleanup (startup failed)")
    else:
        if agent:
            try:
                logger.info("Saving session before shutdown...")
                await agent.stop()
                logger.info("Session saved successfully")
            except Exception as e:
                logger.error(f"Failed to save session during shutdown: {e}")

        if _mcp_prewarm_task and not _mcp_prewarm_task.done():
            _mcp_prewarm_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await _mcp_prewarm_task

        if llm_client:
            await llm_client.close()
        if engine:
            await engine.close()
        logger.info("AIRecon Proxy shutdown complete")


app = FastAPI(
    title="AIRecon Proxy",
    version=_version,
    description="LLM + Docker Sandbox Bridge",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"https?://(localhost|127\.0\.0\.1)(:\d+)?",
    allow_methods=["*"],
    allow_headers=["*"],
)

if os.environ.get("AIRECON_DEBUG"):

    @app.middleware("http")
    async def _log_requests(request: Request, call_next):
        _t0 = time.monotonic()
        _path = request.url.path

        _request_id = f"{_path}:{_t0}"
        _request_start_time[_request_id] = _t0

        try:
            response = await call_next(request)
            _ms = (time.monotonic() - _t0) * 1000

            if _ms > 5000:
                logger.warning(
                    "SLOW REQUEST: %s %s → %d (%.0fms) — event loop may be saturated",
                    request.method,
                    _path,
                    response.status_code,
                    _ms,
                )
            else:
                logger.info(
                    "%s %s → %d  (%.0fms)",
                    request.method,
                    _path,
                    response.status_code,
                    _ms,
                )

            return response
        finally:
            _request_start_time.pop(_request_id, None)


class ChatRequest(BaseModel):
    message: str = Field(..., max_length=100_000)
    stream: bool = True
    request_id: str | None = Field(default=None, max_length=64)


class ShellRequest(BaseModel):
    command: str = Field(..., min_length=1, max_length=20_000)
    timeout: float | None = Field(default=None, ge=1, le=7200)


class ScopeUpdateRequest(BaseModel):
    action: str = Field(..., min_length=1, max_length=16)  # allow|deny|mode|clear|show
    hosts: list[str] = Field(default_factory=list)
    mode: str | None = Field(default=None, max_length=16)


class ModelSelectRequest(BaseModel):
    model: str = Field(..., min_length=1, max_length=300)


class ThinkToggleRequest(BaseModel):
    enabled: bool


class FileAnalyzeRequest(BaseModel):
    file_path: str = Field(..., max_length=500)
    file_content: str = Field(..., max_length=10_000_000)
    task: str = Field(..., max_length=10_000)
    max_iterations: int = Field(30, ge=1, le=50)


class UserInputResponse(BaseModel):
    request_id: str
    value: str = Field("", max_length=10_000)
    cancelled: bool = False


class MCPAddRequest(BaseModel):
    url: str = Field(..., max_length=2000)
    auth: str | None = Field(default=None, max_length=1000)
    name: str | None = Field(default=None, max_length=100)


class MCPToggleRequest(BaseModel):
    name: str = Field(..., max_length=100)


class StatusResponse(BaseModel):
    status: str
    llm: dict[str, Any]
    docker: dict[str, Any]
    agent: dict[str, Any]


_tool_probe_cache: dict[str, Any] = {"ts": 0.0, "result": {}}


async def _probe_sandbox_tools() -> dict[str, bool]:
    """Probe actual CLI tool availability inside the sandbox via `which`, cached.

    Returns {tool: present}. Falls back to an empty dict when the sandbox is not
    reachable so the caller can degrade to the docker-readiness proxy.
    """
    import time as _time

    cfg = get_config()
    bins = [
        b.strip()
        for b in str(getattr(cfg, "tool_health_probe_binaries", "") or "").split(",")
        if b.strip()
    ]
    if not bins or not engine:
        return {}
    try:
        ttl = float(getattr(cfg, "tool_health_probe_ttl", 300.0) or 300.0)
    except (TypeError, ValueError):
        ttl = 300.0
    now = _time.time()
    if (now - float(_tool_probe_cache.get("ts", 0.0))) < ttl and _tool_probe_cache.get(
        "result"
    ):
        return dict(_tool_probe_cache["result"])

    result: dict[str, bool] = {}
    try:
        cmd = "for b in " + " ".join(bins) + "; do command -v \"$b\" >/dev/null 2>&1 && echo \"$b\"; done"
        out = await asyncio.wait_for(
            engine.execute_tool("execute", {"command": cmd, "timeout": 15}),
            timeout=18,
        )
        stdout = ""
        if isinstance(out, dict):
            stdout = str(out.get("stdout", "") or "")
        present = {line.strip() for line in stdout.splitlines() if line.strip()}
        result = {b: (b in present) for b in bins}
        _tool_probe_cache["ts"] = now
        _tool_probe_cache["result"] = dict(result)
    except Exception as e:
        logger.debug("sandbox tool probe failed: %s", e)
        return {}
    return result


@app.get("/api/status")
@_cache_or_noop(expire=5)
async def get_status() -> ORJSONResponse:
    global _llm_health_failures, _llm_health_cooldown_until
    global _llm_last_ok_at, _llm_last_known_ok

    llm_ok = False
    docker_ok = False
    searxng_ok = False
    import time

    current_time = time.time()
    in_cooldown = current_time < _llm_health_cooldown_until
    llm_probe_soft_fail = False

    if not in_cooldown and llm_client:
        try:
            llm_ok = bool(
                await asyncio.wait_for(
                    llm_client.health_check(),
                    timeout=_llm_status_timeout(),
                )
            )

            _llm_health_failures.append(not llm_ok)
            if len(_llm_health_failures) > 10:
                _llm_health_failures.pop(0)

            if llm_ok:
                _llm_last_ok_at = current_time
                _llm_last_known_ok = True
        except asyncio.TimeoutError:
            llm_probe_soft_fail = True
            logger.debug(
                "LLM health check timed out (%.1fs) — using sticky status fallback when available",
                _llm_status_timeout(),
            )
            _llm_health_failures.append(True)
            if len(_llm_health_failures) > 10:
                _llm_health_failures.pop(0)

            if sum(_llm_health_failures[-10:]) >= 3:
                _llm_health_cooldown_until = current_time + 30.0
                logger.warning(
                    "LLM health check circuit breaker tripped (%d/10 failures) — skipping for 30s",
                    sum(_llm_health_failures[-10:]),
                )
        except Exception as e:
            llm_probe_soft_fail = True
            logger.debug("LLM health check failed: %s", e)
            _llm_health_failures.append(True)
            if len(_llm_health_failures) > 10:
                _llm_health_failures.pop(0)

            if sum(_llm_health_failures[-10:]) >= 3:
                _llm_health_cooldown_until = current_time + 30.0
                logger.warning(
                    "LLM health check circuit breaker tripped (%d/10 failures) — skipping for 30s",
                    sum(_llm_health_failures[-10:]),
                )
    elif in_cooldown:
        llm_probe_soft_fail = True
        logger.debug("LLM health check skipped (circuit breaker cooldown)")

    if (
        not llm_ok
        and llm_probe_soft_fail
        and _llm_last_known_ok
        and (current_time - _llm_last_ok_at) <= _llm_sticky_ok_seconds()
    ):
        llm_ok = True
        logger.debug(
            "Using sticky LLM online status (last_success=%.1fs ago)",
            current_time - _llm_last_ok_at,
        )

    try:
        if engine:
            docker_ok = engine.is_connected
    except Exception as e:
        logger.debug("Docker status check failed: %s", e)

    cfg = get_config()

    searx_url = (cfg.searxng_url or "http://localhost:8080").rstrip("/")
    searx_host = (urlparse(searx_url).hostname or "").lower()
    searx_is_local = _is_local_or_unspecified_host(searx_host)

    probe_responded = False
    probe_unavailable = False
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"{searx_url}/healthz",
                timeout=aiohttp.ClientTimeout(total=2),
            ) as resp:
                probe_responded = True
                if resp.status == 200:
                    body = (await resp.text()).strip().upper()
                    searxng_ok = body == "OK"
                elif resp.status in (404, 405):
                    probe_unavailable = True
                    searxng_ok = False
                else:
                    searxng_ok = False
    except Exception as e:
        logger.debug(
            "SearXNG status check failed (%s): %r",
            type(e).__name__,
            e,
        )
        searxng_ok = False

    if not searxng_ok and searx_is_local and (probe_unavailable or not probe_responded):
        try:
            from .searxng import get_shared_manager

            searxng_mgr = get_shared_manager()
            searxng_ok = await searxng_mgr.is_running()
        except Exception as e:
            logger.debug(
                "SearXNG manager fallback failed (%s): %r", type(e).__name__, e
            )

    agent_stats = agent.get_stats() if agent else {}

    caido_connected = False
    try:
        from .caido_client import CaidoClient

        _token = await asyncio.wait_for(
            CaidoClient._get_token(), timeout=get_config().caido_token_timeout
        )
        caido_connected = bool(_token)
    except Exception:
        caido_connected = False

    if agent and isinstance(agent_stats, dict):
        caido_stats = agent_stats.get("caido")
        if not isinstance(caido_stats, dict):
            caido_stats = {"active": False, "findings_count": 0}
            agent_stats["caido"] = caido_stats
        caido_stats["active"] = bool(
            caido_stats.get("active", False) or caido_connected
        )
        caido_stats["findings_count"] = int(caido_stats.get("findings_count", 0) or 0)

    _active_model = getattr(llm_client, "model", None) or cfg.openai_model
    _active_url = cfg.openai_base_url
    _backend_label = "OpenAI"

    # Tool/service readiness dashboard. The Docker sandbox is where the CLI tools
    # (nuclei/nmap/ffuf/…) live, so docker_ok is their readiness proxy; browser
    # and MCP readiness are reported from agent stats when present.
    _browser_ready = False
    _mcp_ready = False
    if isinstance(agent_stats, dict):
        _browser_ready = bool(
            (agent_stats.get("browser") or {}).get("connected")
            if isinstance(agent_stats.get("browser"), dict)
            else agent_stats.get("browser_connected", False)
        )
        _mcp_info = agent_stats.get("mcp")
        if isinstance(_mcp_info, dict):
            _mcp_ready = bool(_mcp_info.get("connected") or _mcp_info.get("servers"))

    # Real per-binary tool availability (cached). All-present => True; any missing
    # => False (with per-tool detail in tools_detail). Empty dict => probe couldn't
    # run, caller falls back to docker_ok.
    _tool_detail = await _probe_sandbox_tools() if docker_ok else {}
    _cli_probe = all(_tool_detail.values()) if _tool_detail else None

    # Scope guard + scan profile surfaced so the operator can see active posture.
    try:
        from .scope import get_scope_guard

        _guard = get_scope_guard()
        _scope_block = {
            "mode": _guard.mode,
            "allowlist": _guard.allow,
            "denylist": _guard.deny,
            "audit_log_enabled": bool(getattr(cfg, "audit_log_enabled", True)),
        }
    except Exception as e:
        logger.debug("scope status unavailable: %s", e)
        _scope_block = {"mode": "unknown"}

    return ORJSONResponse(
        {
            "status": "ok" if (llm_ok and docker_ok) else "degraded",
            "llm": {
                "connected": llm_ok,
                "url": _active_url,
                "model": _active_model,
                "backend": _backend_label,
            },
            "docker": {
                "connected": docker_ok,
                "image": cfg.docker_image,
            },
            "searxng": {
                "connected": searxng_ok,
                "container": "airecon-searxng",
                "url": cfg.searxng_url if cfg.searxng_url else "http://localhost:8080",
            },
            "tools": {
                "sandbox": docker_ok,
                # Real per-binary availability probed in the sandbox (cached);
                # falls back to the docker-readiness proxy when the probe can't run.
                "cli_tools": (_cli_probe if _cli_probe else docker_ok),
                "browser": _browser_ready,
                "mcp": _mcp_ready,
                "caido": caido_connected,
                "searxng": searxng_ok,
            },
            "tools_detail": _tool_detail,
            "scope": _scope_block,
            "scan_profile": getattr(cfg, "scan_profile", "standard"),
            "agent": agent_stats,
        }
    )


@app.get("/api/health")
async def get_health() -> ORJSONResponse:
    docker_ok = False
    try:
        if engine:
            docker_ok = bool(engine.is_connected)
    except Exception as e:
        logger.debug("Docker liveness check failed: %s", e)

    return ORJSONResponse(
        {
            "status": "ok",
            "proxy": {"connected": True},
            "docker": {
                "connected": docker_ok,
                "image": get_config().docker_image,
            },
            "agent": {
                "initialized": agent is not None,
                "busy": bool(_agent_busy),
                "task_running": bool(_agent_task and not _agent_task.done()),
            },
        }
    )


@app.get("/api/progress")
async def get_progress():
    if not agent:
        return JSONResponse({"error": "Agent not initialized"}, status_code=503)
    return JSONResponse(agent.get_progress())


@app.get("/api/diagnostics")
async def get_diagnostics() -> JSONResponse:
    cfg = get_config()
    _backend = "openai"
    _active_model = getattr(llm_client, "model", None) or cfg.openai_model
    health_status: dict[str, Any] = {
        "status": "ok",
        "timestamp": time.time(),
        "components": {
            "llm": {"status": "disconnected", "details": {}},
            "docker": {"status": "disconnected", "details": {}},
            "agent": {"status": "inactive", "details": {}},
        },
    }

    if llm_client:
        try:
            ok = await asyncio.wait_for(llm_client.health_check(), timeout=10.0)
            health_status["components"]["llm"]["status"] = (
                "connected" if ok else "error"
            )
            health_status["components"]["llm"]["details"] = {
                "model": _active_model,
                "backend": _backend,
            }
        except asyncio.TimeoutError:
            health_status["components"]["llm"]["status"] = "timeout"
            health_status["components"]["llm"]["details"] = {
                "model": _active_model,
                "backend": _backend,
            }
        except Exception as e:
            health_status["components"]["llm"]["status"] = "error"
            health_status["components"]["llm"]["details"] = {"error": str(e)}

    if engine:
        try:
            connected = engine.is_connected
            health_status["components"]["docker"]["status"] = (
                "connected" if connected else "disconnected"
            )
            health_status["components"]["docker"]["details"] = {
                "image": cfg.docker_image
            }
        except Exception as e:
            health_status["components"]["docker"]["status"] = "error"
            health_status["components"]["docker"]["details"] = {"error": str(e)}

    if agent:
        try:
            stats = agent.get_stats()
            health_status["components"]["agent"]["status"] = "active"
            health_status["components"]["agent"]["details"] = {
                "tool_executions": stats.get("tool_counts", {}).get("exec", 0),
                "tokens_used": stats.get("token_usage", {}).get("used", 0),
            }
        except Exception as e:
            health_status["components"]["agent"]["status"] = "error"
            health_status["components"]["agent"]["details"] = {"error": str(e)}

    return JSONResponse(health_status)


@app.get("/api/models")
async def list_models() -> ORJSONResponse:
    cfg = get_config()
    try:
        models = await _fetch_openai_models()
    except Exception as e:
        return ORJSONResponse(
            {
                "error": str(e),
                "models": [],
                "count": 0,
                **_runtime_llm_payload(),
            },
            status_code=502,
        )

    # Cheap, no-network capability hint per model: how AIRecon would request
    # reasoning for it in the current request_mode (auto/off/reasoning_effort/
    # enable_thinking). Lets the UI show which models are reasoning-capable.
    capabilities: dict[str, str] = {}
    try:
        from .llm import LLMClient

        _req_mode = str(getattr(cfg, "llm_thinking_request_mode", "auto") or "auto")
        _probed_unsupported = getattr(LLMClient, "_reasoning_unsupported", set()) or set()
        for _m in models:
            _name = str(_m)
            # Models the runtime probe has already learned to reject reasoning
            # params are reported as "off" regardless of the optimistic strategy.
            if _name in _probed_unsupported:
                capabilities[_name] = "off"
            else:
                capabilities[_name] = LLMClient._resolve_thinking_strategy(_name, _req_mode)
    except Exception as e:
        logger.debug("model capability resolution skipped: %s", e)

    return ORJSONResponse(
        {
            "models": models,
            "count": len(models),
            "capabilities": capabilities,
            "source_url": f"{str(cfg.openai_base_url or '').rstrip('/')}/models",
            **_runtime_llm_payload(),
        }
    )


@app.post("/api/models")
async def select_model(request: ModelSelectRequest) -> ORJSONResponse:
    try:
        model = _normalize_model_name(request.model)
    except ValueError as e:
        return ORJSONResponse({"error": str(e)}, status_code=400)

    try:
        _write_runtime_config_value("openai_model", model)
        await _reload_llm_runtime(model=model)
    except Exception as e:
        logger.exception("Failed to switch runtime model to %s", model)
        return ORJSONResponse({"error": f"Failed to switch model: {e}"}, status_code=500)

    return ORJSONResponse(
        {
            "status": "ok",
            "model": model,
            **_runtime_llm_payload(),
        }
    )


@app.get("/api/think")
async def get_thinking() -> ORJSONResponse:
    return ORJSONResponse(_runtime_llm_payload()["thinking"])


@app.post("/api/think")
async def set_thinking(request: ThinkToggleRequest) -> ORJSONResponse:
    try:
        _write_runtime_config_value("llm_enable_thinking", bool(request.enabled))
        await _reload_llm_runtime()
    except Exception as e:
        logger.exception("Failed to set thinking mode to %s", request.enabled)
        return ORJSONResponse(
            {"error": f"Failed to update thinking mode: {e}"}, status_code=500
        )

    return ORJSONResponse(
        {
            "status": "ok",
            **_runtime_llm_payload()["thinking"],
        }
    )


@app.get("/api/tools")
@_cache_or_noop(expire=30)
async def list_tools() -> ORJSONResponse:
    if not agent or not agent._tools_llm:
        if not engine:
            return ORJSONResponse(
                {"tools": [], "error": "Agent not initialized"}, status_code=503
            )
        tools = await engine.discover_tools()
        return ORJSONResponse({"count": len(tools), "tools": tools})

    await _refresh_agent_tool_registry()
    tools = agent._tools_llm or []
    return ORJSONResponse(
        {
            "count": len(tools),
            "tools": tools,
        }
    )


def _scope_state() -> dict[str, Any]:
    cfg = get_config()

    def _split(v: Any) -> list[str]:
        return [s.strip() for s in str(v or "").split(",") if s.strip()]

    return {
        "mode": str(getattr(cfg, "scope_enforcement", "warn") or "warn"),
        "allowlist": _split(getattr(cfg, "scope_allowlist", "")),
        "denylist": _split(getattr(cfg, "scope_denylist", "")),
        "audit_log_enabled": bool(getattr(cfg, "audit_log_enabled", True)),
    }


@app.post("/api/scope")
async def update_scope(request: ScopeUpdateRequest) -> ORJSONResponse:
    """Add/remove scope allow/deny hosts, set enforcement mode, clear, or show.

    Persists to config.yaml and reloads so the running scope guard picks it up.
    """
    from .config import update_config_values

    action = (request.action or "").strip().lower()
    state = _scope_state()
    allow = list(state["allowlist"])
    deny = list(state["denylist"])
    updates: dict[str, Any] = {}

    if action == "allow":
        for h in request.hosts:
            h = str(h).strip()
            if h and h not in allow:
                allow.append(h)
        updates["scope_allowlist"] = ",".join(allow)
    elif action == "deny":
        for h in request.hosts:
            h = str(h).strip()
            if h and h not in deny:
                deny.append(h)
        updates["scope_denylist"] = ",".join(deny)
    elif action == "remove":
        rm = {str(h).strip() for h in request.hosts}
        updates["scope_allowlist"] = ",".join(h for h in allow if h not in rm)
        updates["scope_denylist"] = ",".join(h for h in deny if h not in rm)
    elif action == "mode":
        mode = str(request.mode or "").strip().lower()
        if mode not in ("off", "warn", "block"):
            return ORJSONResponse(
                {"success": False, "error": "mode must be off|warn|block"},
                status_code=400,
            )
        updates["scope_enforcement"] = mode
    elif action == "clear":
        updates["scope_allowlist"] = ""
        updates["scope_denylist"] = ""
    elif action == "show":
        return ORJSONResponse({"success": True, **state})
    else:
        return ORJSONResponse(
            {"success": False, "error": f"unknown action '{action}' (allow|deny|remove|mode|clear|show)"},
            status_code=400,
        )

    try:
        await asyncio.to_thread(update_config_values, updates)
    except Exception as e:
        logger.error("scope update failed: %s", e)
        return ORJSONResponse({"success": False, "error": str(e)}, status_code=500)

    return ORJSONResponse({"success": True, **_scope_state()})


@app.post("/api/shell")
async def shell_execute(request: ShellRequest) -> ORJSONResponse:
    if not engine:
        return ORJSONResponse(
            {"error": "Docker engine not initialized"}, status_code=503
        )

    command = request.command.strip()
    blocked = _find_blocked_shell_command(command)
    if blocked:
        return ORJSONResponse(
            {
                "success": False,
                "blocked": True,
                "error": f"Command '{blocked}' is disabled in /shell for TUI stability",
            },
            status_code=400,
        )

    # Manual /shell commands go through the SAME scope guard + audit log as the
    # agent's execute path, so the audit trail is complete and out-of-scope hosts
    # are refused under scope_enforcement=block (default "warn" is non-blocking).
    try:
        from .scope import audit_log, get_scope_guard

        _guard = get_scope_guard()
        _in_scope, _scope_reason, _scope_host = _guard.check_command(command)
        audit_log(
            {
                "type": "shell",
                "command": command[:500],
                "in_scope": _in_scope,
                "host": _scope_host,
                "reason": _scope_reason,
                "mode": _guard.mode,
            }
        )
        if not _in_scope and _guard.mode == "block":
            return ORJSONResponse(
                {
                    "success": False,
                    "blocked": True,
                    "error": (
                        f"Command blocked by scope guard: {_scope_reason}. "
                        "Adjust scope_allowlist/scope_denylist or set "
                        "scope_enforcement=warn."
                    ),
                },
                status_code=400,
            )
    except Exception as _scope_err:
        logger.debug("scope guard skipped for /shell: %s", _scope_err)

    args: dict[str, Any] = {"command": command}
    if request.timeout is not None:
        args["timeout"] = request.timeout

    result = await engine.execute_tool("execute", args)
    payload = (
        dict(result)
        if isinstance(result, dict)
        else {"success": False, "error": str(result)}
    )
    payload["blocked"] = False
    return ORJSONResponse(payload)


@app.get("/api/mcp/list")
async def mcp_list() -> ORJSONResponse:
    servers = list_mcp_servers()

    for name, cfg in sorted(servers.items()):
        if not bool(cfg.get("enabled", True)):
            continue
        if cfg.get("url") or cfg.get("command"):
            await _ensure_mcp_probe(name, cfg)

    async with _get_mcp_probe_lock():
        cache_snapshot = dict(_mcp_probe_cache)

    now_ts = time.time()

    items: list[dict[str, Any]] = []
    initializing = 0
    for name, cfg in sorted(servers.items()):
        enabled = bool(cfg.get("enabled", True))
        cached = cache_snapshot.get(name, {})

        if not enabled:
            status = "disabled"
            init_age = 0.0
        else:
            status = str(cached.get("status") or "initializing")
            updated_at = float(cached.get("updated_at") or now_ts)
            init_age = max(0.0, now_ts - updated_at)

            if status == "initializing" and init_age > 55.0:
                status = "error"
                cached = {
                    **cached,
                    "tool_error": "MCP startup is taking too long (>55s). Check command path and runtime dependencies.",
                    "tool_count": 0,
                    "tools": [],
                    "total_tools": 0,
                }

            if status == "initializing":
                initializing += 1

        row: dict[str, Any] = {
            "name": name,
            "transport": "command"
            if cfg.get("command")
            else str(cfg.get("transport") or "http"),
            "url": cfg.get("url"),
            "command": cfg.get("command"),
            "args": cfg.get("args", []),
            "enabled": enabled,
            "status": status,
            "tool_count": cached.get("tool_count") if enabled else 0,
            "total_tools": cached.get("total_tools") if enabled else 0,
            "tools": cached.get("tools", []) if enabled else [],
            "tool_error": cached.get("tool_error") if enabled else None,
            "initializing_for": int(init_age) if status == "initializing" else 0,
        }
        items.append(row)

    return ORJSONResponse(
        {
            "count": len(items),
            "initializing": initializing,
            "servers": items,
        }
    )


@app.post("/api/mcp/add")
async def mcp_add(request: MCPAddRequest) -> ORJSONResponse:
    try:
        added = add_mcp_sse_server(request.url.strip(), request.name, request.auth)
        cfg_added = dict(added.get("config", {}))
        if bool(cfg_added.get("enabled", True)):
            await _ensure_mcp_probe(str(added.get("name", "")), cfg_added)
    except ValueError as e:
        return ORJSONResponse({"error": str(e)}, status_code=400)
    except Exception as e:
        return ORJSONResponse(
            {"error": f"Failed to add MCP server: {e}"}, status_code=500
        )

    await _refresh_agent_tool_registry()

    return ORJSONResponse({"status": "ok", **added})


@app.get("/api/mcp/tools/{name}")
async def mcp_tools(name: str) -> ORJSONResponse:
    servers = list_mcp_servers()
    cfg = servers.get(name)
    if not cfg:
        return ORJSONResponse(
            {"error": f"MCP server '{name}' not found"}, status_code=404
        )
    if not bool(cfg.get("enabled", True)):
        return ORJSONResponse(
            {"error": f"MCP server '{name}' is disabled"}, status_code=400
        )

    try:
        ok, info = await asyncio.wait_for(
            mcp_list_tools(name), timeout=get_config().mcp_tools_list_timeout
        )
    except asyncio.TimeoutError:
        return ORJSONResponse(
            {
                "error": f"MCP tools list timed out (>{get_config().mcp_tools_list_timeout:.0f}s)"
            },
            status_code=504,
        )

    if not ok:
        return ORJSONResponse(
            {
                "error": info.get("error", "unknown error")
                if isinstance(info, dict)
                else str(info)
            },
            status_code=502,
        )

    tools = info.get("tools", []) if isinstance(info, dict) else []
    total_tools = (
        info.get("total_tools")
        if isinstance(info, dict) and isinstance(info.get("total_tools"), int)
        else len(tools)
    )
    truncated = bool(info.get("truncated")) if isinstance(info, dict) else False

    return ORJSONResponse(
        {
            "name": name,
            "count": len(tools),
            "total_tools": total_tools,
            "truncated": truncated,
            "tools": tools,
        }
    )


@app.post("/api/mcp/enable")
async def mcp_enable(request: MCPToggleRequest) -> ORJSONResponse:
    if not set_mcp_enabled(request.name, True):
        return ORJSONResponse(
            {"error": f"MCP server '{request.name}' not found"}, status_code=404
        )

    servers = list_mcp_servers()
    cfg = servers.get(request.name) or {}
    if cfg.get("url") or cfg.get("command"):
        await _ensure_mcp_probe(request.name, cfg)
    await _refresh_agent_tool_registry()
    return ORJSONResponse({"status": "ok", "name": request.name, "enabled": True})


@app.post("/api/mcp/disable")
async def mcp_disable(request: MCPToggleRequest) -> ORJSONResponse:
    if not set_mcp_enabled(request.name, False):
        return ORJSONResponse(
            {"error": f"MCP server '{request.name}' not found"}, status_code=404
        )

    async with _get_mcp_probe_lock():
        task = _mcp_probe_tasks.pop(request.name, None)
        _mcp_probe_cache.pop(request.name, None)
    if task and not task.done():
        task.cancel()

    await _refresh_agent_tool_registry()

    return ORJSONResponse({"status": "ok", "name": request.name, "enabled": False})


@app.get("/api/skills")
@_cache_or_noop(expire=60)
async def list_skills() -> ORJSONResponse:
    skills = await _get_skills_cache()
    return ORJSONResponse({"count": len(skills), "skills": skills})


@app.post("/api/chat", response_model=None)
async def chat(request: ChatRequest) -> EventSourceResponse | JSONResponse:
    global _agent_busy

    trace_id = (str(request.request_id or "").strip() or uuid.uuid4().hex[:12])[:64]
    _trace_chat_event(
        trace_id,
        "chat_request_received",
        stream=bool(request.stream),
        message_len=len(request.message),
    )

    if not agent:
        _trace_chat_event(
            trace_id, "chat_request_rejected", reason="agent_not_initialized"
        )
        return JSONResponse(
            {"error": "Agent not initialized", "request_id": trace_id}, status_code=503
        )

    async with _get_agent_busy_lock():
        if _agent_busy:
            _trace_chat_event(trace_id, "chat_request_rejected", reason="agent_busy")
            return JSONResponse(
                {
                    "error": "Agent is currently busy with another session. "
                    "Use /api/stop to interrupt it, then retry.",
                    "busy": True,
                    "request_id": trace_id,
                },
                status_code=409,
            )
        _agent_busy = True

    if request.stream:
        _trace_chat_event(trace_id, "chat_stream_reserved")
        return EventSourceResponse(
            _stream_agent_events(request.message, trace_id),
            media_type="text/event-stream",
        )

    events: list[dict[str, Any]] = []
    try:
        async for event in agent.process_message(request.message):
            event_data = event.data if isinstance(event.data, dict) else {}
            events.append({"type": event.type, "request_id": trace_id, **event_data})
    finally:
        _agent_busy = False
        _trace_chat_event(trace_id, "chat_nonstream_finished", events=len(events))
    return ORJSONResponse({"events": events, "request_id": trace_id})


async def _stream_agent_events(message: str, trace_id: str) -> AsyncIterator[dict]:
    global _agent_busy, _agent_done_event, _agent_task, _agent_failure_count

    if not agent:
        _agent_failure_count += 1
        _trace_chat_event(trace_id, "sse_rejected", reason="agent_not_initialized")
        yield {
            "event": "error",
            "data": json.dumps(
                {
                    "type": "error",
                    "message": "Agent not initialized",
                    "reason": "agent_not_initialized",
                    "request_id": trace_id,
                }
            ),
        }
        return

    _trace_chat_event(trace_id, "sse_stream_started", message_len=len(message))

    _agent_busy = True
    _agent_done_event = asyncio.Event()

    _agent = agent
    queue: asyncio.Queue[dict] = asyncio.Queue(maxsize=512)
    done_event = _agent_done_event
    _overflow_count = 0
    _last_event_time = time.time()

    async def _run() -> None:
        nonlocal _overflow_count, _last_event_time
        global _agent_busy, _agent_failure_count

        try:
            _IDLE_SOFT_SECONDS = float(
                os.environ.get("AIRECON_AGENT_IDLE_SOFT_TIMEOUT", "120")
            )
            _IDLE_HARD_SECONDS = float(
                os.environ.get(
                    "AIRECON_AGENT_IDLE_HARD_TIMEOUT",
                    str(get_config().agent_idle_hard_timeout),
                )
            )
            _IDLE_HARD_TOOL_SECONDS = float(
                os.environ.get(
                    "AIRECON_AGENT_IDLE_HARD_TIMEOUT_TOOL",
                    str(max(_IDLE_HARD_SECONDS, 1800.0)),
                )
            )
            _IDLE_HARD_USER_INPUT_SECONDS = float(
                os.environ.get(
                    "AIRECON_AGENT_IDLE_HARD_TIMEOUT_USER_INPUT",
                    str(max(_IDLE_HARD_SECONDS, 900.0)),
                )
            )
            _IDLE_POLL_SECONDS = float(os.environ.get("AIRECON_AGENT_IDLE_POLL", "30"))
            _IDLE_WARN_INTERVAL_SECONDS = float(
                os.environ.get("AIRECON_AGENT_IDLE_WARN_INTERVAL", "30")
            )

            if _IDLE_HARD_SECONDS < _IDLE_SOFT_SECONDS:
                _IDLE_HARD_SECONDS = _IDLE_SOFT_SECONDS
            if _IDLE_HARD_TOOL_SECONDS < _IDLE_HARD_SECONDS:
                _IDLE_HARD_TOOL_SECONDS = _IDLE_HARD_SECONDS
            if _IDLE_HARD_USER_INPUT_SECONDS < _IDLE_HARD_SECONDS:
                _IDLE_HARD_USER_INPUT_SECONDS = _IDLE_HARD_SECONDS
            _IDLE_POLL_SECONDS = max(0.5, _IDLE_POLL_SECONDS)

            agen = _agent.process_message(message)
            _last_agent_event_time = time.time()
            _last_idle_warn = 0.0
            _next_event_task: asyncio.Task | None = None
            _active_tool_count = 0
            _last_tool_name = ""
            _waiting_user_input = False

            try:
                while True:
                    if _next_event_task is None:
                        _next_event_task = asyncio.ensure_future(agen.__anext__())

                    try:
                        event = await asyncio.wait_for(
                            asyncio.shield(_next_event_task),
                            timeout=_IDLE_POLL_SECONDS,
                        )
                        _next_event_task = None
                    except asyncio.TimeoutError:
                        now = time.time()
                        idle_for = now - _last_agent_event_time
                        phase = "llm_or_tool_wait"
                        hard_timeout = _IDLE_HARD_SECONDS

                        if _active_tool_count > 0:
                            phase = f"tool:{_last_tool_name or 'unknown'}"
                            hard_timeout = _IDLE_HARD_TOOL_SECONDS
                        elif _waiting_user_input:
                            phase = "user_input_wait"
                            hard_timeout = _IDLE_HARD_USER_INPUT_SECONDS

                        if idle_for >= hard_timeout:
                            raise asyncio.TimeoutError(
                                f"agent idle {idle_for:.1f}s exceeded hard timeout {hard_timeout:.1f}s (phase={phase})"
                            ) from None

                        if (
                            idle_for >= _IDLE_SOFT_SECONDS
                            and (now - _last_idle_warn) >= _IDLE_WARN_INTERVAL_SECONDS
                        ):
                            _last_idle_warn = now
                            warn_msg = (
                                f"Agent idle {idle_for:.1f}s (soft timeout {_IDLE_SOFT_SECONDS:.1f}s, "
                                f"hard timeout {hard_timeout:.1f}s, phase={phase}). "
                                "Still waiting for tool/LLM output..."
                            )
                            logger.warning(warn_msg)
                            _trace_chat_event(
                                trace_id,
                                "idle_soft_warning",
                                idle_seconds=round(idle_for, 1),
                                idle_phase=phase,
                                hard_timeout=round(hard_timeout, 1),
                            )
                            try:
                                queue.put_nowait(
                                    {
                                        "event": "progress",
                                        "data": json.dumps(
                                            {
                                                "type": "progress",
                                                "message": warn_msg,
                                                "reason": "agent_idle_soft_timeout",
                                                "request_id": trace_id,
                                                "phase": phase,
                                            }
                                        ),
                                    }
                                )
                            except asyncio.QueueFull:
                                pass
                        continue
                    except StopAsyncIteration:
                        break

                    event_data = event.data if isinstance(event.data, dict) else {}

                    if event.type == "tool_start":
                        _active_tool_count += 1
                        _last_tool_name = str(
                            event_data.get("tool", "") or _last_tool_name
                        )
                        _waiting_user_input = False
                    elif event.type == "tool_end":
                        _active_tool_count = max(0, _active_tool_count - 1)
                        if _active_tool_count == 0:
                            _last_tool_name = ""
                    elif event.type == "user_input_required":
                        _waiting_user_input = True
                    else:
                        _waiting_user_input = False

                    payload = {"type": event.type, "request_id": trace_id, **event_data}
                    item = {
                        "event": event.type,
                        "data": json.dumps(payload, default=str),
                    }
                    if event.type in {
                        "tool_start",
                        "tool_end",
                        "done",
                        "error",
                        "user_input_required",
                    }:
                        _trace_chat_event(
                            trace_id,
                            event.type,
                            tool=event_data.get("tool"),
                            tool_id=event_data.get("tool_id"),
                        )
                    _last_event_time = time.time()
                    _last_agent_event_time = _last_event_time
                    try:
                        queue.put_nowait(item)
                    except asyncio.QueueFull:
                        _overflow_count += 1

                        if _overflow_count <= 3:
                            logger.warning(
                                f"SSE queue full (overflow #{_overflow_count}) — "
                                "dropping event. Client may be disconnected or slow."
                            )

                        if _overflow_count == 10:
                            try:
                                _ = queue.get_nowait()
                            except asyncio.QueueEmpty:
                                pass

                            try:
                                queue.put_nowait(
                                    {
                                        "event": "error",
                                        "data": json.dumps(
                                            {
                                                "type": "error",
                                                "message": "SSE queue overflow — client too slow or disconnected",
                                                "reason": "sse_queue_overflow",
                                                "request_id": trace_id,
                                            }
                                        ),
                                    }
                                )
                            except asyncio.QueueFull:
                                pass
            finally:
                if _next_event_task and not _next_event_task.done():
                    _next_event_task.cancel()
                    with contextlib.suppress(asyncio.CancelledError, Exception):
                        await _next_event_task
        except asyncio.TimeoutError as _timeout_err:
            snapshot = {
                "queue_size": queue.qsize(),
                "agent_task_done": _agent_task.done() if _agent_task else False,
                "engine_connected": bool(engine.is_connected) if engine else False,
                "llm_initialized": bool(llm_client),
                "active_tool_count": _active_tool_count,
                "active_tool": _last_tool_name,
                "waiting_user_input": _waiting_user_input,
            }
            logger.error(
                "Agent idle hard-timeout triggered: %s. This usually means LLM/tool execution is hung with no new events.",
                _timeout_err,
            )
            _trace_chat_event(
                trace_id,
                "idle_hard_timeout",
                error=str(_timeout_err),
                snapshot=snapshot,
            )
            _agent_failure_count += 1
            try:
                queue.put_nowait(
                    {
                        "event": "error",
                        "data": json.dumps(
                            {
                                "type": "error",
                                "message": "Agent idle hard-timeout — check LLM connectivity and long-running tool execution",
                                "reason": "agent_idle_hard_timeout",
                                "request_id": trace_id,
                                "snapshot": snapshot,
                            }
                        ),
                    }
                )
            except asyncio.QueueFull:
                pass
        except asyncio.CancelledError:
            logger.warning("Agent task was cancelled")
            _trace_chat_event(trace_id, "agent_cancelled")
            try:
                queue.put_nowait(
                    {
                        "event": "error",
                        "data": json.dumps(
                            {
                                "type": "error",
                                "message": "Agent task was cancelled",
                                "reason": "agent_cancelled",
                                "request_id": trace_id,
                            }
                        ),
                    }
                )
            except asyncio.QueueFull:
                pass
        except Exception as _exc:
            logger.error(
                "process_message raised uncaught exception: %s", _exc, exc_info=True
            )
            _trace_chat_event(trace_id, "agent_exception", error=str(_exc))
            _agent_failure_count += 1
            try:
                queue.put_nowait(
                    {
                        "event": "error",
                        "data": json.dumps(
                            {
                                "type": "error",
                                "message": f"Agent error: {_exc}",
                                "reason": "agent_exception",
                                "request_id": trace_id,
                            }
                        ),
                    }
                )
            except asyncio.QueueFull:
                pass
        finally:
            _agent_busy = False
            _trace_chat_event(trace_id, "agent_run_finished", queue_size=queue.qsize())
            done_event.set()

    _agent_task = asyncio.create_task(_run(), name="airecon-agent")

    _SSE_HEARTBEAT_INTERVAL = 10.0
    _SSE_POLL_INTERVAL = 0.5
    _SSE_STUCK_THRESHOLD = float(os.environ.get("AIRECON_SSE_STUCK_THRESHOLD", "60"))
    _SSE_STUCK_WARN_INTERVAL = float(
        os.environ.get("AIRECON_SSE_STUCK_WARN_INTERVAL", "30")
    )
    _MAX_STREAM_TIME = int(os.environ.get("AIRECON_SSE_MAX_STREAM_TIME", "7200"))

    try:
        start_time = time.time()
        _last_heartbeat = start_time
        _last_event_time = start_time
        _last_stuck_warn = 0.0

        while True:
            now = time.time()

            if now - start_time > _MAX_STREAM_TIME:
                logger.warning("SSE stream timed out after max stream time")
                _trace_chat_event(
                    trace_id, "sse_stream_timeout", max_stream_time=_MAX_STREAM_TIME
                )
                _agent_failure_count += 1
                break

            if _agent_task.done() and not _agent_task.cancelled():
                try:
                    _agent_task.result()
                except Exception as _task_err:
                    logger.error(f"Agent background task failed: {_task_err}")
                    _trace_chat_event(
                        trace_id, "agent_task_failed", error=str(_task_err)
                    )
                    _agent_failure_count += 1
                if queue.empty():
                    break

            try:
                item = await asyncio.wait_for(queue.get(), timeout=_SSE_POLL_INTERVAL)
                yield item
                _last_event_time = now
                _last_heartbeat = now
                _last_stuck_warn = 0.0
            except asyncio.TimeoutError:
                if _should_emit_stuck_warning(
                    now=now,
                    last_event_at=_last_event_time,
                    last_warn_at=_last_stuck_warn,
                    threshold_seconds=_SSE_STUCK_THRESHOLD,
                    warn_interval_seconds=_SSE_STUCK_WARN_INTERVAL,
                ):
                    idle_secs = int(max(0.0, now - _last_event_time))
                    snapshot = {
                        "queue_size": queue.qsize(),
                        "agent_task_done": _agent_task.done() if _agent_task else False,
                        "agent_task_cancelled": _agent_task.cancelled()
                        if _agent_task
                        else False,
                        "engine_connected": bool(engine.is_connected)
                        if engine
                        else False,
                    }
                    logger.warning(
                        "SSE stream stuck — no events for %ds. Agent task done=%s",
                        idle_secs,
                        _agent_task.done() if _agent_task else "N/A",
                    )
                    _trace_chat_event(
                        trace_id,
                        "sse_stream_stuck",
                        idle_seconds=idle_secs,
                        snapshot=snapshot,
                    )
                    _last_stuck_warn = now

                if now - _last_heartbeat >= _SSE_HEARTBEAT_INTERVAL:
                    yield {
                        "event": "ping",
                        "data": json.dumps({"type": "ping", "request_id": trace_id}),
                    }
                    _last_heartbeat = now
            except StopAsyncIteration:
                logger.debug(
                    "SSE client disconnected — stopping generator (agent task continues)"
                )
                _trace_chat_event(trace_id, "sse_client_disconnected")
                break
            except asyncio.CancelledError:
                logger.info(
                    "SSE stream cancelled by client (normal disconnect). "
                    "Agent task continues running in background."
                )
                _trace_chat_event(trace_id, "sse_stream_cancelled")
                raise
    except asyncio.CancelledError:
        logger.info(
            "SSE generator cancelled (client disconnected). "
            "Cancelling agent background task to free _agent_busy."
        )
        _trace_chat_event(trace_id, "sse_generator_cancelled")
        if _agent_task and not _agent_task.done():
            _agent_task.cancel()
        raise
    finally:
        _trace_chat_event(trace_id, "sse_generator_finished", overflows=_overflow_count)
        if _agent_task and not _agent_task.done():
            _agent_task.cancel()
            logger.debug("Cancelled agent task on SSE generator exit")
        logger.debug(
            f"SSE generator ended — agent task cancelled (overflows={_overflow_count})"
        )


@app.post("/api/file-analyze", response_model=None)
async def file_analyze(
    request: FileAnalyzeRequest,
) -> EventSourceResponse | JSONResponse:
    if not llm_client or not engine:
        return ORJSONResponse({"error": "Services not ready"}, status_code=503)

    return EventSourceResponse(
        _stream_file_agent_events(request),
        media_type="text/event-stream",
    )


async def _stream_file_agent_events(
    request: FileAnalyzeRequest,
) -> AsyncIterator[dict]:
    mini_agent = AgentLoop(llm_client, engine)  # type: ignore[arg-type]
    mini_agent._is_subagent = True
    mini_agent._override_max_iterations = request.max_iterations

    mini_agent._blocked_tools = set(CAIDO_BLOCKED_TOOLS)

    _fp_parts = Path(request.file_path.lstrip("/")).parts
    _target: str | None = None
    for _i, _part in enumerate(_fp_parts):
        if _part == "workspace" and _i + 1 < len(_fp_parts):
            _target = _fp_parts[_i + 1]
            break
        if _i == 0 and "." in _part and not _part.startswith("."):
            _target = _part
            break
    if _target:
        mini_agent.state.active_target = _target

    _MAX_EMBED = 8_000
    file_snippet = request.file_content[:_MAX_EMBED]
    truncation_note = (
        f"\n[File truncated to {_MAX_EMBED} chars. "
        f"Use read_file tool for full content: {request.file_path}]"
        if len(request.file_content) > _MAX_EMBED
        else ""
    )

    safe_file_path = request.file_path.replace("\n", " ").replace("\r", " ")[:500]
    file_context_message = (
        "You are a security file analyzer. Your sole task is to analyze "
        "the provided file and answer the user question. Be concise and "
        "focus on security-relevant findings.\n\n"
        f"Target file: {safe_file_path}\n"
        f"File content:\n```\n{file_snippet}\n```{truncation_note}"
    )

    try:
        try:
            await mini_agent.initialize(target=_target, user_message=request.task)
        except Exception as e:
            yield {
                "event": "error",
                "data": json.dumps(
                    {
                        "type": "error",
                        "message": f"Mini-agent initialization failed: {e}",
                    }
                ),
            }
            return

        if _target:
            mini_agent.state.active_target = _target

        mini_agent.state.conversation.append(
            {"role": "system", "content": file_context_message}
        )

        async for event in mini_agent.process_message(request.task):
            event_data = event.data if isinstance(event.data, dict) else {}
            yield {
                "event": event.type,
                "data": json.dumps({"type": event.type, **event_data}, default=str),
            }
    finally:
        try:
            await mini_agent.stop()
        except Exception as stop_err:
            logger.debug("Mini-agent cleanup failed: %s", stop_err)


@app.post("/api/reset")
async def reset_conversation() -> JSONResponse:
    if agent:
        agent.reset()
    return ORJSONResponse({"status": "ok", "message": "Conversation reset"})


def _build_session_recap(session: Any) -> str:
    """Synthesize a 'previous progress' recap from durable session state so a
    resumed session shows what was done even after the chat was compacted."""
    try:
        parts: list[str] = []
        target = str(getattr(session, "target", "") or "").strip()
        if target:
            parts.append(f"Target: {target}")
        phases = list(getattr(session, "completed_phases", []) or [])
        if phases:
            parts.append(f"Completed phases: {', '.join(str(p) for p in phases)}")
        tools_run = list(getattr(session, "tools_run", []) or [])
        if tools_run:
            uniq = list(dict.fromkeys(str(t) for t in tools_run))
            shown = ", ".join(uniq[:20])
            more = f" (+{len(uniq) - 20} more)" if len(uniq) > 20 else ""
            parts.append(f"Tools run ({len(uniq)}): {shown}{more}")
        vulns = list(getattr(session, "vulnerabilities", []) or [])
        if vulns:
            parts.append(f"Findings recorded: {len(vulns)}")
            for v in vulns[:8]:
                if not isinstance(v, dict):
                    continue
                title = str(
                    v.get("title") or v.get("finding") or v.get("type") or "finding"
                )[:90]
                sev = str(v.get("severity", "") or "").strip()
                url = str(v.get("url") or v.get("endpoint") or "").strip()
                line = f"  - [{sev}] {title}" if sev else f"  - {title}"
                if url:
                    line += f" — {url}"
                parts.append(line)
        scan_count = getattr(session, "scan_count", None)
        if scan_count:
            parts.append(f"Scans: {scan_count}")
        if not parts:
            return ""
        return "↺ Previous progress (restored):\n" + "\n".join(parts)
    except Exception as e:
        logger.debug("session recap build failed: %s", e)
        return ""


@app.get("/api/history")
async def get_history() -> JSONResponse:
    if not agent:
        return ORJSONResponse({"messages": []})

    if agent._session:
        session_id = agent._session.session_id
        from .agent.session import load_session

        saved_session = load_session(session_id)

        if (
            saved_session
            and hasattr(saved_session, "conversation")
            and saved_session.conversation
        ):
            # Keep chat (user/assistant/tool) messages AND the progress-bearing
            # system messages (compression summary, pinned findings, phase
            # context). Dropping ALL system messages made resume show almost
            # nothing once the conversation had been compacted into summaries.
            _progress_system_prefixes = (
                "[SYSTEM: COMPRESSION SUMMARY",
                "[SYSTEM: PINNED CONTEXT",
                "[SYSTEM: CRITICAL FINDINGS",
                "[SYSTEM: EXPLOIT PHASE",
                "[SYSTEM: REPORT PHASE",
            )
            # Prefer the persistent raw-turn buffer (survives compaction) for the
            # chat replay; fall back to whatever survived in the conversation.
            recent_turns = list(getattr(saved_session, "recent_turns", []) or [])
            chat_source = recent_turns if recent_turns else [
                m for m in saved_session.conversation if m.get("role") != "system"
            ]
            messages = list(chat_source)
            # Always keep progress-bearing system messages from the conversation.
            for msg in saved_session.conversation:
                if msg.get("role") == "system" and str(
                    msg.get("content", "")
                ).startswith(_progress_system_prefixes):
                    messages.append(msg)

            # Prepend a recap synthesized from the durable structured state so the
            # operator always sees prior progress (tools run, phases, findings)
            # even when the raw chat/tool turns were compacted away.
            recap = _build_session_recap(saved_session)
            if recap:
                messages = [{"role": "system", "content": recap}] + messages

            logger.debug(
                f"Loaded {len(messages)} history messages from session {session_id}"
            )
            return ORJSONResponse({"messages": messages, "source": "session_file"})

    messages = [
        msg
        for msg in (agent.state.conversation if hasattr(agent, "state") else [])
        if msg.get("role") != "system"
    ]
    return ORJSONResponse({"messages": messages, "source": "agent_memory"})


@app.post("/api/unload")
async def unload_model_endpoint() -> JSONResponse:
    if llm_client:
        await llm_client.unload_model()
        return ORJSONResponse({"status": "ok", "message": "Model unloaded"})
    return JSONResponse(
        {"status": "error", "message": "LLM client not initialized"}, status_code=503
    )


@app.get("/api/sessions")
async def list_sessions_endpoint() -> JSONResponse:
    from .agent.session import list_sessions

    return ORJSONResponse({"sessions": list_sessions()})


@app.get("/api/session/current")
async def current_session():
    if not agent or not agent._session:
        return ORJSONResponse({"session": None})
    s = agent._session
    return ORJSONResponse(
        {
            "session": {
                "session_id": s.session_id,
                "target": s.target,
                "created_at": s.created_at,
                "scan_count": s.scan_count,
                "subdomains": len(s.subdomains),
                "live_hosts": len(s.live_hosts),
                "vulnerabilities": len(s.vulnerabilities),
            }
        }
    )


@app.post("/api/stop")
async def stop_agent() -> JSONResponse:
    global _agent_busy
    if agent:
        await agent.stop()

        _agent_busy = False
        if _agent_done_event:
            _agent_done_event.set()
        return JSONResponse({"status": "ok", "message": "Agent and tools stopped"})
    return JSONResponse(
        {"status": "error", "message": "Agent not initialized"}, status_code=503
    )


@app.get("/api/user-input/pending")
async def get_pending_user_input() -> JSONResponse:
    if not agent or not getattr(agent, "_user_input_event", None):
        return ORJSONResponse({"pending": False})
    return ORJSONResponse(
        {
            "pending": True,
            "request_id": getattr(agent, "_user_input_request_id", ""),
            "prompt": getattr(agent, "_user_input_prompt", ""),
            "input_type": getattr(agent, "_user_input_type", "text"),
        }
    )


@app.post("/api/user-input")
async def submit_user_input(request: UserInputResponse) -> JSONResponse:
    if not agent:
        return JSONResponse({"error": "Agent not initialized"}, status_code=503)
    evt = getattr(agent, "_user_input_event", None)
    if evt is None:
        return JSONResponse({"error": "No pending input request"}, status_code=400)
    if getattr(agent, "_user_input_request_id", None) != request.request_id:
        return JSONResponse({"error": "request_id mismatch"}, status_code=400)

    agent._user_input_value = request.value
    agent._user_input_cancelled = request.cancelled
    evt.set()
    return ORJSONResponse({"status": "ok"})


def create_app() -> FastAPI:
    return app


def run_server() -> None:
    import uvicorn

    cfg = get_config()

    try:
        uvicorn.run(
            "airecon.proxy.server:app",
            host=cfg.proxy_host,
            port=cfg.proxy_port,
            log_level="critical",
            log_config=None,
            reload=False,
        )
    except KeyboardInterrupt:
        logger.info("Proxy server interrupted by user")
    except Exception as e:
        logger.exception("Proxy server crashed: %s", e)

        raise

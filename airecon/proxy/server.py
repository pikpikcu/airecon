"""FastAPI proxy server: bridges TUI client ↔ Ollama ↔ Docker Sandbox."""

from __future__ import annotations

import asyncio
import json
import logging
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, AsyncIterator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sse_starlette.sse import EventSourceResponse

from airecon._version import __version__ as _version

from .agent import AgentLoop
from .config import get_config
from .docker import DockerEngine
from .ollama import OllamaClient

logger = logging.getLogger("airecon.server")

# Global instances
ollama_client: OllamaClient | None = None
engine: DockerEngine | None = None
agent: AgentLoop | None = None
_chat_lock: asyncio.Lock | None = None

# Skills cache — built once at startup, served on every /api/skills request.
# Skills files don't change at runtime so there is no need to re-scan the
# filesystem on each call (109 files × read_text = noticeable event-loop block).
_skills_cache: list[dict] | None = None


def _build_skills_cache_sync() -> list[dict]:
    """Synchronous helper: scan skills dir and extract name/description/category.

    Designed to run in a thread executor so it never blocks the event loop.
    """
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
        except Exception:  # nosec B110
            pass
        result.append({"name": name, "description": description, "category": category})
    return result


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup/shutdown lifecycle."""
    global ollama_client, engine, agent, _chat_lock, _skills_cache

    cfg = get_config()
    logger.info(f"Starting AIRecon Proxy on {cfg.proxy_host}:{cfg.proxy_port}")
    logger.info(f"  Ollama: {cfg.ollama_url} (model: {cfg.ollama_model})")
    logger.info(f"  Docker image: {cfg.docker_image}")

    # Pre-build skills cache in thread executor so /api/skills is instant
    # (109 × read_text on main event loop caused visible TUI lag).
    _skills_cache = await asyncio.to_thread(_build_skills_cache_sync)
    logger.info("  Skills cache: %d skills loaded", len(_skills_cache))

    # Initialize clients
    ollama_client = OllamaClient()
    engine = DockerEngine()
    agent = AgentLoop(ollama=ollama_client, engine=engine)

    # Check Ollama connectivity
    ollama_ok = await ollama_client.health_check()
    logger.info(f"  Ollama status: {'✓ connected' if ollama_ok else '✗ unavailable'}")

    # Ensure Docker image exists (auto-build if needed)
    if cfg.docker_auto_build:
        image_ok = await engine.ensure_image()
        logger.info(f"  Docker image: {'✓ ready' if image_ok else '✗ failed'}")

    # Start sandbox container
    container_ok = await engine.start_container()
    logger.info(f"  Container: {'✓ running' if container_ok else '✗ failed'}")

    # Initialize agent (discover tools)
    try:
        await agent.initialize()
    except Exception as e:
        logger.error(
            f"Agent initialization failed: {e}. Marking agent unavailable.")
        agent = None  # force 503 on /api/chat rather than silent broken state

    _chat_lock = asyncio.Lock()

    yield

    # Shutdown
    if ollama_client:
        await ollama_client.close()
    if engine:
        await engine.close()
    logger.info("AIRecon Proxy shutdown complete")


app = FastAPI(
    title="AIRecon Proxy",
    version=_version,
    description="Ollama + Docker Sandbox Bridge",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    # Restrict to localhost only — this proxy is not meant to be internet-facing
    allow_origin_regex=r"https?://(localhost|127\.0\.0\.1)(:\d+)?",
    allow_methods=["*"],
    allow_headers=["*"],
)


# ─── Request/Response Models ─────────────────────────────────────────

class ChatRequest(BaseModel):
    message: str = Field(..., max_length=100_000)
    stream: bool = True


class FileAnalyzeRequest(BaseModel):
    file_path: str = Field(..., max_length=500)
    file_content: str = Field(..., max_length=10_000_000)  # 10 MB
    task: str = Field(..., max_length=10_000)
    max_iterations: int = Field(30, ge=1, le=50)


class StatusResponse(BaseModel):
    status: str
    ollama: dict[str, Any]
    docker: dict[str, Any]
    agent: dict[str, Any]


# ─── Routes ──────────────────────────────────────────────────────────

@app.get("/api/status")
async def get_status() -> JSONResponse:
    """Health check and connection status."""
    ollama_ok = await ollama_client.health_check() if ollama_client else False
    docker_ok = engine.is_connected if engine else False

    cfg = get_config()

    return JSONResponse({
        "status": "ok" if (ollama_ok and docker_ok) else "degraded",
        "ollama": {
            "connected": ollama_ok,
            "url": cfg.ollama_url,
            "model": cfg.ollama_model,
        },
        "docker": {
            "connected": docker_ok,
            "image": cfg.docker_image,
        },
        "agent": agent.get_stats() if agent else {},
    })


@app.get("/api/progress")
async def get_progress() -> JSONResponse:
    """Real-time progress data: target, findings, tool counts, phase status."""
    if not agent:
        return JSONResponse(
            {"error": "Agent not initialized"}, status_code=503)
    return JSONResponse(agent.get_progress())


@app.get("/api/tools")
async def list_tools() -> JSONResponse:
    """List available tools."""
    if not agent or not agent._tools_ollama:
        if not engine:
            return JSONResponse(
                {"tools": [], "error": "Agent not initialized"}, status_code=503)
        tools = await engine.discover_tools()
        return JSONResponse({"count": len(tools), "tools": tools})

    # Return the full list prepared for Ollama
    # Convert manually to JSON-friendly format if needed
    tools = agent._tools_ollama
    return JSONResponse({
        "count": len(tools),
        "tools": tools,
    })


@app.get("/api/skills")
async def list_skills() -> JSONResponse:
    """List available skill .md files grouped by category.

    Returns the pre-built cache (populated at startup).  If the cache is
    missing for any reason (e.g. test environment without lifespan), fall back
    to building it in a thread executor so the event loop is never blocked.
    """
    global _skills_cache
    if _skills_cache is None:
        _skills_cache = await asyncio.to_thread(_build_skills_cache_sync)
    return JSONResponse({"count": len(_skills_cache), "skills": _skills_cache})


@app.post("/api/chat", response_model=None)
async def chat(request: ChatRequest) -> EventSourceResponse | JSONResponse:
    """Send a message and get streaming response."""
    if not agent:
        return JSONResponse(
            {"error": "Agent not initialized"}, status_code=503)

    if request.stream:
        return EventSourceResponse(
            _stream_agent_events(request.message),
            media_type="text/event-stream",
        )
    else:
        # Non-streaming: collect all events
        events = []
        if _chat_lock:
            async with _chat_lock:
                async for event in agent.process_message(request.message):
                    event_data = event.data if isinstance(
                        event.data, dict) else {}
                    events.append({"type": event.type, **event_data})
        else:
            async for event in agent.process_message(request.message):
                event_data = event.data if isinstance(event.data, dict) else {}
                events.append({"type": event.type, **event_data})
        return JSONResponse({"events": events})


async def _stream_agent_events(message: str) -> AsyncIterator[dict]:
    """Stream agent events as SSE."""
    if not agent:
        yield {
            "event": "error",
            "data": json.dumps({
                "type": "error",
                "message": "Agent not initialized"
            })
        }
        return

    _agent = agent  # capture non-None reference for nested function
    async def _process():
        async for event in _agent.process_message(message):
            event_data = event.data if isinstance(event.data, dict) else {}
            yield {
                "event": event.type,
                "data": json.dumps({"type": event.type, **event_data}, default=str),
            }

    if _chat_lock:
        async with _chat_lock:
            async for item in _process():
                yield item
    else:
        async for item in _process():
            yield item


@app.post("/api/file-analyze", response_model=None)
async def file_analyze(request: FileAnalyzeRequest) -> EventSourceResponse | JSONResponse:
    """Run a fresh mini-agent to analyze a file without interrupting the main recon agent.

    Creates an independent AgentLoop (not the global one) so both can run
    concurrently.  The mini-agent is limited to read/analysis tools and capped
    at max_iterations to prevent runaway usage.
    """
    if not ollama_client or not engine:
        return JSONResponse({"error": "Services not ready"}, status_code=503)

    return EventSourceResponse(
        _stream_file_agent_events(request),
        media_type="text/event-stream",
    )


async def _stream_file_agent_events(
    request: FileAnalyzeRequest,
) -> AsyncIterator[dict]:
    """Stream events from a mini file-analysis AgentLoop."""
    mini_agent = AgentLoop(ollama_client, engine)  # type: ignore[arg-type]
    mini_agent._is_subagent = True  # prevent loading/overwriting parent session via AIRECON_SESSION_ID
    mini_agent._override_max_iterations = request.max_iterations
    # Block destructive/recon-heavy tools — file analysis only needs read/exec
    mini_agent._blocked_tools = {
        "spawn_agent",
        "quick_fuzz", "advanced_fuzz", "deep_fuzz", "schemathesis_fuzz",
        "caido_automate", "caido_send_request",
    }

    # Extract target from file_path so tool outputs land in the correct
    # workspace folder instead of the fallback "unknown/" directory.
    # Handles paths like:
    #   workspace/example.com/output/file.txt  → "example.com"
    #   /workspace/example.com/output/file.txt → "example.com"
    #   example.com/output/file.txt            → "example.com"
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

    # Embed a snippet of file content in the system prompt so the model has
    # immediate context.  If the file is large, the agent can use read_file.
    _MAX_EMBED = 8_000
    file_snippet = request.file_content[:_MAX_EMBED]
    truncation_note = (
        f"\n[File truncated to {_MAX_EMBED} chars. "
        f"Use read_file tool for full content: {request.file_path}]"
        if len(request.file_content) > _MAX_EMBED else ""
    )

    # Sanitize file_path before embedding in prompt (strip newlines, limit length)
    safe_file_path = request.file_path.replace("\n", " ").replace("\r", " ")[:500]
    file_context_message = (
        "You are a security file analyzer. Your sole task is to analyze "
        "the provided file and answer the user question. Be concise and "
        "focus on security-relevant findings.\n\n"
        f"Target file: {safe_file_path}\n"
        f"File content:\n```\n{file_snippet}\n```{truncation_note}"
    )

    try:
        await mini_agent.initialize(target=_target, user_message=request.task)
    except Exception as e:
        yield {
            "event": "error",
            "data": json.dumps(
                {"type": "error", "message": f"Mini-agent initialization failed: {e}"}
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


@app.post("/api/reset")
async def reset_conversation() -> JSONResponse:
    """Reset conversation history."""
    if agent:
        agent.reset()
    return JSONResponse({"status": "ok", "message": "Conversation reset"})


@app.get("/api/history")
async def get_history() -> JSONResponse:
    """Get conversation history (without system prompt)."""
    if not agent:
        return JSONResponse({"messages": []})

    # Skip system message
    messages = [
        msg for msg in (agent.state.conversation if hasattr(agent, "state") else [])
        if msg.get("role") != "system"
    ]
    return JSONResponse({"messages": messages})


@app.post("/api/unload")
async def unload_model_endpoint() -> JSONResponse:
    """Unload the Ollama model (release VRAM)."""
    if ollama_client:
        await ollama_client.unload_model()
        return JSONResponse({"status": "ok", "message": "Model unloaded"})
    return JSONResponse(
        {"status": "error", "message": "Ollama client not initialized"}, status_code=503)


@app.get("/api/sessions")
async def list_sessions_endpoint() -> JSONResponse:
    """List all saved sessions, sorted by most recently updated."""
    from .agent.session import list_sessions
    return JSONResponse({"sessions": list_sessions()})


@app.get("/api/session/current")
async def current_session() -> JSONResponse:
    """Return the currently active session info."""
    if not agent or not agent._session:
        return JSONResponse({"session": None})
    s = agent._session
    return JSONResponse({
        "session": {
            "session_id": s.session_id,
            "target": s.target,
            "created_at": s.created_at,
            "scan_count": s.scan_count,
            "subdomains": len(s.subdomains),
            "live_hosts": len(s.live_hosts),
            "vulnerabilities": len(s.vulnerabilities),
        }
    })


@app.post("/api/stop")
async def stop_agent() -> JSONResponse:
    """Force stop the agent and all running tools."""
    if agent:
        await agent.stop()
        return JSONResponse(
            {"status": "ok", "message": "Agent and tools stopped"})
    return JSONResponse(
        {"status": "error", "message": "Agent not initialized"}, status_code=503)


def create_app() -> FastAPI:
    """Factory function for creating the app."""
    return app


def run_server() -> None:
    """Run the proxy server."""
    import uvicorn

    cfg = get_config()

    # Logging is already configured in __main__.py or logger.py
    # We just run uvicorn

    uvicorn.run(
        "airecon.proxy.server:app",
        host=cfg.proxy_host,
        port=cfg.proxy_port,
        log_level="critical",
        log_config=None,
        reload=False,
    )

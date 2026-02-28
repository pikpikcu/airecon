"""FastAPI proxy server: bridges TUI client ↔ Ollama ↔ Docker Sandbox."""

from __future__ import annotations

import asyncio
import json
import logging
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sse_starlette.sse import EventSourceResponse

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


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup/shutdown lifecycle."""
    global ollama_client, engine, agent, _chat_lock

    cfg = get_config()
    logger.info(f"Starting AIRecon Proxy on {cfg.proxy_host}:{cfg.proxy_port}")
    logger.info(f"  Ollama: {cfg.ollama_url} (model: {cfg.ollama_model})")
    logger.info(f"  Docker image: {cfg.docker_image}")

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
        logger.warning(f"Agent initialization warning: {e}")

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
    version="0.1.4",
    description="Ollama + Docker Sandbox Bridge",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ─── Request/Response Models ─────────────────────────────────────────

class ChatRequest(BaseModel):
    message: str
    stream: bool = True


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
        return JSONResponse({"error": "Agent not initialized"}, status_code=503)
    return JSONResponse(agent.get_progress())


@app.get("/api/tools")
async def list_tools() -> JSONResponse:
    """List available tools."""
    if not agent or not agent._tools_ollama:
        if not engine:
             return JSONResponse({"tools": [], "error": "Agent not initialized"}, status_code=503)
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
    """List available tools grouped by type."""
    if not agent or not agent._tools_ollama:
        return JSONResponse({"count": 0, "tools": []})

    # Return actual registered tool names — no hardcoded lists
    tool_names = [
        t.get("function", {}).get("name", "?")
        for t in agent._tools_ollama
    ]
    return JSONResponse({
        "count": len(tool_names),
        "tools": sorted(tool_names),
    })


@app.post("/api/chat", response_model=None)
async def chat(request: ChatRequest) -> EventSourceResponse | JSONResponse:
    """Send a message and get streaming response."""
    if not agent:
        return JSONResponse({"error": "Agent not initialized"}, status_code=503)

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
                    events.append({"type": event.type, **event.data})
        else:
            async for event in agent.process_message(request.message):
                events.append({"type": event.type, **event.data})
        return JSONResponse({"events": events})


async def _stream_agent_events(message: str) -> AsyncIterator[dict]:
    """Stream agent events as SSE."""
    if _chat_lock:
        async with _chat_lock:
            async for event in agent.process_message(message):
                yield {
                    "event": event.type,
                    "data": json.dumps({"type": event.type, **event.data}, default=str),
                }
    else:
        async for event in agent.process_message(message):
            yield {
                "event": event.type,
                "data": json.dumps({"type": event.type, **event.data}, default=str),
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
    return JSONResponse({"status": "error", "message": "Ollama client not initialized"}, status_code=503)


@app.post("/api/stop")
async def stop_agent() -> JSONResponse:
    """Force stop the agent and all running tools."""
    if agent:
        await agent.stop()
        return JSONResponse({"status": "ok", "message": "Agent and tools stopped"})
    return JSONResponse({"status": "error", "message": "Agent not initialized"}, status_code=503)


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
        log_level="critical", # Force critical only
        log_config=None,      # Do not override our global logging setup
        reload=False,
    )

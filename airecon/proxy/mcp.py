from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import aiohttp

logger = logging.getLogger("airecon.proxy.mcp")

_MCP_CONFIG_PATH = Path.home() / ".airecon" / "mcp.json"


def _normalize_name(raw: str) -> str:
    name = re.sub(r"[^a-zA-Z0-9_-]+", "_", (raw or "").strip().lower())
    return name.strip("_") or "mcp_server"


def _derive_server_name(url: str) -> str:
    host = (urlparse(url).hostname or "mcp_server").split(".")[0]
    return _normalize_name(host)


def load_mcp_config() -> dict[str, Any]:
    if not _MCP_CONFIG_PATH.exists():
        return {"mcpServers": {}}
    try:
        data = json.loads(_MCP_CONFIG_PATH.read_text(encoding="utf-8"))
    except Exception as e:
        logger.debug("Expected failure loading MCP config: %s", e)
        return {"mcpServers": {}}
    if not isinstance(data, dict):
        return {"mcpServers": {}}
    servers = data.get("mcpServers")
    if not isinstance(servers, dict):
        data["mcpServers"] = {}
    return data


def save_mcp_config(config: dict[str, Any]) -> None:
    _MCP_CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    payload = config if isinstance(config, dict) else {"mcpServers": {}}
    if not isinstance(payload.get("mcpServers"), dict):
        payload["mcpServers"] = {}
    _MCP_CONFIG_PATH.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def list_mcp_servers() -> dict[str, dict[str, Any]]:
    data = load_mcp_config()
    servers = data.get("mcpServers", {})
    if not isinstance(servers, dict):
        return {}
    out: dict[str, dict[str, Any]] = {}
    for name, cfg in servers.items():
        if isinstance(cfg, dict):
            out[str(name)] = dict(cfg)
    return out


def _build_auth_headers(auth: str | None) -> dict[str, str]:
    if not auth:
        return {}

    if auth.startswith("apikey:"):
        token = auth[len("apikey:") :].strip()
        return {"Authorization": f"Bearer {token}"} if token else {}

    normalized = auth
    if "/" in normalized and ":" not in normalized:
        normalized = normalized.replace("/", ":", 1)
    if normalized.startswith("user/"):
        normalized = normalized[len("user/") :]

    if ":" not in normalized:
        return {}
    user, password = normalized.split(":", 1)
    import base64

    token = base64.b64encode(f"{user}:{password}".encode("utf-8")).decode("utf-8")
    return {"Authorization": f"Basic {token}"}


def add_mcp_sse_server(
    url: str, name: str | None = None, auth: str | None = None
) -> dict[str, Any]:
    parsed = urlparse((url or "").strip())
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("Invalid MCP URL. Use http:// or https://")

    cfg = load_mcp_config()
    servers = cfg.setdefault("mcpServers", {})
    if not isinstance(servers, dict):
        cfg["mcpServers"] = {}
        servers = cfg["mcpServers"]

    server_name = _normalize_name(name or _derive_server_name(url))
    if server_name in servers:
        raise ValueError(f"MCP server '{server_name}' already exists")

    entry: dict[str, Any] = {
        "transport": "sse",
        "url": parsed.geturl(),
        "enabled": True,
    }
    headers = _build_auth_headers(auth)
    if headers:
        entry["headers"] = headers

    servers[server_name] = entry
    save_mcp_config(cfg)
    return {"name": server_name, "config": entry}


def set_mcp_enabled(name: str, enabled: bool) -> bool:
    cfg = load_mcp_config()
    servers = cfg.get("mcpServers", {})
    if (
        not isinstance(servers, dict)
        or name not in servers
        or not isinstance(servers[name], dict)
    ):
        return False
    servers[name]["enabled"] = bool(enabled)
    save_mcp_config(cfg)
    return True


def mcp_llm_tools(max_servers: int = 10) -> list[dict[str, Any]]:
    servers = list_mcp_servers()
    enabled_servers = sorted(
        [
            (name, cfg)
            for name, cfg in servers.items()
            if bool(cfg.get("enabled", True))
        ],
        key=lambda x: x[0],
    )[:max_servers]

    tools: list[dict[str, Any]] = []
    for name, server_cfg in enabled_servers:
        tool_name = f"mcp_{_normalize_name(name)}"
        desc_prefix = f"MCP server {name}. "
        if server_cfg.get("command"):
            desc_prefix = f"Command-based MCP server {name}. "
        elif server_cfg.get("url"):
            desc_prefix = f"HTTP/SSE MCP server {name}. "
        desc = (
            desc_prefix
            + "Dynamic tools are discovered at runtime. "
            + "Use search_tools or list_tools to inspect available tools, then call_tool to execute."
        )
        tools.append(
            {
                "type": "function",
                "function": {
                    "name": tool_name,
                    "description": desc,
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "action": {
                                "type": "string",
                                "enum": ["list_tools", "search_tools", "call_tool"],
                                "description": "list_tools: list exposed MCP tools; search_tools: find tool by keyword; call_tool: execute specific tool",
                            },
                            "query": {
                                "type": "string",
                                "description": "Search keyword for search_tools (required)",
                            },
                            "limit": {
                                "type": "integer",
                                "description": "Max results (default 5, max 10)",
                            },
                            "tool": {
                                "type": "string",
                                "description": "Tool name for call_tool (required)",
                            },
                            "arguments": {
                                "type": "object",
                                "description": "Arguments for call_tool",
                            },
                        },
                        "required": ["action"],
                    },
                },
            }
        )
    return tools


def mcp_search_tools_payload(
    payload: dict[str, Any], query: str, limit: int = 10
) -> dict[str, Any]:
    raw_tools = payload.get("tools", []) if isinstance(payload, dict) else []
    if not isinstance(raw_tools, list):
        raw_tools = []

    q = (query or "").strip().lower()
    lim = max(1, min(int(limit or 10), 20))
    if not q:
        return {
            "query": query,
            "count": 0,
            "tools": [],
            "error": "search_tools requires a non-empty query",
        }

    scored: list[tuple[int, dict[str, Any]]] = []
    for item in raw_tools:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name", "")).strip()
        desc = str(item.get("description", "")).strip()
        name_l = name.lower()
        desc_l = desc.lower()

        score = 0
        if name_l == q:
            score = 100
        elif name_l.startswith(q):
            score = 80
        elif q in name_l:
            score = 60
        elif q in desc_l:
            score = 40

        if score > 0:
            scored.append((score, {"name": name, "description": desc}))

    scored.sort(key=lambda x: (x[0], x[1].get("name", "")), reverse=True)
    top = [x[1] for x in scored[:lim]]

    return {
        "query": query,
        "count": len(top),
        "tools": top,
        "total_matches": len(scored),
    }


async def _mcp_http_request(
    server_cfg: dict[str, Any], method: str, params: dict[str, Any]
) -> tuple[bool, dict[str, Any]]:
    url = str(server_cfg.get("url") or "").strip()
    if not url:
        return False, {"error": "MCP server URL is missing"}

    headers = dict(server_cfg.get("headers") or {})
    if "Accept" not in headers:
        headers["Accept"] = "application/json, text/event-stream"
    payload = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}

    try:
        timeout = aiohttp.ClientTimeout(total=30)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.post(url, json=payload, headers=headers) as resp:
                body_text = await resp.text()
                if resp.status >= 400:
                    return False, {"error": f"HTTP {resp.status}: {body_text[:400]}"}
                try:
                    data = json.loads(body_text) if body_text else {}
                except Exception as e:
                    logger.debug(
                        "Expected failure parsing MCP HTTP JSON response: %s", e
                    )
                    return False, {"error": "Invalid MCP HTTP JSON response"}
    except Exception as e:
        return False, {"error": f"MCP HTTP request failed: {e}"}

    if isinstance(data, dict) and "error" in data and data["error"]:
        return False, {"error": str(data["error"])}
    if isinstance(data, dict) and "result" in data and isinstance(data["result"], dict):
        return True, data["result"]
    if isinstance(data, dict):
        return True, data
    return False, {"error": "Unexpected MCP HTTP response format"}


async def _mcp_stdio_request(
    server_cfg: dict[str, Any], method: str, params: dict[str, Any]
) -> tuple[bool, dict[str, Any]]:
    command = str(server_cfg.get("command") or "").strip()
    args = [str(x) for x in (server_cfg.get("args") or [])]
    if not command:
        return False, {"error": "MCP command is missing"}

    env = os.environ.copy()
    extra_env = server_cfg.get("env")
    if isinstance(extra_env, dict):
        env.update({str(k): str(v) for k, v in extra_env.items()})

    try:
        proc = await asyncio.create_subprocess_exec(
            command,
            *args,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
        )
    except Exception as e:
        return False, {"error": f"Failed to start MCP command: {e}"}

    async def _write_message(msg: dict[str, Any]) -> None:
        if proc.stdin is None:
            raise RuntimeError("MCP process stdin not available")
        proc.stdin.write((json.dumps(msg) + "\n").encode("utf-8"))
        await proc.stdin.drain()

    async def _read_response_for(req_id: int, timeout: float = 30.0) -> dict[str, Any]:
        if proc.stdout is None:
            raise RuntimeError("MCP process stdout not available")
        deadline = asyncio.get_running_loop().time() + timeout
        buf = bytearray()
        max_line_bytes = (
            10 * 1024 * 1024
        )

        while True:
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                raise TimeoutError(f"Timeout waiting MCP response id={req_id}")

            chunk = await asyncio.wait_for(proc.stdout.read(4096), timeout=remaining)
            if not chunk:
                raise TimeoutError(
                    f"MCP server closed stdout while waiting response id={req_id}"
                )
            buf.extend(chunk)

            if len(buf) > max_line_bytes:
                raise RuntimeError(
                    f"MCP server response exceeds max chunk size ({max_line_bytes} bytes)"
                )

            while True:
                nl = buf.find(b"\n")
                if nl == -1:
                    break
                line = bytes(buf[: nl + 1])
                del buf[: nl + 1]

                raw = line.decode("utf-8", errors="ignore").strip()
                if not raw:
                    continue
                try:
                    payload = json.loads(raw)
                except Exception as e:
                    logger.debug(
                        "Expected failure parsing MCP stdio response line: %s", e
                    )
                    continue

                if not isinstance(payload, dict):
                    continue

                if payload.get("id") != req_id:
                    continue
                return payload

    try:
        init_req_id = 1
        await _write_message(
            {
                "jsonrpc": "2.0",
                "id": init_req_id,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {"tools": {}},
                    "clientInfo": {"name": "airecon", "version": "0.1.6"},
                },
            }
        )
        init_resp = await _read_response_for(init_req_id, timeout=30.0)
        if init_resp.get("error"):
            return False, {"error": str(init_resp.get("error"))}

        await _write_message(
            {
                "jsonrpc": "2.0",
                "method": "notifications/initialized",
                "params": {},
            }
        )

        req_id = 2
        await _write_message(
            {
                "jsonrpc": "2.0",
                "id": req_id,
                "method": method,
                "params": params if isinstance(params, dict) else {},
            }
        )
        resp = await _read_response_for(req_id, timeout=30.0)
    except Exception as e:
        err_msg = str(e).strip() or type(e).__name__
        stderr_tail = ""
        with contextlib.suppress(Exception):
            if proc.returncode is None:
                proc.kill()
        with contextlib.suppress(Exception):
            await asyncio.wait_for(proc.wait(), timeout=3)
        with contextlib.suppress(Exception):
            if proc.stderr is not None:
                raw_stderr = await asyncio.wait_for(proc.stderr.read(), timeout=0.2)
                stderr_tail = raw_stderr.decode("utf-8", errors="ignore").strip()[:400]
        if (
            "Separator is found" in err_msg and "chunk is longer" in err_msg
        ) or "response exceeds max chunk size" in err_msg.lower():
            err_msg = (
                "MCP server response exceeds max chunk size. "
                "The tools/list payload is too large. "
                "Use action='search_tools' with a query (e.g., query='scan') "
                "instead of listing all tools at once."
            )
        elif stderr_tail:
            err_msg = f"{err_msg} | stderr: {stderr_tail}" if err_msg else stderr_tail
        return False, {"error": f"MCP stdio request failed: {err_msg}"}
    finally:
        with contextlib.suppress(Exception):
            if proc.stdin:
                proc.stdin.close()
        with contextlib.suppress(Exception):
            await asyncio.wait_for(proc.wait(), timeout=3)

    if isinstance(resp, dict) and resp.get("error"):
        return False, {"error": str(resp.get("error"))}

    result = resp.get("result") if isinstance(resp, dict) else None
    if isinstance(result, dict):
        return True, result
    if isinstance(resp, dict):
        return True, resp
    return False, {"error": "Unexpected MCP stdio response format"}


async def mcp_list_tools(server_name: str) -> tuple[bool, dict[str, Any]]:
    server_cfg = list_mcp_servers().get(server_name)
    if not server_cfg:
        return False, {"error": f"MCP server '{server_name}' not found"}
    if not bool(server_cfg.get("enabled", True)):
        return False, {"error": f"MCP server '{server_name}' is disabled"}

    if server_cfg.get("command"):
        ok, payload = await _mcp_stdio_request(server_cfg, "tools/list", {})
    else:
        ok, payload = await _mcp_http_request(server_cfg, "tools/list", {})

    if not ok:
        return False, payload

    tools = payload.get("tools", []) if isinstance(payload, dict) else []
    if not isinstance(tools, list):
        tools = []

    total_tools = (
        payload.get("total_tools")
        if isinstance(payload, dict) and isinstance(payload.get("total_tools"), int)
        else len(tools)
    )

    max_tools = 50
    if len(tools) > max_tools:
        trimmed = tools[:max_tools]
        omitted = len(tools) - max_tools
        return True, {
            "tools": trimmed,
            "truncated": True,
            "total_tools": total_tools,
            "omitted": omitted,
        }

    return True, {"tools": tools, "total_tools": total_tools}


async def mcp_call_tool(
    server_name: str, tool: str, arguments: dict[str, Any] | None = None
) -> tuple[bool, dict[str, Any]]:
    server_cfg = list_mcp_servers().get(server_name)
    if not server_cfg:
        return False, {"error": f"MCP server '{server_name}' not found"}
    if not bool(server_cfg.get("enabled", True)):
        return False, {"error": f"MCP server '{server_name}' is disabled"}

    payload_args = arguments if isinstance(arguments, dict) else {}
    params = {"name": tool, "arguments": payload_args}

    if server_cfg.get("command"):
        ok, payload = await _mcp_stdio_request(server_cfg, "tools/call", params)
    else:
        ok, payload = await _mcp_http_request(server_cfg, "tools/call", params)

    if not ok:
        return False, payload
    return True, {"result": payload}

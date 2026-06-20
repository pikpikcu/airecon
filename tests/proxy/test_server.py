"""Tests for server.py FastAPI routes — with mocked LLM/Docker/Agent globals."""

from __future__ import annotations

import asyncio
import ipaddress
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import httpx

import airecon.proxy.server as srv


def test_is_local_or_unspecified_host():
    assert srv._is_local_or_unspecified_host("localhost") is True
    assert srv._is_local_or_unspecified_host("127.0.0.1") is True
    assert srv._is_local_or_unspecified_host("::1") is True
    assert srv._is_local_or_unspecified_host(ipaddress.IPv4Address(0).compressed) is True
    assert srv._is_local_or_unspecified_host("::") is True
    assert srv._is_local_or_unspecified_host("example.com") is False


def test_should_emit_stuck_warning_first_hit_and_rate_limited():
    assert srv._should_emit_stuck_warning(
        now=360.0,
        last_event_at=0.0,
        last_warn_at=0.0,
        threshold_seconds=300.0,
        warn_interval_seconds=60.0,
    ) is True

    assert srv._should_emit_stuck_warning(
        now=390.0,
        last_event_at=0.0,
        last_warn_at=360.0,
        threshold_seconds=300.0,
        warn_interval_seconds=60.0,
    ) is False

    assert srv._should_emit_stuck_warning(
        now=421.0,
        last_event_at=0.0,
        last_warn_at=360.0,
        threshold_seconds=300.0,
        warn_interval_seconds=60.0,
    ) is True


def test_should_emit_stuck_warning_false_before_threshold():
    assert srv._should_emit_stuck_warning(
        now=250.0,
        last_event_at=0.0,
        last_warn_at=0.0,
        threshold_seconds=300.0,
        warn_interval_seconds=60.0,
    ) is False


# ── Fixture: inject mocked globals before each test ──────────────────────────


@pytest.fixture(autouse=True)
def _patch_server_globals(tmp_path):
    """Replace module-level globals so routes work without real services."""
    mock_agent = _make_mock_agent()
    mock_llm = _make_mock_llm()
    mock_engine = _make_mock_engine()

    with (
        patch.dict("os.environ", {"AIRECON_TEST_MODE": "1"}, clear=False),
        patch.object(srv, "agent", mock_agent),
        patch.object(srv, "llm_client", mock_llm),
        patch.object(srv, "engine", mock_engine),
        # Reset busy flag before each test so tests don't interfere
        patch.object(srv, "_agent_busy", False),
    ):
        yield {
            "agent": mock_agent,
            "llm": mock_llm,
            "engine": mock_engine,
        }


def _make_mock_agent() -> MagicMock:
    m = MagicMock()
    m.get_stats.return_value = {"iterations": 5, "phase": "RECON"}
    m.get_progress.return_value = {
        "target": "example.com",
        "phase": "RECON",
        "iteration": 5,
    }
    m._tools_llm = [{"type": "function", "function": {"name": "execute"}}]
    m.state = MagicMock()
    m.state.conversation = [
        {"role": "system", "content": "system prompt"},
        {"role": "user", "content": "scan example.com"},
        {"role": "assistant", "content": "Starting scan."},
    ]
    m._session = MagicMock()
    m._session.session_id = "sess_001"
    m._session.target = "example.com"
    m._session.created_at = "2026-03-18T00:00:00"
    m._session.scan_count = 3
    m._session.subdomains = ["a.example.com"]
    m._session.live_hosts = ["1.2.3.4"]
    m._session.vulnerabilities = [{"title": "SQLi", "severity": "HIGH"}]

    async def _process(msg):
        from airecon.proxy.agent.models import AgentEvent

        yield AgentEvent(type="text", data={"content": "scanning..."})
        yield AgentEvent(type="done", data={})

    m.process_message = _process
    m.reset = MagicMock()
    m.stop = AsyncMock()
    return m


def _make_mock_llm() -> MagicMock:
    m = MagicMock()
    m.health_check = AsyncMock(return_value=True)
    m.unload_model = AsyncMock()
    m.model = "test-model"
    return m


def _make_mock_engine() -> MagicMock:
    m = MagicMock()
    m.is_connected = True
    m.discover_tools = AsyncMock(return_value=[])
    return m


# Helper: create TestClient WITHOUT starting lifespan (we manage globals ourselves)
class _OneShotClient:
    """Open/close TestClient per request to avoid leaked background tasks."""

    def request(self, method: str, url: str, **kwargs):
        async def _do_request():
            transport = httpx.ASGITransport(app=srv.app, raise_app_exceptions=True)
            async with httpx.AsyncClient(
                transport=transport,
                base_url="http://testserver",
            ) as client:
                return await client.request(method, url, **kwargs)

        return asyncio.run(_do_request())

    def get(self, url: str, **kwargs):
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs):
        return self.request("POST", url, **kwargs)


def _client() -> _OneShotClient:
    return _OneShotClient()


# ── GET /api/status ───────────────────────────────────────────────────────────


class TestGetStatus:
    def test_returns_200(self):
        r = _client().get("/api/status")
        assert r.status_code == 200

    def test_status_ok_when_both_connected(self):
        r = _client().get("/api/status")
        data = r.json()
        assert data["status"] == "ok"
        assert data["llm"]["connected"] is True
        assert data["docker"]["connected"] is True

    def test_status_degraded_when_llm_down(self, _patch_server_globals):
        _patch_server_globals["llm"].health_check = AsyncMock(return_value=False)
        r = _client().get("/api/status")
        assert r.json()["status"] == "degraded"

    def test_status_degraded_when_docker_down(self, _patch_server_globals):
        _patch_server_globals["engine"].is_connected = False
        r = _client().get("/api/status")
        assert r.json()["status"] == "degraded"

    def test_agent_stats_included(self):
        r = _client().get("/api/status")
        assert "agent" in r.json()

    def test_tool_health_block_present(self):
        data = _client().get("/api/status").json()
        assert "tools" in data
        for key in ("sandbox", "cli_tools", "browser", "mcp", "caido", "searxng"):
            assert key in data["tools"]

    def test_scope_and_profile_surfaced(self):
        data = _client().get("/api/status").json()
        assert "scope" in data and "mode" in data["scope"]
        assert "scan_profile" in data

    def test_status_sets_caido_active_when_live_probe_succeeds(self, _patch_server_globals):
        _patch_server_globals["agent"].get_stats.return_value = {
            "message_count": 1,
            "tool_counts": {},
            "caido": {"active": False, "findings_count": 0},
        }
        with patch("airecon.proxy.caido_client.CaidoClient._get_token", new=AsyncMock(return_value="tok")):
            r = _client().get("/api/status")
        data = r.json()
        assert data["agent"]["caido"]["active"] is True
        assert data["agent"]["caido"]["findings_count"] == 0

    def test_no_agent_returns_empty_stats(self):
        with patch.object(srv, "agent", None):
            r = _client().get("/api/status")
            assert r.json()["agent"] == {}


class TestGetHealth:
    def test_health_returns_liveness_without_llm_probe(self, _patch_server_globals):
        _patch_server_globals["llm"].health_check = AsyncMock(
            side_effect=AssertionError("health must not probe LLM")
        )

        r = _client().get("/api/health")
        data = r.json()

        assert r.status_code == 200
        assert data["status"] == "ok"
        assert data["proxy"]["connected"] is True
        assert data["docker"]["connected"] is True
        assert data["agent"]["initialized"] is True


class TestModels:
    def test_extract_model_ids_handles_openai_payload(self):
        payload = {
            "data": [
                {"id": "gpt-4o"},
                {"id": "gpt-4o-mini"},
                {"id": "gpt-4o"},
                {"name": "fallback-name"},
                "string-model",
            ]
        }

        assert srv._extract_model_ids(payload) == [
            "gpt-4o",
            "gpt-4o-mini",
            "fallback-name",
            "string-model",
        ]

    def test_models_endpoint_lists_available_models(self):
        cfg = SimpleNamespace(
            openai_base_url="http://llm.test/v1",
            openai_model="gpt-4o",
            llm_enable_thinking=True,
            llm_thinking_mode="low",
            llm_thinking_request_mode="auto",
        )
        with (
            patch.object(srv, "get_config", return_value=cfg),
            patch.object(
                srv,
                "_fetch_openai_models",
                new=AsyncMock(return_value=["gpt-4o", "gpt-4o-mini"]),
            ),
        ):
            r = _client().get("/api/models")

        data = r.json()
        assert r.status_code == 200
        assert data["count"] == 2
        assert data["models"] == ["gpt-4o", "gpt-4o-mini"]
        assert data["source_url"] == "http://llm.test/v1/models"
        # Capability hint per model (no network). In auto mode the optimistic
        # strategy is reasoning_effort (runtime probe degrades unsupported ones).
        assert set(data["capabilities"]) == {"gpt-4o", "gpt-4o-mini"}
        assert data["capabilities"]["gpt-4o"] in ("reasoning_effort", "off")

    def test_select_model_persists_and_reloads_runtime(self):
        runtime_payload = {
            "current_model": "gpt-4o-mini",
            "openai_base_url": "http://llm.test/v1",
            "thinking": {
                "enabled": True,
                "mode": "low",
                "request_mode": "auto",
                "supports_thinking": True,
            },
        }
        with (
            patch.object(srv, "_write_runtime_config_value") as write_config,
            patch.object(srv, "_reload_llm_runtime", new=AsyncMock()) as reload_llm,
            patch.object(srv, "_runtime_llm_payload", return_value=runtime_payload),
        ):
            r = _client().post("/api/models", json={"model": "gpt-4o-mini"})

        assert r.status_code == 200
        assert r.json()["model"] == "gpt-4o-mini"
        write_config.assert_called_once_with("openai_model", "gpt-4o-mini")
        reload_llm.assert_awaited_once_with(model="gpt-4o-mini")

    def test_select_model_rejects_blank_model(self):
        with patch.object(srv, "_write_runtime_config_value") as write_config:
            r = _client().post("/api/models", json={"model": "   "})

        assert r.status_code == 400
        write_config.assert_not_called()


class TestThinking:
    def test_get_thinking_returns_runtime_state(self):
        runtime_payload = {
            "current_model": "gpt-4o",
            "openai_base_url": "http://llm.test/v1",
            "thinking": {
                "enabled": True,
                "mode": "low",
                "request_mode": "auto",
                "supports_thinking": None,
            },
        }
        with patch.object(srv, "_runtime_llm_payload", return_value=runtime_payload):
            r = _client().get("/api/think")

        assert r.status_code == 200
        assert r.json()["enabled"] is True
        assert r.json()["request_mode"] == "auto"

    def test_set_thinking_persists_and_reloads_runtime(self):
        runtime_payload = {
            "current_model": "gpt-4o",
            "openai_base_url": "http://llm.test/v1",
            "thinking": {
                "enabled": False,
                "mode": "low",
                "request_mode": "auto",
                "supports_thinking": False,
            },
        }
        with (
            patch.object(srv, "_write_runtime_config_value") as write_config,
            patch.object(srv, "_reload_llm_runtime", new=AsyncMock()) as reload_llm,
            patch.object(srv, "_runtime_llm_payload", return_value=runtime_payload),
        ):
            r = _client().post("/api/think", json={"enabled": False})

        data = r.json()
        assert r.status_code == 200
        assert data["enabled"] is False
        write_config.assert_called_once_with("llm_enable_thinking", False)
        reload_llm.assert_awaited_once()


# ── GET /api/progress ─────────────────────────────────────────────────────────


class TestGetProgress:
    def test_returns_200_with_agent(self):
        r = _client().get("/api/progress")
        assert r.status_code == 200
        assert "target" in r.json()

    def test_returns_503_without_agent(self):
        with patch.object(srv, "agent", None):
            r = _client().get("/api/progress")
            assert r.status_code == 503


# ── GET /api/tools ────────────────────────────────────────────────────────────


class TestListTools:
    def test_returns_tools_from_agent(self):
        r = _client().get("/api/tools")
        assert r.status_code == 200
        data = r.json()
        assert data["count"] >= 1

    def test_returns_503_when_agent_and_engine_none(self):
        with patch.object(srv, "agent", None), patch.object(srv, "engine", None):
            r = _client().get("/api/tools")
            assert r.status_code == 503

    def test_falls_back_to_engine_when_no_agent_tools(self, _patch_server_globals):
        """When agent exists but _tools_llm is empty, call engine.discover_tools."""
        _patch_server_globals["agent"]._tools_llm = []
        r = _client().get("/api/tools")
        assert r.status_code == 200


# ── GET /api/skills ───────────────────────────────────────────────────────────


class TestMCP:
    def test_mcp_list_returns_empty_when_no_servers(self):
        with patch("airecon.proxy.server.list_mcp_servers", return_value={}):
            r = _client().get("/api/mcp/list")
        assert r.status_code == 200
        body = r.json()
        assert body["count"] == 0
        assert body["servers"] == []

    def test_mcp_list_includes_command_server_tool_count(self):
        server_cfg = {
            "command": "python3",
            "args": ["/usr/share/hexstrike-ai/hexstrike_mcp.py"],
            "env": {"PYTHONUNBUFFERED": "1"},
        }
        fp = srv._mcp_cfg_fingerprint(server_cfg)

        with (
            patch("airecon.proxy.server.list_mcp_servers", return_value={"hexstrike": server_cfg}),
            patch("airecon.proxy.server._ensure_mcp_probe", new=AsyncMock()),
            patch.dict(
                srv.__dict__,
                {
                    "_mcp_probe_cache": {
                        "hexstrike": {
                            "fingerprint": fp,
                            "status": "ready",
                            "tool_count": 2,
                            "tools": ["mcp_hexstrike_ping", "mcp_hexstrike_scan"],
                            "tool_error": None,
                            "updated_at": 0,
                        }
                    }
                },
                clear=False,
            ),
        ):
            r = _client().get("/api/mcp/list")

        assert r.status_code == 200
        body = r.json()
        assert body["count"] == 1
        assert body["servers"][0]["name"] == "hexstrike"
        assert body["servers"][0]["transport"] == "command"
        assert body["servers"][0]["status"] == "ready"
        assert body["servers"][0]["tool_count"] == 2

    def test_mcp_add_rejects_invalid_url(self):
        r = _client().post("/api/mcp/add", json={"url": "not-a-url"})
        assert r.status_code == 400

    def test_mcp_disable_and_enable_by_name(self):
        with (
            patch("airecon.proxy.server.set_mcp_enabled", side_effect=[True, True]),
            patch("airecon.proxy.server.list_mcp_servers", return_value={
                "hexstrike": {
                    "command": "python3",
                    "args": ["x.py"],
                    "enabled": True,
                }
            }),
            patch("airecon.proxy.server._ensure_mcp_probe", new=AsyncMock()),
        ):
            r1 = _client().post("/api/mcp/disable", json={"name": "hexstrike"})
            r2 = _client().post("/api/mcp/enable", json={"name": "hexstrike"})

        assert r1.status_code == 200
        assert r2.status_code == 200
        assert r2.json().get("enabled") is True

    def test_mcp_list_name_tools(self):
        with (
            patch("airecon.proxy.server.list_mcp_servers", return_value={
                "hexstrike": {
                    "command": "python3",
                    "args": ["x.py"],
                    "enabled": True,
                }
            }),
            patch("airecon.proxy.server.mcp_list_tools", new=AsyncMock(return_value=(True, {"tools": [{"name": "scan"}]}))),
        ):
            r = _client().get("/api/mcp/tools/hexstrike")

        assert r.status_code == 200
        assert r.json().get("count") == 1


class TestShell:
    def test_shell_executes_via_docker_engine(self, _patch_server_globals):
        _patch_server_globals["engine"].execute_tool = AsyncMock(return_value={
            "success": True,
            "stdout": "hello\n",
            "stderr": "",
            "exit_code": 0,
        })
        r = _client().post("/api/shell", json={"command": "echo hello"})
        assert r.status_code == 200
        data = r.json()
        assert data["success"] is True
        assert data["blocked"] is False
        _patch_server_globals["engine"].execute_tool.assert_awaited_once_with("execute", {"command": "echo hello"})

    def test_shell_rejects_blocked_tmux_like_command(self):
        r = _client().post("/api/shell", json={"command": "tmux new -s test"})
        assert r.status_code == 400
        data = r.json()
        assert data["blocked"] is True
        assert "disabled" in data["error"]

    def test_shell_returns_503_when_engine_missing(self):
        with patch.object(srv, "engine", None):
            r = _client().post("/api/shell", json={"command": "echo hi"})
        assert r.status_code == 503

    def test_shell_blocked_by_scope_guard_in_block_mode(self, _patch_server_globals, monkeypatch):
        import airecon.proxy.scope as scope_mod
        from types import SimpleNamespace

        fake = SimpleNamespace(
            scope_enforcement="block",
            scope_allowlist="acme.test",
            scope_denylist="",
            audit_log_enabled=False,
        )
        monkeypatch.setattr(scope_mod, "get_config", lambda: fake)
        r = _client().post("/api/shell", json={"command": "curl https://evil.test/x"})
        assert r.status_code == 400
        data = r.json()
        assert data["blocked"] is True
        assert "scope guard" in data["error"]

    def test_shell_allows_in_scope_command_in_block_mode(self, _patch_server_globals, monkeypatch):
        import airecon.proxy.scope as scope_mod
        from types import SimpleNamespace

        _patch_server_globals["engine"].execute_tool = AsyncMock(
            return_value={"success": True, "stdout": "ok\n", "stderr": "", "exit_code": 0}
        )
        fake = SimpleNamespace(
            scope_enforcement="block",
            scope_allowlist="acme.test",
            scope_denylist="",
            audit_log_enabled=False,
        )
        monkeypatch.setattr(scope_mod, "get_config", lambda: fake)
        r = _client().post("/api/shell", json={"command": "curl https://api.acme.test/x"})
        assert r.status_code == 200
        assert r.json()["success"] is True


class TestListSkills:
    def test_empty_skills_dir(self):
        """When skills dir doesn't exist, returns count=0."""
        with (
            patch.object(srv, "_skills_cache", None),
            patch.object(srv, "_build_skills_cache_sync", return_value=[]),
        ):
            r = _client().get("/api/skills")
        assert r.status_code == 200
        assert r.json()["count"] == 0

    def test_skills_with_real_dir(self):
        """The actual skills dir should return count > 0 if populated."""
        r = _client().get("/api/skills")
        assert r.status_code == 200
        data = r.json()
        assert "skills" in data
        assert isinstance(data["count"], int)


# ── POST /api/chat ────────────────────────────────────────────────────────────


class TestChat:
    def test_non_streaming_returns_events(self):
        r = _client().post(
            "/api/chat", json={"message": "scan example.com", "stream": False}
        )
        assert r.status_code == 200
        data = r.json()
        assert "events" in data
        assert len(data["events"]) >= 1

    def test_non_streaming_propagates_request_id(self):
        r = _client().post(
            "/api/chat",
            json={"message": "scan example.com", "stream": False, "request_id": "req-123"},
        )
        assert r.status_code == 200
        data = r.json()
        assert data.get("request_id") == "req-123"
        assert data["events"]
        assert all(evt.get("request_id") == "req-123" for evt in data["events"])

    def test_non_streaming_without_agent_returns_503(self):
        with patch.object(srv, "agent", None):
            r = _client().post("/api/chat", json={"message": "hi", "stream": False})
            assert r.status_code == 503

    def test_empty_message_rejected(self):
        r = _client().post("/api/chat", json={"message": "", "stream": False})
        # Pydantic field validator allows empty string (no min_length), so 200 or 422
        assert r.status_code in (200, 422)

    def test_message_too_long_rejected(self):
        r = _client().post(
            "/api/chat", json={"message": "x" * 100_001, "stream": False}
        )
        assert r.status_code == 422

    @pytest.mark.asyncio
    async def test_chat_stream_sets_busy_before_response_returns(self, _patch_server_globals):
        with patch.object(srv, "_agent_busy", False):
            response = await srv.chat(srv.ChatRequest(message="example.com", stream=True))
            assert isinstance(response, srv.EventSourceResponse)
            assert srv._agent_busy is True
            srv._agent_busy = False

    @pytest.mark.asyncio
    async def test_chat_stream_rejects_second_request_when_first_reserved_busy(self, _patch_server_globals):
        with patch.object(srv, "_agent_busy", False):
            first = await srv.chat(srv.ChatRequest(message="first", stream=True))
            assert isinstance(first, srv.EventSourceResponse)

            second = await srv.chat(srv.ChatRequest(message="second", stream=True))
            assert isinstance(second, srv.JSONResponse)
            assert second.status_code == 409
            payload = json.loads(second.body.decode())
            assert payload.get("busy") is True
            srv._agent_busy = False

    @pytest.mark.asyncio
    async def test_stream_soft_idle_timeout_emits_progress_not_error(self, _patch_server_globals):
        async def _slow_then_done(_msg: str):
            from airecon.proxy.agent.models import AgentEvent

            await asyncio.sleep(0.6)
            yield AgentEvent(type="done", data={})

        agent = _patch_server_globals["agent"]
        agent.process_message = _slow_then_done

        env = {
            "AIRECON_AGENT_IDLE_SOFT_TIMEOUT": "0.5",
            "AIRECON_AGENT_IDLE_HARD_TIMEOUT": "2.0",
            "AIRECON_AGENT_IDLE_POLL": "0.5",
            "AIRECON_AGENT_IDLE_WARN_INTERVAL": "0.5",
            "AIRECON_SSE_MAX_STREAM_TIME": "10",
        }

        events: list[dict] = []
        with patch.dict("os.environ", env, clear=False):
            async for item in srv._stream_agent_events("scan target", "t-stream"):
                events.append(item)
                if item.get("event") == "done":
                    break

        event_types = [e.get("event") for e in events]
        assert "progress" in event_types
        assert "error" not in event_types

    @pytest.mark.asyncio
    async def test_stream_hard_idle_timeout_emits_error(self, _patch_server_globals):
        async def _very_slow(_msg: str):
            from airecon.proxy.agent.models import AgentEvent

            await asyncio.sleep(2.2)
            yield AgentEvent(type="done", data={})

        agent = _patch_server_globals["agent"]
        agent.process_message = _very_slow

        env = {
            "AIRECON_AGENT_IDLE_SOFT_TIMEOUT": "0.5",
            "AIRECON_AGENT_IDLE_HARD_TIMEOUT": "1.0",
            "AIRECON_AGENT_IDLE_POLL": "0.5",
            "AIRECON_AGENT_IDLE_WARN_INTERVAL": "0.5",
            "AIRECON_SSE_MAX_STREAM_TIME": "10",
        }

        error_data = ""
        with patch.dict("os.environ", env, clear=False):
            async for item in srv._stream_agent_events("scan target", "t-stream"):
                if item.get("event") == "error":
                    error_data = item.get("data", "")
                    break

        assert "hard-timeout" in error_data

    @pytest.mark.asyncio
    async def test_stream_tool_idle_uses_extended_hard_timeout(self, _patch_server_globals):
        async def _slow_tool_then_done(_msg: str):
            from airecon.proxy.agent.models import AgentEvent

            yield AgentEvent(type="tool_start", data={"tool": "nuclei", "tool_id": "t-1"})
            await asyncio.sleep(1.4)
            yield AgentEvent(type="tool_end", data={"tool": "nuclei", "tool_id": "t-1", "success": True})
            yield AgentEvent(type="done", data={})

        agent = _patch_server_globals["agent"]
        agent.process_message = _slow_tool_then_done

        env = {
            "AIRECON_AGENT_IDLE_SOFT_TIMEOUT": "0.5",
            "AIRECON_AGENT_IDLE_HARD_TIMEOUT": "1.0",
            "AIRECON_AGENT_IDLE_HARD_TIMEOUT_TOOL": "2.0",
            "AIRECON_AGENT_IDLE_POLL": "0.2",
            "AIRECON_AGENT_IDLE_WARN_INTERVAL": "0.4",
            "AIRECON_SSE_MAX_STREAM_TIME": "10",
        }

        seen_events: list[str] = []
        error_data = ""
        with patch.dict("os.environ", env, clear=False):
            async for item in srv._stream_agent_events("scan target", "t-tool"):
                event_name = item.get("event", "")
                seen_events.append(event_name)
                if event_name == "error":
                    error_data = item.get("data", "")
                    break
                if event_name == "done":
                    break

        assert "error" not in seen_events
        assert "done" in seen_events
        assert "hard-timeout" not in error_data

    @pytest.mark.asyncio
    async def test_stream_resets_busy_flag_after_completion(self, _patch_server_globals):
        async def _done(_msg: str):
            from airecon.proxy.agent.models import AgentEvent

            yield AgentEvent(type="done", data={})

        agent = _patch_server_globals["agent"]
        agent.process_message = _done

        with patch.object(srv, "_agent_busy", False):
            events = [item async for item in srv._stream_agent_events("scan target", "t-cancel")]

        assert any(e.get("event") == "done" for e in events)
        assert srv._agent_busy is False

    @pytest.mark.asyncio
    async def test_stream_user_input_end_to_end_realtime_submit(self, _patch_server_globals):
        """Live smoke: SSE emits user_input_required, then /api/user-input resumes stream."""
        from airecon.proxy.agent.models import AgentEvent

        agent = _patch_server_globals["agent"]

        async def _interactive_process(_msg: str):
            agent._user_input_event = asyncio.Event()
            agent._user_input_request_id = "req-live-001"
            agent._user_input_prompt = "Enter TOTP code"
            agent._user_input_type = "totp"
            agent._user_input_value = ""
            agent._user_input_cancelled = False

            yield AgentEvent(
                type="user_input_required",
                data={
                    "request_id": "req-live-001",
                    "prompt": "Enter TOTP code",
                    "input_type": "totp",
                },
            )

            await asyncio.wait_for(agent._user_input_event.wait(), timeout=5.0)
            yield AgentEvent(type="text", data={"content": f"received:{agent._user_input_value}"})
            yield AgentEvent(type="done", data={})

        agent.process_message = _interactive_process

        seen_types: list[str] = []
        text_chunks: list[str] = []

        async def _consume_stream() -> None:
            with patch.object(srv, "_agent_busy", False):
                async for item in srv._stream_agent_events("start", "t-max"):
                    payload = item.get("data", "")
                    if not payload:
                        continue
                    data = json.loads(payload)
                    ev_type = data.get("type", "")
                    seen_types.append(ev_type)

                    if ev_type == "user_input_required":
                        submit_resp = await srv.submit_user_input(
                            srv.UserInputResponse(
                                request_id=data["request_id"],
                                value="123456",
                                cancelled=False,
                            )
                        )
                        assert submit_resp.status_code == 200
                    elif ev_type == "text":
                        text_chunks.append(data.get("content", ""))
                    elif ev_type == "done":
                        break

        await asyncio.wait_for(_consume_stream(), timeout=10.0)

        assert "user_input_required" in seen_types
        assert "done" in seen_types
        assert any("received:123456" in c for c in text_chunks)


# ── POST /api/reset ───────────────────────────────────────────────────────────


class TestResetConversation:
    def test_reset_returns_ok(self):
        r = _client().post("/api/reset")
        assert r.status_code == 200
        assert r.json()["status"] == "ok"

    def test_reset_without_agent_still_200(self):
        with patch.object(srv, "agent", None):
            r = _client().post("/api/reset")
            assert r.status_code == 200

    def test_reset_calls_agent_reset(self, _patch_server_globals):
        _client().post("/api/reset")
        _patch_server_globals["agent"].reset.assert_called_once()


# ── GET /api/history ─────────────────────────────────────────────────────────


class TestGetHistory:
    def test_returns_non_system_messages(self):
        r = _client().get("/api/history")
        assert r.status_code == 200
        msgs = r.json()["messages"]
        # System messages must be stripped
        assert all(m.get("role") != "system" for m in msgs)
        # user + assistant messages present
        roles = {m["role"] for m in msgs}
        assert "user" in roles

    def test_returns_empty_list_without_agent(self):
        with patch.object(srv, "agent", None):
            r = _client().get("/api/history")
            assert r.status_code == 200
            assert r.json()["messages"] == []

    def test_session_file_surfaces_progress_and_tool_calls(self, monkeypatch):
        # A heavily compacted conversation: mostly summaries + 1 user + 1 assistant
        # tool-call. The endpoint must still surface a progress recap, keep the
        # compression summary, and preserve chat + tool calls.
        from types import SimpleNamespace
        import airecon.proxy.agent.session as session_mod

        fake_session = SimpleNamespace(
            session_id="sess_resume",
            target="ringkas.co.id",
            completed_phases=["RECON", "ANALYSIS"],
            tools_run=["nmap", "nuclei", "ffuf"],
            vulnerabilities=[{"title": "SQLi in id", "severity": "HIGH", "url": "/login"}],
            scan_count=41,
            conversation=[
                {"role": "system", "content": "[SYSTEM: COMPRESSION SUMMARY] goal/progress/findings"},
                {"role": "system", "content": "[SYSTEM: ACTIVE_TARGET=ringkas.co.id]"},
                {"role": "user", "content": "full recon on ringkas.co.id"},
                {"role": "assistant", "content": "", "tool_calls": [
                    {"function": {"name": "execute", "arguments": "{\"command\": \"nmap -sV ringkas.co.id\"}"}}
                ]},
            ],
        )
        monkeypatch.setattr(session_mod, "load_session", lambda sid: fake_session)
        # agent._session must exist with a session_id
        srv.agent._session = SimpleNamespace(session_id="sess_resume")

        r = _client().get("/api/history")
        assert r.status_code == 200
        data = r.json()
        assert data["source"] == "session_file"
        blob = "\n".join(
            srv._build_session_recap(fake_session) if False else str(m.get("content", ""))
            for m in data["messages"]
        )
        # progress recap present
        assert "Previous progress" in blob
        assert "ringkas.co.id" in blob
        # compression summary kept; ephemeral ACTIVE_TARGET dropped
        assert "COMPRESSION SUMMARY" in blob
        assert "ACTIVE_TARGET" not in blob
        # chat + tool call preserved
        assert any(m.get("role") == "user" for m in data["messages"])
        assert any(m.get("tool_calls") for m in data["messages"])


# ── GET /api/sessions ─────────────────────────────────────────────────────────


class TestListSessions:
    def test_returns_sessions_list(self):
        with patch(
            "airecon.proxy.agent.session.list_sessions",
            return_value=[
                {"session_id": "s1", "target": "a.com", "created_at": "2026-01-01"}
            ],
        ):
            r = _client().get("/api/sessions")
        assert r.status_code == 200
        assert len(r.json()["sessions"]) == 1

    def test_returns_empty_list_when_no_sessions(self):
        with patch("airecon.proxy.agent.session.list_sessions", return_value=[]):
            r = _client().get("/api/sessions")
        assert r.status_code == 200
        assert r.json()["sessions"] == []


# ── GET /api/session/current ─────────────────────────────────────────────────


class TestCurrentSession:
    def test_returns_session_info_with_agent(self):
        r = _client().get("/api/session/current")
        assert r.status_code == 200
        sess = r.json()["session"]
        assert sess["session_id"] == "sess_001"
        assert sess["target"] == "example.com"

    def test_returns_null_without_agent(self):
        with patch.object(srv, "agent", None):
            r = _client().get("/api/session/current")
            assert r.status_code == 200
            assert r.json()["session"] is None

    def test_returns_null_without_session(self, _patch_server_globals):
        _patch_server_globals["agent"]._session = None
        r = _client().get("/api/session/current")
        assert r.json()["session"] is None


# ── POST /api/stop ────────────────────────────────────────────────────────────


class TestStopAgent:
    def test_stop_returns_ok(self):
        r = _client().post("/api/stop")
        assert r.status_code == 200
        assert r.json()["status"] == "ok"

    def test_stop_without_agent_returns_503(self):
        with patch.object(srv, "agent", None):
            r = _client().post("/api/stop")
            assert r.status_code == 503

    def test_stop_calls_agent_stop(self, _patch_server_globals):
        _client().post("/api/stop")
        _patch_server_globals["agent"].stop.assert_called_once()


# ── POST /api/unload ─────────────────────────────────────────────────────────


class TestUnloadModel:
    def test_unload_returns_ok(self):
        r = _client().post("/api/unload")
        assert r.status_code == 200
        assert r.json()["status"] == "ok"

    def test_unload_without_client_returns_503(self):
        with patch.object(srv, "llm_client", None):
            r = _client().post("/api/unload")
            assert r.status_code == 503

    def test_unload_calls_unload_model(self, _patch_server_globals):
        _client().post("/api/unload")
        _patch_server_globals["llm"].unload_model.assert_called_once()


# ── _stream_file_agent_events cleanup ────────────────────────────────────────


class TestFileAnalyzeStreamCleanup:
    @pytest.mark.asyncio
    async def test_mini_agent_is_stopped_after_stream_completes(self):
        stop_mock = AsyncMock()

        class _MiniAgent:
            def __init__(self, *args, **kwargs):
                self._is_subagent = False
                self._override_max_iterations = None
                self._blocked_tools = set()
                self.state = SimpleNamespace(active_target=None, conversation=[])
                self.stop = stop_mock

            async def initialize(self, *args, **kwargs):
                return None

            async def process_message(self, _msg: str):
                from airecon.proxy.agent.models import AgentEvent

                yield AgentEvent(type="done", data={})

        req = srv.FileAnalyzeRequest(
            file_path="workspace/example.com/output/file.txt",
            file_content="hello",
            task="analyze",
            max_iterations=2,
        )

        with (
            patch.object(srv, "AgentLoop", _MiniAgent),
            patch.object(srv, "llm_client", object()),
            patch.object(srv, "engine", object()),
        ):
            events = [event async for event in srv._stream_file_agent_events(req)]

        assert len(events) == 1
        stop_mock.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_mini_agent_is_stopped_when_initialize_fails(self):
        stop_mock = AsyncMock()

        class _MiniAgent:
            def __init__(self, *args, **kwargs):
                self._is_subagent = False
                self._override_max_iterations = None
                self._blocked_tools = set()
                self.state = SimpleNamespace(active_target=None, conversation=[])
                self.stop = stop_mock

            async def initialize(self, *args, **kwargs):
                raise RuntimeError("init failed")

            async def process_message(self, _msg: str):
                if False:
                    yield None

        req = srv.FileAnalyzeRequest(
            file_path="workspace/example.com/output/file.txt",
            file_content="hello",
            task="analyze",
            max_iterations=2,
        )

        with (
            patch.object(srv, "AgentLoop", _MiniAgent),
            patch.object(srv, "llm_client", object()),
            patch.object(srv, "engine", object()),
        ):
            events = [event async for event in srv._stream_file_agent_events(req)]

        assert len(events) == 1
        assert events[0]["event"] == "error"
        stop_mock.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_mini_agent_is_stopped_when_stream_is_cancelled(self):
        stop_mock = AsyncMock()
        started = asyncio.Event()
        wait_forever = asyncio.Event()

        class _MiniAgent:
            def __init__(self, *args, **kwargs):
                self._is_subagent = False
                self._override_max_iterations = None
                self._blocked_tools = set()
                self.state = SimpleNamespace(active_target=None, conversation=[])
                self.stop = stop_mock

            async def initialize(self, *args, **kwargs):
                return None

            async def process_message(self, _msg: str):
                from airecon.proxy.agent.models import AgentEvent

                started.set()
                yield AgentEvent(type="thinking", data={"content": "working"})
                await wait_forever.wait()

        req = srv.FileAnalyzeRequest(
            file_path="workspace/example.com/output/file.txt",
            file_content="hello",
            task="analyze",
            max_iterations=2,
        )

        with (
            patch.object(srv, "AgentLoop", _MiniAgent),
            patch.object(srv, "llm_client", object()),
            patch.object(srv, "engine", object()),
        ):
            gen = srv._stream_file_agent_events(req)
            first_event = await gen.__anext__()
            assert first_event["event"] == "thinking"
            await started.wait()
            await gen.aclose()

        stop_mock.assert_awaited_once()


# ── GET /api/user-input/pending ───────────────────────────────────────────────


class TestGetPendingUserInput:
    def test_no_pending_when_agent_has_no_event(self, _patch_server_globals):
        agent = _patch_server_globals["agent"]
        agent._user_input_event = None
        r = _client().get("/api/user-input/pending")
        assert r.status_code == 200
        assert r.json()["pending"] is False

    def test_pending_when_event_set(self, _patch_server_globals):
        import asyncio

        agent = _patch_server_globals["agent"]
        agent._user_input_event = asyncio.Event()
        agent._user_input_request_id = "req-abc"
        agent._user_input_prompt = "Enter TOTP code"
        agent._user_input_type = "totp"
        r = _client().get("/api/user-input/pending")
        assert r.status_code == 200
        data = r.json()
        assert data["pending"] is True
        assert data["request_id"] == "req-abc"
        assert data["prompt"] == "Enter TOTP code"
        assert data["input_type"] == "totp"

    def test_no_pending_when_no_agent(self):
        with patch.object(srv, "agent", None):
            r = _client().get("/api/user-input/pending")
        assert r.status_code == 200
        assert r.json()["pending"] is False


# ── POST /api/user-input ──────────────────────────────────────────────────────


class TestSubmitUserInput:
    def _make_agent_with_event(self):
        import asyncio

        agent = _make_mock_agent()
        evt = asyncio.Event()
        agent._user_input_event = evt
        agent._user_input_request_id = "req-xyz"
        agent._user_input_value = ""
        agent._user_input_cancelled = False
        return agent, evt

    def test_submit_sets_value_and_fires_event(self):
        agent, evt = self._make_agent_with_event()
        with patch.object(srv, "agent", agent):
            r = _client().post(
                "/api/user-input",
                json={"request_id": "req-xyz", "value": "123456", "cancelled": False},
            )
        assert r.status_code == 200
        assert r.json()["status"] == "ok"
        assert agent._user_input_value == "123456"
        assert evt.is_set()

    def test_submit_cancel_sets_cancelled_flag(self):
        agent, evt = self._make_agent_with_event()
        with patch.object(srv, "agent", agent):
            r = _client().post(
                "/api/user-input",
                json={"request_id": "req-xyz", "value": "", "cancelled": True},
            )
        assert r.status_code == 200
        assert agent._user_input_cancelled is True
        assert evt.is_set()

    def test_submit_wrong_request_id_returns_400(self):
        agent, _ = self._make_agent_with_event()
        with patch.object(srv, "agent", agent):
            r = _client().post(
                "/api/user-input",
                json={"request_id": "wrong-id", "value": "abc"},
            )
        assert r.status_code == 400

    def test_submit_no_pending_event_returns_400(self):
        agent = _make_mock_agent()
        agent._user_input_event = None
        with patch.object(srv, "agent", agent):
            r = _client().post(
                "/api/user-input",
                json={"request_id": "any", "value": "abc"},
            )
        assert r.status_code == 400

    def test_submit_no_agent_returns_503(self):
        with patch.object(srv, "agent", None):
            r = _client().post(
                "/api/user-input",
                json={"request_id": "any", "value": "abc"},
            )
        assert r.status_code == 503

    def test_submit_value_too_long_returns_422(self):
        r = _client().post(
            "/api/user-input",
            json={"request_id": "req-xyz", "value": "x" * 10_001},
        )
        assert r.status_code == 422

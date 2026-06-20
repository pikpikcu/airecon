"""Lightweight integration smoke/contract tests for server, browser, and LLM."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

import airecon.proxy.server as srv
from airecon.proxy.browser import browser_action
from airecon.proxy.llm import LLMClient


@pytest.mark.asyncio
async def test_server_status_smoke_contract() -> None:
    mock_agent = MagicMock()
    mock_agent.get_stats.return_value = {"phase": "RECON"}
    mock_llm = MagicMock()
    mock_llm.model = "test-model"
    mock_llm.health_check = AsyncMock(return_value=True)
    mock_engine = MagicMock()
    mock_engine.is_connected = True

    with (
        patch.object(srv, "agent", mock_agent),
        patch.object(srv, "llm_client", mock_llm),
        patch.object(srv, "engine", mock_engine),
    ):
        transport = httpx.ASGITransport(app=srv.app, raise_app_exceptions=True)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://testserver"
        ) as client:
            response = await client.get("/api/status")

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "ok"
    assert payload["llm"]["connected"] is True
    assert payload["docker"]["connected"] is True
    assert payload["agent"]["phase"] == "RECON"


@pytest.mark.asyncio
async def test_server_skills_contract_uses_cache_fallback() -> None:
    fake_skills = [{"name": "[tools] Demo", "description": "demo", "category": "tools"}]
    with (
        patch.dict("os.environ", {"AIRECON_TEST_MODE": "1"}, clear=False),
        patch.object(srv, "_skills_cache", None),
        patch.object(srv, "_build_skills_cache_sync", return_value=fake_skills),
    ):
        transport = httpx.ASGITransport(app=srv.app, raise_app_exceptions=True)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://testserver"
        ) as client:
            response = await client.get("/api/skills")

    assert response.status_code == 200
    data = response.json()
    assert data["count"] == 1
    assert data["skills"][0]["category"] == "tools"


def test_browser_execute_js_parallel_smoke_contract(mocker) -> None:
    execute_js = mocker.patch(
        "airecon.proxy.browser._manager.execute_js",
        return_value={"ok": True},
    )
    result = browser_action(action="execute_js", js_code="return 1", parallel=True)
    execute_js.assert_called_once_with("return 1", None, parallel=True)
    assert result["ok"] is True


def _contract_cfg() -> SimpleNamespace:
    return SimpleNamespace(
        openai_max_tokens=4096,
        openai_temperature=0.15,
        llm_timeout=120.0,
        llm_chunk_timeout=30.0,
        llm_context_window=65536,
    )


@pytest.mark.asyncio
async def test_llm_complete_contract_accepts_openai_message_content() -> None:
    """LLMClient.complete() parses OpenAI choices[0].message.content."""
    client = LLMClient.__new__(LLMClient)
    client.model = "test-model"
    client._host = "http://127.0.0.1:20128/v1"
    client._api_key = ""
    client._backend_name = "9router/OpenAI-compatible"
    # Mock the OpenAI-shaped HTTP response.
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "choices": [{"message": {"content": "ok"}}]
    }
    mock_httpx_client = AsyncMock()
    mock_httpx_client.request = AsyncMock(return_value=mock_response)
    LLMClient._httpx_client = mock_httpx_client
    LLMClient._initialized = True
    LLMClient._global_semaphore = asyncio.Semaphore(1)
    client._request_semaphore = asyncio.Semaphore(1)

    with patch(
        "airecon.proxy.llm.get_config", return_value=_contract_cfg()
    ), patch("airecon.proxy.llm.get_memory_manager", return_value=MagicMock()):
        result = await client.complete(
            messages=[{"role": "user", "content": "ping"}], max_retries=0
        )

    assert result == "ok"
    # Clean up
    LLMClient._httpx_client = None
    LLMClient._initialized = False


@pytest.mark.asyncio
async def test_llm_complete_contract_rejects_invalid_response_format() -> None:
    """LLMClient.complete() rejects a response missing choices/message/content."""
    client = LLMClient.__new__(LLMClient)
    client.model = "test-model"
    client._host = "http://127.0.0.1:20128/v1"
    client._api_key = ""
    client._backend_name = "9router/OpenAI-compatible"
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"unexpected": "shape"}
    mock_httpx_client = AsyncMock()
    mock_httpx_client.request = AsyncMock(return_value=mock_response)
    LLMClient._httpx_client = mock_httpx_client
    LLMClient._initialized = True
    LLMClient._global_semaphore = asyncio.Semaphore(1)
    client._request_semaphore = asyncio.Semaphore(1)

    with patch(
        "airecon.proxy.llm.get_config", return_value=_contract_cfg()
    ), patch("airecon.proxy.llm.get_memory_manager", return_value=MagicMock()):
        with pytest.raises(RuntimeError, match="Invalid LLM response"):
            await client.complete(
                messages=[{"role": "user", "content": "ping"}], max_retries=0
            )

    # Clean up
    LLMClient._httpx_client = None
    LLMClient._initialized = False

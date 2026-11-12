"""Exercise the real /brain slash-command handler with a synthetic local API."""
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock
import httpx
import pytest
from airecon.tui.app import AIReconApp


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [200, 503])
async def test_brain_command_uses_local_api_and_reports_outcome(status):
    app = AIReconApp(show_startup_screen=False, auto_poll_services=False)
    await app._http.aclose()
    data = {"summary": {"total_insights": 1}, "semantic_recall": True, "embedding_model": "fixture", "retrieval_mode": "lexical", "insights": []} if status == 200 else {"error": "fixture unavailable"}
    get = AsyncMock(return_value=httpx.Response(status, json=data))
    app._http = SimpleNamespace(get=get)
    chat = MagicMock()
    app.query_one = MagicMock(return_value=chat)
    await app._handle_slash_command("/brain")
    get.assert_awaited_once_with("/api/brain", timeout=10.0)
    if status == 200:
        text = chat.add_assistant_message.call_args[0][0]
        assert "lexical" in text and "insights:" in text
        chat.add_error_message.assert_not_called()
    else:
        assert "fixture unavailable" in chat.add_error_message.call_args[0][0]

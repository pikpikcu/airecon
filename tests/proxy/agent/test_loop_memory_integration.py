from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from airecon.proxy.agent.adaptive_learning import TargetMemoryStore
from airecon.proxy.agent.loop import AgentLoop
from airecon.proxy.agent.session import SessionData


@pytest.fixture
def agent_loop():
    llm_mock = MagicMock()
    llm_mock.chat_stream = AsyncMock()

    engine_mock = MagicMock()
    engine_mock.discover_tools = AsyncMock(return_value=[])
    engine_mock.tools_to_llm_format = MagicMock(return_value=[])

    with patch("airecon.proxy.agent.loop.get_config") as mock_config:
        mock_config.return_value = SimpleNamespace(
            agent_max_tool_iterations=5,
            agent_max_browser_visits_per_domain=3,
        )
        yield AgentLoop(llm=llm_mock, engine=engine_mock)


def test_save_new_findings_to_memory_dedupes_per_session(agent_loop):
    agent_loop._session = SessionData(target="example.com", session_id="sess-1")
    agent_loop._session.vulnerabilities.append(
        {
            "type": "xss",
            "severity": "High",
            "url": "https://example.com/search",
            "parameter": "q",
            "description": "Reflected XSS in q",
            "evidence": ["payload reflected"],
            # Verified so it passes the cross-session learning gate
            # (intelligence_learn_only_verified); this test asserts dedup, not gating.
            "verified": True,
        }
    )
    agent_loop._memory_manager = MagicMock()

    first = agent_loop._save_new_findings_to_memory()
    second = agent_loop._save_new_findings_to_memory()

    assert first == 1
    assert second == 0
    assert agent_loop._memory_manager.save_finding.call_count == 1


def test_record_target_memory_persists_to_disk(agent_loop, tmp_path):
    agent_loop._session = SessionData(target="example.com", session_id="sess-1")
    agent_loop._session.technologies["nginx"] = "1.25"
    agent_loop.state.evidence_log.append(
        {"summary": "Login flow observed", "confidence": 0.9}
    )
    agent_loop._target_memory_store = TargetMemoryStore(base_dir=tmp_path)

    agent_loop._record_target_memory(
        tool_name="http_observe",
        arguments={"url": "https://example.com/login"},
        result={"endpoints": ["/login"], "params": ["redirect"]},
        success=True,
    )

    saved_path = agent_loop._target_memory_store._file_path("example.com")
    data = json.loads(saved_path.read_text(encoding="utf-8"))

    assert saved_path.exists()
    assert "nginx" in data["tech_stack"]
    assert "/login" in data["endpoints"]
    assert "redirect" in data["sensitive_params"]
    assert "https://example.com/login" in data["auth_endpoints"]

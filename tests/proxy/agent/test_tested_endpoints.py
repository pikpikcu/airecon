"""Tests for tested_endpoints tracking in session.py and loop.py."""

from __future__ import annotations

from unittest.mock import MagicMock

from airecon.proxy.agent.session import (
    SessionData,
    record_tested_endpoint,
    _MAX_TESTED_ENDPOINTS,
)
from airecon.proxy.agent.loop import AgentLoop


# ─────────────────────────────────────────────────────────────
# record_tested_endpoint
# ─────────────────────────────────────────────────────────────


class TestRecordTestedEndpoint:
    def test_adds_get_endpoint(self):
        s = SessionData()
        record_tested_endpoint(s, "https://example.com/api/users")
        assert "GET https://example.com/api/users" in s.tested_endpoints

    def test_adds_post_endpoint(self):
        s = SessionData()
        record_tested_endpoint(s, "https://example.com/login", method="POST")
        assert "POST https://example.com/login" in s.tested_endpoints

    def test_deduplicates(self):
        s = SessionData()
        record_tested_endpoint(s, "https://example.com/api")
        record_tested_endpoint(s, "https://example.com/api")
        assert len(s.tested_endpoints) == 1

    def test_different_methods_not_deduped(self):
        s = SessionData()
        record_tested_endpoint(s, "https://example.com/api", method="GET")
        record_tested_endpoint(s, "https://example.com/api", method="POST")
        assert len(s.tested_endpoints) == 2

    def test_empty_url_ignored(self):
        s = SessionData()
        record_tested_endpoint(s, "")
        record_tested_endpoint(s, "   ")
        assert len(s.tested_endpoints) == 0

    def test_none_like_url_ignored(self):
        s = SessionData()
        record_tested_endpoint(s, "")
        assert s.tested_endpoints == []

    def test_method_uppercased(self):
        s = SessionData()
        record_tested_endpoint(s, "https://example.com/x", method="post")
        assert "POST https://example.com/x" in s.tested_endpoints

    def test_url_stripped(self):
        s = SessionData()
        record_tested_endpoint(s, "  https://example.com/api  ", method="GET")
        assert "GET https://example.com/api" in s.tested_endpoints

    def test_cap_at_max(self):
        s = SessionData()
        for i in range(_MAX_TESTED_ENDPOINTS + 50):
            record_tested_endpoint(s, f"https://example.com/path/{i}")
        assert len(s.tested_endpoints) <= _MAX_TESTED_ENDPOINTS

    def test_lru_drops_oldest(self):
        s = SessionData()
        # Fill to cap
        for i in range(_MAX_TESTED_ENDPOINTS):
            record_tested_endpoint(s, f"https://example.com/old/{i}")
        # Add one more — oldest should be gone
        record_tested_endpoint(s, "https://example.com/newest")
        assert "GET https://example.com/newest" in s.tested_endpoints
        # First entry should be dropped
        assert "GET https://example.com/old/0" not in s.tested_endpoints

    def test_persisted_in_session_field(self):
        s = SessionData()
        record_tested_endpoint(s, "https://target.com/login", "POST")
        assert len(s.tested_endpoints) == 1
        assert s.tested_endpoints[0] == "POST https://target.com/login"


# ─────────────────────────────────────────────────────────────
# SessionData.tested_endpoints default
# ─────────────────────────────────────────────────────────────


class TestTestedEndpointsDefault:
    def test_default_empty(self):
        s = SessionData()
        assert s.tested_endpoints == []

    def test_independent_between_sessions(self):
        s1 = SessionData()
        s2 = SessionData()
        record_tested_endpoint(s1, "https://a.com/api")
        assert s2.tested_endpoints == []


# ─────────────────────────────────────────────────────────────
# AgentLoop._record_tested_endpoint
# ─────────────────────────────────────────────────────────────


def _make_loop_with_session() -> tuple[AgentLoop, SessionData]:
    loop = AgentLoop(llm=MagicMock(), engine=MagicMock())
    session = SessionData(target="https://target.com")
    loop._session = session
    return loop, session


class TestRecordTestedEndpointLoop:
    def test_execute_curl_records_url(self):
        loop, session = _make_loop_with_session()
        loop._record_tested_endpoint(
            "execute", {"command": "curl https://target.com/api/v1/users"}
        )
        assert any("target.com/api/v1/users" in ep for ep in session.tested_endpoints)

    def test_execute_post_detects_method(self):
        loop, session = _make_loop_with_session()
        loop._record_tested_endpoint(
            "execute", {"command": "curl -X POST https://target.com/login -d 'user=x'"}
        )
        assert any(ep.startswith("POST") for ep in session.tested_endpoints)

    def test_execute_data_flag_implies_post(self):
        loop, session = _make_loop_with_session()
        loop._record_tested_endpoint(
            "execute",
            {"command": "curl -d 'payload=test' https://target.com/submit"},
        )
        assert any(ep.startswith("POST") for ep in session.tested_endpoints)

    def test_browser_goto_records_url(self):
        loop, session = _make_loop_with_session()
        loop._record_tested_endpoint(
            "browser_action",
            {"action": "goto", "url": "https://target.com/dashboard"},
        )
        assert "GET https://target.com/dashboard" in session.tested_endpoints

    def test_browser_new_tab_records_url(self):
        loop, session = _make_loop_with_session()
        loop._record_tested_endpoint(
            "browser_action",
            {"action": "new_tab", "url": "https://target.com/admin"},
        )
        assert "GET https://target.com/admin" in session.tested_endpoints

    def test_browser_click_ignored(self):
        loop, session = _make_loop_with_session()
        loop._record_tested_endpoint(
            "browser_action", {"action": "click", "coordinate": "100,200"}
        )
        assert session.tested_endpoints == []

    def test_fuzz_tool_records_url(self):
        loop, session = _make_loop_with_session()
        loop._record_tested_endpoint(
            "quick_fuzz", {"url": "https://target.com/api/search"}
        )
        assert any("target.com/api/search" in ep for ep in session.tested_endpoints)

    def test_advanced_fuzz_records_url(self):
        loop, session = _make_loop_with_session()
        loop._record_tested_endpoint(
            "advanced_fuzz", {"url": "https://target.com/api/data"}
        )
        assert any("target.com/api/data" in ep for ep in session.tested_endpoints)

    def test_no_session_does_nothing(self):
        loop = AgentLoop(llm=MagicMock(), engine=MagicMock())
        loop._session = None
        # Should not raise
        loop._record_tested_endpoint(
            "execute", {"command": "curl https://target.com/api"}
        )

    def test_execute_no_url_does_nothing(self):
        loop, session = _make_loop_with_session()
        loop._record_tested_endpoint("execute", {"command": "ls /workspace/output/"})
        assert session.tested_endpoints == []

    def test_web_search_ignored(self):
        loop, session = _make_loop_with_session()
        loop._record_tested_endpoint("web_search", {"query": "sqlmap tutorial"})
        assert session.tested_endpoints == []

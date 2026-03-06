"""Tests for session persistence (save/load/list) and session_to_context."""

import json
import pytest
from unittest.mock import patch
from airecon.proxy.agent.session import (
    SessionData,
    save_session,
    load_session,
    list_sessions,
)


@pytest.fixture
def tmp_sessions_dir(tmp_path):
    """Patch SESSIONS_DIR to a temporary directory for each test."""
    sessions_dir = tmp_path / "sessions"
    sessions_dir.mkdir()
    with patch("airecon.proxy.agent.session.SESSIONS_DIR", sessions_dir):
        yield sessions_dir


class TestSaveAndLoadSession:
    def test_roundtrip_basic(self, tmp_sessions_dir):
        session = SessionData(
            target="example.com",
            subdomains=["api.example.com", "dev.example.com"],
            live_hosts=["http://api.example.com"],
            open_ports={"api.example.com": [80, 443]},
            technologies={"nginx": "1.18.0"},
        )
        save_session(session)

        loaded = load_session(session.session_id)
        assert loaded is not None
        assert loaded.target == "example.com"
        assert loaded.subdomains == ["api.example.com", "dev.example.com"]
        assert loaded.live_hosts == ["http://api.example.com"]
        assert loaded.open_ports["api.example.com"] == [80, 443]
        assert loaded.technologies["nginx"] == "1.18.0"

    def test_roundtrip_vulnerabilities(self, tmp_sessions_dir):
        session = SessionData(target="target.com")
        session.vulnerabilities = [
            {"finding": "SQL Injection in ?id=", "target": "target.com", "timestamp": "2026-01-01"}
        ]
        save_session(session)

        loaded = load_session(session.session_id)
        assert loaded is not None
        assert len(loaded.vulnerabilities) == 1
        assert "SQL Injection" in loaded.vulnerabilities[0]["finding"]

    def test_roundtrip_auth_fields(self, tmp_sessions_dir):
        session = SessionData(target="secure.com")
        session.auth_cookies = [{"name": "session", "value": "abc123"}]
        session.auth_tokens = {"Authorization": "Bearer xyz"}
        session.auth_type = "login_form"
        save_session(session)

        loaded = load_session(session.session_id)
        assert loaded is not None
        assert loaded.auth_type == "login_form"
        assert loaded.auth_tokens.get("Authorization") == "Bearer xyz"

    def test_load_nonexistent_returns_none(self, tmp_sessions_dir):
        result = load_session("nonexistent_session_id_xyz")
        assert result is None

    def test_load_corrupted_json_returns_none(self, tmp_sessions_dir):
        bad_file = tmp_sessions_dir / "bad_session.json"
        bad_file.write_text("{INVALID JSON HERE")
        result = load_session("bad_session")
        assert result is None

    def test_save_creates_directory_if_missing(self, tmp_path):
        nested = tmp_path / "deep" / "nested" / "sessions"
        with patch("airecon.proxy.agent.session.SESSIONS_DIR", nested):
            session = SessionData(target="test.com")
            save_session(session)
            assert nested.exists()
            assert (nested / f"{session.session_id}.json").exists()

    def test_save_file_is_valid_json(self, tmp_sessions_dir):
        session = SessionData(target="example.com")
        session.scan_count = 5
        save_session(session)

        filepath = tmp_sessions_dir / f"{session.session_id}.json"
        assert filepath.exists()
        data = json.loads(filepath.read_text())
        assert data["target"] == "example.com"
        assert data["scan_count"] == 5

    def test_session_id_auto_generated(self):
        s1 = SessionData(target="a.com")
        s2 = SessionData(target="b.com")
        assert s1.session_id != ""
        assert s2.session_id != ""
        assert s1.session_id != s2.session_id

    def test_session_created_at_auto_set(self):
        session = SessionData(target="test.com")
        assert session.created_at != ""


class TestListSessions:
    def test_list_empty_dir(self, tmp_sessions_dir):
        sessions = list_sessions()
        assert sessions == []

    def test_list_returns_summaries(self, tmp_sessions_dir):
        s1 = SessionData(target="alpha.com")
        s1.subdomains = ["sub1.alpha.com", "sub2.alpha.com"]
        s1.vulnerabilities = [{"finding": "XSS", "target": "alpha.com"}]
        s2 = SessionData(target="beta.com")
        save_session(s1)
        save_session(s2)

        sessions = list_sessions()
        assert len(sessions) == 2
        targets = {s["target"] for s in sessions}
        assert "alpha.com" in targets
        assert "beta.com" in targets

        alpha = next(s for s in sessions if s["target"] == "alpha.com")
        assert alpha["subdomains"] == 2
        assert alpha["vulnerabilities"] == 1

    def test_list_missing_dir_returns_empty(self, tmp_path):
        nonexistent = tmp_path / "no_sessions"
        with patch("airecon.proxy.agent.session.SESSIONS_DIR", nonexistent):
            assert list_sessions() == []

    def test_list_skips_corrupted_files(self, tmp_sessions_dir):
        (tmp_sessions_dir / "corrupt.json").write_text("NOT JSON")
        s = SessionData(target="good.com")
        save_session(s)

        sessions = list_sessions()
        # Only the valid session should appear
        assert len(sessions) == 1
        assert sessions[0]["target"] == "good.com"

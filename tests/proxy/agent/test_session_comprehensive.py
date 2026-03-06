"""Tests for airecon.proxy.agent.session module.

P2 Priority: Tests for SessionData serialization, save/load, session_to_context accuracy.
"""

import pytest
import json
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock
from datetime import datetime

from airecon.proxy.agent.session import (
    SessionData,
    generate_session_id,
    save_session,
    load_session,
    list_sessions,
    _calculate_similarity,
    _is_duplicate_vulnerability,
    update_from_parsed_output,
    SESSIONS_DIR,
)
from airecon.proxy.agent.output_parser import ParsedOutput


class TestGenerateSessionId:
    """Test session ID generation."""

    def test_generate_unique_session_ids(self):
        """Test that each call generates a unique ID."""
        id1 = generate_session_id()
        id2 = generate_session_id()
        assert id1 != id2

    def test_session_id_format(self):
        """Test that session ID follows format: timestamp_hex."""
        session_id = generate_session_id()
        parts = session_id.split("_")
        assert len(parts) == 2
        # First part should be integer timestamp
        timestamp = int(parts[0])
        assert timestamp > 0
        # Second part should be 8-character hex
        hex_part = parts[1]
        assert len(hex_part) == 8
        int(hex_part, 16)  # Should be valid hex


class TestSessionDataBasics:
    """Test SessionData initialization and basic properties."""

    def test_session_creation_default(self):
        """Test creating a session with default values."""
        session = SessionData(target="example.com")
        assert session.target == "example.com"
        assert session.session_id  # Should be auto-generated
        assert session.created_at  # Should be auto-set
        assert session.current_phase == "RECON"
        assert session.subdomains == []
        assert session.vulnerabilities == []

    def test_session_creation_with_id(self):
        """Test creating session with provided ID."""
        session_id = "1234567890_abcdef12"
        session = SessionData(session_id=session_id, target="example.com")
        assert session.session_id == session_id

    def test_session_default_fields(self):
        """Test all default fields are empty."""
        session = SessionData(target="example.com")
        assert session.subdomains == []
        assert session.live_hosts == []
        assert session.open_ports == {}
        assert session.urls == []
        assert session.technologies == {}
        assert session.vulnerabilities == []
        assert session.attack_chains == []
        assert session.completed_phases == []
        assert session.tools_run == []
        assert session.scan_count == 0
        assert session.auth_cookies == []
        assert session.auth_tokens == {}

    def test_session_mutable_defaults_not_shared(self):
        """Test that mutable defaults are not shared between instances."""
        s1 = SessionData(target="target1.com")
        s2 = SessionData(target="target2.com")
        
        s1.subdomains.append("sub1.target1.com")
        assert "sub1.target1.com" not in s2.subdomains


class TestSessionSerialization:
    """Test serialization and deserialization."""

    def test_session_to_dict(self):
        """Test converting session to dictionary."""
        from dataclasses import asdict
        session = SessionData(
            session_id="test_123_abc",
            target="example.com",
            subdomains=["api.example.com"],
            vulnerabilities=[{"finding": "XSS", "target": "api.example.com"}]
        )
        session_dict = asdict(session)
        assert session_dict["session_id"] == "test_123_abc"
        assert session_dict["target"] == "example.com"
        assert len(session_dict["subdomains"]) == 1

    def test_session_from_dict(self):
        """Test reconstructing session from dictionary."""
        data = {
            "session_id": "test_123_abc",
            "target": "example.com",
            "subdomains": ["api.example.com"],
            "vulnerabilities": [{"finding": "XSS"}],
            "created_at": datetime.now().isoformat(),
            "updated_at": None,
        }
        session = SessionData(
            session_id=data["session_id"],
            target=data["target"],
            subdomains=data["subdomains"],
            vulnerabilities=data["vulnerabilities"]
        )
        assert session.target == "example.com"

    def test_session_json_serializable(self):
        """Test that session can be JSON serialized."""
        from dataclasses import asdict
        session = SessionData(
            target="example.com",
            subdomains=["sub1.example.com"],
            technologies={"nginx": "1.18.0"}
        )
        session_dict = asdict(session)
        json_str = json.dumps(session_dict, default=str)
        assert "example.com" in json_str
        assert "nginx" in json_str


class TestCalculateSimilarity:
    """Test vulnerability similarity calculation."""

    def test_similarity_identical_strings(self):
        """Test that identical strings have similarity 1.0."""
        sim = _calculate_similarity("XSS in search", "XSS in search")
        assert sim == 1.0

    def test_similarity_different_case(self):
        """Test case-insensitive comparison."""
        sim = _calculate_similarity("XSS in search", "xss in search")
        assert sim == 1.0

    def test_similarity_different_strings(self):
        """Test completely different strings."""
        sim = _calculate_similarity("XSS vulnerability", "SQL injection flaw")
        assert sim < 0.5

    def test_similarity_with_parameters(self):
        """Test that different parameters are not considered similar."""
        sim = _calculate_similarity(
            "XSS in parameter id=123",
            "XSS in parameter name=456"
        )
        # Should be low because parameters differ
        assert sim < 0.5

    def test_similarity_same_parameter(self):
        """Test that same parameter location is more similar."""
        sim1 = _calculate_similarity(
            "XSS in parameter id",
            "XSS in parameter id"
        )
        assert sim1 == 1.0


class TestDuplicateVulnerabilityDetection:
    """Test vulnerability deduplication logic."""

    def test_duplicate_exact_match(self):
        """Test exact match detection."""
        new_vuln = {"finding": "XSS in search", "target": "api.example.com"}
        existing = [
            {"finding": "XSS in search", "target": "api.example.com"}
        ]
        assert _is_duplicate_vulnerability(new_vuln, existing) is True

    def test_same_finding_different_subdomain_is_duplicate(self):
        """Same finding on different subdomains IS a duplicate (dedup by description).

        combined_sim = 1.0 * 0.8 + 0.0 * 0.2 = 0.8 >= 0.7 threshold.
        """
        new_vuln = {"finding": "XSS in search", "target": "api.example.com"}
        existing = [
            {"finding": "XSS in search", "target": "admin.example.com"}
        ]
        assert _is_duplicate_vulnerability(new_vuln, existing) is True

    def test_not_duplicate_different_parameter(self):
        """Test that different parameters are not duplicates."""
        new_vuln = {"finding": "XSS in parameter id", "target": "api.example.com"}
        existing = [
            {"finding": "XSS in parameter name", "target": "api.example.com"}
        ]
        assert _is_duplicate_vulnerability(new_vuln, existing) is False

    def test_duplicate_with_no_target(self):
        """Test deduplication when target is not specified."""
        new_vuln = {"finding": "XSS in application", "target": ""}
        existing = [
            {"finding": "XSS in application", "target": ""}
        ]
        assert _is_duplicate_vulnerability(new_vuln, existing) is True


class TestUpdateFromParsedOutput:
    """Test updating session from parsed tool output."""

    def test_update_from_nmap_output(self):
        """Test updating session from nmap parsed output."""
        session = SessionData(target="example.com")
        parsed = ParsedOutput(
            tool="nmap",
            summary="Nmap: 2 open ports",
            items=["80/tcp open http", "443/tcp open https"],
            total_count=2
        )
        
        update_from_parsed_output(session, parsed, "nmap -sV example.com")
        
        assert session.scan_count == 1
        assert "nmap" in session.tools_run

    def test_update_from_subfinder_output(self):
        """Test updating session from subfinder parsed output."""
        session = SessionData(target="example.com")
        parsed = ParsedOutput(
            tool="subfinder",
            summary="Found 3 subdomains",
            items=["api.example.com", "admin.example.com", "app.example.com"],
            total_count=3
        )
        
        update_from_parsed_output(session, parsed)
        
        assert len(session.subdomains) == 3
        assert "api.example.com" in session.subdomains

    def test_update_increments_scan_count(self):
        """Test that scan_count is incremented."""
        session = SessionData(target="example.com")
        assert session.scan_count == 0
        
        parsed = ParsedOutput(tool="nmap", summary="Test", items=[], total_count=0)
        update_from_parsed_output(session, parsed)
        assert session.scan_count == 1
        
        update_from_parsed_output(session, parsed)
        assert session.scan_count == 2

    def test_update_tracks_tools(self):
        """Test that tools_run is updated."""
        session = SessionData(target="example.com")
        
        parsed = ParsedOutput(tool="nmap", summary="Test", items=[], total_count=0)
        update_from_parsed_output(session, parsed, "nmap example.com")
        assert "nmap" in session.tools_run

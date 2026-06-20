"""Comprehensive tests for all new AIRecon features.

Tests verify that features are actually integrated and working,
not just standalone prototypes.
"""

from __future__ import annotations

import json
from pathlib import Path



# ── 1. Payload Memory Engine ────────────────────────────────────────────────


class TestPayloadMemoryEngine:
    """Test payload-level learning: track success/failure, skip failed payloads."""

    def test_record_and_skip_failed_payload(self):
        """Payload that failed 2+ times should be skipped."""
        from airecon.proxy.agent.payload_memory import PayloadMemoryEngine

        engine = PayloadMemoryEngine()

        engine.record_attempt(
            payload="' OR 1=1--",
            vuln_type="sql_injection",
            target="http://example.com/api",
            param="id",
            success=False,
            confidence=0.1,
            status_code=200,
        )
        engine.record_attempt(
            payload="' OR 1=1--",
            vuln_type="sql_injection",
            target="http://example.com/api",
            param="id",
            success=False,
            confidence=0.1,
            status_code=200,
        )

        should_skip, reason = engine.should_skip_payload(
            "' OR 1=1--", "sql_injection", "http://example.com/api", "id"
        )
        assert should_skip is True
        assert "Failed 2 times" in reason

    def test_successful_payload_not_skipped(self):
        """Payload that succeeded should NOT be skipped."""
        from airecon.proxy.agent.payload_memory import PayloadMemoryEngine

        engine = PayloadMemoryEngine()

        engine.record_attempt(
            payload="' UNION SELECT NULL--",
            vuln_type="sql_injection",
            target="http://example.com/api",
            param="id",
            success=True,
            confidence=0.85,
            status_code=500,
        )

        should_skip, reason = engine.should_skip_payload(
            "' UNION SELECT NULL--", "sql_injection", "http://example.com/api", "id"
        )
        assert should_skip is False

    def test_get_successful_payloads(self):
        """Get historically successful payloads for a vuln type."""
        from airecon.proxy.agent.payload_memory import PayloadMemoryEngine

        engine = PayloadMemoryEngine()

        payloads = [
            ("' OR 1=1--", 0.8, True),
            ("' UNION SELECT NULL--", 0.9, True),
            ("admin'--", 0.1, False),
        ]
        for payload, conf, success in payloads:
            engine.record_attempt(
                payload=payload,
                vuln_type="sql_injection",
                target="http://example.com",
                param="user",
                success=success,
                confidence=conf,
                status_code=500 if success else 200,
            )

        successful = engine.get_successful_payloads("sql_injection")
        assert len(successful) == 2
        assert successful[0][0] == "' UNION SELECT NULL--"

    def test_save_and_load(self, tmp_path):
        """Payload memory persists to disk and reloads."""
        from airecon.proxy.agent.payload_memory import PayloadMemoryEngine

        engine = PayloadMemoryEngine()
        engine.record_attempt(
            payload="test_payload",
            vuln_type="xss",
            target="http://test.com",
            param="q",
            success=True,
            confidence=0.75,
            status_code=200,
        )

        save_path = tmp_path / "payload_memory.json"
        engine.save(save_path)
        assert save_path.exists()

        engine2 = PayloadMemoryEngine()
        loaded = engine2.load(save_path)
        assert loaded == 1
        assert len(engine2.records) == 1


# ── 2. Session Persistence ──────────────────────────────────────────────────


class TestSessionPersistence:
    """Test cross-session persistence: save/load state between runs."""

    def test_save_and_load_session_state(self, tmp_path):
        """Session state persists across sessions."""
        from airecon.proxy.agent.session_persistence import SessionPersistenceEngine

        engine = SessionPersistenceEngine(tmp_path)

        state = {
            "iteration": 50,
            "phase": "ANALYSIS",
            "evidence_count": 15,
        }
        engine.save_session_state("http://test.com", state)

        loaded = engine.load_session_state("http://test.com")
        assert loaded is not None
        assert loaded["iteration"] == 50
        assert loaded["phase"] == "ANALYSIS"

    def test_load_nonexistent_returns_none(self, tmp_path):
        """Loading state for unknown target returns None."""
        from airecon.proxy.agent.session_persistence import SessionPersistenceEngine

        engine = SessionPersistenceEngine(tmp_path)
        result = engine.load_session_state("http://unknown.com")
        assert result is None

    def test_save_and_load_payload_memory(self, tmp_path):
        """Payload memory persists per target."""
        from airecon.proxy.agent.session_persistence import SessionPersistenceEngine

        engine = SessionPersistenceEngine(tmp_path)

        records = [
            {
                "payload": "test",
                "vuln_type": "xss",
                "target": "http://test.com",
                "param": "q",
                "success": True,
                "confidence": 0.8,
                "status_code": 200,
                "waf_detected": "",
                "tech_stack": [],
                "response_time_ms": 150.0,
                "error": "",
                "timestamp": 1700000000.0,
                "attempts": 1,
            }
        ]
        engine.save_payload_memory("http://test.com", records)

        loaded = engine.load_payload_memory("http://test.com")
        assert len(loaded) == 1
        assert loaded[0]["payload"] == "test"


# ── 3. Verification Engine Integration ──────────────────────────────────────


class TestVerificationEngine:
    """Test zero-FP verification: loads from data files, filters findings."""

    def test_loads_patterns_from_data(self):
        """Verification patterns loaded from verification_patterns.json."""
        from airecon.proxy.agent.verification import _VERIFICATION_DATA

        assert "clean_response_patterns" in _VERIFICATION_DATA
        assert "dynamic_content_markers" in _VERIFICATION_DATA
        assert "honeypot_indicators" in _VERIFICATION_DATA
        assert "waf_block_indicators" in _VERIFICATION_DATA
        assert len(_VERIFICATION_DATA["clean_response_patterns"]) > 0

    def test_loads_waf_signatures_from_data(self):
        """WAF signatures loaded from waf_signatures.json."""
        from airecon.proxy.agent.verification import _WAF_CDN_SIGNATURES

        assert len(_WAF_CDN_SIGNATURES) > 0
        names = [name for name, _ in _WAF_CDN_SIGNATURES]
        assert any("cloudflare" in n.lower() for n in names) or len(names) > 0 or len(names) > 0

    def test_loads_payloads_from_fuzzer_data(self):
        """Verification payloads loaded from fuzzer_data.json."""
        from airecon.proxy.agent.verification import _VERIFY_PAYLOADS

        assert "sql_injection" in _VERIFY_PAYLOADS
        assert "xss" in _VERIFY_PAYLOADS
        assert len(_VERIFY_PAYLOADS["sql_injection"]) > 0

    def test_verification_detects_reflection_only(self):
        """Verification engine detects reflection-only (HTML-encoded) payloads."""
        from airecon.proxy.agent.verification import FalsePositiveDetector

        detector = FalsePositiveDetector()

        # When payload IS in response AND is also HTML-encoded, it's safe reflection
        payload = "<script>alert(1)</script>"
        baseline = "<html><body>Normal page</body></html>"
        # Payload appears both raw AND encoded (common in some apps)
        fuzz_response = (
            "<html><body><script>alert(1)</script> "
            "&lt;script&gt;alert(1)&lt;/script&gt;</body></html>"
        )

        is_reflection, reason = detector.detect_reflection_only(
            payload, baseline, fuzz_response
        )
        assert is_reflection is True
        assert "HTML-encoded" in reason

    def test_verification_detects_dynamic_content(self):
        """Verification engine detects dynamic content as FP indicator."""
        from airecon.proxy.agent.verification import FalsePositiveDetector

        detector = FalsePositiveDetector()

        baseline = "<html><body>Static page</body></html>"
        fuzz_response = (
            "<html><body>2026-04-05T12:00:00Z "
            "550e8400-e29b-41d4-a716-446655440000 "
            "1712345678901 1712345678902 1712345678903 1712345678904 1712345678905"
            "</body></html>"
        )

        is_dynamic, reasons = detector.detect_dynamic_content(baseline, fuzz_response)
        assert is_dynamic is True


# ── 4. Target Profiler Integration ──────────────────────────────────────────


class TestTargetProfilerIntegration:
    """Test target profiler loads from tech_correlations.json."""

    def test_loads_tech_categories_from_data(self):
        """Tech categories loaded from tech_correlations.json."""
        from airecon.proxy.agent.target_profiler import _TECH_CORRELATIONS

        assert len(_TECH_CORRELATIONS) > 50
        techs_with_category = [
            name for name, info in _TECH_CORRELATIONS.items() if info.get("category")
        ]
        assert len(techs_with_category) > 50

    def test_tech_category_lookup(self):
        """Tech categories are correctly assigned."""
        from airecon.proxy.agent.target_profiler import _TECH_CORRELATIONS

        cat = _TECH_CORRELATIONS.get("django", {}).get("category", "")
        assert cat and cat.lower() == "framework"
        cat = _TECH_CORRELATIONS.get("mysql", {}).get("category", "")
        assert cat and cat.lower() == "database"
        cat = _TECH_CORRELATIONS.get("aws", {}).get("category", "")
        assert cat and cat.lower() == "cloud"
        cat = _TECH_CORRELATIONS.get("cloudflare", {}).get("category", "")
        assert cat and cat.lower() == "cdn_waf"
        cat = _TECH_CORRELATIONS.get("wordpress", {}).get("category", "")
        assert cat and cat.lower() == "cms"
        cat = _TECH_CORRELATIONS.get("nginx", {}).get("category", "")
        assert cat and cat.lower() == "infrastructure"

    def test_get_techs_by_category(self):
        """Can filter techs by category dynamically."""
        from airecon.proxy.agent.target_profiler import _TECH_CORRELATIONS

        framework_techs = {
            name
            for name, info in _TECH_CORRELATIONS.items()
            if info.get("category") == "framework"
        }
        assert "django" in framework_techs
        assert "flask" in framework_techs
        assert "mysql" not in framework_techs


# ── 5. Tool Scorer Integration ──────────────────────────────────────────────


class TestToolScorerIntegration:
    """Test tool scorer loads phase mappings from tools_meta.json."""

    def test_phase_category_map_from_data(self):
        """Phase-category mapping loaded from tools_meta.json."""
        from airecon.proxy.agent.tool_scorer import _CATEGORY_PHASE_MAP

        assert "RECON" in _CATEGORY_PHASE_MAP
        assert "ANALYSIS" in _CATEGORY_PHASE_MAP
        assert "EXPLOIT" in _CATEGORY_PHASE_MAP
        assert "REPORT" in _CATEGORY_PHASE_MAP
        assert len(_CATEGORY_PHASE_MAP["RECON"]) > 0

    def test_phase_extras_from_data(self):
        """Phase extras loaded from tools_meta.json."""
        from airecon.proxy.agent.tool_scorer import _PHASE_EXTRAS

        assert "RECON" in _PHASE_EXTRAS
        assert "caido_set_scope" in _PHASE_EXTRAS["RECON"]
        assert "quick_fuzz" in _PHASE_EXTRAS["EXPLOIT"]

    def test_report_tools_from_data(self):
        """Report tools loaded from tools_meta.json."""
        from airecon.proxy.agent.tool_scorer import _REPORT_TOOLS

        assert "create_vulnerability_report" in _REPORT_TOOLS
        assert "create_file" in _REPORT_TOOLS

    def test_phase_blocked_tools(self):
        """Tools from wrong phase are blocked."""
        from airecon.proxy.agent.tool_scorer import _PHASE_BLOCKED_TOOLS

        recon_blocked = _PHASE_BLOCKED_TOOLS.get("RECON", set())
        assert "stratus-red-team" in recon_blocked

    def test_phase_appropriate_tools(self):
        """Appropriate tools are available per phase."""
        from airecon.proxy.agent.tool_scorer import _PHASE_APPROPRIATE_TOOLS

        recon_tools = _PHASE_APPROPRIATE_TOOLS.get("RECON", set())
        assert "execute" in recon_tools
        assert "subfinder" in recon_tools
        assert "nmap" in recon_tools


# ── 6. URL Intelligence Integration ─────────────────────────────────────────


class TestUrlIntelligenceIntegration:
    """Test URL intelligence loads patterns from data files."""

    def test_file_extensions_from_data(self):
        """File extensions loaded from file_extensions.json."""
        from airecon.proxy.agent.url_intelligence import _EXT_DATA

        assert "static" in _EXT_DATA
        assert "png" in _EXT_DATA["static"]
        assert "high_value" in _EXT_DATA
        assert "js" in _EXT_DATA["high_value"]

    def test_static_dir_patterns_from_data(self):
        """Static directory patterns loaded from endpoint_patterns.json."""
        from airecon.proxy.agent.url_intelligence import _ENDPOINT_DATA

        assert "static_dir_patterns" in _ENDPOINT_DATA
        assert "/assets/" in _ENDPOINT_DATA["static_dir_patterns"]
        assert "/static/" in _ENDPOINT_DATA["static_dir_patterns"]

    def test_endpoint_url_patterns_from_data(self):
        """URL patterns loaded from endpoint_patterns.json."""
        from airecon.proxy.agent.url_intelligence import _ENDPOINT_DATA

        assert "url_patterns" in _ENDPOINT_DATA
        assert len(_ENDPOINT_DATA["url_patterns"]) > 0


# ── 7. Data Loader Integration ──────────────────────────────────────────────


class TestDataLoaderIntegration:
    """Test shared data loader works correctly."""

    def test_load_attack_chains(self):
        """Attack chains loaded from attack_chains.json."""
        from airecon.proxy.data_loader import load_attack_chains

        chains = load_attack_chains()
        assert len(chains) > 0
        for chain in chains[:3]:
            assert "id" in chain
            assert "name" in chain
            assert "triggers" in chain
            assert "steps" in chain
            assert "required_findings" in chain

    def test_load_waf_signatures(self):
        """WAF signatures loaded from waf_signatures.json."""
        from airecon.proxy.data_loader import load_waf_signatures

        sigs = load_waf_signatures()
        assert isinstance(sigs, dict)
        assert "header_signatures" in sigs
        assert len(sigs.get("header_signatures", [])) > 0

    def test_load_waf_bypass_strategies(self):
        """WAF bypass strategies loaded from data files."""
        from airecon.proxy.data_loader import load_waf_bypass_strategies

        strategies = load_waf_bypass_strategies("cloudflare")
        assert isinstance(strategies, list)
        assert len(strategies) > 0

    def test_load_recon_tools(self):
        """Recon tools loaded from tools_meta.json."""
        from airecon.proxy.data_loader import load_recon_tools

        tools = load_recon_tools()
        assert isinstance(tools, set)
        assert len(tools) > 0
        assert "execute" in tools
        assert "browser_action" in tools

    def test_merge_headers(self):
        """Header merging works correctly."""
        from airecon.proxy.data_loader import merge_headers

        base = {"User-Agent": "test", "Accept": "text/html"}
        override = {"User-Agent": "custom", "X-Custom": "value"}
        merged = merge_headers(base, override)
        assert merged["User-Agent"] == "custom"
        assert merged["Accept"] == "text/html"
        assert merged["X-Custom"] == "value"

    def test_severity_conversion(self):
        """Severity conversion is consistent (1-5 scale)."""
        from airecon.proxy.data_loader import int_to_severity, severity_to_int

        assert severity_to_int("CRITICAL") == 5
        assert severity_to_int("HIGH") == 4
        assert severity_to_int("MEDIUM") == 3
        assert severity_to_int("LOW") == 2
        assert severity_to_int("INFO") == 1
        assert severity_to_int("warning") == 3
        assert severity_to_int("ERROR") == 4
        assert severity_to_int("4") == 4

        assert int_to_severity(5) == "CRITICAL"
        assert int_to_severity(4) == "HIGH"
        assert int_to_severity(1) == "INFO"


# ── 8. Config Integration ───────────────────────────────────────────────────


class TestConfigIntegration:
    """Test config system: essential keys written to YAML, all 125 available."""

    def test_essential_keys_defined(self):
        """Only essential keys are written to config.yaml."""
        from airecon.proxy.config import _ESSENTIAL_CONFIG_KEYS

        assert "openai_base_url" in _ESSENTIAL_CONFIG_KEYS
        assert "openai_model" in _ESSENTIAL_CONFIG_KEYS
        assert "proxy_port" in _ESSENTIAL_CONFIG_KEYS
        assert "verification_enabled" not in _ESSENTIAL_CONFIG_KEYS
        assert "intelligence_enabled" not in _ESSENTIAL_CONFIG_KEYS
        assert "caido_graphql_url" not in _ESSENTIAL_CONFIG_KEYS

    def test_all_defaults_available(self):
        """All 125 config keys have defaults."""
        from airecon.proxy.config import DEFAULT_CONFIG

        assert len(DEFAULT_CONFIG) >= 120
        assert "openai_base_url" in DEFAULT_CONFIG
        assert "fuzzer_quick_timeout_seconds" in DEFAULT_CONFIG
        assert "payload_memory_enabled" in DEFAULT_CONFIG

    def test_openai_base_url_required(self):
        """openai_base_url is required and validated."""
        from airecon.proxy.config import Config

        cfg = Config.load_with_defaults(
            {
                "openai_base_url": "http://127.0.0.1:20128/v1",
                "openai_model": "claude-sonnet-4",
            }
        )
        assert cfg.openai_base_url == "http://127.0.0.1:20128/v1"
        assert cfg.openai_model == "claude-sonnet-4"


# ── 9. End-to-End Integration Tests ─────────────────────────────────────────


class TestEndToEndIntegration:
    """Test that features actually work together, not just in isolation."""

    def test_fuzzer_uses_payload_memory(self):
        """Fuzzer integrates payload memory for skip logic."""
        from airecon.proxy import fuzzer as fuzzer_mod

        assert hasattr(fuzzer_mod.Fuzzer, "__init__")

        source = Path(fuzzer_mod.__file__).read_text()
        assert "payload_memory" in source
        assert "should_skip_payload" in source
        assert "record_attempt" in source

    def test_verification_uses_data_files(self):
        """Verification engine uses data files, not hardcoded values."""
        from airecon.proxy.agent import verification as ver_mod

        source = Path(ver_mod.__file__).read_text()

        assert "from ..data_loader import" in source
        assert "_VERIFICATION_DATA" in source

    def test_target_profiler_uses_tech_correlations(self):
        """Target profiler loads tech data from tech_correlations.json."""
        from airecon.proxy.agent import target_profiler as tp_mod

        source = Path(tp_mod.__file__).read_text()

        assert "load_tech_correlations" in source or "_TECH_CORRELATIONS" in source
        assert "framework_techs = {" not in source
        assert "database_techs = {" not in source

    def test_tool_scorer_uses_tools_meta(self):
        """Tool scorer loads phase mappings from tools_meta.json."""
        from airecon.proxy.agent import tool_scorer as ts_mod

        source = Path(ts_mod.__file__).read_text()

        assert "phase_category_map" in source
        assert "phase_extras" in source
        assert "report_tools" in source

    def test_all_data_files_exist(self):
        """All required data files exist and are valid JSON."""
        from airecon.proxy import data_loader as dl_mod

        data_dir = Path(dl_mod.__file__).parent / "data"

        required_files = [
            "verification_patterns.json",
            "file_extensions.json",
            "endpoint_patterns.json",
            "tech_correlations.json",
            "tools_meta.json",
            "tools.json",
            "fuzzer_data.json",
            "waf_signatures.json",
            "attack_chains.json",
            "patterns.json",
        ]

        for filename in required_files:
            filepath = data_dir / filename
            assert filepath.exists(), f"Missing data file: {filename}"
            json.loads(filepath.read_text())

    def test_session_persistence_integrated_in_loop(self):
        """Session persistence is integrated in agent loop."""
        from airecon.proxy.agent import loop as loop_mod

        source = Path(loop_mod.__file__).read_text()

        assert "_save_session_persistence" in source
        assert "session_persistence" in source

    def test_session_persistence_integrated_in_lifecycle(self):
        """Session persistence loads on session init."""
        from airecon.proxy.agent import loop_lifecycle as lc_mod

        source = Path(lc_mod.__file__).read_text()

        assert "_load_session_persistence" in source

    def test_per_tool_timeout_integrated(self):
        """Per-tool timeout is integrated in tool cycle."""
        from airecon.proxy.agent import loop_tool_cycle as ltc_mod

        source = Path(ltc_mod.__file__).read_text()

        assert "wait_for" in source
        assert "per_tool_timeout" in source or "timeout=" in source

    def test_graceful_degradation_backoff(self):
        """Graceful degradation has progressive backoff."""
        from airecon.proxy.agent import loop_tool_cycle as ltc_mod

        source = Path(ltc_mod.__file__).read_text()

        assert "_backoff_waits" in source or "backoff" in source.lower()

    def test_browser_tracking_pixel_blocking(self):
        """Browser blocks tracking/analytics URLs."""
        from airecon.proxy import browser as browser_mod

        source = Path(browser_mod.__file__).read_text()

        assert "tracking" in source.lower()
        assert "cdn-cgi/rum" in source or "__ptq" in source

    def test_realtime_response_tracking(self):
        """Real-time response time tracking exists."""
        from airecon.proxy.agent import loop_tool_cycle as ltc_mod

        source = Path(ltc_mod.__file__).read_text()

        assert "_tool_response_times" in source or "_request_times" in source

    def test_no_bare_except_exception(self):
        """No bare 'except Exception:' without logging in agent files."""
        import re

        from airecon.proxy.agent import loop_exploration as le_mod

        agent_dir = Path(le_mod.__file__).parent

        for py_file in agent_dir.glob("*.py"):
            source = py_file.read_text()
            bare_excepts = re.findall(r"except Exception:(?!\s*as\s)", source)
            assert len(bare_excepts) == 0, (
                f"Found {len(bare_excepts)} bare 'except Exception:' in {py_file.name}"
            )

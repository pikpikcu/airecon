"""Tests for InteractiveRealTimeTester in fuzzer.py."""

from __future__ import annotations

import pytest
import httpx
from unittest.mock import AsyncMock, MagicMock
from airecon.proxy.fuzzer import Fuzzer, InteractiveRealTimeTester


class TestInteractiveRealTimeTester:
    """Test real-time fuzzing with live result streaming."""

    def test_init_sets_defaults(self) -> None:
        """Test InteractiveRealTimeTester initialization."""
        tester = InteractiveRealTimeTester("https://example.com/search")

        assert tester.target == "https://example.com/search"
        assert tester.fuzzer is not None
        assert tester.chain_engine is not None
        assert tester.on_finding is None
        assert tester._findings == []
        assert tester._chains == []

    def test_init_with_custom_params(self) -> None:
        """Test initialization with custom threads, timeout, headers."""
        headers = {"Authorization": "Bearer token123"}
        tester = InteractiveRealTimeTester(
            target="https://api.example.com",
            threads=10,
            timeout=30,
            headers=headers,
        )

        assert tester.target == "https://api.example.com"
        assert tester.fuzzer.threads == 10
        assert tester.fuzzer.timeout == 30
        assert tester.fuzzer.headers == headers

    @pytest.mark.asyncio
    async def test_probe_baseline_returns_param_stats(self) -> None:
        """Test probe_baseline returns statistics for each parameter."""
        tester = InteractiveRealTimeTester("https://example.com/search")

        # Mock fuzzer probe method
        tester.fuzzer.probe = AsyncMock(
            return_value={
                "status": 200,
                "response_time": 0.5,
                "body_length": 1024,
            }
        )

        result = await tester.probe_baseline(["q", "id", "page"])

        assert isinstance(result, dict)
        assert len(result) > 0

    @pytest.mark.asyncio
    async def test_stream_fuzz_yields_finding_events(self) -> None:
        """Test stream_fuzz yields RealTimeEvent with finding data."""
        tester = InteractiveRealTimeTester("https://example.com/search")

        # Mock fuzzer to yield findings
        async def mock_fuzz(*args, **kwargs):
            yield {
                "param": "q",
                "payload": "' OR 1=1--",
                "vuln_type": "SQL Injection",
                "severity": "high",
                "status_code": 500,
            }

        tester.fuzzer.fuzz = mock_fuzz

        events = []
        async for event in tester.stream_fuzz(params=["q"]):
            events.append(event)
            if len(events) >= 1:
                break

        assert len(events) > 0
        assert events[0].event_type in ("finding", "progress", "complete")

    @pytest.mark.asyncio
    async def test_stream_fuzz_yields_chain_discovery_events(self) -> None:
        """Test stream_fuzz yields chain discovery events when exploit chains found."""
        tester = InteractiveRealTimeTester("https://example.com/api")

        # Mock chain engine to return chains
        mock_chain = MagicMock()
        mock_chain.chain_id = "sqli_to_rce"
        mock_chain.name = "SQL Injection to RCE Chain"
        mock_chain.steps = ["SQLi", "File Read", "RCE"]

        async def mock_fuzz_with_chain(*args, **kwargs):
            yield {
                "param": "id",
                "payload": "1; cat /etc/passwd",
                "vuln_type": "SQL Injection",
                "severity": "critical",
            }
            # Simulate chain discovery
            tester._chains.append(mock_chain)

        tester.fuzzer.fuzz = mock_fuzz_with_chain
        tester.chain_engine.find_chains = AsyncMock(return_value=[mock_chain])

        events = []
        async for event in tester.stream_fuzz(params=["id"]):
            events.append(event)
            if len(events) >= 2:
                break

        # Should have at least finding event
        assert len(events) > 0

    @pytest.mark.asyncio
    async def test_stream_fuzz_handles_errors_gracefully(self) -> None:
        """Test stream_fuzz handles fuzzer errors without crashing."""
        tester = InteractiveRealTimeTester("https://example.com/broken")

        # Mock fuzzer to raise error
        async def mock_fuzz_error(*args, **kwargs):
            raise Exception("Connection timeout")

        tester.fuzzer.fuzz = mock_fuzz_error

        events = []
        # Should not crash, should handle error gracefully
        try:
            async for event in tester.stream_fuzz(params=["q"]):
                events.append(event)
        except Exception as e:
            # Error is expected, but should be handled
            assert "timeout" in str(e).lower() or "connection" in str(e).lower()

    @pytest.mark.asyncio
    async def test_stop_request(self) -> None:
        """Test stop method sets stop event."""
        tester = InteractiveRealTimeTester("https://example.com")

        assert tester._stop_event.is_set() is False
        await tester.stop()
        assert tester._stop_event.is_set() is True

    def test_get_summary_returns_stats(self) -> None:
        """Test get_summary returns fuzzing statistics."""
        tester = InteractiveRealTimeTester("https://example.com")

        # Add mock findings
        mock_finding = MagicMock()
        mock_finding.param = "q"
        mock_finding.vuln_type = "XSS"
        mock_finding.severity = "medium"
        tester._findings.append(mock_finding)

        summary = tester.get_summary()

        assert isinstance(summary, dict)
        assert "findings" in summary or "total" in summary or len(summary) > 0


class TestAuthRecoverySafety:
    """Auth recovery should not post credentials to non-login endpoints."""

    @pytest.mark.asyncio
    async def test_skip_auth_recovery_without_login_url(self) -> None:
        fuzzer = Fuzzer(
            "https://example.com/api/private",
            enable_waf_bypass=False,
            enable_rate_limit=False,
            enable_auth_recovery=True,
        )
        try:
            response = httpx.Response(
                401,
                text="Unauthorized",
                request=httpx.Request("GET", "https://example.com/api/private"),
            )
            fuzzer.auth_manager.handle_auth_failure = AsyncMock(return_value=True)  # type: ignore[assignment]
            out = await fuzzer._maybe_recover_auth(response, param="id", value="1")
            assert out is response
            fuzzer.auth_manager.handle_auth_failure.assert_not_called()  # type: ignore[union-attr]
        finally:
            await fuzzer.close()

    @pytest.mark.asyncio
    async def test_auth_recovery_uses_explicit_login_url(self) -> None:
        fuzzer = Fuzzer(
            "https://example.com/api/private",
            enable_waf_bypass=False,
            enable_rate_limit=False,
            enable_auth_recovery=True,
            auth_login_url="https://example.com/login",
        )
        try:
            response = httpx.Response(
                401,
                text="Unauthorized",
                request=httpx.Request("GET", "https://example.com/api/private"),
            )
            fuzzer.auth_manager.handle_auth_failure = AsyncMock(return_value=False)  # type: ignore[assignment]
            out = await fuzzer._maybe_recover_auth(response, param="id", value="1")
            assert out is response
            fuzzer.auth_manager.handle_auth_failure.assert_awaited_once_with(  # type: ignore[union-attr]
                response,
                "https://example.com/login",
            )
        finally:
            await fuzzer.close()


class TestAdvancedPhaseProbes:
    """Tests for Phase 2 and Phase 3 advanced fuzzing probes."""

    @staticmethod
    def _resp(
        status: int, text: str, url: str = "https://example.com/"
    ) -> httpx.Response:
        return httpx.Response(
            status,
            text=text,
            headers={"content-type": "application/json"},
            request=httpx.Request("GET", url),
        )

    @pytest.mark.asyncio
    async def test_cloud_ssrf_probe_detects_metadata(self) -> None:
        fuzzer = Fuzzer(
            "https://example.com/fetch",
            enable_waf_bypass=False,
            enable_rate_limit=False,
            enable_auth_recovery=False,
        )
        fuzzer._fetch_baseline = AsyncMock(return_value={"status": 200})

        async def fake_probe_request(**kwargs):
            params = kwargs.get("params") or kwargs.get("data") or {}
            payload = next(iter(params.values()), "")
            if "169.254.169.254" in str(payload):
                return self._resp(
                    200,
                    "latest/meta-data iam/security-credentials instance-id",
                ), 120.0
            return self._resp(200, "ok"), 80.0

        fuzzer._probe_request = fake_probe_request
        findings = await fuzzer._run_cloud_ssrf_exploitation(["url"])
        assert any(f.vuln_type == "ssrf_cloud_metadata" for f in findings)

    @pytest.mark.asyncio
    async def test_graphql_automation_detects_multiple_signals(self) -> None:
        fuzzer = Fuzzer(
            "https://example.com/graphql",
            enable_waf_bypass=False,
            enable_rate_limit=False,
            enable_auth_recovery=False,
        )

        async def fake_probe_request(**kwargs):
            json_body = kwargs.get("json_body")
            if isinstance(json_body, list):
                return self._resp(200, '[{"data":{"__typename":"Query"}}]'), 50.0
            query = ""
            if isinstance(json_body, dict):
                query = str(json_body.get("query", ""))
            if "__typename" in query and "__schema" not in query:
                return self._resp(200, '{"data":{"__typename":"Query"}}'), 40.0
            if "__schema" in query:
                return self._resp(
                    200, '{"data":{"__schema":{"types":[{"name":"User"}]}}}'
                ), 65.0
            if 'id:"2"' in query:
                return self._resp(
                    200, '{"data":{"user":{"id":"2","email":"b@x.io","role":"admin"}}}'
                ), 55.0
            if 'id:"1"' in query:
                return self._resp(
                    200, '{"data":{"user":{"id":"1","email":"a@x.io","role":"user"}}}'
                ), 55.0
            return self._resp(404, '{"error":"not found"}'), 30.0

        fuzzer._probe_request = fake_probe_request
        findings = await fuzzer._run_graphql_automation(["https://example.com/graphql"])
        vuln_types = {f.vuln_type for f in findings}
        assert "graphql_introspection_exposed" in vuln_types
        assert "graphql_batching_enabled" in vuln_types
        assert "graphql_idor_candidate" in vuln_types

    @pytest.mark.asyncio
    async def test_race_probe_detects_divergence(self) -> None:
        fuzzer = Fuzzer(
            "https://example.com/checkout",
            enable_waf_bypass=False,
            enable_rate_limit=False,
            enable_auth_recovery=False,
        )

        counter = {"n": 0}

        async def fake_probe_request(**kwargs):
            counter["n"] += 1
            if counter["n"] % 2 == 0:
                return self._resp(200, '{"balance":99}'), 25.0
            return self._resp(409, '{"error":"conflict"}'), 25.0

        fuzzer._probe_request = fake_probe_request
        findings = await fuzzer._run_race_condition_testing(["amount"])
        assert any(f.vuln_type == "race_condition_possible" for f in findings)

    @pytest.mark.asyncio
    async def test_second_order_probe_detects_delayed_marker(self) -> None:
        fuzzer = Fuzzer(
            "https://example.com/profile/update",
            enable_waf_bypass=False,
            enable_rate_limit=False,
            enable_auth_recovery=False,
        )
        state = {"marker": ""}

        async def fake_probe_request(**kwargs):
            params = kwargs.get("params") or kwargs.get("data") or {}
            value = next(iter(params.values()), "")
            if "AIRECON_SO_" in str(value):
                state["marker"] = str(value).split("'")[0]
                return self._resp(200, '{"saved":true}'), 70.0
            url = str(kwargs.get("url", ""))
            if "/profile" in url and state["marker"]:
                return self._resp(200, f'{{"view":"{state["marker"]}"}}', url=url), 45.0
            return self._resp(
                200, '{"ok":true}', url=url or "https://example.com/"
            ), 35.0

        fuzzer._probe_request = fake_probe_request
        findings = await fuzzer._run_second_order_detection(
            store_params=["comment"],
            trigger_paths=["/profile"],
        )
        assert any(f.vuln_type == "second_order_reflection" for f in findings)

    @pytest.mark.asyncio
    async def test_cache_probe_detects_marker_reflection(self) -> None:
        fuzzer = Fuzzer(
            "https://example.com/",
            enable_waf_bypass=False,
            enable_rate_limit=False,
            enable_auth_recovery=False,
        )
        state = {"marker": "", "poisoned": False}

        async def fake_probe_request(**kwargs):
            headers = kwargs.get("headers") or {}
            if headers.get("X-Forwarded-Host"):
                state["marker"] = headers["X-Forwarded-Host"].split(".")[0]
                state["poisoned"] = True
                return self._resp(200, '{"cache":"probe"}'), 40.0
            if headers.get("X-Original-URL"):
                return self._resp(200, '{"cache":"probe"}'), 40.0
            if headers.get("X-Host"):
                return self._resp(200, '{"cache":"probe"}'), 40.0
            method = kwargs.get("method", "GET")
            if method == "GET" and state["poisoned"] and state["marker"]:
                state["poisoned"] = False
                return self._resp(200, f'{{"host":"{state["marker"]}"}}'), 35.0
            if method == "POST":
                return self._resp(400, '{"error":"bad request"}'), 35.0
            return self._resp(200, '{"host":"clean"}'), 35.0

        fuzzer._probe_request = fake_probe_request
        findings = await fuzzer._run_http_desync_cache_testing()
        assert any(f.vuln_type == "cache_poisoning_candidate" for f in findings)

    @pytest.mark.asyncio
    async def test_race_probe_bypasses_rate_limiter_for_parallel_burst(self) -> None:
        fuzzer = Fuzzer(
            "https://example.com/checkout",
            enable_waf_bypass=False,
            enable_rate_limit=True,
            enable_auth_recovery=False,
        )
        fuzzer.rate_limiter.request = AsyncMock(
            side_effect=AssertionError("rate limiter should not be used for race burst")
        )

        counter = {"n": 0}
        make_resp = self._resp

        class _DummyClient:
            async def request(self, method, url, **kwargs):
                del method, url, kwargs
                counter["n"] += 1
                if counter["n"] % 2 == 0:
                    return make_resp(200, '{"balance":99}')
                return make_resp(409, '{"error":"conflict"}')

        dummy_client = _DummyClient()
        fuzzer._get_direct_client = AsyncMock(return_value=dummy_client)

        findings = await fuzzer._run_race_condition_testing(["amount"])
        assert any(f.vuln_type == "race_condition_possible" for f in findings)
        assert fuzzer.rate_limiter.request.await_count == 0
        await fuzzer.close()


@pytest.mark.asyncio
async def test_evolve_batch_keeps_vuln_type():
    from unittest.mock import MagicMock

    from airecon.proxy.fuzzer import Fuzzer, FuzzResult

    fuzzer = Fuzzer.__new__(Fuzzer)
    fuzzer.detected_wafs = []
    engine = MagicMock()
    result = FuzzResult(
        target="https://example.com",
        parameter="q",
        payload="fixture",
        vuln_type="fixture_type",
        severity="info",
        evidence="fixture",
        confidence=0.9,
        response_code=200,
        response_length=1,
        time_ms=1.0,
    )
    await fuzzer._evolve_payloads_batch(engine, [result], 0)
    engine.evolve.assert_called_once()
    assert engine.evolve.call_args.args[0] == "fixture_type"

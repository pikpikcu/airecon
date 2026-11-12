from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest

from airecon.proxy.config import DEFAULT_CONFIG
from airecon.proxy.fuzzer import Fuzzer


@pytest.mark.asyncio
@pytest.mark.parametrize("response", [
    httpx.Response(200, text="actual response evidence", headers={"X-Fixture": "present"}),
    None,
])
async def test_verification_receives_captured_response_not_payload(monkeypatch, response):
    fuzzer = Fuzzer.__new__(Fuzzer)
    fuzzer.target = "https://example.com/fixture"
    fuzzer.headers = {}
    fuzzer._baseline = {"q": {"body": "baseline fixture"}}
    finding = fuzzer._build_finding(
        param="q", payload="input fixture", vuln_type="fixture", confidence=0.9,
        evidence="fixture", response=response, time_ms=1.0,
    )
    verifier = SimpleNamespace(verify_finding=AsyncMock(return_value=SimpleNamespace(
        verified_confidence=0.9, verification_tier=1, details={},
    )))
    config = SimpleNamespace(**(DEFAULT_CONFIG | {"verification_enabled": True}))
    monkeypatch.setattr("airecon.proxy.config.get_config", lambda: config)
    monkeypatch.setattr("airecon.proxy.agent.verification.VerificationEngine", lambda **kwargs: verifier)
    assert await fuzzer._verify_findings([finding]) == [finding]
    sent = verifier.verify_finding.call_args.kwargs
    assert sent["fuzz_body"] == (response.text if response is not None else "")
    assert sent["response_headers"] == (dict(response.headers) if response is not None else {})
    assert sent["response_status"] == (response.status_code if response is not None else 0)

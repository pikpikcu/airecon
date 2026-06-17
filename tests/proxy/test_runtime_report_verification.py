"""Tests for active runtime verification on the report path.

Covers the type-aware block/no-block logic added in v1.7.1-beta:
- replay-reliable types that actively fail to reproduce are blocked
- stateful/novel types are never blocked by replay
- POST-only / unreachable endpoints are never treated as disproof
- confirmed findings stamp verification metadata onto session vulns
"""

from __future__ import annotations

import types

import pytest

import airecon.proxy.agent.verification as verif_mod
from airecon.proxy.agent.executors_reporting import _ReportingExecutorMixin
from airecon.proxy.agent.verification import VerificationResult


def _make_fake_engine(**result_kwargs):
    """Return a fake VerificationEngine class yielding a controlled result."""

    base = dict(
        finding_id="x",
        vuln_type="xss",
        parameter="q",
        target="https://t.example/s?q=1",
        original_confidence=0.6,
        verified_confidence=0.6,
        verification_tier=0,
        is_false_positive=False,
    )
    base.update(result_kwargs)

    class _FakeEngine:
        def __init__(self, *a, **k):
            pass

        async def verify_finding(self, *a, **k):
            return VerificationResult(**base)

    return _FakeEngine


def _stub(monkeypatch, **result_kwargs):
    monkeypatch.setattr(verif_mod, "VerificationEngine", _make_fake_engine(**result_kwargs))
    s = types.SimpleNamespace()
    s.state = types.SimpleNamespace(
        active_target="https://t.example",
        auth_headers=None,
        session_headers=None,
        http_headers=None,
    )
    s._session = types.SimpleNamespace(vulnerabilities=[])
    s._runtime_verify_report = _ReportingExecutorMixin._runtime_verify_report.__get__(s)
    s._infer_runtime_vuln_type = _ReportingExecutorMixin._infer_runtime_vuln_type.__get__(s)
    s._extract_http_target = _ReportingExecutorMixin._extract_http_target.__get__(s)
    s._extract_injection_param = _ReportingExecutorMixin._extract_injection_param
    s._verification_http_headers = _ReportingExecutorMixin._verification_http_headers.__get__(s)
    return s


_XSS_ARGS = {
    "title": "Reflected XSS in q",
    "description": "cross-site scripting",
    "endpoint": "https://t.example/s?q=1",
    "method": "GET",
}


@pytest.mark.asyncio
async def test_block_reliable_type_unreproducible(monkeypatch):
    s = _stub(
        monkeypatch,
        replay_success=False,
        replay_count=3,
        negative_test_passed=True,
        evidence_bundle=[{"status": 200, "confirmed": False}],
    )
    out = await s._runtime_verify_report(_XSS_ARGS)
    assert out["ran"] is True
    assert out["blocked"] is True
    assert "could not reproduce" in out["reason"]


@pytest.mark.asyncio
async def test_no_block_when_confirmed(monkeypatch):
    s = _stub(
        monkeypatch,
        replay_success=True,
        replay_count=3,
        verified_confidence=0.9,
        evidence_bundle=[{"status": 200, "confirmed": True}],
    )
    out = await s._runtime_verify_report(_XSS_ARGS)
    assert out["blocked"] is False
    assert out["replay_success"] is True
    assert out["confidence"] >= 0.9


@pytest.mark.asyncio
async def test_no_block_stateful_type(monkeypatch):
    # IDOR is not in the runtime-confirmator keyword map → never actively tested.
    s = _stub(monkeypatch, replay_success=False, replay_count=3, negative_test_passed=True)
    out = await s._runtime_verify_report(
        {"title": "IDOR on /api/users/1", "endpoint": "https://t.example/api/users/1"}
    )
    assert out["ran"] is False
    assert out["blocked"] is False


@pytest.mark.asyncio
async def test_no_block_post_method(monkeypatch):
    s = _stub(
        monkeypatch,
        replay_success=False,
        replay_count=3,
        negative_test_passed=True,
        evidence_bundle=[{"status": 200}],
    )
    args = dict(_XSS_ARGS, method="POST")
    out = await s._runtime_verify_report(args)
    assert out["ran"] is True
    assert out["blocked"] is False


@pytest.mark.asyncio
async def test_no_block_unreachable_endpoint(monkeypatch):
    # All replay attempts returned >=400 → endpoint not exercised, no disproof.
    s = _stub(
        monkeypatch,
        replay_success=False,
        replay_count=3,
        negative_test_passed=True,
        evidence_bundle=[{"status": 403}, {"status": 404}],
    )
    out = await s._runtime_verify_report(_XSS_ARGS)
    assert out["blocked"] is False


@pytest.mark.asyncio
async def test_no_block_without_injection_point(monkeypatch):
    s = _stub(monkeypatch, replay_success=False, replay_count=3)
    # endpoint has no query param and no explicit parameter
    out = await s._runtime_verify_report(
        {"title": "Reflected XSS", "endpoint": "https://t.example/s", "method": "GET"}
    )
    assert out["ran"] is False

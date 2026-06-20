"""Tests for the target-specific novel-discovery rework (v1.7.1-beta).

The old engine picked tactics at random from a fixed list on a mechanical
iteration cadence, so every run injected the same generic checklist regardless
of target. These tests lock in the replacement:
- tactics are derived from the actual findings (target-specific)
- output is deterministic (same findings -> same tactics), not random
- different targets get different tactics
- no generic filler when there is no matching signal
- the emergent vector is finding-grounded, not a random-md5 placeholder
- the LLM cache, when populated, takes precedence
"""

from __future__ import annotations

import pytest

import airecon.proxy.agent.novel_discovery as nd


def _f(title, **extra):
    d = {"title": title}
    d.update(extra)
    return d


def test_tactics_are_target_specific_jwt():
    findings = [
        _f("JWT alg=none accepted on /api/login", category="jwt", parameter="token"),
        _f("Bearer token not validated", category="auth"),
    ]
    out = nd.analyze_novel_vectors(findings, iteration=1)
    tactics = " ".join(out["innovative_tactics"]).lower()
    assert "jwt" in tactics  # tied to the actual JWT finding


def test_tactics_differ_across_targets():
    jwt_findings = [_f("JWT signature weakness", category="jwt")]
    graphql_findings = [_f("GraphQL introspection enabled", category="graphql")]

    jwt_t = nd.analyze_novel_vectors(jwt_findings, iteration=0)["innovative_tactics"]
    gql_t = nd.analyze_novel_vectors(graphql_findings, iteration=0)["innovative_tactics"]

    assert jwt_t != gql_t  # different targets -> different tactics
    assert any("jwt" in t.lower() for t in jwt_t)
    assert any("graphql" in t.lower() for t in gql_t)


def test_output_is_deterministic_not_random():
    findings = [
        _f("Race condition on /coupon/redeem", category="concurrency_issue"),
        _f("Balance transfer lacks locking", category="logic_conflict"),
    ]
    a = nd.analyze_novel_vectors(findings, iteration=7)["innovative_tactics"]
    b = nd.analyze_novel_vectors(findings, iteration=99)["innovative_tactics"]
    # Same findings must yield the same tactics regardless of iteration number.
    assert a == b


def test_no_generic_filler_without_matching_signal():
    findings = [_f("zxqv obscure thing with no theme keywords")]
    out = nd.analyze_novel_vectors(findings, iteration=3)
    assert out["innovative_tactics"] == []  # no canned filler injected


def test_emergent_vector_is_finding_grounded():
    findings = [
        _f("Information disclosure in stack trace", category="information_disclosure"),
        _f("Broken access control on /admin", category="access_control"),
        _f("Predictable order IDs", category="predictability"),
    ]
    out = nd.analyze_novel_vectors(findings, iteration=2)
    vecs = out["novel_vectors"]
    assert vecs, "expected an emergent vector for 3 findings with >=2 signals"
    v = vecs[0]
    # Grounded in the real finding titles, not a hardcoded placeholder string.
    assert v["description"] != "Multi-finding escalation path"
    assert v["bases"]
    assert any("disclosure" in b.lower() or "access" in b.lower() for b in v["bases"])
    assert v["source"] == "heuristic"


def test_emergent_vector_stable_id_for_same_findings():
    findings = [
        _f("Info disclosure A", category="information_disclosure"),
        _f("Access control B", category="access_control"),
        _f("Predictable C", category="predictability"),
    ]
    v1 = nd.analyze_novel_vectors(findings, iteration=1)["novel_vectors"][0]["id"]
    v2 = nd.analyze_novel_vectors(findings, iteration=50)["novel_vectors"][0]["id"]
    assert v1 == v2  # deterministic id, not random per call


def test_llm_cache_takes_precedence():
    findings = [_f("Some SQLi on /search", category="sqli", parameter="q")]
    sig = nd._findings_signature(findings)
    nd._LLM_VECTOR_CACHE[sig] = {
        "tactics": ["Pivot the /search SQLi into stacked queries for RCE on MSSQL"],
        "vector": {
            "description": "Chain /search SQLi -> creds -> admin panel",
            "escalation": "Dump users table, crack hash, log into /admin",
            "confidence": 0.8,
        },
    }
    try:
        out = nd.analyze_novel_vectors(findings, iteration=0)
        assert out["innovative_tactics"][0].startswith("Pivot the /search SQLi")
        assert out["novel_vectors"][0]["source"] == "llm"
        assert out["novel_vectors"][0]["confidence"] == 0.8
    finally:
        nd._LLM_VECTOR_CACHE.pop(sig, None)


@pytest.mark.asyncio
async def test_llm_generator_noops_without_backend(monkeypatch):
    # No backend configured -> returns {} and does not populate cache.
    class _Cfg:
        openai_base_url = ""
        openai_model = ""

    monkeypatch.setattr("airecon.proxy.config.get_config", lambda: _Cfg())
    out = await nd.generate_llm_novel_vectors([_f("X", category="xss")])
    assert out == {}

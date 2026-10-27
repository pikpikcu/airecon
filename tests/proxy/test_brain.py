"""Tests for the cross-session brain: vectors, retrieval, dedup, pruning."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from airecon.proxy.brain import cosine, pack_vector, unpack_vector


def test_vector_roundtrip_is_faithful():
    vec = [0.1, -0.25, 3.5, 0.0]
    restored = unpack_vector(pack_vector(vec))
    assert len(restored) == len(vec)
    for a, b in zip(vec, restored):
        assert abs(a - b) < 1e-6


def test_cosine_ranks_identical_above_orthogonal():
    a = [1.0, 0.0, 0.0]
    b = [1.0, 0.0, 0.0]
    c = [0.0, 1.0, 0.0]
    assert cosine(a, b) == pytest.approx(1.0)
    assert cosine(a, c) == pytest.approx(0.0)
    assert cosine(a, b) > cosine(a, c)


def test_cosine_handles_mismatched_and_empty():
    assert cosine([], [1.0]) == 0.0
    assert cosine([1.0, 2.0], [1.0]) == 0.0
    assert cosine([0.0, 0.0], [1.0, 1.0]) == 0.0


class _FakeCfg:
    intelligence_semantic_recall = True
    embedding_model = "test-embed"
    intelligence_dedup_threshold = 0.9
    intelligence_utility_floor = 0.2
    intelligence_insight_ttl_days = 90
    openai_base_url = "http://localhost:20128/v1"
    openai_api_key = "k"
    openai_model = "m"
    llm_timeout = 5.0
    intelligence_embeddings_enabled = True


def _engine(tmp_path, monkeypatch):
    from airecon.proxy.agent import adaptive_learning as al

    monkeypatch.setattr(al, "_MEMORY_DB", tmp_path / "airecon.db")
    monkeypatch.setattr(al, "_LEARNING_DIR", tmp_path / "learning")
    with patch("airecon.proxy.config.get_config", return_value=_FakeCfg()):
        eng = al.AdaptiveLearningEngine(min_observations=2, session_id="s1")
    eng._semantic_recall = True
    eng._embedding_model = "test-embed"
    return eng


def test_semantic_recall_prefers_similar_insight(tmp_path, monkeypatch):
    eng = _engine(tmp_path, monkeypatch)
    from airecon.proxy.agent.adaptive_learning import LearnedInsight

    kw = dict(
        category="vuln_pattern", description="d", recommendation="r",
        conditions={}, confidence=0.6, observation_count=1,
    )
    remote = LearnedInsight(insight_id="remote", title="nginx", **kw)
    auth = LearnedInsight(insight_id="auth", title="jwt", **kw)
    eng.learned_insights = [remote, auth]
    eng._insight_vectors = {"remote": [1.0, 0.0], "auth": [0.0, 1.0]}

    with patch.object(eng, "_embed_texts", return_value=[[0.9, 0.1]]):
        hits = eng.get_insights_semantic(phase="EXPLOIT", tech_stack=["nginx"])
    assert hits and hits[0].insight_id == "remote"


def test_store_dedups_semantically_similar_insight(tmp_path, monkeypatch):
    eng = _engine(tmp_path, monkeypatch)
    eng._dedup_threshold = 0.9
    from airecon.proxy.agent.adaptive_learning import LearnedInsight

    existing = LearnedInsight(
        insight_id="a", category="vuln_pattern", title="one", description="d",
        conditions={}, recommendation="r", confidence=0.6, observation_count=1,
    )
    eng.learned_insights = [existing]
    eng._insight_vectors = {"a": [1.0, 0.0]}

    dupe = LearnedInsight(
        insight_id="b", category="vuln_pattern", title="two", description="d",
        conditions={}, recommendation="r", confidence=0.8, observation_count=1,
    )
    stored, created = eng._store_learned_insight(dupe, vector=[0.99, 0.01])
    assert created is False
    assert stored.insight_id == "a"
    assert stored.confidence == pytest.approx(0.8)
    assert len(eng.learned_insights) == 1


def test_store_keeps_distinct_insight(tmp_path, monkeypatch):
    eng = _engine(tmp_path, monkeypatch)
    eng._dedup_threshold = 0.9
    from airecon.proxy.agent.adaptive_learning import LearnedInsight

    existing = LearnedInsight(
        insight_id="a", category="vuln_pattern", title="one", description="d",
        conditions={}, recommendation="r", confidence=0.6, observation_count=1,
    )
    eng.learned_insights = [existing]
    eng._insight_vectors = {"a": [1.0, 0.0]}

    fresh = LearnedInsight(
        insight_id="c", category="vuln_pattern", title="three", description="d",
        conditions={}, recommendation="r", confidence=0.6, observation_count=1,
    )
    stored, created = eng._store_learned_insight(fresh, vector=[0.0, 1.0])
    assert created is True
    assert len(eng.learned_insights) == 2


def test_embed_texts_never_raises_without_model(tmp_path, monkeypatch):
    eng = _engine(tmp_path, monkeypatch)
    eng._embedding_model = ""
    assert eng._embed_texts(["x"]) == []


def test_prune_drops_low_utility_insight(tmp_path, monkeypatch):
    eng = _engine(tmp_path, monkeypatch)
    from airecon.proxy.agent.adaptive_learning import LearnedInsight, _insight_ref_id

    weak = LearnedInsight(
        insight_id="weak", category="vuln_pattern", title="weak", description="d",
        conditions={}, recommendation="r", confidence=0.6, observation_count=1,
        session_ids=["old-session"],
    )
    eng.learned_insights = [weak]
    eng._insight_vectors = {"weak": [1.0, 0.0]}

    eng._bump_utility({_insight_ref_id("weak")}, hit=False)
    eng._bump_utility({_insight_ref_id("weak")}, hit=False)
    eng._bump_utility({_insight_ref_id("weak")}, hit=False)
    eng._utility_floor = 0.2
    eng._prune_learned_insights()
    assert eng.learned_insights == []


def test_prune_keeps_high_utility_insight(tmp_path, monkeypatch):
    eng = _engine(tmp_path, monkeypatch)
    from airecon.proxy.agent.adaptive_learning import LearnedInsight, _insight_ref_id

    strong = LearnedInsight(
        insight_id="strong", category="vuln_pattern", title="strong", description="d",
        conditions={}, recommendation="r", confidence=0.6, observation_count=1,
        session_ids=["old-session"],
    )
    eng.learned_insights = [strong]
    ref = _insight_ref_id("strong")
    for _ in range(3):
        eng._bump_utility({ref}, hit=True)
    eng._prune_learned_insights()
    assert len(eng.learned_insights) == 1


def _patch_distill(monkeypatch, payload):
    import json
    from airecon.proxy.agent import adaptive_learning as al

    class _FakeFuture:
        def result(self, timeout=None):
            return json.dumps(payload)

    class _FakeExecutor:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def submit(self, fn):
            return _FakeFuture()

    monkeypatch.setattr(
        al.concurrent.futures,
        "ThreadPoolExecutor",
        lambda max_workers=1: _FakeExecutor(),
    )


@pytest.mark.asyncio
async def test_distill_learns_from_failures_with_lower_confidence(tmp_path, monkeypatch):
    eng = _engine(tmp_path, monkeypatch)
    from airecon.proxy.agent.adaptive_learning import ObservationLog

    eng.observation_log = [
        ObservationLog(
            timestamp=1.0, tool_name="hydra", arguments={},
            result_summary="login throttled", success=False, confidence=0.1,
            phase="EXPLOIT", target_type="nginx",
        )
        for _ in range(6)
    ]
    _patch_distill(
        monkeypatch,
        [
            {
                "category": "vuln_pattern",
                "title": "avoid hydra on throttled login",
                "conditions": {"tech": "nginx"},
                "recommendation": "switch to slow password-spray",
                "outcome": "failure",
            }
        ],
    )
    eng._embedding_model = ""
    with patch("airecon.proxy.config.get_config", return_value=_FakeCfg()):
        added = eng.distill_insights(base_url="http://router.local/v1", model="m")
    assert len(added) == 1
    assert added[0].confidence == pytest.approx(0.35)


@pytest.mark.asyncio
async def test_distill_persists_vectors_for_recall(tmp_path, monkeypatch):
    eng = _engine(tmp_path, monkeypatch)
    from airecon.proxy.agent.adaptive_learning import ObservationLog

    eng.observation_log = [
        ObservationLog(
            timestamp=1.0, tool_name="nuclei", arguments={},
            result_summary="cve hit", success=True, confidence=0.9,
            phase="EXPLOIT", target_type="nginx",
        )
        for _ in range(6)
    ]
    _patch_distill(
        monkeypatch,
        [
            {
                "category": "vuln_pattern",
                "title": "nuclei finds nginx CVEs",
                "conditions": {"tech": "nginx"},
                "recommendation": "run nuclei first",
                "outcome": "success",
            }
        ],
    )
    with patch.object(eng, "_embed_texts", return_value=[[1.0, 0.0, 0.0]]):
        added = eng.distill_insights(base_url="http://router.local/v1", model="m")
    assert added and eng._insight_vectors.get(added[0].insight_id) == [1.0, 0.0, 0.0]

    with patch.object(eng, "_embed_texts", return_value=[[0.95, 0.05, 0.0]]):
        hits = eng.get_insights_semantic(phase="EXPLOIT", tech_stack=["nginx"])
    assert hits and hits[0].insight_id == added[0].insight_id


def test_get_insights_for_context_falls_back_when_no_vectors(tmp_path, monkeypatch):
    eng = _engine(tmp_path, monkeypatch)
    from airecon.proxy.agent.adaptive_learning import LearnedInsight

    eng.learned_insights = [
        LearnedInsight(
            insight_id="x", category="tool_tech", title="nmap", description="d",
            conditions={"phase": "RECON"}, recommendation="r", confidence=0.7,
            observation_count=3,
        )
    ]
    eng._insight_vectors = {}
    with patch.object(eng, "_load_insight_vectors", return_value=None):
        out = eng.get_insights_for_context(phase="RECON", tech_stack=["nginx"])
    assert [i.insight_id for i in out] == ["x"]


def test_delete_embeddings_for_refs_removes_only_requested_rows():
    import sqlite3

    from airecon.proxy.memory import MemoryManager, _init_schema

    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    _init_schema(conn)
    manager = MemoryManager.__new__(MemoryManager)
    manager.conn = conn
    for kind, ref in (("insight", 1), ("insight", 2), ("insight", 3), ("knowledge", 1)):
        manager.upsert_embedding(kind, ref, "fixture", b"\x00" * 8, 2)
    manager.delete_embeddings_for_refs("insight", [1, 3, 999])
    rows = conn.execute("SELECT kind, ref_id FROM embeddings ORDER BY kind, ref_id").fetchall()
    assert [tuple(r) for r in rows] == [("insight", 2), ("knowledge", 1)]
    conn.close()

"""Cross-session memory contracts: async recall, storage and truthful utility."""
from __future__ import annotations
import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock
import pytest
from airecon.proxy.agent import adaptive_learning as al
from airecon.proxy.config import DEFAULT_CONFIG

@pytest.fixture
def engine(monkeypatch,tmp_path):
    cfg=SimpleNamespace(**(DEFAULT_CONFIG|{"embedding_model":"fixture-embed","intelligence_semantic_recall":True,"intelligence_embeddings_enabled":True}))
    monkeypatch.setattr("airecon.proxy.config.get_config",lambda:cfg)
    monkeypatch.setattr(al,"_MEMORY_DB",tmp_path/"memory.db")
    monkeypatch.setattr(al,"_LEARNING_DIR",tmp_path/"learning")
    e=al.AdaptiveLearningEngine(session_id="current")
    e.learned_insights=[]
    return e

def item(identity="a",session="previous"):
    return al.LearnedInsight(insight_id=identity,category="tool_tech",title="fixture "+identity,description="fixture",conditions={"phase":"RECON","tech":"nginx"},recommendation="read fixture",confidence=.7,observation_count=5,session_ids=[session])

@pytest.mark.asyncio
async def test_semantic_recall_does_not_block_event_loop(engine):
    engine.learned_insights=[item()]
    engine._insight_vectors={"a":[1.,0.]}
    client=SimpleNamespace(embed=AsyncMock(return_value=[[1.,0.]]))
    ran=[]
    async def delayed(*args,**kwargs):
        await asyncio.sleep(.03)
        return [[1.,0.]]
    client.embed.side_effect=delayed
    asyncio.get_running_loop().call_later(.005,lambda:ran.append(True))
    result=await engine.recall_async(client,"RECON",["nginx"])
    assert ran and result[0].insight_id=="a"


def test_hit_attribution_does_not_inflate_recalls(engine):
    engine.learned_insights=[item()]
    for _ in range(3):
        engine.record_recall(engine.learned_insights)
        engine.attribute_hit()
    stats=engine._utility_map()["a"]
    assert stats["recalls"]==3 and stats["hits"]==3


def test_pruning_removes_both_persistent_retrieval_stores(engine):
    value=item()
    engine.learned_insights=[value]
    engine._insight_vectors={"a":[1.,0.]}
    engine._persist_insights_to_memory_db([value])
    engine._persist_insight_vectors([value])
    for _ in range(3):
        engine.record_recall([value])
    engine._prune_learned_insights()
    assert not engine.learned_insights
    con=al._open_memory_db(read_only=True)
    assert con.execute("SELECT COUNT(*) FROM embeddings").fetchone()[0]==0
    assert con.execute("SELECT COUNT(*) FROM knowledge WHERE title=?",(value.title,)).fetchone()[0]==0
    con.close()

@pytest.mark.asyncio
async def test_async_distill_learns_failures_and_reloads_vectors(engine):
    import json
    engine.observation_log=[al.ObservationLog(timestamp=1,tool_name="fixture",arguments={},result_summary="fixture failure",success=False,confidence=.1,phase="RECON",target_type="nginx") for _ in range(9)]
    client=SimpleNamespace(complete=AsyncMock(return_value=json.dumps([{"category":"tool_tech","title":"avoid fixture failure","conditions":{"tech":"nginx"},"recommendation":"use fixture alternative","outcome":"failure"}])),embed=AsyncMock(return_value=[[1.,0.]]))
    result=await engine.distill_async(client)
    assert len(result)==1 and result[0].confidence==.35
    engine._insight_vectors={}
    engine._load_insight_vectors()
    assert engine._insight_vectors[result[0].insight_id]==[1.,0.]


@pytest.mark.asyncio
async def test_async_recall_lexical_fallback_is_counted(engine):
    engine.learned_insights = [item()]
    result = await engine.recall_async(SimpleNamespace(embed=AsyncMock(return_value=None)), "RECON", ["nginx"])
    assert result[0].insight_id == "a"
    assert engine._utility_map()["a"]["recalls"] == 1


@pytest.mark.asyncio
async def test_semantic_miss_keeps_lexical_matches(engine):
    engine.learned_insights = [item()]
    engine._insight_vectors = {"a": [1., 0.]}
    result = await engine.recall_async(SimpleNamespace(embed=AsyncMock(return_value=[[0., 1.]])), "RECON", ["nginx"])
    assert [i.insight_id for i in result] == ["a"]
    assert engine._last_recall_mode == "lexical"


@pytest.mark.asyncio
async def test_async_distill_without_embeddings_remains_usable(engine):
    import json
    engine.observation_log = [al.ObservationLog(timestamp=1, tool_name="fixture", arguments={}, result_summary="failure", success=False, confidence=.1, phase="RECON", target_type="nginx") for _ in range(9)]
    reply = [{"category":"tool_tech", "title":"avoid fixture", "conditions":{}, "recommendation":"fixture alternative", "outcome":"failure"}]
    client = SimpleNamespace(complete=AsyncMock(return_value=json.dumps(reply)), embed=AsyncMock(return_value=None))
    result = await engine.distill_async(client)
    assert len(result) == 1 and result[0].confidence == .35


def test_retirement_keeps_unrelated_knowledge_with_same_title(engine):
    value = item()
    engine.learned_insights = [value]
    engine._persist_insights_to_memory_db([value])
    con = al._open_memory_db(read_only=False)
    con.execute("INSERT INTO knowledge(category,title,content,confidence,tags) VALUES (?,?,?,?,?)", ("operator_note",value.title,"keep this",1.,'["manual"]'))
    con.commit()
    con.close()
    for _ in range(3):
        engine.record_recall([value])
    engine._prune_learned_insights()
    con = al._open_memory_db(read_only=True)
    assert con.execute("SELECT content FROM knowledge WHERE category='operator_note'").fetchone()[0] == "keep this"
    con.close()


def test_renamed_semantic_merge_does_not_leave_retired_knowledge(engine):
    value = item()
    engine.learned_insights = [value]
    engine._insight_vectors = {"a": [1., 0.]}
    engine._persist_insights_to_memory_db([value])
    incoming = item("b")
    incoming.title = "renamed fixture"
    stored, created = engine._store_learned_insight(incoming, vector=[1., 0.])
    assert not created
    for _ in range(3):
        engine.record_recall([stored])
    engine._prune_learned_insights()
    con = al._open_memory_db(read_only=True)
    assert con.execute("SELECT COUNT(*) FROM knowledge").fetchone()[0] == 0
    con.close()

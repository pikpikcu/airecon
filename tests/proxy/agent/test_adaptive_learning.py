"""Tests for Adaptive Learning."""

from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path

import pytest


def _init_learning_db(db_path: Path) -> None:
    from airecon.proxy.memory import _init_schema, configure_sqlite_connection

    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    configure_sqlite_connection(conn)
    _init_schema(conn)
    conn.close()


@pytest.fixture
def isolated_learning_paths(tmp_path, monkeypatch):
    import airecon.proxy.agent.adaptive_learning as learning_mod

    learning_dir = tmp_path / "learning"
    learning_dir.mkdir()
    memory_dir = tmp_path / "memory"
    memory_dir.mkdir()
    memory_db = memory_dir / "airecon.db"

    monkeypatch.setattr(learning_mod, "_LEARNING_DIR", learning_dir)
    monkeypatch.setattr(learning_mod, "_MEMORY_DB", memory_db)
    monkeypatch.setattr(learning_mod, "_TARGET_MEMORY_DIR", tmp_path / "by_target")
    return learning_mod, memory_db


class TestToolPerformance:
    def test_creation(self):
        from airecon.proxy.agent.adaptive_learning import ToolPerformance

        p = ToolPerformance(tool_name="test")
        assert p.tool_name == "test"


class TestAdaptiveLearningEngine:
    def test_init(self, isolated_learning_paths):
        learning_mod, _ = isolated_learning_paths

        engine = learning_mod.AdaptiveLearningEngine()
        assert engine is not None

    def test_import_from_memory_db_aggregates_scoped_tool_usage(
        self, isolated_learning_paths
    ):
        learning_mod, memory_db = isolated_learning_paths
        _init_learning_db(memory_db)

        conn = sqlite3.connect(str(memory_db))
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.executemany(
            """
            INSERT INTO tool_usage
            (tool_name, target, success_count, failure_count, avg_duration_sec, typical_output_size)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            [
                ("nmap", "a.example.com", 1, 0, 10.0, 100),
                ("nmap", "b.example.com", 2, 1, 20.0, 200),
            ],
        )
        conn.commit()
        conn.close()

        engine = learning_mod.AdaptiveLearningEngine(session_id="test_import")
        perf = engine.tool_performances["nmap"]

        assert perf.successes == 3
        assert perf.failures == 1
        assert perf.total_uses == 4

    def test_sync_to_memory_db_collapses_duplicate_global_rows(
        self, isolated_learning_paths
    ):
        learning_mod, memory_db = isolated_learning_paths
        _init_learning_db(memory_db)

        conn = sqlite3.connect(str(memory_db))
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.executemany(
            """
            INSERT INTO tool_usage
            (tool_name, target, success_count, failure_count, avg_duration_sec, typical_output_size)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            [
                ("ffuf", "", 1, 0, 1.0, 10),
                ("ffuf", "", 3, 1, 2.0, 20),
                ("ffuf", "example.com", 2, 0, 1.5, 15),
            ],
        )
        conn.commit()
        conn.close()

        engine = learning_mod.AdaptiveLearningEngine(session_id="test_sync")
        engine.tool_performances["ffuf"] = learning_mod.ToolPerformance(
            tool_name="ffuf",
            total_uses=6,
            successes=5,
            failures=1,
            avg_duration=1.7,
        )
        engine._sync_to_memory_db()

        conn = sqlite3.connect(str(memory_db))
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute(
            """
            SELECT success_count, failure_count
            FROM tool_usage
            WHERE tool_name = ? AND target = ''
            ORDER BY id ASC
            """,
            ("ffuf",),
        )
        rows = cur.fetchall()
        conn.close()

        assert len(rows) == 1
        assert rows[0]["success_count"] == 5
        assert rows[0]["failure_count"] == 1

    @pytest.mark.asyncio
    async def test_distill_insights_uses_worker_executor_inside_running_loop(
        self, isolated_learning_paths, monkeypatch
    ):
        learning_mod, _ = isolated_learning_paths
        engine = learning_mod.AdaptiveLearningEngine(
            min_observations=1,
            session_id="test_distill",
        )
        engine.observation_log = [
            learning_mod.ObservationLog(
                timestamp=1.0,
                tool_name="http_observe",
                arguments={},
                result_summary="ok",
                success=True,
                confidence=0.8,
                phase="RECON",
                target_type="nginx",
            )
            for _ in range(3)
        ]

        calls: dict[str, object] = {}

        class _FakeFuture:
            def result(self, timeout=None):
                calls["timeout"] = timeout
                return json.dumps(
                    [
                        {
                            "category": "tool_tech",
                            "title": "Prefer observe first",
                            "conditions": {"tech": "nginx"},
                            "recommendation": "Run observe before fuzzing",
                        }
                    ]
                )

        class _FakeExecutor:
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def submit(self, fn):
                calls["submitted"] = True
                return _FakeFuture()

        monkeypatch.setattr(
            learning_mod.concurrent.futures,
            "ThreadPoolExecutor",
            lambda max_workers=1: _FakeExecutor(),
        )

        insights = engine.distill_insights(
            base_url="http://router.local/v1",
            model="qwen-test",
        )

        assert calls["submitted"] is True
        assert calls["timeout"] == 125
        assert len(insights) == 1
        assert insights[0].title == "Prefer observe first"

    @pytest.mark.asyncio
    async def test_distill_insights_persists_knowledge_to_memory_db(
        self, isolated_learning_paths, monkeypatch
    ):
        learning_mod, memory_db = isolated_learning_paths
        _init_learning_db(memory_db)

        engine = learning_mod.AdaptiveLearningEngine(
            min_observations=1,
            session_id="test_knowledge",
        )
        engine.observation_log = [
            learning_mod.ObservationLog(
                timestamp=1.0,
                tool_name="auth_probe",
                arguments={},
                result_summary="login flow reused",
                success=True,
                confidence=0.8,
                phase="EXPLOIT",
                target_type="nginx",
            )
            for _ in range(3)
        ]

        class _FakeFuture:
            def result(self, timeout=None):
                return json.dumps(
                    [
                        {
                            "category": "exploit_chain",
                            "title": "Reuse login bypass early",
                            "conditions": {"phase": "EXPLOIT", "tech": "NGINX"},
                            "recommendation": "Carry the working auth bypass forward before deeper exploit steps",
                        }
                    ]
                )

        class _FakeExecutor:
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def submit(self, fn):
                return _FakeFuture()

        monkeypatch.setattr(
            learning_mod.concurrent.futures,
            "ThreadPoolExecutor",
            lambda max_workers=1: _FakeExecutor(),
        )

        insights = engine.distill_insights(
            base_url="http://router.local/v1",
            model="qwen-test",
        )

        assert len(insights) == 1

        conn = sqlite3.connect(str(memory_db))
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute("SELECT category, title, content, tags FROM knowledge")
        row = cur.fetchone()
        conn.close()

        assert row is not None
        assert row["category"] == "exploitation"
        assert row["title"] == "Reuse login bypass early"
        assert "auth bypass" in row["content"].lower()
        assert "phase:exploit" in json.loads(row["tags"])
        assert "tech:nginx" in json.loads(row["tags"])

    def test_tool_name_and_phase_caches_are_metadata_driven(self, monkeypatch):
        import airecon.proxy.agent.adaptive_learning as learning_mod

        fake_meta = {
            "categories": {
                "reconnaissance": {"api_probe": ["scanx"]},
                "vulnerability_scanning": {"web_tests": ["auditx"]},
            },
            "tool_descriptions": {"scriptx": "script helper"},
            "analysis_phase_vuln_tools": ["vulnx"],
            "watchdog_safe_command_prefixes": ["prefixx"],
            "phase_category_map": {
                "RECON": ["api_probe"],
                "ANALYSIS": ["web_tests"],
                "EXPLOIT": [],
                "REPORT": [],
            },
            "phase_extras": {
                "RECON": ["extra_recon"],
                "ANALYSIS": ["extra_analysis"],
                "EXPLOIT": ["extra_exploit"],
                "REPORT": ["extra_report"],
            },
            "callable_core_tools": ["corex"],
            "report_tools": ["reportx"],
        }
        fake_tools = [
            {"function": {"name": "callablex"}},
            {"function": {"name": "dynamic_runner"}},
        ]

        monkeypatch.setattr(learning_mod, "_TOOL_NAME_CACHE", [])
        monkeypatch.setattr(learning_mod, "_PHASE_TOOL_CACHE", {})
        monkeypatch.setattr(learning_mod, "_load_tools_meta", lambda: fake_meta)
        monkeypatch.setattr(learning_mod, "_load_tool_definitions", lambda: fake_tools)

        known = learning_mod._cache_known_tool_names()
        phase_tools = learning_mod._cache_phase_tools()

        assert "scanx" in known
        assert "callablex" in known
        assert "dynamic_runner" in known
        assert "reportx" in known
        assert "prefixx" in known

        assert phase_tools["recon"] == {"scanx", "extra_recon"}
        assert phase_tools["analysis"] == {"auditx", "extra_analysis", "vulnx"}
        assert phase_tools["exploit"] == {"extra_exploit"}
        assert phase_tools["report"] == {"extra_report", "reportx"}

        assert learning_mod._infer_phase_from_tool("reportx") == "report"
        assert learning_mod._infer_phase_from_tool("extra_analysis") == "analysis"
        assert learning_mod._infer_phase_from_tool("callablex") == "recon"

    def test_recommend_strategy_matches_phase_case_insensitively(
        self, isolated_learning_paths
    ):
        learning_mod, _ = isolated_learning_paths
        engine = learning_mod.AdaptiveLearningEngine(session_id="test_strategy_case")
        engine.strategy_patterns.append(
            learning_mod.StrategyPattern(
                pattern_id="pat-1",
                description="Recon nginx first",
                conditions={"phase": "recon", "tech": "nginx"},
                tool_sequence=["http_observe", "ffuf"],
                success_count=3,
                failure_count=0,
            )
        )

        strategy = engine.recommend_strategy({"phase": "RECON", "tech": "NGINX"})

        assert strategy is not None
        assert strategy.pattern_id == "pat-1"

    def test_recommend_tools_honors_legacy_detected_tech_context(
        self, isolated_learning_paths
    ):
        learning_mod, _ = isolated_learning_paths
        engine = learning_mod.AdaptiveLearningEngine(session_id="test_legacy_context")
        perf = learning_mod.ToolPerformance(
            tool_name="sqlmap",
            total_uses=4,
            successes=4,
            failures=0,
            last_used=time.time(),
        )
        perf.context_scores["tech=nginx=detected"] = 0.95
        engine.tool_performances["sqlmap"] = perf

        recs = engine.recommend_tools(phase="ANALYSIS", tech_stack=["Nginx"], top_n=3)

        assert recs
        assert recs[0][0] == "sqlmap"


class TestTargetMemoryStore:
    def test_revisited_target_increments_session_count_and_prompt_text(self, tmp_path):
        from airecon.proxy.agent.adaptive_learning import TargetMemoryStore

        store = TargetMemoryStore(base_dir=tmp_path)
        store.record_endpoint("https://example.com", "/login")
        store.save("https://example.com")

        new_store = TargetMemoryStore(base_dir=tmp_path)
        injection = new_store.get_injection_text("https://example.com")

        assert injection is not None
        assert "from 1 previous session(s) on example.com" in injection

        data = json.loads(new_store._file_path("https://example.com").read_text())
        assert data["session_count"] == 2

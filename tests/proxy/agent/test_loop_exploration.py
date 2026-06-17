"""Tests for Exploration Mixin."""

from __future__ import annotations

from types import SimpleNamespace

import airecon.proxy.agent.loop_exploration as loop_exploration_mod


class TestExplorationMixin:
    def test_module_imports(self):
        from airecon.proxy.agent import loop_exploration
        assert loop_exploration is not None

    def test_untested_vuln_classes_use_ontology_not_tool_names(self):
        from airecon.proxy.agent.loop_exploration import _ExplorationMixin

        class Dummy(_ExplorationMixin):
            def __init__(self):
                self.state = SimpleNamespace(evidence_log=[], skills_used=[], iteration=0)
                self._session = SimpleNamespace(vulnerabilities=[])

            def _load_skills_index(self):
                return {}

            def _get_vuln_terms_from_system_prompt(self):
                return []

        agent = Dummy()
        untested = agent._get_untested_vuln_classes(set())

        assert "protocol_abuse" in untested
        assert "sqlmap" not in untested

    def test_tested_vuln_classes_are_normalized_to_ontology_labels(self):
        from airecon.proxy.agent.loop_exploration import _ExplorationMixin

        class Dummy(_ExplorationMixin):
            def __init__(self):
                self.state = SimpleNamespace(
                    evidence_log=[
                        {"tags": ["xss"], "summary": "Reflected xss in search response"}
                    ],
                    skills_used=[],
                    iteration=0,
                )
                self._session = SimpleNamespace(
                    vulnerabilities=[
                        {
                            "title": "JWT alg:none auth bypass in API",
                            "severity": "HIGH",
                        }
                    ]
                )

            def _load_skills_index(self):
                return {}

            def _get_vuln_terms_from_system_prompt(self):
                return []

        agent = Dummy()
        tested = agent._get_tested_vuln_classes()

        assert "client_side" in tested
        assert "authentication" in tested

    def test_record_adaptive_learning_marks_detected_tech_context(self, monkeypatch):
        from airecon.proxy.agent.loop_exploration import _ExplorationMixin

        class EngineStub:
            def __init__(self):
                self.observation_log = []
                self.tool_result_call = None

            def record_tool_result(self, **kwargs):
                self.tool_result_call = kwargs

            def record_observation(self, **kwargs):
                self.observation_log.append(kwargs)

            def record_strategy_result(self, **kwargs):
                return None

            def save_state(self):
                return None

            def distill_insights(self, **kwargs):
                return []

        class Dummy(_ExplorationMixin):
            def __init__(self):
                self._engine = EngineStub()
                self._session = SimpleNamespace(
                    target="https://example.com",
                    session_id="sess-1",
                    technologies={"Nginx": "detected"},
                    vulnerabilities=[],
                )
                self.state = SimpleNamespace(tool_history=[])

            def _ensure_adaptive_learning_engine(self):
                return self._engine

            def _record_target_memory(self, tool_name, arguments, result, success):
                return None

        monkeypatch.setattr(
            loop_exploration_mod,
            "get_config",
            lambda: SimpleNamespace(
                intelligence_enabled=True,
                intelligence_adaptive_learning_enabled=True,
                openai_base_url="http://127.0.0.1:20128/v1",
                openai_api_key="",
                openai_model="qwen3.5:9b",
            ),
        )

        agent = Dummy()
        agent._record_adaptive_learning(
            tool_name="http_observe",
            arguments={},
            result={"confidence": 0.9},
            success=True,
            duration=0.2,
            phase="ANALYSIS",
        )

        assert agent._engine.tool_result_call is not None
        context = agent._engine.tool_result_call["context"]
        assert context["phase"] == "ANALYSIS"
        assert context["tech=nginx"] == "detected"

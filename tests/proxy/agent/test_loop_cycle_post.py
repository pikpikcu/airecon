"""Tests for loop_cycle_post.py — tool result finalization."""

from __future__ import annotations

from unittest.mock import MagicMock
from types import SimpleNamespace

import pytest


class TestFinalizeToolResults:
    @pytest.fixture
    def agent(self):
        from airecon.proxy.agent.loop_cycle_post import _CyclePostMixin
        from airecon.proxy.agent.pipeline import PipelinePhase

        class DummyAgent(_CyclePostMixin):
            def __init__(self):
                from airecon.proxy.agent.models import AgentState

                self.state = AgentState()
                self._session = MagicMock()
                self._session.target = "example.com"
                self._session.vulnerabilities = []
                self._session.exploit_chains = []
                self._session.hypothesis_queue = []
                self._session.waf_profiles = {}
                self._session.loaded_skills = []
                self._session.technologies = {}
                self._caido_available = False
                self._consecutive_failures = 0
                self._tools_llm = [
                    {"function": {"name": "execute", "description": "run"}},
                ]
                self._loaded_tech_skill_paths = set()
                self._mentor_tool_call_count = 0
                self.pipeline = MagicMock()
                self.pipeline.check_tool_phase_fit.return_value = None

            def _get_current_phase(self):

                return PipelinePhase.RECON

            def _truncate_result(self, result):
                return str(result)[:100]

            def _track_tool_usage(self, tool_name, arguments):
                pass

            def _record_tool_to_memory(self, tool_name, success, duration=0.0, output_size=0):
                pass

            def _smart_format_tool_result(
                self, tool_name, result, success, raw_command
            ):
                return str(result)

            def _build_phase_gate_note(self, tool_name, success):
                return ""

            def _record_evidence_from_result(self, **kwargs):
                pass

            def _update_objectives_from_tool(self, *args):
                pass

            def _update_objectives_from_session(self, phase):
                pass

            def _append_tool_result(self, tool_name, content, success, tc_id):
                pass

            def _check_tool_budget(self, tool_name, phase):
                return ""

            def _refresh_exploration_state(self):
                pass

            def _suggest_alternative_tool(self, tool_name, raw_command):
                return ""

            def _save_recon_exploit_pattern(self, **kwargs):
                pass

            def _record_tested_endpoint(self, tool_name, arguments):
                pass

            def _extract_result_text(self, result):
                return str(result) if result else ""

            def _auto_form_hypotheses(self, phase, tool_name, arguments, result_text):
                pass

        return DummyAgent()

    @pytest.mark.asyncio
    async def test_finalize_yields_tool_end_event(self, agent):
        all_results = {
            0: (
                None,  # idx placeholder
                {"id": "tc1"},  # tc
                "execute",  # tool_name
                {"command": "ls"},  # arguments
                True,  # was_valid
                0.5,  # duration
                {"success": True, "result": "file1.txt"},  # result
                None,  # output_file
                True,  # success
            )
        }

        events = []
        async for event in agent._finalize_tool_results(
            MagicMock(value="RECON"), all_results, False
        ):
            events.append(event)

        tool_end_events = [e for e in events if e.type == "tool_end"]
        assert len(tool_end_events) == 1
        assert tool_end_events[0].data["tool"] == "execute"
        assert tool_end_events[0].data["success"] is True

    @pytest.mark.asyncio
    async def test_finalize_handles_validation_error(self, agent):
        all_results = {
            0: (
                None,
                {"id": "tc2"},
                "execute",
                {"command": ""},
                False,  # was_valid
                0.0,
                {"success": False, "error": "empty command"},
                None,
                False,
            )
        }

        events = []
        async for event in agent._finalize_tool_results(
            MagicMock(value="RECON"), all_results, False
        ):
            events.append(event)

        tool_end_events = [e for e in events if e.type == "tool_end"]
        assert len(tool_end_events) == 1
        assert "VALIDATION ERROR" in tool_end_events[0].data["result_preview"]
        assert agent._consecutive_failures == 1

    @pytest.mark.asyncio
    async def test_finalize_increments_consecutive_failures_on_error(self, agent):
        all_results = {
            0: (
                None,
                {"id": "tc3"},
                "execute",
                {"command": "ls"},
                True,
                0.5,
                {"success": False, "error": "command failed"},
                None,
                False,
            )
        }

        async for _ in agent._finalize_tool_results(
            MagicMock(value="RECON"), all_results, False
        ):
            pass

        assert agent._consecutive_failures == 1

    @pytest.mark.asyncio
    async def test_finalize_resets_consecutive_failures_on_success(self, agent):
        agent._consecutive_failures = 3
        all_results = {
            0: (
                None,
                {"id": "tc4"},
                "execute",
                {"command": "ls"},
                True,
                0.5,
                {"success": True, "result": "ok"},
                None,
                True,
            )
        }

        async for _ in agent._finalize_tool_results(
            MagicMock(value="RECON"), all_results, False
        ):
            pass

        assert agent._consecutive_failures == 0

    @pytest.mark.asyncio
    async def test_finalize_yields_done_on_task_complete(self, agent):
        all_results = {
            0: (
                None,
                {"id": "tc5"},
                "execute",
                {"command": "ls"},
                True,
                0.5,
                {"success": True, "result": "ok"},
                None,
                True,
            )
        }

        events = []
        async for event in agent._finalize_tool_results(
            MagicMock(value="RECON"), all_results, True
        ):
            events.append(event)

        assert any(e.type == "done" for e in events)
        assert agent._iteration_terminated is True

    @pytest.mark.asyncio
    async def test_finalize_tracks_loaded_tech_skill_paths(self, agent, monkeypatch):
        monkeypatch.setattr(
            "airecon.proxy.agent.loop_cycle_post.parse_tool_output",
            lambda *_args, **_kwargs: SimpleNamespace(total_count=1),
        )

        def _fake_update(session, _parsed, _raw):
            session.technologies["wordpress"] = "6.0"

        monkeypatch.setattr(
            "airecon.proxy.agent.loop_cycle_post.update_from_parsed_output",
            _fake_update,
        )
        monkeypatch.setattr(
            "airecon.proxy.agent.loop_cycle_post.auto_load_skills_for_technologies",
            lambda *_args, **_kwargs: (
                "[AUTO-LOADED SKILL: technologies/wordpress.md]\ncontent",
                ["technologies/wordpress.md"],
            ),
        )

        all_results = {
            0: (
                None,
                {"id": "tc6"},
                "execute",
                {"command": "fingerprint"},
                True,
                0.5,
                {"success": True, "stdout": "wp-json", "result": "wp-json"},
                None,
                True,
            )
        }

        async for _ in agent._finalize_tool_results(
            MagicMock(value="RECON"), all_results, False
        ):
            pass

        assert "technologies/wordpress.md" in agent._loaded_tech_skill_paths
        assert "technologies/wordpress.md" in agent._session.loaded_skills

    @pytest.mark.asyncio
    async def test_finalize_includes_caido_status(self, agent):
        agent._caido_available = True
        agent.state.tool_counts["caido_send_request"] = 5
        all_results = {
            0: (
                None,
                {"id": "tc6"},
                "execute",
                {"command": "ls"},
                True,
                0.5,
                {"success": True, "result": "ok"},
                None,
                True,
            )
        }

        events = []
        async for event in agent._finalize_tool_results(
            MagicMock(value="RECON"), all_results, False
        ):
            events.append(event)

        tool_end = [e for e in events if e.type == "tool_end"][0]
        assert tool_end.data["caido"]["active"] is True
        assert tool_end.data["caido"]["findings_count"] == 5

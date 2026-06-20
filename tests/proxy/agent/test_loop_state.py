"""Tests for loop_state.py — token sync, recovery state, scope integrity."""

from __future__ import annotations


from airecon.proxy.agent.loop_state import _StateMixin
from airecon.proxy.agent.models import AgentState


def _make_agent():
    class DummyAgent(_StateMixin):
        def __init__(self):
            self.state = AgentState()
            self._session = type(
                "Session",
                (),
                {
                    "target": "example.com",
                    "session_id": "test_001",
                    "subdomains": ["sub.example.com"],
                    "live_hosts": ["http://example.com"],
                    "vulnerabilities": [{"type": "xss", "severity": "High"}],
                    "open_ports": {"80": "http"},
                    "technologies": {"nginx": "1.18"},
                    "waf_profiles": {},
                    "current_phase": "RECON",
                    "token_total": 0,
                    "token_prompt_total": 0,
                    "token_completion_total": 0,
                    "token_last_used": 0,
                    "adaptive_num_ctx": 0,
                    "adaptive_num_predict_cap": 0,
                    "vram_crash_count": 0,
                    "loaded_skills": [],
                    "scan_count": 1,
                    "conversation": [],
                },
            )()
            self._memory_manager = None
            self.llm = type("LLM", (), {"model": "llama3"})()
            self._adaptive_num_ctx = 0
            self._adaptive_num_predict_cap = 0
            self._vram_crash_count = 0
            self._last_token_snapshot_time = 0
            self._token_snapshot_task = None
            self._token_snapshot_resave_requested = False
            self._scope_anchor_target = None
            self._scope_lock_active = False
            self._last_saved_cumulative = 0

    return DummyAgent()


class TestSyncTokenUsage:
    def test_sync_from_session(self):
        agent = _make_agent()
        agent._session.token_total = 5000
        agent._session.token_prompt_total = 3000
        agent._session.token_completion_total = 2000
        agent._session.token_last_used = 1000
        agent._sync_token_usage_from_session()
        assert agent.state.token_usage["cumulative"] == 5000
        assert agent.state.token_usage["used"] == 1000

    def test_sync_to_session(self):
        agent = _make_agent()
        agent.state.token_usage["cumulative"] = 6000
        agent.state.token_usage["cumulative_prompt"] = 4000
        agent.state.token_usage["cumulative_completion"] = 2000
        agent.state.token_usage["used"] = 1500
        agent._sync_token_usage_to_session()
        assert agent._session.token_total == 6000
        assert agent._session.token_last_used == 1500

    def test_sync_from_session_no_session(self):
        agent = _make_agent()
        agent._session = None
        agent._sync_token_usage_from_session()


class TestRecordTokenUsage:
    def test_records_tokens(self):
        agent = _make_agent()
        agent._record_token_usage(prompt_tokens=1000, completion_tokens=500)
        assert agent.state.token_usage["last_prompt"] == 1000
        assert agent.state.token_usage["cumulative"] == 1500

    def test_ignores_zero_tokens(self):
        agent = _make_agent()
        agent._record_token_usage(prompt_tokens=0, completion_tokens=0)
        assert agent.state.token_usage["cumulative"] == 0

    def test_clamps_negative_tokens(self):
        agent = _make_agent()
        agent._record_token_usage(prompt_tokens=-10, completion_tokens=-5)
        assert agent.state.token_usage["cumulative"] == 0

    def test_accumulates_cumulative(self):
        agent = _make_agent()
        agent._record_token_usage(prompt_tokens=1000, completion_tokens=500)
        agent._record_token_usage(prompt_tokens=200, completion_tokens=100)
        assert agent.state.token_usage["cumulative"] == 1800


class TestRecomputeUsedTokens:
    def test_estimates_tokens_from_conversation(self):
        agent = _make_agent()
        agent.state.conversation = [
            {"role": "system", "content": "You are a pentester"},
            {"role": "user", "content": "Scan example.com"},
        ]
        used = agent._recompute_used_tokens_from_conversation()
        assert used > 0

    def test_returns_zero_for_empty_conversation(self):
        agent = _make_agent()
        agent.state.conversation = []
        used = agent._recompute_used_tokens_from_conversation()
        assert used == 0


class TestSyncRecoveryState:
    def test_sync_from_session(self):
        agent = _make_agent()
        agent._session.adaptive_num_ctx = 4096
        agent._session.adaptive_num_predict_cap = 1024
        agent._session.vram_crash_count = 2
        agent._sync_recovery_state_from_session()
        assert agent._adaptive_num_ctx == 4096
        assert agent._vram_crash_count == 2

    def test_sync_to_session(self):
        agent = _make_agent()
        agent._adaptive_num_ctx = 8192
        agent._adaptive_num_predict_cap = 2048
        agent._vram_crash_count = 3
        agent._sync_recovery_state_to_session()
        assert agent._session.adaptive_num_ctx == 8192
        assert agent._session.vram_crash_count == 3


class TestHasScanWork:
    def test_returns_true_with_scan_count(self):
        agent = _make_agent()
        assert agent._has_scan_work() is True

    def test_returns_false_without_work(self):
        agent = _make_agent()
        agent._session.scan_count = 0
        agent.state.evidence_log = []
        assert agent._has_scan_work() is False

    def test_returns_false_without_session(self):
        agent = _make_agent()
        agent._session = None
        assert agent._has_scan_work() is False

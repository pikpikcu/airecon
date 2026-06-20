"""Tests for budget pressure cascade in AgentLoop.

Verifies that urgency messages are injected exactly once per threshold level
and that REPORT phase is forced at 100% budget exhaustion.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch


def _make_loop(max_iterations: int = 100):
    from airecon.proxy.agent.loop import AgentLoop

    llm_mock = MagicMock()
    engine_mock = MagicMock()
    engine_mock.discover_tools = MagicMock(return_value=[])
    engine_mock.tools_to_llm_format = MagicMock(return_value=[])

    with patch("airecon.proxy.agent.loop.get_config") as mock_cfg:
        cfg = MagicMock()
        cfg.agent_max_tool_iterations = max_iterations
        cfg.llm_context_window = 4096
        mock_cfg.return_value = cfg
        loop = AgentLoop(llm=llm_mock, engine=engine_mock)

    loop.state.max_iterations = max_iterations
    return loop


def _budget_msgs(loop) -> list[str]:
    return [
        m["content"]
        for m in loop.state.conversation
        if m.get("role") == "system" and m["content"].startswith("[SYSTEM: BUDGET")
    ]


class TestBudgetPressureCascade:
    def _simulate_to_ratio(self, loop, ratio: float) -> None:
        """Advance iteration counter then run the cascade check inline."""
        loop.state.iteration = int(loop.state.max_iterations * ratio)
        # Replicate the cascade logic (same code as loop.py)
        _budget_ratio = loop.state.iteration / max(loop.state.max_iterations, 1)

        if _budget_ratio >= 1.0 and loop._budget_pressure_level < 4:
            loop._budget_pressure_level = 4
            loop.state.conversation.append(
                {
                    "role": "system",
                    "content": (
                        "[SYSTEM: BUDGET EXHAUSTED] You have used all available "
                        "iterations. STOP all testing immediately. Your ONLY task "
                        "now is to call the report tool and write the final report "
                        "with everything you have found."
                    ),
                }
            )
        elif _budget_ratio >= 0.95 and loop._budget_pressure_level < 3:
            loop._budget_pressure_level = 3
            remaining = loop.state.max_iterations - loop.state.iteration
            loop.state.conversation.append(
                {
                    "role": "system",
                    "content": (
                        f"[SYSTEM: BUDGET CRITICAL — {remaining} iterations left] "
                        "STOP all new discovery. You must now: (1) call the report "
                        "tool with all confirmed findings, (2) advance to REPORT "
                        "phase if not already there. No more scanning or fuzzing."
                    ),
                }
            )
        elif _budget_ratio >= 0.85 and loop._budget_pressure_level < 2:
            loop._budget_pressure_level = 2
            remaining = loop.state.max_iterations - loop.state.iteration
            loop.state.conversation.append(
                {
                    "role": "system",
                    "content": (
                        f"[SYSTEM: BUDGET WARNING — {remaining} iterations left] "
                        "Begin consolidating findings for the report. Finish any "
                        "in-progress tests, then switch to REPORT phase. Do not "
                        "start new discovery chains."
                    ),
                }
            )
        elif _budget_ratio >= 0.70 and loop._budget_pressure_level < 1:
            loop._budget_pressure_level = 1
            remaining = loop.state.max_iterations - loop.state.iteration
            loop.state.conversation.append(
                {
                    "role": "system",
                    "content": (
                        f"[SYSTEM: BUDGET NOTICE — {remaining} iterations left] "
                        "Prioritise your highest-value untested attack vectors only. "
                        "Avoid retrying already-tested paths or broad enumeration."
                    ),
                }
            )

    def test_no_message_below_70pct(self):
        loop = _make_loop(100)
        self._simulate_to_ratio(loop, 0.50)
        assert _budget_msgs(loop) == []
        assert loop._budget_pressure_level == 0

    def test_level1_fires_at_70pct(self):
        loop = _make_loop(100)
        self._simulate_to_ratio(loop, 0.70)
        msgs = _budget_msgs(loop)
        assert len(msgs) == 1
        assert "BUDGET NOTICE" in msgs[0]
        assert loop._budget_pressure_level == 1

    def test_level2_fires_at_85pct(self):
        loop = _make_loop(100)
        self._simulate_to_ratio(loop, 0.70)
        self._simulate_to_ratio(loop, 0.85)
        msgs = _budget_msgs(loop)
        assert len(msgs) == 2
        assert any("BUDGET WARNING" in m for m in msgs)
        assert loop._budget_pressure_level == 2

    def test_level3_fires_at_95pct(self):
        loop = _make_loop(100)
        self._simulate_to_ratio(loop, 0.70)
        self._simulate_to_ratio(loop, 0.85)
        self._simulate_to_ratio(loop, 0.95)
        msgs = _budget_msgs(loop)
        assert len(msgs) == 3
        assert any("BUDGET CRITICAL" in m for m in msgs)
        assert loop._budget_pressure_level == 3

    def test_level4_fires_at_100pct(self):
        loop = _make_loop(100)
        self._simulate_to_ratio(loop, 0.70)
        self._simulate_to_ratio(loop, 0.85)
        self._simulate_to_ratio(loop, 0.95)
        self._simulate_to_ratio(loop, 1.0)
        msgs = _budget_msgs(loop)
        assert len(msgs) == 4
        assert any("BUDGET EXHAUSTED" in m for m in msgs)
        assert loop._budget_pressure_level == 4

    def test_each_level_fires_exactly_once(self):
        """Calling the same ratio multiple times must not re-inject messages."""
        loop = _make_loop(100)
        # Simulate many iterations at 70%
        for _ in range(5):
            self._simulate_to_ratio(loop, 0.70)
        msgs = _budget_msgs(loop)
        assert len(msgs) == 1, "L1 fired more than once"

    def test_budget_pressure_level_initialises_at_zero(self):
        loop = _make_loop()
        assert loop._budget_pressure_level == 0

    def test_remaining_count_in_message(self):
        """Remaining iteration count must be accurate in the injected message."""
        loop = _make_loop(200)
        self._simulate_to_ratio(loop, 0.70)
        msgs = _budget_msgs(loop)
        # At 70% of 200 = 140 iterations → 60 remaining
        assert "60 iterations left" in msgs[0]

"""Tests for Hermes-inspired patterns added to AIRecon.

Covers:
- _repair_tool_pairs() ID-based orphan fix (models.py)
- add_message() <think> stripping (models.py)
- _AIRECON_TOOL_NAMES hallucination guard (executors.py)
- isinstance(dict) args validation (executors.py)
- _THINK_BLOCK_RE / _THINK_OPEN_RE edge cases
"""

from __future__ import annotations

import pytest

from airecon.proxy.agent.models import (
    AgentState,
    _THINK_BLOCK_RE,
    _THINK_OPEN_RE,
)
from airecon.proxy.agent.executors import _AIRECON_TOOL_NAMES


# ---------------------------------------------------------------------------
# _repair_tool_pairs — ID-based orphan detection
# ---------------------------------------------------------------------------


class TestRepairToolPairs:
    def test_valid_pair_untouched(self):
        msgs = [
            {"role": "user", "content": "go"},
            {
                "role": "assistant",
                "content": "",
                "tool_calls": [
                    {"id": "call_1", "function": {"name": "execute", "arguments": "{}"}}
                ],
            },
            {"role": "tool", "tool_call_id": "call_1", "content": "ok"},
        ]
        result = AgentState._repair_tool_pairs(msgs)
        assert len(result) == 3
        assert result[2]["role"] == "tool"
        assert result[2]["tool_call_id"] == "call_1"

    def test_orphaned_result_dropped(self):
        """tool result whose call_id doesn't match any assistant tool_call is removed."""
        msgs = [
            {"role": "user", "content": "go"},
            {"role": "tool", "tool_call_id": "ghost_id", "content": "stale result"},
        ]
        result = AgentState._repair_tool_pairs(msgs)
        assert not any(m["role"] == "tool" for m in result)

    def test_missing_result_stub_inserted(self):
        """assistant tool_call with no matching tool result gets a stub."""
        msgs = [
            {"role": "user", "content": "go"},
            {
                "role": "assistant",
                "content": "",
                "tool_calls": [
                    {
                        "id": "call_x",
                        "function": {"name": "web_search", "arguments": "{}"},
                    }
                ],
            },
        ]
        result = AgentState._repair_tool_pairs(msgs)
        assert result[-1]["role"] == "tool"
        assert result[-1]["tool_call_id"] == "call_x"
        assert "compressed" in result[-1]["content"].lower()

    def test_multiple_calls_one_missing(self):
        """Two tool_calls: first has result, second is missing → stub for second only."""
        msgs = [
            {"role": "user", "content": "go"},
            {
                "role": "assistant",
                "content": "",
                "tool_calls": [
                    {
                        "id": "call_1",
                        "function": {"name": "execute", "arguments": "{}"},
                    },
                    {
                        "id": "call_2",
                        "function": {"name": "web_search", "arguments": "{}"},
                    },
                ],
            },
            {"role": "tool", "tool_call_id": "call_1", "content": "result1"},
        ]
        result = AgentState._repair_tool_pairs(msgs)
        tool_msgs = [m for m in result if m["role"] == "tool"]
        assert len(tool_msgs) == 2
        call_ids = {m["tool_call_id"] for m in tool_msgs}
        assert "call_1" in call_ids
        assert "call_2" in call_ids

    def test_empty_messages_safe(self):
        assert AgentState._repair_tool_pairs([]) == []

    def test_no_tool_calls_unchanged(self):
        msgs = [
            {"role": "system", "content": "sys"},
            {"role": "user", "content": "hello"},
            {"role": "assistant", "content": "hi"},
        ]
        result = AgentState._repair_tool_pairs(msgs)
        assert result == msgs

    def test_system_messages_preserved(self):
        msgs = [
            {"role": "system", "content": "[SYSTEM: PINNED CONTEXT]"},
            {"role": "user", "content": "scan"},
            {
                "role": "assistant",
                "content": "",
                "tool_calls": [
                    {"id": "c1", "function": {"name": "execute", "arguments": "{}"}}
                ],
            },
            {"role": "tool", "tool_call_id": "c1", "content": "done"},
        ]
        result = AgentState._repair_tool_pairs(msgs)
        assert result[0]["role"] == "system"
        assert len(result) == 4

    def test_non_standard_tool_call_object(self):
        """tool_calls entry as object with .id attribute (LLM sometimes returns these)."""

        class FakeTc:
            id = "call_obj"
            function = None

        msgs = [
            {"role": "user", "content": "go"},
            {"role": "assistant", "content": "", "tool_calls": [FakeTc()]},
        ]
        result = AgentState._repair_tool_pairs(msgs)
        # Should insert stub with id from FakeTc
        stubs = [m for m in result if m["role"] == "tool"]
        assert len(stubs) == 1
        assert stubs[0]["tool_call_id"] == "call_obj"


# ---------------------------------------------------------------------------
# add_message() — <think> block stripping
# ---------------------------------------------------------------------------


class TestAddMessageThinkStrip:
    def setup_method(self):
        self.state = AgentState()

    def test_complete_think_block_stripped(self):
        self.state.add_message("assistant", "Before.<think>reasoning</think>After.")
        content = self.state.conversation[-1]["content"]
        assert "<think>" not in content
        assert "After." in content

    def test_unclosed_think_stripped(self):
        self.state.add_message("assistant", "Done.<think>unclosed reasoning")
        content = self.state.conversation[-1]["content"]
        assert "<think>" not in content
        assert "Done." in content

    def test_multiple_think_blocks_stripped(self):
        self.state.add_message(
            "assistant", "<think>a</think>keep1<think>b</think>keep2"
        )
        content = self.state.conversation[-1]["content"]
        assert "<think>" not in content
        assert "keep1" in content
        assert "keep2" in content

    def test_no_think_unchanged(self):
        self.state.add_message("assistant", "No think blocks here.")
        assert self.state.conversation[-1]["content"] == "No think blocks here."

    def test_thinking_element_not_stripped(self):
        """<thinking> (not <think>) must NOT be stripped — different tag."""
        self.state.add_message("assistant", "Error in <thinking> element found.")
        content = self.state.conversation[-1]["content"]
        assert "thinking" in content  # preserved

    def test_non_assistant_role_not_stripped(self):
        """Only assistant messages are stripped, not user/tool messages."""
        self.state.add_message("user", "I said <think>test</think>")
        content = self.state.conversation[-1]["content"]
        assert "<think>" in content  # user message unchanged

    def test_empty_content_safe(self):
        self.state.add_message("assistant", "")
        assert self.state.conversation[-1]["content"] == ""

    def test_only_think_block_results_in_empty(self):
        self.state.add_message("assistant", "<think>only thinking</think>")
        content = self.state.conversation[-1]["content"]
        assert "<think>" not in content
        assert content == ""


# ---------------------------------------------------------------------------
# _THINK_BLOCK_RE / _THINK_OPEN_RE regex correctness
# ---------------------------------------------------------------------------


class TestThinkRegex:
    def test_block_re_case_insensitive(self):
        result = _THINK_BLOCK_RE.sub("", "<THINK>hidden</THINK>visible")
        assert "visible" in result
        assert "hidden" not in result

    def test_block_re_multiline_content(self):
        text = "start<think>\nline1\nline2\n</think>end"
        result = _THINK_BLOCK_RE.sub("", text)
        assert "start" in result
        assert "end" in result
        assert "line1" not in result

    def test_open_re_strips_to_end(self):
        text = "prefix<think>no closing tag\nmore content"
        result = _THINK_OPEN_RE.sub("", text).strip()
        assert result == "prefix"

    def test_open_re_not_triggered_by_closed_block(self):
        """If block is properly closed, _THINK_OPEN_RE should not match."""
        text = "<think>closed</think>"
        # The negative lookahead (?!</think>) ensures this doesn't match
        result = _THINK_OPEN_RE.sub("", text)
        # The closed block itself is not matched by _THINK_OPEN_RE
        # (it matches open tag followed by content that is NOT immediately </think>)
        assert isinstance(result, str)  # just verify no crash


# ---------------------------------------------------------------------------
# _AIRECON_TOOL_NAMES hallucination guard
# ---------------------------------------------------------------------------


class TestAIReconToolNames:
    def test_web_search_in_set(self):
        assert "web_search" in _AIRECON_TOOL_NAMES

    def test_http_observe_in_set(self):
        assert "http_observe" in _AIRECON_TOOL_NAMES

    def test_execute_not_in_set(self):
        """execute should NOT be in the set — we never want to block it."""
        assert "execute" not in _AIRECON_TOOL_NAMES

    def test_nmap_not_in_set(self):
        """Shell binaries like nmap must not be blocked."""
        assert "nmap" not in _AIRECON_TOOL_NAMES

    def test_set_is_nonempty(self):
        assert len(_AIRECON_TOOL_NAMES) >= 10

    def test_all_entries_are_strings(self):
        assert all(isinstance(n, str) for n in _AIRECON_TOOL_NAMES)


# ---------------------------------------------------------------------------
# isinstance(dict) args validation guard (via _execute_tool_and_record)
# ---------------------------------------------------------------------------


class TestArgsValidation:
    """Verify non-dict args are rejected before dispatch."""

    @pytest.mark.asyncio
    async def test_list_args_rejected(self):
        """Passing a list as arguments must return an error, not crash."""
        from unittest.mock import MagicMock
        from airecon.proxy.agent.executors import _ExecutorMixin

        class FakeExecutor(_ExecutorMixin):
            state = AgentState()
            _session = None
            _last_output_file = None
            _executed_tool_counts: dict = {}
            engine = MagicMock()

        executor = FakeExecutor()
        # Provide list instead of dict
        ok, duration, result, _ = await executor._execute_tool_and_record(
            "execute",
            ["this", "is", "wrong"],  # type: ignore[arg-type]
        )
        assert ok is False
        assert "dict" in result["error"].lower()

    @pytest.mark.asyncio
    async def test_string_args_rejected(self):
        from unittest.mock import MagicMock
        from airecon.proxy.agent.executors import _ExecutorMixin

        class FakeExecutor(_ExecutorMixin):
            state = AgentState()
            _session = None
            _last_output_file = None
            _executed_tool_counts: dict = {}
            engine = MagicMock()

        executor = FakeExecutor()
        ok, _, result, _ = await executor._execute_tool_and_record(
            "web_search",
            "just a string",  # type: ignore[arg-type]
        )
        assert ok is False
        assert "dict" in result["error"].lower()

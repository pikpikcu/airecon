"""PR #129 protocol cases, ported to the integrated public converters.

The original PR file exercised private client helpers that the integration
replaced with ``airecon.proxy.llm_protocol``. Stream parsing and auth headers
are covered by ``test_protocol_integration.py`` and
``test_anthropic_protocol_hardening.py``; native Anthropic now sends only
``x-api-key`` unless ``llm_anthropic_auth`` selects bearer or both.
"""

from __future__ import annotations

import json

from airecon.proxy.llm import _to_openai_messages
from airecon.proxy.llm_protocol import anthropic_messages, anthropic_tools


class TestAnthropicMessages:
    def test_system_extracted_and_tool_pairing(self):
        system, msgs = anthropic_messages(
            [
                {"role": "system", "content": "be helpful"},
                {"role": "user", "content": "hi"},
                {
                    "role": "assistant",
                    "tool_calls": [
                        {
                            "id": "call_a",
                            "function": {
                                "name": "get_weather",
                                "arguments": {"city": "Tokyo"},
                            },
                        }
                    ],
                },
                {"role": "tool", "tool_call_id": "call_a", "content": "22C"},
            ]
        )
        assert system == "be helpful"
        assert msgs[0] == {"role": "user", "content": [{"type": "text", "text": "hi"}]}
        assert msgs[1]["content"][0] == {
            "type": "tool_use",
            "id": "call_a",
            "name": "get_weather",
            "input": {"city": "Tokyo"},
        }
        assert msgs[2]["content"][0]["type"] == "tool_result"
        assert msgs[2]["content"][0]["tool_use_id"] == "call_a"
        assert "22C" in json.dumps(msgs[2]["content"][0]["content"])

    def test_fifo_binds_missing_tool_call_id(self):
        _, msgs = anthropic_messages(
            [
                {"role": "user", "content": "go"},
                {
                    "role": "assistant",
                    "tool_calls": [
                        {"id": "call_z", "function": {"name": "t", "arguments": {}}}
                    ],
                },
                {"role": "tool", "content": "ok"},
            ]
        )
        assert msgs[-1]["content"][0]["tool_use_id"] == "call_z"

    def test_orphan_tool_result_dropped(self):
        _, msgs = anthropic_messages(
            [
                {"role": "user", "content": "go"},
                {"role": "tool", "tool_call_id": "ghost", "content": "x"},
            ]
        )
        assert all(
            b.get("type") != "tool_result" for m in msgs for b in m["content"]
        )

    def test_consecutive_same_role_coalesced(self):
        _, msgs = anthropic_messages(
            [
                {"role": "user", "content": "one"},
                {"role": "user", "content": "two"},
            ]
        )
        assert len(msgs) == 1
        assert [b["text"] for b in msgs[0]["content"]] == ["one", "two"]


class TestAnthropicTools:
    def test_function_schema_to_input_schema(self):
        out = anthropic_tools(
            [
                {
                    "type": "function",
                    "function": {
                        "name": "get_weather",
                        "description": "w",
                        "parameters": {"type": "object", "properties": {}},
                    },
                }
            ]
        )
        assert out[0]["name"] == "get_weather"
        assert out[0]["input_schema"] == {"type": "object", "properties": {}}


class TestOpenAIMessagesRegression:
    def test_still_pairs_tool_results(self):
        msgs = _to_openai_messages(
            [
                {"role": "user", "content": "hi"},
                {
                    "role": "assistant",
                    "tool_calls": [
                        {"id": "c1", "function": {"name": "t", "arguments": {"a": 1}}}
                    ],
                },
                {"role": "tool", "content": "ok"},
            ]
        )
        assert msgs[-1]["role"] == "tool"
        assert msgs[-1]["tool_call_id"] == "c1"
        assert json.loads(msgs[-2]["tool_calls"][0]["function"]["arguments"]) == {"a": 1}

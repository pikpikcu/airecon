from __future__ import annotations

import copy
import json
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from airecon.proxy.config import DEFAULT_CONFIG
from airecon.proxy.context_budget import (
    CORE_TOOL_NAMES,
    ContextBudgetError,
    fit_tools_to_budget,
    pack_history,
    request_chars,
)


@pytest.fixture
def agent(monkeypatch, tmp_path):
    from airecon.proxy.agent.loop import AgentLoop

    cfg = SimpleNamespace(**DEFAULT_CONFIG)
    for module in ("loop", "loop_context", "models"):
        monkeypatch.setattr(f"airecon.proxy.agent.{module}.get_config", lambda: cfg)
    monkeypatch.setattr("airecon.proxy.config._workspace_root_cache", tmp_path)
    loop = AgentLoop(llm=MagicMock(), engine=MagicMock())
    loop.state.active_target = "fixture.test"
    loop.state.conversation = [
        {"role": "system", "content": "Only authorized fixture scope."},
        {"role": "user", "content": "Read the local fixture exactly."},
    ]
    return loop


def _num_ctx_for_budget(budget: int, num_predict: int = 1024) -> int:
    return (budget + num_predict + 256 + 2) // 3 + num_predict + 256


def _core_tools(conversation, tools):
    return fit_tools_to_budget(conversation, tools, 1)


def _group(call_id: str, path: str, content: str) -> list[dict]:
    return [
        {"role": "assistant", "content": "", "tool_calls": [{
            "id": call_id, "function": {"name": "read_file", "arguments": {"path": path}},
        }]},
        {"role": "tool", "name": "read_file", "tool_call_id": call_id, "content": content},
    ]


@pytest.mark.asyncio
async def test_second_budget_pass_keeps_latest_read_group_and_single_notice(agent):
    from airecon.proxy.agent.tool_defs import get_tool_definitions

    agent._tools_llm = get_tool_definitions()
    old_page = "older evidence page " * 400
    latest_page = "latest evidence page " * 400
    agent.state.conversation.extend(
        _group("read_0", "fixture.txt", old_page)
        + _group("read_1", "fixture.txt", latest_page)
    )
    core = _core_tools(agent.state.conversation, agent._tools_llm)
    mandatory = agent.state.conversation[:2]
    budget = (
        request_chars(mandatory, core)
        + request_chars(_group("read_1", "fixture.txt", latest_page), [])
        + 1600
    )

    await agent._enforce_char_budget(_num_ctx_for_budget(budget), 1024)

    assert not any(m.get("content") == old_page for m in agent.state.conversation)
    assert any(m.get("content") == latest_page for m in agent.state.conversation)
    snapshot = json.dumps(agent.state.conversation, sort_keys=True, default=str)
    tools_after_first = json.dumps(agent._tools_budgeted, sort_keys=True, default=str)
    notices_after_first = sum(
        "[Older tool groups archived" in str(m.get("content", ""))
        for m in agent.state.conversation
    )
    assert notices_after_first == 1

    await agent._enforce_char_budget(_num_ctx_for_budget(budget), 1024)

    contents = [m.get("content") for m in agent.state.conversation]
    notices = sum("[Older tool groups archived" in str(c) for c in contents if c)
    assert notices == 1, "second pass must not stack archive notices"
    assert latest_page in contents, "the exact latest read page must survive the second pass"
    latest_call = [
        m for m in agent.state.conversation
        if m.get("role") == "assistant"
        and any(tc.get("id") == "read_1" for tc in m.get("tool_calls", []))
    ]
    assert latest_call, "the latest assistant tool-call turn must survive the second pass"
    assert json.dumps(agent.state.conversation, sort_keys=True, default=str) == snapshot, (
        "second pass on an already-packed conversation must be a no-op"
    )
    assert json.dumps(agent._tools_budgeted, sort_keys=True, default=str) == tools_after_first


@pytest.mark.asyncio
async def test_user_role_read_pages_evict_whole_groups(agent):
    from airecon.proxy.agent import loop_context
    from airecon.proxy.agent.tool_defs import get_tool_definitions

    loop_context.get_config().tool_response_role = "user"
    agent._tools_llm = get_tool_definitions()
    pages = [f"user-role evidence page {i} " * 240 for i in range(3)]
    for i, page in enumerate(pages):
        agent.state.conversation.append({
            "role": "assistant", "content": "", "tool_calls": [{
                "id": f"read_{i}", "function": {"name": "read_file", "arguments": {"path": "fixture.txt"}},
            }],
        })
        agent._append_tool_result("read_file", page, True, f"read_{i}")

    core = _core_tools(agent.state.conversation, agent._tools_llm)
    mandatory = agent.state.conversation[:2]
    latest_group = agent.state.conversation[-2:]
    budget = request_chars(mandatory, core) + request_chars(latest_group, []) + 600

    await agent._enforce_char_budget(_num_ctx_for_budget(budget), 1024)

    contents = [str(m.get("content", "")) for m in agent.state.conversation]
    joined = "\n".join(contents)
    assert pages[2] in joined, "the latest page must stay intact"
    assert pages[0] not in joined, "older pages must be evicted with their group"
    assert pages[1] not in joined, "older pages must be evicted with their group"


@pytest.mark.asyncio
async def test_evicted_archive_is_pageable_by_read_file(agent):
    from airecon.proxy import filesystem
    from airecon.proxy.context_budget import ArtifactCompressor

    marker = "EVIDENCE-MARKER-7f3a"
    old_page = f"{marker} older archive page body " * 220
    latest_page = "latest short page"
    conversation = [
        {"role": "system", "content": "Only authorized fixture scope."},
        {"role": "user", "content": "Read the local fixture exactly."},
        *_group("read_0", "fixture.txt", old_page),
        *_group("read_1", "fixture.txt", latest_page),
    ]
    compressor = ArtifactCompressor(agent._get_artifact_compressor().root, "session")
    budget = (
        request_chars(conversation[:2], [])
        + request_chars(_group("read_1", "fixture.txt", latest_page), [])
        + 400
    )
    packed = pack_history(conversation, None, budget, compressor)
    assert any("[Older tool groups archived" in str(m.get("content", "")) for m in packed)
    assert not any(m.get("content") == old_page for m in packed)

    archives = sorted((compressor.root / compressor.directory).glob("*.txt"))
    assert archives, "the evicted group must be archived on disk"
    result = filesystem.read_file(str(archives[0]), 0, 100)

    assert result["success"], result
    assert "LINE TOO LARGE" not in str(result.get("result", "")), (
        "archives must be line-oriented so read_file can page them"
    )
    assert marker in str(result.get("result", ""))


NOTICE = "[Older tool groups archived"


def test_archive_notice_adds_no_synthetic_assistant_turn(agent):
    from airecon.proxy.context_budget import ArtifactCompressor
    from airecon.proxy.llm import _to_openai_messages
    from airecon.proxy.llm_protocol import anthropic_messages

    latest = {
        "role": "assistant", "content": "", "reasoning_content": "Fixture plan.",
        "tool_calls": [{"id": "read_1", "function": {"name": "read_file",
                                                     "arguments": {"path": "fixture.txt"}}}],
        "_provider_blocks": [
            {"type": "thinking", "thinking": "Fixture plan.", "signature": "fixture-signature"},
            {"type": "tool_use", "id": "read_1", "name": "read_file",
             "input": {"path": "fixture.txt"}},
        ],
    }
    old = _group("read_0", "fixture.txt", "older evidence page " * 400)
    old[0]["reasoning_content"] = "Older fixture plan."
    conversation = [
        {"role": "system", "content": "Only authorized fixture scope."},
        {"role": "user", "content": "Read the local fixture exactly."},
        *old,
        latest,
        {"role": "tool", "name": "read_file", "tool_call_id": "read_1", "content": "latest page"},
    ]
    compressor = ArtifactCompressor(agent._get_artifact_compressor().root, "session")
    budget = request_chars(conversation[:2] + conversation[-2:], []) + 600
    packed = pack_history(conversation, None, budget, compressor)

    notices = [m for m in packed if NOTICE in str(m.get("content", ""))]
    assert len(notices) == 1 and notices[0]["role"] != "assistant"
    assert [m for m in packed if m.get("role") == "assistant"] == [latest]

    wire = _to_openai_messages(packed, replay_reasoning=True)
    assert wire[0]["role"] == "system" and NOTICE in wire[0]["content"]
    assert all("reasoning_content" in m for m in wire if m["role"] == "assistant")
    assert wire[-1]["role"] == "tool"

    system, converted = anthropic_messages(packed)
    assert NOTICE in system
    assistant_turns = [m for m in converted if m["role"] == "assistant"]
    assert len(assistant_turns) == 1
    assert assistant_turns[0]["content"][0]["type"] == "thinking"


def _decode_archive(text: str) -> list[dict]:
    lines = text.split("\n")
    assert lines[0].startswith("[Archived tool group"), lines[0]
    logical: list[list[str]] = []
    for line in lines[1:]:
        tag, body = line[:2], line[2:]
        if tag == "\u00bb ":
            logical[-1][1] += body
        else:
            assert tag in ("@ ", "| "), line[:40]
            logical.append([tag, body])
    messages: list[dict] = []
    for tag, body in logical:
        if tag == "@ ":
            messages.append({"meta": json.loads(body), "lines": []})
        else:
            messages[-1]["lines"].append(body)
    out = []
    for item in messages:
        message = dict(item["meta"])
        if item["lines"]:
            message["content"] = "\n".join(item["lines"])
        out.append(message)
    return out


def test_archive_round_trips_exactly_and_every_line_is_pageable(agent):
    from airecon.proxy import filesystem
    from airecon.proxy.context_budget import ArtifactCompressor

    tricky = "\n".join([
        "\u00bb leading continuation marker in the original",
        "\u00bb\u00bb doubled marker",
        "| leading pipe", "@ leading at", "",
        "\x1b[31mred\x1b[0m " * 700,
        'quote " and backslash \\ ' * 300,
        "carriage\rreturn kept",
        "multibyte \u00e9\u4e2d\U0001f600 " * 500,
        "tail line \u00bb",
    ])
    old = _group("read_0", "fixture.txt", tricky)
    old[0]["tool_calls"][0]["function"]["arguments"] = {"path": "x" * 9000}
    conversation = [
        {"role": "system", "content": "Only authorized fixture scope."},
        {"role": "user", "content": "Read the local fixture exactly."},
        *old,
        *_group("read_1", "fixture.txt", "latest short page"),
    ]
    compressor = ArtifactCompressor(agent._get_artifact_compressor().root, "session")
    budget = request_chars(conversation[:2] + conversation[-2:], []) + 600
    pack_history(conversation, None, budget, compressor)

    archives = sorted((compressor.root / compressor.directory).glob("*.txt"))
    assert len(archives) == 1
    text = archives[0].read_bytes().decode("utf-8")
    assert _decode_archive(text) == old

    per_line = filesystem._READ_CONTENT_WIRE_BYTES // 2
    assert all(filesystem._wire_bytes(line + "\n") <= per_line for line in text.split("\n"))
    offset = 0
    while True:
        page = filesystem.read_file(str(archives[0]), offset=offset, limit=500)
        assert page["success"] and not page.get("line_too_large"), page
        if not page.get("has_more"):
            break
        offset = page["next_offset"]


def test_assistant_role_notice_from_saved_sessions_is_normalized(agent):
    from airecon.proxy.context_budget import ArtifactCompressor, _minimum_request_messages

    legacy = {"role": "assistant", "content": (
        "[Older tool groups archived under output/context/0123456789abcdef/; "
        "use list_files/read_file for exact evidence.]")}
    latest = _group("read_1", "fixture.txt", "latest exact page " * 50)
    conversation = [
        {"role": "system", "content": "Only authorized fixture scope."},
        {"role": "user", "content": "Read the local fixture exactly."},
        *latest,
        legacy,
    ]

    assert latest[1] in _minimum_request_messages(conversation)

    compressor = ArtifactCompressor(agent._get_artifact_compressor().root, "session")
    packed = pack_history(conversation, None, 10**6, compressor)
    assert [m for m in packed if m.get("role") == "assistant"] == [latest[0]]
    notices = [m for m in packed if NOTICE in str(m.get("content", ""))]
    assert len(notices) == 1 and notices[0]["role"] == "system" and notices[0]["_archive_notice"]
    assert notices[0]["content"] == legacy["content"]
    assert packed == pack_history(packed, None, 10**6, compressor)


def _signed_group(call_id: str, content: str) -> list[dict]:
    group = _group(call_id, "fixture.txt", content)
    group[0]["_provider_blocks"] = [
        {"type": "thinking", "thinking": f"Fixture plan {call_id}.",
         "signature": f"fixture-signature-{call_id}-" + "s" * 300},
        {"type": "tool_use", "id": call_id, "name": "read_file",
         "input": {"path": "fixture.txt"}},
    ]
    group[0]["_protected"] = True
    return group


@pytest.mark.asyncio
async def test_older_signed_groups_are_archived_verbatim_and_latest_stays_exact(
    agent, monkeypatch,
):
    from airecon.proxy.agent import loop_context
    from airecon.proxy.agent.tool_defs import get_tool_definitions
    from airecon.proxy.llm_protocol import anthropic_messages

    cfg = loop_context.get_config()
    cfg.llm_provider = "anthropic"
    monkeypatch.setattr("airecon.proxy.config.get_config", lambda: cfg)
    agent._tools_llm = get_tool_definitions()
    older = [_signed_group(f"read_{i}", f"older signed page {i} " * 100) for i in range(6)]
    report = {"role": "system", "content": "REPORT evidence: fixture finding.", "_protected": True}
    pinned = _group("pinned_0", "fixture.txt", "pinned evidence page " * 20)
    for message in pinned:
        message["_protected"] = True
    latest = _signed_group("read_latest", "latest signed page " * 100)
    agent.state.conversation.extend(
        pinned + [message for group in older for message in group] + [report] + latest
    )
    kept = copy.deepcopy(agent.state.conversation[:2] + pinned + [report] + latest)
    core = _core_tools(agent.state.conversation, agent._tools_llm)
    budget = request_chars(kept, core) + 400
    agent._context_char_budget = budget

    await agent._enforce_char_budget(65536, 1024)

    conversation = agent.state.conversation
    assert request_chars(conversation, agent._tools_budgeted) <= budget
    assert [m for m in conversation if not m.get("_archive_notice")] == kept
    _system, converted = anthropic_messages(conversation)
    assert [m["content"] for m in converted if m["role"] == "assistant"][-1] == (
        latest[0]["_provider_blocks"]
    )
    compressor = agent._get_artifact_compressor()
    archived = [
        _decode_archive(path.read_bytes().decode("utf-8"))
        for path in (compressor.root / compressor.directory).glob("*.txt")
    ]
    for group in older:
        assert group in archived, "an evicted signed group must be archived verbatim"


def _append_execute_group(agent, role: str, output: str) -> None:
    from airecon.proxy.agent import loop_context

    loop_context.get_config().tool_response_role = role
    agent.state.conversation.append({
        "role": "assistant", "content": "", "tool_calls": [{
            "id": "exec_1", "function": {"name": "execute", "arguments": {"command": "echo fixture"}},
        }],
    })
    agent._append_tool_result("execute", output, True, "exec_1")


@pytest.mark.parametrize("role", ["tool", "user"])
@pytest.mark.asyncio
async def test_latest_execute_result_is_reserved_before_optional_schemas(agent, role):
    from airecon.proxy.agent.tool_defs import get_tool_definitions
    from airecon.proxy.context_budget import _minimum_request_messages

    registry = get_tool_definitions()
    core = _core_tools(agent.state.conversation, registry)
    optional = [tool for tool in registry if tool not in core]
    agent._tools_llm = core + optional
    output = "".join(f"fixture scan line {i:04d} ok\n" for i in range(300))
    _append_execute_group(agent, role, output)
    call, result = copy.deepcopy(agent.state.conversation[-2:])
    compressor = agent._get_artifact_compressor()
    smallest, _ = compressor.preview(
        result["content"], 400, reference=result["_context_ref"], external=False,
    )
    shrunk = agent.state.conversation[:2] + [call, {**result, "content": smallest}]
    budget = request_chars(shrunk, core + optional[:25]) - 1
    agent._context_char_budget = budget

    await agent._enforce_char_budget(65536, 1024)

    conversation = agent.state.conversation
    names = {tool["function"]["name"] for tool in agent._tools_budgeted}
    assert names >= set(CORE_TOOL_NAMES)
    assert len(core) <= len(agent._tools_budgeted) < len(core) + 25
    assert request_chars(conversation, agent._tools_budgeted) <= budget
    assert conversation[-2] == call
    assert "[Compacted preview" in conversation[-1]["content"]
    assert compressor.load(conversation[-1]["_context_ref"]) == output
    snapshot = copy.deepcopy(conversation)
    tools_after_first = list(agent._tools_budgeted)
    await agent._enforce_char_budget(65536, 1024)
    assert agent.state.conversation == snapshot
    assert agent._tools_budgeted == tools_after_first
    reserved = request_chars(_minimum_request_messages(snapshot), core)
    assert reserved >= request_chars(shrunk, core)
    assert reserved == request_chars(_minimum_request_messages(shrunk), core)


@pytest.mark.asyncio
async def test_irreducible_latest_execute_result_still_raises_with_core_schemas(agent):
    from airecon.proxy.agent.tool_defs import get_tool_definitions

    agent._tools_llm = get_tool_definitions()
    core = _core_tools(agent.state.conversation, agent._tools_llm)
    _append_execute_group(agent, "tool", "fixture scan line ok\n" * 300)
    budget = request_chars(agent.state.conversation[:3], core) + 100
    agent._context_char_budget = budget

    with pytest.raises(ContextBudgetError):
        await agent._enforce_char_budget(65536, 1024)
    assert fit_tools_to_budget(agent.state.conversation, agent._tools_llm, budget) == core

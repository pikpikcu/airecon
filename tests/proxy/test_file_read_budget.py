"""read_file is bounded in serialized bytes, never by silently cutting content."""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from airecon.proxy import filesystem
from airecon.proxy.config import DEFAULT_CONFIG
from airecon.proxy.context_budget import request_chars
from airecon.proxy.filesystem import read_file

LIMIT = filesystem._READ_RESULT_WIRE_BYTES
_HEADER_LINE = re.compile(r"\[[^\n]*\]")


def wire(text: str) -> int:
    """Bytes the text occupies inside a JSON request body."""
    return len(json.dumps(text, ensure_ascii=False).encode("utf-8")) - 2


def read(root: Path, name: str, **kwargs):
    with patch("airecon.proxy.filesystem.get_workspace_root", return_value=root):
        return read_file(name, **kwargs)


def source_lines(path: Path) -> list[bytes]:
    return path.read_bytes().splitlines(keepends=True)


def assert_exact_page(result: dict, lines: list[bytes], start: int, stop: int) -> None:
    expected = b"".join(lines[start:stop]).decode("utf-8")
    text = result["result"]
    assert text.endswith(expected)
    header = text[: len(text) - len(expected)]
    assert header.endswith("\n")
    assert all(_HEADER_LINE.fullmatch(line) for line in header.splitlines()), header


def read_all_pages(root: Path, name: str, **kwargs) -> list[dict]:
    """Follow the continuation metadata exactly as a caller would."""
    path = root / name
    lines = source_lines(path)
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    pages: list[dict] = []
    offset = 0
    while True:
        page = read(root, name, offset=offset, **kwargs)
        assert page["success"] is True
        assert wire(page["result"]) <= LIMIT
        assert page["total_lines"] == len(lines)
        assert page["offset"] == offset
        assert page["next_offset"] > offset, "a page must make progress"
        assert_exact_page(page, lines, offset, page["next_offset"])
        assert f"[Lines {offset + 1}–{page['next_offset']} of {len(lines)} total]" in page["result"]
        pages.append(page)
        assert page["has_more"] is (page["next_offset"] < len(lines))
        if not page["has_more"]:
            break
        assert f"offset={page['next_offset']}" in page["result"]
        offset = page["next_offset"]
        assert len(pages) < 1000
    assert pages[-1]["next_offset"] == len(lines)
    assert hashlib.sha256(path.read_bytes()).hexdigest() == digest
    return pages


def test_byte_limit_stays_below_formatter_cut_and_reserves_framing():
    # _smart_format_tool_result cuts any result above 12000 characters mid-line.
    assert LIMIT < 12000
    assert (
        filesystem._READ_CONTENT_WIRE_BYTES + filesystem._READ_FRAMING_RESERVE_BYTES
        == LIMIT
    )


def test_wide_file_under_the_line_limit_is_paged_by_bytes(tmp_path):
    path = tmp_path / "wide.txt"
    path.write_bytes(b"".join(b"%03d " % i + b"x" * 596 + b"\n" for i in range(200)))
    assert path.stat().st_size == 120200

    first = read(tmp_path, "wide.txt")

    assert wire(first["result"]) <= LIMIT
    assert first["has_more"] is True
    assert first["byte_limited"] is True
    pages = read_all_pages(tmp_path, "wide.txt")
    assert len(pages) > 10


def test_single_long_line_gets_a_plan_not_a_partial_line(tmp_path):
    payload = json.dumps({"marker_start": "A" * 59981, "marker_end": 1}, separators=(",", ":"))
    path = tmp_path / "min.json"
    path.write_text(payload)
    size = path.stat().st_size
    assert size == 60015
    digest = hashlib.sha256(path.read_bytes()).hexdigest()

    result = read(tmp_path, "min.json", limit=1)

    assert result["success"] is True
    assert result["line_too_large"] is True
    assert result["content_returned"] is False
    assert result["line_number"] == 1
    assert result["line_bytes"] == size
    assert result["line_byte_offset"] == 0
    assert result["has_more"] is False
    assert wire(result["result"]) <= 2048
    assert "marker_start" not in result["result"]
    assert "AAAA" not in result["result"]
    assert "LINE TOO LARGE" in result["result"]
    assert "execute" in result["result"]
    assert hashlib.sha256(path.read_bytes()).hexdigest() == digest


def test_long_first_line_does_not_block_the_following_lines(tmp_path):
    path = tmp_path / "mixed.log"
    path.write_bytes(b"H" * 30000 + b"\n" + b"".join(b"row %d\n" % i for i in range(5)))

    first = read(tmp_path, "mixed.log")
    assert first["line_too_large"] is True
    assert first["next_offset"] == 1
    assert first["has_more"] is True
    assert "offset=1" in first["result"]
    assert "HHHH" not in first["result"]

    rest = read(tmp_path, "mixed.log", offset=first["next_offset"])
    assert_exact_page(rest, source_lines(path), 1, 6)
    assert rest["has_more"] is False


def test_page_stops_before_an_oversized_line_and_reports_it_next(tmp_path):
    path = tmp_path / "tail.log"
    path.write_bytes(b"a\nb\n" + b"Z" * 20000 + b"\nc\n")

    first = read(tmp_path, "tail.log")
    assert_exact_page(first, source_lines(path), 0, 2)
    assert first["next_offset"] == 2
    assert first["has_more"] is True

    blocked = read(tmp_path, "tail.log", offset=2)
    assert blocked["line_too_large"] is True
    assert blocked["line_number"] == 3
    assert blocked["line_byte_offset"] == 4
    assert blocked["line_bytes"] == 20001


def test_escaping_and_multibyte_text_are_budgeted_as_serialized(tmp_path):
    line = ('"\\\t\x01' * 60 + "日本語 🙂 é\n").encode("utf-8")
    path = tmp_path / "escaped.txt"
    path.write_bytes(line * 120)
    assert wire(line.decode()) > 2 * len(line)

    pages = read_all_pages(tmp_path, "escaped.txt")

    assert len(pages) > 1
    # Raw bytes alone would have fit far more lines than the wire form allows.
    assert all(page["next_offset"] - page["offset"] < LIMIT // len(line) for page in pages)


def test_file_over_200kib_with_few_lines_is_paged_exactly(tmp_path):
    path = tmp_path / "big.csv"
    path.write_bytes(b"".join(b"%04d," % i + b"v" * 994 + b"\n" for i in range(300)))
    assert path.stat().st_size > filesystem._LARGE_FILE_BYTE_THRESHOLD

    pages = read_all_pages(tmp_path, "big.csv", limit=500)

    assert "large_file" not in pages[0]


def test_large_file_advisory_sample_is_bounded_and_labelled(tmp_path):
    path = tmp_path / "urls.txt"
    path.write_bytes(
        b"Q" * 150000 + b"\n" + b"".join(b"https://fixture.test/%d\n" % i for i in range(4000))
    )

    result = read(tmp_path, "urls.txt")

    assert result["large_file"] is True
    assert result["total_lines"] == 4001
    assert wire(result["result"]) <= LIMIT
    assert "QQQQ" not in result["result"]
    assert "line 1: 150,001 bytes" in result["result"]
    assert "https://fixture.test/0" in result["result"]


def _archive_group(count: int) -> list[dict]:
    group = []
    for i in range(count):
        group.append({"role": "tool", "name": "web_search", "tool_call_id": f"call_{i}", "content": f"result line {i} " + "y" * 40})
    return group


def test_large_context_archive_pages_exactly_like_a_small_file(tmp_path):
    from airecon.proxy.context_budget import ArtifactCompressor, _archive_group_text

    compressor = ArtifactCompressor(tmp_path)
    reference = compressor.save(_archive_group_text(_archive_group(2000)))
    path = tmp_path / reference
    assert path.stat().st_size > filesystem._LARGE_FILE_BYTE_THRESHOLD
    assert len(path.read_bytes().splitlines()) > filesystem._LARGE_FILE_LINE_THRESHOLD
    assert path.read_bytes().startswith(b"[Archived tool group")

    first = read(tmp_path, reference)
    assert "large_file" not in first, "a context archive must page, not advise"

    pages = read_all_pages(tmp_path, reference)
    assert len(pages) > 1


def test_same_size_non_archive_file_still_gets_the_advisory(tmp_path):
    path = tmp_path / "plain.txt"
    path.write_bytes(b"".join(b"row %04d " % i + b"z" * 100 + b"\n" for i in range(2000)))
    assert path.stat().st_size > filesystem._LARGE_FILE_BYTE_THRESHOLD
    assert len(path.read_bytes().splitlines()) > filesystem._LARGE_FILE_LINE_THRESHOLD

    result = read(tmp_path, "plain.txt")

    assert result["large_file"] is True


def test_empty_file_reads_as_empty(tmp_path):
    (tmp_path / "empty.txt").write_bytes(b"")

    result = read(tmp_path, "empty.txt")

    assert result == {"success": True, "result": "", "total_lines": 0}


def test_small_file_is_returned_verbatim_without_pagination(tmp_path):
    raw = "alpha\r\nbeta \"quoted\"\n\n  indented é\nno trailing newline"
    (tmp_path / "small.txt").write_bytes(raw.encode("utf-8"))

    result = read(tmp_path, "small.txt")

    assert result == {"success": True, "result": raw, "total_lines": 5}


def test_offset_and_limit_return_exact_lines_with_accurate_metadata(tmp_path):
    path = tmp_path / "rows.txt"
    path.write_bytes(b"".join(b"row %d\n" % i for i in range(10)))
    lines = source_lines(path)

    page = read(tmp_path, "rows.txt", offset=5, limit=3)
    assert_exact_page(page, lines, 5, 8)
    assert "[Lines 6–8 of 10 total]" in page["result"]
    assert (page["offset"], page["limit"], page["next_offset"]) == (5, 3, 8)
    assert page["has_more"] is True
    assert page["byte_limited"] is False

    last = read(tmp_path, "rows.txt", offset=8, limit=3)
    assert_exact_page(last, lines, 8, 10)
    assert last["has_more"] is False

    beyond = read(tmp_path, "rows.txt", offset=10)
    assert beyond["success"] is True
    assert beyond["has_more"] is False
    assert "row" not in beyond["result"]
    assert "10" in beyond["result"]


def test_undecodable_bytes_are_reported_not_silently_replaced(tmp_path):
    (tmp_path / "blob.txt").write_bytes(b"ok\n\xff\xfe broken\n")

    result = read(tmp_path, "blob.txt")

    assert result["success"] is True
    assert result["lossy_decode"] is True
    assert "not valid UTF-8" in result["result"]


@pytest.fixture
def agent(monkeypatch, tmp_path):
    from airecon.proxy.agent.loop import AgentLoop
    from airecon.proxy.agent.tool_defs import get_tool_definitions

    cfg = SimpleNamespace(**DEFAULT_CONFIG)
    for module in ("loop", "loop_context", "models"):
        monkeypatch.setattr(f"airecon.proxy.agent.{module}.get_config", lambda: cfg)
    monkeypatch.setattr("airecon.proxy.config._workspace_root_cache", tmp_path)
    loop = AgentLoop(llm=MagicMock(), engine=MagicMock())
    loop.state.active_target = "fixture.test"
    loop._tools_llm = get_tool_definitions()
    loop.state.conversation = [
        {"role": "system", "content": "Only authorized fixture scope."},
        {"role": "user", "content": "Read the local fixture exactly."},
    ]
    return loop, cfg


@pytest.mark.parametrize("role", ["tool", "user"])
@pytest.mark.parametrize("kind", ["wide", "single_line"])
@pytest.mark.parametrize("ctf", [False, True])
@pytest.mark.asyncio
async def test_default_read_fits_the_smallest_context_fixture(agent, tmp_path, role, kind, ctf):
    """Reader -> formatter -> history -> budget gate, including CTF mode."""
    loop, cfg = agent
    cfg.tool_response_role = role
    cfg.model_max_tool_result_chars = 5000
    loop._ctf_mode = ctf
    path = tmp_path / "fixture.txt"
    if kind == "wide":
        path.write_bytes(b"".join(b"%03d " % i + b"x" * 596 + b"\n" for i in range(200)))
    else:
        path.write_bytes(b'{"k":"' + b"A" * 60000 + b'"}')
    call = {"role": "assistant", "content": "Reading fixture.txt"}
    if role == "tool":
        call = {"role": "assistant", "content": "", "tool_calls": [{
            "id": "read_1", "function": {"name": "read_file", "arguments": {"path": "fixture.txt"}},
        }]}
    loop.state.conversation.append(call)

    result = read(tmp_path, "fixture.txt")
    formatted = loop._smart_format_tool_result("read_file", result, True)
    assert formatted == result["result"], "formatter must not cut a bounded read"
    loop._append_tool_result("read_file", formatted, True, "read_1")

    await loop._enforce_char_budget(8192, 1024)

    budget = (8192 - 1024 - 256) * 3
    assert request_chars(loop._messages_for_llm(), loop._tools_budgeted) <= budget
    latest = loop.state.conversation[-1]
    assert latest["name"] == "read_file"
    assert latest["content"].endswith(formatted)
    assert {"execute", "read_file"} <= {
        tool["function"]["name"] for tool in loop._tools_budgeted
    }
    assert loop.state.conversation[0]["content"] == "Only authorized fixture scope."
    assert loop.state.conversation[1]["content"] == "Read the local fixture exactly."


def test_ctf_formatter_still_bounds_non_read_tools(agent):
    loop, _cfg = agent
    loop._ctf_mode = True
    result = {"success": True, "result": "Fixture result " * 1000}
    formatted = loop._smart_format_tool_result("web_search", result, True)
    assert len(formatted) < len(result["result"])
    assert formatted.endswith("\n... (truncated)")

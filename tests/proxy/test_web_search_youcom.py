"""Tests for the optional keyless You.com web-search provider."""

from __future__ import annotations

import pytest

from airecon.proxy import web_search_youcom


class TestParseSse:
    """Test _parse_sse() helper."""

    def test_extracts_result_object(self):
        sse = (
            'event: message\n'
            'data: {"jsonrpc":"2.0","method":"notifications/message",'
            '"params":{"level":"info","data":"Search successful"}}\n\n'
            'event: message\n'
            'data: {"result":{"content":[{"type":"text","text":"{}"}]}}\n'
        )
        parsed = web_search_youcom._parse_sse(sse)
        assert parsed is not None
        assert "content" in parsed["result"]

    def test_returns_none_when_no_result(self):
        sse = 'data: {"jsonrpc":"2.0","method":"notifications/message"}\n'
        assert web_search_youcom._parse_sse(sse) is None

    def test_skips_malformed_lines(self):
        sse = 'data: not-json\n\ndata: {"result":{"id":1}}\n'
        assert web_search_youcom._parse_sse(sse) == {"result": {"id": 1}}

    def test_empty_body(self):
        assert web_search_youcom._parse_sse("") is None


class TestSnippet:
    """Test _snippet() helper."""

    def test_prefers_snippets(self):
        item = {"snippets": ["first snippet"], "description": "desc"}
        assert web_search_youcom._snippet(item) == "first snippet"

    def test_falls_back_to_highlights(self):
        item = {"contents": {"highlights": ["highlight text"]}, "description": "desc"}
        assert web_search_youcom._snippet(item) == "highlight text"

    def test_falls_back_to_description(self):
        assert web_search_youcom._snippet({"description": "desc"}) == "desc"

    def test_truncates_long_snippets(self):
        item = {"snippets": ["x" * 500]}
        snippet = web_search_youcom._snippet(item)
        assert len(snippet) == 300
        assert snippet.endswith("...")

    def test_missing_everything(self):
        assert web_search_youcom._snippet({}) == "No description"


class TestFormatResults:
    """Test format_results() output layout."""

    def test_matches_ddg_layout(self):
        web = [
            {"url": "https://example.com", "title": "Example", "description": "A page"}
        ]
        out = web_search_youcom.format_results(web)
        assert out == "1. [youcom] **Example**\n   URL: https://example.com\n   A page"

    def test_multiple_results_numbered(self):
        web = [
            {"url": "https://a.example", "title": "A", "description": "da"},
            {"url": "https://b.example", "title": "B", "description": "db"},
        ]
        out = web_search_youcom.format_results(web)
        assert "1. [youcom] **A**" in out
        assert "2. [youcom] **B**" in out


class TestYoucomSearch:
    """Test youcom_search() function contract."""

    def test_function_exists(self):
        assert callable(web_search_youcom.youcom_search)

    @pytest.mark.asyncio
    async def test_returns_error_on_connection_failure(self):
        # Unroutable URL — fails fast without network mocking.
        result = await web_search_youcom.youcom_search(
            "query", 5, url="http://127.0.0.1:1/mcp"
        )
        assert result["success"] is False
        assert "error" in result

    @pytest.mark.asyncio
    async def test_signature_accepts_expected_parameters(self):
        import inspect

        sig = inspect.signature(web_search_youcom.youcom_search)
        assert "query" in sig.parameters
        assert "max_results" in sig.parameters
        assert "url" in sig.parameters


class TestConfigDefaults:
    """You.com provider must be opt-in and disabled by default."""

    def test_defaults_off(self):
        from airecon.proxy.config import DEFAULT_CONFIG

        assert DEFAULT_CONFIG["youcom_search"] is False
        assert (
            DEFAULT_CONFIG["youcom_url"] == "https://api.you.com/mcp?profile=free"
        )

    def test_module_imports(self):
        from airecon.proxy import web_search

        assert web_search is not None

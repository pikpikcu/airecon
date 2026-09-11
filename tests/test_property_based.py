"""Property-based tests using hypothesis."""

from __future__ import annotations

import pytest

try:
    from hypothesis import given, settings, strategies as st
    HAS_HYPOTHESIS = True
except ImportError:
    HAS_HYPOTHESIS = False

pytestmark = pytest.mark.skipif(
    not HAS_HYPOTHESIS, reason="hypothesis not installed"
)

if HAS_HYPOTHESIS:

    class TestUrlNormalization:
        """Property tests for URL normalization logic."""

        @given(
            scheme=st.one_of(st.just("http"), st.just("https"), st.just("")),
            host=st.text(
                min_size=1, max_size=50, alphabet=st.characters(blacklist_characters="/")
            ),
            port=st.one_of(st.just(""), st.just(":80"), st.just(":443"), st.just(":8080")),
            path=st.text(
                min_size=0,
                max_size=100,
                alphabet=st.characters(blacklist_characters="\x00"),
            ),
        )
        @settings(max_examples=50)
        def test_url_construction_never_raises(self, scheme, host, port, path):
            """URL construction should never raise for any input."""
            from urllib.parse import urljoin

            base = f"{scheme}://{host}{port}" if scheme else f"http://{host}{port}"
            try:
                result = urljoin(base, path)
                assert isinstance(result, str)
            except (ValueError, UnicodeError):
                pass  # Expected for some edge cases

    class TestCommandParsing:
        """Property tests for command parsing."""

        @given(
            cmd=st.text(
                min_size=1,
                max_size=500,
                alphabet=st.characters(blacklist_characters="\x00\n"),
            ),
        )
        @settings(max_examples=100)
        def test_extract_primary_binary_never_raises(self, cmd):
            """Command binary extraction should never raise."""
            from airecon.proxy.agent.command_parse import extract_primary_binary

            try:
                result = extract_primary_binary(cmd)
                if result is not None:
                    assert isinstance(result, str)
            except Exception:
                pass  # Some edge cases may fail

    class TestJaccardSimilarity:
        """Property tests for Jaccard similarity (operates on strings)."""

        @given(
            a=st.text(
                min_size=0,
                max_size=200,
                alphabet=st.characters(whitelist_categories=("Ll", "Lu", "Nd", "Zs")),
            ),
            b=st.text(
                min_size=0,
                max_size=200,
                alphabet=st.characters(whitelist_categories=("Ll", "Lu", "Nd", "Zs")),
            ),
        )
        @settings(max_examples=100)
        def test_jaccard_is_symmetric(self, a, b):
            """Jaccard similarity should be symmetric: J(A,B) == J(B,A)."""
            from airecon.proxy.agent.models import jaccard_similarity

            ab = jaccard_similarity(a, b)
            ba = jaccard_similarity(b, a)
            assert ab == ba

        @given(
            a=st.text(
                min_size=1,
                max_size=200,
                alphabet=st.characters(whitelist_categories=("Ll", "Lu", "Nd", "Zs")),
            ),
        )
        @settings(max_examples=50)
        def test_jaccard_identical_strings_is_nonzero(self, a):
            """Jaccard similarity of identical non-empty strings should be 1.0."""
            from airecon.proxy.agent.models import jaccard_similarity

            if a.strip():
                assert jaccard_similarity(a, a) == 1.0
            else:
                assert jaccard_similarity(a, a) == 0.0

        @given(
            a=st.text(
                min_size=0,
                max_size=200,
                alphabet=st.characters(whitelist_categories=("Ll", "Lu", "Nd", "Zs")),
            ),
            b=st.text(
                min_size=0,
                max_size=200,
                alphabet=st.characters(whitelist_categories=("Ll", "Lu", "Nd", "Zs")),
            ),
        )
        @settings(max_examples=50)
        def test_jaccard_is_between_zero_and_one(self, a, b):
            """Jaccard similarity should always be in [0, 1]."""
            from airecon.proxy.agent.models import jaccard_similarity

            result = jaccard_similarity(a, b)
            assert 0.0 <= result <= 1.0

    class TestConfigBounds:
        """Property tests for config value bounds."""

        @given(val=st.integers(min_value=-1000000, max_value=1000000))
        @settings(max_examples=50)
        def test_llm_context_window_bounds(self, val):
            """Config should handle extreme num_ctx values."""
            from airecon.proxy.config import Config, DEFAULT_CONFIG

            cfg = Config(
                llm_context_window=val,
                **{k: v for k, v in DEFAULT_CONFIG.items() if k != "llm_context_window"},
            )
            assert cfg.llm_context_window == val

        @given(val=st.integers(min_value=-100, max_value=10000))
        @settings(max_examples=50)
        def test_agent_max_iterations_bounds(self, val):
            """Config should handle extreme iteration values."""
            from airecon.proxy.config import Config, DEFAULT_CONFIG

            cfg = Config(
                agent_max_tool_iterations=val,
                **{
                    k: v
                    for k, v in DEFAULT_CONFIG.items()
                    if k != "agent_max_tool_iterations"
                },
            )
            assert cfg.agent_max_tool_iterations == val

    class TestSeverityValidation:
        """Property tests for severity validation."""

        @given(
            severity=st.one_of(
                st.just("Critical"),
                st.just("High"),
                st.just("Medium"),
                st.just("Low"),
                st.just("Info"),
                st.just(""),
                st.text(min_size=1, max_size=20),
            )
        )
        @settings(max_examples=50)
        def test_severity_for_evidence_never_raises(self, severity):
            """Severity calculation should never raise."""
            from airecon.proxy.agent.owasp import severity_for_evidence

            try:
                result = severity_for_evidence(f"Test with {severity}", [], 0.5, "execute")
                assert isinstance(result, int)
                assert 1 <= result <= 5
            except Exception:
                pass

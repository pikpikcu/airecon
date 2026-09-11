"""Regression tests: HTTP 429 rate limits are retryable, not fatal.

A 429 ("quota will reset after Ns") previously aborted the whole run because
only 5xx was treated as retryable. These lock in the corrected classification
and the reset-hint-aware backoff.
"""

from __future__ import annotations

from airecon.proxy.llm import (
    LLMClient,
    _is_retryable_status,
    _retry_wait_seconds,
)


def test_429_and_408_and_5xx_are_retryable():
    assert _is_retryable_status(429) is True
    assert _is_retryable_status(408) is True
    assert _is_retryable_status(503) is True
    assert _is_retryable_status(500) is True


def test_4xx_client_errors_not_retryable():
    for code in (400, 401, 403, 404, 422):
        assert _is_retryable_status(code) is False


def test_retry_wait_honors_reset_hint_on_429():
    body = (
        '{"error":{"code":429,"message":"You have exhausted your capacity on '
        'this model. Your quota will reset after 6s."}}'
    )
    # attempt 0 base would be 5s; hint is 6s -> 6+1 cushion = 7s
    wait = _retry_wait_seconds(429, body, attempt=0)
    assert 6.0 <= wait <= 8.0


def test_retry_wait_is_capped():
    body = "rate limited, reset after 9999 seconds"
    assert _retry_wait_seconds(429, body, attempt=0) <= 30.0


def test_retry_wait_falls_back_to_exponential_without_hint():
    # 5xx with no hint -> base exponential 5*(attempt+1)
    assert _retry_wait_seconds(503, "internal error", attempt=0) == 5.0
    assert _retry_wait_seconds(503, "internal error", attempt=1) == 10.0


def test_429_is_not_treated_as_unsupported_reasoning():
    # _maybe_degrade_reasoning must only fire on 400 reasoning rejections.
    assert LLMClient._is_unsupported_reasoning_error(429, "reasoning_effort") is False

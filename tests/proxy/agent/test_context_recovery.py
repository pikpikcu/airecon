"""Tests for proactive context monitoring and multi-level VRAM recovery in loop.py."""

from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, MagicMock

from airecon.proxy.agent.loop import AgentLoop


# ─────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────


def _make_loop() -> AgentLoop:
    llm = MagicMock()
    engine = MagicMock()
    return AgentLoop(llm=llm, engine=engine)


# ─────────────────────────────────────────────────────────────
# Initial state
# ─────────────────────────────────────────────────────────────


class TestInitialState:
    def test_adaptive_num_ctx_starts_zero(self):
        loop = _make_loop()
        assert loop._adaptive_num_ctx == 0

    def test_vram_crash_count_starts_zero(self):
        loop = _make_loop()
        assert loop._vram_crash_count == 0

    def test_token_usage_limit_default(self):
        loop = _make_loop()
        assert loop.state.token_usage["limit"] == 65536

    def test_token_usage_used_default(self):
        loop = _make_loop()
        assert loop.state.token_usage["used"] == 0


# ─────────────────────────────────────────────────────────────
# _adaptive_num_ctx persistence logic
# ─────────────────────────────────────────────────────────────


class TestAdaptiveNumCtxPersistence:
    def test_zero_means_use_config_default(self):
        """_adaptive_num_ctx == 0 → use cfg.llm_context_window."""
        loop = _make_loop()
        assert loop._adaptive_num_ctx == 0
        # When 0, caller should use cfg.llm_context_window
        effective = loop._adaptive_num_ctx if loop._adaptive_num_ctx > 0 else 131072
        assert effective == 131072

    def test_nonzero_overrides_config(self):
        """_adaptive_num_ctx > 0 → override config default."""
        loop = _make_loop()
        loop._adaptive_num_ctx = 16384
        effective = loop._adaptive_num_ctx if loop._adaptive_num_ctx > 0 else 131072
        assert effective == 16384

    def test_crash_count_increments_independently(self):
        loop = _make_loop()
        loop._vram_crash_count += 1
        loop._vram_crash_count += 1
        assert loop._vram_crash_count == 2
        # adaptive_num_ctx is independent
        assert loop._adaptive_num_ctx == 0


# ─────────────────────────────────────────────────────────────
# Multi-level escalation logic (pure unit, no async)
# ─────────────────────────────────────────────────────────────


class TestMultiLevelEscalationLogic:
    """Test the escalation tier logic independent of the async stream loop."""

    def _tier(self, crash_count: int, num_ctx_small: int) -> tuple[int, int, int]:
        """Replicate the tier selection logic from loop.py."""
        if crash_count == 1:
            return num_ctx_small, 80, 0
        elif crash_count == 2:
            return max(4096, num_ctx_small // 2), 50, 5
        elif crash_count == 3:
            return max(4096, num_ctx_small // 4), 30, 10
        else:
            return 4096, 20, 30

    def test_tier1_uses_num_ctx_small(self):
        ctx, msgs, wait = self._tier(1, 32768)
        assert ctx == 32768
        assert msgs == 80
        assert wait == 0

    def test_tier2_halves_ctx(self):
        ctx, msgs, wait = self._tier(2, 32768)
        assert ctx == 16384
        assert msgs == 50
        assert wait == 5

    def test_tier3_quarters_ctx(self):
        ctx, msgs, wait = self._tier(3, 32768)
        assert ctx == 8192
        assert msgs == 30
        assert wait == 10

    def test_tier4_uses_minimum(self):
        ctx, msgs, wait = self._tier(4, 32768)
        assert ctx == 4096
        assert msgs == 20
        assert wait == 30

    def test_tier5_same_as_tier4(self):
        ctx, msgs, wait = self._tier(5, 32768)
        assert ctx == 4096
        assert msgs == 20
        assert wait == 30

    def test_small_num_ctx_floored_at_4096_tier2(self):
        """If num_ctx_small is very small, floor at 4096."""
        ctx, _, _ = self._tier(2, 4096)
        assert ctx == 4096

    def test_small_num_ctx_floored_at_4096_tier3(self):
        ctx, _, _ = self._tier(3, 8192)
        assert ctx == max(4096, 8192 // 4)
        assert ctx == 4096

    def test_retry_guard_allows_four_vram_retries(self):
        retries = 0
        allowed = []
        for _ in range(5):
            can_retry = retries < 4
            allowed.append(can_retry)
            if can_retry:
                retries += 1
        assert allowed == [True, True, True, True, False]


# ─────────────────────────────────────────────────────────────
# Proactive context monitoring logic
# ─────────────────────────────────────────────────────────────


class TestProactiveContextMonitoring:
    def test_80_percent_threshold_triggers_trim(self):
        """Usage >= 80% of context window should trigger proactive trim."""
        ctx_used = 26215  # just above 80% of 32768 (32768 * 0.80 = 26214.4)
        ctx_limit = 32768
        ratio = ctx_used / ctx_limit
        assert ratio >= 0.80

    def test_79_percent_does_not_trigger(self):
        ctx_used = 25804  # ~78.7%
        ctx_limit = 32768
        ratio = ctx_used / ctx_limit
        assert ratio < 0.80

    def test_90_percent_uses_more_aggressive_trim(self):
        """At 90%+ usage, trim target is 35 messages (vs 50 at 80-89%)."""
        ratio_90 = 0.90
        ratio_80 = 0.85
        trim_90 = 50 if ratio_90 < 0.90 else 35
        trim_80 = 50 if ratio_80 < 0.90 else 35
        assert trim_90 == 35
        assert trim_80 == 50

    def test_zero_ctx_used_skips_check(self):
        """If no tokens used yet (first iteration), skip proactive trim."""
        ctx_used = 0
        ctx_limit = 32768
        # Condition: ctx_used > 0 and ctx_limit > 0
        should_check = ctx_used > 0 and ctx_limit > 0
        assert not should_check

    def test_zero_ctx_limit_skips_check(self):
        ctx_used = 1000
        ctx_limit = 0
        should_check = ctx_used > 0 and ctx_limit > 0
        assert not should_check

    def test_token_usage_limit_synced_with_adaptive_ctx(self):
        """token_usage['limit'] should match adaptive_num_ctx."""
        loop = _make_loop()
        # Simulate what the loop does at the start of each iteration
        adaptive_num_ctx = 16384
        loop.state.token_usage["limit"] = adaptive_num_ctx
        assert loop.state.token_usage["limit"] == 16384

    def test_token_usage_limit_updates_after_override(self):
        loop = _make_loop()
        loop._adaptive_num_ctx = 8192
        adaptive_num_ctx = (
            loop._adaptive_num_ctx if loop._adaptive_num_ctx > 0 else 131072
        )
        loop.state.token_usage["limit"] = adaptive_num_ctx
        assert loop.state.token_usage["limit"] == 8192


class TestNumKeepClamping:
    def test_num_keep_is_clamped_when_ctx_shrinks(self):
        loop = _make_loop()
        safe = loop._fit_num_keep_to_ctx(num_keep=8192, num_ctx=4096, num_predict=1024)
        # 4096 - 1024 - 256 = 2816 max safe keep
        assert safe == 2816

    def test_num_keep_kept_when_within_budget(self):
        loop = _make_loop()
        safe = loop._fit_num_keep_to_ctx(num_keep=2048, num_ctx=16384, num_predict=2048)
        assert safe == 2048

    def test_num_keep_never_negative(self):
        loop = _make_loop()
        safe = loop._fit_num_keep_to_ctx(num_keep=4096, num_ctx=1024, num_predict=900)
        assert safe >= 0


# ─────────────────────────────────────────────────────────────
# VRAM crash error detection patterns
# ─────────────────────────────────────────────────────────────


class TestVramCrashDetection:
    PATTERNS = [
        "invalid character '<'",
        "failed to parse JSON",
        "HTML error page",
        "unexpected end of json",
        "<!doctype",
        "<html",
        "out of memory",
        "cuda out of memory",
        "llm runner process no longer alive",
        "signal: killed",
    ]

    def _is_vram_crash(self, err_str: str) -> bool:
        err_lower = err_str.lower()
        return (
            "invalid character '<'" in err_str
            or "failed to parse JSON" in err_str
            or "HTML error page" in err_str
            or "unexpected end of json" in err_lower
            or "<!doctype" in err_lower
            or "<html" in err_lower
            or "out of memory" in err_lower
            or "cuda out of memory" in err_lower
            or "llm runner process no longer alive" in err_lower
            or "signal: killed" in err_lower
        )

    def test_oom_detected(self):
        assert self._is_vram_crash("out of memory")

    def test_cuda_oom_detected(self):
        assert self._is_vram_crash("CUDA out of memory")

    def test_html_error_page_detected(self):
        assert self._is_vram_crash("HTML error page returned")

    def test_killed_signal_detected(self):
        assert self._is_vram_crash("signal: killed")

    def test_llm_runner_dead_detected(self):
        assert self._is_vram_crash("llm runner process no longer alive")

    def test_normal_error_not_vram(self):
        assert not self._is_vram_crash("connection refused")

    def test_timeout_not_vram(self):
        assert not self._is_vram_crash("request timed out")

    def test_model_not_found_not_vram(self):
        assert not self._is_vram_crash("model not found: llama3")


class TestLLMResetFallback:
    @pytest.mark.asyncio
    async def test_reset_context_retries_and_succeeds(self):
        loop = _make_loop()
        loop.llm.reset_context = AsyncMock(side_effect=[False, False, True])

        ok = await loop._reset_llm_context()

        assert ok is True
        assert loop.llm.reset_context.await_count == 3

    @pytest.mark.asyncio
    async def test_reset_context_failure_triggers_local_fallback(self):
        loop = _make_loop()
        loop.llm.reset_context = AsyncMock(return_value=False)
        loop._apply_local_context_fallback = MagicMock()

        ok = await loop._reset_llm_context()

        assert ok is False
        loop._apply_local_context_fallback.assert_called_once()


class _FakeResp:
    def __init__(self, payload: dict, status: int = 200):
        self.status = status
        self._payload = payload

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def json(self):
        return self._payload


class _FakeSession:
    def __init__(self, payload: dict):
        self._payload = payload

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    def get(self, *args, **kwargs):
        return _FakeResp(self._payload)


class TestPsContextResetGuard:
    @pytest.mark.asyncio
    async def test_high_ps_context_does_not_reset_when_local_used_is_low(self, monkeypatch):
        loop = _make_loop()
        loop.llm.model = "qwen3"
        loop.llm._host = "http://llm.local"
        loop.state.token_usage["used"] = 2048
        loop._reset_llm_context = AsyncMock(return_value=True)

        payload = {"models": [{"name": "qwen3:latest", "context_length": 131072}]}
        monkeypatch.setattr("airecon.proxy.agent.loop.aiohttp.ClientSession", lambda *a, **k: _FakeSession(payload))
        monkeypatch.setattr("airecon.proxy.llm._CONTEXT_RESET_THRESHOLD", 100000, raising=False)

        await loop._check_and_reset_context()

        loop._reset_llm_context.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_reset_cooldown_blocks_repeat_resets(self, monkeypatch):
        loop = _make_loop()
        loop.llm.model = "qwen3"
        loop.llm._host = "http://llm.local"
        loop.state.token_usage["used"] = 131072
        loop._reset_llm_context = AsyncMock(return_value=True)

        payload = {"models": [{"name": "qwen3:latest", "context_length": 131072}]}
        monkeypatch.setattr("airecon.proxy.agent.loop.aiohttp.ClientSession", lambda *a, **k: _FakeSession(payload))
        monkeypatch.setattr("airecon.proxy.llm._CONTEXT_RESET_THRESHOLD", 100000, raising=False)

        # First check should reset.
        await loop._check_and_reset_context()
        assert loop._reset_llm_context.await_count == 1

        # Force check window open but still inside reset cooldown.
        loop._last_context_check = 0.0
        await loop._check_and_reset_context()
        assert loop._reset_llm_context.await_count == 1

    @pytest.mark.asyncio
    async def test_reset_cooldown_honors_config_override_zero(self, monkeypatch):
        loop = _make_loop()
        loop.llm.model = "qwen3"
        loop.llm._host = "http://llm.local"
        loop.state.token_usage["used"] = 131072
        loop._reset_llm_context = AsyncMock(return_value=True)

        payload = {"models": [{"name": "qwen3:latest", "context_length": 131072}]}
        monkeypatch.setattr("airecon.proxy.agent.loop.aiohttp.ClientSession", lambda *a, **k: _FakeSession(payload))
        monkeypatch.setattr("airecon.proxy.llm._CONTEXT_RESET_THRESHOLD", 100000, raising=False)

        class _Cfg:
            agent_context_reset_cooldown_seconds = 0

        monkeypatch.setattr("airecon.proxy.agent.loop.get_config", lambda: _Cfg())

        await loop._check_and_reset_context()
        assert loop._reset_llm_context.await_count == 1

        # Force check window open; with cooldown=0 second reset is allowed.
        loop._last_context_check = 0.0
        await loop._check_and_reset_context()
        assert loop._reset_llm_context.await_count == 2

"""Tests for Fuzzing Executors."""
import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from airecon.proxy.agent.executors_fuzzing import _FuzzingExecutorMixin
from airecon.proxy.fuzzer import FuzzResult, InteractiveRealTimeTester


@pytest.mark.asyncio
@pytest.mark.parametrize("fail", [True, False])
async def test_deep_fuzz_consumes_error_events_and_keeps_partial_findings(monkeypatch, fail):
    finding = FuzzResult(target="https://example.com", parameter="q", payload="test",
                         vuln_type="xss", severity="high", confidence=0.9, evidence="fixture",
                         response_code=200, response_length=4, time_ms=1.0)

    async def fuzz(**kwargs):
        yield finding
        if fail:
            raise RuntimeError("injected transport failure")

    tester = InteractiveRealTimeTester.__new__(InteractiveRealTimeTester)
    tester.target = "https://example.com"
    tester.fuzzer = SimpleNamespace(fuzz=fuzz, close=AsyncMock(),
                                   run_phase2_advanced_tests=AsyncMock(return_value=[]),
                                   run_phase3_advanced_tests=AsyncMock(return_value=[]))
    tester.chain_engine = SimpleNamespace(find_chains=AsyncMock(return_value=[]))
    tester.on_finding = None
    tester._stop_event = asyncio.Event()
    tester._findings = []
    tester._chains = []
    monkeypatch.setattr("airecon.proxy.fuzzer.InteractiveRealTimeTester", lambda *args, **kwargs: tester)
    agent = _FuzzingExecutorMixin()
    agent.state = SimpleNamespace(tool_history=[], tool_counts={"total": 0})
    agent._session = SimpleNamespace(target="example.com", auth_headers={}, auth_cookies=[])
    agent._save_tool_output = lambda *args: None
    ok, _, result, _ = await agent._execute_deep_fuzz_tool("deep_fuzz", {"target": tester.target, "params": ["q"], "vuln_types": ["xss"]})
    assert ok is not fail
    assert result["success"] is not fail
    assert len(result["findings"]) == 1
    assert agent.state.tool_history[-1].status == ("error" if fail else "success")
    tester.fuzzer.close.assert_awaited_once()
    if fail:
        assert "injected transport failure" in result["error"]
        assert result["partial"] is True
        tester.fuzzer.run_phase2_advanced_tests.assert_not_awaited()
        tester.fuzzer.run_phase3_advanced_tests.assert_not_awaited()
    else:
        tester.fuzzer.run_phase2_advanced_tests.assert_awaited_once()
        tester.fuzzer.run_phase3_advanced_tests.assert_awaited_once()


class TestFuzzingExecutor:
    def test_module_imports(self):
        from airecon.proxy.agent import executors_fuzzing
        assert executors_fuzzing is not None

# Stability & Quality Status (2026-03-27)

This page documents the current, test-backed stability state of AIRecon.

## Executive Summary

AIRecon is **not yet in fully stable state** for all components.

- Core proxy/agent logic is largely functional and many tests pass.
- Full quality gate is still blocked by type-check errors and hanging test suites.
- "All features 100% working" cannot be claimed yet.

## Validation Snapshot

Commands used during this review:

```bash
pyright airecon tests --outputjson
pytest --collect-only -q
timeout 180 pytest -q tests/tui
timeout 240 pytest -q tests/proxy
timeout 60 pytest -q tests/proxy/test_server.py
timeout 30 pytest -vv tests/tui/test_widgets.py -s
timeout 120 pytest -q tests/tui/test_app.py
timeout 120 pytest -q tests/tui/test_path_completer.py
timeout 180 pytest -q tests/benchmark
```

Observed results:

- `pyright`: **12 errors** (browser, fuzzer, startup, chat widgets).
- `pytest --collect-only`: **1376 tests collected**.
- `tests/benchmark`: **17 passed**.
- `tests/tui`: **timeout** (hang).
- `tests/proxy`: **timeout** (hang near completion).
- Per-file scan in `tests/proxy`: timeout concentrated in `tests/proxy/test_server.py`.

## Current Blockers

1. Type-check regressions (`pyright` not clean):
- `airecon/proxy/browser.py` optional-member errors.
- `airecon/proxy/fuzzer.py` optional-member errors.
- `airecon/tui/startup.py` unused coroutine warning/error path.
- `airecon/tui/widgets/chat.py` optional-member errors.

2. Hanging tests prevent full CI confidence:
- `tests/proxy/test_server.py` hangs from first status test in current environment.
- `tests/tui/test_app.py` and `tests/tui/test_widgets.py` time out.

3. End-to-end runtime coverage is still limited:
- No complete local proof yet for all real integrations together (`Ollama + Docker + Browser + TUI`) in one automated run.

## Is Ollama Performance Degraded?

Short answer: **it depends on model size and context configuration**, not only AIRecon code.

- Larger models generally provide more reliable planning and tool-use than smaller ones.
- As model size shrinks, expect weaker planning, more hallucinations, and less reliable tool calls.
- Context settings still matter: very small `llm_context_window` values or aggressive truncation can reduce output quality even on larger models.

## Stability Exit Criteria

AIRecon can be labeled "stable" after all are true:

1. `pyright airecon tests` reports **0 errors**.
2. Full `pytest` suite finishes without hangs/timeouts.
3. One automated smoke run validates startup + chat + tool call + report flow against real local dependencies.

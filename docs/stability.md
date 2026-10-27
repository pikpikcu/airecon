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

## Ollama: repeated `no user query found in messages`

Ollama may return HTTP 500 with this error after server-side context truncation
removes the user turn while retaining assistant tool calls and tool results.
This can happen even when AIRecon sent a valid, non-empty user message.

- Check the running model's `context_length` in Ollama's `/api/ps` response;
  the model's advertised maximum is not its currently allocated context.
- Ollama's OpenAI-compatible `/v1` endpoint ignores per-request `num_ctx`.
  Configure `OLLAMA_CONTEXT_LENGTH` on the server or `PARAMETER num_ctx` in
  the model's Modelfile, within the server's memory capacity.
- Match AIRecon's `llm_context_window` to the actual server context. Changing
  only the client setting does not allocate a larger context on Ollama.
- If prompt and tool schemas alone exceed that capacity, use a larger supported
  server context or a different model/backend; trimming tool results is not enough.

The HTTP client does not retry an identical rejected context. The agent can
retry up to three times after shrinking the actual serialized request and
reducing the output reservation. The learned byte ceiling is saved with the
session. If required instructions, schemas, or the latest complete tool group
cannot fit, it stops with an actionable error rather than repeatedly compacting
the same state. Common context errors from other OpenAI-compatible backends use
the same bounded recovery; only the Ollama-specific error gets Ollama advice.

All user instructions and explicitly protected context remain mandatory.
The request estimate includes tool schemas, call arguments and JSON framing.
It is a conservative UTF-8-byte heuristic, not exact model tokenization.
Restart AIRecon after applying code/config changes; an already-running process
does not reload modified Python modules automatically.

## Recoverable output compression: RTK and Caveman

Install the optional native tools on the machine running the AIRecon proxy:

```bash
python -m airecon.compressors_install
```

This downloads pinned, SHA-256-verified Linux x86-64/aarch64 release assets into
`~/.airecon/bin`: RTK OSS `v1.1.0` and Caveman Engine `bin-v4.0.2`.
The manifest ships in `airecon/proxy/data/compressors.json`. It does not install
shell hooks, rewrite scan commands, add LLM proxies, or change Ollama/systemd.
Existing different binaries are not overwritten. Unsupported platforms retain
built-in compaction and can supply their own compatible executables.

- RTK `pipe` is preferred for development/test output; Caveman `compress` is
  preferred for other tool output. They are alternatives, not stacked lossy passes.
- Discovery checks `AIRECON_RTK_BIN` / `AIRECON_CAVEMAN_BIN`, then the managed
  install, then PATH. Set either variable to `off` to disable that native tool.
- Missing, failed, oversized, or timed-out native output falls back to built-in
  compaction. Native invocations have a three-second timeout and fixed argv,
  not shell execution. No API or network compression service is configured.
- Tool output is saved locally before replacing it with a preview, including
  short results that a future summary may omit. Artifacts are content-addressed
  UTF-8 files with SHA-256 checks under the target workspace's
  `output/context/<session-key>/` directory. Files use mode `0600`.
- Previews prioritize error/finding lines, mark omissions explicitly, and carry
  a `read_file` path to the original. A preview is never proof of a clean scan.
  Exact `read_file` results are not passed through lossy native compressors;
  paginate large reads when the latest tool group cannot fit.
- Archive failure keeps the original result; the request budget can stop the
  run rather than pretend the omitted evidence is recoverable. Old sessions
  whose results were already truncated cannot have those missing bytes restored.

Licensing is component-specific: this integration invokes the Apache-2.0 RTK
OSS CLI, not RTK's separately licensed engine/proxy. Caveman's standalone engine
is optional too; retain upstream release licenses and third-party notices when
redistributing binaries. Neither executable is bundled in AIRecon's wheel.

## Stability Exit Criteria

### Invalid or empty native tool arguments

A model can emit an empty tool request, incomplete JSON, or a tool response
truncated by its output limit. The client rejects those calls before completing
the batch; malformed JSON is never replaced with invented `{}` arguments.
Required fields are checked against the advertised schema, while the existing
scope/security validators still run before execution. Empty strings remain valid
where the tool contract permits them (for example empty file content).

The agent makes at most two correction requests with the relevant schema and
then stops with `invalid_tool_arguments` if the model cannot correct its output.
It neither invents a shell command nor applies the connection-error backoff to
this model-output error. In-band streaming errors also fail instead of finalizing
partial calls. Restart AIRecon to load this behavior in an existing process.

### Release criteria

AIRecon can be labeled "stable" after all are true:

1. `pyright airecon tests` reports **0 errors**.
2. Full `pytest` suite finishes without hangs/timeouts.
3. One automated smoke run validates startup + chat + tool call + report flow against real local dependencies.

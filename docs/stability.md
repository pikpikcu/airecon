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

## Provider conversation state

- Native Anthropic and OpenAI-compatible requests share trailing-instruction
  normalization: a retry after a text-only assistant response stays a final
  user turn, rather than becoming an unsupported assistant prefill. Pending
  native tool-use blocks and their signed thinking blocks remain unchanged.
- OpenAI-compatible tool-call streams preserve opaque `extra_content`, including
  Gemini's `google.thought_signature`, across deltas and replay.
- Explicit `reasoning_content` returned by a provider is retained separately
  from UI-only `thinking` and stored in conversation history. Filtering old UI
  thinking does not remove provider state.
- `llm_reasoning_replay: auto` sends stored reasoning back only where it is
  needed: DeepSeek API hosts and `deepseek/`-prefixed gateway models, whose
  thinking mode rejects tool requests that omit earlier reasoning, and any
  host+model whose backend returns a 400 asking for missing `reasoning_content`
  (learned once per process for that host, then the same request is resent;
  streaming and non-streaming calls both learn). A locally served
  DeepSeek-named model is not matched by name. Local and other gateways do not receive it, and the request
  budget counts exactly what is sent. `always` and `off` force the behavior;
  `off` is never overridden by learning.
- Missing reasoning history or thought signatures are not treated as evidence
  that the model lacks optional reasoning-parameter support. No replacement
  signatures or reasoning text are fabricated. Sessions that already lost this
  state cannot recover it from the fix; start a new session in that case.

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
  Exact `read_file` results are not passed through lossy native compressors,
  in either tool-result role.
- `read_file` pages are bounded in bytes as well as lines. One result is at
  most 8192 bytes measured as JSON-escaped UTF-8 (7680 for file content, 512
  reserved for the page header), and contains whole lines only, with their
  original line endings. A page closes at `limit` lines or at the byte bound,
  whichever comes first; `next_offset`, `has_more` and `byte_limited` say where
  to continue. Small files that fit are still returned verbatim with no header.
- A single line that cannot fit a page is never cut: the result is a short
  `line_too_large` notice with the line number, byte length, byte offset and an
  `execute`-based retrieval plan, and no file content. Advisory samples follow
  the same rule and label any line they leave out. The file itself is never
  modified. Bytes that are not valid UTF-8 are flagged with `lossy_decode`.
- When a context window is tight, optional tool schemas are left out of the
  request before any instruction or exact read is touched, both on the normal
  path and when recovering from a backend context rejection. The core tools
  (`execute`, `read_file`, `web_search`, `create_note`,
  `create_vulnerability_report`) are always sent. If instructions, core schemas
  and the latest exact tool group still cannot fit, the run stops with a
  context-budget error instead of dropping them.
- Archive failure keeps the original result; the request budget can stop the
  run rather than pretend the omitted evidence is recoverable. Old sessions
  whose results were already truncated cannot have those missing bytes restored.
- Older tool groups are evicted whole (assistant turn plus every result, in
  both `tool_response_role` modes) into line-oriented archives under
  `output/context/<session>/` that `read_file` can page: a legend line, then
  `@ ` JSON headers, `| ` content lines and `» ` continuations for lines split
  to stay under the page byte bound. The latest real tool group and its exact
  `read_file` page are never evicted, and a second budget pass on an
  already-packed history changes nothing.
- The single archive notice is a system-role message, so it joins the system
  prompt on the wire instead of becoming a synthetic assistant turn (which
  DeepSeek thinking mode and Anthropic signed thinking would reject).

Licensing is component-specific: this integration invokes the Apache-2.0 RTK
OSS CLI, not RTK's separately licensed engine/proxy. Caveman's standalone engine
is optional too; retain upstream release licenses and third-party notices when
redistributing binaries. Neither executable is bundled in AIRecon's wheel.

## Python execution: no host REPL (python_session removed)

The `python_session` tool has been **removed**. It executed model-generated
Python on the proxy host via in-process `exec()`/`eval()` — giving model code
the host filesystem, subprocess and network with no sandbox. That seam is
closed fail-closed:

- The in-process session machinery (`_PythonSession`) is deleted from
  `airecon/proxy/agent/executors_utils.py`.
- The `python_session` handler still exists only as a defense for persisted
  or attempted old calls: it rejects every call with a structured
  `{"success": false, "error": ...}` before any code execution or
  utility-state side effect. Both dispatch entry paths (`_dispatch_tool` and
  `_execute_tool_and_record`) reach this rejection.
- The tool is removed from the advertised catalog (`tools.json`) and from
  `tools_meta.json` (`callable_core_tools`), so models are no longer offered
  a Python REPL.
- There is deliberately **no configuration switch** that re-enables host
  execution.

**Limitation / intended usage:** to run Python, use the `execute` tool so the
code runs INSIDE the Docker target sandbox (for example a `python3 - <<'PY'`
heredoc command through `execute`). No persistent, stateful Python REPL is
offered; state must be kept in workspace files between `execute` calls.
Pinned by `tests/proxy/agent/test_python_session_isolation.py`.

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

# Stability & Quality Status (2026-11-12)

This page documents the current, test-backed stability state of AIRecon.

## Executive Summary

The current candidate passed its local regression and configured static-analysis
gates, including the verified `/api/status` sticky-health fix. No result here
certifies every real integration or establishes that AIRecon is free of bugs.

- Baseline: 2575 tests passed and 5 skipped before these fixes.
- Candidate: 2666 tests passed and 5 skipped on both Python 3.12 and 3.13,
  with 91 additional cases against the original baseline.
- Configured Pyright, Ruff, and the medium/high Bandit gate are clean.
- The installed wheel passed three consecutive localhost API + real Docker +
  Playwright/Chromium + headless Textual TUI + report round trips. The LLM endpoint
  was an explicitly synthetic protocol fixture, not a real model acceptance test.
- Public release acceptance remains open: remote CI still refers to the old PR
  head, and the chosen real provider/model and production rollout are unverified.
- Claude and GLM supplied read-only reviews. Grok attempts failed with HTTP 402
  or insufficient credits and do not count as a completed review.

This snapshot supersedes the March type-error and hanging-suite observations.
The work is local on `airecon-openai`; PR #130 was still OPEN when checked.

## Validation Snapshot

The full suite ran with Python 3.12.12 and 3.13.15 in disposable Bubblewrap environments:
the checkout was read-only, HOME/XDG paths were private, process and network
namespaces were isolated, and runtime files were written outside the repository.
Optional native compressors were disabled for deterministic local tests.

Core verification commands (pytest additionally supplied private temporary,
JUnit, and coverage-output paths inside the isolated environment):

```bash
python -m pytest tests/ -q --tb=short -p no:cacheprovider \
  -p pytest_timeout --timeout=60 --cov=airecon --cov-fail-under=52
ruff check .
pyright --outputjson
bandit -r airecon/ -x '**/tests/**,**/__pycache__/**' --skip B105,B107 -ll
git diff --check
```

Observed results:

- Python 3.12.12: **2665 passed, 5 skipped**, in 164.13 seconds. One upstream
  Starlette deprecation warning concerns its test-client httpx adapter.
- Python 3.13.15: **2665 passed, 5 skipped**, in 134.93 seconds, without warnings.
- Both runs have no test failures/errors; coverage is **63.54%**, above the
  configured 52% threshold. Neither run proves real-model planning quality.
- All five skips are existing output-merge tests whose feature is not implemented;
  they are not successful feature checks.
- Configured production type check: **0 errors and 0 warnings**, 108 files analyzed.
  This is `pyright` using the project configuration, not a type check of every test.
- Ruff and whitespace checks: passed.
- Bandit: no medium/high findings with B105 and B107 excluded; this is not a
  claim that all security findings or all lower-severity checks are absent.
- The wheel built in a read-only checkout, installed in a separate clean Python
  3.12 environment, and passed dependency compatibility checks. Packaged source
  and required data/container assets matched the candidate. CLI version/help,
  start help, and proxy help all exited successfully outside the checkout.
- Three installed-wheel runs exercised a real localhost API, TUI shell rendering,
  Playwright CDP connection to Chromium, synthetic LLM wire response, and report
  file round trip. A uniquely named disposable Docker sandbox also preserved
  partial timeout output, spared a concurrent job, reaped the timed-out job,
  survived misleading stderr, and recovered after deliberate container removal.
  The disposable container was confirmed absent afterward.
- Ten follow-up syntax-valid mutations were killed by named regressions covering
  SQLite locks/transactions/ownership/publication, browser cancellation/shared
  startup/reaping, partial startup cleanup, and LLM health status. No fixture or
  import errors counted as kills. The earlier scope/redirect audit also killed
  five guards before this follow-up.
- Gitleaks found no leaks in the tracked diff or the new test files. This is a
  bounded candidate scan, not a claim about all stored assessment data.

## Reproduced Fixes

The parent validated accepted review hypotheses with failing regression tests
before applying fixes. Unit tests isolate external boundaries. Installed-wheel
acceptance additionally exercises real disposable Docker, Playwright, localhost
HTTP, and headless TUI components; only the LLM model itself is a protocol fixture.

| Area | Corrected behavior | Regression coverage |
| --- | --- | --- |
| Docker recovery | Ordinary stderr cannot reset a running sandbox; failed inspection is unknown, not confirmed loss. | `tests/proxy/test_docker.py` |
| Scope failures | Execution and `/api/shell` fail closed if the scope guard raises. | `test_network_scope_regressions.py`, `test_server.py` |
| Host extraction | Path-qualified local files are not hosts; single/triple-slash URLs, scheme-relative hosts, and escaped slashes remain checked. | `test_scope_guard.py` |
| MCP policy | Scope is checked at the shared transport boundary using raw nested strings and keys, including supported JSON-encoded argument objects. | `test_mcp_scope.py` |
| Workspace operands | Absolute container paths retain their meaning after `cd` and in symbolic links. | `test_workspace_path_remap.py` |
| Command timeout | Partial output survives; cleanup targets only the invocation marker, not unrelated process names. | `test_docker_job_cleanup.py` |
| Parallel cancellation | Only newly added tool blocks are removed in `finally`; pre-existing blocks survive. | `test_parallel_tool_cleanup.py` |
| HTTP redirects | Each hop is bounded and scope-checked; loops, malformed destinations, HTTPS downgrades, and cross-origin request-body forwarding are rejected. | `test_http_observe_redirects.py` |
| Browser evaluation | The CAPTCHA DOM coroutine is scheduled and awaited on the browser loop. | `test_browser.py` |
| Fuzzer evolution | Vulnerability-type metadata reaches the evolution grouping. | `test_fuzzer.py` |
| Finding verification | Verification uses captured response evidence and the actual status, not the input payload or an invented HTTP 200. | `test_fuzzer_verification_evidence.py` |
| MCP lifecycle | Stdio servers that ignore EOF are killed and reaped, including cancellation during cleanup. | `test_mcp_process_cleanup.py` |
| Integration fixture | Filesystem round trips write into the test workspace, not the real checkout workspace. | `tests/test_integration.py` |
| SQLite ownership/concurrency | Managers own connections, serialize each connection, reserve writes before read/update sequences, and roll back failed batches. Busy writers do not stall readers on another manager. | `test_memory_concurrency.py` |
| SQLite initialization | Failed schema setup closes its connection; the singleton is published only after successful connection and can retry a failed initialization. | `test_memory_concurrency.py` |
| Browser startup | Startup has a bounded retry/fallback budget, overlapping callers share one future/deadline, and timeout/cancellation cleans up the driver and Docker exec process. | `test_browser_startup.py` |
| Server lifespan | Partial startup, serving exceptions, and initialization cancellation still clean up created resources; one cleanup failure does not skip other resources. | `test_server_lifecycle.py` |
| LLM readiness | Authentication, quota, missing endpoints, malformed model payloads, and HTML proxy fallbacks no longer appear connected. A successful models response is required. | `test_llm_health_contract.py` |

## Remaining Risks and Untested Boundaries

- The former SQLite and browser-startup risks were reproduced and corrected.
  Cancellation during Playwright's own driver startup, before it returns a handle,
  was not separately fault-injected and is not certified by the later-stage mocks.
- Console-log stringification was not shown to cause measurable lag; no
  performance fix was applied on that hypothesis alone.
- Claude's lower-priority long-line retrieval advisory and absolute-host-path
  file creation concerns were not reproduced or traced through their callers;
  neither is certified as a fixed defect.
- Scope parsing is a heuristic, not universal network isolation for arbitrary
  commands or third-party MCP implementations. Unqualified dotted filenames
  still receive conservative host treatment.
- Real Docker recovery/job cleanup and live Playwright/API/TUI/report round trips
  are now observed. An autonomous workflow using the chosen real model/provider
  still needs environment-specific acceptance; synthetic protocol replies do not
  establish model correctness, performance, or production provider availability.
- Both supported Python versions pass locally. Remote PR checks were green for
  `5e4b641`, not this uncommitted candidate; they cannot certify the new changes.
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

1. The configured production-source `pyright` gate reports **0 errors**;
   test-source type checking is not implied by that configuration.
2. Full `pytest` suite finishes without hangs/timeouts.
3. Installed-package startup + chat/tool/report flows pass with the chosen real
   provider/model and approved local dependencies, not only synthetic replies.
4. Exact-candidate remote CI and environment-specific rollout/rollback evidence
   are recorded before declaring a production release.

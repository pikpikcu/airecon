# Changelog

## [v1.7.1-beta] - 2026-06-15

### Added — Zero-FP verification on the LLM finding path
- feat(verify): wired `VerificationEngine` into the LLM-discovered report path. Previously active replay verification only ran on the fuzzer path; LLM-authored findings passed the text-based pre-report gate and were written without any runtime corroboration. The report tool now runs an active runtime check (`_runtime_verify_report`) on top of the existing gate.
- feat(verify): the runtime check is **type-aware and non-monotonous by design** — it corroborates and stamps true positives with verification metadata, but blocks *only* deterministically-reproducible classes (`xss`, `sql_injection`, `ssti`, `path_traversal`, `command_injection`, `open_redirect`, `ssrf`, `xxe`) under strict guards: confident type extraction, GET/HEAD method, a live endpoint (replay saw status < 400), replay attempted ≥2 times and failed, negative test passed, and not flagged a false positive. Stateful, auth-dependent, novel, POST-only, or unreachable findings are **never** blocked by replay — they rest on recorded session evidence and the PoC.
- feat(verify): expanded runtime confirmators — added `open_redirect` (3xx `Location` to the injected host), `ssrf` (cloud metadata markers: `169.254.169.254`, `metadata.google.internal`, IAM credential leakage, `root:x:`), and `xxe` (LFI file indicators + `/etc/passwd` content) detection, plus supplemental verification payloads for each.
- feat(report): severity/verification grounding — reports now render a `## Verification` section (Status + runtime confidence + legend) and surface `verification_status` / `verification_confidence`, so severity is anchored to whether the finding actually reproduced at runtime rather than to the model's unverified claim.

### Added — target-specific novel-vector discovery (anti-monotony)
- feat(agent): reworked `novel_discovery` from random-canned to evidence-driven and LLM-driven. The old engine picked "innovative tactics" via `rng.choice()` from a fixed 20-item list on a mechanical `iteration % 3/5` cadence, and built "novel vectors" from a random md5 seed with a hardcoded description and a `len(findings)`-only confidence — i.e. it injected the same generic checklist into the agent's context every run regardless of target. Replaced with: (1) a themed tactic library where each tactic is selected only when its theme keywords actually appear in the current findings (deterministic, target-specific, no filler when nothing matches); (2) a finding-grounded emergent vector that fires on real evidence (≥3 findings AND ≥2 distinct signal types), with a stable id and confidence grounded in the signal count; (3) an optional async `generate_llm_novel_vectors()` that asks the configured LLM for non-obvious, finding-specific attack paths and caches them by findings-signature for the sync prompt builder to consume. Wired into `_run_iteration_housekeeping` (every 4th iteration, ≥2 vulns); no-ops cleanly when the backend is unconfigured and falls back to the evidence-derived path. Output contract (`innovative_tactics`/`novel_vectors`/`combinations`/`recommendations`/`anomalies_detected`) is unchanged, so `chain_planner` and the prelude prompt builder are unaffected.

### Improved — the brain learns only from verified outcomes (grows smarter, not dumber)
- feat(intelligence): the cross-session memory brain (`_save_new_findings_to_memory`) now learns **only from VERIFIED / high-confidence findings**. Previously every session vulnerability — verified or not — was persisted, so accumulated false positives would degrade the agent over time. Gated by `intelligence_learn_only_verified` (default True): a finding is persisted only if `verified`/`replay_verified` is set or `verified_confidence ≥ intelligence_learn_min_confidence` (default 0.65). This makes "the longer you use it, the smarter it gets" actually true — the brain compounds proven knowledge instead of noise. Disable the gate to learn from all findings (noisier).

### Improved — memory & datasets used actively as the brain
- feat(intelligence): cold-start dataset knowledge. When cross-session memory has not yet learned patterns for the detected stack (fresh install / new target), the agent now injects a KNOWLEDGE BASE brief built from the static `tech_correlations` dataset (known issues, paths-to-check, tools) keyed to the discovered technologies — so datasets are used as the brain from iteration 1 instead of only after history accumulates. Memory-learned patterns take over automatically as they become available.
- feat(intelligence): memory/dataset usage is now far more active and config-driven. Learned-pattern / cold-start recall runs every `intelligence_memory_recall_interval` iterations (default 4, was a hardcoded 8) and dataset/finding correlation every `intelligence_correlation_interval` (default 6, was a hardcoded 10). Within-session learning kicks in faster: `intelligence_adaptive_min_observations` default lowered 3 → 2, so the agent starts acting on what worked/failed this session sooner.

### Improved — smarter compaction & memory
- feat(memory): conversation truncation now preserves protected system context **by type** instead of blindly keeping the last two. The freshest of each protected class (STRICT_SCOPE_MODE, PINNED CONTEXT, RECOVERY STATE, COMPRESSION SUMMARY, MEMORY BRAIN, REPORT PHASE, RECOVERY MODE) is retained, bounded by `memory_protected_context_max` (default 6) — so scope, confirmed findings, recovery state and the rolling handoff summary can no longer be dropped just because several protected messages accumulated. The first user message (original task) remains explicitly preserved.
- feat(memory): the rolling memory-handoff summary re-injection budget (`memory_compression_summary_chars`, default 700) and the per-message compressor input cap (`memory_compression_input_per_msg_chars`, default 350) are now config-driven and **scale ×2 for large-context models** (effective context ≥ 100K) — long sessions on roomy models retain more detail in the Goal/Progress/Findings/Decisions handoff instead of being clipped at a fixed size. Defaults are unchanged, so behavior on standard-context models is identical.

### Added — observability (Tier 3)
- feat(status): `/api/status` now reports a tool/service readiness dashboard (`tools`: sandbox, cli_tools, browser, mcp, caido, searxng) plus the active `scan_profile` and `scope` posture (mode/allowlist/denylist/audit flag) so the operator can see what's ready and the active safety stance.
- feat(progress): `get_progress()` (`/api/progress`) enriched with a timeline view — current `phase`, `last_tool`, `last_command`, `last_tool_status`, and a `stuck` flag (consecutive failures ≥ stagnation threshold) — for a live "what is the agent doing" panel.
- feat(models): `/api/models` adds a no-network per-model `capabilities` map (resolved reasoning strategy, with models the runtime probe already learned to reject reasoning reported as `off`), complementing the existing active-model/thinking info.

### Added — platform features (data-driven, no hardcoding)
- feat(report): persist machine-captured evidence per finding. Runtime verification now returns its replay evidence bundle (payload/status/length/confirmed per attempt); `create_vulnerability_report` writes it to `<slug>.evidence.json` beside the report and renders an Evidence table in the `.md` that links the artifact — findings are now reproducible/defensible beyond the model's PoC text.
- feat(report): finding lifecycle label (`VALIDATED` / `SUSPECTED` / `INFORMATIONAL`) derived deterministically from verification status, shown in the report header and returned in the result.
- feat(report): `.md` Classification section for optional LLM-supplied `cwe` / `owasp` (added to the `create_vulnerability_report` tool schema in `tools.json`).
- feat(scope): config-driven scope guard + persistent audit log (`airecon/proxy/scope.py`). `scope_allowlist`/`scope_denylist`/`scope_enforcement` (off|warn|block) gate the `execute` path by target host (apex+subdomain and `*.` wildcard matching); every command is recorded to `~/.airecon/audit/audit.jsonl`. Default `warn` is non-breaking; `block` refuses out-of-scope hosts.
- feat(config): data-driven scan profiles (`data/scan_profiles.json`, key `scan_profile`): quick|standard|deep|stealth|ctf|bugbounty. A profile is a baseline override layer applied between defaults and the user's `config.yaml` (user keys still win); `standard` is identity so default behavior is unchanged. No hardcoded profile branches.
- chore(learning): `distill_insights` now routes through `LLMClient` (gains the shared 5xx-retry + reasoning-capability + timeout plumbing) instead of a bespoke aiohttp call; removed dead locals.

### Added — `/scope` TUI command to manage scope live
- feat(scope): set the scope guard from the TUI without editing config.yaml. `/scope allow <h1> <h2> …`, `/scope deny <hosts…>`, `/scope remove <hosts…>`, `/scope mode off|warn|block`, `/scope clear`, and `/scope` (show). Backed by a new `POST /api/scope` endpoint and `config.update_config_values()` which persists to config.yaml (preserving comments/sections) and reloads, so the running scope guard picks up changes immediately. Added to the command palette/hints and `/help`.

### Fixed — new config keys now surfaced in generated config.yaml
- fix(config): the generated `config.yaml` only writes keys that are in BOTH `_ESSENTIAL_CONFIG_KEYS` and a `_CONFIG_CATEGORIES` group. All keys added this release (`notify_webhook_url`/`notify_completion_flag`, `scan_profile`, `scope_allowlist`/`scope_denylist`/`scope_enforcement`/`audit_log_enabled`, `tool_health_probe_binaries`/`tool_health_probe_ttl`, the `intelligence_*` recall/learning keys, and the `memory_*` compaction keys) were active via defaults but invisible in the file, so users couldn't discover or edit them. Added new commented sections — Scan Profile, Scope Guard & Audit, Notifications, Tool Health, Intelligence & Memory — and registered the keys as essential, so a freshly generated config.yaml now includes them with descriptions. Existing configs are migrated on next load.

### Fixed — proxy startup failures now produce a crash log + visible reason
- fix(startup): the proxy worker imported `airecon.proxy.server` OUTSIDE the crash-handling try, so an import-time failure (missing dependency, bad proxy module) killed the thread silently — the TUI showed "Proxy thread stopped before responding. Check airecon_proxy_crash.log" but no log was ever written. The import is now guarded; any import/startup failure writes the crash log and records a human-readable reason. `run_server()` returning unexpectedly (e.g. proxy-port conflict) is also captured. All proxy error messages now print the FULL crash-log path (`get_crash_log_path()`, e.g. `/tmp/airecon_proxy_crash.log` — not just the bare filename, which was unfindable on macOS/Windows temp dirs) plus the actual error text.

### Fixed — entrypoint chown no longer clobbers host files (P1 safety)
- fix(docker): `docker-entrypoint.sh` ran `chown -R` + `chmod -R` on the entire `/workspace` host bind-mount, rewriting ownership/permissions of the user's real files (git objects, secrets, source, `@`-referenced copies) — the top risk flagged in the code audit. It now adjusts only the mount-point directory (non-recursive), so the sandbox user can create its own output subdirs while every existing file inside keeps its original ownership and permissions.

### Added — operability (P3)
- feat(status): real sandbox tool-health probing. `/api/status` `tools.cli_tools` now reflects an actual cached `which` probe of `tool_health_probe_binaries` (default nuclei/nmap/ffuf/httpx/katana/subfinder/sqlmap) inside the sandbox, with per-binary detail in `tools_detail`, instead of a docker-readiness proxy. Cached for `tool_health_probe_ttl` (300s); falls back to the proxy when the probe can't run.
- feat(notify): completion notifications (`airecon/proxy/notify.py`). When a scan finishes, AIRecon optionally POSTs a JSON summary to `notify_webhook_url` (Slack/Discord/generic) and writes a `COMPLETE.json` summary into the target's workspace folder (`notify_completion_flag`, default on). Best-effort and non-blocking — wired at the agent loop's clean-finish hook.
- feat(resume): richer resume history. The session now keeps a persistent `recent_turns` buffer (last 400 raw user/assistant/tool turns, deduped) that survives conversation compaction, so resuming replays real chat + tool calls even after the live conversation was compressed into summaries. `/api/history` prefers this buffer for the chat replay.

### Fixed — resume session now shows real prior history + tool calls
- fix(resume): `/api/history` dropped ALL system messages, so once a session's conversation had been compacted into summaries, resuming showed almost nothing ("Restored 1 messages"). It now (1) keeps chat (user/assistant/tool) turns including assistant `tool_calls`, (2) keeps progress-bearing system messages (compression summary, pinned findings, phase context) while still dropping ephemeral ones, and (3) prepends a recap synthesized from durable session state (`_build_session_recap`: target, completed phases, tools run, recorded findings, scan count). So a resumed session shows what was actually done before — chat history, tool calls, and progress — even after heavy compaction.

### Fixed — /shell now scope-guarded + audited
- fix(shell): the `/api/shell` (TUI `/shell`) endpoint previously ran commands via `DockerEngine.execute_tool` directly, bypassing the scope guard and audit log that the agent's `execute` path uses. Manual shell commands now go through the same `get_scope_guard()` check + `audit_log()` — out-of-scope hosts are refused under `scope_enforcement=block` and every command is recorded — so the audit trail is complete and the security posture is consistent across agent and manual execution. Default `warn` mode keeps it non-blocking. (The existing TUI-stability blocklist for tmux/screen/etc. is unchanged.)

### Fixed — quit hang (Ctrl+C → "yes")
- fix(tui): `action_quit` could freeze the app on quit while a scan was streaming. It closed the shared HTTP client while the SSE stream worker still held an in-flight response on it (which can block), and never cancelled that worker. Now it (1) cancels the chat-stream worker first so the connection is released, (2) hard-bounds both `POST /api/stop` and `aclose()` with `asyncio.wait_for(..., 2s)`, and (3) always reaches `self.exit()` via a `finally`, so a slow/stuck server or lingering connection can never hang the shutdown. Covered by `tests/tui/test_action_quit_no_hang.py` (incl. simulated stop/aclose stalls).

### Fixed — bugs found in post-merge audit
- fix(config): `Config.load()` was not thread-safe — `_write_yaml_with_comments` wrote the YAML in place (non-atomic), so when several threads loaded a config that needed migration (file present but missing newer keys), one thread could read the file mid-write, parse it as empty/None, and reset to `DEFAULT_CONFIG` (losing e.g. `openai_model`). Surfaced as a flaky failure of `test_config_survives_concurrent_reads` (~1/3 runs). Fixed by writing atomically via a temp file + `os.replace()`; the failing combo now passes 6/6 under stress.
- fix(report): removed two bare `except Exception:` blocks in `executors_reporting.py` (introduced with the runtime-verification work) that violated the project's no-bare-except convention (caught by `test_no_bare_except_exception`); they now bind `as _e` and log at debug.

### Changed — full Ollama→LLM rename + de-hardcoded recon/exploit techniques
- refactor(naming): removed every `ollama` identifier from the codebase (244 occurrences across ~53 files) now that the backend is OpenAI-compatible. `self.ollama`→`self.llm`, `ollama_client`→`llm_client`, the `/api/status` JSON key `ollama`→`llm` (server emit + TUI consume in sync), UI step id `step-ollama`→`step-llm`, reactives `ollama_status`/`ollama_degraded`→`llm_*`, all helper/var/test names, and docstrings/comments. Verified: 0 remaining `ollama` mentions in `airecon/`, 0 undefined names (pyflakes), package imports clean, AgentLoop MRO intact, ~1300 tests green. (Docs under `docs/` still contain historical changelog entries and setup steps that reference Ollama — those need prose rewriting, not a mechanical rename, and are tracked separately.)
- refactor(fuzzer): the tech-stack payload augmentation (`_augment_payloads_for_target`) no longer hardcodes per-tech `if "mysql"/"django"/"windows"…` branches with inline payloads. The vuln_type→tech_token→payloads mapping moved to `fuzzer_data.json` (`TECH_PAYLOAD_AUGMENTS`) and the code is a generic data-driven lookup. Behavior verified identical.
- refactor(fuzzer): `get_priority_parameters` no longer hardcodes `if "login"/"admin"/"api"… in url` branches; the url-keyword→priority-params mapping moved to `fuzzer_data.json` (`PRIORITY_PARAM_HINTS`, ordered for first-match-wins). Behavior verified identical (incl. the `/admin/users` matches-"user" precedence quirk).
- refactor(agent): REMOVED the prelude "expert testing" narrow keyword→canned-hint matcher entirely (`if "api"/"user_id"/"search"… in url_str` → "fuzz with ffuf" / "change IDs 1,2,3,999"). It was both dumb and dead: crude substring matching (e.g. "profile" matched "file"), the same canned text every run biasing a capable model toward a fixed playbook, and — critically — its generated strings were discarded because `testing.txt` has no `{expert_patterns}` placeholder, so the matcher only ever acted as a trigger. The senior-pentester methodology (`prompts/testing.txt`) is now injected on a REAL signal — an actual discovered attack surface (endpoints + concrete injection points / findings) — and is grounded with the target's real endpoints/params so the model reasons over real data instead of generic keyword guesses. (An interim `data/expert_url_hints.json` that merely relocated the hardcoding was created and then removed in favor of this.)
- note: verification evidence signatures (e.g. `root:x:` for LFI, `<script>…alert` for XSS) are intentionally kept inline — they are the deterministic definition of "this vuln reproduced", not tunable heuristics, and externalizing them would weaken the zero-FP guarantee.

### Changed — removed model-name hardcoding (automatic capability detection)
- fix(llm): the thinking-strategy resolver no longer guesses reasoning capability from a hardcoded model-name list (the old `qwen3/glm/o1/o3/gpt-5/...` substring tuples, which never scaled and silently mishandled Claude). `_resolve_thinking_strategy` now has **no model list at all**: an explicit `llm_thinking_request_mode` (off/reasoning_effort/enable_thinking) is honored, and `auto` uses the OpenAI-standard `reasoning_effort` parameter. Capability is then discovered **at runtime** — if the backend returns the standard HTTP 400 "unsupported parameter" for reasoning (exactly what OpenAI returns for non-reasoning models), the client strips the param, records the model in `_reasoning_unsupported`, and retries the same request. So GPT, Claude, Qwen, Gemini, Grok, DeepSeek and any future model are handled automatically, on any gateway, with no code or config edits. `enable_thinking` (a non-standard vLLM/SGLang chat-template flag) remains an explicit opt-in. New `_is_unsupported_reasoning_error` / `_maybe_degrade_reasoning` helpers implement the probe-and-degrade. (Supersedes the interim `data/thinking_markers.json` approach, which was just relocated hardcoding and has been removed.)
- fix(agent): conversation-compaction thresholds (and the `keep_recent` window) are no longer gated on a hardcoded `"qwen" + 72b/120b/122b` model-name check. `loop_cycle_prelude` now decides the "roomy context" tolerance from the effective context window (`_ROOMY_CONTEXT_TOKENS = 100K`), so every large-context model (Claude 200K, GPT-5, Gemini, large Qwen, …) gets the lenient pressure/compress thresholds — not just Qwen.
- fix(agent): the LLM-compression watchdog timeout in `models.compress_with_llm` no longer keys off `"122b" in model.lower()`. It now scales from the configured `llm_timeout` (bounded to a 20–45s band), so slow models/gateways get headroom automatically without any model-name special-casing.

### Changed
- feat(llm): completed migration from Ollama-only to an OpenAI-compatible LLM backend. The agent now talks to any OpenAI-compatible gateway (LiteLLM / vLLM / hosted / a local gateway) via `openai_base_url` / `openai_api_key` / `openai_model`; a local Ollama instance is still usable when proxied through such a gateway.
- feat(llm): thinking/reasoning is plumbed end-to-end on the OpenAI path — `reasoning_content`/`reasoning` deltas are surfaced as thinking, `reasoning_effort` is honored, and `chat_template_kwargs.enable_thinking` is auto-set for Qwen3/vLLM-style models.
- docs(branding): README and docs badges now describe the LLM backend as "OpenAI-compatible" instead of "Ollama (local)".

### Removed
- chore(config): removed 4 dead scalar config keys with no consumers — `pipeline_recon_budget`, `pipeline_analysis_budget`, `pipeline_exploit_budget`, and `pipeline_report_budget`. The misleading `pipeline_report_budget` "(0 = blocked)" description implied reporting could be capped; in reality per-phase tool budgeting is handled by the `pipeline_tool_budget_*` keys and `create_vulnerability_report` is never throttled. Removed from the config schema, category list, `Config` dataclass, and validation ranges.

### Fixed — code-audit findings
- fix(docker): added `DockerEngine.close()` (F-001). The server lifespan shutdown called `await engine.close()` on a class that only had `stop_container()`/`force_stop()`, raising `AttributeError` and leaving a dirty shutdown. `close()` now cancels background tasks and kills active child processes (container left in place).
- fix(llm): `LLMClient.close()` now resets `_httpx_client`/`_initialized` (F-006) so a later `_async_init()` rebuilds a fresh client instead of re-using a closed one.
- fix(llm): transient HTTP 5xx from the backend is now retried (F-007). `_post()`/stream paths previously raised a bare `RuntimeError` that short-circuited the retry branch; they now raise `LLMBackendHTTPError(status_code)`, and the complete/stream loops retry 5xx while still failing fast on 4xx.
- fix(config): corrected the numeric-bounds key typo `model_tool_result_chars` → `model_max_tool_result_chars` (F-009) so the field is actually range-validated.
- fix(config): `reload_config(config_path=...)` can now re-point at a different config file instead of staying stuck on the first sticky `_config_path` (F-010).
- fix(agent): fast conversation compression now runs `_repair_tool_pairs()` before assigning the kept window (F-011), preventing severed assistant-tool_call / tool-result pairs from producing an invalid request to strict OpenAI-compatible backends.
- fix(docker): `DockerEngine` now honors the configured `docker_image` as the source of truth for inspect/build/run (F-004); container naming stays on `CONTAINER_PREFIX`.
- fix(tui): startup no longer triggers an implicit Docker build when `docker_auto_build` is false (F-005); it checks `image_exists()` and prints a manual-build hint instead.
- fix(config): purged remaining stale `ollama_*` functional config lookups and renamed user-visible Ollama log/label strings left over from the migration.

### Validation
- tests: config suite green (`AIRECON_OPENAI_MODEL` unset); `airecon/proxy/config.py` compiles and `DEFAULT_CONFIG` / `Config` build cleanly with the budget keys removed.
- tests: new `tests/proxy/test_runtime_report_verification.py` (6 cases) covers the type-aware block/no-block logic — reliable-type-unreproducible blocks, confirmed/stateful/POST/unreachable/no-injection-point all pass through. Verification + reporting suites green (100 passed).
- tests: new `tests/proxy/test_audit_fixes_v171.py` (6 cases) locks in the audit fixes — close() state reset, 5xx-retry/4xx-no-retry, bounds-key correctness, orphan tool-pair repair, DockerEngine.close presence. Config/docker/llm/verification suites green (49 passed).
- tests: new `tests/proxy/test_thinking_capability_auto.py` (14 cases) proves there is no model-name list (auto resolves uniformly), the 400 "unsupported parameter" detection, the strip-and-remember degrade, the per-model skip after probing, and an end-to-end stream test where a 400 triggers a reasoning-stripped retry that succeeds.
- tests: new `tests/proxy/test_novel_discovery_target_specific.py` (8 cases) proves the novel-discovery rework — tactics are target-specific, deterministic (not random), differ across targets, emit no filler without a matching signal, the emergent vector is finding-grounded with a stable id, and the LLM cache takes precedence. chain/novel/prelude/audit/verification suites green (81 passed).

---

## [v0.1.7-beta] - 2026-04-02

### Fixed
- fix(server): `/api/status` now reports `degraded` when Ollama health check explicitly returns false (sticky online fallback only for transient probe failures)
- fix(tui): restored status bar visibility by keeping status bar CSS in widget-local `StatusBar.DEFAULT_CSS`
- fix(version): align package export by re-exporting version from `airecon._version` in `airecon/__init__.py`
- fix(quality): resolve Ruff F401 for package `__version__` re-export

### Improved
- feat(mcp): expose and display `total_tools` for MCP servers to avoid misleading truncated counts
- feat(tui): `/mcp list <name>` now shows first 10 tools only to keep UI/context lightweight
- feat(tui): moved ConfirmDelete modal CSS to global `styles.tcss` with scoped selectors

### Validation
- tests: suite green at release time

---

## [v0.1.6-beta] - 2026-03-17

### Critical Security Fixes

#### Session Save Race Condition
- fix(agent): add `asyncio.Lock()` to `_schedule_token_usage_snapshot_save()` to prevent concurrent session save corruption
- fix(agent): acquire lock in `stop()` method before synchronous session save
- fix(server): call `agent.stop()` in lifespan shutdown to ensure session saved on exit

#### Symlink TOCTOU Vulnerability
- fix(filesystem): check `file_path.is_symlink()` before create/read operations
- fix(filesystem): resolve symlink and verify it points within workspace
- fix(filesystem): use atomic writes via `tempfile.mkstemp()` + `os.replace()` to prevent partial writes

#### Command Injection Prevention
- fix(validators): add 8 new dangerous patterns to `DANGEROUS_PATTERNS`:
  - `\$\{[^}]+\}` - variable expansion
  - `<\([^)]+\)` - process substitution
  - `\$'[^']*'` - ANSI-C quoting
  - `` `[^`]+` `` - backtick command substitution
  - `\$\([^)]+\)` - $(command) substitution
  - `;\s*(curl|wget|nc|...)` - pipe to interpreter
  - `\|\s*(bash|sh|python|...)` - pipe to interpreter
  - `/etc/(passwd|shadow|sudoers|ssh/)` - sensitive file access
  - `chmod\s+[0-7]*[4-7][0-7]{2}` - setuid/setgid chmod

### Stability Improvements

#### Session Persistence
- fix(agent): save session on Ctrl+C/exit in `AgentLoop.stop()` method
- fix(server): call `agent.stop()` in lifespan shutdown handler
- fix(agent): log session data count (subdomains, live_hosts, vulns) on save

#### HTTP Timeout Protection
- fix(fuzzer): propagate baseline failures with explicit logging
- fix(fuzzer): skip unreachable params (status=-1) before fuzzing
- fix(fuzzer): log skipped params due to baseline failures

#### Browser Resource Cleanup
- fix(browser): add force kill fallback (`pkill -9 chromium`) on cleanup failure
- fix(browser): surface screenshot failures to caller via `screenshot_failure` flag in result dict

#### CVE Validation
- fix(reporting): tighten `_CVE_RE` regex from `r'^CVE-\d{4}-\d{4,7}$'` to `r'^CVE-(19[89]|20\d{2})-\d{4,7}$'`
- fix(reporting): validate CVE year range 1989-2099 to prevent fake CVEs

#### Context Management
- fix(models): make context limits config-based via `_get_context_limits()`
- fix(models): calculate `max_conversation_messages = ollama_num_ctx // 128`
- fix(models): add 5 new config keys: `agent_max_conversation_messages`, `agent_compression_trigger_ratio`,
  `agent_uncompressed_keep_count`, `agent_llm_compression_num_ctx`, `agent_llm_compression_num_predict`

#### Tool Result Truncation
- fix(models): add `_truncate_tool_result()` helper function (50KB limit)
- fix(executors): add `_append_tool_history()` helper with truncation on append
- fix(models): keep legacy truncation in `add_message()` as safety net

#### Incremental Pruning
- fix(loop): change `_executed_cmd_hashes` pruning from `.clear()` to FIFO keep newest 2500
- fix(loop): log pruning: "incrementally pruned: X → 2500 entries"

### Code Quality
- refactor: remove 51 lines of verbose FIX comments
- refactor: simplify docstrings across 12 files
- test: update test_validation.py to reflect improved security
- test: all 1369 tests passing (100% backward compatible)

### Files Modified
- `airecon/proxy/agent/loop.py` - Session lock, save on shutdown, incremental pruning
- `airecon/proxy/agent/validators.py` - 8 new dangerous patterns
- `airecon/proxy/agent/models.py` - Config-based context limits, truncation helper
- `airecon/proxy/agent/session.py` - Vulnerability dedup fix
- `airecon/proxy/agent/executors.py` - Tool result truncation helper
- `airecon/proxy/filesystem.py` - Symlink TOCTOU protection, atomic writes
- `airecon/proxy/browser.py` - Screenshot failure surfacing, force kill cleanup
- `airecon/proxy/fuzzer.py` - Baseline failure propagation
- `airecon/proxy/reporting.py` - CVE validation regex
- `airecon/proxy/server.py` - Session save on shutdown
- `airecon/proxy/config.py` - Bounds validation for all numeric fields
- `tests/proxy/test_validation.py` - Updated for improved security
- `tests/proxy/test_fuzzer.py` - Updated for baseline failure handling

---

### Added

#### Phase 1 — Autonomous Recovery & Exploration Engine
- feat(agent): watchdog forcing — LLM stuck in text-only loop forces `execute` tool (max 2x before abort)
- feat(agent): anti-stagnation exploration — temperature boost when no new high-confidence evidence (≥0.65)
- feat(agent): tool diversity tracking — same-tool streak detection via `_recent_tool_names` deque
- feat(agent): per-phase exploration directives via `_build_exploration_directive()`
- feat(agent): quality scoreboard — evidence 40%, reproducibility 35%, impact 25%
- feat(agent): recovery state context injected after conversation truncation
- feat(models): `objective_queue` (max 64) + `evidence_log` (max 200, dedup last 50)
- feat(config): 6 new exploration config keys (`agent_exploration_mode`, `agent_exploration_intensity`,
  `agent_exploration_temperature`, `agent_stagnation_threshold`, `agent_tool_diversity_window`,
  `agent_max_same_tool_streak`)

#### Phase 2 — Skill Orchestration & Tool Budget
- feat(agent): skill phase boost — `_PHASE_SKILL_DIRECTORIES` gives +2 score to phase-preferred skills
- feat(agent): tool budget per phase — `_PHASE_TOOL_BUDGETS` with soft limits per tool per phase
- feat(agent): budget warnings at 75% (warning), 100% (exhausted), 0 (discouraged)
- feat(pipeline): phase skill hints injected into `get_phase_prompt()`

#### Ollama Stability — Context & VRAM Recovery
- feat(agent): multi-level VRAM crash recovery — 4 escalation tiers persisted via `_adaptive_num_ctx`:
  Tier 1 (`ollama_num_ctx_small`, 80 msgs), Tier 2 (÷2, 50 msgs, 5s wait),
  Tier 3 (÷4, 30 msgs, 10s wait), Tier 4 (4096, 20 msgs, 30s wait)
- feat(agent): proactive context monitoring — trims at ≥80% token usage, aggressive at ≥90%
- feat(agent): dynamic compression interval (5/10/15 iters based on context fullness)
- feat(agent): skip `compress_with_llm` when >65% context full (OOM prevention)
- feat(agent): `_cap_tool_result` scales down dynamically with `_adaptive_num_ctx`
- feat(agent): `_adaptive_num_predict_cap` limits token generation after VRAM crash
- feat(ollama): `complete()` accepts `options: dict` (num_ctx, num_predict, temperature)
- feat(models): `compress_with_llm` passes `num_ctx=8192, num_predict=1024` to avoid OOM
- feat(agent): session auto-saved after each VRAM crash recovery

#### Tested Endpoints Memory
- feat(session): `SessionData.tested_endpoints` — LRU list (max 500) tracking `"METHOD url"` strings
- feat(session): `record_tested_endpoint(session, url, method)` with dedup + LRU eviction
- feat(agent): `_record_tested_endpoint()` auto-records from execute (curl), browser_action, fuzz tools
- feat(agent): last 20 tested endpoints shown in `_build_critical_findings_context` after truncation

#### @/file and @/folder References
- feat(agent): `@/path` resolver — copies local files/dirs to Docker workspace/uploads/ automatically
- feat(agent): per-file `try/except OSError` in directory copy — single file errors no longer abort
- feat(agent): detailed skip reporting (binary, too-large, OS-error) in copy summary

#### TUI — Slash Command Autocomplete
- feat(tui): `/` prefix triggers slash command autocomplete in chat input
- feat(tui): `PathCompleter` widget with proper error logging

#### Agent Intelligence
- feat(agent): attack chain detection — links vuln evidence across phases
- feat(agent): semantic dedup for objectives (Jaccard 0.70 threshold)
- feat(agent): adaptive thinking with confidence floor 0.65 for meaningful evidence
- feat(agent): cross-session memory — loads prior session findings on start
- feat(agent): 6 hypothesis-driven vuln discovery improvements
- feat(data): expand all correlation pattern files (major expansion)
- feat(data): rename `expert_testing_patterns.json` → `patterns.json`
- feat(zeroday): redesign zero-day patterns for realistic LLM discovery
- feat(agent): smart fuzzer routing + dynamic URL correlation + injection-chain detection
- feat(agent): data-driven injection points, port/tech hints, HTTP impact validation
- feat(skills): add 22 new skills (frameworks, protocols, technologies, LLM coverage)
- feat(skills): aggressive exploration mode + headless reverse/pwn skill loading

### Fixed
- fix(agent): `[CONTEXT MONITOR]` messages removed from TUI output (logged to file only)
- fix(security): block `$()` and backtick command substitution in watchdog (`has_dangerous_patterns()`)
- fix(security): auth header propagation improvements
- fix(validators): add auth browser actions: `login_form`, `handle_totp`, `save_auth_state`,
  `inject_cookies`, `oauth_authorize`
- fix(agent): `_executed_cmd_hashes` pruned at >5000 entries to prevent memory leak
- fix(agent): IDOR false positive reduction in correlation engine
- fix(agent): phase timeout now counts iterations (not wall-clock time)
- fix(agent): evidence truncation preserves high-confidence items
- fix(agent): press_key dedup, DDG lock race, port-scan rerun block
- fix(agent): harden LLM loop, subagent isolation, and command detection
- fix(agent): subdomain workspace path, CTF false positives, LLM hallucination
- fix(agent): watchdog extracts full multi-line bash scripts (not just first command)
- fix(ollama): enforce thinking/native_tools invariant + guard max_retries
- fix(ollama): improve detection-failure warning
- fix(browser): add `--ignore-certificate-errors` for TLS cipher mismatch on pentest targets
- fix(docker): fix 8+ binary name mismatches between tools_meta.json and installed binaries
- fix(docker): fix race condition in docker force_stop
- fix(patterns): fix all match-breaking issues across data pattern files
- fix(reporting): `_resolve_report_workspace_target()` for URL/file/path resolution
- fix(tui): `PathCompleter.hide()` bare except replaced with proper logging
- fix(data): `spawn_agent` max iterations 200→100 in tools.json
- fix(data): `web_search` updated to SearXNG preferred + DuckDuckGo fallback

### Changed
- refactor(ollama): remove name-heuristic capability detection
- docs: condense README from 983 → 228 lines
- docs: add airecon-skills community library reference
- ci: add label-based project board routing workflow
- chore: add `coming_soon/` to .gitignore (local-only roadmap)
- style: fix ruff E702 semicolons, unused imports, unused variables across codebase
- test: 448 → 879 tests (96% growth); new test files for context recovery, tested endpoints,
  recon dedup, path completer, command parse, reporting helpers

---

## [v0.1.5-beta] - 2026-03-05

### Fixed
- fix(core): unpack tuple return value from auto_load_skills_for_message to resolve unhashable list crash
- fix(core): resolve correlation logger, fuzzer graceful degradation, and browser timeout bugs
- fix(docker): fix race condition in docker force_stop and ollama model detection
- fix(tui): initialize live output and remove unused reload override
- fix(test): patch browser unpacking bug in unit tests

### Added
- test: implement comprehensive unit test suite covering proxy, agent, and TUI components

### Changed
- chore: remove .vscode from version control tracking
- chore: add __pycache__ and workspace/ to .gitignore
- docs: update README badge version formats

---

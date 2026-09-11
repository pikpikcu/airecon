# AIRecon Configuration Reference

## Table of Contents

1. [Config File Location](#1-config-file-location)
2. [Full Config Reference](#2-full-config-reference)
3. [LLM Backend Settings](#3-llm-backend-settings)
4. [Agent Behavior](#4-agent-behavior)
   - [Context Management](#context-management)
   - [Exploration Engine](#exploration-engine)
   - [Tool Execution](#tool-execution)
5. [Docker Sandbox](#5-docker-sandbox)
6. [Server Settings](#6-server-settings)
7. [Safety Settings](#7-safety-settings)
8. [Browser Settings](#8-browser-settings)
9. [Search Settings](#9-search-settings)
10. [Session Settings](#10-session-settings)
11. [Environment Variable Overrides](#11-environment-variable-overrides)
12. [Configuration Presets](#12-configuration-presets)

---

## 1. Config File Location

| Path | Purpose |
|------|---------|
| `~/.airecon/config.yaml` | Primary config (auto-created on first run with comments) |

On first run, if no config file exists, AIRecon writes the defaults to `~/.airecon/config.yaml` with inline comments explaining each setting. Edit this file to customize behavior.

```bash
# View current config
cat ~/.airecon/config.yaml

# Edit
nano ~/.airecon/config.yaml
# or
code ~/.airecon/config.yaml
```

**YAML format benefits:**
- ✅ Native comment support (no separate example file needed)
- ✅ Cleaner syntax (no quotes for strings, no trailing commas)
- ✅ Self-documenting (comments explain each setting)

---

## 2. Full Config Reference

```yaml
#╔══════════════════════════════════════════════════════════╗
#║              AIRecon Configuration File                  ║
#║                                                          ║
#║  Version: 1.7.1b0                                        ║
#║  Format: YAML (supports comments)                        ║
#║  Edit this file to customize AIRecon behavior            ║
#║                                                          ║
#║  Docs: https://github.com/pikpikcu/airecon               ║
#║                                                          ║
#║  NOTE: Only essential settings are written here.         ║
#║  All other values use sensible defaults in config.py.    ║
#╚══════════════════════════════════════════════════════════╝

# Quick Start:
#   1. Set openai_base_url to your OpenAI-compatible gateway (must include /v1).
#      - Local/offline: a local gateway (default http://localhost:20128/v1), vLLM, LiteLLM, or a gateway->Ollama
#      - Hosted: any OpenAI/Anthropic/Gemini-compatible endpoint (set openai_api_key)
#   2. Set openai_model to a model your gateway exposes (must support tool calling).
#   3. Context sizes: 32768 (small/CTF), 65536 (standard), 131072+ (long-context hosted).
#   4. Run: airecon start

# ======================================
# LLM Backend (OpenAI-compatible / LiteLLM / vLLM / hosted)
# ======================================
# OpenAI-compatible API base URL. REQUIRED. Must include /v1. default (local gateway): http://localhost:20128/v1
openai_base_url: "http://localhost:20128/v1"
# API key sent as 'Authorization: Bearer <key>'. Leave empty for local gateways without auth.
openai_api_key: ""
# Model name. REQUIRED. e.g. 'claude-sonnet-4', 'gpt-4o', 'gemini-2.0-flash', or 'qwen3:8b' via a local gateway.
openai_model: ""
# Whether the model supports native function/tool calling (REQUIRED for AIRecon to function).
openai_supports_native_tools: true

# ======================================
# LLM Tuning
# ======================================
# Max tokens to generate (OpenAI max_tokens).
openai_max_tokens: 16384
# Output randomness. 0.0=deterministic, 0.15=recommended (strict), 0.3=creative.
openai_temperature: 0.15
# Total request timeout (seconds). Increase for slow gateways / large models.
llm_timeout: 180.0
# Assumed context window (tokens). Raise for long-context hosted models (131072+).
llm_context_window: 65536
# Context for CTF/summary mode.
llm_context_window_small: 32768
# Master switch for extended thinking.
llm_enable_thinking: true
# Thinking intensity: low | medium | high | adaptive.
llm_thinking_mode: low
# How to request reasoning: auto = use the OpenAI-standard reasoning_effort and auto-detect
# support at runtime (HTTP 400 unsupported -> stripped & remembered; no model-name list).
# off | reasoning_effort | enable_thinking (vLLM/SGLang chat-template flag) to force.
llm_thinking_request_mode: auto

# ======================================
# Proxy Server
# ======================================
# Host to bind proxy server. 127.0.0.1 = localhost only.
proxy_host: 127.0.0.1
# Port for proxy server. Default 3000.
proxy_port: 3000

# ======================================
# Timeouts
# ======================================
# Docker command timeout (seconds). 900s = 15 min for long scans (nmap, nuclei).
command_timeout: 900.0

# ======================================
# Docker Sandbox
# ======================================
# Container memory limit. '16g' = 16GB (stable for 32GB+ RAM host, 18GB image + Chromium). Prevents OOM kills. Set to '12g' for 32GB RAM, '8g' for 16GB systems, '4g' for 8GB systems.
docker_memory_limit: 16g

# ======================================
# Deep Recon
# ======================================
# Auto-start deep recon on session start.
deep_recon_autostart: true
# Recon execution mode: standard|full. standard=respect user scope, full=auto-expand simple target prompts into comprehensive recon.
agent_recon_mode: standard

# ======================================
# Safety
# ======================================
# Allow destructive tests (e.g., DELETE requests). Default: False for safety.
allow_destructive_testing: false
```

---

## 3. LLM Backend Settings

### `openai_base_url`
**Type:** string | **Default:** `"http://localhost:20128/v1"` | **Required**

The OpenAI-compatible `/v1` endpoint AIRecon talks to. **Must include the `/v1` suffix.**

```yaml
# local-gateway default (can proxy a local Ollama / vLLM)
openai_base_url: "http://localhost:20128/v1"

# Remote / hosted gateway
openai_base_url: "https://your-gateway.example/v1"
```

---

### `openai_api_key`
**Type:** string | **Default:** `""`

Sent as `Authorization: Bearer <key>`. Leave empty for local gateways that don't require auth; set it for hosted endpoints.

---

### `openai_model`
**Type:** string | **Default:** `""` | **Required**

Any model name your gateway exposes (check `GET <base_url>/models`). Must support native tool calling.

```yaml
openai_model: "claude-sonnet-4"     # hosted
openai_model: "gpt-4o"              # hosted
openai_model: "gemini-2.0-flash"    # hosted
openai_model: "qwen3:8b"            # local via a local gateway (Ollama/vLLM)
```

> **Reasoning is auto-detected** at runtime (`llm_thinking_request_mode: auto`) — no model-name list to maintain.
>
> **Small models:** local models below ~8B are not recommended for full engagements. Expect more tool-call errors and hallucinations as size shrinks.

---

### `openai_temperature`
**Type:** float | **Default:** `0.15`

Controls output randomness. This is the single most impactful setting for agent reliability.

| Value | Effect on AIRecon |
|-------|------------------|
| `0.0` | Fully deterministic. Same input = same output every time. |
| `0.1`–`0.15` | **Recommended.** Strict instruction following. Minimal hallucination. Model respects scope rules. |
| `0.2` | Slightly more adaptive. Useful if model feels repetitive when stuck on a problem. |
| `0.3` | Noticeable creativity. Still acceptable for tool-calling agents. |
| `0.5–0.6` | High risk of scope creep (model "improvises" extra steps). Chain creep becomes frequent. |
| `> 0.7` | Model frequently ignores scope rules, invents tool output, hallucinates CVEs. Not recommended. |

**Why low temperature matters for security agents:**

The model's job is to follow strict protocols (task scoping, CVSS scoring, PoC requirements) rather than to be creative. Higher temperature increases the chance the model "reasons itself" into skipping rules.

For reasoning-capable models with `llm_enable_thinking: true`, the `<think>` phase handles analytical depth internally. The output temperature can therefore be very low (0.15) without losing quality.

---

### `llm_context_window`
**Type:** int | **Default:** `65536` (64K tokens)

Context window size in tokens. Larger = more history visible to the model = better continuity, but requires more VRAM.

| Value | Approx VRAM impact (varies by model) | Use case |
|-------|-------------------------|----------|
| `-1` | N/A (server default) | **Unlimited** — use Ollama server's default/max (recommended for remote servers) |
| `8192` | ~2 GB | Quick tests, very limited VRAM |
| `32768` | ~8 GB | General use with 8–16 GB VRAM |
| `65536` | ~15 GB | **Default** — deep sessions on mid/large VRAM |
| `131072` | ~31 GB | Large context window; high VRAM requirement |
| `1000000` | ~248 GB | 1M tokens — specialized setups only |

**For remote Ollama servers:** Set `llm_context_window: -1` to use the server's default/max context limit without hardcoding a value. This is useful when connecting to cloud Ollama instances with high context limits.

> If you get VRAM/OOM errors, reduce this first. The agent uses automatic multi-level crash recovery (see VRAM Recovery below) and proactive context trimming at ≥80% usage.

---

### `llm_context_window_small`
**Type:** int | **Default:** `32768` (32K tokens)

A smaller context window used for compression calls (`compress_with_llm`) and VRAM crash recovery tiers. Reduces VRAM pressure during context management. This is also the starting point for multi-level recovery — see VRAM Recovery below.

---

### `openai_max_tokens`
**Type:** int | **Default:** `16384`

Maximum number of tokens the model can generate in a single response. 32768 ≈ ~24,000 words — sufficient for complex reasoning + tool-calling responses.

Reduce to `8192` if responses feel slow. The agent automatically caps this further after VRAM crashes.

---

### `llm_timeout`
**Type:** float | **Default:** `180.0` seconds

How long to wait for a streaming response before giving up. Increase for slow remote servers or large models.

```yaml
# Example: increase for slow inference
llm_timeout: 240.0

# For very large models (122B) on CPU
llm_timeout: 7200.0
```

---

### `llm_chunk_timeout`
**Type:** float | **Default:** `180.0` seconds (3 minutes)

Per-chunk stream timeout. If no token arrives for this long, the stream is considered stalled and a recoverable TimeoutError is raised.

180s is tuned for 122B model prefill on remote GPU servers — can take 2-3 minutes for long context windows (128K KV cache fill is slow over the network).

---

### `llm_enable_thinking`
**Type:** bool | **Default:** `true`

Enables the `think=true` parameter when calling Ollama, which activates extended reasoning (`<think>` blocks) for supported models.

| Model type | Recommended setting |
|------------|-------------------|
| Reasoning-capable model | `true` |
| Standard/chat model (llama3, mistral) | `false` |

When enabled, the TUI shows the model's internal reasoning process in the thinking panel, separate from the final output. This is very useful for understanding why the agent made a specific decision.

---

### `llm_thinking_mode`
**Type:** string | **Default:** `adaptive`

Controls **WHEN** the model uses `<think>` reasoning blocks. Different from `openai_temperature` — thinking_mode affects reasoning depth, temperature affects output randomness.

| Mode | Behavior | Use Case |
|------|----------|----------|
| `low` | Minimal thinking — only for deep tools (advanced_fuzz, create_vulnerability_report) | Fast iteration, quick recon |
| `medium` | Balanced — think for ANALYSIS/EXPLOIT phases + deep tools | Standard pentesting |
| `high` | Deep reasoning — think for most iterations (except shallow tools after iter 15) | Complex targets, maximum thoroughness |
| `adaptive` | Auto-adjust based on phase, tool complexity, and stagnation | **Recommended** — smart balance |

**Thinking mode vs temperature:**
- `llm_thinking_mode`: Controls reasoning depth (whether model thinks before answering)
- `openai_temperature`: Controls output randomness (how varied/creative the answer is)

**Example combinations:**
```yaml
# Standard security testing (recommended)
llm_thinking_mode: adaptive  # Smart reasoning when needed
openai_temperature: 0.15        # Strict, reliable output

# Deep analysis (complex targets)
llm_thinking_mode: high      # Deep reasoning for most iterations
openai_temperature: 0.15        # Still strict output

# Fast recon (many targets)
llm_thinking_mode: low       # Minimal thinking, fast iteration
openai_temperature: 0.15        # Strict output
```

---

### `llm_keep_alive`
**Type:** int or string | **Default:** `-1`

How long to keep the model loaded in VRAM after inference completes.

| Value | Behavior |
|-------|----------|
| `-1` | Keep model loaded indefinitely (best for dedicated servers) |
| `"60m"` | Unload after 60 minutes of inactivity |
| `"5m"` | Unload after 5 minutes (good for shared machines) |
| `0` | Unload immediately after each inference |

For shared workstations, use `"60m"` to free VRAM when not in use. For dedicated pentest servers, use `-1` for fastest response times.

---

## 4. Agent Behavior

### Context Management

These settings control how AIRecon manages conversation context to prevent VRAM crashes and optimize memory usage.

### `agent_max_conversation_messages`
**Type:** int | **Default:** `llm_context_window // 128` (1024 for 131K context)

Maximum number of conversation messages before truncation. Automatically calculated from `llm_context_window` unless explicitly set.

```yaml
# Auto-calculated (recommended)
agent_max_conversation_messages: 1024

# Manual override for 32K context
agent_max_conversation_messages: 256

# Manual override for 131K context
agent_max_conversation_messages: 1024
```

---

### `agent_compression_trigger_ratio`
**Type:** float (0.5–0.95) | **Default:** `0.8`

Triggers LLM-based compression when conversation reaches this percentage of `agent_max_conversation_messages`.

```yaml
# Compress earlier (at 70% full)
agent_compression_trigger_ratio: 0.7

# Compress later (at 90% full)
agent_compression_trigger_ratio: 0.9
```

---

### `agent_uncompressed_keep_count`
**Type:** int (5–100) | **Default:** `20`

Number of most recent messages to keep uncompressed during tool result compression.

```yaml
# Keep more context uncompressed
agent_uncompressed_keep_count: 30

# Aggressive compression
agent_uncompressed_keep_count: 10
```

---

### `agent_llm_compression_num_ctx`
**Type:** int (1024–32768) | **Default:** `8192`

Context window size used during LLM-based compression calls. Kept small to save VRAM.

```yaml
# For very low VRAM
agent_llm_compression_num_ctx: 4096

# For better compression quality
agent_llm_compression_num_ctx: 16384
```

---

### `agent_llm_compression_num_predict`
**Type:** int (256–8192) | **Default:** `1024`

Maximum tokens for compression output. Controls how detailed the compressed summary is.

```yaml
# Shorter summaries
agent_llm_compression_num_predict: 512

# More detailed summaries
agent_llm_compression_num_predict: 2048
```

---

### `deep_recon_autostart`
**Type:** bool | **Default:** `true`

When `true`, if the user inputs **only** a bare domain name (e.g., just `example.com` with nothing else), AIRecon automatically expands it into a full deep recon prompt:

```
Perform a comprehensive full deep recon and vulnerability scan on example.com. Use all available tools.
```

Set to `false` if you want the agent to treat bare domain input as "just set the target, wait for further instructions."

```yaml
# Auto-expand bare domain to full recon
deep_recon_autostart: true

# Treat bare domain as target selection only
deep_recon_autostart: false
```

---

### `agent_max_tool_iterations`
**Type:** int | **Default:** `1200`

Safety limit on the number of tool call cycles per user message. Prevents infinite loops.

For full recon engagements on complex targets, 1200 iterations allows Phase 1–4 to complete fully. For specific tasks, the agent typically finishes in 3–20 iterations.

```yaml
# Tight limit for specific tasks only
agent_max_tool_iterations: 100

# Extended for deep recon
agent_max_tool_iterations: 1200
```

---

### `agent_repeat_tool_call_limit`
**Type:** int | **Default:** `2`

How many times the **exact same tool + identical arguments** combination is allowed before being blocked as a duplicate.

The agent maintains a count per (tool, arguments) pair per session. When the count reaches this limit, the tool call is rejected with an error message telling the agent to try something different.

```yaml
# Strict: block after first repeat
agent_repeat_tool_call_limit: 1

# Relaxed: allow up to 3 identical calls
agent_repeat_tool_call_limit: 3
```

> Note: This only blocks **identical** calls (same tool + same arguments). Different arguments or a different tool on the same target are not affected.

---

### `agent_missing_tool_retry_limit`
**Type:** int | **Default:** `2`

How many consecutive times the agent may call a tool that does not exist before the session is aborted.

When the agent hallucinates a tool name (e.g., calls `run_nmap` instead of `execute`), it receives an error listing the valid tools. If it continues calling non-existent tools this many times in a row, the session stops to prevent an infinite error loop.

---

### `tool_response_role`
**Type:** string | **Default:** `"tool"`

The message role used when returning tool results to the LLM in the conversation history.

| Value | When to use |
|-------|-------------|
| `"tool"` | Models that support the Ollama `tool` message role (most modern models) |
| `"user"` | Fallback for older models that don't understand the tool role |

Most models work correctly with `"tool"`. If you see the model failing to parse tool results, try `"user"`.

---

## 5. Docker Sandbox

### `docker_image`
**Type:** string | **Default:** `"airecon-sandbox"`

The name of the Docker image used as the execution sandbox. Must be built before first use.

```bash
docker build -t airecon-sandbox airecon/containers/
```

If you build with a different tag, update this setting accordingly.

---

### `docker_auto_build`
**Type:** bool | **Default:** `true`

If `true`, AIRecon attempts to build the Docker image automatically at startup if it is not found. This can fail in restricted environments. Manual build is more reliable.

---

### `docker_memory_limit`
**Type:** string | **Default:** `"8g"`

Container memory limit via Docker cgroups. Prevents runaway tools (gau, amass, Chromium) from consuming all host RAM and triggering silent kernel OOM kills.

| Value | Host RAM requirement |
|-------|---------------------|
| `"4g"` | Minimum — 8GB host RAM |
| `"8g"` | **Default** — 16GB host RAM |
| `"12g"` | High — 24GB+ host RAM |
| `"16g"` | Maximum — 32GB+ host RAM |

With a cgroup limit, Docker sends SIGKILL to the over-limit process and sets `OOMKilled=true` in `docker inspect`, giving the post-mortem logger a clear signal rather than a silent container disappearance.

---

### `command_timeout`
**Type:** float | **Default:** `900.0` seconds (15 minutes)

Maximum time a single shell command may run inside the Docker container before being killed.

```yaml
# Quick scans only
command_timeout: 120.0

# Allow long-running tools (masscan, full nmap, large sqlmap)
command_timeout: 1800.0
```

Nuclei, sqlmap, and full nmap scans can easily take > 10 minutes on large target lists. Increase this if commands are being killed prematurely.

---

## 6. Server Settings

### `proxy_host` / `proxy_port`
**Type:** string / int | **Defaults:** `"127.0.0.1"` / `3000`

The host and port for the internal FastAPI server that bridges the TUI and the agent loop via SSE (Server-Sent Events).

Only change these if port 3000 is already in use on your machine:

```yaml
proxy_host: "127.0.0.1"
proxy_port: 3001
```

---

## 7. Safety Settings

### `allow_destructive_testing`
**Type:** bool | **Default:** `false`

When `true`, modifies the system prompt to authorize destructive/aggressive testing:
- Changes "non-destructive penetration testing" to "UNRESTRICTED DESTRUCTIVE penetration testing"
- Injects a `<safety_override>` block that lifts rate limiting, politeness constraints, and adds aggressive recon directives
- Zero false positive enforcement is tightened further

Set to `false` for passive/non-destructive engagements or when working in shared/production environments.

```yaml
# Production-safe assessment
allow_destructive_testing: false

# Full offensive engagement (authorized)
allow_destructive_testing: true
```

---

## 8. Browser Settings

### `browser_page_load_delay`
**Type:** float | **Default:** `1.0` seconds

How long to wait after a page navigation before performing browser actions. Increase for slow targets or heavily JavaScript-rendered pages.

```yaml
# Fast, well-performing targets
browser_page_load_delay: 0.5

# Slow targets or heavy SPAs (React, Vue, Angular)
browser_page_load_delay: 3.0
```

---

### `browser_action_timeout`
**Type:** int | **Default:** `120` seconds (2 minutes)

Timeout for each browser action (click, fill, navigate, etc.). Increase for slow targets or complex JavaScript interactions.

```yaml
# Fast targets
browser_action_timeout: 60

# Complex SPAs with heavy JS
browser_action_timeout: 300
```

---

## 9. Search Settings

### `searxng_url`
**Type:** string | **Default:** `"http://localhost:8080"`

The URL of your SearXNG instance. If set, the `web_search` tool uses SearXNG for full Google dork operator support.

```yaml
# Local SearXNG (default)
searxng_url: "http://localhost:8080"

# Empty = DuckDuckGo fallback (limited operators, rate-limited)
searxng_url: ""
```

AIRecon auto-manages the SearXNG Docker container lifecycle (start on use, stop on exit). To start manually:

```bash
docker run -d --name searxng -p 8080:8080 searxng/searxng
```

---

### `searxng_engines`
**Type:** string | **Default:** `"google,bing,duckduckgo,brave,google_news,github,stackoverflow"`

Comma-separated list of engines to query via SearXNG.

```yaml
# Full engine set (slower but broader)
searxng_engines: "google,bing,duckduckgo,brave,startpage,github,stackoverflow,reddit,google_scholar,google_news"

# Fast subset for quick lookups
searxng_engines: "google,bing,duckduckgo"
```

---

## 10. Session Settings

### `vuln_similarity_threshold`
**Type:** float | **Default:** `0.7`

Jaccard similarity threshold for vulnerability deduplication. When a new vulnerability finding has similarity ≥ this value compared to an existing entry, it is merged rather than added as a duplicate.

| Value | Behavior |
|-------|----------|
| `0.9` | Only near-identical findings are merged — more duplicates allowed |
| `0.7` | **Default** — reasonable deduplication for most cases |
| `0.5` | Aggressive deduplication — similar findings merged even if endpoint differs |
| `0.3` | Very aggressive — not recommended |

---

### `evidence_similarity_threshold`
**Type:** float | **Default:** `0.70`

Jaccard similarity threshold for evidence deduplication (subdomains, URLs, HTTP responses). Works the same as `vuln_similarity_threshold` but for non-vulnerability evidence.

---

## 11. Pipeline Settings

These control the minimum depth criteria required before a RECON → ANALYSIS phase transition is triggered.

### `pipeline_recon_min_subdomains`
**Type:** int | **Default:** `3`

Minimum number of subdomains that must be discovered before RECON is considered complete. Prevents premature phase transition if the agent only finds 1–2 subdomains.

---

### `pipeline_recon_min_urls`
**Type:** int | **Default:** `1`

Minimum number of URLs collected before RECON → ANALYSIS transition.

---

### `pipeline_recon_soft_timeout`
**Type:** int | **Default:** `30`

Maximum RECON iterations before forcing a transition to ANALYSIS regardless of depth criteria. Prevents infinite RECON loops on targets with very limited attack surface.

---

## 12. Agent Exploration Settings

### `agent_exploration_mode`
**Type:** bool | **Default:** `true`

Enables the Phase 1 anti-stagnation exploration engine. When active:
- Monitors for stagnation (no new high-confidence evidence after N iterations)
- Boosts temperature to `agent_exploration_temperature` when stagnation detected
- Enforces tool diversity via same-tool streak detection
- Injects per-phase exploration directives into the system prompt

---

### `agent_exploration_intensity`
**Type:** float (0.0–1.0) | **Default:** `0.9`

How aggressively the exploration engine pushes the agent into new territory when stagnation is detected. Higher values inject stronger directives. `0.9` is tuned for 122B models; reduce to `0.5`–`0.6` for smaller models.

---

### `agent_exploration_temperature`
**Type:** float (0.0–2.0) | **Default:** `0.5`

Temperature used when the agent is in exploration mode (stagnation detected). Higher than `openai_temperature` to encourage new approaches without losing control.

---

### `agent_stagnation_threshold`
**Type:** int | **Default:** `2`

Number of consecutive iterations with no new high-confidence evidence (≥0.65 confidence) before exploration mode activates.

---

### `agent_tool_diversity_window`
**Type:** int (min 3) | **Default:** `8`

Number of most-recent tool calls tracked for diversity analysis. The agent checks this window for same-tool streaks.

---

### `agent_max_same_tool_streak`
**Type:** int | **Default:** `3`

Maximum allowed consecutive uses of the same tool before a diversity warning is injected. Prevents the agent from looping on a single tool.

---

### `agent_plan_revision_interval`
**Type:** int | **Default:** `30`

How many iterations between full plan revision checkpoints. At each checkpoint, the agent reviews all findings and updates its exploitation plan.

---

### `agent_phase_creative_temperature`
**Type:** float (0.0–1.0) | **Default:** `0.20`

Temperature used for ANALYSIS and EXPLOIT phases. Slightly warmer than base temperature to encourage creative attack chaining without hallucination risk.

---

## 13. Environment Variable Overrides

Any config key can be overridden without editing the file using environment variables. Format: `AIRECON_<KEY_UPPERCASE>`.

```bash
# Override model
AIRECON_OPENAI_MODEL=qwen3.5:35b airecon start

# Override temperature
AIRECON_OPENAI_TEMPERATURE=0.2 airecon start

# Disable destructive testing
AIRECON_ALLOW_DESTRUCTIVE_TESTING=false airecon start

# Use a different Ollama endpoint
AIRECON_OPENAI_BASE_URL=http://10.0.0.5:20128/v1 airecon start

# Override context window
AIRECON_LLM_CONTEXT_WINDOW=65536 airecon start
```

**Type conversion rules:**
- `bool`: accepts `true`, `1`, `yes` → True | `false`, `0`, `no` → False
- `int` / `float`: standard numeric conversion
- `string`: used as-is

Environment variables take precedence over the config file. They are applied at startup and do not persist.

---

## 14. Configuration Presets

### Preset: Small (8–12 GB VRAM, qwen3.5:9b)

```yaml
openai_model: "qwen3.5:9b"
llm_context_window: 32768
llm_context_window_small: 16384
openai_temperature: 0.15
openai_max_tokens: 8192
llm_enable_thinking: true
openai_supports_thinking: true
openai_supports_native_tools: true
command_timeout: 600.0
agent_max_tool_iterations: 300
searxng_url: "http://localhost:8080"
```

### Preset: Recommended (16–24 GB VRAM, qwen3.5:35b)

```yaml
openai_model: "qwen3.5:35b"
llm_context_window: 65536
llm_context_window_small: 32768
openai_temperature: 0.15
openai_max_tokens: 16384
llm_enable_thinking: true
openai_supports_thinking: true
openai_supports_native_tools: true
llm_keep_alive: "60m"
command_timeout: 900.0
agent_max_tool_iterations: 800
searxng_url: "http://localhost:8080"
```

### Preset: High-end (48+ GB VRAM, qwen3.5:122b)

```yaml
openai_model: "qwen3.5:122b"
llm_context_window: 65536
llm_context_window_small: 32768
openai_temperature: 0.15
openai_max_tokens: 16384
llm_enable_thinking: true
openai_supports_thinking: true
openai_supports_native_tools: true
llm_timeout: 240.0
llm_keep_alive: "60m"
command_timeout: 900.0
agent_max_tool_iterations: 800
searxng_url: "http://localhost:8080"
```

### Preset: Remote Ollama (GPU server)

```yaml
openai_base_url: "http://192.168.1.100:11434"
openai_model: "qwen3.5:122b"
llm_timeout: 240.0
llm_context_window: 65536
llm_context_window_small: 32768
openai_temperature: 0.15
llm_enable_thinking: true
openai_supports_thinking: true
openai_supports_native_tools: true
llm_keep_alive: "60m"
agent_max_tool_iterations: 800
searxng_url: "http://localhost:8080"
```

### Preset: Passive / non-destructive assessment

```yaml
openai_temperature: 0.15
allow_destructive_testing: false
deep_recon_autostart: false
command_timeout: 300.0
agent_max_tool_iterations: 100
```

### Preset: CTF / Benchmark mode

```yaml
llm_context_window: 65536
openai_max_tokens: 8192
agent_max_tool_iterations: 150
agent_exploration_mode: false
deep_recon_autostart: false
allow_destructive_testing: true
```

Optimized for CTF challenges where you want fast, focused exploitation without broad recon.

---

## 15. Troubleshooting

### VRAM / OOM Errors

1. **Reduce `llm_context_window`** — Start with 65536, then 32768
2. **Reduce `openai_max_tokens`** — Try 16384 or 8192
3. **Set `llm_keep_alive: "5m"`** — Frees VRAM between sessions
4. **Check `docker_memory_limit`** — Ensure container has enough RAM

### Agent Stuck in Loops

1. **Reduce `agent_max_tool_iterations`** — Try 300-500
2. **Lower `agent_repeat_tool_call_limit`** — Set to 1
3. **Increase `agent_stagnation_threshold`** — Try 3-4

### Hallucinated Tool Calls

1. **Lower `openai_temperature`** — Try 0.1 or 0.0
2. **Ensure `llm_enable_thinking: true`** — Helps model reason before acting
3. **Check model capability** — Use a model that supports native tool calling; smaller models are less reliable

### Slow Response Times

1. **Reduce `llm_context_window`** — Less context = faster inference
2. **Reduce `llm_timeout`** — Fail fast on stalled requests
3. **Use smaller model** — for example, qwen3.5:35b is faster than qwen3.5:122b

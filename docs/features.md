# AIRecon Features

> For the complete tool-by-tool reference including schemas, flags, and usage examples, see [Tools Reference](tools.md).

## Table of Contents

- [Deep Thinking Model Support](#deep-thinking-model-support)
- [Docker Sandbox Execution](#docker-sandbox-execution)
- [Pipeline Phases](#pipeline-phases)
- [Task Scope Enforcement](#task-scope-enforcement)
- [Browser Automation](#browser-automation)
- [Browser Authentication](#browser-authentication)
- [SearXNG & Web Search](#searxng--web-search)
- [Caido Integration](#caido-integration)
- [Fuzzing Engine](#fuzzing-engine)
- [API Schema Fuzzing (Schemathesis)](#api-schema-fuzzing-schemathesis)
- [Technology Fingerprinting](#technology-fingerprinting)
- [Correlation Engine](#correlation-engine)
- [Multi-Agent System](#multi-agent-system)
- [Session Persistence & Resume](#session-persistence--resume)
- [Anti Context-Loss](#anti-context-loss)
- [Skills System](#skills-system)
- [Local Knowledge Base](#local-knowledge-base)
- [Verified Vulnerability Reporting](#verified-vulnerability-reporting)
- [Workspace Isolation](#workspace-isolation)
- [URL Pattern Matching (gf)](#url-pattern-matching-gf)
- [Anti-Hallucination Controls](#anti-hallucination-controls)
- [MCP Support](#mcp-support)

---

## Deep Thinking Model Support

AIRecon supports reasoning models that generate internal thoughts (`<think>`) before producing a final answer. This is useful for complex tasks such as:

- Planning multi-stage attack chains
- Analyzing vulnerability proof-of-concepts
- Debugging complex tool errors
- Formulating exploit hypotheses
- Navigating scope rules under complex context

When enabled, AIRecon keeps the reasoning stream separate from final output. The TUI can surface it for debugging or auditability.

**Controlled via config:**

- `llm_enable_thinking: true|false` — master switch for extended thinking.
- `llm_thinking_mode: low|medium|high|adaptive` — how often the agent spends a thinking turn (low = only deep tools, high = most iterations).
- `llm_thinking_request_mode: auto|off|reasoning_effort|enable_thinking` — how the OpenAI-compatible gateway is asked to reason:
  - `auto` (default) detects from the model name — sends `reasoning_effort` to o-series/gpt-5/gemini-thinking/grok-reasoning/QwQ/DeepSeek-R1 and `chat_template_kwargs.enable_thinking` to Qwen3/GLM/vLLM-hosted models, and stays silent for plain models (gpt-4o, gemini-flash) that would reject reasoning params.
  - `off` never sends reasoning params (use for non-reasoning models).
  - `reasoning_effort` / `enable_thinking` force a specific strategy.

For the documented use cases above to actually engage, point `openai_model` at a reasoning-capable model. A lightweight non-reasoning model (e.g. `gemini-*-flash`) will go straight to tool calls regardless of these settings.

---

## Docker Sandbox Execution

All shell commands run inside an isolated **Kali Linux Docker container** (`airecon-sandbox`). The `execute` tool is the single entry point for shell access inside the sandbox.

```
Agent Loop  →  execute tool  →  docker exec airecon-sandbox bash -c "<command>"
```

**Common tools in the sandbox image include (may vary by build):**

| Category | Tools |
|----------|-------|
| Subdomain Discovery | `subfinder`, `amass`, `assetfinder`, `dnsx`, `shuffledns`, `massdns`, `sublist3r`, `hakip2host` |
| Port Scanning | `nmap`, `naabu`, `masscan`, `netcat` |
| Web Crawling | `katana`, `gospider`, `gau`, `waybackurls`, `httpx`, `httprobe`, `meg`, `waymore` |
| Fingerprinting | `whatweb`, `wafw00f`, `wappalyzer`, `tlsx`, `retire`, `wpscan`, `joomscan` |
| JS Analysis | `jsleak`, `jsluice`, `gf`, `trufflehog`, `js-beautify`, `LinkFinder` |
| Fuzzing | `ffuf`, `feroxbuster`, `dirsearch`, `arjun`, `x8`, `headi`, `dalfox`, `wfuzz` |
| Vuln Scanning | `nuclei`, `nikto`, `wapiti`, `sqlmap`, `ghauri`, `nosqli`, `toxicache`, `csprecon`, `semgrep`, `trivy` |
| Exploitation | `sqlmap`, `ghauri`, `dalfox`, `interactsh-client`, `testssl.sh` |
| JWT & GraphQL | `jwt_tool`, `jwt-cracker`, `inql`, `GraphQLmap` |
| Secrets | `gitleaks`, `trufflehog`, `bandit`, `git-dumper` |
| Password Attacks | `hydra`, `medusa`, `hashcat`, `john` |
| Cloud & S3 | `s3scanner`, `festin`, `shodan` |
| Wordlists | Full SecLists at `/usr/share/seclists/`, FuzzDB at `/home/pentester/wordlists/fuzzdb/`, rockyou |
| Scripting | `python3`, `bash`, `curl`, `wget`, `jq`, `ripgrep`, `parallel`, `tmux` |

Sandbox user permissions and network access are defined by the container build; consult the sandbox image for exact defaults.

---

## Pipeline Phases

AIRecon operates through a structured 4-phase state machine. Phase transitions are triggered automatically based on real findings from tool output — not iteration counts.

<div class="pipeline-diagram">
  <pre><code>RECON
  Objective: Enumerate attack surface
  Example tools: execute (subfinder/httpx/nmap/katana/ffuf), web_search, browser_action
      │
      ▼
ANALYSIS
  Objective: Identify injection points, misconfigs, tech stack
  Example tools: execute, browser_action, code_analysis (Semgrep), read_file
      │
      ▼
EXPLOIT
  Objective: Test and confirm vulnerabilities
  Example tools: execute, quick_fuzz, advanced_fuzz, schemathesis_fuzz,
                 caido_send_request, caido_automate, spawn_agent, create_vulnerability_report
      │
      ▼
REPORT
  Objective: Document confirmed findings
  Example tools: create_vulnerability_report, create_file, read_file
  </code></pre>
</div>

Phase guidance is **soft-enforced** and configurable via `pipeline_*` settings: AIRecon warns when tools are used outside their typical phase but does not hard-block execution.

### Automatic Checkpoints

The agent loop runs automatic checkpoints during execution. Intervals are configurable.

| Checkpoint | Purpose |
|-----------|---------|
| Pipeline evaluation | Check phase transition criteria and refresh session context |
| Self-evaluation | Progress review and plan adjustment |
| Context compression | Trim conversation history to prevent context overflow |

---

## Task Scope Enforcement

Before calling any tool, the agent classifies the request:

| Type | Signal | Behavior |
|------|--------|----------|
| `[SPECIFIC TASK]` | Single verb + target ("find subdomains", "scan ports") | Runs only the requested operation, then stops |
| `[FULL RECON]` | Broad engagement ("pentest", "full recon", "bug bounty") | Follows the full SOP, chains all phases |

For specific tasks, AIRecon is instructed to avoid expanding scope unless the user explicitly asks for follow-on steps.

---

## Browser Automation

The agent controls a headless Chromium browser via Playwright. The browser runs inside the Docker sandbox.

**Available browser actions:**

| Action | Description |
|--------|-------------|
| `launch` / `goto` | Open browser, navigate to URL |
| `click` / `double_click` / `hover` | Mouse interactions |
| `type` / `press_key` | Keyboard input |
| `scroll` | Page scrolling |
| `execute_js` | Run arbitrary JavaScript in page context |
| `view_source` | Get full page HTML source |
| `get_console_logs` | Capture browser console output |
| `get_network_logs` | Capture all network requests/responses |
| `save_pdf` | Save page as PDF |
| `new_tab` / `switch_tab` / `close_tab` | Tab management |
| `wait` | Wait for element or condition |

Use cases: JavaScript-heavy apps, OAuth flows, XSS verification, DOM inspection, React/Vue error leak detection.

---

## Browser Authentication

AIRecon supports full authenticated testing via the `browser_action` tool's authentication sub-actions.

### Supported Methods

| Method | Action | Description |
|--------|--------|-------------|
| Form login | `login_form` | Uses provided selectors or common defaults for username/password fields and submit buttons. |
| TOTP / 2FA | `handle_totp` | RFC 6238 TOTP — generates code from Base32 secret automatically |
| OAuth flows | `oauth_authorize` | Handles redirect-based OAuth: navigates authorize URL, grants permissions, captures redirect |
| Cookie injection | `inject_cookies` | Load a saved cookie dict directly into the active browser session |
| State persistence | `save_auth_state` | Serializes cookies + localStorage + sessionStorage to disk for later re-use |

### Example: Authenticated Scan Workflow

```
# Step 1: Login via form
login to https://example.com/login with user=admin@example.com pass=secret123

# Step 2: Agent internally calls:
#   browser_action: login_form url=https://example.com/login
#                   username_selector=auto password_selector=auto
#                   submit_selector=auto

# Step 3: Save auth state
#   browser_action: save_auth_state path=workspace/example.com/auth.json

# Step 4: All subsequent requests use the saved session
#   Nuclei, httpx, and custom scripts can be seeded with the extracted cookies
```

### Example: TOTP (2FA) Login

```
test https://app.example.com with TOTP: JBSWY3DPEHPK3PXP
```

The agent generates the current TOTP code using the provided secret and types it into the 2FA field automatically.

---

## SearXNG & Web Search

The `web_search` tool supports two backends:

| Backend | Setup | Capabilities |
|---------|-------|-------------|
| **SearXNG** (recommended) | Docker container, auto-managed | Full Google dork operators, multi-engine, 50 results |
| **DuckDuckGo** (fallback) | No setup needed | Limited operators, rate-limited, ~5 results |

### SearXNG Engines

When configured, SearXNG queries all of these simultaneously:

```
google, bing, duckduckgo, brave, startpage, github, stackoverflow,
reddit, google_scholar, google_news
```

### Supported Dork Operators

```
site:example.com ext:php
inurl:admin filetype:pdf
intitle:"index of" intext:password
```

### Setup

```text
# Auto-managed (add to config):
"searxng_url": "http://localhost:8080"

# Manual:
docker run -d --name searxng -p 8080:8080 searxng/searxng
```

AIRecon will start/stop the SearXNG container automatically. Falls back to DuckDuckGo if the container is unavailable.

---

## Caido Integration

AIRecon connects natively to [Caido](https://caido.io) at `127.0.0.1:48080/graphql` using auto-managed session tokens.

### Available Tools

| Tool | Timeout | Description |
|------|---------|-------------|
| `caido_list_requests` | — | Query HTTP history with HTTPQL filters |
| `caido_send_request` | 60s | Replay and modify HTTP requests |
| `caido_automate` | 90s | Intruder-style fuzzing with `§FUZZ§` byte markers |
| `caido_get_findings` | — | Retrieve annotated vulnerability findings |
| `caido_intercept` | — | Enable/disable intercept mode |

### HTTPQL Filter Examples

```
# All POST requests to /api
method:POST AND path:/api

# Requests with Authorization header from specific host
header:Authorization AND host:example.com

# Find 500 errors
status:500
```

### §FUZZ§ Markers

The `caido_automate` tool uses `§FUZZ§` byte-offset markers identical to Burp Suite Intruder:

```
# Raw request with fuzz marker:
POST /api/login HTTP/1.1
Host: example.com
Content-Type: application/json

{"username": "§FUZZ§", "password": "test"}
```

---

## Fuzzing Engine

AIRecon includes a built-in fuzzing engine separate from external tools like ffuf or wfuzz.

### Architecture

```
FuzzTarget (URL, parameter, method, context)
    │
    ▼
MutationEngine
    ├── SQL injection (1000+ payloads)
    ├── XSS (800+ payloads)
    ├── SSRF (500+ payloads)
    ├── SSTI (300+ payloads)
    ├── Path traversal (400+ patterns)
    └── Command injection (600+ payloads)
    │
    ▼
ExpertHeuristics
    ├── Technology-specific payload selection
    ├── WAF fingerprint → bypass routing
    └── Context-aware injection point scoring
    │
    ▼
ExploitChainEngine
    ├── SSRF → CSRF chain patterns
    ├── SQLi → file read chains
    ├── XSS → account takeover
    └── Zero-day discovery patterns
```

### Fuzzing Tools

| Tool | Use case |
|------|----------|
| `quick_fuzz` | Fast single-parameter sweep, 10–50 payloads |
| `advanced_fuzz` | Multi-vector with heuristic payload selection |
| `deep_fuzz` | Exhaustive — all payload categories + ExploitChainEngine |
| `generate_wordlist` | Context-aware custom wordlist generation |
| `schemathesis_fuzz` | OpenAPI/Swagger schema-aware API fuzzing |

---

## API Schema Fuzzing (Schemathesis)

When a target exposes an OpenAPI or Swagger specification, AIRecon uses Schemathesis to perform property-based API fuzzing.

### Auto-Discovery

Schemathesis automatically discovers specs from common paths:

```
/openapi.json
/swagger.json
/api/docs
/api/v1/openapi.json
/docs/openapi.json
```

### What It Tests

For **every documented endpoint**, Schemathesis generates test cases checking for:

| Check | Description |
|-------|-------------|
| HTTP 500 errors | Unhandled exceptions — likely RCE or injection vector |
| Schema validation failures | Server accepts invalid input — broken validation |
| Missing authentication | Endpoint accessible without auth header |
| Authorization bypass | User A can access User B's resources |
| Content-type confusion | Accepts unexpected content types |

### Usage

```
# Auto-discover and fuzz
schemathesis_fuzz url=https://example.com/openapi.json

# With Bearer token
schemathesis_fuzz url=https://example.com/openapi.json auth="Bearer eyJ..."

# With API key
schemathesis_fuzz url=https://example.com/openapi.json headers={"X-API-Key": "secret"}
```

---

## Technology Fingerprinting

AIRecon parses technology fingerprint data from multiple tool outputs and stores them in structured session state.

### Parsed Sources

| Tool | Output parsed |
|------|--------------|
| `whatweb` | JSON mode: `--log-json` — tech name + version |
| `httpx` | `-tech-detect` flag — tech list in JSON output |
| `nuclei` | Technology detection templates |

### Session Storage

Technologies are stored per-host in `session.technologies`:

```json
{
    "api.example.com": ["nginx/1.24", "PHP/8.1", "Laravel", "MySQL"],
    "app.example.com": ["Node.js/20.0", "React", "Express", "Redis"]
}
```

### Feeds the Correlation Engine

As soon as fingerprinting data is parsed, the correlation engine fires automatically (see below).

---

## Correlation Engine

The correlation engine automatically suggests likely vulnerabilities based on detected technologies and open ports.

### Rule Sources

| Source | Count | Example |
|--------|-------|---------|
| Port correlations (`data/port_correlations.json`) | 40+ | Port 6379 open → Redis without auth, try `redis-cli -h <host>` |
| Technology correlations (`data/tech_correlations.json`) | 86+ | `Laravel` → check CVE-2021-3129 (RCE via deserialization) |
| CVE correlations (`data/cve_correlations.json`) | 50+ | `Log4j` in tech → test Log4Shell payloads immediately |
| Attack chains (`data/attack_chains.json`) | 32+ | SSRF → internal scan → pivot patterns |
| Business logic patterns | 18+ | Race conditions, IDOR chains, auth bypass patterns |
| Zero-day patterns | 17+ | Novel vulnerability discovery patterns |

### Output

Correlation suggestions are injected into the agent's context as:

```
[CORRELATION] Detected: nginx/1.24 on port 443
  → Check for CVE-2023-44487 (HTTP/2 Rapid Reset)
  → Test for server-side request forgery via internal proxy
```

---

## Multi-Agent System

### spawn_agent

Spawns a depth=1 specialist agent focused on a single domain. The main agent loop continues while the specialist runs in parallel.

**Available specialists:**

| Specialist | Focus |
|-----------|-------|
| `sqli` | SQL injection testing — all vectors, WAF bypass |
| `xss` | XSS discovery — reflected, stored, DOM, CSP bypass |
| `ssrf` | SSRF probing — cloud metadata, internal ports, protocol wrappers |
| `lfi` | Local/remote file inclusion and path traversal |
| `recon` | Deep subdomain/port/crawl recon on a single target |
| `exploit` | PoC development and exploitation for confirmed vulns |
| `analyzer` | Code review and static analysis |
| `reporter` | Report consolidation and formatting |

Results from the specialist are merged back into the main session on completion, including vulnerability deduplication.

### run_parallel_agents

Runs multiple agents concurrently against different targets. Bounded by a semaphore to prevent resource exhaustion.

```
run parallel recon on: target1.com, target2.com, target3.com
```

Each agent has its own isolated workspace and session. Findings are aggregated at the end.

### AgentGraph (DAG)

Sequential multi-agent pipelines via directed acyclic graph:

```
Recon Agent
    ↓
Analyzer Agent
    ↓
Exploiter Agent + Specialist Agents (parallel)
    ↓
Reporter Agent
```

Used for fully automated, structured end-to-end assessments.

---

## Session Persistence & Resume

All session data is stored at `~/.airecon/sessions/<session_id>.json`:

```json
{
    "session_id": "abc123",
    "target": "example.com",
    "subdomains": ["sub1.example.com", "api.example.com"],
    "live_hosts": ["https://sub1.example.com"],
    "open_ports": {"sub1.example.com": [80, 443, 8080]},
    "technologies": {"sub1.example.com": ["nginx/1.24", "PHP/8.1"]},
    "urls": ["https://sub1.example.com/api/v1/users"],
    "vulnerabilities": [
        {
            "type": "SQL Injection",
            "endpoint": "/api/login",
            "severity": "HIGH",
            "cvss": 9.1,
            "confirmed": true
        }
    ],
    "attack_chains": [],
    "auth_cookies": {"session": "abc123def456"},
    "auth_tokens": {"Authorization": "Bearer eyJ..."},
    "completed_phases": ["RECON", "ANALYSIS"]
}
```

### Resume

```text
airecon start --session <session_id>
```

The agent re-reads all prior findings and picks up exactly where it left off — skipping work already done.

### Vulnerability Deduplication

Vulnerabilities are deduplicated using **Jaccard similarity** on title + endpoint + description. If a new finding has similarity ≥ `vuln_similarity_threshold` (default: 0.7) with an existing entry, it is merged rather than duplicated.

---

## Anti Context-Loss

AIRecon uses multiple mechanisms to keep long sessions stable:
- Periodic session summaries injected into context
- Token usage monitoring with adaptive truncation
- LLM-based compression with rolling memory handoff
- Local fallback summaries if remote context reset fails
- VRAM/OOM recovery with reduced context windows to keep the run alive

Intervals and thresholds are configurable in `config.yaml`.

### Tested Endpoints Memory

`SessionData.tested_endpoints` tracks endpoints the agent has already tested. Recent items are re-injected into context after truncation to reduce duplicate testing.

### Session Persistence

All findings are continuously persisted to `~/.airecon/sessions/<session_id>.json`. On resume (`airecon start --session <id>`), the agent re-reads all prior findings including subdomains, vulnerabilities, technologies, tested endpoints, and auth tokens.

---

## @/file and @/folder References

You can reference local files or directories directly in the chat input using `@/path` syntax. AIRecon automatically copies the referenced content into the Docker workspace and includes it in the agent's context.

### Supported Inputs

| Syntax | Behavior |
|--------|----------|
| `@/path/to/file.txt` | Copy single file to `workspace/uploads/`, read content into context |
| `@/path/to/dir/` | Copy directory tree to `workspace/uploads/` and summarize: up to 40 text files, 50KB each, 200KB total |
| `@/path/to/script.py` | Non-text files (binary) are copied but not read into context |

### Example Usage

```
analyze this burp export: @/home/user/Downloads/burp_export.xml
check this config for secrets: @/etc/nginx/nginx.conf
review my source code: @/home/user/projects/webapp/src/
```

### Copy Summary

After copying, AIRecon reports:
```
Files read into context: 12 | Skipped: 2 binary/non-text, 1 too large (>50KB), 3 over read limit (40 files / 200KB)
```

---

## TUI — Slash Command Autocomplete

In the chat input, typing `/` triggers an autocomplete dropdown listing available slash commands. The exact command set depends on your build and configuration.

Press `Tab` or `↓/↑` to navigate, `Enter` to select. The dropdown closes on `Escape` or when you continue typing beyond the autocomplete scope.

---

## Skills System

Skills are Markdown files in `airecon/proxy/skills/` that give the agent specialized knowledge on demand without permanently bloating the system prompt.

**How it works:**
1. At startup, AIRecon builds an index of available skills
2. When the agent detects a relevant technology or vuln class, it calls `read_file` with the skill path
3. The skill content is loaded into context for that session

**Why on-demand?** Loading every skill at startup would consume substantial context window budget for most targets.

**Keyword mappings:** skill suggestions are driven by pattern matches in the system prompt and session signals.

To add your own skill, see [Adding Custom Skills](development/creating_skills.md).

---

## Local Knowledge Base

AIRecon can query a locally indexed security knowledge base via the `dataset_search` tool. The knowledge base is built from curated HuggingFace datasets and stored as SQLite FTS5 databases at `~/.airecon/datasets/`.

### Setup

```bash
git clone https://github.com/pikpikcu/airecon-dataset.git
cd airecon-dataset
python install.py
```

Restart AIRecon — the tool is available immediately with no config changes.

### What's Indexed

| Dataset | Records | Coverage |
|---------|---------|---------|
| Pentest Agent (CVE workflows) | 322,433 | Enumeration → exploitation chains, MITRE ATT&CK, NVD |
| CTF SaTML 2024 | 190,657 | Real attack/defense interaction data |
| CTF Instruct | 141,182 | Pwn, web, crypto, forensics, reverse engineering |
| Cybersecurity CVE | 124,732 | CVE analysis, CVSS, exploitation context |
| SQL Injection Q&A | 50,632 | Conversational SQLi — detection, bypass, exploitation |
| Red Team Offensive | 78,430 | Lateral movement, privilege escalation, evasion |
| Cybersecurity Fenrir | 83,918 | Attack/defense instruction pairs |
| Cybersecurity Q&A | 53,199 | Broad security Q&A |
| StackExchange Reverse Engineering | 20,641 | Binary analysis, disassembly, debugging, malware, CTF RE |
| Nuclei Templates | 23,180 | Nuclei YAML template generation |
| NVD Security Instructions | 2,063 | Structured CVE analysis — severity, affected systems, remediation |
| APT Privilege Escalation | 1,000 | Linux priv esc techniques with APT tactics and commands |
| Bug Bounty & Pentest | 146 | Rich technique entries with payloads and bypass methods |

**~1,092,213 total records across 13 datasets**

### How the Agent Uses It

The system prompt instructs the agent to query `dataset_search` **before** attempting unknown techniques. This reduces hallucination and surfaces concrete techniques, payloads, and exploitation steps grounded in real data.

```
# Agent uses it automatically, e.g.:
dataset_search: {"query": "log4j RCE exploitation chain"}
dataset_search: {"query": "nuclei template SSRF detection"}
dataset_search: {"query": "WAF bypass SQL injection", "category": "bug-bounty"}
```

Results are ranked by FTS5 relevance and capped at 500 chars each to preserve LLM context budget. Special characters (CVE dashes, angle brackets) are sanitized automatically.

### Category Filters

| Category | Content |
|----------|---------|
| `vulnerability` | CVE-focused entries |
| `bug-bounty` | Bug bounty techniques and payloads |
| `ctf` | CTF challenges and writeups |
| `pentest` | Red team and offensive techniques |
| `general` | Broad cybersecurity knowledge |

### Custom Knowledge

Add your own `.jsonl` files to `airecon-dataset/custom/` and re-run `install.py`. Useful for internal wiki content, proprietary technique notes, or target-specific intelligence.

See [airecon-dataset](https://github.com/pikpikcu/airecon-dataset) for the full dataset list, install options, and adding new datasets.

---

## Verified Vulnerability Reporting

The `create_vulnerability_report` tool generates professional penetration test reports.

### Validation Rules

All fields are validated before a report is accepted:

| Field | Requirement |
|-------|-------------|
| `poc_script_code` | >50 characters, must contain a real target URL |
| `poc_description` | Must include HTTP status code evidence (e.g., "HTTP 200", "302 redirect") |
| `technical_analysis` | >80 characters |
| Language check | Reports using "might", "possibly", "could be" without evidence are rejected |
| CVSS vector | Must be a valid CVSS 3.1 vector string |

### Report Structure

```markdown
# <Vulnerability Type> in <Endpoint>

**Severity:** <CRITICAL/HIGH/MED/LOW> (CVSS <score>)
**Endpoint:** <method> <path>

## Technical Analysis
## Proof of Concept
## Evidence (HTTP request/response)
## Impact
## Suggested Fix (optional code snippet)
## CVSS Vector
## Remediation
```

### Suggested Fix

Reports can optionally include a `suggested_fix` field with a developer-ready code snippet:

```
create_vulnerability_report(..., suggested_fix="cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))")
```

---

## Workspace Isolation

Each target gets a fully isolated directory:

```
workspace/<target>/
├── output/          # Tool outputs (.txt, .json, .xml, .nmap, ...)
│   ├── subdomains.txt
│   ├── live_hosts.txt
│   ├── nmap_full.xml
│   └── nuclei_results.json
├── command/         # Execution metadata and logs (.json)
├── tools/           # AI-generated scripts (.py, .sh)
└── vulnerabilities/ # Vulnerability reports (.md)
    ├── sql_injection_api_login.md
    └── idor_user_profile.md
```

The agent always operates from within this directory — relative paths prevent workspace corruption across targets.

---

## URL Pattern Matching (gf)

The `gf` tool (grep with named patterns) is pre-configured with security-focused patterns to classify and filter URL lists for targeted testing:

| Pattern | What it flags |
|---------|---------------|
| `xss` | Parameters likely to be reflected (`q=`, `search=`, `msg=`) |
| `sqli` | Parameters suspicious for SQL injection (`id=`, `order=`, `where=`) |
| `ssrf` | Parameters that accept URLs (`url=`, `redirect=`, `next=`, `dest=`) |
| `lfi` | Parameters that look like file paths (`file=`, `path=`, `template=`) |
| `idor` | Numeric or UUID identifiers in paths (`/user/123`, `/account/uuid`) |
| `rce` | Command-injection-prone parameters (`cmd=`, `exec=`, `shell=`) |
| `redirect` | Open redirect candidates (`return=`, `goto=`, `callback=`) |
| `cors` | CORS-related response headers |

---

## Anti-Hallucination Controls

AIRecon includes multiple mechanisms to prevent the LLM from hallucinating tool outputs or vulnerability findings.

### Hallucination Detection

The agent loop checks for common hallucination patterns in model output:

```python
hallucination_signals = [
    "i have found",           # Claims finding without tool output
    "the scan shows",         # Claims scan result without running scan
    "the results indicate",   # Claims results without tool evidence
    "my analysis shows",      # Claims analysis without code_analysis tool
    "it appears that",        # Speculative claim without evidence
    "based on my knowledge",  # LLM knowledge, not live tool output
    "without running",        # Explicitly admits no tool used
]
```

### Tool Call Validation

Before accepting a tool call, the agent validates:
1. Tool name exists in registered tools
2. Required arguments are provided
3. Argument types match schema

### Evidence Requirement

Vulnerability reports require concrete evidence:
- HTTP request/response pairs
- Screenshot or PoC script
- CVSS vector string

Reports without evidence are rejected with:
```
[VALIDATION ERROR] Vulnerability report rejected: missing evidence. 
Include HTTP response, PoC script, or screenshot.
```

### Confidence Scoring

All findings include a confidence score (0.0–1.0):
- ≥0.65 = high confidence (confirmed)
- 0.4–0.65 = medium confidence (likely)
- <0.4 = low confidence (speculative)

Low-confidence findings are flagged for manual review.

---

## MCP Support

AIRecon supports external **Model Context Protocol (MCP) servers** for extended tool capabilities. MCP servers expose tools via HTTP (SSE) or command-line transport.

### Setup

Add MCP servers via TUI slash command or config:

```
/mcp add http://localhost:3001 auth:apikey:yourtoken example_name
```

Or add to `~/.airecon/mcp.json`:

```json
{
  "mcpServers": {
    "hexstrike": {
      "command": "python3",
      "args": [
        "/path/hexstrike-ai/hexstrike_mcp.py",
        "--server",
        "http://127.0.0.1:8888"
      ],
      "env": {
        "PYTHONUNBUFFERED": "1"
      },
      "enabled": true
    },
    "xssgen": {
      "command": "python3",
      "args": [
        "/path/xssgen/xss_client.py",
        "--server",
        "http://127.0.0.1:8000"
      ],
      "env": {
        "PYTHONUNBUFFERED": "1"
      },
      "enabled": true
    },
    "context7": {
      "transport": "sse",
      "url": "https://example.com/mcp",
      "enabled": true,
      "headers": {
        "Authorization": "Bearer xxxxx"
      }
    }
  }
}     
```

### Available Commands

| Command | Description |
|---------|-------------|
| `/mcp` | Show MCP command help/usage |
| `/mcp list` | List configured MCP servers with readiness info (when available) |
| `/mcp list <name>` | Show tools from a specific server (output may be truncated) |
| `/mcp add <url> auth:user/pass|auth:apikey:<token> [name]` | Add MCP server with optional auth |
| `/mcp enable <name>` | Enable a disabled server |
| `/mcp disable <name>` | Disable active server |

### Tool Usage

MCP tools are exposed to the agent as `mcp_<server_name>`. The LLM can:

- `action=list_tools`: Get tools (may be truncated for readability)
- `action=search_tools query=<keyword>`: Find tools by name/description
- `action=call_tool tool=<name> arguments={...}`: Execute a tool

### Example

```
agent → mcp_example(action=list_tools)
→ {"tools": [{"name": "nmap_scan"}, ...]}

agent → mcp_example(action=search_tools query="nmap")
→ {"tools": [{"name": "nmap_scan"}], "count": 1}

agent → mcp_example(action=call_tool tool="nmap_scan" arguments={"target": "192.168.1.1"})
→ {"result": {"output": "PORT     STATE SERVICE", ...}}
```

### Display

| TUI Command | Output |
|-------------|--------|
| `/mcp list` | `🟢 example - Ready (tool count if provided)` |
| `/mcp list example` | Shows tools (truncated for readability) |

---

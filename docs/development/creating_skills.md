# Skills System — Complete Guide

## Table of Contents

1. [What are Skills?](#1-what-are-skills)
2. [How Skills Work Internally](#2-how-skills-work-internally)
3. [Available Skills Reference](#3-available-skills-reference)
4. [airecon-skills Community Library](#4-airecon-skills-community-library)
5. [Creating a Custom Skill](#5-creating-a-custom-skill)
6. [Skill Writing Guidelines](#6-skill-writing-guidelines)
7. [Full Skill Template](#7-full-skill-template)
8. [Testing Your Skill](#8-testing-your-skill)

---

## 1. What are Skills?

Skills are plain Markdown (`.md`) files stored in `airecon/proxy/skills/`. They contain specialized knowledge about attack techniques, tool usage, and testing procedures for specific technologies or vulnerability classes.

**Skills complement the system prompt.** The system prompt gives the agent general security methodology. Skills provide deep, specific knowledge on-demand — without bloating the main prompt with information that is irrelevant to most targets.

**Examples of what skills contain:**
- Step-by-step testing checklists for a specific vulnerability (e.g., SQLi, SSRF)
- Exact tool commands for a specific technology (e.g., GraphQL introspection, Firebase rules)
- Payload collections tailored to a specific attack surface
- Knowledge about a specific framework's security model (e.g., Next.js server actions, FastAPI auth)

---

## 2. How Skills Work Internally

### 2.1 Discovery at startup

When AIRecon starts, `system.py` scans the entire `skills/` tree and builds a list of all `.md` files with their absolute paths:

```python
# airecon/proxy/system.py
def _load_local_skills() -> str:
    skills_dir = Path(__file__).resolve().parent / "skills"
    for path in sorted(skills_dir.rglob("*.md")):
        parts.append(f"- {path.absolute().as_posix()}")
```

This list is injected into the system prompt as an `<available_skills>` block:

```
<available_skills>
You have access to the following skill documents. If you need specific guidance
on a topic, use the `read_file` tool with the EXACT absolute path listed below:
- /home/user/.../airecon/proxy/skills/vulnerabilities/xss.md
- /home/user/.../airecon/proxy/skills/vulnerabilities/sqli.md
- /home/user/.../airecon/proxy/skills/protocols/graphql.md
...
</available_skills>
```

### 2.2 On-demand loading by the agent

The agent does **not** preload skill content into its context. Skills are loaded on demand using the `read_file` tool:

```
# Agent calls:
read_file(path="/absolute/path/to/skills/vulnerabilities/ssrf.md")
```

The agent decides to read a skill when:
- It detects a relevant technology in scan results (e.g., `whatweb` returns "GraphQL")
- It encounters a vulnerability class it wants detailed guidance on
- The user prompt references a specific topic (e.g., "test for JWT issues")
- A tool output contains keywords that match a skill topic

### 2.3 Why this design?

Loading all skills at startup would consume 50,000+ tokens of context window — wasted on irrelevant content for most targets. On-demand loading means the agent only pays the context cost for skills it actually needs.

---

## 3. Available Skills Reference

### Vulnerabilities (`skills/vulnerabilities/`)

| File | Topic |
|------|-------|
| `api_testing.md` | REST/SOAP/GraphQL parameter discovery, verb tampering, rate limit bypass |
| `authentication_jwt.md` | JWT attacks: alg:none, weak secrets, RS256→HS256 confusion, kid injection |
| `bfla.md` | BFLA / privilege escalation via HTTP method tampering |
| `business_logic.md` | Business logic flaws, 7-step procedure, workflow abuse, state machine attacks |
| `csrf.md` | CSRF bypass techniques: SameSite confusion, token stealing, JSON CSRF, multipart |
| `deserialization.md` | Java gadget chains, PHP object injection, Python pickle, .NET deserialization |
| `exploitation.md` | General exploitation patterns, PoC construction, post-exploitation |
| `grpc.md` | gRPC proto enumeration, reflection API abuse, auth bypass, injection |
| `http_smuggling.md` | CL.TE, TE.CL, TE.TE desync, request tunneling |
| `idor.md` | IDOR discovery and exploitation: numeric, UUID, encoded IDs |
| `information_disclosure.md` | Sensitive data leakage: error messages, debug endpoints, JS secrets |
| `insecure_file_uploads.md` | File upload bypass: extension spoofing, polyglots, path traversal via upload |
| `kubernetes.md` | RBAC misconfig, etcd exposure, container escape, service account abuse |
| `mass_assignment.md` | Mass assignment and parameter pollution attacks |
| `oauth_saml.md` | Authorization code abuse, implicit flow, SAML assertion manipulation |
| `open_redirect.md` | Open redirect detection and OAuth `redirect_uri` abuse |
| `path_traversal.md` | Path traversal, LFI, RFI, PHP wrapper chains, log poisoning |
| `privilege_escalation.md` | Vertical/horizontal privilege escalation, JWT privilege claims, role confusion |
| `prototype_pollution.md` | Client-side and server-side (Node.js), lodash/merge sinks |
| `race_conditions.md` | Race condition testing: limit bypass, TOCTOU, last-write-wins |
| `rce.md` | Remote code execution via SSTI, command injection, deserialization gadgets |
| `sql_injection.md` | SQLi: error-based, blind, time-based, OOB, WAF bypass, SQLMap advanced |
| `ssrf.md` | SSRF: cloud metadata, internal ports, DNS rebinding, protocol wrappers, filter bypass |
| `ssti.md` | SSTI: Jinja2, Twig, Freemarker, Smarty, Pebble template injection |
| `subdomain_takeover.md` | Takeover detection and exploitation for unclaimed DNS/cloud resources |
| `supply_chain.md` | Dependency confusion, typosquatting, malicious package injection |
| `waf_detection.md` | WAF fingerprinting, bypass techniques, encoding evasion |
| `web_cache_poisoning.md` | Header injection, cache key normalization, CPDoS |
| `websocket.md` | WS hijacking, CSWSH, protocol downgrade, message injection |
| `xss.md` | XSS: reflected, stored, DOM-based, mutation, CSP bypass, exfiltration |
| `xxe.md` | XXE: file read, SSRF via DTD, billion laughs, SVG/XLSX vectors |

### Reconnaissance (`skills/reconnaissance/`)

| File | Topic |
|------|-------|
| `full_recon.md` | 19KB Standard Operating Procedure — complete recon workflow with concrete success criteria, tool sequencing, artifact requirements, and phase transition rules |

### Frameworks (`skills/frameworks/`)

| File | Topic |
|------|-------|
| `fastapi.md` | FastAPI security: dependency injection abuse, auth bypass, OpenAPI exposure, validation bypass |
| `nextjs.md` | Next.js security: middleware bypass, server actions, API routes, ISR cache poisoning, SSRF via redirects |

### Technologies (`skills/technologies/`)

| File | Topic |
|------|-------|
| `cloud_security.md` | AWS/GCP/Azure misconfigs: S3 ACLs, IAM privilege escalation, metadata service abuse |
| `firebase_firestore.md` | Firebase security rules testing, unauthenticated access, NoSQL injection |
| `supabase.md` | Supabase RLS bypass, storage misconfigs, service key exposure, API key abuse |

### Protocols (`skills/protocols/`)

| File | Topic |
|------|-------|
| `active_directory.md` | Kerberoasting, AS-REP roasting, BloodHound, lateral movement, DCSync |
| `graphql.md` | GraphQL introspection, injection, batching abuse, IDOR via aliases, DoS |

### Payloads (`skills/payloads/`)

| File | Topic |
|------|-------|
| `command_injection.md` | Command injection payload collection with filter bypass variants |
| `lfi.md` | LFI payload collection: path normalization, PHP wrappers, null bytes |
| `sqli.md` | SQL injection payload collection by database type and technique |
| `ssrf.md` | SSRF payload collection: cloud metadata URLs, protocol wrappers |
| `ssti.md` | SSTI payload collection by template engine |
| `xss.md` | XSS payload collection: filter bypass, DOM sinks, CSP bypass |
| `xxe.md` | XXE payload collection: OOB exfil, DTD injection, SVG/XLSX vectors |

### Tools (`skills/tools/`)

| File | Topic |
|------|-------|
| `advanced_fuzzing.md` | AIRecon fuzzing engine usage: quick_fuzz, advanced_fuzz, deep_fuzz, schemathesis |
| `browser_automation.md` | Playwright browser automation: auth flows, JS execution, network capture |
| `caido.md` | Caido proxy integration: HTTPQL filters, §FUZZ§ markers, automate patterns |
| `dalfox.md` | Dalfox XSS scanner: flags, blind XSS, DOM scan, custom payloads |
| `install.md` | Tool installation procedures for the Kali sandbox |
| `nmap.md` | Nmap usage: script categories, output formats, NSE scripts for web |
| `nuclei.md` | Nuclei templates: custom templates, severity filters, OOB templates |
| `scripting.md` | 81KB scripting guide: Python patterns for HTTP testing, auth, rate limiting |
| `semgrep.md` | Semgrep SAST: custom rules, OWASP rulesets, triage workflow |
| `sqlmap.md` | SQLmap: tamper scripts, blind injection, file read/write, OS shell |
| `tool_catalog.md` | Full catalog of all preinstalled Kali sandbox tools with usage examples |

---

## 4. airecon-skills Community Library

**[airecon-skills](https://github.com/pikpikcu/airecon-skills)** is the official community skill library for AIRecon — a collection of CLI-based playbooks for CTF, bug bounty, and pentesting that extend the built-in skill set.

### What's included

The library provides specialized skills not bundled with AIRecon by default:

| Category | Examples |
|----------|---------|
| CTF | Reverse engineering, binary exploitation, crypto challenges, web CTF |
| Bug Bounty | Platform-specific recon SOPs, disclosure tips, P1 hunting patterns |
| Protocols | MQTT, Redis, MongoDB, Kafka, Elasticsearch attack playbooks |
| Cloud | AWS privilege escalation chains, GCP service account abuse, Azure AD attacks |
| Mobile | Android APK decompile + secrets scan, iOS plist inspection |
| Frameworks | Django, Rails, Spring Boot, Laravel, WordPress deep dives |

### Installation

```bash
# Clone into your local skills directory
git clone https://github.com/pikpikcu/airecon-skills ~/.airecon/skills

# Or clone alongside the built-in skills
git clone https://github.com/pikpikcu/airecon-skills /path/to/airecon-skills
```

Then configure AIRecon to load skills from the additional directory by setting the path in your config or by symlinking into the built-in skills folder:

```bash
# Option 1: Symlink into built-in skills (recommended)
ln -s ~/.airecon/skills/skills/* /path/to/airecon/airecon/proxy/skills/

# Option 2: Copy skills you want
cp -r ~/.airecon/skills/skills/ctf /path/to/airecon/airecon/proxy/skills/
```

After adding skills, restart AIRecon — they will appear automatically in `<available_skills>`.

### Verifying community skills are loaded

```bash
python3 -c "
from airecon.proxy.system import get_system_prompt
p = get_system_prompt()
start = p.find('<available_skills>')
end = p.find('</available_skills>') + len('</available_skills>')
print(p[start:end])
" | grep -i ctf  # or whatever category you added
```

### Contributing to airecon-skills

If you write a skill that could be useful to others, consider contributing it upstream:

1. Fork [github.com/pikpikcu/airecon-skills](https://github.com/pikpikcu/airecon-skills)
2. Add your skill in the appropriate category folder
3. Follow the [Skill Writing Guidelines](#6-skill-writing-guidelines) below
4. Open a pull request

---

## 5. Creating a Custom Skill

### Step 1: Choose the right location

**Built-in skills** (ship with AIRecon): add to `airecon/proxy/skills/<category>/`

**Community skills** (airecon-skills library): contribute to [github.com/pikpikcu/airecon-skills](https://github.com/pikpikcu/airecon-skills)

**Private skills** (your own): place anywhere and symlink into the built-in skills directory.

### Step 2: Choose the right category

| Your skill is about... | Folder |
|-----------------------|--------|
| A specific vulnerability class | `skills/vulnerabilities/` |
| A web framework | `skills/frameworks/` |
| A backend technology or SaaS | `skills/technologies/` |
| A protocol (GraphQL, WebSocket, gRPC, AD) | `skills/protocols/` |
| Recon methodology / SOP | `skills/reconnaissance/` |
| Payload collections | `skills/payloads/` |
| Tool usage guide | `skills/tools/` |

### Step 3: Create the file

```bash
# Example: adding a WebSocket testing skill
touch airecon/proxy/skills/protocols/websocket.md
```

### Step 4: Write the skill (see [Full Template](#7-full-skill-template) below)

### Step 5: Restart AIRecon

Skills are scanned at startup. Restart for the new file to appear in the `<available_skills>` list.

```bash
# Stop current session and restart
airecon start
```

### Step 6: Verify

Ask the agent to check a relevant target. When it detects the relevant technology, it should read your skill. You can also manually trigger it:

```
# In the TUI, type:
read the websocket skill and test this target for WebSocket vulnerabilities
```

---

## 6. Skill Writing Guidelines

### DO: Be specific and actionable

```markdown
# Good
Run: `python3 /home/pentester/tools/jwt_tool/jwt_tool.py <token> -X a`
This tests the alg:none bypass — if it succeeds, the server accepts unsigned tokens.

# Bad
"Test the JWT implementation for common vulnerabilities."
```

### DO: Include exact commands with real flags

```markdown
# Good
`subfinder -d <target> -all -recursive -o output/subdomains.txt`

# Bad
"Use subfinder to find subdomains."
```

### DO: Explain what success looks like

```markdown
**Success indicator:** Response changes from 403 to 200, or user data from a different account appears in the response body.
```

### DO: Keep payloads focused — 5 representative ones, not 50

```markdown
# Good (5 payloads covering different bypass patterns)
```sql
' OR 1=1--
' OR '1'='1
admin'--
' UNION SELECT NULL--
1; DROP TABLE users--
```

### DON'T: Write generic advice

```markdown
# Bad — this is already in the system prompt
"Test all endpoints for injection vulnerabilities."
```

### DON'T: Add lengthy prose explanations

Skills go into context window. Every word costs tokens. If something is already covered by general security knowledge, skip it.

### DON'T: Add more than one vulnerability class per file

Split `sql_and_nosql_injection.md` into `sql_injection.md` and `nosql_injection.md`. The agent searches for specific skills — mixing topics makes skills harder to locate and use efficiently.

---

## 7. Full Skill Template

```markdown
# <Skill Name>

**Trigger condition:** <When should the agent load this skill? What observation in scan output indicates this skill is relevant?>

## Overview
<2–3 sentences max. What is this vulnerability/technology and why does it matter for security testing?>

## Detection
How to confirm the target uses this technology or is affected:

```bash
# Detection command 1
<exact command>

# Detection command 2
<exact command>
```

**Indicators in tool output:**
- `<string or pattern to look for in httpx/nuclei/browser output>`
- `<another indicator>`

## Testing Checklist

### Test 1: <Name>
**Tool:** `<command with exact flags>`
**What to look for:** `<success indicator>`

### Test 2: <Name>
**Tool:** `<command>`
**What to look for:** `<success indicator>`

### Test 3: <Name> (Manual)
1. `<step 1>`
2. `<step 2>`
3. `<expected result>`

## Key Payloads

```
<payload 1 — covers bypass pattern A>
<payload 2 — covers bypass pattern B>
<payload 3 — WAF evasion variant>
```

## Tools Available

| Tool | Command | Purpose |
|------|---------|---------|
| `<tool>` | `<exact invocation>` | <one-line purpose> |
| `python3 /home/pentester/tools/<t>/<s>.py` | `<args>` | <purpose> |

## Exploitation (When Vulnerability is Confirmed)

1. Document: capture the exact request/response pair demonstrating impact
2. Prove impact: `<exact command or payload that demonstrates damage>`
3. Report: call `create_vulnerability_report` with:
   - `poc_script_code`: working Python script that reproduces the issue
   - `impact`: exact data accessed or action taken

## Common Bypasses

- **WAF filter:** `<bypass technique>`
- **Encoding:** `<alternative encoding>`
- **Edge case:** `<less-obvious variant>`

## Remediation Summary
- <Fix point 1>
- <Fix point 2>
```

---

## 8. Testing Your Skill

After creating a skill, verify it works as expected:

**1. Check it appears in the skill list:**

```bash
# Start AIRecon and look at the system prompt (dev mode)
python3 -c "
from airecon.proxy.system import get_system_prompt
p = get_system_prompt()
# Find the available_skills block
start = p.find('<available_skills>')
end = p.find('</available_skills>') + len('</available_skills>')
print(p[start:end])
"
```

**2. Test the read_file path directly:**

```bash
# Find the exact absolute path AIRecon will use
python3 -c "
from pathlib import Path
import airecon.proxy.system as sp
skills_dir = Path(sp.__file__).resolve().parent / 'skills'
for p in sorted(skills_dir.rglob('*.md')):
    if 'your_skill_name' in str(p):
        print(p.absolute().as_posix())
"
```

**3. Manually trigger in the TUI:**

```
# Type in the TUI:
read the skill at /absolute/path/to/your/skill.md and summarize it
```

If the agent reads and summarizes it correctly, the skill is working.

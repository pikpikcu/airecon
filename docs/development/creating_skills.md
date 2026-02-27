# Skills System — Complete Guide

## Table of Contents

1. [What are Skills?](#1-what-are-skills)
2. [How Skills Work Internally](#2-how-skills-work-internally)
3. [Available Skills Reference](#3-available-skills-reference)
4. [Creating a Custom Skill](#4-creating-a-custom-skill)
5. [Skill Writing Guidelines](#5-skill-writing-guidelines)
6. [Full Skill Template](#6-full-skill-template)
7. [Testing Your Skill](#7-testing-your-skill)

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
| `authentication_jwt.md` | JWT attacks: alg:none, weak secrets, RS256→HS256 confusion, kid injection |
| `broken_function_level_authorization.md` | BFLA / privilege escalation via HTTP method tampering |
| `business_logic.md` | Business logic flaws, workflow abuse, state machine attacks |
| `csrf.md` | CSRF bypass techniques: SameSite, token stealing, JSON CSRF |
| `exploitation.md` | General exploitation patterns and PoC construction |
| `idor.md` | IDOR discovery and exploitation: numeric, UUID, encoded IDs |
| `information_disclosure.md` | Sensitive data leakage: error messages, debug endpoints, JS secrets |
| `insecure_file_uploads.md` | File upload bypass: extension spoofing, polyglots, path traversal |
| `mass_assignment.md` | Mass assignment and parameter pollution attacks |
| `open_redirect.md` | Open redirect detection and OAuth flow abuse |
| `path_traversal_lfi_rfi.md` | Path traversal, LFI, and RFI techniques |
| `race_conditions.md` | Race condition testing and TOCTOU exploitation |
| `rce.md` | Remote code execution via SSTI, command injection, deserialization |
| `sql_injection.md` | SQLi: error-based, blind, time-based, OOB, WAF bypass |
| `ssrf.md` | SSRF: cloud metadata, internal ports, protocol wrappers, filter bypass |
| `subdomain_takeover.md` | Takeover detection and exploitation for unclaimed DNS records |
| `xss.md` | XSS: reflected, stored, DOM-based, CSP bypass, exfiltration |
| `xxe.md` | XXE: file read, SSRF via DTD, blind OOB XXE |

### Reconnaissance (`skills/reconnaissance/`)

| File | Topic |
|------|-------|
| `active_scanning.md` | Active scanning methodology and tool selection |
| `comprehensive_recon.md` | Full recon workflow: subdomain → live → crawl → vuln |
| `dns_intelligence.md` | DNS enumeration, zone transfers, DNSSEC analysis |
| `js_recon.md` | JavaScript analysis: endpoint extraction, secret detection, source maps |
| `tls_ssl_recon.md` | TLS/SSL auditing: cipher suites, certificate analysis, weak configs |

### Frameworks (`skills/frameworks/`)

| File | Topic |
|------|-------|
| `fastapi.md` | FastAPI security: dependency injection, auth bypass, OpenAPI exposure |
| `nextjs.md` | Next.js security: server actions, API routes, ISR cache poisoning |

### Technologies (`skills/technologies/`)

| File | Topic |
|------|-------|
| `firebase_firestore.md` | Firebase security rules testing, unauthenticated access |
| `supabase.md` | Supabase RLS bypass, storage misconfigs, service key exposure |

### Protocols (`skills/protocols/`)

| File | Topic |
|------|-------|
| `graphql.md` | GraphQL introspection, injection, batching attacks, DoS |

### Custom (`skills/custom/`)

| File | Topic |
|------|-------|
| `recon.md` | Extended deep recon methodology |
| `advanced_recon_workflow.md` | Advanced chaining and automation patterns |

---

## 4. Creating a Custom Skill

### Step 1: Choose the right category

| Your skill is about... | Folder |
|-----------------------|--------|
| A specific vulnerability class | `skills/vulnerabilities/` |
| A web framework | `skills/frameworks/` |
| A backend technology or SaaS | `skills/technologies/` |
| A protocol (GraphQL, WebSocket, gRPC) | `skills/protocols/` |
| Recon methodology | `skills/reconnaissance/` |
| Anything else / personal techniques | `skills/custom/` |

### Step 2: Create the file

```bash
# Example: adding a WebSocket testing skill
touch airecon/proxy/skills/protocols/websocket.md
```

### Step 3: Write the skill (see [Full Template](#6-full-skill-template) below)

### Step 4: Restart AIRecon

Skills are scanned at startup. Restart for the new file to appear in the `<available_skills>` list.

```bash
# Stop current session and restart
airecon start
```

### Step 5: Verify

Ask the agent to check a relevant target. When it detects the relevant technology, it should read your skill. You can also manually trigger it:

```
# In the TUI, type:
read the websocket skill and test this target for WebSocket vulnerabilities
```

---

## 5. Skill Writing Guidelines

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

## 6. Full Skill Template

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

## 7. Testing Your Skill

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

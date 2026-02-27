---
name: advanced_recon_workflow
description: Concrete workflows for advanced reconnaissance, manual analysis, and "hacker" logic.
---

# Advanced Recon & Hacker Logic

Do not be a "script kiddie". Automated tools (`nuclei`, `subfinder`) are just the beginning. Real vulnerabilities are found by manually analyzing the data.

## 1. JavaScript Analysis (The Gold Mine)
**Goal**: Find hidden API endpoints, hardcoded credentials, and developer comments.

**Workflow**:
1.  **Gather JS URLs**: Use `katana` or `execute_command` with `grep` to find `.js` files.
2.  **Download**: Use `wget` to download them locally.
3.  **Analyze**: Use `grep` or `jq` to find secrets.

**Example Commands (Use `execute_command`)**:
```bash
# Download all JS files to a folder
mkdir -p workspace/<target>/js
wget -P workspace/<target>/js -i workspace/<target>/js_urls.txt

# Grep for secrets
grep -rE "api_key|secret|token|password|auth" workspace/<target>/js

# Extract endpoints
grep -rEo "(http|https)://[a-zA-Z0-9./?=_-]*" workspace/<target>/js
```

## 2. Parameter Fuzzing (The Hidden Door)
**Goal**: Find hidden parameters that trigger debug modes or IDORs.

**Workflow**:
1.  Identify a target endpoint (e.g., `example.com/api/user`).
2.  Use `ffuf` to guess parameter names.

**Example Command**:
```bash
ffuf -u https://<target>/api/v1/user?FUZZ=1 -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -mc 200,401,403,500 -fs 123
```

## 3. Port Scanning (Manual Verification)
**Goal**: Verify services on non-standard ports that `nmap` might miss or misidentify.

**Workflow**:
1.  Run `nmap` with service detection (`-sV`) and default scripts (`-sC`) on *specific* interesting ports found by mass scanners.

**Example Command**:
```bash
nmap -sV -sC -p 8080,8443,9200,27017 <target> -oN workspace/<target>/manual_nmap.txt
```

## 4. Content Discovery (The Deep Dive)
**Goal**: Find admin panels, backups, and config files.

**Workflow**:
1.  Don't just scan `/`. Scan interesting subdirectories.
2.  Look for backup extensions (`.bak`, `.old`, `.zip`).

**Example Command**:
```bash
ffuf -u https://<target>/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files-lowercase.txt -e .php,.html,.json,.bak,.old
```

## 5. "Hacker Logic" Checklist
-   [ ] Did I check the HTML source for comments? `curl -s <url> | grep "<!--"`
-   [ ] Did I check `robots.txt` and `sitemap.xml`?
-   [ ] Did I try to bypass 403 Forbidden errors? (X-Forwarded-For, Host header injection)
-   [ ] Did I look for Subdomain Takeover opportunities?

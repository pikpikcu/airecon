# Full Recon Standard Operating Procedure

This document is for [FULL RECON] engagements ONLY.
For [SPECIFIC TASK] requests, do NOT follow this SOP — execute only what was asked.

---

## Workspace Structure

You execute commands inside the Docker Sandbox. CWD is already the target workspace root.

REQUIRED STRUCTURE (AUTO-CREATED — do NOT run mkdir manually):

    output/          — MANDATORY for all tool outputs
    command/         — system-managed logs. READ ONLY.
    tools/           — custom scripts you create for this target.
    vulnerabilities/ — ONLY write here via create_vulnerability_report tool.

CRITICAL: NEVER use absolute paths starting with /workspace/. ALWAYS use relative paths.
    Correct:   output/file.txt
    Wrong:     /workspace/target/output/file.txt

If a tool fails to output to the directory, move it immediately: mv raw_output.txt output/

---

## Engagement Rules

BROWSER MANDATE: Use browser_action on EVERY web target.
    Visit the site, extract view_source, check for hidden comments, API keys in JS, DOM vulnerabilities.
    Use get_console_logs to find React/Vue errors that leak info.

CAIDO MANDATE: Run caido-setup via execute to start the headless Caido Web Proxy on port 48080
    and retrieve the Bearer token. Use execute to send GraphQL requests or interact via caido-cli
    to intercept and tamper with traffic.

SCRIPTING MANDATE: If a tool does not exist for a specific check, WRITE IT.
    Create tools/fuzz_login.py to brute force a specific parameter.
    Create tools/extract_tokens.py to parse complex JS.

CHAINING: subfinder -> httpx -> nuclei -> browser -> caido -> exploit.

ADVANCED EXECUTION:
    Execute start to finish. Do NOT stop after each step to ask what to do next.
    If a step fails, log it and auto-skip to the next.
    Customize flags — use specific wordlists, aggressive timeouts, and advanced filters.
    Analyze output within scope: finding port 8080 during a port scan means NOTE it —
    do NOT auto-browse it unless it was asked.

---

## Definitions (NON-NEGOTIABLE — Read Before Starting)

### "Live Host" Definition
A host is LIVE if httpx returns ANY of these HTTP status codes: 200, 201, 204, 301, 302, 307, 400, 401, 403, 404, 405, 429, 500, 503.
A host is DEAD only if: connection refused, connection timeout, DNS NXDOMAIN.
    Concrete check: httpx -l output/resolved.txt -status-code -o output/live_hosts.txt
    A "live host" = any line in live_hosts.txt that contains an HTTP status code.
    DO NOT skip 401/403 targets — they are often the most interesting.

### "Phase Complete" Criteria
Phase N is complete when ALL of the following are TRUE:
    ✓ Minimum number of DISTINCT tools have been run (see each phase)
    ✓ Each tool produced at least one output file in output/
    ✓ All output files have been verified non-empty: wc -l output/<file>
    ✗ FAIL: Running a tool that crashes or produces empty output does NOT count as complete
    ✗ FAIL: Running the same tool twice with different flags counts as 1 tool, not 2

### "Distinct Tool" Definition
A "distinct tool" is counted by the BINARY NAME, not the flags:
    ✓ subfinder + amass = 2 distinct tools
    ✗ subfinder -d target1 + subfinder -d target2 = 1 tool (same binary)
    ✗ nmap -sV + nmap -sC = 1 tool (same binary)

---

## Nuclei Hard Gate (ENFORCED BY SYSTEM — CANNOT BE BYPASSED)

nuclei is FORBIDDEN as a first step. The system will BLOCK nuclei unless ALL conditions are met:
    1. Phase 1 complete: at least 2 discovery tools ran AND produced output files with content.
       Verify: wc -l output/subdomains_subfinder.txt output/resolved.txt
    2. Phase 2 complete: at least 2 enumeration tools ran AND produced output files with content.
       Verify: wc -l output/nmap_scan.gnmap output/live_hosts.txt
    3. Live probe: at least ONE manual probe confirmed live hosts.
       Verify: curl -I --max-time 5 <first_live_host_from_httpx> OR httpx returning non-empty live_hosts.txt

If the system blocks nuclei, run the missing Phase tools first, then retry.

MINIMUM TOOL DIVERSITY MANDATE: Each phase MUST use the minimum number of distinct tools listed.
You may NOT proceed to the next phase until: (a) minimum tools run AND (b) output files are non-empty.

---

## Phase 1 — Discovery & Scope (minimum 3 distinct tools)

COMPLETE CRITERIA: output/resolved.txt exists AND wc -l output/resolved.txt shows > 0 lines.

    subfinder -d <target> -o output/subdomains_subfinder.txt
    amass enum -passive -d <target> -o output/subdomains_amass.txt
      OR  assetfinder --subs-only <target> | tee output/subdomains_assetfinder.txt
    gau <target> | grep -oP '^https?://[^/]+' | sort -u | tee output/hosts_gau.txt
    cat output/subdomains_*.txt | sort -u | dnsx -silent -o output/resolved.txt
    httpx -l output/resolved.txt -title -tech-detect -status-code -o output/live_hosts.txt

POST-PHASE CHECK (MANDATORY):
    wc -l output/resolved.txt output/live_hosts.txt
    If both files have >0 lines → Phase 1 COMPLETE.
    If any file is empty → re-run the corresponding tool with different flags or wordlist.

RECURSIVE ANALYSIS: Treat EACH live subdomain as a new target. Do not just scan example.com.

---

## Phase 2 — Enumeration (minimum 3 distinct tools)

COMPLETE CRITERIA: At least 2 of (nmap_scan.gnmap, live_hosts.txt with tech, urls_katana.txt) exist AND are non-empty.

    sudo nmap -sV -sC --open -iL output/resolved.txt -oA output/nmap_scan
      OR  naabu -l output/resolved.txt -o output/ports.txt
    whatweb -i output/live_hosts.txt --log-brief output/whatweb.txt
    katana -l output/live_hosts.txt -o output/urls_katana.txt
      AND  gospider -S output/live_hosts.txt -o output/gospider/
    waybackurls < output/resolved.txt | tee output/wayback.txt
    tlsx -l output/resolved.txt -o output/tls.txt
    cut-cdn -l output/resolved.txt -o output/no_cdn.txt

POST-PHASE CHECK (MANDATORY):
    wc -l output/urls_katana.txt output/wayback.txt
    ls -la output/nmap_scan.gnmap 2>/dev/null || ls -la output/ports.txt 2>/dev/null
    If at least 2 distinct enumeration tool outputs are non-empty → Phase 2 COMPLETE.
    THEN run live probe: curl -sI --max-time 10 $(head -1 output/live_hosts.txt | awk '{print $1}')
    Confirm HTTP response is received (any status code) → Live probe COMPLETE.

---

## Phase 3 — Vulnerability Scanning (minimum 4 distinct tools — nuclei allowed ONLY here)

    cat output/urls_katana.txt | jsleak | tee output/js_secrets.txt
      AND  jsluice urls output/urls_katana.txt
    gitleaks detect --source . --report-path output/gitleaks.json  (if source code found)
    x8 -u <url> -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -o output/params.txt
    csprecon -d <target> | tee output/csp.txt
    wafw00f <url> | tee output/waf.txt
    nuclei -l output/live_hosts.txt -t /home/pentester/nuclei-templates -severity medium,high,critical -o output/nuclei.txt
    nikto -h <url> -o output/nikto.txt
      OR  wapiti -u <url> -o output/wapiti/ -f html
    dalfox file output/urls_katana.txt --output output/xss.txt
    sqlmap -m output/urls_katana.txt --batch --output-dir output/sqlmap/

---

## Phase 4 — Deep Analysis (MANDATORY)

    BROWSER: Visit top targets with browser_action. Check source, console, network.
    PROXY: Run caido-setup to boot headless Caido on port 48080 and retrieve your API token.
      Use it to tamper with requests (BOLA, IDOR, Logic).
    IP-to-Host pivot: hakip2host <IP> — find other sites on same IP
    OOB/SSRF testing: interactsh-client for out-of-band callback listener
    Cache probing: toxicache -u <url>
    NoSQL: nosqli -u <url>
    HTTP header injection: headi -u <url>

---

## Phase 5 — Exploitation & Validation

    NO ASSUMPTIONS: If you suspect a vuln, PROVE IT. Construct a PoC.
    If a scan says "Potential XSS", you MUST verify it specifically.
    RCE/SSRF: Use interactsh-client OOB listener to validate blind callbacks.

---

## Phase 6 — Reporting (MANDATORY)

    CRITICAL RULE: If you find a vulnerability (Medium/High/Critical),
    use create_vulnerability_report IMMEDIATELY. Do NOT just mention it in chat.
    The task is NOT complete until the report is generated.

---

## Custom Scripting Mandate

You are expected to WRITE YOUR OWN SCRIPTS for manual recon, exploitation, and analysis.
This is NON-OPTIONAL. Scripts go into tools/ within the current workspace.

Examples:
    tools/enumerate_js_endpoints.py   — crawl JS URLs, extract API endpoints and parameters
    tools/idor_bruteforce.py          — iterate user IDs in an API endpoint, compare responses
    tools/jwt_alg_confusion.py        — RS256 to HS256 confusion with a known public key
    tools/graphql_introspect.py       — full GraphQL schema dump and automated mutation fuzzing
    tools/ssrf_probe.py               — probe each URL param for SSRF with interactsh callback URLs
    tools/cache_deception.py          — append path suffixes (.css, .js, .png) to test cache poisoning
    tools/postmessage_analyze.py      — extract postMessage handlers from JS files, analyze origins

Script requirements:
    1. Use requests, aiohttp, subprocess, re, json — all available via python3
    2. Always write to output/ — save results to output/<scriptname>_results.txt
    3. Log every request + response (status, length, body snippet) for evidence
    4. Make them re-runnable: accept target URL/domain as argv[1] when possible
    5. NEVER hardcode credentials or tokens — read from environment variables

Example template:

    #!/usr/bin/env python3
    import sys, requests
    TARGET = sys.argv[1] if len(sys.argv) > 1 else "https://example.com"
    results = []
    for path in ["/api/v1/users", "/api/v2/users"]:
        r = requests.get(TARGET + path, timeout=10)
        results.append(f"{r.status_code} {len(r.text)} {TARGET+path}")
    with open("output/manual_enum.txt", "w") as f:
        f.write("\n".join(results))
    print("\n".join(results))

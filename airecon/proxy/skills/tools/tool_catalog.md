# Tool Catalog — AIRecon Kali Linux Sandbox

All tools are pre-installed in the Kali Linux Docker container.
Before first use of any CLI tool, verify it: which <tool> && <tool> --help

---

## Git-Cloned Tools Location

    /home/pentester/tools/
    Run: ls /home/pentester/tools/   to see all available tools.
    Python tools:  python3 /home/pentester/tools/<toolname>/<script.py> [args]
    Bash tools:    bash /home/pentester/tools/<toolname>/<script.sh> [args]

---

## Self-Install Capability (Full Authorization)

You run as pentester with FULL sudo access and internet access.
If a tool is NOT installed, install it immediately. Do NOT skip the task.

    sudo apt-get install -y <tool>
    pip3 install <package>
    pipx install <package>
    go install github.com/<repo>@latest
    npm install -g <package>
    git clone https://github.com/<repo>.git /home/pentester/tools/<name>
    wget <url> -O /tmp/tool && chmod +x /tmp/tool && sudo mv /tmp/tool /usr/local/bin/

---

## Subdomain Discovery

    subfinder, amass (v3.23.3), assetfinder, dnsx, shuffledns, massdns, sublist3r, hakip2host, cut-cdn

## DNS & IP Intelligence

    dnsx, tlsx, dig, nslookup, whois, dnsrecon, dnsenum, nrich, notify (Slack/Discord alerts)

## Port Scanning

    nmap (use: sudo nmap -sS for SYN scan), naabu, masscan (IP-only — resolve domain first!), netcat
    MASSCAN NOTE: Accepts IP addresses ONLY. Always resolve domains with dig or python before passing.

## Web Crawling & URL Discovery

    katana, gospider, gau, waybackurls, meg, httprobe, httpx, waymore, dirsearch, feroxbuster

## Technology Fingerprinting

    whatweb, httpx (-tech-detect flag), tlsx, wafw00f, nikto, wapiti
    wappalyzer (npm):   wappalyzer https://target.com
    retire (npm):       retire --js --jspath output/js_files/
    eslint, jshint, js-beautify (deobfuscate + lint JS)

## CMS & Platform Scanners

    wpscan:    wpscan --url https://target.com --enumerate p,u,t
    joomscan:  joomscan -u https://target.com

## JavaScript Analysis

    jsleak, jsluice, gf, trufflehog
    /home/pentester/tools/JS-Snooper/js_snooper.sh
    /home/pentester/tools/jsniper.sh/jsniper.sh
    /home/pentester/tools/LinkFinder/linkfinder.py
    /home/pentester/tools/LinksDumper/LinksDumper.py
    /home/pentester/tools/jsfinder/jsfinder.py
    /home/pentester/tools/JS-Scan/

## Parameter, Fuzzing & Directory Brute-Force

    ffuf, feroxbuster, x8, headi, arjun, dalfox (XSS), dirsearch

## Browser & Agentic Tools

    browser_action — headless Chromium (goto, click, type_text, scroll, execute_js, view_source, get_console_logs)
    web_search     — DuckDuckGo search for payloads, CVEs, techniques
    param-miner    — discover hidden HTTP parameters

## Password Attacks & Brute-Force

    hydra          — multi-protocol login brute-force (SSH, FTP, HTTP, SMB)
    medusa         — fast parallel login brute-force
    hashcat        — GPU hash cracking
    john           — John the Ripper
    Wordlists: /usr/share/seclists/Passwords/  |  /usr/share/wordlists/rockyou.txt

## CVE & Vulnerability Intelligence

    cvemap / vulnx:   cvemap -q nginx  OR  cvemap -cve CVE-2024-xxxx
    searchsploit:     searchsploit apache 2.4

## JWT & Auth Testing

    python3 /home/pentester/tools/jwt_tool/jwt_tool.py — full JWT attack suite (alg:none, weak secret, RS256->HS256)
    jwt-cracker (npm)

## GraphQL Testing

    inql (pipx)
    python3 /home/pentester/tools/GraphQLmap/graphqlmap.py

## CORS Testing

    python3 /home/pentester/tools/Corsy/corsy.py

## SSL/TLS & Crypto

    testssl.sh — comprehensive TLS audit (heartbleed, BEAST, POODLE, weak ciphers)

## Git Exposure & Secrets

    git-dumper (pipx), gitleaks, trufflehog, git-secrets
    /home/pentester/tools/GitHunter/

## PostMessage & DOM XSS

    /home/pentester/tools/postMessage-tracker/
    /home/pentester/tools/PostMessage_Fuzz_Tool/

## Cloud & S3 Recon

    s3scanner (pipx), festin (pipx — hidden S3 via DNS and SSL), shodan CLI

## SAST & Code Analysis

    semgrep, bandit, eslint, jshint, trivy

## Vulnerability Scanning

    nuclei (GATE: after Phases 1+2 only), nikto, wapiti, sqlmap, dalfox,
    csprecon, nosqli, toxicache, semgrep, trivy

## Secret & Leak Detection

    gitleaks, trufflehog, bandit, semgrep, git-secrets
    gf with patterns from /home/pentester/.gf/
      (secrets, sqli, xss, ssrf, redirect, rce, lfi, idor, debug-pages, cors, upload-fields, interestingparams)

## Exploitation & Payloads

    sqlmap, ghauri, dalfox, nosqli, headi, interactsh-client (OOB/blind callback listener), caido-cli

## Proxy & Traffic Interception

    caido-setup (auto-boot Caido on port 48080), zaproxy

## Wordlists & Payloads

    /usr/share/seclists/           — full SecLists (Discovery, Fuzzing, Payloads, Passwords, Usernames)
    /home/pentester/wordlists/fuzzdb/  — FuzzDB structured attack payloads
    /usr/share/wordlists/          — rockyou and others
    /usr/share/nmap/scripts/       — NSE scripts

## Scripting (Always Available — Use Aggressively)

    python3, bash, curl, wget, jq, ripgrep, parallel, tmux

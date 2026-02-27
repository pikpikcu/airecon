---
name: js_recon
description: Methodologies for static analysis of client-side JavaScript.
---

# JavaScript Reconnaissance

Client-side JavaScript libraries are often one of the most overlooked areas of a security assessment. They can contain hidden API endpoints, hardcoded credentials, and logic flaws.

## 1. Endpoint Extraction

Modern Single Page Applications (SPAs) often bundle all their routes into large JS files. Extracting these can reveal administrative panels or unlinked API endpoints.

### Tools & Commands
*   **katana**: A next-generation crawling and spidering framework.
    ```bash
    katana -u target.com -d 5 -jc -kf -aff -c 10 -o endpoints.txt
    ```
*   **xnLinkFinder**: Python tool to discover endpoints in JS files.
    ```bash
    python3 xnLinkFinder.py -i target.com -sp target_js.txt -sf target_domains.txt -o cli
    ```

### Workflow
1.  Crawl the target to collect all `.js` usage.
2.  Pass the JS types to an extractor like `xnLinkFinder` or `GAP`.
3.  Filter for interesting paths (e.g., `/api/v1`, `/admin`, `/graphql`).

## 2. Secret Hunting

Developers often accidentally commit keys, tokens, or passwords to client-side code.

### Tools & Commands
*   **SecretFinder**: Python script to find sensitive data (apikeys, accesstokens, etc) in JS files.
    ```bash
    python3 SecretFinder.py -i https://target.com/main.js -o cli
    ```
*   **Mantra**: A tool to find secrets in JS files with custom regex.
    ```bash
    cat js_urls.txt | mantra
    ```

### Key Secrets to Look For
*   **AWS Access Keys**: `AKIA...`
*   **Google API Keys**: `AIza...`
*   **Stripe Tokens**: `sk_live_...`
*   **Slack Webhooks**: `https://hooks.slack.com/...`
*   **JWT Tokens**: `ey...`

## 3. DOM Analysis

Identifying DOM-based vulnerabilities (XSS, Open Redirect) requires analyzing how data flows from sources to sinks.

### Sinks & Sources
*   **Sources**: `location.search`, `location.hash`, `document.cookie`, `window.name`.
*   **Sinks**: `innerHTML`, `document.write`, `eval`, `setTimeout`, `location.href`.

### Tools
*   **DOMInvader**: A browser extension (built into Burp Suite) that tracks sources and sinks.
*   **Mantra**: Can also be used to grep for specific dangerous functions.
    ```bash
    grep -E "innerHTML|document.write" app.js
    ```

## 4. Source Map Reconstruction

If source maps (`.map` files) are present, you can reconstruct the original source code (e.g., TypeScript, unminified JS).

### Tool
*   **sourcemapper**:
    ```bash
    sourcemapper -url https://target.com/assets/index.js.map -output ./source_code
## 5. Advanced JS Recon Pipeline

Leverage these one-liners for rapid, deep analysis of JavaScript files.

### Complete JS Pipeline
Resolve subdomains, crawl for JS files, and save them.
```bash
subfinder -d target.com -silent | httpx -silent | katana -d 5 -jc -silent | grep -iE '\.js$' | anew js.txt
```

### Extract Secrets from JS
Scan JS files for exposures using nuclei.
```bash
cat js.txt | httpx -silent -sr -srd js_files/ && nuclei -t exposures/ -target js.txt
```

### LinkFinder on JS Files
Find endpoints using LinkFinder.
```bash
cat js.txt | xargs -I@ -P10 bash -c 'python3 linkfinder.py -i @ -o cli 2>/dev/null' | anew endpoints.txt
```

### SecretFinder Mass Scan
Mass scan for secrets using SecretFinder.
```bash
cat js.txt | xargs -I@ -P5 python3 SecretFinder.py -i @ -o cli | anew secrets.txt
```

### JS Variables Extraction
Extract variable assignments.
```bash
cat file.js | grep -oE "var\s+\w+\s*=\s*['\"][^'\"]+['\"]" | sort -u
```

### API Keys from JS
Find API keys using nuclei templates.
```bash
cat js.txt | nuclei -t http/exposures/tokens/ -silent | anew api_keys.txt
```

### Extract All URLs from JS
Extract http/https URLs.
```bash
cat js.txt | xargs -I@ curl -s @ | grep -oE "(https?://[^\"\'\`\s\<\>]+)" | sort -u | anew js_urls.txt
```

### Find API Endpoints in JS
Extract potential API routes.
```bash
cat js.txt | xargs -I@ curl -s @ | grep -oE "(/api/[^\"\'\`\s\<\>]+|/v[0-9]+/[^\"\'\`\s\<\>]+)" | sort -u
```

### Extract Hardcoded Credentials
Search for common credential keywords.
```bash
cat js.txt | xargs -I@ curl -s @ | grep -iE "(password|passwd|pwd|secret|api_key|apikey|token|auth)" | sort -u
```

### Extract AWS Keys from JS
Find AWS keys.
```bash
cat js.txt | xargs -I@ curl -s @ | grep -oE "(AKIA[0-9A-Z]{16}|ABIA[0-9A-Z]{16}|ACCA[0-9A-Z]{16}|ASIA[0-9A-Z]{16})" | sort -u | anew aws_keys.txt
```

### Extract Google API Keys from JS
Find Google API keys.
```bash
cat js.txt | xargs -I@ curl -s @ | grep -oE "AIza[0-9A-Za-z\-_]{35}" | sort -u | anew google_api_keys.txt
```

### Extract Firebase URLs from JS
Find Firebase instances.
```bash
cat js.txt | xargs -I@ curl -s @ | grep -oE "https://[a-zA-Z0-9-]+\.firebaseio\.com|https://[a-zA-Z0-9-]+\.firebase\.com" | sort -u | anew firebase_urls.txt
```

### Extract S3 Buckets from JS
Find S3 buckets.
```bash
cat js.txt | xargs -I@ curl -s @ | grep -oE "[a-zA-Z0-9.-]+\.s3\.amazonaws\.com|s3://[a-zA-Z0-9.-]+|s3-[a-zA-Z0-9-]+\.amazonaws\.com/[a-zA-Z0-9.-]+" | sort -u | anew s3_from_js.txt
```

### Extract Internal IPs from JS
Find internal IP addresses.
```bash
cat js.txt | xargs -I@ curl -s @ | grep -oE "(10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|172\.(1[6-9]|2[0-9]|3[0-1])\.[0-9]{1,3}\.[0-9]{1,3}|192\.168\.[0-9]{1,3}\.[0-9]{1,3})" | sort -u | anew internal_ips.txt
```

### Extract Slack Webhooks from JS
Find Slack webhooks.
```bash
cat js.txt | xargs -I@ curl -s @ | grep -oE "https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+" | sort -u | anew slack_webhooks.txt
```

### Extract GitHub Tokens from JS
Find GitHub tokens.
```bash
cat js.txt | xargs -I@ curl -s @ | grep -oE "(ghp_[a-zA-Z0-9]{36}|gho_[a-zA-Z0-9]{36}|ghu_[a-zA-Z0-9]{36}|ghs_[a-zA-Z0-9]{36}|ghr_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59})" | sort -u | anew github_tokens.txt
```

### Extract Private Keys from JS
Find private keys.
```bash
cat js.txt | xargs -I@ curl -s @ | grep -oE "-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY( BLOCK)?-----" | sort -u | anew private_keys_found.txt
```

### Extract Email Addresses from JS
Find email addresses.
```bash
cat js.txt | xargs -I@ curl -s @ | grep -oE "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}" | sort -u | anew emails_from_js.txt
```

### Extract Hidden Subdomains from JS
Find subdomains mentioned in JS.
```bash
cat js.txt | xargs -I@ curl -s @ | grep -oE "https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}" | sed 's|https\?://||' | cut -d'/' -f1 | sort -u | anew subdomains_from_js.txt
```

### Extract GraphQL Endpoints from JS
Find GraphQL endpoints.
```bash
cat js.txt | xargs -I@ curl -s @ | grep -oE "(graphql|gql|query|mutation)[^\"']*" | grep -oE "/[a-zA-Z0-9/_-]*graphql[a-zA-Z0-9/_-]*" | sort -u | anew graphql_endpoints.txt
```

### Extract JWT Tokens from JS Files
Find JWT tokens.
```bash
cat js.txt | xargs -I@ curl -s @ | grep -oE "eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*" | sort -u | anew jwt_tokens.txt
```

### Find Webpack Source Maps
Check for source maps.
```bash
cat js.txt | sed 's/\.js$/.js.map/' | httpx -silent -mc 200 -ct -match-string "sourcesContent" | anew sourcemaps.txt
```

### Extract Discord Webhooks from JS
Find Discord webhooks.
```bash
cat js.txt | xargs -I@ curl -s @ | grep -oE "https://discord\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+" | sort -u | anew discord_webhooks.txt
```

### Find Hidden Admin Routes in JS
Find potential admin routes.
```bash
cat js.txt | xargs -I@ curl -s @ | grep -oE "[\"\'][/][a-zA-Z0-9_/-]*(admin|dashboard|manage|config|settings|internal|private|debug|api/v[0-9])[a-zA-Z0-9_/-]*[\"\']" | tr -d "\"'" | sort -u | anew hidden_routes.txt
```

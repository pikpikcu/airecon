---
name: js-recon
description: Advanced JavaScript reconnaissance covering endpoint extraction, secret hunting, webpack analysis, source maps, prototype pollution vectors, and DOM security review
---

# JavaScript Reconnaissance

JavaScript is the most underanalyzed part of web assessments. JS files reveal API endpoints, authentication logic, hardcoded secrets, internal tool names, and vulnerability sinks. Treat every JS file as a potential attack surface.

---

## Endpoint & URL Extraction

### Crawl and Collect JS Files

    # katana — JS-aware spider with headless rendering
    katana -u https://target.com -d 5 -jc -aff -kf -c 10 -o output/urls_katana.txt
    grep "\.js" output/urls_katana.txt | sort -u > output/js_files.txt

    # gospider with JS parsing
    gospider -s https://target.com -d 5 --js -o output/gospider/

    # gau for historical JS
    gau target.com | grep "\.js$" | sort -u | tee output/js_historical.txt

### Extract Endpoints from JS

    # jsleak — fast endpoint and secret extraction
    cat output/js_files.txt | jsleak | tee output/jsleak_results.txt

    # jsluice — structured JS analysis
    jsluice urls output/urls_katana.txt
    jsluice secrets output/urls_katana.txt

    # LinkFinder — classic endpoint extractor
    python3 /home/pentester/tools/LinkFinder/linkfinder.py \
      -i https://target.com -d -o output/linkfinder.html

    # Custom regex from downloaded JS
    find output/ -name "*.js" -exec grep -hoE \
      "(\"|\')(/api/[^\"\']+|/v[0-9]+/[^\"\']+|/graphql[^\"\']*)(\"|\')"\
      {} \; | sort -u > output/api_endpoints.txt

    # Batch extract from all JS URLs
    cat output/js_files.txt | \
      xargs -P 10 -I{} sh -c 'curl -sk {} | jsluice urls' 2>/dev/null | \
      jq -r '.url' | sort -u > output/js_endpoints.txt

---

## Secret Hunting

### Automated Tools

    # trufflehog — entropy + regex, best coverage
    trufflehog filesystem output/ --json | tee output/trufflehog.json
    cat output/trufflehog.json | jq -r '.SourceMetadata.Data.Filesystem.file + ": " + .Raw'

    # gitleaks — scan downloaded JS for secrets
    gitleaks detect --source output/ --report-path output/gitleaks.json

    # gf patterns — targeted grep across collected URLs
    cat output/urls_katana.txt | gf secrets
    cat output/js_endpoints.txt | gf aws-keys
    cat output/js_endpoints.txt | gf api-keys

### Manual Pattern Search

    # Download all JS files first
    mkdir -p output/js_raw
    cat output/js_files.txt | xargs -P 5 -I{} sh -c \
      'name=$(echo {} | md5sum | cut -c1-8); curl -sk {} > output/js_raw/$name.js'

    # Key patterns
    rg -i "api[_-]?key"                                    output/js_raw/
    rg -i "secret|password|token|credential|auth"          output/js_raw/ | grep -v "//.*secret"
    rg "AKIA[A-Z0-9]{16}"                                  output/js_raw/  # AWS key
    rg "sk_live_[0-9a-zA-Z]{24}"                           output/js_raw/  # Stripe secret
    rg "ghp_[a-zA-Z0-9]{36}"                               output/js_raw/  # GitHub PAT
    rg "ey[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+" output/js_raw/ # JWT
    rg "AIza[0-9A-Za-z_-]{35}"                             output/js_raw/  # Google API key
    rg "[0-9a-f]{32}"                                      output/js_raw/ | head -20

---

## Webpack / Bundle Analysis

Modern SPAs bundle all code into a few large JS files. Source maps expose original source.

### Source Map Recovery

    # Check for source map reference at end of JS file
    curl -s https://target.com/static/main.js | tail -5 | grep sourceMappingURL

    # Download and extract
    curl -s https://target.com/static/main.js.map -o output/main.js.map

    # Reconstruct source tree (sourcemapper)
    sourcemapper -output output/src_reconstructed/ -url https://target.com/static/main.js.map

    # Manual extraction via Python
    python3 -c "
    import json,sys,os
    m=json.load(open('output/main.js.map'))
    for src,content in zip(m.get('sources',[]),m.get('sourcesContent') or []):
        if content:
            path='output/src/'+src
            os.makedirs(os.path.dirname(path),exist_ok=True)
            open(path,'w').write(content)
    "

### Webpack Chunk Enumeration

    # Enumerate sequential chunks
    for i in $(seq 0 100); do
        code=$(curl -sk -o /dev/null -w "%{http_code}" https://target.com/static/js/$i.chunk.js)
        [ "$code" = "200" ] && echo "Chunk found: $i.chunk.js"
    done

    # Beautify before analysis
    cat output/js_raw/main.js | js-beautify -j - > output/main_pretty.js

---

## DOM Security Review

### XSS Sinks

    # Dangerous sinks in beautified JS
    grep -n "innerHTML\|outerHTML\|document\.write\|eval(\|setTimeout(\|setInterval(" output/main_pretty.js

    # Source patterns
    grep -n "location\.hash\|location\.search\|document\.referrer\|URLSearchParams" output/main_pretty.js

### PostMessage Handlers (CSRF / XSS)

    # Find handlers — check if origin is validated
    grep -n "addEventListener.*message\|postMessage" output/main_pretty.js

    # If no origin check: any origin can send arbitrary messages → XSS/CSRF
    # /home/pentester/tools/postMessage-tracker/
    # /home/pentester/tools/PostMessage_Fuzz_Tool/

### Prototype Pollution Gadgets

    # Find merge/extend patterns that may be pollutable
    grep -nE "\.merge\(|\.extend\(|deepMerge|defaultsDeep|Object\.assign" output/main_pretty.js

    # Find proto filtering (or absence of it)
    grep -n "__proto__\|constructor.*prototype\|hasOwnProperty" output/main_pretty.js

### Internal URLs and Config

    # Hardcoded internal/dev hostnames
    grep -nE "https?://[a-z0-9.-]+(:[0-9]+)?(/[a-zA-Z0-9._/-]*)?" output/main_pretty.js | \
      grep -v "cdn\|google\|facebook\|analytics\|example" | head -50

    grep -nE '"(dev|staging|internal|admin|test)\.' output/main_pretty.js

---

## GraphQL Discovery from JS

    # Apps embed query strings directly in JS
    grep -n "gql\`\|GraphQL\|query.*mutation" output/main_pretty.js

    # Extract operation names
    grep -oE "(query|mutation|subscription)\s+[A-Za-z_][A-Za-z0-9_]*" \
      output/main_pretty.js | sort -u

---

## Supply Chain Checks

    # Check for outdated libraries with known vulns
    retire --js --jspath output/js_raw/

    # Check scripts loaded without Subresource Integrity (SRI)
    curl -s https://target.com | grep -E "script.*src=" | grep -v "integrity="

---

## Automated Pipeline

    echo "=== JS Recon Pipeline ===" && \
    katana -u https://target.com -d 5 -jc -aff -o output/katana.txt 2>/dev/null && \
    grep "\.js" output/katana.txt | sort -u > output/js_list.txt && \
    echo "[*] $(wc -l < output/js_list.txt) JS files found" && \
    cat output/js_list.txt | jsleak | tee output/jsleak.txt && \
    gitleaks detect --source output/ --report-path output/gitleaks.json 2>/dev/null && \
    echo "[*] Done — check output/jsleak.txt and output/gitleaks.json"

---

## Pro Tips

1. Source maps (main.js.map) are the holy grail — expose full unminified source tree with comments
2. Webpack chunks (0.chunk.js ... 100.chunk.js) contain different app modules — enumerate them
3. Admin routes hardcoded in JS bundles are often unlinked but fully functional endpoints
4. postMessage handlers without origin validation = XSS/CSRF from any attacker-controlled domain
5. Check JS loaded by error pages / 404s — they often include different config or debug values
6. Beautify before grepping — jsleak and jsluice miss things that grep finds in readable code
7. trufflehog + gf covers ~90% of secret patterns; manual regex catches the remaining edge cases

## Summary

JS recon: crawl → collect all JS → source map recovery → endpoint extraction → secret hunt → DOM sink analysis. Source maps and webpack chunks are the highest-value targets most tools skip. Every hardcoded URL, config object, or API key in JS is a direct finding.

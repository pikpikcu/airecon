---
name: deep
description: Exhaustive security assessment with maximum coverage, depth, and vulnerability chaining
---

# Deep Testing Mode

Exhaustive security assessment. Maximum coverage, maximum depth. Finding what others miss is the goal.

## Approach

Thorough understanding before exploitation. Test every parameter, every endpoint, every edge case. Chain findings for maximum impact.

## Phase 1: Exhaustive Reconnaissance

**Whitebox (source available)**
- Map every file, module, and code path in the repository
- Trace all entry points from HTTP handlers to database queries
- Document all authentication mechanisms and implementations
- Map authorization checks and access control model
- Identify all external service integrations and API calls
- Analyze configuration for secrets and misconfigurations
- Review database schemas and data relationships
- Map background jobs, cron tasks, async processing
- Identify all serialization/deserialization points
- Review file handling: upload, download, processing
- Understand the deployment model and infrastructure assumptions
- Check all dependency versions against CVE databases

**Blackbox (no source)**
- Exhaustive subdomain enumeration with multiple sources and tools and techniques (recursive, permutation)
- Full port scanning across all services and infrastructure (all 65535 ports)
- Complete content discovery with multiple wordlists (raft, seclists, custom per-target)
- Technology fingerprinting on all assets (Wappalyzer, nucleo-templates)
- API discovery via docs, JavaScript analysis, fuzzing
- Identify all parameters including hidden and rarely-used ones
- Map all user roles with different account types
- Document rate limiting, WAF rules, security controls - and their bypasses
- Document complete application architecture as understood from outside
- **Cloud Asset Discovery** - Enumerate S3 buckets, Azure blobs, GCP functions
- **Archive Mining** - Dig through Wayback Machine, Google Cache, and GitHub for leaks
- **Blind Interaction** - Test for Out-of-Band (OOB) interactions (DNS/HTTP via Collaborator)
- **Visual Recon** - Automated screenshotting and visual diffing of all assets
- **Behavioral Analysis** - Analyze response times and error messages for side-channel leaks
- **JavaScript Static Analysis** - Extract secrets, endpoints, and logic from client-side code

## Phase 2: Business Logic Deep Dive

Create a complete storyboard of the application:

- **User flows** - document every step of every workflow
- **State machines** - map all transitions (Created → Paid → Shipped → Delivered)
- **Trust boundaries** - identify where privilege changes hands
- **Invariants** - what rules should the application always enforce
- **Implicit assumptions** - what does the code assume that might be violated
- **Multi-step attack surfaces** - where can normal functionality be abused
- **Third-party integrations** - map all external service dependencies

Use the application extensively as every user type to understand the full data lifecycle.

## Phase 3: Comprehensive Attack Surface Testing

Test every input vector with every applicable technique.

**Input Handling (Aggressive)**
- Multiple injection types: SQL, NoSQL, LDAP, XPath, command, template
- **Polyglot Payloads**: Use payloads that trigger XSS, SQLi, and SSI simultaneously
- **Mutation Fuzzing**: Bit-flipping and protocol mutation on binary inputs
- **SSTI Deep Dive**: Test all template engines (Jinja2, Freemarker, Velocity, Mako)
- Encoding bypasses: double encoding, unicode, null bytes, HTTP parameter pollution
- Boundary conditions and type confusion (e.g., array vs string vs int)
- Large payloads and buffer-related issues (DoS via ReDoS or allocation)

**Authentication & Session (Advanced)**
- Exhaustive brute force protection testing (IP rotation, header evasion)
- Session fixation, hijacking, prediction (entropy analysis)
- **JWT/Token Attacks**: Algorithm confusion (HS256 vs RS256), `None` algo, interfering with signature
- **SSO/SAML/OIDC Abuse**: Golden SAML, XML Signature Wrapping, Replay attacks, race conditions in callback
- OAuth flow abuse scenarios (Open Redirect in `redirect_uri`, Code leakage)
- Password reset vulnerabilities: Host header poisoning, token leakage, timing attacks
- **MFA Fatigue**: Flooding MFA requests to force user acceptance
- Account enumeration through all channels (Login, Forgot Password, Registration, API)

**Access Control (Deep)**
- Test every endpoint for horizontal (same role) and vertical (higher role) access control
- **Complex Object IDOR**: Nested JSON objects, non-numeric IDs (GUIDs), mass assignment
- Parameter tampering on all object references
- Forced browsing to all discovered resources (admin panels, backup files)
- HTTP method tampering (GET vs POST vs PUT vs DELETE vs HEAD vs PATCH)
- Access control after session state changes (logout, role change)

**File Operations & XXE**
- Exhaustive file upload bypass: extension, content-type, magic bytes, race conditions
- **Polyglot Files**: GIF/JAR/PHP combinations
- Path traversal on all file parameters (deep nested `../../../../`)
- SSRF through file inclusion (and via PDF/Image generators)
- **Blind XXE**: Out-of-band data exfiltration via DTD injection

**Business Logic & Financial (High Risk)**
- **Race Conditions**: Parallel requests on limit-checks (coupons, transfers, withdrawals)
- Workflow bypass on every multi-step process (skip step 2 in a 3-step checkout)
- **Mathematical Logic**: Negative amounts, decimal rounding errors, currency conversion flaws
- Parallel execution attacks (exploiting non-atomic database transactions)
- TOCTOU (time-of-check to time-of-use) vulnerabilities

**Infrastructure & Cloud Exploitation**
- **Cloud Metadata Abuse**: Try to bypass IMDSv2 (AWS), access Metadata Service (GCP/Azure)
- **Container Breakout**: Check for exposed Docker sockets, capabilities, mounts
- **Subdomain Takeover**: Verify dangling CNAMEs for all cloud services
- **Cache Poisoning**: Target CDN/Varnish layers with header manipulation
- **Web Cache Deception**: Force caching of sensitive user data
 
**Advanced Protocols**
- **HTTP Request Smuggling**: CL.TE, TE.CL, TE.TE attacks on proxy chains
- **HTTP/2 Attacks**: Request Smuggling (H2.CL, H2.TE), Header compression attacks
- **WebSocket**: CSWSH (Cross-Site WebSocket Hijacking), Input validation
- **GraphQL**: Introspection abuse, Batching attacks (DoS/Brute-force), Deep nested queries

## Phase 4: Vulnerability Chaining

Individual bugs are starting points. Chain them for maximum impact:

- Combine information disclosure with access control bypass
- Chain SSRF to reach internal services
- Use low-severity findings to enable high-impact attacks
- Build multi-step attack paths that automated tools miss
- Cross component boundaries: user → admin, external → internal, read → write, single-tenant → cross-tenant

### Killer Chains (Recipes)
 
**1. The "Shell" Chain (LFI -> RCE)**
-   **Finding**: Local File Inclusion (LFI).
-   **Pivot**: Docker /proc/self/environ, Apache access.log, PHP session upload.
-   **Execution**: Inject PHP logic into the log/env, encompass with LFI.
-   **Result**: Remote Code Execution (RCE).
 
**2. The "Cloud" Chain (SSRF -> Cloud Compromise)**
-   **Finding**: SSRF (Server-Side Request Forgery).
-   **Pivot**: Hit Cloud Metadata (AWS `169.254.169.254`, GCP `metadata.google.internal`).
-   **Execution**: Extract IAM role credentials.
-   **Result**: Access S3 buckets, EC2 instances, or Kubernetes clusters.
 
**3. The "Identity" Chain (Open Redirect -> Account Takeover)**
-   **Finding**: Open Redirect on a trusted domain.
-   **Pivot**: OAuth authorization flow (`redirect_uri`).
-   **Execution**: Redirect the OAuth Code/Token to attacker domain.
-   **Result**: Full Account Takeover without credentials.
 
**4. The "Frontend" Chain (Prototype Pollution -> RCE)**
-   **Finding**: Client-side Prototype Pollution.
-   **Pivot**: Identify gadgets in used libraries (e.g., Lodash, jQuery).
-   **Execution**: Pollute Object prototype to spawn processes or bypass auth.
-   **Result**: RCE or Admin Access.
 
### Logical Pivoting
-   **Low-Priv ID Leak -> Admin IDOR**: Use leaked GUIDs from low-priv API to fuzz Admin endpoints.
-   **CORS Misconfig -> Intranet Access**: Use a null-origin CORS to force the victim browser to scan internal networks (192.168.x.x).
-   **XSS -> CSRF**: Use XSS to read Anti-CSRF tokens, then forge state-changing requests (change password/email).

**Chaining Principles**
- Treat every finding as a pivot point: ask "what does this unlock next?"
- Continue until reaching maximum privilege / maximum data exposure / maximum control
- Prefer end-to-end exploit paths over isolated bugs: initial foothold → pivot → privilege gain → sensitive action/data
- Validate chains by executing the full sequence (proxy + browser for workflows, python for automation)
- When a pivot is found, spawn focused agents to continue the chain in the next component
-   **Always Ask**: "What does this specific primitive allow me to touch next?"
-   **Combine Contexts**: Mix Client-side (XSS) with Server-side (IDOR) for maximum damage.
-   **Escalate**: Never stop at "Alert(1)". Stop at "Admin Panel Accessed".

## Phase 5: Persistent Testing

When initial attempts fail:

- Research technology-specific bypasses
- Try alternative exploitation techniques
- Test edge cases and unusual functionality
- Test with different client contexts
- Revisit areas with new information from other findings
- Consider timing-based and blind exploitation
- Look for logic flaws that require deep application understanding

## Phase 6: Comprehensive Reporting

- Document every confirmed vulnerability with full details
- Include all severity levels—low findings may enable chains
- Complete reproduction steps and working PoC
- Remediation recommendations with specific guidance
- Note areas requiring additional review beyond current scope

## Agent Strategy

After reconnaissance, decompose the application hierarchically:

1. **Component level** - Auth System, Payment Gateway, User Profile, Admin Panel
2. **Feature level** - Login Form, Registration API, Password Reset
3. **Vulnerability level** - SQLi Agent, XSS Agent, Auth Bypass Agent

Spawn specialized agents at each level. Scale horizontally to maximum parallelization:
- Do NOT overload a single agent with multiple vulnerability types
- Each agent focuses on one specific area or vulnerability type
- Creates a massive parallel swarm covering every angle

## Mindset

Relentless. Creative. Patient. Thorough. Persistent.

This is about finding what others miss. Test every parameter, every endpoint, every edge case. If one approach fails, try ten more. Understand how components interact to find systemic issues.

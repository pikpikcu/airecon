# nmap & naabu — Usage Guide for AIRecon

nmap and naabu are port scanners and service fingerprinters. They are infrastructure-level tools
that answer "what is listening on this host?" — not "what vulnerability exists here?" Understanding
the distinction is critical. Port scan results are raw data that require manual interpretation and
correlation before any further action is taken.

---

## MANDATORY PRE-CONDITIONS (All must be true before using nmap or naabu)

  [ ] You have confirmed the target is within scope — IP, hostname, or CIDR explicitly authorized.
  [ ] For domain-based targets: DNS resolution has been performed and you are scanning the IP,
      not passing a domain name to masscan (masscan requires IP addresses only).
  [ ] You have a specific reason to port scan this host — what are you trying to learn?
      State it: "I am scanning to determine if port 8080 is open because the JS referenced
      an internal API on that port" — NOT "I am scanning because it is the next step."
  [ ] output/host_profiles.json either has an entry for this host already, or you are creating
      the entry — port scan results must be written into the host profile immediately after.

Port scanning without a stated purpose is reconnaissance noise, not intelligence.

---

## What Port Scanning Tells You (and What It Does Not)

  WHAT IT TELLS YOU:
    - Which TCP/UDP ports are open (accepting connections)
    - Service banners and version strings (with -sV)
    - Operating system fingerprint (with -O, requires root)
    - Response behavior under different probe types

  WHAT IT DOES NOT TELL YOU:
    - Whether a web application on port 8080 is vulnerable
    - Whether a service is exploitable
    - What the business logic of an application is
    - Anything about authentication, authorization, or input handling

  A port scan result is the BEGINNING of investigation for each discovered service.
  It is not a vulnerability finding. It is not a reason to run an exploit scanner.
  Every open port requires manual investigation: what is running? what version? what does it do?

---

## Scan Types and When to Use Each

  REACHABILITY CHECK (before host profile — lightweight):
    Purpose: Quickly confirm which hosts are alive before heavier enumeration.
    Use: At the start, before manual profiling, to prioritize which hosts to investigate.
    Command pattern: ping sweep or fast TCP check on common ports only.
    Output: Feed into host prioritization — NOT into automated scanners.

  TOP PORTS SCAN (during host profiling):
    Purpose: Understand the service landscape of a specific host you are manually profiling.
    Use: As part of STEP 3 manual profiling — one scan per host, recorded in host_profiles.json.
    Prerequisite: You are actively profiling this host, not bulk-scanning a list.
    Command pattern: top 1000 ports, version detection, default scripts on confirmed live host.

  TARGETED SERVICE SCAN (after finding a specific open port):
    Purpose: Deep fingerprint a specific service already discovered on a specific port.
    Use: When a port is open and you want version, OS, and NSE script output for that service.
    Prerequisite: The port was already found in a previous scan. You are now going deeper.
    Command pattern: single port, full version detection, relevant NSE scripts only.

  FULL PORT SCAN (when top ports reveal nothing interesting):
    Purpose: Check all 65535 ports for unusual services on non-standard ports.
    Use: Only after top port scan finds nothing interesting and you have a specific reason to
    believe non-standard ports are in use (e.g., JS references to :4000, :9000, :15000).
    Command pattern: full range, SYN scan, lower speed to avoid detection.

  UDP SCAN (specific service investigation only):
    Purpose: Detect UDP services like DNS, SNMP, NTP, TFTP.
    Use: Only when you have a specific hypothesis about a UDP service.
    Prerequisite: Root privileges required. Slow — do not run against all hosts.

---

## TWO-PASS SCANNING WORKFLOW (preferred — do not skip pass 1)

  The two-pass approach avoids running -sV on all ports (slow + noisy) by first finding open ports,
  then running service detection ONLY on those ports. Always prefer this over a single full scan.

  PASS 1 — Discovery (fast, finds open ports):
    nmap -n -Pn --top-ports 100 --open -T4 --max-retries 1 --host-timeout 90s -oN output/nmap_quick.txt <host>
    Extract open ports: grep "^[0-9]" output/nmap_quick.txt | cut -d/ -f1 | paste -sd,

  PASS 2 — Enrichment (service detection on discovered ports only):
    nmap -n -Pn -sV -sC -p <comma_ports_from_pass1> --script-timeout 30s --host-timeout 3m -oN output/nmap_services.txt <host>

  No-root fallback (when SYN scan not available):
    nmap -n -Pn -sT --top-ports 100 --open --host-timeout 90s <host>

  Prefer naabu for broad initial port discovery (faster):
    naabu -host <host> -top-ports 1000 -silent -o output/ports.txt
    Then feed to nmap enrichment: nmap -n -Pn -sV -sC -p $(cat output/ports.txt | grep -oP ':\K\d+' | paste -sd,) <host>

---

## Usage Patterns

  Standard host profile scan (top ports, version detection):
    sudo nmap -sS -sV -sC --open -p- --min-rate 1000 <host> -oA output/nmap_<host>

  Fast top-1000 ports (for initial host profiling):
    sudo nmap -sS --open --top-ports 1000 <host> -oN output/nmap_quick_<host>.txt

  Targeted single-port deep scan (after discovering an interesting port):
    sudo nmap -sV -sC -p <port> <host> --script=<relevant_script> -oN output/nmap_port<port>_<host>.txt

  Full port range (only when specifically justified):
    sudo nmap -sS -p- --min-rate 5000 <host> -oN output/nmap_fullports_<host>.txt

  Light reachability check across resolved hosts (before profiling):
    naabu -l output/resolved.txt -top-ports 1000 -o output/ports_naabu.txt

  UDP scan for specific services (requires strong justification):
    sudo nmap -sU -p 53,161,123,69 <host> -oN output/nmap_udp_<host>.txt

  nrich — passive IP enrichment (no API key, uses Shodan InternetDB):
    # After collecting IPs, enrich with known ports/CVEs/tags from Shodan InternetDB:
    cat output/live_ips.txt | nrich -           # Enrich all IPs
    echo "1.2.3.4" | nrich -                    # Single IP
    cat output/live_ips.txt | nrich - -json > output/nrich_results.json

    # nrich returns per-IP: open_ports, cves, cpes, tags (no active scan — purely passive lookup)
    # Perfect complement to nmap: use nrich BEFORE active scan to pre-check known exposure
    # Install: go install github.com/projectdiscovery/nrich/cmd/nrich@latest

  NEVER use these patterns:
    nmap -iL output/live_hosts.txt -A           (aggressive scan on unknown list, no purpose stated)
    nmap <IP> -sV --script=vuln                 (vuln script category = automated spray, banned)
    masscan output/live_hosts.txt               (masscan requires IPs, not hostnames)

  NSE SCRIPTS — USE SELECTIVELY:
    Default scripts (-sC) are acceptable during host profiling.
    The "vuln" script category is FORBIDDEN — it is equivalent to running an automated vuln scanner.
    Select specific NSE scripts only when you have a hypothesis about a specific service.
    Example: if you found Apache Struts, use --script=http-struts2-* NOT --script=vuln.

---

## Interpreting Results — Mandatory Steps After Every Scan

After nmap or naabu completes, for EVERY open port found:

  STEP 1: Identify the service running on that port.
    Do NOT trust the service label alone. Banner says "Apache httpd" — visit it in the browser.
    Banner says "OpenSSH 7.4" — note the version, look up its CVE history, but do NOT auto-exploit.

  STEP 2: Manually investigate the service.
    For web ports (80, 443, 8080, 8443, 3000, 4000, 5000, etc.):
      → browser_action: visit the port, view source, observe the application.
    For non-web ports (SSH, FTP, SMTP, Redis, MongoDB, etc.):
      → Manual banner grab: nc -v <host> <port> or curl telnet://<host>:<port>
      → Identify: is this expected? is it exposed unintentionally? is it authenticated?

  STEP 3: Record in host_profiles.json.
    For each open port: { "port": N, "service": "...", "version": "...", "notes": "..." }
    Document what you manually observed, not just what nmap guessed.

  STEP 4: Form a hypothesis before taking further action.
    "Port 6379 is open and appears to be Redis — is it authenticated? I will test with redis-cli."
    "Port 9200 is open and appears to be Elasticsearch — is the API exposed without auth?"
    DO NOT: "Port 9200 is open, run nuclei against it." — this is the forbidden pattern.

  STEP 5: Manually verify the hypothesis.
    Before using any automated scanner against a discovered service, manually confirm:
    - Is it actually that service? (version banner, behavior)
    - Is it the expected configuration or an anomaly?
    - Is there a specific, plausible vulnerability for this version that warrants testing?

---

## Version Information — The Correct Follow-Up Workflow

When nmap returns a specific version (e.g., "Apache Tomcat 9.0.35"):

  DO:
    1. Note the exact version string.
    2. Manually search for known CVEs: web_search "Apache Tomcat 9.0.35 CVE"
    3. Read the CVE description — understand what the vulnerability actually is.
    4. Determine: is this application's usage pattern consistent with the vulnerable code path?
    5. If yes: manually craft a targeted test or use a specific CVE template (not a generic scan).

  DO NOT:
    → Run a generic "vuln" NSE script category against it.
    → Load the host into a vulnerability scanner "to check for CVEs."
    → Assume the version is vulnerable without reading the CVE conditions.

---

## Workflow Integration (Where nmap/naabu Fit)

  Phase 1 STEP 2 (Live Host Detection):
    naabu or light nmap for reachability and common port check across resolved hosts.
    Output: feeds into host prioritization — NOT into scanners.

  Phase 1 STEP 3 (Manual Profiling):
    Full port scan of each specific host being profiled (one at a time).
    Output: recorded directly into output/host_profiles.json for that host.

  Phase 2+ (Targeted Service Investigation):
    Single-port deep scans on specific interesting services discovered during profiling.
    Always followed by manual investigation of the discovered service.

  NEVER:
    Scan a list of hosts in bulk and immediately pipe results into a vulnerability scanner.
    Use the "vuln" NSE script category at any phase.
    Treat scan results as findings — they are starting points for manual investigation.

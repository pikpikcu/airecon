---
name: tls_ssl_recon
description: Intelligence gathering through SSL/TLS certificate analysis.
---

# TLS/SSL Reconnaissance

SSL/TLS certificates are a goldmine of information about an organization's infrastructure, hidden assets, and backend systems.

## 1. Certificate Transparency (CT) Logs

CT logs record every SSL certificate issued by public CAs. This allows you to find subdomains moments after they are created.

### Tools & Commands
*   **ctfr**: Python tool to query CT logs without bruteforcing.
    ```bash
    python3 ctfr.py -d target.com
    ```
*   **crt.sh**: Manual/Automated querying.
    ```bash
    curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u
    ```

### Workflow
1.  Query CT logs for `target.com`.
2.  Extract all Subject Alternative Names (SANs).
3.  Identify dev/staging/internal subdomains (e.g., `vpn.dev.target.com`).
4.  Continuously monitor for new entries (using `certstream`) to catch assets as they come online.

## 2. SSL/TLS Configuration Analysis

Weak configurations can lead to Man-in-the-Middle (MitM) attacks or decryption of traffic.

### Tools & Commands
*   **testssl.sh**: The gold standard for CLI SSL testing.
    ```bash
    ./testssl.sh --fast --parallel https://target.com
    ```
*   **sslscan**: Fast scanner for supported ciphers.
    ```bash
    sslscan target.com:443
    ```

### Key Findings to Look For
*   **Weak Protocols**: SSLv2, SSLv3, TLS 1.0, TLS 1.1 (Deprecated).
*   **Weak Ciphers**: NULL, RC4, DES, 3DES, EXPORT.
*   **Vulnerabilities**: Heartbleed, POODLE, DROWN, ROBOT, FREAK, LOGJAM.
*   **Missing Headers**: HSTS (HTTP Strict Transport Security).

## 3. Infrastructure Fingerprinting (JARM)

JARM is an active fingerprinting tool that sends specially crafted TLS client hellos and records the specific attributes of the TLS server hello responses.

### Usage
```bash
jarm.sh -d target.com
```

### Analysis
*   **Identify C2 Servers**: Cobalt Strike and other C2 frameworks often have unique JARM signatures.
*   **Group Assets**: Identify all servers running the exact same stack (OS + Web Server + Library versions) even if they are on different IPs/Domains.
*   **Detect WAFs**: Determine if the target is behind Cloudflare, Akamai, or AWS based on the TLS handshake signature.

## 4. Subject Alternative Name (SAN) Enumeration

Certificates often cover multiple domains (multi-domain certs). Finding one domain allows you to find the others listed in the SAN field.

### Commands
```bash
openssl s_client -connect target.com:443 < /dev/null | openssl x509 -noout -text | grep -A 1 "Subject Alternative Name"
```

## 5. Certificate Expiration & Validity

*   **Expired Certs**: Can indicate abandoned infrastructure or potential for takeover.
## 6. Advanced TLSx Workflows

Leverage `tlsx` for rapid, large-scale certificate analysis.

### Basic TLS Certificate Scan
Full extraction of certificate details.
```bash
echo target.com | tlsx -san -cn -so -sv -ss -serial -hash md5 -jarm -ja3 -wc -tps -ve -ce -ct -cdn -silent | tee tlsx_full.txt
```

### Subdomain Discovery via SANs
Extract subdomains from Subject Alternative Names.
```bash
subfinder -d target.com -silent | tlsx -san -cn -silent -resp-only | grep -oE "[a-zA-Z0-9.-]+\.target\.com" | sort -u | anew san_subdomains.txt
```

### Expired Certificate Hunter
Find hosts with expired SSL certificates.
```bash
cat hosts.txt | tlsx -expired -silent -cn -so | tee expired_certs.txt
```

### Self-Signed Certificate Detection
Identify self-signed certificates (potential security issue).
```bash
cat hosts.txt | tlsx -self-signed -silent -cn -so -hash sha256 | tee self_signed.txt
```

### TLS Version Enumeration (Weak TLS)
Find hosts with deprecated TLS versions (TLS 1.0/1.1).
```bash
cat hosts.txt | tlsx -tls-version -silent | grep -E "(tls10|tls11)" | tee weak_tls_versions.txt
```

### JARM Fingerprinting Pipeline
Fingerprint server technology stack.
```bash
subfinder -d target.com -silent | httpx -silent | tlsx -jarm -silent -json | jq -r '[.host, .jarm_hash] | @tsv' | sort -k2 | anew jarm_fingerprints.txt
```

### Certificate Chain & Issuer Analysis
Analyze certificate chain to identify CA.
```bash
cat hosts.txt | tlsx -so -serial -hash sha256 -ve -ce -json -silent | jq -r '[.host, .issuer_cn, .not_after, .serial] | @tsv' | anew cert_chain_analysis.txt
```

### Mass TLS Scan with Cipher Enumeration
Full cipher suite enumeration.
```bash
subfinder -d target.com -silent | httpx -silent | tlsx -cipher -tls-version -silent -json | jq -r '[.host, .version, .cipher] | @tsv' | anew cipher_enum.txt
```

### Mismatched Certificate Detection
Find certificates where CN doesn't match hostname.
```bash
cat hosts.txt | tlsx -mismatched -cn -san -silent | tee mismatched_certs.txt
```

### Ultimate TLS Recon Pipeline
Complete TLS intelligence gathering in one command.
```bash
subfinder -d target.com -all -silent | httpx -silent -p 443,8443,4443,9443 | tlsx -san -cn -so -sv -ss -serial -expired -self-signed -mismatched -tls-version -jarm -hash sha256 -json -silent | jq -c '{host: .host, cn: .subject_cn, san: .san, issuer: .issuer_cn, expired: .expired, self_signed: .self_signed, tls: .version, jarm: .jarm_hash}' | tee tlsx_full_recon.json
```

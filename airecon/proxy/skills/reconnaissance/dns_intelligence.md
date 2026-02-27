---
name: dns_intelligence
description: Methodologies for deep DNS analysis, zone transfers, and record enumeration.
---

# DNS Intelligence

DNS is the backbone of the internet and often the first place to find misconfigurations. This skill focuses on extracting every ounce of data from DNS servers.

## 1. Zone Transfers (AXFR)

 A successful Zone Transfer leaks the entire DNS database for a domain, revealing all subdomains, internal IP addresses, and sometimes even test environments.

### Command
```bash
dig axfr @<nameserver> target.com
```

### Analysis
*   **Look for**: `dev`, `staging`, `vpn`, `intranet` subdomains.
*   **Internal IPs**: Records pointing to `192.168.x.x` or `10.x.x.x`.

## 2. Comprehensive Record Enumeration

Don't just look for `A` records. Other record types hold valuable intelligence.

### Record Types & Value
*   **MX**: Mail servers. Often outsourced (Google/Outlook) but sometimes self-hosted (vulnerable).
*   **TXT**: SPF/DMARC records often reveal third-party email providers (SendGrid, Mailgun) which can be used for phishing or takeover if the account is deleted.
*   **SRV**: Service records. Can point to LDAP, Kerberos, or SIP servers.
*   **CNAME**: Aliases. Crucial for Subdomain Takeover.
*   **NS**: Nameservers. Check if they are self-hosted (potential DoS target) or cloud-hosted.

### Automated Tool: `dnsx`
```bash
subfinder -d target.com -silent | dnsx -silent -a -aaaa -cname -ns -mx -txt -resp
```

## 3. Reverse DNS (PTR)

Mapping IP ranges back to hostnames. This is essential when you have a CIDR block and want to know what's running on those IPs.

### Workflow
1.  Identify the organization's ASN or IP ranges (see `comprehensive_recon.md`).
2.  Perform reverse lookup on the entire range.

### Command
```bash
dnsx -silent -ptr -l ip_list.txt
```

## 4. Subdomain Takeover Detection

Identify subdomains pointing to cloud services that have been deleted/deprovisioned.

### Indicators
*   **CNAME**: `target.com` -> `bucket.s3.amazonaws.com` (If the bucket doesn't exist, you can claim it).
*   **CNAME**: `blog.target.com` -> `target.github.io` (If the repo is deleted, you can claim it).

### Tool: `subjack`
```bash
subjack -w subdomains.txt -t 100 -timeout 30 -ssl -c fingerprints.json -v 3
```

## 5. DNS Security (DNSSEC/NSEC)

*   **NSEC Walking**: If DNSSEC is enabled with NSEC (not NSEC3), you can walk the zone to enumerate all valid subdomains.
    ```bash
## 6. Advanced DNS Workflows (dnsx)

Leverage `dnsx` for rapid, large-scale DNS analysis.

### 1. Mass DNS Resolution + Wildcard Filtering
Resolve subdomains and filter out wildcards.
```bash
subfinder -d target.com -silent | dnsx -silent -a -resp-only -wd target.com | sort -u | anew resolved_ips.txt
```

### 2. Multi-Record Type DNS Enumeration
Query A, AAAA, CNAME, MX, NS, TXT records simultaneously.
```bash
echo target.com | dnsx -silent -a -aaaa -cname -mx -ns -txt -resp | tee full_dns_records.txt
```

### 3. CNAME Extraction for Subdomain Takeover
Find dangling CNAMEs pointing to vulnerable services.
```bash
subfinder -d target.com -silent | dnsx -silent -cname -resp-only | grep -iE "(s3|cloudfront|herokuapp|github|azure|shopify|fastly|pantheon|zendesk|readme|ghost|surge|bitbucket|wordpress|tumblr)" | anew cname_takeover_candidates.txt
```

### 4. Reverse DNS (PTR) on IP Ranges
Discover hidden hosts via reverse DNS lookups.
```bash
prips 192.168.1.0/24 | dnsx -silent -ptr -resp-only | anew ptr_discovered_hosts.txt
```

### 5. MX Records for Email Security Analysis
Extract MX records to identify mail servers and SPF bypass opportunities.
```bash
cat domains.txt | dnsx -silent -mx -resp | awk '{print $1, $2}' | sort -u | tee mx_records.txt && cat domains.txt | dnsx -silent -txt -resp | grep -i "spf" | anew spf_records.txt
```

### 6. NS Records + DNS Zone Transfer Check
Enumerate nameservers and check for misconfigured zone transfers.
```bash
cat domains.txt | dnsx -silent -ns -resp-only | tee nameservers.txt && cat nameservers.txt | xargs -I@ -P10 sh -c 'host -t axfr target.com @ 2>&1 | grep -v "failed\|timed out" && echo "[ZONE TRANSFER] @"' | anew zone_transfers.txt
```

### 7. DNS Brute-force with Custom Resolvers
Mass DNS brute-force with custom resolver list.
```bash
cat wordlist.txt | sed 's/$/.target.com/' | dnsx -silent -r resolvers.txt -rl 500 -t 200 -retry 3 -resp-only | anew bruteforced_subs.txt
```

### 8. JSON Output for Advanced Parsing
Full DNS recon with JSON output for pipeline integration.
```bash
subfinder -d target.com -silent | dnsx -silent -a -aaaa -cname -mx -ns -txt -ptr -resp -json | jq -c '{host: .host, a: .a, aaaa: .aaaa, cname: .cname, mx: .mx, ns: .ns, txt: .txt}' | tee dns_full_recon.json
```

### 9. ASN Discovery via DNS + IP Correlation
Resolve domains, extract unique IPs, and identify ASN ownership.
```bash
subfinder -d target.com -silent | dnsx -silent -a -resp-only | sort -u | tee target_ips.txt | xargs -I{} sh -c 'whois {} 2>/dev/null | grep -iE "(netname|orgname|asn|origin)" | head -5' | anew asn_info.txt
```

### 10. Ultimate DNS Recon Pipeline
Complete DNS intelligence gathering.
```bash
domain="target.com"; subfinder -d $domain -all -silent | tee subs_$domain.txt | dnsx -silent -a -aaaa -cname -mx -ns -txt -resp -json -o dns_records_$domain.json; cat subs_$domain.txt | dnsx -silent -cname -resp-only | grep -iE "(s3|cloudfront|azure|github)" | anew takeover_$domain.txt; cat dns_records_$domain.json | jq -r '.a[]?' | sort -u | dnsx -silent -ptr -resp-only | anew ptr_$domain.txt; echo "[+] DNS Recon Complete: $(wc -l < subs_$domain.txt) subdomains | $(cat dns_records_$domain.json | wc -l) records"
```

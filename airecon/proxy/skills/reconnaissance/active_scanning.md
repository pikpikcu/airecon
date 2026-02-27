---
name: active_scanning
description: Methodologies for active reconnaissance and vulnerability scanning.
---

# Active Scanning

Active scanning involves directly interacting with the target to find open ports, services, and vulnerabilities. This generates more noise than passive recon but provides deeper insights.

## 1. Port Scanning & Service Discovery

### Rapid Port Scanning
Use `masscan` for extremely fast port scanning of large IP ranges.
```bash
masscan -p1-65535 <ip_range> --rate=1000 -e <interface> -oG masscan_output.grep
```

### Targeted Service Scanning
Use `nmap` on ports found by masscan for detailed service versioning.
```bash
nmap -sC -sV -p <ports> <target>
```

## 2. Web Fuzzing & Content Discovery

### Directory Bruteforcing
Use `dirb` or `gobuster` to find hidden directories and files.
```bash
dirb https://target.com /usr/share/wordlists/dirb/common.txt
```

### Parameter Discovery
Use `paramspider` to find hidden parameters that could be vulnerable to XSS or SQLi.
```bash
paramspider -d target.com
```

### CMS Scanning (WordPress)
Use `wpscan` to enumerate users, plugins, and themes on WordPress sites.
```bash
wpscan --url https://target.com --enumerate u,p,t --api-token <token>
```

## 3. Vulnerability Scanning

### Web Server Scanning
Use `nikto` to scan for outdated server software, dangerous files, and misconfigurations.
```bash
nikto -h https://target.com
```

### XSS Scanning
Use `dalfox` to audit URLs for Cross-Site Scripting vulnerabilities.
```bash
cat urls.txt | dalfox pipe
```

## 4. Infrastructure & filtering

### Passive Recon (Shodan)
Use `shodan` CLI to find exposed services without touching them.
```bash
shodan search org:"Target Org"
```

### URL Filtering
Use `uro` to filter out uninteresting or duplicate URLs from your recon data.
```bash
cat all_urls.txt | uro | tee filtered_urls.txt
```

## 5. DNS Resolution
Use `massdns` for high-performance bulk DNS resolution.
```bash
massdns -r resolvers.txt -t A -o S -w results.txt domains.txt
```

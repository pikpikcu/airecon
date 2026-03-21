"""Structured output parsers for common recon tools.

Instead of feeding raw stdout (thousands of lines) to the LLM,
parse it into a concise summary + key items.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from xml.etree.ElementTree import (
    ParseError as XMLParseError,  # nosec B405 - only importing exception class, not a parser
)

import defusedxml.ElementTree as ET

from .command_parse import extract_primary_binary

logger = logging.getLogger("airecon.agent.output_parser")


@dataclass
class ParsedOutput:
    """Structured representation of a tool's output."""
    tool: str
    summary: str             # e.g. "Found 47 subdomains"
    items: list[str] = field(default_factory=list)  # First N items for context
    total_count: int = 0
    raw_truncated: str = ""  # Fallback raw output (first 3000 chars)
    # Technology fingerprints extracted from tool output: {"nginx": "1.18.0",
    # "Bootstrap": "3.3.7"}
    technologies: dict[str, str] = field(default_factory=dict)


# Maximum items to include in parsed output for LLM context.
# Raised from 25 → 100 to give the LLM broader coverage of large scans
# (e.g. 80+ open ports from nmap, 100+ endpoints from ffuf).
# Monitor prompt size if slow responses or context-limit errors appear.
MAX_ITEMS = 100
MAX_RAW_FALLBACK = 3000


def _load_tool_patterns() -> list[tuple[re.Pattern[str], str]]:
    """Load tool binary → parser type mappings from data/tools_meta.json.

    Falls back to an empty list (triggers generic parser for all tools)
    if the JSON file is unavailable.
    """
    try:
        path = Path(__file__).resolve().parent.parent / "data" / "tools_meta.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        patterns = data.get("output_parser_tool_patterns", {})
        return [
            (re.compile(rf"\b{re.escape(binary)}\b"), parser_type)
            for binary, parser_type in patterns.items()
            if binary and parser_type
        ]
    except Exception as exc:
        logger.warning(
            "Could not load output_parser_tool_patterns from tools_meta.json: %s — "
            "tool detection disabled, generic parser will be used for all tools.",
            exc,
        )
        return []


# ── Tool Detection ──────────────────────────────────────────────────

# Map of tool binary names → parser type. Loaded from tools_meta.json
# (single source of truth). Each entry: (compiled regex, parser_type_name).
_TOOL_PATTERNS: list[tuple[re.Pattern[str], str]] = _load_tool_patterns()


def detect_tool(command: str) -> str | None:
    """Detect the primary tool from a command string."""
    first_token = extract_primary_binary(command)
    if not first_token:
        return None

    for pattern, tool_name in _TOOL_PATTERNS:
        if pattern.search(first_token):
            return tool_name
    return None


# ── Parsers ─────────────────────────────────────────────────────────

def parse_tool_output(command: str, stdout: str) -> ParsedOutput | None:
    """Auto-detect tool from command and parse its output.

    ALWAYS tries to return a ParsedOutput — either from a known tool parser
    or from the generic smart parser. Returns None ONLY if stdout is empty.
    """
    if not stdout or not stdout.strip():
        return None

    tool = detect_tool(command)

    parser_fn = _PARSERS.get(tool) if tool else None
    if parser_fn:
        try:
            result = parser_fn(stdout)
            result.tool = tool or ""
            return result
        except Exception as e:
            logger.warning(f"Parser failed for {tool}: {e}")

    # Fallback: generic smart parser for ALL unknown tools
    try:
        result = _parse_generic_smart(stdout)
        detected = tool or extract_primary_binary(command) or "unknown"
        if not tool:
            logger.warning(
                f"Unknown tool detected: {detected}. Using generic parser. "
                f"Output quality may be reduced. Command: {command[:100]}"
            )
            # Ensure raw output is attached so insights aren't lost
            if not result.raw_truncated:
                result.raw_truncated = stdout[:MAX_RAW_FALLBACK]
        result.tool = detected
        return result
    except Exception as e:
        logger.warning(f"Generic parser failed: {e}")
        return None


def _parse_nmap(stdout: str) -> ParsedOutput:
    """Parse nmap output — extract open ports and services."""
    # Try XML parsing first (if output contains XML)
    if "<?xml" in stdout or "<nmaprun" in stdout:
        return _parse_nmap_xml(stdout)

    # Otherwise parse grep/text output
    open_ports: list[str] = []
    hosts_up = 0
    hosts_down = 0

    for line in stdout.split("\n"):
        line = line.strip()
        # Match open port lines: "80/tcp  open  http  Apache/2.4.51"
        port_match = re.match(
            r"(\d+)/(tcp|udp)\s+(open|filtered)\s+(\S+)\s*(.*)", line
        )
        if port_match:
            port, proto, state, service, version = port_match.groups()
            version = version.strip()[:60]
            entry = f"{port}/{proto} {state} {service}"
            if version:
                entry += f" ({version})"
            open_ports.append(entry)
        elif "Host is up" in line:
            hosts_up += 1
        elif "host down" in line.lower():
            hosts_down += 1

    if not open_ports:
        return ParsedOutput(
            tool="nmap",
            summary=f"Nmap scan complete — 0 open ports found ({hosts_up} hosts up, {hosts_down} down)",
            items=[],
            total_count=0,
            raw_truncated=stdout[:MAX_RAW_FALLBACK],
        )

    return ParsedOutput(
        tool="nmap",
        summary=f"Nmap: {len(open_ports)} open ports found ({hosts_up} hosts up)",
        items=open_ports[:MAX_ITEMS],
        total_count=len(open_ports),
    )


def _parse_nmap_xml(stdout: str) -> ParsedOutput:
    """Parse nmap XML output."""
    # Extract XML portion
    xml_start = stdout.find("<?xml")
    if xml_start == -1:
        xml_start = stdout.find("<nmaprun")
    if xml_start == -1:
        return _parse_nmap(stdout.replace("<?xml", ""))  # fallback to text

    xml_content = stdout[xml_start:]

    try:
        root = ET.fromstring(xml_content)
    except XMLParseError:
        # Try to find just the nmap text output
        return ParsedOutput(
            tool="nmap",
            summary="Nmap XML parse failed — showing raw output",
            raw_truncated=stdout[:MAX_RAW_FALLBACK],
        )

    open_ports: list[str] = []
    hosts_up = 0

    for host in root.findall(".//host"):
        addr_el = host.find("address")
        addr = addr_el.get("addr", "?") if addr_el is not None else "?"
        status = host.find("status")
        if status is not None and status.get("state") == "up":
            hosts_up += 1

        for port in host.findall(".//port"):
            state_el = port.find("state")
            if state_el is not None and state_el.get(
                    "state") in ("open", "filtered"):
                portid = port.get("portid", "?")
                proto = port.get("protocol", "tcp")
                service_el = port.find("service")
                service = service_el.get(
                    "name", "unknown") if service_el is not None else "unknown"
                product = service_el.get(
                    "product", "") if service_el is not None else ""
                version = service_el.get(
                    "version", "") if service_el is not None else ""
                state = state_el.get("state")
                entry = f"{addr}:{portid}/{proto} {state} {service}"
                if product:
                    entry += f" {product}"
                if version:
                    entry += f" {version}"
                open_ports.append(entry)

    return ParsedOutput(
        tool="nmap",
        summary=f"Nmap: {len(open_ports)} open ports across {hosts_up} hosts",
        items=open_ports[:MAX_ITEMS],
        total_count=len(open_ports),
    )


def _parse_nuclei(stdout: str) -> ParsedOutput:
    """Parse nuclei output — JSON lines or text format."""
    findings: list[str] = []
    severity_counts: dict[str, int] = {
        "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    for line in stdout.strip().split("\n"):
        line = line.strip()
        if not line:
            continue

        # Try JSON line format
        if line.startswith("{"):
            try:
                data = json.loads(line)
                template_id = data.get(
                    "template-id",
                    data.get(
                        "templateID",
                        "?"))
                severity = data.get("info", {}).get("severity", "info").lower()
                matched = data.get("matched-at", data.get("matched", ""))
                name = data.get("info", {}).get("name", template_id)
                severity_counts[severity] = severity_counts.get(
                    severity, 0) + 1
                findings.append(f"[{severity.upper()}] {name} — {matched}")
                continue
            except json.JSONDecodeError:
                pass

        # Text format: "[template-id] [severity] matched-url"
        text_match = re.match(r"\[([^\]]+)\]\s*\[([^\]]+)\]\s*(.*)", line)
        if text_match:
            template_id, severity, rest = text_match.groups()
            severity = severity.strip().lower()
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            findings.append(
                f"[{severity.upper()}] {template_id} — {rest.strip()}")

    if not findings:
        return ParsedOutput(
            tool="nuclei",
            summary="Nuclei scan complete — 0 findings",
            items=[],
            total_count=0,
            raw_truncated=stdout[:MAX_RAW_FALLBACK],
        )

    sev_str = ", ".join(
        f"{v} {k}" for k,
        v in severity_counts.items() if v > 0)
    # Sort by severity (critical first)
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    findings.sort(key=lambda f: sev_order.get(f.split("]")[0].strip("["), 5))

    return ParsedOutput(
        tool="nuclei",
        summary=f"Nuclei: {len(findings)} findings ({sev_str})",
        items=findings[:MAX_ITEMS],
        total_count=len(findings),
    )


def _parse_httpx(stdout: str) -> ParsedOutput:
    """Parse httpx output — JSON lines or text format.

    Extracts technologies from -tech-detect JSON output into ParsedOutput.technologies.
    """
    hosts: list[str] = []
    technologies: dict[str, str] = {}

    for line in stdout.strip().split("\n"):
        line = line.strip()
        if not line:
            continue

        # JSON lines format (httpx -json or -tech-detect)
        if line.startswith("{"):
            try:
                data = json.loads(line)
                url = data.get("url", data.get("input", ""))
                status = data.get("status_code", data.get("status-code", ""))
                title = data.get("title", "")
                # tech can be a list of "Name/version" strings (httpx
                # -tech-detect)
                tech_raw = data.get("tech", [])
                entry = f"{url} [{status}]"
                if title:
                    entry += f" \"{title}\""
                if tech_raw:
                    entry += f" [{','.join(tech_raw[:3])}]"
                    for t in tech_raw:
                        # Normalize "Name/version" → technologies["Name"] =
                        # "version"
                        if "/" in t:
                            name, _, ver = t.partition("/")
                            technologies[name.strip()] = ver.strip()
                        else:
                            technologies[t.strip()] = ""
                hosts.append(entry)
                continue
            except json.JSONDecodeError:
                pass

        # Plain URL or "url [status_code]" format
        if line.startswith("http"):
            hosts.append(line)

    if not hosts:
        return ParsedOutput(
            tool="httpx",
            summary="httpx probe complete — 0 live hosts",
            items=[],
            total_count=0,
            raw_truncated=stdout[:MAX_RAW_FALLBACK],
            technologies=technologies,
        )

    return ParsedOutput(
        tool="httpx",
        summary=f"httpx: {len(hosts)} live hosts found"
        + (f", {len(technologies)} technologies" if technologies else ""),
        items=hosts[:MAX_ITEMS],
        total_count=len(hosts),
        technologies=technologies,
    )


def _parse_whatweb(stdout: str) -> ParsedOutput:
    """Parse whatweb output — JSON array or text 'Summary:' format.

    WhatWeb JSON (--log-json):
        [{"target":"http://...","plugins":{"nginx":{"version":["1.18.0"]},...}}]

    WhatWeb text:
        WhatWeb report for http://...
        Summary   : Bootstrap[3.3.7], nginx[1.18.0], PHP[7.4.3]
    """
    technologies: dict[str, str] = {}
    items: list[str] = []

    # ── Try JSON format first ──────────────────────────────────────────
    stripped = stdout.strip()
    if stripped.startswith("[") or stripped.startswith("{"):
        try:
            data = json.loads(stripped)
            if isinstance(data, dict):
                data = [data]
            for entry in (data if isinstance(data, list) else []):
                target = entry.get("target", "")
                plugins = entry.get("plugins", {})
                for name, info in plugins.items():
                    versions = info.get("version", info.get("string", []))
                    ver = versions[0] if versions else ""
                    technologies[name] = ver
                    items.append(
                        f"{name}{('/' + ver) if ver else ''} on {target}")
            if technologies:
                return ParsedOutput(
                    tool="whatweb",
                    summary=f"WhatWeb: {len(technologies)} technologies fingerprinted",
                    items=items[:MAX_ITEMS],
                    total_count=len(technologies),
                    technologies=technologies,
                )
        except (json.JSONDecodeError, TypeError):
            pass

    # ── Parse text format ─────────────────────────────────────────────
    # WhatWeb text: "Summary   : Bootstrap[3.3.7], nginx[1.18.0], PHP[7.4.3]"
    _summary_re = re.compile(r"^Summary\s*:\s*(.+)$", re.IGNORECASE)
    _tech_token_re = re.compile(r"([A-Za-z0-9_.\-]+)\[([^\]]+)\]")
    _tech_bare_re = re.compile(r"\b([A-Z][A-Za-z0-9_.\-]+)\b")
    current_target = ""

    for line in stdout.split("\n"):
        line = line.strip()
        if line.lower().startswith("whatweb report for"):
            current_target = line.split("for", 1)[-1].strip()
        m = _summary_re.match(line)
        if not m:
            continue
        summary_str = m.group(1)
        # Extract "Name[version]" tokens
        found_any = False
        for tech_m in _tech_token_re.finditer(summary_str):
            name, value = tech_m.group(1), tech_m.group(2)
            # Skip non-tech tokens like Email[...], Country[...]
            _SKIP = {
                "Email",
                "Country",
                "IP",
                "Meta",
                "Script",
                "Title",
                "Frame"}
            if name in _SKIP:
                continue
            technologies[name] = value if re.match(r"[\d.]", value) else ""
            items.append(f"{name}{('/' + technologies[name]) if technologies[name] else ''}"
                         + (f" on {current_target}" if current_target else ""))
            found_any = True
        # If no "[version]" tokens found, try bare capitalised words
        if not found_any:
            for bare_m in _tech_bare_re.finditer(summary_str):
                name = bare_m.group(1)
                if name not in {"HTTP", "HTML", "URL", "API"}:
                    technologies[name] = ""
                    items.append(
                        name + (f" on {current_target}" if current_target else ""))

    if not technologies:
        return ParsedOutput(
            tool="whatweb",
            summary="WhatWeb: no technologies parsed",
            items=[],
            total_count=0,
            raw_truncated=stdout[:MAX_RAW_FALLBACK],
        )

    return ParsedOutput(
        tool="whatweb",
        summary=f"WhatWeb: {len(technologies)} technologies fingerprinted",
        items=items[:MAX_ITEMS],
        total_count=len(technologies),
        technologies=technologies,
    )


def _parse_line_list(stdout: str) -> ParsedOutput:
    """Generic parser for line-per-item tools (subfinder, katana, waybackurls, etc.)."""
    # Log-prefix patterns to skip: [INFO], [+], [*], [ERR], [WRN] — but NOT
    # katana/gospider output lines like "[javascript] https://..." which contain
    # real URLs. We only skip lines whose bracket prefix is a log-level word.
    _LOG_PREFIX_RE = re.compile(r"^\[(INFO|ERR|WRN|DEBUG|WARN|ERROR|FATAL)\]", re.IGNORECASE)
    items = []
    for line in stdout.strip().split("\n"):
        line = line.strip()
        if not line:
            continue
        if line.startswith("//"):
            continue
        # Skip pure log-level prefixes, but keep URL lines starting with [
        if line.startswith("[") and _LOG_PREFIX_RE.match(line):
            continue
        items.append(line)

    # Deduplicate preserving order
    seen: set[str] = set()
    unique: list[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            unique.append(item)

    return ParsedOutput(
        tool="list",
        summary=f"Found {len(unique)} items ({len(items) - len(unique)} duplicates removed)",
        items=unique[:MAX_ITEMS],
        total_count=len(unique),
    )


def _parse_ffuf(stdout: str) -> ParsedOutput:
    """Parse ffuf output — JSON or text format."""
    results: list[str] = []

    # Try as JSON report
    try:
        data = json.loads(stdout)
        if isinstance(data, dict) and "results" in data:
            for r in data["results"]:
                url = r.get("url", r.get("input", {}).get("FUZZ", "?"))
                status = r.get("status", "?")
                length = r.get("length", "?")
                words = r.get("words", "?")
                results.append(
                    f"{url} [Status: {status}, Size: {length}, Words: {words}]")
    except (json.JSONDecodeError, TypeError):
        pass

    # Fallback: parse text output
    if not results:
        for line in stdout.strip().split("\n"):
            # ffuf text output: "page  [Status: 200, Size: 1234, Words: 56,
            # Lines: 7]"
            if "[Status:" in line:
                results.append(line.strip())
            elif re.match(r"\S+\s+\[", line):
                results.append(line.strip())

    if not results:
        return ParsedOutput(
            tool="ffuf",
            summary="ffuf scan complete — 0 results",
            items=[],
            total_count=0,
            raw_truncated=stdout[:MAX_RAW_FALLBACK],
        )

    return ParsedOutput(
        tool="ffuf",
        summary=f"ffuf: {len(results)} endpoints discovered",
        items=results[:MAX_ITEMS],
        total_count=len(results),
    )


def _parse_naabu(stdout: str) -> ParsedOutput:
    """Parse naabu output — host:port per line."""
    ports: list[str] = []
    port_counts: dict[str, list[str]] = {}  # host -> [ports]

    for line in stdout.strip().split("\n"):
        line = line.strip()
        if not line:
            continue
        # Format: "host:port" or just "host:port"
        if ":" in line:
            parts = line.rsplit(":", 1)
            if len(parts) == 2 and parts[1].isdigit():
                host, port = parts
                port_counts.setdefault(host, []).append(port)
                ports.append(line)
        elif line.isdigit():
            ports.append(f":{line}")

    if not ports:
        return ParsedOutput(
            tool="naabu",
            summary="naabu scan complete — 0 open ports",
            items=[],
            total_count=0,
            raw_truncated=stdout[:MAX_RAW_FALLBACK],
        )

    host_summary = ", ".join(
        f"{h}({len(p)} ports)" for h, p in list(port_counts.items())[:5])
    return ParsedOutput(
        tool="naabu",
        summary=f"naabu: {len(ports)} open ports across {len(port_counts)} hosts — {host_summary}",
        items=ports[:MAX_ITEMS],
        total_count=len(ports),
    )


# ── Exploitation Tool Parsers ────────────────────────────────────────

def _parse_sqlmap(stdout: str) -> ParsedOutput:
    """Parse sqlmap/ghauri output — extract injection points and payloads."""
    findings: list[str] = []
    param_vulns: list[str] = []
    dbms: str = ""
    current_url: str = ""

    for line in stdout.split("\n"):
        line = line.strip()
        if not line:
            continue

        # Target URL
        if line.startswith("URL:") or "testing URL" in line.lower():
            m = re.search(r"https?://\S+", line)
            if m:
                current_url = m.group(0)

        # Vulnerable parameter found
        vuln_param = re.match(
            r".*parameter\s+'?([^']+?)'?\s+(?:is|appears to be|was found)\s+(?:vulnerable|injectable)",
            line, re.IGNORECASE,
        )
        if vuln_param:
            param = vuln_param.group(1).strip()
            entry = f"[HIGH] SQLi parameter vulnerable: {param}"
            if current_url:
                entry += f" @ {current_url}"
            param_vulns.append(entry)
            findings.append(entry)
            continue

        # Payload/technique lines
        if re.match(r"\s+Type:", line, re.IGNORECASE):
            findings.append(f"  Technique: {line.strip()}")
        elif re.match(r"\s+Payload:", line, re.IGNORECASE):
            findings.append(f"  {line.strip()}")

        # DBMS detection
        m_db = re.search(r"back-end DBMS(?:\s+is)?\s*:?\s+(.+)", line, re.IGNORECASE)
        if m_db:
            dbms = m_db.group(1).strip()

        # Data extraction / dump lines
        if re.match(r"\[INFO\].*(?:fetching|dumping|retrieving)", line, re.IGNORECASE):
            findings.append(line)

        # Critical results — extracted data
        if re.match(r"Database:\s+", line, re.IGNORECASE):
            findings.append(f"[CRITICAL] {line}")
        elif re.match(r"Table:\s+", line, re.IGNORECASE):
            findings.append(f"[HIGH] {line}")

    if not findings and not param_vulns:
        # Check if it ran but found nothing
        if "sqlmap identified the following injection point" in stdout.lower():
            findings.append("[HIGH] sqlmap identified injection points (check full output)")
        elif "no parameter(s) found" in stdout.lower() or "not injectable" in stdout.lower():
            return ParsedOutput(
                tool="sqlmap",
                summary="sqlmap: no injectable parameters found",
                items=[],
                total_count=0,
                raw_truncated=stdout[:MAX_RAW_FALLBACK],
            )
        else:
            return ParsedOutput(
                tool="sqlmap",
                summary="sqlmap: scan complete",
                items=[],
                total_count=0,
                raw_truncated=stdout[:MAX_RAW_FALLBACK],
            )

    vuln_count = len(param_vulns)
    dbms_note = f" | DBMS: {dbms}" if dbms else ""
    return ParsedOutput(
        tool="sqlmap",
        summary=f"sqlmap: {vuln_count} vulnerable parameter(s) found{dbms_note}",
        items=findings[:MAX_ITEMS],
        total_count=len(findings),
    )


def _parse_nikto(stdout: str) -> ParsedOutput:
    """Parse nikto output — extract findings and vulnerabilities."""
    findings: list[str] = []
    target: str = ""

    for line in stdout.split("\n"):
        line = line.strip()
        if not line:
            continue

        # Target header
        if line.startswith("- Target IP:") or line.startswith("+ Target IP:"):
            target = line
            continue
        if line.startswith("+ Target Hostname:") or line.startswith("- Target Hostname:"):
            target += " " + line.split(":", 1)[-1].strip()
            continue

        # Findings start with "+ " or "- "
        if line.startswith("+ ") or line.startswith("- "):
            content = line[2:].strip()

            # Skip non-finding info lines
            skip_patterns = (
                "Nikto", "Start Time", "End Time", "No CGI",
                "allowed HTTP Methods", "Server:", "retrieved:",
                "items found", "0 errors", "scan took", "Host:",
            )
            if any(s.lower() in content.lower() for s in skip_patterns):
                continue

            # Severity tagging based on content
            sev = "MEDIUM"
            high_patterns = ("XSS", "SQL", "RCE", "command", "injection",
                             "traversal", "passwd", "password", "credentials",
                             "admin", "phpinfo", "config", "backup", "shell")
            low_patterns = ("X-Frame-Options", "X-Content-Type", "anti-clickjacking",
                            "Strict-Transport", "Content-Security")
            if any(p.lower() in content.lower() for p in high_patterns):
                sev = "HIGH"
            elif any(p.lower() in content.lower() for p in low_patterns):
                sev = "LOW"

            # Extract OSVDB IDs as reference
            osvdb_match = re.search(r"OSVDB-(\d+)", content)
            osvdb_note = f" [OSVDB-{osvdb_match.group(1)}]" if osvdb_match else ""

            findings.append(f"[{sev}] {content}{osvdb_note}")

    if not findings:
        return ParsedOutput(
            tool="nikto",
            summary="nikto: no findings",
            items=[],
            total_count=0,
            raw_truncated=stdout[:MAX_RAW_FALLBACK],
        )

    high_count = sum(1 for f in findings if f.startswith("[HIGH]"))
    target_note = f" on {target}" if target else ""
    return ParsedOutput(
        tool="nikto",
        summary=f"nikto: {len(findings)} findings ({high_count} HIGH){target_note}",
        items=findings[:MAX_ITEMS],
        total_count=len(findings),
    )


def _parse_dalfox(stdout: str) -> ParsedOutput:
    """Parse dalfox output — extract XSS vulnerability findings."""
    findings: list[str] = []
    poc_lines: list[str] = []

    for line in stdout.split("\n"):
        line = line.strip()
        if not line:
            continue

        # dalfox marks vulns with [V] and POC with [POC]
        if line.startswith("[V]") or "] [V]" in line:
            findings.append(f"[HIGH] XSS VERIFIED: {line}")
        elif line.startswith("[POC]") or "] [POC]" in line:
            poc_lines.append(f"  PoC: {line}")
        elif line.startswith("[G]") or "] [G]" in line:
            # [G] = Good finding (potential XSS)
            findings.append(f"[MEDIUM] XSS potential: {line}")
        elif re.match(r"\[WEAK\]|\[I\]", line, re.IGNORECASE):
            findings.append(f"[LOW] {line}")

    # Combine findings with their PoC lines
    combined = findings[:MAX_ITEMS]
    if poc_lines:
        combined.extend(poc_lines[:10])

    if not combined:
        return ParsedOutput(
            tool="dalfox",
            summary="dalfox: no XSS vulnerabilities found",
            items=[],
            total_count=0,
            raw_truncated=stdout[:MAX_RAW_FALLBACK],
        )

    verified = sum(1 for f in findings if "[HIGH]" in f)
    return ParsedOutput(
        tool="dalfox",
        summary=f"dalfox: {len(findings)} XSS findings ({verified} verified)",
        items=combined,
        total_count=len(combined),
    )


def _parse_wpscan(stdout: str) -> ParsedOutput:
    """Parse wpscan output — extract WordPress vulnerabilities, plugins, users."""
    findings: list[str] = []
    current_section: str = ""

    lines = stdout.split("\n")
    i = 0
    while i < len(lines):
        line = lines[i].strip()

        # Section headers
        if re.match(r"\[i\]\s+(WordPress|Plugins|Themes|Users|Config)", line, re.IGNORECASE):
            current_section = line
        elif re.match(r"\[\+\]\s+WordPress version", line, re.IGNORECASE):
            findings.append(f"[INFO] {line}")
        elif re.match(r"\[!\]", line):
            # [!] = vulnerability / issue
            sev = "HIGH"
            content = line[3:].strip()
            if any(k in content.lower() for k in ("critical", "rce", "sqli", "exec")):
                sev = "CRITICAL"
            elif any(k in content.lower() for k in ("xss", "csrf", "auth", "bypass")):
                sev = "HIGH"
            elif any(k in content.lower() for k in ("info", "disclosure", "enum")):
                sev = "MEDIUM"
            findings.append(f"[{sev}] {content}")
        elif re.match(r"\[\+\]\s+Username found", line, re.IGNORECASE):
            findings.append(f"[MEDIUM] {line[3:].strip()}")
        elif re.match(r"\[\+\]\s+.+found", line, re.IGNORECASE) and "plugin" in current_section.lower():
            findings.append(f"[INFO] Plugin: {line[3:].strip()}")

        # CVE references on the next few lines after a [!]
        if findings and "[HIGH]" in findings[-1] or (findings and "[CRITICAL]" in findings[-1]):
            # Look ahead for CVE
            for j in range(1, min(5, len(lines) - i)):
                ahead = lines[i + j].strip()
                cve_m = re.search(r"CVE-\d{4}-\d+", ahead)
                if cve_m:
                    findings[-1] += f" ({cve_m.group(0)})"
                    break
                if not ahead or ahead.startswith("["):
                    break

        i += 1

    if not findings:
        return ParsedOutput(
            tool="wpscan",
            summary="wpscan: no vulnerabilities found",
            items=[],
            total_count=0,
            raw_truncated=stdout[:MAX_RAW_FALLBACK],
        )

    vuln_count = sum(1 for f in findings if "[HIGH]" in f or "[CRITICAL]" in f)
    return ParsedOutput(
        tool="wpscan",
        summary=f"wpscan: {len(findings)} findings ({vuln_count} HIGH/CRITICAL)",
        items=findings[:MAX_ITEMS],
        total_count=len(findings),
    )


# ── Generic Smart Parser ────────────────────────────────────────────

def _parse_generic_smart(stdout: str) -> ParsedOutput:
    """Smart parser for ANY tool output — auto-detects format.

    Handles: JSON lines, CSV-like tables, URL lists, key:value pairs,
    bracket-tagged lines [TAG] content, and generic text.
    """
    lines = [line.strip()
             for line in stdout.strip().split("\n") if line.strip()]
    total = len(lines)

    if total == 0:
        return ParsedOutput(
            tool="unknown", summary="Empty output", total_count=0)

    # Detect: JSON lines output
    json_count = sum(1 for line in lines[:20] if line.startswith("{"))
    if json_count > len(lines[:20]) * 0.5:
        return _parse_generic_jsonl(lines)

    # Detect: all lines are URLs
    url_count = sum(1 for line in lines[:20] if re.match(r"https?://", line))
    if url_count > len(lines[:20]) * 0.7:
        return _parse_line_list(stdout)

    # Detect: bracket-tagged lines like "[tag] content" (nuclei-style,
    # nikto-style)
    tag_count = sum(1 for line in lines[:20] if re.match(r"^\[.+\]", line))
    if tag_count > len(lines[:20]) * 0.5:
        return _parse_generic_tagged(lines)

    # Detect: table-like output (columns separated by spaces/tabs)
    # Check if lines have consistent column count
    col_counts = [len(re.split(r"\s{2,}|\t", line)) for line in lines[:10]]
    if col_counts and min(col_counts) >= 3 and max(
            col_counts) - min(col_counts) <= 1:
        return _parse_generic_table(lines)

    # Detect: key:value or key=value pairs
    kv_count = sum(1 for line in lines[:20] if re.match(
        r"^[\w\-\.]+:\s+.+", line))
    if kv_count > len(lines[:20]) * 0.5:
        return _parse_generic_kv(lines)

    # Default: smart line summary
    return _parse_generic_lines(lines)


def _parse_generic_jsonl(lines: list[str]) -> ParsedOutput:
    """Parse JSON lines output from any tool."""
    items: list[str] = []
    for line in lines:
        if not line.startswith("{"):
            continue
        try:
            data = json.loads(line)
            # Try common key patterns
            summary_parts = []
            for key in ("url", "host", "ip", "domain",
                        "target", "matched", "name", "input"):
                if key in data:
                    summary_parts.append(str(data[key]))
                    break
            # Add severity/status if present
            for key in ("severity", "status", "status_code", "type", "level"):
                if key in data:
                    summary_parts.append(f"[{data[key]}]")
                    break
            # Add info/description if present
            for key in ("info", "title", "description", "message"):
                val = data.get(key)
                if isinstance(val, str) and val:
                    summary_parts.append(val[:80])
                    break
                elif isinstance(val, dict) and "name" in val:
                    summary_parts.append(val["name"][:80])
                    break
            items.append(" ".join(summary_parts)
                         if summary_parts else line[:120])
        except json.JSONDecodeError:
            items.append(line[:120])

    seen: set[str] = set()
    # type: ignore
    unique = [i for i in items if i not in seen and not seen.add(i)]

    return ParsedOutput(
        tool="json",
        summary=f"JSON output: {len(unique)} entries",
        items=unique[:MAX_ITEMS],
        total_count=len(unique),
    )


def _parse_generic_tagged(lines: list[str]) -> ParsedOutput:
    """Parse bracket-tagged output like [INFO] message, [+] found, etc."""
    items: list[str] = []
    tag_counts: dict[str, int] = {}

    for line in lines:
        match = re.match(r"^\[([^\]]+)\]\s*(.*)", line)
        if match:
            tag, content = match.groups()
            tag = tag.strip().upper()
            tag_counts[tag] = tag_counts.get(tag, 0) + 1
            if content.strip():
                items.append(f"[{tag}] {content.strip()[:120]}")
        else:
            items.append(line[:120])

    tag_str = ", ".join(
        f"{v}x {k}" for k,
        v in sorted(
            tag_counts.items(),
            key=lambda x: -
            x[1])[
            :5])

    seen: set[str] = set()
    # type: ignore
    unique = [i for i in items if i not in seen and not seen.add(i)]

    return ParsedOutput(
        tool="tagged",
        summary=f"{len(unique)} results ({tag_str})",
        items=unique[:MAX_ITEMS],
        total_count=len(unique),
    )


def _parse_generic_table(lines: list[str]) -> ParsedOutput:
    """Parse table-like output with columns."""
    items: list[str] = []
    # header = lines[0] if lines else ""

    for line in lines[:MAX_ITEMS + 5]:
        items.append(line[:150])

    return ParsedOutput(
        tool="table",
        summary=f"Table output: {len(lines)} rows",
        items=items[:MAX_ITEMS],
        total_count=len(lines),
    )


def _parse_generic_kv(lines: list[str]) -> ParsedOutput:
    """Parse key:value or key=value output."""
    items: list[str] = []
    for line in lines:
        items.append(line[:150])

    return ParsedOutput(
        tool="kv",
        summary=f"Output: {len(lines)} entries",
        items=items[:MAX_ITEMS],
        total_count=len(lines),
    )


def _parse_generic_lines(lines: list[str]) -> ParsedOutput:
    """Smart line-based summary for any text output."""
    # Filter out empty/noise lines
    meaningful = [
        line for line in lines if len(line) > 3 and not line.startswith(
            ("---", "===", "###", "✓", "✗", "Error", "Warning"))]

    seen: set[str] = set()
    # type: ignore
    unique = [i for i in meaningful if i not in seen and not seen.add(i)]

    dupes = len(meaningful) - len(unique)
    return ParsedOutput(
        tool="text",
        summary=f"Output: {len(unique)} lines" +
        (f" ({dupes} duplicates removed)" if dupes > 0 else ""),
        items=unique[:MAX_ITEMS],
        total_count=len(unique),
        raw_truncated="" if len(
            unique) <= MAX_ITEMS else "\n".join(lines[-10:]),
    )


def _parse_hydra(stdout: str) -> ParsedOutput:
    """Parse hydra/medusa output — extract credential findings."""
    findings: list[str] = []

    for line in stdout.split("\n"):
        line = line.strip()
        if not line:
            continue
        # Hydra format: "[22][ssh] host: 1.2.3.4   login: admin   password: 123456"
        if re.match(r"\[\d+\]\[", line) and ("login:" in line or "password:" in line):
            findings.append(f"[HIGH] Credential found: {line}")
        # Medusa format: "ACCOUNT FOUND: [ssh] Host: 1.2.3.4 User: admin Password: 123"
        elif re.match(r"ACCOUNT FOUND:", line, re.IGNORECASE):
            findings.append(f"[HIGH] Credential found: {line}")
        # "[DATA] ... valid passwords ... or status lines"
        elif line.startswith("[DATA]") and "valid" in line.lower():
            findings.append(f"[MEDIUM] {line}")

    if not findings:
        return ParsedOutput(
            tool="hydra",
            summary="hydra: no credentials found",
            items=[],
            total_count=0,
            raw_truncated=stdout[:MAX_RAW_FALLBACK],
        )
    return ParsedOutput(
        tool="hydra",
        summary=f"hydra: {len(findings)} credential(s) found",
        items=findings[:MAX_ITEMS],
        total_count=len(findings),
    )


def _parse_metasploit(stdout: str) -> ParsedOutput:
    """Parse metasploit/msfconsole output — extract exploitation results."""
    findings: list[str] = []
    _NEGATIVE_RE = re.compile(
        r"\b(?:"
        r"not\s+vulnerable(?:\s+to)?"
        r"|not\s+affected"
        r"|unaffected"
        r"|not\s+impacted"
        r"|no\s+vulnerabilit(?:y|ies)"
        r"|not\s+exploitable"
        r"|already\s+patched"
        r"|fully\s+patched"
        r"|fixed\s+in"
        r"|patch\s+available"
        r")\b",
        re.IGNORECASE,
    )

    for line in stdout.split("\n"):
        line = line.strip()
        if not line:
            continue
        if _NEGATIVE_RE.search(line):
            continue
        # "[+] host - Vulnerable to ..." or "[+] Meterpreter session ..."
        if line.startswith("[+]") and any(
            kw in line.lower()
            for kw in ("vulnerable", "session opened", "shell", "meterpreter",
                       "exploit succeeded", "access granted", "root")
        ):
            findings.append(f"[HIGH] {line}")
        # "[*] ... found ..."
        elif line.startswith("[*]") and "found" in line.lower():
            findings.append(f"[MEDIUM] {line}")

    if not findings:
        return ParsedOutput(
            tool="metasploit",
            summary="metasploit: no exploitation results",
            items=[],
            total_count=0,
            raw_truncated=stdout[:MAX_RAW_FALLBACK],
        )
    return ParsedOutput(
        tool="metasploit",
        summary=f"metasploit: {len(findings)} result(s)",
        items=findings[:MAX_ITEMS],
        total_count=len(findings),
    )


# ── Parser Registry ──────────────────────────────────────────────────

# Maps parser type names (from output_parser_tool_patterns in tools_meta.json)
# to their corresponding parser functions. This dict is logic (name→function
# binding), not data, so it lives in Python rather than JSON.
_PARSERS: dict[str, Any] = {
    "nmap": _parse_nmap,
    "nuclei": _parse_nuclei,
    "subfinder": _parse_line_list,
    "httpx": _parse_httpx,
    "url_list": _parse_line_list,
    "ffuf": _parse_ffuf,
    "naabu": _parse_naabu,
    "sqlmap": _parse_sqlmap,
    "nikto": _parse_nikto,
    "dalfox": _parse_dalfox,
    "wpscan": _parse_wpscan,
    "dnsx": _parse_line_list,
    "whatweb": _parse_whatweb,
    "dig": _parse_line_list,
    "hydra": _parse_hydra,
    "metasploit": _parse_metasploit,
}

"""Structured output parsers for common recon tools.

Instead of feeding raw stdout (thousands of lines) to the LLM,
parse it into a concise summary + key items.
"""

from __future__ import annotations

import json
import logging
import re
import defusedxml.ElementTree as ET
from xml.etree.ElementTree import ParseError as XMLParseError  # nosec B405 - only importing exception class, not a parser
from dataclasses import dataclass, field


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


# ── Tool Detection ──────────────────────────────────────────────────

# Map of tool binary names → parser function name
_TOOL_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\bnmap\b"), "nmap"),
    (re.compile(r"\bnuclei\b"), "nuclei"),
    (re.compile(r"\bsubfinder\b"), "subfinder"),
    (re.compile(r"\bamass\b"), "subfinder"),       # same line-based format
    (re.compile(r"\bassetfinder\b"), "subfinder"),
    (re.compile(r"\bfindomain\b"), "subfinder"),
    (re.compile(r"\bhttpx\b"), "httpx"),
    (re.compile(r"\bkatana\b"), "url_list"),
    (re.compile(r"\bgospider\b"), "url_list"),
    (re.compile(r"\bwaybackurls\b"), "url_list"),
    (re.compile(r"\bgau\b"), "url_list"),
    (re.compile(r"\bffuf\b"), "ffuf"),
    (re.compile(r"\bnaabu\b"), "naabu"),
    (re.compile(r"\bdnsx\b"), "dnsx"),
    (re.compile(r"\bwhatweb\b"), "whatweb"),
    (re.compile(r"\bdig\b"), "dig"),
    (re.compile(r"\bwfuzz\b"), "ffuf"),            # similar format
    (re.compile(r"\bdirsearch\b"), "url_list"),
    (re.compile(r"\bferoxbuster\b"), "url_list"),
]


def detect_tool(command: str) -> str | None:
    """Detect the primary tool from a command string."""
    # Strip the cd prefix that executors.py adds
    cmd = re.sub(r"^cd\s+/workspace/[^\s]+\s*&&\s*", "", command).strip()
    # Get the first token (the binary name)
    first_token = cmd.split()[0] if cmd.split() else ""
    # Also check for sudo prefix
    if first_token == "sudo" and len(cmd.split()) > 1:  # nosec B105 - not a password
        first_token = cmd.split()[1]

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

    parsers = {
        "nmap": _parse_nmap,
        "nuclei": _parse_nuclei,
        "subfinder": _parse_line_list,
        "httpx": _parse_httpx,
        "url_list": _parse_line_list,
        "ffuf": _parse_ffuf,
        "naabu": _parse_naabu,
        "dnsx": _parse_line_list,
        "whatweb": _parse_whatweb,
        "dig": _parse_line_list,
    }

    parser_fn = parsers.get(tool) if tool else None
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
        detected = tool or _detect_tool_name_from_cmd(command)
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


def _detect_tool_name_from_cmd(command: str) -> str:
    """Extract the tool binary name from a command string."""
    cmd = re.sub(r"^cd\s+/workspace/[^\s]+\s*&&\s*", "", command).strip()
    tokens = cmd.split()
    if not tokens:
        return "unknown"
    name = tokens[0]
    if name == "sudo" and len(tokens) > 1:
        name = tokens[1]
    # Strip path prefix
    name = name.rsplit("/", 1)[-1]
    return name


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
                entry = f"{addr}:{portid}/{proto} {state_el.get('state')} {service}"
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
    items = []
    for line in stdout.strip().split("\n"):
        line = line.strip()
        if line and not line.startswith("[") and not line.startswith("//"):
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

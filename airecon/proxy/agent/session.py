"""Session persistence — save/load findings per target across sessions.

Stores structured findings (subdomains, ports, vulns, etc.) in
~/.airecon/sessions/<target>.json so the agent can resume where it left off.
"""

from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Any

from .output_parser import ParsedOutput

logger = logging.getLogger("airecon.agent.session")

SESSIONS_DIR = Path.home() / ".airecon" / "sessions"


@dataclass
class SessionData:
    """Persistent per-target session state."""
    target: str
    subdomains: list[str] = field(default_factory=list)
    live_hosts: list[str] = field(default_factory=list)
    open_ports: dict[str, list[int]] = field(default_factory=dict)
    urls: list[str] = field(default_factory=list)
    technologies: dict[str, str] = field(default_factory=dict)
    vulnerabilities: list[dict[str, Any]] = field(default_factory=list)
    completed_phases: list[str] = field(default_factory=list)
    tools_run: list[str] = field(default_factory=list)
    scan_count: int = 0
    created_at: str = ""
    updated_at: str = ""

    def __post_init__(self) -> None:
        if not self.created_at:
            self.created_at = datetime.now().isoformat()
        self.updated_at = datetime.now().isoformat()


def _target_to_filename(target: str) -> str:
    """Sanitize target name for use as filename."""
    return re.sub(r"[^a-zA-Z0-9.\-_]", "_", target) + ".json"


def load_session(target: str) -> SessionData | None:
    """Load a previous session for the given target.

    Returns None if no session exists.
    """
    filepath = SESSIONS_DIR / _target_to_filename(target)
    if not filepath.exists():
        return None

    try:
        with open(filepath, "r") as f:
            data = json.load(f)
        session = SessionData(
            target=data.get("target", target),
            subdomains=data.get("subdomains", []),
            live_hosts=data.get("live_hosts", []),
            open_ports=data.get("open_ports", {}),
            urls=data.get("urls", []),
            technologies=data.get("technologies", {}),
            vulnerabilities=data.get("vulnerabilities", []),
            completed_phases=data.get("completed_phases", []),
            tools_run=data.get("tools_run", []),
            scan_count=data.get("scan_count", 0),
            created_at=data.get("created_at", ""),
            updated_at=data.get("updated_at", ""),
        )
        logger.info(f"Loaded session for {target}: {len(session.subdomains)} subs, {len(session.live_hosts)} live, {len(session.vulnerabilities)} vulns")
        return session
    except Exception as e:
        logger.warning(f"Failed to load session for {target}: {e}")
        return None


def save_session(session: SessionData) -> None:
    """Save session data to disk."""
    try:
        SESSIONS_DIR.mkdir(parents=True, exist_ok=True)
        filepath = SESSIONS_DIR / _target_to_filename(session.target)
        session.updated_at = datetime.now().isoformat()
        with open(filepath, "w") as f:
            json.dump(asdict(session), f, indent=2, default=str)
        logger.info(f"Saved session for {session.target}")
    except Exception as e:
        logger.error(f"Failed to save session for {session.target}: {e}")


def update_from_parsed_output(
    session: SessionData,
    parsed: ParsedOutput,
    command: str = "",
) -> None:
    """Update session data based on WHAT THE DATA LOOKS LIKE, not which tool produced it.

    Classification logic:
    - Items that look like subdomains (e.g. "sub.example.com") → session.subdomains
    - Items that look like URLs (start with http) → session.urls or session.live_hosts
    - Items that look like host:port → session.open_ports
    - Items that look like port/proto lines → session.open_ports
    - Items with severity tags [CRITICAL] [HIGH] etc → session.vulnerabilities
    - Everything else: logged but not stored (no false assumptions)
    """
    session.scan_count += 1
    session.updated_at = datetime.now().isoformat()

    # Track which tools have been run (use actual binary name)
    tool_key = parsed.tool
    if tool_key and tool_key not in session.tools_run:
        session.tools_run.append(tool_key)

    if not parsed.items:
        return

    # Classify each item by its content pattern
    _SUBDOMAIN_RE = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)+$")
    _URL_RE = re.compile(r"^https?://")
    _HOST_PORT_RE = re.compile(r"^([a-zA-Z0-9.\-]+):(\d+)")
    _PORT_PROTO_RE = re.compile(r"^(\d+)/(tcp|udp)\s+(open|filtered)")
    _SEVERITY_RE = re.compile(r"^\[(CRITICAL|HIGH|MEDIUM|LOW|INFO)\]", re.IGNORECASE)
    _HTTP_STATUS_RE = re.compile(r"https?://\S+\s+\[(\d{3})\]")

    for item in parsed.items:
        item_stripped = item.strip()
        if not item_stripped:
            continue

        # 1. Severity-tagged finding → vulnerability
        if _SEVERITY_RE.match(item_stripped):
            session.vulnerabilities.append({
                "finding": item_stripped,
                "source": tool_key,
                "timestamp": datetime.now().isoformat(),
            })
            continue

        # 2. URL with status code (httpx-style) → live_hosts
        status_match = _HTTP_STATUS_RE.match(item_stripped)
        if status_match:
            url = item_stripped.split(" [")[0].strip()
            if url and url not in session.live_hosts:
                session.live_hosts.append(url)
            continue

        # 3. Plain URL → urls collection
        if _URL_RE.match(item_stripped):
            url = item_stripped.split()[0]  # take just the URL part
            if url not in session.urls:
                session.urls.append(url)
            continue

        # 4. host:port format → open_ports
        hp_match = _HOST_PORT_RE.match(item_stripped)
        if hp_match:
            host, port_str = hp_match.group(1), hp_match.group(2)
            if port_str.isdigit():
                port = int(port_str)
                session.open_ports.setdefault(host, [])
                if port not in session.open_ports[host]:
                    session.open_ports[host].append(port)
            continue

        # 5. port/proto state service (nmap-style) → open_ports under target
        pp_match = _PORT_PROTO_RE.match(item_stripped)
        if pp_match:
            port_str = pp_match.group(1)
            if port_str.isdigit():
                port = int(port_str)
                session.open_ports.setdefault(session.target, [])
                if port not in session.open_ports[session.target]:
                    session.open_ports[session.target].append(port)
            continue

        # 6. Looks like a subdomain → subdomains
        # Must have at least one dot, no spaces, no special chars
        clean = item_stripped.split()[0]  # first token only
        if _SUBDOMAIN_RE.match(clean) and len(clean) > 4:
            if clean not in session.subdomains:
                session.subdomains.append(clean)
            continue

        # 7. Anything else: we DON'T store it to avoid false assumptions.
        # It stays in the parsed output for the LLM to see but doesn't
        # pollute structured session data.


def session_to_context(session: SessionData) -> str:
    """Format session data as a context string for injection into conversation."""
    parts = [f"[SYSTEM: PREVIOUS SESSION DATA for {session.target}]"]
    parts.append(f"Session from: {session.created_at}")
    parts.append(f"Tools previously run: {', '.join(session.tools_run) if session.tools_run else 'none'}")
    parts.append(f"Total scans: {session.scan_count}")

    if session.subdomains:
        count = len(session.subdomains)
        preview = ", ".join(session.subdomains[:10])
        parts.append(f"Subdomains found: {count} — {preview}" + (f" ... +{count-10} more" if count > 10 else ""))

    if session.live_hosts:
        count = len(session.live_hosts)
        preview = ", ".join(session.live_hosts[:10])
        parts.append(f"Live hosts: {count} — {preview}" + (f" ... +{count-10} more" if count > 10 else ""))

    if session.open_ports:
        total_ports = sum(len(p) for p in session.open_ports.values())
        port_preview = []
        for host, ports in list(session.open_ports.items())[:5]:
            port_preview.append(f"{host}: {','.join(str(p) for p in sorted(ports)[:10])}")
        parts.append(f"Open ports: {total_ports} total — " + "; ".join(port_preview))

    if session.urls:
        parts.append(f"URLs collected: {len(session.urls)}")

    if session.vulnerabilities:
        parts.append(f"Vulnerabilities found: {len(session.vulnerabilities)}")
        for v in session.vulnerabilities[:5]:
            parts.append(f"  - {v.get('finding', '?')}")

    if session.completed_phases:
        parts.append(f"Completed phases: {', '.join(session.completed_phases)}")

    parts.append("Use this data to RESUME work — do NOT re-run scans that already have results above.")
    return "\n".join(parts)

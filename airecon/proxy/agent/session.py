"""Session persistence — save/load findings per session across runs.

Sessions are identified by a unique ID (unix_timestamp_randomhex), not by target name.
Each `airecon start` creates a new session. Use `airecon start --session <id>` to resume.

Storage: ~/.airecon/sessions/<session_id>.json
"""

from __future__ import annotations

import json
import logging
import re
import time
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from .output_parser import ParsedOutput

logger = logging.getLogger("airecon.agent.session")

SESSIONS_DIR = Path.home() / ".airecon" / "sessions"

# Similarity threshold for vulnerability deduplication (0-1)
VULN_SIMILARITY_THRESHOLD = 0.7


def generate_session_id() -> str:
    """Generate a unique session ID: <unix_timestamp>_<8_random_hex>.

    Example: 1740842400_a3b4c5d6
    """
    return f"{int(time.time())}_{uuid.uuid4().hex[:8]}"


def _normalize_url(url: str) -> str:
    """Normalize a URL for deduplication.

    - Lowercase scheme and host
    - Sort query parameters alphabetically
    - Strip URL fragment (#...)
    - Strip trailing slash from path (except root "/")

    Returns the original string unchanged if parsing fails.
    """
    try:
        p = urlparse(url)
        query = urlencode(sorted(parse_qsl(p.query, keep_blank_values=True)))
        return urlunparse((
            p.scheme.lower(),
            p.netloc.lower(),
            p.path.rstrip("/") or "/",
            p.params,
            query,
            "",  # strip fragment
        ))
    except Exception:
        return url


def _calculate_similarity(v1: str, v2: str) -> float:
    """Calculate similarity between two vulnerability strings using simple approach."""
    v1_lower = v1.lower()
    v2_lower = v2.lower()

    if v1_lower == v2_lower:
        return 1.0

    # Extract parameter context to avoid false dedup of diff params
    param_re = re.compile(
        r"(?:[?&]([a-z0-9_\[\]\-]+)=|parameter\s+['\"]?([a-z0-9_\[\]\-]+)['\"]?)")
    m1 = param_re.search(v1_lower)
    m2 = param_re.search(v2_lower)

    if m1 and m2:
        p1 = m1.group(1) or m1.group(2)
        p2 = m2.group(1) or m2.group(2)
        if p1 and p2 and p1 != p2:
            return 0.0  # Different targeted parameters = NOT duplicate

    # Check for common words
    words1 = set(v1_lower.split())
    words2 = set(v2_lower.split())

    if not words1 or not words2:
        return 0.0

    intersection = words1 & words2
    union = words1 | words2

    return len(intersection) / len(union)


def _is_duplicate_vulnerability(
        new_vuln: dict, existing_vulns: list[dict]) -> bool:
    """Check if a vulnerability is a duplicate of an existing one.

    Uses vuln_similarity_threshold from config (default: VULN_SIMILARITY_THRESHOLD).
    """
    try:
        from ..config import get_config
        threshold = get_config().vuln_similarity_threshold
    except Exception:
        threshold = VULN_SIMILARITY_THRESHOLD

    new_finding = new_vuln.get("finding", "")
    new_target = new_vuln.get("target", "")

    for existing in existing_vulns:
        existing_finding = existing.get("finding", "")
        existing_target = existing.get("target", "")

        # Check finding similarity — _calculate_similarity already returns 0.0
        # when the two findings mention different URL parameters, preventing
        # false deduplication of findings on different parameters.
        finding_sim = _calculate_similarity(new_finding, existing_finding)

        # Check target similarity (if both have targets)
        target_sim = 1.0 if new_target == existing_target else 0.0

        # Combined similarity
        combined_sim = (finding_sim * 0.8) + (target_sim * 0.2)

        if combined_sim >= threshold:
            return True

    return False


@dataclass
class SessionData:
    """Persistent per-session state, identified by a unique session_id."""

    # Session identity
    session_id: str = ""
    target: str = ""

    # Findings
    subdomains: list[str] = field(default_factory=list)
    live_hosts: list[str] = field(default_factory=list)
    open_ports: dict[str, list[int]] = field(default_factory=dict)
    urls: list[str] = field(default_factory=list)
    technologies: dict[str, str] = field(default_factory=dict)
    vulnerabilities: list[dict[str, Any]] = field(default_factory=list)
    attack_chains: list[dict[str, Any]] = field(default_factory=list)
    completed_phases: list[str] = field(default_factory=list)
    current_phase: str = "RECON"
    tools_run: list[str] = field(default_factory=list)
    scan_count: int = 0
    created_at: str = ""
    updated_at: str = ""

    # Browser auth state (persisted so re-runs skip re-login)
    auth_cookies: list[dict[str, Any]] = field(default_factory=list)
    auth_tokens: dict[str, str] = field(default_factory=dict)
    auth_type: str = ""  # "form", "totp", "oauth", "cookie"

    def __post_init__(self) -> None:
        if not self.session_id:
            self.session_id = generate_session_id()
        if not self.created_at:
            self.created_at = datetime.now().isoformat()


def load_session(session_id: str) -> SessionData | None:
    """Load a session by its unique ID.

    Returns None if the session file does not exist.
    """
    filepath = SESSIONS_DIR / f"{session_id}.json"
    if not filepath.exists():
        return None

    try:
        with open(filepath, "r") as f:
            data = json.load(f)
        session = SessionData(
            session_id=data.get("session_id", session_id),
            target=data.get("target", ""),
            subdomains=data.get("subdomains", []),
            live_hosts=data.get("live_hosts", []),
            open_ports=data.get("open_ports", {}),
            urls=data.get("urls", []),
            technologies=data.get("technologies", {}),
            vulnerabilities=data.get("vulnerabilities", []),
            attack_chains=data.get("attack_chains", []),
            completed_phases=data.get("completed_phases", []),
            current_phase=data.get("current_phase", "RECON"),
            tools_run=data.get("tools_run", []),
            scan_count=data.get("scan_count", 0),
            created_at=data.get("created_at", ""),
            updated_at=data.get("updated_at", ""),
            auth_cookies=data.get("auth_cookies", []),
            auth_tokens=data.get("auth_tokens", {}),
            auth_type=data.get("auth_type", ""),
        )
        logger.info(
            f"Loaded session {session_id} (target={session.target}): "
            f"{len(session.subdomains)} subs, {len(session.live_hosts)} live, "
            f"{len(session.vulnerabilities)} vulns"
        )
        return session
    except Exception as e:
        logger.warning(f"Failed to load session {session_id}: {e}")
        return None


def save_session(session: SessionData) -> None:
    """Save session data to disk using session_id as filename."""
    try:
        SESSIONS_DIR.mkdir(parents=True, exist_ok=True)
        filepath = SESSIONS_DIR / f"{session.session_id}.json"
        with open(filepath, "w") as f:
            json.dump(asdict(session), f, indent=2, default=str)
        logger.info(
            f"Saved session {session.session_id} (target={session.target})"
        )
    except Exception as e:
        logger.error(f"Failed to save session {session.session_id}: {e}")


def list_sessions() -> list[dict]:
    """Return a list of all saved sessions, sorted by most recently updated first.

    Each entry contains summary information (not the full data).
    """
    sessions: list[dict] = []
    if not SESSIONS_DIR.exists():
        return sessions

    for path in SESSIONS_DIR.glob("*.json"):
        try:
            with open(path, "r") as f:
                data = json.load(f)
            sessions.append({
                "session_id": data.get("session_id", path.stem),
                "target": data.get("target", ""),
                "created_at": data.get("created_at", ""),
                "scan_count": data.get("scan_count", 0),
                "subdomains": len(data.get("subdomains", [])),
                "live_hosts": len(data.get("live_hosts", [])),
                "vulnerabilities": len(data.get("vulnerabilities", [])),
            })
        except Exception as _e:
            logger.debug("Could not load session metadata: %s", _e)

    sessions.sort(key=lambda s: s["created_at"], reverse=True)
    return sessions


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

    # Track which tools have been run (use actual binary name)
    tool_key = parsed.tool
    if tool_key and tool_key not in session.tools_run:
        session.tools_run.append(tool_key)

    # Merge technologies from tool output (whatweb, httpx -tech-detect)
    if parsed.technologies:
        for name, version in parsed.technologies.items():
            if name and name not in session.technologies:
                session.technologies[name] = version
            elif name and version and not session.technologies.get(name):
                # Upgrade an empty-version entry when a version is now
                # available
                session.technologies[name] = version

    if not parsed.items:
        return

    # Classify each item by its content pattern
    _SUBDOMAIN_RE = re.compile(
        r"^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)+$"
    )
    _URL_RE = re.compile(r"^https?://")
    _HOST_PORT_RE = re.compile(r"^([a-zA-Z0-9.\-]+):(\d+)")
    _PORT_PROTO_RE = re.compile(r"^(\d+)/(tcp|udp)\s+(open|filtered)")
    _SEVERITY_RE = re.compile(
        r"^\[(CRITICAL|HIGH|MEDIUM|LOW|INFO)\]",
        re.IGNORECASE)
    _HTTP_STATUS_RE = re.compile(r"https?://\S+\s+\[(\d{3})\]")

    for item in parsed.items:
        item_stripped = item.strip()
        if not item_stripped:
            continue

        # 1. Severity-tagged finding → vulnerability
        if _SEVERITY_RE.match(item_stripped):
            new_vuln = {
                "finding": item_stripped,
                "source": tool_key,
                "timestamp": datetime.now().isoformat(),
            }
            # Check for duplicates before adding
            if not _is_duplicate_vulnerability(
                    new_vuln, session.vulnerabilities):
                session.vulnerabilities.append(new_vuln)
            continue

        # 2. URL with status code (httpx-style) → live_hosts
        status_match = _HTTP_STATUS_RE.match(item_stripped)
        if status_match:
            url = _normalize_url(item_stripped.split(" [")[0].strip())
            if url and url not in session.live_hosts:
                session.live_hosts.append(url)
            continue

        # 3. Plain URL → urls collection
        if _URL_RE.match(item_stripped):
            url = _normalize_url(item_stripped.split()[0])
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
    target_label = session.target or "unknown target"
    parts = [
        f"[SYSTEM: PREVIOUS SESSION DATA — Session {
            session.session_id} for {target_label}]"]
    parts.append(f"Session created: {session.created_at}")
    parts.append(
        f"Tools previously run: {
            ', '.join(
                session.tools_run) if session.tools_run else 'none'}"
    )
    parts.append(f"Total scans: {session.scan_count}")

    if session.subdomains:
        count = len(session.subdomains)
        preview = ", ".join(session.subdomains[:10])
        parts.append(
            f"Subdomains found: {count} — {preview}"
            + (f" ... +{count - 10} more" if count > 10 else "")
        )

    if session.live_hosts:
        count = len(session.live_hosts)
        preview = ", ".join(session.live_hosts[:10])
        parts.append(
            f"Live hosts: {count} — {preview}"
            + (f" ... +{count - 10} more" if count > 10 else "")
        )

    if session.open_ports:
        total_ports = sum(len(p) for p in session.open_ports.values())
        port_preview = []
        for host, ports in list(session.open_ports.items())[:5]:
            port_preview.append(
                f"{host}: {','.join(str(p) for p in sorted(ports)[:10])}"
            )
        parts.append(
            f"Open ports: {total_ports} total — " +
            "; ".join(port_preview))

    if session.urls:
        parts.append(f"URLs collected: {len(session.urls)}")

    if session.technologies:
        count = len(session.technologies)
        # Format as "Name/version" where version is known, else just "Name"
        tech_parts = [
            f"{name}/{ver}" if ver else name
            for name, ver in list(session.technologies.items())[:15]
        ]
        parts.append(
            f"Technologies fingerprinted: {count} — {', '.join(tech_parts)}"
            + (f" ... +{count - 15} more" if count > 15 else "")
        )

    if session.vulnerabilities:
        parts.append(f"Vulnerabilities found: {len(session.vulnerabilities)}")
        for v in session.vulnerabilities[:5]:
            flag_info = f" (FLAG: {v.get('flag')})" if v.get("flag") else ""
            parts.append(f"  - {v.get('finding', '?')}{flag_info}")

    if session.attack_chains:
        parts.append(f"Attack chains identified: {len(session.attack_chains)}")
        for chain in session.attack_chains[:3]:
            parts.append(f"  - Chain: {' -> '.join(chain.get('steps', []))}")

    if session.completed_phases:
        parts.append(
            f"Completed phases: {
                ', '.join(
                    session.completed_phases)}")

    if session.auth_cookies or session.auth_tokens:
        auth_info = f"Auth state: {session.auth_type or 'unknown'} — "
        if session.auth_cookies:
            auth_info += f"{len(session.auth_cookies)} cookies captured"
        if session.auth_tokens:
            auth_info += f", tokens: {', '.join(session.auth_tokens.keys())}"
        parts.append(
            auth_info +
            " (use inject_cookies action to restore session)")

    parts.append(
        "Use this data to RESUME work — do NOT re-run scans that already have results above."
    )
    return "\n".join(parts)

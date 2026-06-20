from __future__ import annotations

import json
import logging
import re
import time
from pathlib import Path
from typing import Any

from .config import APP_DIR_NAME, get_config

logger = logging.getLogger("airecon.scope")

_URL_HOST_RE = re.compile(r"https?://([^/\s:\"'`]+)", re.IGNORECASE)
_BARE_HOST_RE = re.compile(
    r"\b((?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}|(?:\d{1,3}\.){3}\d{1,3})\b",
    re.IGNORECASE,
)


def extract_hosts(text: str) -> list[str]:
    """Best-effort extraction of target hosts from a command/URL string."""
    if not text:
        return []
    hosts: set[str] = set()
    for m in _URL_HOST_RE.finditer(text):
        hosts.add(m.group(1).split(":", 1)[0].lower())
    for m in _BARE_HOST_RE.finditer(text):
        hosts.add(m.group(1).split(":", 1)[0].lower())
    return sorted(hosts)


def host_matches(host: str, pattern: str) -> bool:
    """Pattern match: 'example.com' matches the apex and any subdomain;
    '*.example.com' matches subdomains only; otherwise exact match."""
    host = (host or "").strip().lower().rstrip(".")
    pattern = (pattern or "").strip().lower().rstrip(".")
    if not host or not pattern:
        return False
    if pattern.startswith("*."):
        base = pattern[2:]
        return host.endswith("." + base)
    return host == pattern or host.endswith("." + pattern)


class ScopeGuard:
    def __init__(self, allowlist: list[str], denylist: list[str], mode: str) -> None:
        self.allow = [p for p in allowlist if p]
        self.deny = [p for p in denylist if p]
        self.mode = (mode or "warn").strip().lower()

    @property
    def enabled(self) -> bool:
        return self.mode in ("warn", "block")

    def check_host(self, host: str) -> tuple[bool, str]:
        for p in self.deny:
            if host_matches(host, p):
                return False, f"host '{host}' matches denylist entry '{p}'"
        if self.allow:
            if not any(host_matches(host, p) for p in self.allow):
                return False, f"host '{host}' is not in the scope allowlist"
        return True, ""

    def check_command(self, text: str) -> tuple[bool, str, str]:
        """Return (allowed, reason, offending_host) for a command/URL string."""
        if not self.enabled:
            return True, "", ""
        for host in extract_hosts(text):
            ok, reason = self.check_host(host)
            if not ok:
                return False, reason, host
        return True, "", ""


def get_scope_guard() -> ScopeGuard:
    cfg = get_config()

    def _split(val: Any) -> list[str]:
        return [s.strip() for s in str(val or "").split(",") if s.strip()]

    return ScopeGuard(
        allowlist=_split(getattr(cfg, "scope_allowlist", "")),
        denylist=_split(getattr(cfg, "scope_denylist", "")),
        mode=str(getattr(cfg, "scope_enforcement", "warn") or "warn"),
    )


def _audit_path() -> Path:
    return Path.home() / APP_DIR_NAME / "audit" / "audit.jsonl"


def audit_log(event: dict[str, Any]) -> None:
    """Append an event to the persistent JSONL audit log (best-effort)."""
    try:
        if not bool(getattr(get_config(), "audit_log_enabled", True)):
            return
        path = _audit_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        record = {"ts": round(time.time(), 3), **event}
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")
    except Exception as e:  # never let auditing break the agent
        logger.debug("audit log write failed: %s", e)

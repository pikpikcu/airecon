from __future__ import annotations

import json
import logging
import re
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .config import APP_DIR_NAME, get_config

logger = logging.getLogger("airecon.scope")

_URL_HOST_RE = re.compile(r"https?://([^/\s:\"'`]+)", re.IGNORECASE)
_BARE_HOST_RE = re.compile(
    r"\b((?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}|(?:\d{1,3}\.){3}\d{1,3})\b",
    re.IGNORECASE,
)


def extract_hosts(text: str) -> list[str]:
    if not text:
        return []
    hosts: set[str] = set()
    for m in _URL_HOST_RE.finditer(text):
        hosts.add(m.group(1).split(":", 1)[0].lower())
    for m in _BARE_HOST_RE.finditer(text):
        hosts.add(m.group(1).split(":", 1)[0].lower())
    return sorted(hosts)


def host_matches(host: str, pattern: str) -> bool:
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
        if not self.enabled:
            return True, "", ""
        for host in extract_hosts(text):
            ok, reason = self.check_host(host)
            if not ok:
                return False, reason, host
        return True, "", ""

    def check_tool(self, tool_name: str, arguments: dict[str, Any]) -> tuple[bool, str, str]:
        if not self.enabled:
            return True, "", ""
        # Check destinations, not notes, payloads, or search queries.
        fields = {
            "schemathesis_fuzz": ("schema_url", "base_url"),
            "http_observe": ("url",),
            "browser_action": ("url",),
            "advanced_fuzz": ("target", "auth_login_url", "graphql_endpoints"),
            "quick_fuzz": ("target",),
            "deep_fuzz": ("target", "auth_login_url", "graphql_endpoints"),
            "caido_send_request": ("host",),
            "caido_automate": ("host",),
            "spawn_agent": ("target",),
            "run_parallel_agents": ("targets",),
        }.get(tool_name, ())
        for field in fields:
            value = arguments.get(field, "")
            for destination in value if isinstance(value, list) else [value]:
                if not isinstance(destination, str) or not destination.strip():
                    continue
                destination = destination.strip()
                if field == "schema_url" and not destination.lower().startswith(("http://", "https://")):
                    continue  # Local schema file, not a host.
                try:
                    host = urlsplit(destination if "://" in destination else "//" + destination).hostname
                except ValueError:
                    return False, "invalid network destination", ""
                if host:
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


def check_network_tool_scope(tool_name: str, arguments: dict[str, Any]) -> str | None:
    guard = get_scope_guard()
    ok, reason, host = guard.check_tool(tool_name, arguments)
    if not ok:
        audit_log({"type": tool_name, "host": host, "in_scope": False,
                   "reason": reason, "mode": guard.mode})
        if guard.mode == "block":
            return f"Tool blocked by scope guard: {reason}."
        logger.warning("Scope advisory (%s): %s", tool_name, reason)
    return None


def _audit_path() -> Path:
    return Path.home() / APP_DIR_NAME / "audit" / "audit.jsonl"


def audit_log(event: dict[str, Any]) -> None:
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

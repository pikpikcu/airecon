from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

from .models import ToolExecution
from .output_parser import ParsedOutput

logger = logging.getLogger("airecon.agent")

FINDING_FORMAT = "Param: {p} | Vuln: {v} | Severity: {s} | Conf: {c:.2f} | Evidence: {e}"
NO_VULNS_FOUND = "No vulnerabilities found with confidence > 0.60."

MAX_RAW_FALLBACK = 3000


def _safe_non_negative_int(value: Any, default: int = 0) -> int:
    try:
        v = int(value)
        return v if v >= 0 else default
    except (TypeError, ValueError):
        return default


def as_bool(value: Any, default: bool = True) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "y", "on"}
    return default


def as_str_list(value: Any) -> list[str] | None:
    if not isinstance(value, list):
        return None
    cleaned = [str(v).strip() for v in value if str(v).strip()]
    return cleaned or None


def format_finding(r: Any) -> str:
    return FINDING_FORMAT.format(
        p=r.parameter, v=r.vuln_type, s=r.severity,
        c=r.confidence, e=r.evidence,
    )


def safe_save_tool_output(self, tool_name: str, arguments: dict[str, Any], res_dict: dict[str, Any]) -> None:
    try:
        self._save_tool_output(tool_name, arguments, res_dict)
    except Exception as _e:
        logger.debug("Could not save tool output: %s", _e)


def record_tool_completion(
    self,
    tool_name: str,
    arguments: dict[str, Any],
    result: dict[str, Any],
    duration: float,
    success: bool,
) -> tuple[bool, float, dict[str, Any], str | None]:
    self.state.tool_history.append(
        ToolExecution(
            tool_name=tool_name,
            arguments=arguments,
            result=result,
            duration=duration,
            status="success" if success else "error",
        )
    )
    self.state.tool_counts["total"] += 1
    return success, duration, result, None


def tool_finish(
    self,
    tool_name: str,
    arguments: dict[str, Any],
    result: dict[str, Any],
    start_time: float,
    success: bool,
    output_file: str | None = None,
) -> tuple[bool, float, dict[str, Any], str | None]:
    duration = time.time() - start_time
    safe_save_tool_output(self, tool_name, arguments, result)
    return record_tool_completion(self, tool_name, arguments, result, duration, success)


def deduplicate(items: list[str]) -> list[str]:
    seen: set[str] = set()
    return [item for item in items if item not in seen and not seen.add(item)]


def empty_parsed_output(
    tool_name: str,
    summary: str = "",
    raw_truncated: str = "",
) -> ParsedOutput:
    return ParsedOutput(
        tool=tool_name,
        summary=summary or f"{tool_name} complete -- 0 results",
        total_count=0,
        raw_truncated=raw_truncated[:MAX_RAW_FALLBACK],
    )


async def async_sleep_backoff(attempt: int, base: float = 2.0, max_wait: float = 120.0) -> float:
    wait = min(base ** (attempt + 1), max_wait)
    await asyncio.sleep(wait)
    return wait


def sync_backoff(attempt: int, base: float = 2.0, max_wait: float = 120.0) -> float:
    return min(base ** (attempt + 1), max_wait)


def cfg_typed(cfg: Any, key: str, default: Any, converter: type) -> Any:
    try:
        val = getattr(cfg, key, default)
        if isinstance(val, converter):
            return val
        if isinstance(val, str):
            return converter(val) if val else default
        return converter(val)
    except Exception as _e:
        return default


def is_host_in_scope(target_url: str, session_target: str) -> bool:
    if not session_target or not target_url:
        return True
    try:
        from urllib.parse import urlparse
        target_host = urlparse(target_url).hostname or ""
        if "://" in session_target:
            scope_host = urlparse(session_target).hostname or ""
        else:
            scope_host = session_target.split(":")[0].split("/")[0].lower()
        if not scope_host or not target_host:
            return True
        target_host = target_host.lower()
        scope_host = scope_host.lower()
        return target_host == scope_host or target_host.endswith("." + scope_host)
    except Exception as _e:
        return True


def extract_domain_from_url(url: str) -> str:
    try:
        from urllib.parse import urlparse
        return urlparse(url).hostname or ""
    except Exception as _e:
        return ""

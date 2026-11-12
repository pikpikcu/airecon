from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger("airecon.agent")

_TOOLS_META_CACHE: dict[str, dict[str, Any]] = {}


def _load_specialist_prefixes() -> dict[str, str]:
    try:
        path = Path(__file__).resolve().parent.parent / "data" / "tools_meta.json"
        return json.loads(path.read_text(encoding="utf-8")).get("specialist_prompts", {})
    except Exception as exc:
        logger.warning("Could not load specialist_prompts from tools_meta.json: %s", exc)
        return {}


_SPECIALIST_PREFIXES: dict[str, str] = _load_specialist_prefixes()

_RESULT_TRUNCATION_THRESHOLD = 10000
_READ_FILE_CONTENT_TRUNCATION_THRESHOLD = 2000
_MAX_COMMAND_LENGTH = 20_000

def _safe_non_negative_int(value: Any) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return 0
    return parsed if parsed >= 0 else 0


def _load_recon_bins(category: str) -> frozenset[str]:
    try:
        path = Path(__file__).resolve().parent.parent / "data" / "tools_meta.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        bins = (
            data.get("categories", {})
            .get("reconnaissance", {})
            .get(category, [])
        )
        return frozenset(str(x).strip().lower() for x in bins if str(x).strip())
    except Exception as exc:
        logger.warning(
            "Could not load recon bins (category=%r) from tools_meta.json: %s — "
            "returning empty set. Check that data/tools_meta.json exists.",
            category,
            exc,
        )
        return frozenset()


_RECON_SUBDOMAIN_BINS: frozenset[str] = _load_recon_bins("subdomain_enum")

_RECON_PORT_SCAN_BINS: frozenset[str] = _load_recon_bins("port_scan")

_RECON_LIVE_HOST_BINS: frozenset[str] = _load_recon_bins("live_host_probe")

_RECON_CONTENT_DISCOVERY_BINS: frozenset[str] = (
    _load_recon_bins("crawling")
    | _load_recon_bins("directory_bruteforce")
)


def _load_airecon_tool_names() -> frozenset[str]:
    try:
        path = Path(__file__).resolve().parent.parent / "data" / "tools.json"
        data = json.loads(path.read_text(encoding="utf-8"))

        return frozenset(
            str(t["function"]["name"])
            for t in data
            if isinstance(t, dict) and isinstance(t.get("function"), dict) and t["function"].get("name")
        )
    except Exception as exc:
        logger.warning("Could not load tool names from tools.json: %s", exc)
        return frozenset()


_AIRECON_TOOL_NAMES: frozenset[str] = (
    _load_airecon_tool_names() - {"execute"}
)


def _load_tool_flag_conflicts() -> dict[str, tuple[list[str], str]]:
    cache_key = "tool_flag_conflicts"
    if cache_key in _TOOLS_META_CACHE:
        return _TOOLS_META_CACHE[cache_key]

    try:
        path = Path(__file__).resolve().parent.parent / "data" / "tools_meta.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        raw = data.get("tool_flag_conflicts", {})
        result = {
            tool: (entry["flags"], entry["correct_tool"])
            for tool, entry in raw.items()
            if isinstance(entry.get("flags"), list) and entry.get("correct_tool")
        }
        _TOOLS_META_CACHE[cache_key] = result
        return result
    except Exception as exc:
        logger.warning(
            "Could not load tool_flag_conflicts from tools_meta.json: %s — "
            "flag conflict detection disabled. Check that data/tools_meta.json exists.",
            exc,
        )
        _TOOLS_META_CACHE[cache_key] = {}
        return {}


_TOOL_FLAG_CONFLICTS: dict[str, tuple[list[str], str]] = _load_tool_flag_conflicts()

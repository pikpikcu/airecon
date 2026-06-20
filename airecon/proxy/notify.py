from __future__ import annotations

import json
import logging
import re
import time
from typing import Any

from .config import get_config, get_workspace_root

logger = logging.getLogger("airecon.notify")


def _sanitize(name: str) -> str:
    safe = re.sub(r"[^a-zA-Z0-9._-]+", "_", str(name or "")).strip("._-")
    return safe or "unknown_target"


async def notify_completion(target: str, summary: dict[str, Any]) -> None:
    cfg = get_config()
    payload = {
        "event": "airecon.scan.complete",
        "target": target,
        "ts": round(time.time(), 3),
        **summary,
    }

    url = str(getattr(cfg, "notify_webhook_url", "") or "").strip()
    if url:
        try:
            import httpx

            async with httpx.AsyncClient(timeout=5.0) as client:
                await client.post(url, json=payload)
            logger.info("Completion webhook posted for target=%s", target)
        except Exception as e:
            logger.debug("completion webhook failed: %s", e)

    if bool(getattr(cfg, "notify_completion_flag", True)):
        try:
            target_dir = get_workspace_root() / _sanitize(target)
            target_dir.mkdir(parents=True, exist_ok=True)
            (target_dir / "COMPLETE.json").write_text(
                json.dumps(payload, indent=2, default=str), encoding="utf-8"
            )
        except Exception as e:
            logger.debug("completion flag write failed: %s", e)

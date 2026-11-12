from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Any

logger = logging.getLogger("airecon.agent.session_persistence")
_VERSION = "1.0.0"

class SessionPersistenceEngine:
    def __init__(self, workspace_root: str | Path | None = None):
        self.workspace_root = Path(workspace_root) if workspace_root else None

    def _get_session_dir(self, target: str) -> Path:
        if not self.workspace_root:
            raise ValueError("workspace_root not set")
        safe_name = target.replace("://", "_").replace("/", "_").replace(":", "_")
        session_dir = self.workspace_root / safe_name
        session_dir.mkdir(parents=True, exist_ok=True)
        return session_dir

    def _save_json(self, target: str, filename: str, payload: Any) -> Path:
        session_dir = self._get_session_dir(target)
        fpath = session_dir / filename
        data = {"version": _VERSION, "saved_at": time.time(), "target": target, "payload": payload}
        fpath.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
        return fpath

    def _load_json(self, target: str, filename: str) -> Any | None:
        try:
            session_dir = self._get_session_dir(target)
            fpath = session_dir / filename
            if not fpath.exists():
                return None
            data = json.loads(fpath.read_text(encoding="utf-8"))
            if data.get("version") != _VERSION:
                return None
            return data.get("payload")
        except Exception as e:
            logger.debug("Failed to load %s for %s: %s", filename, target, e)
            return None

    def save_session_state(self, target: str, state: dict[str, Any]) -> Path:
        logger.info("Session state saved for %s", target)
        return self._save_json(target, "session_state.json", state)

    def load_session_state(self, target: str) -> dict[str, Any] | None:
        result = self._load_json(target, "session_state.json")
        if result is not None:
            logger.info("Session state loaded for %s", target)
        return result

    def save_payload_memory(self, target: str, records: list[dict[str, Any]]) -> Path:
        return self._save_json(target, "payload_memory.json", records)

    def load_payload_memory(self, target: str) -> list[dict[str, Any]]:
        result = self._load_json(target, "payload_memory.json")
        return result if isinstance(result, list) else []

    def save_adaptive_state(self, target: str, state: dict[str, Any]) -> Path:
        return self._save_json(target, "adaptive_state.json", state)

    def load_adaptive_state(self, target: str) -> dict[str, Any] | None:
        return self._load_json(target, "adaptive_state.json")

from __future__ import annotations

import json
import logging
import re
import secrets
import time
from datetime import datetime
from pathlib import Path
from typing import Any

from ..config import get_workspace_root

logger = logging.getLogger("airecon.agent")

_PYTHON_SESSION_DISABLED_ERROR = (
    "python_session has been removed: it executed model-generated Python on the "
    "proxy host via in-process exec/eval. Use the execute tool to run Python "
    "INSIDE the Docker target sandbox instead (e.g. execute a 'python3 -' "
    "heredoc command). No persistent Python REPL is offered."
)


# === Notes System ===


class _NotesManager:
    def __init__(self, storage_dir: Path):
        self.storage_dir = storage_dir
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        self.notes_index: dict[str, dict] = {}
        self._load_index()

    def _load_index(self):
        index_file = self.storage_dir / "notes_index.json"
        if index_file.exists():
            try:
                self.notes_index = json.loads(index_file.read_text(encoding="utf-8"))
            except Exception as _e:
                self.notes_index = {}

    def _save_index(self):
        index_file = self.storage_dir / "notes_index.json"
        index_file.write_text(json.dumps(self.notes_index, indent=2), encoding="utf-8")

    def create(
        self,
        category: str,
        title: str,
        content: str,
        tags: list[str] | None = None,
    ) -> dict[str, Any]:
        note_id = (
            f"note_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{secrets.token_hex(4)}"
        )
        note = {
            "id": note_id,
            "category": category,
            "title": title,
            "content": content,
            "tags": tags or [],
            "created_at": datetime.now().isoformat(),
            "updated_at": datetime.now().isoformat(),
        }
        self.notes_index[note_id] = note
        self._save_index()
        # Also write individual markdown file for wiki export
        note_file = self.storage_dir / f"{note_id}.md"
        note_file.write_text(self._to_markdown(note), encoding="utf-8")
        return {
            "success": True,
            "message": (
                "Working note saved. This is session documentation only, "
                "not a final vulnerability report."
            ),
            "artifact_type": "working_note",
            "report_generated": False,
            "note_id": note_id,
            "note_path": str(note_file),
            "note": note,
        }

    def _to_markdown(self, note: dict) -> str:
        return f"""# {note["title"]}

**Category:** {note["category"]}
**Created:** {note["created_at"]}
**Tags:** {note.get("tags", [])}

{note["content"]}
"""

    def list_notes(
        self,
        category: str | None = None,
        tag: str | None = None,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        notes = list(self.notes_index.values())
        if category:
            notes = [n for n in notes if str(n.get("category", "")) == str(category)]
        if tag:
            wanted = str(tag).strip().lower()
            notes = [
                n
                for n in notes
                if wanted in {str(t).strip().lower() for t in n.get("tags", [])}
            ]
        notes.sort(
            key=lambda n: (
                str(n.get("updated_at", "")),
                str(n.get("created_at", "")),
                str(n.get("id", "")),
            ),
            reverse=True,
        )
        return [
            {
                "id": n.get("id", ""),
                "title": n.get("title", ""),
                "category": n.get("category", ""),
                "tags": list(n.get("tags", []) or []),
                "created_at": n.get("created_at", ""),
                "updated_at": n.get("updated_at", ""),
            }
            for n in notes[: max(1, int(limit))]
        ]

    def search(
        self,
        query: str,
        category: str | None = None,
        limit: int = 20,
    ) -> list[dict[str, Any]]:
        needle = str(query or "").strip().lower()
        if not needle:
            return []

        notes = list(self.notes_index.values())
        if category:
            notes = [n for n in notes if str(n.get("category", "")) == str(category)]

        matches: list[dict[str, Any]] = []
        for note in notes:
            haystack = "\n".join(
                [
                    str(note.get("title", "")),
                    str(note.get("content", "")),
                    str(note.get("category", "")),
                    " ".join(str(t) for t in note.get("tags", []) or []),
                ]
            ).lower()
            if needle not in haystack:
                continue
            matches.append(note)

        matches.sort(
            key=lambda n: (
                str(n.get("updated_at", "")),
                str(n.get("created_at", "")),
                str(n.get("id", "")),
            ),
            reverse=True,
        )
        return matches[: max(1, int(limit))]

    def get(self, note_id: str) -> dict[str, Any] | None:
        return self.notes_index.get(str(note_id or "").strip())

    def export_wiki(self, output_path: Path) -> dict[str, Any]:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        notes = list(self.notes_index.values())
        notes.sort(
            key=lambda n: (
                str(n.get("category", "")),
                str(n.get("created_at", "")),
                str(n.get("id", "")),
            )
        )

        sections = ["# Notes Wiki", ""]
        current_category = None
        for note in notes:
            category = str(note.get("category", "uncategorized"))
            if category != current_category:
                current_category = category
                sections.append(f"## {category.title()}")
                sections.append("")
            sections.append(self._to_markdown(note).rstrip())
            sections.append("")

        output_path.write_text("\n".join(sections).strip() + "\n", encoding="utf-8")
        return {
            "success": True,
            "path": str(output_path),
            "count": len(notes),
        }


class _UtilsExecutorMixin:
    def __init__(self) -> None:
        super().__init__()  # Ensure parent init
        self._ensure_utils_runtime_state()

    def _get_notes_storage_dir(self) -> Path | None:
        ws_root = get_workspace_root()
        target = ""

        state = getattr(self, "state", None)
        if state is not None:
            target = str(getattr(state, "active_target", "") or "").strip()

        if not target:
            session = getattr(self, "_session", None)
            if session is not None:
                target = str(getattr(session, "target", "") or "").strip()

        target = target.strip().strip("/")
        if not target:
            return None
        return ws_root / target / "notes"

    def _notes_manager_unavailable_result(self) -> dict[str, Any]:
        return {
            "success": False,
            "error": (
                "Notes require an active target. Start or switch to a target first "
                "so notes are stored under workspace/<target>/notes."
            ),
        }

    def _ensure_utils_runtime_state(self) -> None:
        if not hasattr(self, "_python_sessions") or not isinstance(
            self._python_sessions, dict
        ):
            self._python_sessions = {}
        if not hasattr(self, "_python_session_timeout") or not isinstance(
            self._python_session_timeout, (int, float)
        ):
            self._python_session_timeout = 300
        if not hasattr(self, "_thoughts_log") or not isinstance(
            self._thoughts_log, list
        ):
            self._thoughts_log = []
        try:
            notes_dir = self._get_notes_storage_dir()
            current_dir = getattr(self, "_notes_manager_dir", None)
            if notes_dir is None:
                self._notes_manager = None
                self._notes_manager_dir = None
            elif (
                not hasattr(self, "_notes_manager")
                or self._notes_manager is None
                or current_dir != notes_dir
            ):
                self._notes_manager = _NotesManager(notes_dir)
                self._notes_manager_dir = notes_dir
        except Exception as exc:
            logger.debug("Utility notes manager init failed: %s", exc)
            self._notes_manager = None
            self._notes_manager_dir = None

    # === Python Session (removed: fail-closed) ===
    # The legacy implementation ran model-generated Python via in-process
    # exec()/eval() on the proxy host — arbitrary host filesystem, subprocess
    # and network access with no sandbox. The execution machinery has been
    # deleted; this handler remains only so persisted/attempted old calls are
    # rejected with a structured error BEFORE any code execution or
    # utility-state side effect. There is deliberately no config switch that
    # re-enables host execution; run Python via the `execute` tool inside the
    # Docker target sandbox instead. No persistent Python REPL is offered.
    async def _execute_python_session_tool(
        self, tool_name: str, arguments: dict[str, Any]
    ) -> tuple[bool, float, dict[str, Any], str | None]:
        start_time = time.time()
        session_id = arguments.get("session_id", "default")
        return (
            False,
            time.time() - start_time,
            {
                "success": False,
                "error": _PYTHON_SESSION_DISABLED_ERROR,
                "session_id": session_id,
                "session_state": {},
            },
            None,
        )

    # === Edit File ===
    async def _execute_edit_file_tool(
        self, tool_name: str, arguments: dict[str, Any]
    ) -> tuple[bool, float, dict[str, Any], str | None]:
        start_time = time.time()
        path = arguments.get("path", "")
        old_str = arguments.get("old_str", "")
        new_str = arguments.get("new_str", "")

        if not path or old_str is None or new_str is None:
            return (
                False,
                0.0,
                {"success": False, "error": "path, old_str, new_str are required"},
                None,
            )

        # Resolve path
        ws_root = get_workspace_root()
        file_path = (ws_root / path).resolve()
        try:
            file_path.relative_to(ws_root.resolve())
        except ValueError:
            return (
                False,
                0.0,
                {"success": False, "error": "Path outside workspace"},
                None,
            )

        if not file_path.exists():
            return (
                False,
                0.0,
                {"success": False, "error": f"File not found: {path}"},
                None,
            )

        try:
            content = file_path.read_text(encoding="utf-8")
        except Exception as e:
            return False, 0.0, {"success": False, "error": f"Failed to read: {e}"}, None

        if old_str not in content:
            return (
                False,
                0.0,
                {
                    "success": False,
                    "error": "old_str not found in file (exact match required)",
                },
                None,
            )

        # Count occurrences
        count = content.count(old_str)
        if count > 1:
            # Replace only first occurrence to be surgical
            new_content = content.replace(old_str, new_str, 1)
        else:
            new_content = content.replace(old_str, new_str)

        try:
            file_path.write_text(new_content, encoding="utf-8")
            return (
                True,
                time.time() - start_time,
                {
                    "success": True,
                    "path": path,
                    "lines_modified": 1,
                    "total_occurrences": count,
                    "preview": f"Replaced first occurrence of {len(old_str)} chars with {len(new_str)} chars",
                },
                None,
            )
        except Exception as e:
            return (
                False,
                time.time() - start_time,
                {"success": False, "error": f"Failed to write: {e}"},
                None,
            )

    # === Think ===
    async def _execute_think_tool(
        self, tool_name: str, arguments: dict[str, Any]
    ) -> tuple[bool, float, dict[str, Any], str | None]:
        start_time = time.time()
        thought = arguments.get("thought", "").strip()
        category = arguments.get("category", "observation")
        confidence = arguments.get("confidence")

        if not thought:
            return False, 0.0, {"success": False, "error": "thought is required"}, None

        self._ensure_utils_runtime_state()
        entry = {
            "timestamp": datetime.now().isoformat(),
            "thought": thought,
            "category": category,
        }
        if confidence is not None:
            try:
                entry["confidence"] = float(confidence)
            except Exception as _e:
                entry["confidence"] = None

        self._thoughts_log.append(entry)

        # Also write to log file
        try:
            ws_root = get_workspace_root()
            phase = "unknown"
            if hasattr(self, "_get_current_phase"):
                try:
                    phase = self._get_current_phase().value
                except Exception as _e:
                    logger.debug("Failed to read current phase for thoughts log: %s", _e)
            log_file = ws_root / "output" / f"thoughts_{phase}.log"
            log_file.parent.mkdir(parents=True, exist_ok=True)
            with open(log_file, "a", encoding="utf-8") as f:
                f.write(f"[{entry['timestamp']}] [{category.upper()}] {thought}\n")
        except Exception as e:
            logger.debug("Failed to write thoughts log: %s", e)

        return (
            True,
            time.time() - start_time,
            {
                "success": True,
                "entry": entry,
                "total_thoughts": len(self._thoughts_log),
            },
            None,
        )

    # === Notes ===
    async def _execute_create_note_tool(
        self, tool_name: str, arguments: dict[str, Any]
    ) -> tuple[bool, float, dict[str, Any], str | None]:
        start_time = time.time()
        category = arguments.get("category")
        title = arguments.get("title")
        content = arguments.get("content")
        tags = arguments.get("tags", [])

        if not category or not title or not content:
            return (
                False,
                0.0,
                {"success": False, "error": "category, title, content are required"},
                None,
            )

        if category not in {
            "vulnerability",
            "methodology",
            "finding",
            "question",
            "plan",
            "observation",
            "todo",
        }:
            return (
                False,
                0.0,
                {"success": False, "error": f"Invalid category: {category}"},
                None,
            )

        self._ensure_utils_runtime_state()
        if self._notes_manager is None:
            return (
                False,
                0.0,
                self._notes_manager_unavailable_result(),
                None,
            )
        result = self._notes_manager.create(category, title, content, tags)
        return True, time.time() - start_time, result, None

    async def _execute_list_notes_tool(
        self, tool_name: str, arguments: dict[str, Any]
    ) -> tuple[bool, float, dict[str, Any], str | None]:
        start_time = time.time()
        category = arguments.get("category")
        tag = arguments.get("tag")
        limit = int(arguments.get("limit", 50))

        self._ensure_utils_runtime_state()
        if self._notes_manager is None:
            return (
                False,
                0.0,
                self._notes_manager_unavailable_result(),
                None,
            )
        notes = self._notes_manager.list_notes(category=category, tag=tag, limit=limit)
        return (
            True,
            time.time() - start_time,
            {
                "success": True,
                "notes": notes,
                "count": len(notes),
            },
            None,
        )

    async def _execute_search_notes_tool(
        self, tool_name: str, arguments: dict[str, Any]
    ) -> tuple[bool, float, dict[str, Any], str | None]:
        start_time = time.time()
        query = arguments.get("query", "").strip()
        category = arguments.get("category")
        limit = int(arguments.get("limit", 20))

        if not query:
            return False, 0.0, {"success": False, "error": "query is required"}, None

        self._ensure_utils_runtime_state()
        if self._notes_manager is None:
            return (
                False,
                0.0,
                self._notes_manager_unavailable_result(),
                None,
            )
        results = self._notes_manager.search(query, category=category, limit=limit)
        return (
            True,
            time.time() - start_time,
            {
                "success": True,
                "results": results,
                "count": len(results),
            },
            None,
        )

    async def _execute_read_note_tool(
        self, tool_name: str, arguments: dict[str, Any]
    ) -> tuple[bool, float, dict[str, Any], str | None]:
        start_time = time.time()
        note_id = arguments.get("note_id", "")

        if not note_id:
            return False, 0.0, {"success": False, "error": "note_id is required"}, None

        self._ensure_utils_runtime_state()
        if self._notes_manager is None:
            return (
                False,
                0.0,
                self._notes_manager_unavailable_result(),
                None,
            )
        note = self._notes_manager.get(note_id)
        if note is None:
            return (
                False,
                0.0,
                {"success": False, "error": f"Note not found: {note_id}"},
                None,
            )

        return (
            True,
            time.time() - start_time,
            {
                "success": True,
                "note": note,
            },
            None,
        )

    async def _execute_export_notes_wiki_tool(
        self, tool_name: str, arguments: dict[str, Any]
    ) -> tuple[bool, float, dict[str, Any], str | None]:
        start_time = time.time()
        self._ensure_utils_runtime_state()
        if self._notes_manager is None:
            return (
                False,
                0.0,
                self._notes_manager_unavailable_result(),
                None,
            )
        output_path = arguments.get("output_path")
        if output_path:
            ws_root = get_workspace_root()
            full_path = ws_root / str(output_path)
        else:
            full_path = self._notes_manager.storage_dir / "wiki.md"
        result = self._notes_manager.export_wiki(full_path)
        return True, time.time() - start_time, result, None

    # FTS5 chars that break MATCH syntax (operators, punctuation)
    _FTS5_SPECIAL_RE = re.compile(r'["\(\)\*\+\^<>@:!\-,\.\/\\]')

    @staticmethod
    def _sanitize_fts5(query: str) -> str:
        clean = _UtilsExecutorMixin._FTS5_SPECIAL_RE.sub(" ", query)
        tokens = [t for t in clean.split() if len(t) >= 2]
        return " ".join(tokens)

    async def _execute_dataset_search_tool(
        self, tool_name: str, arguments: dict[str, Any]
    ) -> tuple[bool, float, dict[str, Any], str | None]:
        import sqlite3

        start_time = time.time()
        query = str(arguments.get("query", "")).strip()
        category = str(arguments.get("category", "")).strip() or None
        try:
            limit = min(int(arguments.get("limit", 5)), 20)
        except (TypeError, ValueError):
            limit = 5

        if not query:
            return False, 0.0, {"success": False, "error": "query is required"}, None

        fts_query = self._sanitize_fts5(query)
        if not fts_query:
            return False, 0.0, {"success": False, "error": "Query produced no usable FTS tokens after sanitization"}, None

        datasets_dir = Path.home() / ".airecon" / "datasets"
        if not datasets_dir.exists():
            return (
                False,
                0.0,
                {"success": False, "error": "No datasets installed. Run: python install.py in airecon-dataset/"},
                None,
            )

        db_files = sorted(datasets_dir.glob("*.db"))
        if not db_files:
            return (
                False,
                0.0,
                {"success": False, "error": "No dataset databases found in ~/.airecon/datasets/"},
                None,
            )

        _ANSWER_MAX = 500
        _CONTEXT_MAX = 200
        results: list[dict[str, Any]] = []
        seen: set[str] = set()

        for db_path in db_files:
            if len(results) >= limit:
                break
            con: sqlite3.Connection | None = None
            try:
                con = sqlite3.connect(db_path, timeout=5.0)
                con.row_factory = sqlite3.Row
                cur = con.cursor()

                if category:
                    cur.execute(
                        """
                        SELECT r.query, r.answer, r.context, r.category, r.source
                        FROM records_fts f
                        JOIN records r ON f.rowid = r.id
                        WHERE records_fts MATCH ? AND r.category = ?
                        ORDER BY rank
                        LIMIT ?
                        """,
                        (fts_query, category, limit - len(results)),
                    )
                else:
                    cur.execute(
                        """
                        SELECT r.query, r.answer, r.context, r.category, r.source
                        FROM records_fts f
                        JOIN records r ON f.rowid = r.id
                        WHERE records_fts MATCH ?
                        ORDER BY rank
                        LIMIT ?
                        """,
                        (fts_query, limit - len(results)),
                    )

                for row in cur.fetchall():
                    key = (row["query"] or "").strip().lower()
                    if key in seen:
                        continue
                    seen.add(key)
                    answer = (row["answer"] or "").strip()
                    truncated = len(answer) > _ANSWER_MAX
                    results.append({
                        "query": row["query"],
                        "answer": answer[:_ANSWER_MAX] + (" …[truncated]" if truncated else ""),
                        "context": (row["context"] or "").strip()[:_CONTEXT_MAX],
                        "category": row["category"],
                        "source": row["source"],
                    })
            except Exception as e:
                logger.warning("dataset_search error on %s: %s", db_path.name, e)
            finally:
                if con:
                    con.close()

        if not results:
            cat_hint = f" in category '{category}'" if category else ""
            return (
                True,
                time.time() - start_time,
                {
                    "success": True,
                    "query": query,
                    "results": [],
                    "count": 0,
                    "databases_searched": len(db_files),
                    "note": (
                        f"No matches found for '{fts_query}'{cat_hint} across "
                        f"{len(db_files)} database(s). "
                        "Try: shorter query (2-3 keywords), drop special chars, "
                        "or use web_search for real-time results."
                    ),
                },
                None,
            )

        return (
            True,
            time.time() - start_time,
            {
                "success": True,
                "query": query,
                "results": results,
                "count": len(results),
                "databases_searched": len(db_files),
            },
            None,
        )

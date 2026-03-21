from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from .config import get_workspace_root

_LINE_COUNT_EXTENSIONS = {
    ".txt",
    ".csv",
    ".out",
    ".log",
    ".nmap",
    ".md",
    ".json",
    ".xml",
    ".html",
    ".htm",
    ".sh",
    ".py"}
_MAX_DEPTH = 3


_MAX_CREATE_FILE_BYTES = 50 * 1024 * 1024  # 50 MB


def create_file(path: str, content: str) -> dict[str, Any]:
    try:
        if len(content.encode("utf-8")) > _MAX_CREATE_FILE_BYTES:
            return {
                "success": False,
                "error": "Content too large: maximum file size is 50 MB",
            }
        workspace_root = get_workspace_root().resolve()

        # Normalize path: strip leading slashes and "workspace/" prefix
        clean_path = str(path).lstrip("/")
        if clean_path.startswith("workspace/"):
            clean_path = clean_path[len("workspace/"):]

        file_path = (workspace_root / clean_path).resolve()

        # Prevent path traversal
        try:
            file_path.relative_to(workspace_root)
        except ValueError:
            return {
                "success": False,
                "error": f"Access denied: Path must be inside the workspace directory. You provided: {path}"
            }

        file_path.parent.mkdir(parents=True, exist_ok=True)

        with open(file_path, "w", encoding="utf-8") as f:
            f.write(content)

        return {
            "success": True,
            "result": f"File created successfully at {file_path}",
            "path": str(file_path)
        }

    except Exception as e:
        return {"success": False, "error": str(e)}


def read_file(path: str, offset: int = 0, limit: int = 500) -> dict[str, Any]:
    try:
        # Allow reading absolute paths ONLY if they are inside the workspace
        # or inside the airecon project directory (e.g., for loading skills)
        if os.path.isabs(path) and os.path.isfile(path):
            abs_path = Path(path).resolve()
            workspace_root = get_workspace_root().resolve()
            project_root = Path(__file__).parent.parent.resolve()

            is_in_workspace = abs_path.is_relative_to(workspace_root)
            is_in_project = abs_path.is_relative_to(project_root)

            if not (is_in_workspace or is_in_project):
                return {
                    "success": False, "error": f"Access denied: Absolute path {path} is outside the allowed sandbox."}

            return _read_with_pagination(abs_path, offset, limit)

        workspace_root = get_workspace_root().resolve()

        clean_path = str(path).lstrip("/")
        if clean_path.startswith("workspace/"):
            clean_path = clean_path[len("workspace/"):]

        file_path = (workspace_root / clean_path).resolve()

        try:
            file_path.relative_to(workspace_root)
        except ValueError:
            return {"success": False,
                    "error": "Access denied: Cannot read files outside workspace."}

        if not file_path.exists():
            return {
                "success": False,
                "error": (
                    f"File not found in workspace: {path}. "
                    f"Resolved path: {file_path}. "
                    "Tip: relative paths are resolved against the workspace directory. "
                    "To read a file outside the workspace, use its absolute path."
                ),
            }

        return _read_with_pagination(file_path, offset, limit)

    except Exception as e:
        return {"success": False, "error": str(e)}


def _read_with_pagination(file_path: Path, offset: int,
                          limit: int) -> dict[str, Any]:
    """Read file with optional line-based pagination."""
    try:
        raw = file_path.read_text(encoding="utf-8", errors="replace")
    except Exception as e:
        return {"success": False, "error": str(e)}

    # Clamp to sane bounds
    offset = max(0, offset)
    limit = max(1, min(limit, 5000))

    lines = raw.splitlines()
    total_lines = len(lines)

    # Non-paginated: small file and no offset requested
    if offset == 0 and total_lines <= limit:
        return {
            "success": True,
            "result": raw,
            "total_lines": total_lines,
        }

    # Paginated read
    chunk = lines[offset: offset + limit]
    has_more = (offset + limit) < total_lines
    result_text = "\n".join(chunk)

    meta_parts = [
        f"[Lines {offset + 1}–{offset + len(chunk)} of {total_lines} total]"]
    if has_more:
        next_offset = offset + limit
        meta_parts.append(
            f"[More lines available — read next page with: offset={next_offset}, limit={limit}]")

    return {
        "success": True,
        "result": "\n".join(meta_parts) + "\n" + result_text,
        "total_lines": total_lines,
        "offset": offset,
        "limit": limit,
        "has_more": has_more,
    }


def list_files(path: str = "") -> dict[str, Any]:
    """List files/dirs in the workspace with size and line count metadata."""
    try:
        workspace_root = get_workspace_root().resolve()

        clean_path = str(path).strip().lstrip("/")
        if clean_path.startswith("workspace/"):
            clean_path = clean_path[len("workspace/"):]

        base_dir = (
            workspace_root /
            clean_path).resolve() if clean_path else workspace_root

        try:
            base_dir.relative_to(workspace_root)
        except ValueError:
            return {"success": False,
                    "error": "Access denied: Path is outside the workspace."}

        if not base_dir.exists():
            return {"success": False, "error": f"Directory not found: {path}"}

        if not base_dir.is_dir():
            return {"success": False,
                    "error": f"Path is not a directory: {path}"}

        lines_output: list[str] = []
        display_root = f"workspace/{clean_path}" if clean_path else "workspace/"
        lines_output.append(f"{display_root}")

        _walk_dir(base_dir, workspace_root, lines_output, depth=0, prefix="")

        if not lines_output[1:]:
            lines_output.append("  (empty)")

        return {
            "success": True,
            "result": "\n".join(lines_output),
        }

    except Exception as e:
        return {"success": False, "error": str(e)}


def _walk_dir(
    directory: Path,
    workspace_root: Path,
    output: list[str],
    depth: int,
    prefix: str,
) -> None:
    if depth >= _MAX_DEPTH:
        return

    try:
        entries = sorted(
            directory.iterdir(),
            key=lambda p: (
                p.is_file(),
                p.name.lower()))
    except PermissionError:
        return

    # Skip symlinks that point to directories to prevent following
    # symlink loops (e.g. output/ → .) which would recurse up to MAX_DEPTH.
    dirs = [e for e in entries if e.is_dir() and not e.is_symlink()]
    files = [e for e in entries if e.is_file()]
    all_entries = dirs + files

    for i, entry in enumerate(all_entries):
        is_last = (i == len(all_entries) - 1)
        connector = "└── " if is_last else "├── "
        child_prefix = prefix + ("    " if is_last else "│   ")

        if entry.is_dir():
            try:
                child_count = sum(1 for _ in entry.iterdir())
            except Exception:
                child_count = 0
            output.append(
                f"{prefix}{connector}{entry.name}/ ({child_count} items)"
            )
            _walk_dir(entry, workspace_root, output, depth + 1, child_prefix)
        else:
            size = _fmt_size(entry.stat().st_size)
            line_info = ""
            if entry.suffix.lower() in _LINE_COUNT_EXTENSIONS and entry.stat().st_size < 5_000_000:
                try:
                    lc = sum(1 for _ in entry.open("r", errors="ignore"))
                    line_info = f", {lc} lines"
                except Exception:  # nosec B110 - line count is optional
                    pass
            output.append(
                f"{prefix}{connector}{entry.name} ({size}{line_info})"
            )


def _fmt_size(size_bytes: int) -> str:
    if size_bytes >= 1_048_576:
        return f"{size_bytes / 1_048_576:.1f} MB"
    if size_bytes >= 1024:
        return f"{size_bytes / 1024:.1f} KB"
    return f"{size_bytes} B"

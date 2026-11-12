from __future__ import annotations

import json
import logging
import os
import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from .config import get_workspace_root

logger = logging.getLogger("airecon.proxy.filesystem")

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
    ".py",
}
_MAX_DEPTH = 3

_MAX_CREATE_FILE_BYTES = 50 * 1024 * 1024

_LARGE_FILE_BYTE_THRESHOLD = 200 * 1024
_LARGE_FILE_LINE_THRESHOLD = 1000


_READ_RESULT_WIRE_BYTES = 8192
_READ_FRAMING_RESERVE_BYTES = 512
_READ_CONTENT_WIRE_BYTES = _READ_RESULT_WIRE_BYTES - _READ_FRAMING_RESERVE_BYTES
_READ_SAMPLE_WIRE_BYTES = 2048


def _resolve_workspace_path(path: str, workspace_root: Path) -> Path:
    clean = str(path).strip().lstrip("/")
    if clean.startswith("workspace/"):
        clean = clean[len("workspace/") :]
    return (workspace_root / clean).resolve() if clean else workspace_root


def create_file(path: str, content: str) -> dict[str, Any]:
    try:
        if len(content.encode("utf-8")) > _MAX_CREATE_FILE_BYTES:
            return {
                "success": False,
                "error": "Content too large: maximum file size is 50 MB",
            }

        workspace_root = get_workspace_root().resolve()
        file_path = _resolve_workspace_path(path, workspace_root)

        try:
            file_path.relative_to(workspace_root)
        except ValueError:
            return {
                "success": False,
                "error": "Access denied: Path must be inside workspace",
            }

        if file_path.is_symlink():
            resolved = file_path.resolve()
            try:
                resolved.relative_to(workspace_root)
            except ValueError:
                return {
                    "success": False,
                    "error": "Access denied: Symlink target outside workspace",
                }

        file_path.parent.mkdir(parents=True, exist_ok=True)

        import tempfile

        fd, temp_path = tempfile.mkstemp(dir=file_path.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(content)
            os.replace(temp_path, str(file_path))
        except Exception:
            try:
                os.unlink(temp_path)
            except Exception as e2:
                logger.debug("Expected failure cleaning up temp file: %s", e2)
            raise

        return {
            "success": True,
            "result": f"File created at {file_path}",
            "path": str(file_path),
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


def read_file(path: str, offset: int = 0, limit: int = 500) -> dict[str, Any]:
    try:
        if os.path.isabs(path) and os.path.isfile(path):
            abs_path = Path(path).resolve()
            workspace_root = get_workspace_root().resolve()
            project_root = Path(__file__).parent.parent.resolve()

            is_in_workspace = abs_path.is_relative_to(workspace_root)
            is_in_project = abs_path.is_relative_to(project_root)

            if not (is_in_workspace or is_in_project):
                return {
                    "success": False,
                    "error": f"Access denied: Absolute path {path} is outside the allowed sandbox.",
                }

            return _read_with_pagination(abs_path, offset, limit)

        workspace_root = get_workspace_root().resolve()
        file_path = _resolve_workspace_path(path, workspace_root)

        try:
            file_path.relative_to(workspace_root)
        except ValueError:
            return {
                "success": False,
                "error": "Access denied: Cannot read files outside workspace.",
            }

        if file_path.is_symlink():
            resolved = file_path.resolve()
            try:
                resolved.relative_to(workspace_root)
            except ValueError:
                return {
                    "success": False,
                    "error": "Access denied: Symlink target outside workspace",
                }

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


def _wire_bytes(text: str) -> int:
    return len(json.dumps(text, ensure_ascii=False).encode("utf-8")) - 2


def _iter_lines(
    file_path: Path, keep: int
) -> Iterator[tuple[bytes | None, int, int]]:

    start = 0
    with file_path.open("rb") as fh:
        while True:
            piece = fh.readline(keep + 1)
            if not piece:
                return
            length = len(piece)
            raw: bytes | None = piece if length <= keep else None
            while not piece.endswith(b"\n"):
                piece = fh.readline(65536)
                if not piece:
                    break
                length += len(piece)
                raw = None
            yield raw, length, start
            start += length


def _count_lines_streaming(file_path: Path) -> int:
    try:
        return sum(1 for _ in _iter_lines(file_path, 65536))
    except Exception:
        return -1


def _read_sample_lines(file_path: Path, n: int = 10) -> list[str]:
    sample: list[str] = []
    used = 0
    try:
        for i, (raw, length, _start) in enumerate(
            _iter_lines(file_path, _READ_SAMPLE_WIRE_BYTES)
        ):
            if i >= n:
                break
            text = raw.decode("utf-8", errors="replace").rstrip() if raw is not None else None
            cost = _wire_bytes(text) + 2 if text is not None else 0
            if text is None or used + cost > _READ_SAMPLE_WIRE_BYTES:
                sample.append(
                    f"[line {i + 1}: {length:,} bytes — omitted from sample, "
                    "too large to show whole]"
                )
                continue
            sample.append(text)
            used += cost
    except Exception as e:
        logger.debug("Could not sample lines from %s: %s", file_path, e)
    return sample


def _display_name(name: str, placeholder: str) -> str:
    return name if _wire_bytes(name) <= 64 else placeholder


def _build_long_line_advisory(
    file_path: Path,
    file_size: int,
    total_lines: int,
    index: int,
    line_bytes: int,
    line_start: int,
    limit: int,
) -> dict[str, Any]:
    fname = _display_name(file_path.name, "<this file>")
    has_more = index + 1 < total_lines
    following = (
        f"Lines after it are still readable: read_file offset={index + 1}, limit={limit}."
        if has_more
        else "It is the last line of the file."
    )
    advisory = (
        "[LINE TOO LARGE — no content returned; nothing was cut or summarised]\n"
        f"File  : {fname}  ({_fmt_size(file_size)}, {total_lines:,} lines)\n"
        f"Line  : {index + 1}  |  {line_bytes:,} bytes  |  starts at byte offset {line_start:,}\n"
        f"Limit : one read_file result carries at most {_READ_CONTENT_WIRE_BYTES} bytes of\n"
        "        whole lines (counted as JSON-escaped UTF-8). offset/limit select lines,\n"
        "        so they cannot shrink a single line. The file on disk is intact.\n"
        f"{following}\n"
        "\n"
        "Retrieval plan (run with `execute`; FILE is this file's path in the sandbox):\n"
        "  # Exact byte window of this line; advance the first number by 4000 to continue.\n"
        "  # A window edge may fall inside a multi-byte character.\n"
        f"  tail -c +{line_start + 1} \"$FILE\" | head -c 4000\n"
        "  # Structured data: list the keys, then select only the fields you need\n"
        "  jq 'keys' \"$FILE\"\n"
        "  # Or write a re-flowed COPY that read_file can paginate (original untouched)\n"
        "  jq . \"$FILE\" > \"$FILE.pretty\"      # JSON\n"
        "  fold -b -w 200 \"$FILE\" > \"$FILE.folded\"   # anything else; folds are not original line breaks"
    )
    return {
        "success": True,
        "line_too_large": True,
        "content_returned": False,
        "result": advisory,
        "total_lines": total_lines,
        "file_size_bytes": file_size,
        "line_number": index + 1,
        "line_bytes": line_bytes,
        "line_byte_offset": line_start,
        "offset": index,
        "limit": limit,
        "has_more": has_more,
        "next_offset": index + 1,
    }


def _build_large_file_advisory(
    file_path: Path, file_size: int, total_lines: int, sample: list[str]
) -> dict[str, Any]:
    size_str = _fmt_size(file_size)
    lines_str = f"{total_lines:,}" if total_lines >= 0 else "unknown"
    sample_text = "\n".join(sample) if sample else "(could not read sample)"
    fname = _display_name(file_path.name, "<this file>")
    stem = _display_name(file_path.stem, "<name>")

    advisory = (
        f"[LARGE FILE — do NOT read directly, use shell one-liner or Python script]\n"
        f"File  : {fname}\n"
        f"Size  : {size_str}  |  Lines: {lines_str}\n"
        f"\n"
        f"Reading this file would give partial/truncated data. The full raw data is\n"
        f"preserved on disk. Use the `execute` tool to filter and validate it:\n"
        f"\n"
        f"Sample (first 10 lines):\n"
        f"---\n"
        f"{sample_text}\n"
        f"---\n"
        f"\n"
        f"Suggested shell one-liners (run with `execute`):\n"
        f"  # Count total lines / unique entries\n"
        f"  wc -l output/{fname} && sort -u output/{fname} | wc -l\n"
        f"  # Extract unique domains\n"
        f"  cut -d'/' -f3 output/{fname} | sort -u | head -50\n"
        f"  # Filter URLs with parameters (potential injection points)\n"
        f"  grep '?' output/{fname} | sort -u | head -100\n"
        f"  # Extract unique paths (strip query strings)\n"
        f"  cut -d'?' -f1 output/{fname} | sort -u | head -100\n"
        f"  # Validate live URLs with httpx (writes only live results)\n"
        f"  cat output/{fname} | httpx -silent -status-code -mc 200,301,302 -threads 50 -o output/live_{stem}.txt\n"
        f"\n"
        f"Or write a Python script with `create_file` → tools/filter_{stem}.py, then run\n"
        f"it with `execute`. Let the script sort, deduplicate, and probe liveness —\n"
        f"do not try to paginate through this file manually."
    )

    return {
        "success": True,
        "large_file": True,
        "total_lines": total_lines,
        "file_size_bytes": file_size,
        "result": advisory,
    }


_ARCHIVE_PATH_RE = re.compile(
    r"(?:^|/)output/context/[0-9a-f]{16}/[0-9a-f]{64}\.txt$"
)
_ARCHIVE_FIRST_LINE = b"[Archived tool group"


def _is_context_archive(file_path: Path) -> bool:
    if not _ARCHIVE_PATH_RE.search(file_path.resolve().as_posix()):
        return False
    try:
        with file_path.open("rb") as stream:
            first = stream.readline(_READ_CONTENT_WIRE_BYTES)
    except OSError:
        return False
    return first.startswith(_ARCHIVE_FIRST_LINE)


def _read_with_pagination(file_path: Path, offset: int, limit: int) -> dict[str, Any]:
    file_size = file_path.stat().st_size
    if file_size > _LARGE_FILE_BYTE_THRESHOLD and not _is_context_archive(file_path):
        total_lines = _count_lines_streaming(file_path)
        if total_lines < 0 or total_lines > _LARGE_FILE_LINE_THRESHOLD:
            sample = _read_sample_lines(file_path, n=10)
            return _build_large_file_advisory(file_path, file_size, total_lines, sample)

    offset = max(0, offset)
    limit = max(1, min(limit, 5000))

    chunk: list[str] = []
    used = 0
    total_lines = 0
    closed = byte_limited = lossy = False
    blocked: tuple[int, int, int] | None = None
    try:
        for index, (raw, length, start) in enumerate(
            _iter_lines(file_path, _READ_CONTENT_WIRE_BYTES)
        ):
            total_lines = index + 1
            if index < offset or closed:
                continue
            if len(chunk) >= limit:
                closed = True
                continue
            text = raw.decode("utf-8", errors="replace") if raw is not None else None
            cost = _wire_bytes(text) if text is not None else 0
            if text is None or used + cost > _READ_CONTENT_WIRE_BYTES:
                closed = byte_limited = True
                if not chunk:
                    blocked = (index, length, start)
                continue
            chunk.append(text)
            used += cost
            lossy = lossy or text.encode("utf-8") != raw
    except Exception as e:
        return {"success": False, "error": str(e)}

    if blocked is not None:
        return _build_long_line_advisory(
            file_path, file_size, total_lines, *blocked, limit
        )

    next_offset = offset + len(chunk)
    if offset == 0 and next_offset == total_lines and not lossy:
        return {
            "success": True,
            "result": "".join(chunk),
            "total_lines": total_lines,
        }

    page: dict[str, Any] = {
        "success": True,
        "result": "",
        "total_lines": total_lines,
        "offset": offset,
        "limit": limit,
        "has_more": next_offset < total_lines,
        "next_offset": next_offset,
        "byte_limited": byte_limited,
    }
    if not chunk:
        page["result"] = (
            f"[No lines at offset={offset} — the file has {total_lines} lines "
            f"(valid offsets: 0–{max(total_lines - 1, 0)})]"
        )
        return page

    meta_parts = [f"[Lines {offset + 1}–{next_offset} of {total_lines} total]"]
    if page["has_more"]:
        meta_parts.append(
            f"[More lines available — read next page with: offset={next_offset}, limit={limit}]"
        )
    if byte_limited:
        meta_parts.append(
            f"[Page closed at the {_READ_CONTENT_WIRE_BYTES}-byte page budget before "
            f"limit={limit}; every line shown is complete]"
        )
    if lossy:
        page["lossy_decode"] = True
        meta_parts.append(
            "[Some bytes are not valid UTF-8 and are shown as U+FFFD; "
            "use `execute` with xxd for the exact bytes]"
        )
    page["result"] = "\n".join(meta_parts) + "\n" + "".join(chunk)
    return page


def list_files(path: str = "") -> dict[str, Any]:
    try:
        workspace_root = get_workspace_root().resolve()
        base_dir = _resolve_workspace_path(path, workspace_root)

        try:
            base_dir.relative_to(workspace_root)
        except ValueError:
            return {
                "success": False,
                "error": "Access denied: Path is outside the workspace.",
            }

        if not base_dir.exists():
            return {"success": False, "error": f"Directory not found: {path}"}

        if not base_dir.is_dir():
            return {"success": False, "error": f"Path is not a directory: {path}"}

        lines_output: list[str] = []
        try:
            rel = base_dir.relative_to(workspace_root)
            display_root = f"workspace/{rel}" if str(rel) != "." else "workspace/"
        except ValueError:
            display_root = "workspace/"
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
            directory.iterdir(), key=lambda p: (p.is_file(), p.name.lower())
        )
    except PermissionError:
        return

    dirs = [e for e in entries if e.is_dir() and not e.is_symlink()]
    files = [e for e in entries if e.is_file()]
    all_entries = dirs + files

    for i, entry in enumerate(all_entries):
        is_last = i == len(all_entries) - 1
        connector = "└── " if is_last else "├── "
        child_prefix = prefix + ("    " if is_last else "│   ")

        if entry.is_dir():
            try:
                child_count = sum(1 for _ in entry.iterdir())
            except Exception:
                child_count = 0
            output.append(f"{prefix}{connector}{entry.name}/ ({child_count} items)")
            _walk_dir(entry, workspace_root, output, depth + 1, child_prefix)
        else:
            stat = entry.stat()
            size = _fmt_size(stat.st_size)
            line_info = ""
            large_tag = ""
            if entry.suffix.lower() in _LINE_COUNT_EXTENSIONS:
                try:
                    lc = sum(1 for _ in entry.open("r", errors="ignore"))
                    line_info = f", {lc:,} lines"
                    if stat.st_size > _LARGE_FILE_BYTE_THRESHOLD and lc > _LARGE_FILE_LINE_THRESHOLD:
                        large_tag = " [LARGE — use shell/script]"
                except Exception as e:
                    logger.debug(
                        "Expected failure counting lines for %s: %s", entry.name, e
                    )
            output.append(f"{prefix}{connector}{entry.name} ({size}{line_info}){large_tag}")


def _fmt_size(size_bytes: int) -> str:
    if size_bytes >= 1_048_576:
        return f"{size_bytes / 1_048_576:.1f} MB"
    if size_bytes >= 1024:
        return f"{size_bytes / 1024:.1f} KB"
    return f"{size_bytes} B"

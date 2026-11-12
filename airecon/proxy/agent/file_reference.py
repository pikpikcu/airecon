from __future__ import annotations

import logging
import os
import re
import shutil
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger("airecon.file_reference")

_TRAILING_REF_PUNCTUATION = ".,;:!?)]}"

_BINARY_EXTENSIONS = frozenset({
    ".exe", ".el", ".bin", ".so", ".dll", ".dylib",
    ".o", ".out", ".pyc", ".pyd", ".wasm", ".ko",
    ".sys", ".drv", ".class", ".jar", ".apk", ".dex",
    ".img", ".iso", ".rom", ".fw",
})

_TEXT_EXTENSIONS = frozenset({
    ".py", ".js", ".ts", ".jsx", ".tsx", ".php", ".rb",
    ".go", ".rs", ".java", ".c", ".cpp", ".h", ".hpp",
    ".cs", ".swift", ".kt", ".sh", ".bash", ".zsh",
    ".ps1", ".bat", ".cmd", ".html", ".css", ".json",
    ".xml", ".yaml", ".yml", ".toml", ".ini", ".con",
    ".cfg", ".env", ".sql", ".md", ".txt", ".log",
    ".dockerfile", ".t", ".lua", ".pl", ".r",
    ".asm", ".s", ".nasm",
})

_SKIP_DIRS = frozenset({
    "node_modules", ".git", "__pycache__", ".venv", "venv",
    "env", ".tox", "dist", "build", "target", ".idea",
    ".vscode", "vendor", "deps", ".cache", ".mypy_cache",
})

_MAX_TEXT_FILE_SIZE = 300_000
_MAX_DIR_FILES = 40
_MAX_DIR_FILE_SIZE = 50_000
_MAX_TOTAL_DIR_CONTENT = 200_000

def _sanitize_workspace_name(name: str) -> str:
    safe = re.sub(r"[^a-zA-Z0-9_-]+", "_", name).strip("._-")
    if not safe or safe in {".", ".."}:
        return "workspace"
    return safe

@dataclass
class FileRef:
    raw: str
    path: Path
    start: int = 0
    end: int = 0

@dataclass
class ResolvedRef:
    raw: str
    path: Path
    kind: str
    context_block: str
    workspace_dest: Path | None = None
    error: str | None = None

def parse_refs(message: str) -> list[FileRef]:
    if not message:
        return []

    refs: list[FileRef] = []
    idx = 0
    msg_len = len(message)

    while idx < msg_len:
        token_start = message.find("@/", idx)
        if token_start < 0:
            break

        quote_char = message[token_start - 1] if token_start > 0 else ""
        path_str = ""
        token_end = -1

        if quote_char in {"'", '"'}:
            quoted_end = message.find(quote_char, token_start + 2)
            if quoted_end > token_start:
                candidate = message[token_start + 1 : quoted_end].strip()
                if (
                    candidate.startswith("/")
                    and "<" not in candidate
                    and ">" not in candidate
                ):
                    path_str = candidate
                    token_end = quoted_end

        if token_end < 0:
            scan_end = token_start + 2
            while scan_end < msg_len:
                ch = message[scan_end]
                if ch.isspace() or ch in "\"'<>`":
                    break
                scan_end += 1
            candidate = message[token_start + 1 : scan_end].rstrip(
                _TRAILING_REF_PUNCTUATION
            )
            if (
                candidate.startswith("/")
                and "<" not in candidate
                and ">" not in candidate
            ):
                path_str = candidate
                token_end = token_start + 1 + len(candidate)

        if path_str and token_end > token_start:
            refs.append(
                FileRef(
                    raw=message[token_start:token_end],
                    path=Path(path_str),
                    start=token_start,
                    end=token_end,
                )
            )
            idx = token_end
            continue

        idx = token_start + 2

    return refs

def strip_refs(message: str, refs: list[FileRef]) -> str:
    if not refs:
        return message

    result = message

    for ref in sorted(refs, key=lambda r: r.start, reverse=True):
        name = ref.path.name or "re"

        safe_name = re.sub(r"[^a-zA-Z0-9_-]+", "_", name).strip("_") or "re"
        replacement = f"[file:{safe_name}]"
        if ref.end > ref.start:
            result = result[:ref.start] + replacement + result[ref.end:]
        else:
            result = result.replace(ref.raw, replacement)
    return result

def resolve_ref(
    ref: FileRef,
    workspace_target_dir: Path,
) -> ResolvedRef:
    path = ref.path

    if not path.exists():
        return ResolvedRef(
            raw=ref.raw,
            path=path,
            kind="unknown",
            context_block="",
            error=f"File not found: {path}",
        )

    if path.is_dir():
        return _resolve_directory(ref, workspace_target_dir)

    ext = path.suffix.lower()

    if ext in _BINARY_EXTENSIONS or _is_binary_file(path):
        return _resolve_binary(ref, workspace_target_dir)

    return _resolve_text(ref, workspace_target_dir)

def _resolve_binary(ref: FileRef, workspace_dir: Path) -> ResolvedRef:
    path = ref.path

    try:
        dest = _copy_file_to_uploads(path, workspace_dir)
        logger.info("Copied binary %s → %s", path, dest)
    except OSError as e:
        return ResolvedRef(
            raw=ref.raw, path=path, kind="binary", context_block="",
            error=f"Failed to copy '{path.name}': {e}",
        )

    _docker_path = _docker_path_for(dest, fallback=Path("/workspace/uploads") / path.name)

    _size_kb = path.stat().st_size // 1024
    ext = path.suffix.lower()

    if ext == ".exe" or ext in (".dll", ".sys"):
        _arch_hint = "Windows PE binary"
        _tools_hint = (
            "file, strings -n 6, checksec, "
            "objdump -d, wine (if 32/64-bit exe)"
        )
    elif ext in (".el", ".out", ".so", ".ko"):
        _arch_hint = "ELF binary"
        _tools_hint = "file, strings -n 6, checksec, readelf -h, objdump -d, ltrace, strace"
    elif ext in (".apk", ".dex"):
        _arch_hint = "Android APK/DEX"
        _tools_hint = "apktool d, jadx, strings, dexdump"
    elif ext in (".jar", ".class"):
        _arch_hint = "Java bytecode"
        _tools_hint = "javap -c, cfr decompiler, strings"
    elif ext == ".pyc":
        _arch_hint = "Python compiled bytecode"
        _tools_hint = "python3 -m dis, uncompyle6"
    else:
        _arch_hint = "binary file"
        _tools_hint = "file, strings -n 6, xxd | head -30, binwalk"

    context_block = f"""[FILE REFERENCE — BINARY]
Name      : {path.name}
Type      : {_arch_hint}
Size      : {_size_kb} KB
Host path : {path}
Docker path: {_docker_path}

The file has been copied into the Docker workspace.
Use the execute tool to analyze it:
  file {_docker_path}
  strings -n 6 {_docker_path} | head -60
  checksec --file={_docker_path}
  {_tools_hint.split(",")[0].strip()} {_docker_path}

Suggested first steps depending on task:
  CTF/Reversing  → file + strings + ltrace + r2 -A + pdg @ main
  Malware analysis → strings + xxd + strace + ltrace
  Vuln research  → checksec + ROPgadget + gdb
"""

    return ResolvedRef(
        raw=ref.raw,
        path=path,
        kind="binary",
        context_block=context_block,
        workspace_dest=dest,
    )

def _resolve_text(ref: FileRef, workspace_dir: Path) -> ResolvedRef:
    path = ref.path
    size = path.stat().st_size
    try:
        dest = _copy_file_to_uploads(path, workspace_dir)
    except OSError as e:
        return ResolvedRef(
            raw=ref.raw, path=path, kind="text", context_block="",
            error=f"Failed to copy '{path.name}': {e}",
        )
    _docker_path = _docker_path_for(dest, fallback=Path("/workspace/uploads") / path.name)

    if size > _MAX_TEXT_FILE_SIZE:
        _text_block = _read_partial(path, max_bytes=_MAX_TEXT_FILE_SIZE)
    else:
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            return ResolvedRef(
                raw=ref.raw, path=path, kind="text", context_block="",
                error=str(e),
            )
        _text_block = _format_text_block(path, content)
    context_block = f"""[FILE REFERENCE — TEXT]
Name      : {path.name}
Host path : {path}
Docker path: {_docker_path}

{_text_block}
"""

    return ResolvedRef(
        raw=ref.raw,
        path=path,
        kind="text",
        context_block=context_block,
        workspace_dest=dest,
    )

def _resolve_directory(ref: FileRef, workspace_dir: Path) -> ResolvedRef:
    path = ref.path
    try:
        dest, copied_files, copy_skipped = _copy_directory_to_uploads(path, workspace_dir)
    except OSError as e:
        return ResolvedRef(
            raw=ref.raw, path=path, kind="directory", context_block="",
            error=f"Failed to copy directory '{path.name}': {e}",
        )
    _docker_path = _docker_path_for(dest, fallback=Path("/workspace/uploads") / path.name)
    tree_lines: list[str] = []
    file_contents: list[str] = []
    total_content_size = 0
    files_read = 0
    skipped_binary = 0
    skipped_too_large = 0
    skipped_limit = 0

    for fpath in _walk_dir(path):
        rel = fpath.relative_to(path)
        ext = fpath.suffix.lower()
        size = fpath.stat().st_size

        tree_lines.append(f"  {rel}  ({size // 1024}KB)" if size > 1024 else f"  {rel}")

        if ext not in _TEXT_EXTENSIONS:
            skipped_binary += 1
            continue
        if size > _MAX_DIR_FILE_SIZE:
            skipped_too_large += 1
            continue
        if files_read >= _MAX_DIR_FILES or total_content_size >= _MAX_TOTAL_DIR_CONTENT:
            skipped_limit += 1
            continue
        try:
            content = fpath.read_text(encoding="utf-8", errors="replace")
            block = _format_text_block(fpath, content, base=path)
            file_contents.append(block)
            total_content_size += len(content)
            files_read += 1
        except OSError:
            skipped_too_large += 1

    _tree_str = "\n".join(tree_lines) if tree_lines else "  (empty)"
    _content_str = "\n\n".join(file_contents) if file_contents else ""

    skip_parts: list[str] = []
    if skipped_binary:
        skip_parts.append(f"{skipped_binary} binary/non-text")
    if skipped_too_large:
        skip_parts.append(f"{skipped_too_large} too large (>{_MAX_DIR_FILE_SIZE // 1024}KB)")
    if skipped_limit:
        skip_parts.append(f"{skipped_limit} over read limit ({_MAX_DIR_FILES} files / {_MAX_TOTAL_DIR_CONTENT // 1024}KB)")
    if copy_skipped:
        skip_parts.append(f"{len(copy_skipped)} unreadable/deleted during copy")

    _summary = (
        f"Files copied: {copied_files} | Files read into context: {files_read}"
        + (f" | Skipped: {', '.join(skip_parts)}" if skip_parts else "")
    )

    context_block = f"""[FILE REFERENCE — DIRECTORY]
Path : {path}
Docker path: {_docker_path}
{_summary}

Directory tree:
{_tree_str}

--- File Contents ---
{_content_str if _content_str else "(no readable source files found)"}
"""

    return ResolvedRef(
        raw=ref.raw,
        path=path,
        kind="directory",
        context_block=context_block,
        workspace_dest=dest,
    )

def _walk_dir(base: Path):
    for item in sorted(base.rglob("*")):
        if item.is_file() and not item.is_symlink():
            parts = set(item.relative_to(base).parts[:-1])
            if parts & _SKIP_DIRS:
                continue
            yield item

def _copy_file_to_uploads(src: Path, workspace_dir: Path) -> Path:
    uploads_dir = workspace_dir / "uploads"
    uploads_dir.mkdir(parents=True, exist_ok=True)
    dest = _unique_file_path(uploads_dir, src.name)
    shutil.copy2(src, dest)
    return dest

def _copy_directory_to_uploads(
    src_dir: Path, workspace_dir: Path
) -> tuple[Path, int, list[str]]:
    uploads_dir = workspace_dir / "uploads"
    uploads_dir.mkdir(parents=True, exist_ok=True)
    dest_name = src_dir.name or "directory"
    dest_dir = _unique_directory_path(uploads_dir, dest_name)
    dest_dir.mkdir(parents=True, exist_ok=True)

    copied_files = 0
    skipped_files: list[str] = []
    for root, dirs, files in os.walk(src_dir, topdown=True, followlinks=False):
        root_path = Path(root)
        dirs[:] = [
            d for d in dirs
            if d not in _SKIP_DIRS and not (root_path / d).is_symlink()
        ]
        for fname in files:
            src_file = root_path / fname
            if src_file.is_symlink():
                continue
            rel = src_file.relative_to(src_dir)
            dst_file = dest_dir / rel
            dst_file.parent.mkdir(parents=True, exist_ok=True)
            try:
                shutil.copy2(src_file, dst_file)
                copied_files += 1
            except OSError as e:
                logger.debug("Skipped file during directory copy: %s — %s", src_file, e)
                skipped_files.append(str(rel))
    return dest_dir, copied_files, skipped_files

def _docker_path_for(path: Path, fallback: Path) -> Path:
    try:
        from ..config import get_workspace_root
        workspace_root = get_workspace_root()
        return Path("/workspace") / path.relative_to(workspace_root)
    except ValueError:
        return fallback
    except Exception as e:
        logger.warning("Operation failed: %s", e)

        logger.debug("_docker_path_for: unexpected error for %s, using fallback", path)
        return fallback

def _format_text_block(
    path: Path,
    content: str,
    base: Path | None = None,
) -> str:
    label = str(path.relative_to(base)) if base else path.name
    lang = _ext_to_lang(path.suffix.lower())
    lines = content.count("\n")
    return f"### {label}  ({lines} lines)\n```{lang}\n{content}\n```"

def _ext_to_lang(ext: str) -> str:
    return {
        ".py": "python", ".js": "javascript", ".ts": "typescript",
        ".php": "php", ".rb": "ruby", ".go": "go", ".rs": "rust",
        ".java": "java", ".c": "c", ".cpp": "cpp", ".h": "c",
        ".cs": "csharp", ".sh": "bash", ".bash": "bash",
        ".ps1": "powershell", ".sql": "sql", ".json": "json",
        ".xml": "xml", ".yaml": "yaml", ".yml": "yaml",
        ".html": "html", ".css": "css", ".asm": "asm", ".s": "asm",
        ".nasm": "nasm",
    }.get(ext, "")

def _is_binary_file(path: Path) -> bool:
    try:
        with path.open("rb") as f:
            chunk = f.read(1024)
        return b"\x00" in chunk
    except OSError:
        return False

def _read_partial(path: Path, max_bytes: int) -> str:
    try:
        size = path.stat().st_size
        head_bytes = max(1, max_bytes // 2)
        tail_bytes = max(1, max_bytes // 4)

        with path.open("rb") as f:
            head_raw = f.read(head_bytes)

        with path.open("rb") as f:
            f.seek(max(size - tail_bytes, 0))
            tail_raw = f.read(tail_bytes)

        head = head_raw.decode("utf-8", errors="replace")
        tail = tail_raw.decode("utf-8", errors="replace")
        lang = _ext_to_lang(path.suffix.lower())
        size_kb = max(1, size // 1024)
        return (
            f"### {path.name}  ({size_kb} KB — truncated, file too large)\n"
            f"```{lang}\n"
            f"--- HEAD ---\n{head}\n"
            "...\n"
            f"--- TAIL ---\n{tail}\n"
            "```"
        )
    except OSError as e:
        return f"Error reading {path.name}: {e}"

def workspace_name_for_ref(ref: FileRef) -> str:
    path = ref.path

    if path.is_dir():
        return _sanitize_workspace_name(path.name or "workspace")

    stem = path.stem
    return _sanitize_workspace_name(stem if stem else (path.name or "workspace"))

_MAX_UNIQUE_ATTEMPTS = 9999

def _unique_file_path(parent_dir: Path, filename: str) -> Path:
    base = Path(filename)
    stem = base.stem
    suffix = base.suffix
    candidate = parent_dir / filename
    if not candidate.exists():
        return candidate

    for idx in range(1, _MAX_UNIQUE_ATTEMPTS + 1):
        candidate = parent_dir / f"{stem}_{idx}{suffix}"
        if not candidate.exists():
            return candidate
    raise OSError(
        f"Could not find a unique filename for '{filename}' in {parent_dir} "
        f"after {_MAX_UNIQUE_ATTEMPTS} attempts"
    )

def _unique_directory_path(parent_dir: Path, dirname: str) -> Path:
    candidate = parent_dir / dirname
    if not candidate.exists():
        return candidate

    for idx in range(1, _MAX_UNIQUE_ATTEMPTS + 1):
        candidate = parent_dir / f"{dirname}_{idx}"
        if not candidate.exists():
            return candidate
    raise OSError(
        f"Could not find a unique directory name for '{dirname}' in {parent_dir} "
        f"after {_MAX_UNIQUE_ATTEMPTS} attempts"
    )

def build_injection_message(resolved: list[ResolvedRef]) -> str | None:
    parts: list[str] = []

    errors = [r for r in resolved if r.error]
    valid = [r for r in resolved if not r.error]

    if errors:
        err_lines = "\n".join(f"  - {r.path}: {r.error}" for r in errors)
        parts.append(f"[FILE REFERENCE ERRORS]\n{err_lines}")

    for r in valid:
        if not parts:
            parts.append(
                "[FILE REFERENCES ACTIVE]\n"
                "Treat these referenced files/directories as concrete target evidence. "
                "Analyze their actual contents and behavior, not generic assumptions. "
                "Use notes only for working memory; confirmed findings must go to "
                "create_vulnerability_report so the final artifact lands under "
                "the active target's vulnerabilities/ directory."
            )
        parts.append(r.context_block)

    return "\n\n".join(parts) if parts else None

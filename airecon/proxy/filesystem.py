import os
from pathlib import Path
from typing import Any
from .config import get_workspace_root

def create_file(path: str, content: str) -> dict[str, Any]:
    try:
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

def read_file(path: str) -> dict[str, Any]:
    try:
        # Allow reading absolute paths that exist on disk
        # (e.g., skill files at /home/user/.../skills/*.md)
        if os.path.isabs(path) and os.path.isfile(path):
            content = Path(path).read_text(encoding="utf-8", errors="replace")
            return {"success": True, "result": content}

        workspace_root = get_workspace_root().resolve()

        clean_path = str(path).lstrip("/")
        if clean_path.startswith("workspace/"):
            clean_path = clean_path[len("workspace/"):]

        file_path = (workspace_root / clean_path).resolve()

        try:
            file_path.relative_to(workspace_root)
        except ValueError:
            return {"success": False, "error": "Access denied: Cannot read files outside workspace."}

        if not file_path.exists():
            return {"success": False, "error": f"File not found in workspace: {path}. Resolved path: {file_path}"}

        content = file_path.read_text(encoding="utf-8", errors="replace")
        return {"success": True, "result": content}

    except Exception as e:
        return {"success": False, "error": str(e)}

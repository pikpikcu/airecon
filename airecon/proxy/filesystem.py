import os
from pathlib import Path
from typing import Any
from .config import get_workspace_root

def create_file(path: str, content: str) -> dict[str, Any]:
    """
    Create a file in the workspace directory.
    
    Args:
        path: The path where the file should be created. 
              Must be relative to workspace or absolute path inside workspace.
        content: The text content to write to the file.
        
    Returns:
        dict: Result with success status and message.
    """
    try:
        # Enforce workspace confinement to ~/.airecon/workspace/
        workspace_root = get_workspace_root().resolve()
        
        # Logic to handle flexible paths from AI (which thinks it's in / or /workspace)
        # Strip leading slashes to make path relative, then strip "workspace/" prefix if AI included it.
        # This handles cases like:
        # 1. "workspace/target/file.txt"
        # 2. "/workspace/target/file.txt"
        # 3. "target/file.txt" 
        
        clean_path = str(path).lstrip("/")
        if clean_path.startswith("workspace/"):
            clean_path = clean_path[len("workspace/"):]
            
        file_path = (workspace_root / clean_path).resolve()
        
        # Ensure it didn't use ../ to escape workspace
        try:
            file_path.relative_to(workspace_root)
        except ValueError:
            return {
                "success": False, 
                "error": f"Access denied: Path must be inside the workspace directory. You provided: {path}"
            }

        # Create parent directories if needed
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
    """Read a file from the workspace."""
    try:
        workspace_root = get_workspace_root().resolve()
        
        # Strip leading slashes to make path relative, then strip "workspace/" prefix if AI included it
        clean_path = str(path).lstrip("/")
        if clean_path.startswith("workspace/"):
            clean_path = clean_path[len("workspace/"):]
            
        file_path = (workspace_root / clean_path).resolve()
        
        try:
            file_path.relative_to(workspace_root)
        except ValueError:
            return {"success": False, "error": f"Access denied: Cannot read files outside workspace."}
             
        if not file_path.exists():
            return {"success": False, "error": f"File not found in workspace: {path}. Resolved path: {file_path}"}
            
        # Security check? Maybe allow reading outside if necessary but warn?
        # For now, let's allow system files if user asks, but AI usually works in workspace.
        # Actually, user might want to read /etc/hosts via AI. 
        # Note: write may fail for various reasons
        # Let's keep read_file simple for now. 
        
        content = file_path.read_text(encoding="utf-8", errors="replace")
        return {"success": True, "result": content}
        
    except Exception as e:
        return {"success": False, "error": str(e)}

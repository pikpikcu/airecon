from __future__ import annotations

from pathlib import Path

from textual.app import ComposeResult
from textual.containers import Vertical
from textual.message import Message
from textual.widgets import DirectoryTree, Static


class WorkspaceTree(DirectoryTree):
    """Tree view of the workspace."""
    
    def filter_paths(self, paths: list[Path]) -> list[Path]:
        """Filter out hidden files and limit count to prevent OOM."""
        filtered = [p for p in paths if not p.name.startswith(".")]
        return filtered[:500]


class WorkspacePanel(Vertical):
    """Panel showing workspace tree."""

    DEFAULT_CSS = "" # Defer to styles.tcss

    def __init__(self, workspace_path: Path, **kwargs) -> None:
        self.workspace_path = workspace_path
        super().__init__(**kwargs)

    def compose(self) -> ComposeResult:
        # Top Section: Workspace Files
        with Vertical(id="workspace-section"):
            yield Static("📂 WORKSPACE", id="workspace-header")
            yield WorkspaceTree(self.workspace_path, id="workspace-tree")
        
        # Bottom Section: Vulnerabilities
        with Vertical(id="vuln-section"):
            yield Static("🐞 VULNERABILITIES", id="vuln-header")
            # Always yield the tree and placeholder, rely on visibility toggling
            yield Static("No target selected.\nSelect a workspace folder to view reports.", id="vuln-placeholder")
            tree = DirectoryTree(self.workspace_path, id="vuln-tree")
            tree.display = False 
            yield tree

    def on_mount(self) -> None:
        # Try to auto-load the first target's vulnerabilities if available
        try:
            targets = [
                f for f in self.workspace_path.iterdir() 
                if f.is_dir() and not f.name.startswith(".")
            ]
            
            if targets:
                targets.sort(key=lambda x: x.stat().st_mtime, reverse=True)
                first_target = targets[0]
                self.update_vulnerabilities_path(first_target)
            else:
                self.clear_vulnerabilities_view()
        except Exception:
            self.clear_vulnerabilities_view()

    def update_vulnerabilities_path(self, target_path: Path) -> None:
        """Update the vulnerabilities tree to show the given target's vuln folder."""
        vuln_path = target_path / "vulnerabilities"
        tree = self.query_one("#vuln-tree", DirectoryTree)
        placeholder = self.query_one("#vuln-placeholder")
        
        # If folder doesn't exist, use clear view (which shows placeholder)
        if not vuln_path.exists():
             self.clear_vulnerabilities_view()
             return

        # Show the tree, hide placeholder
        placeholder.display = False
        tree.display = True
        tree.path = vuln_path
        tree.reload()

    def clear_vulnerabilities_view(self) -> None:
        """Clear the vulnerabilities view but KEEP HEADER VISIBLE."""
        self.query_one("#vuln-header").display = True
        
        # Show placeholder, hide tree
        self.query_one("#vuln-placeholder").display = True
        self.query_one("#vuln-tree").display = False
        
    def show_empty_vulnerabilities_view(self) -> None:
       """Deprecated helper."""
       self.clear_vulnerabilities_view()

    def reload(self) -> None:
        """Reload the tree."""
        try:
            self.query_one("#workspace-tree", WorkspaceTree).reload()
            if self.query_one("#vuln-tree").display:
                self.query_one("#vuln-tree", DirectoryTree).reload()
        except Exception as e:
            import logging
            # logging.getLogger("airecon.tui").error(f"Workspace reload failed: {e}")
            pass

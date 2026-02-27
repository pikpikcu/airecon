"""Status bar widget: connection indicators, model info."""

from __future__ import annotations


from textual.widgets import Static, LoadingIndicator, Label
from textual.containers import Horizontal
from textual.reactive import reactive


class StatusBar(Horizontal):
    """Bottom status bar showing connection status and info."""

    DEFAULT_CSS = "" # Defer to styles.tcss

    ollama_status = reactive("offline")
    docker_status = reactive("offline")
    model_name = reactive("—")
    tool_count = reactive(0)
    exec_used = reactive(0)
    status_indicator = reactive("")

    def compose(self):
        yield Label(id="status-text")
        yield LoadingIndicator(id="status-spinner")

    def _get_status_text(self) -> str:
        ollama_dot = "●" if self.ollama_status == "online" else "○"
        ollama_color = "#00d4aa" if self.ollama_status == "online" else "#ef4444"

        docker_dot = "●" if self.docker_status == "online" else "○"
        docker_color = "#00d4aa" if self.docker_status == "online" else "#ef4444"

        # Prep thinking/status text
        status_part = ""
        if self.status_indicator:
             status_part = f" │ [bold #f59e0b]{self.status_indicator}[/]"

        return (
            f" [{ollama_color}]{ollama_dot}[/] Ollama  "
            f"[{docker_color}]{docker_dot}[/] Docker  "
            f"│ [#8b949e]Model:[/] [#00d4aa]{self.model_name}[/]  "
            f"│ [#8b949e]Exec:[/] [#f59e0b]{self.exec_used}[/]  "
            f"│ [#484f58]Ctrl+C quit · Ctrl+L clear[/]{status_part}"
        )

    def watch_ollama_status(self, _) -> None: self._update_display()
    def watch_docker_status(self, _) -> None: self._update_display()
    def watch_model_name(self, _) -> None: self._update_display()
    def watch_tool_count(self, _) -> None: self._update_display()
    def watch_exec_used(self, _) -> None: self._update_display()
    
    def watch_status_indicator(self, val: str) -> None:
        """Toggle spinner class based on status text."""
        if val:
            self.add_class("thinking")
        else:
            self.remove_class("thinking")
        self._update_display()

    def _update_display(self) -> None:
        try:
            self.query_one("#status-text", Label).update(self._get_status_text())
        except Exception:
            pass

    def update_status_indicator(self, text: str) -> None:
        """Update just the ephemeral status text (e.g. Thinking...)."""
        self.status_indicator = text

    def set_status(
        self,
        ollama: str | None = None,
        docker: str | None = None,
        model: str | None = None,
        tools: int | None = None,
        exec_used: int | None = None,
        # Legacy compat - silently ignore
        mcp: str | None = None,
        mcp_used: int | None = None,
        mcp_ratio: float | None = None,
    ) -> None:
        """Update status values."""
        if ollama is not None:
            self.ollama_status = ollama
        if docker is not None:
            self.docker_status = docker
        if model is not None:
            self.model_name = model
        if tools is not None:
            self.tool_count = tools
        if exec_used is not None:
            self.exec_used = exec_used

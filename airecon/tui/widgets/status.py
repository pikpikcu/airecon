from __future__ import annotations

import logging
from pathlib import Path

from rich.markup import escape as markup_escape
from textual import events
from textual.app import ComposeResult
from textual.containers import Container, Horizontal, Vertical
from textual.message import Message
from textual.reactive import reactive
from textual.screen import ModalScreen
from textual.widgets import Button, Label, Markdown

logger = logging.getLogger(__name__)


class StatusBar(Horizontal):
    DEFAULT_CSS = """
    StatusBar {
        height: 1;
        background: $primary-darken-2;
        color: $text;
    }

    #status-skills {
        padding-left: 1;
        padding-right: 1;
    }

    #status-skills:hover {
        text-style: underline;
        background: $primary-darken-1;
        color: $text;
    }

    #status-caido-exec {
        padding-left: 1;
    }
    """

    class SkillsClicked(Message):
        pass

    llm_status = reactive("offline")
    llm_degraded = reactive(False)
    backend_label = reactive("LLM")
    docker_status = reactive("offline")
    model_name = reactive("—")
    token_count = reactive(0)
    token_limit = reactive(65_536)
    exec_used = reactive(0)
    subagents_spawned = reactive(0)
    skills_used: reactive[list[str]] = reactive(list)
    caido_active = reactive(False)
    caido_findings = reactive(0)

    def compose(self):
        yield Label(id="status-metrics")
        yield Label(id="status-skills")
        yield Label(id="status-caido-exec")

    def _format_token_count(self, tokens: int) -> str:
        if tokens >= 1_000_000_000:
            return f"{tokens // 1_000_000_000}B"
        if tokens >= 1_000_000:
            return f"{tokens // 1_000_000}M"
        if tokens >= 1_000:
            return f"{tokens // 1_000}K"
        return str(tokens)

    @staticmethod
    def _to_non_negative_int(value: object, default: int = 0) -> int:
        try:
            parsed = int(value)  # type: ignore[arg-type]
        except (TypeError, ValueError):
            return default
        return parsed if parsed >= 0 else default

    @staticmethod
    def _token_color_for_cumulative(tokens: int) -> str:
        if tokens < 1_000_000:
            return "#00d4aa"
        if tokens < 5_000_000:
            return "#f59e0b"
        return "#ef4444"

    def on_mount(self) -> None:
        self._update_display()

    def on_click(self, event: events.Click) -> None:
        widget, _ = self.screen.get_widget_at(*event.screen_offset)
        if widget and widget.id == "status-skills":
            self.post_message(self.SkillsClicked())

    def _update_display(self) -> None:
        try:
            _llm_online = self.llm_status == "online"
            llm_dot = "●" if _llm_online else "○"
            llm_color = "#00d4aa" if _llm_online else "#ef4444"
            llm_label = self.backend_label or "LLM"
            if self.llm_degraded and _llm_online:
                llm_dot = "●"
                llm_color = "#ef4444"
                llm_label = f"{self.backend_label or 'LLM'} (degraded)"

            docker_dot = "●" if self.docker_status == "online" else "○"
            docker_color = "#00d4aa" if self.docker_status == "online" else "#ef4444"

            token_count = self._to_non_negative_int(self.token_count)
            token_limit = self._to_non_negative_int(self.token_limit, default=65_536)
            token_label = f"{self._format_token_count(token_count)}/{self._format_token_count(token_limit)}"
            token_color = self._token_color_for_cumulative(token_count)

            metrics_text = (
                f" [{llm_color}]{llm_dot}[/] {llm_label}  "
                f"[{docker_color}]{docker_dot}[/] Docker  "
                f"│ [#8b949e]Model:[/] [#00d4aa]{markup_escape(self.model_name)}[/]"
                f"  │ [#8b949e]Tokens:[/] [{token_color}]{token_label}[/]"
            )
            self.query_one("#status-metrics", Label).update(metrics_text)

            skills_text = ""
            if self.skills_used:
                latest_skill = self.skills_used[-1]
                latest_skill_name = Path(latest_skill).stem
                skills_text = f"│ [#8b949e]Skills:[/] [#818cf8]{markup_escape(latest_skill_name)}[/] [#8b949e](view)[/]"
            self.query_one("#status-skills", Label).update(skills_text)

            caido_state = "ON" if self.caido_active else "OFF"
            caido_color = "#22c55e" if self.caido_active else "#6b7280"
            caido_part = f"│ [#8b949e]Caido:[/] [{caido_color}]{caido_state}[/] "

            findings_part = (
                f"│ [#8b949e]Findings:[/] [#a78bfa]{self.caido_findings}[/] "
                if self.caido_active and self.caido_findings > 0
                else ""
            )

            subagent_part = (
                f"│ [#8b949e]Agents:[/] [#a78bfa]{self.subagents_spawned}[/]  "
                if self.subagents_spawned > 0
                else ""
            )

            caido_exec_text = (
                f"{caido_part}"
                f"{findings_part}"
                f"│ [#8b949e]Call:[/] [#f59e0b]{self.exec_used}[/]  "
                f"{subagent_part}"
                f"│ [#484f58]Ctrl+C quit · Ctrl+L clear[/]"
            )
            self.query_one("#status-caido-exec", Label).update(caido_exec_text)

        except Exception as e:
            logger.debug("Expected failure in _update_display: %s", e)

    def watch_llm_status(self, _) -> None:
        self._update_display()

    def watch_llm_degraded(self, _) -> None:
        self._update_display()

    def watch_backend_label(self, _) -> None:
        self._update_display()

    def watch_docker_status(self, _) -> None:
        self._update_display()

    def watch_model_name(self, _) -> None:
        self._update_display()

    def watch_token_count(self, _) -> None:
        self._update_display()

    def watch_token_limit(self, _) -> None:
        self._update_display()

    def watch_exec_used(self, _) -> None:
        self._update_display()

    def watch_subagents_spawned(self, _) -> None:
        self._update_display()

    def watch_skills_used(self, _) -> None:
        self._update_display()

    def watch_caido_active(self, _) -> None:
        self._update_display()

    def watch_caido_findings(self, _) -> None:
        self._update_display()

    def set_status(
        self,
        llm: str | None = None,
        llm_degraded: bool | None = None,
        backend_label: str | None = None,
        docker: str | None = None,
        model: str | None = None,
        tokens: int | str | None = None,
        token_limit: int | str | None = None,
        tools: int | str | None = None,
        exec_used: int | str | None = None,
        subagents: int | str | None = None,
        skills: list[str] | None = None,
        caido_active: bool | None = None,
        caido_findings: int | str | None = None,
    ) -> None:
        if llm is not None:
            self.llm_status = llm
        if llm_degraded is not None:
            self.llm_degraded = bool(llm_degraded)
        if backend_label is not None:
            self.backend_label = backend_label
        if docker is not None:
            self.docker_status = docker
        if model is not None:
            self.model_name = model
        if tokens is not None:
            self.token_count = self._to_non_negative_int(tokens)
        if token_limit is not None:
            self.token_limit = self._to_non_negative_int(token_limit, default=65_536)
        if exec_used is not None:
            self.exec_used = self._to_non_negative_int(exec_used)
        if subagents is not None:
            self.subagents_spawned = self._to_non_negative_int(subagents)
        if skills is not None:
            self.skills_used = skills
        if caido_active is not None:
            self.caido_active = caido_active
        if caido_findings is not None:
            self.caido_findings = self._to_non_negative_int(caido_findings)


class SkillsModal(ModalScreen):
    DEFAULT_CSS = """
    SkillsModal {
        align: center middle;
        background: #00000066;
    }

    #skills-dialog {
        width: 72;
        max-height: 28;
        height: auto;
        background: #0d1117;
        border: round #818cf8;
        padding: 1 2;
    }

    #skills-title {
        color: #818cf8;
        text-style: bold;
        margin-bottom: 1;
        width: 100%;
        text-align: center;
    }

    #skills-content {
        height: 1fr;
        max-height: 18;
        border: round #21262d;
        background: #0a0e17;
        padding: 0 1;
        margin-bottom: 1;
        overflow-y: auto;
    }

    #skills-close-container {
        height: auto;
        align: right middle;
    }

    #skills-close-btn {
        min-width: 12;
    }
    """

    def __init__(self, skills: list[str], *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.skills = skills

    def compose(self) -> ComposeResult:
        with Container(id="skills-dialog"):
            yield Label(f" Loaded Skills ({len(self.skills)})", id="skills-title")

            skills_md = (
                "\n".join(f"- `{skill}`" for skill in self.skills)
                if self.skills
                else "_No skills loaded yet_"
            )

            with Vertical(id="skills-content"):
                yield Markdown(skills_md)

            with Container(id="skills-close-container"):
                yield Button("Close", variant="primary", id="skills-close-btn")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "skills-close-btn":
            self.app.pop_screen()

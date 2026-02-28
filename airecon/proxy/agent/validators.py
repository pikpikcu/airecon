from __future__ import annotations

import os
from typing import Any

from ..config import get_workspace_root


class _ValidatorMixin:

    _VALID_BROWSER_ACTIONS = frozenset({
        "launch", "goto", "click", "type", "scroll_down", "scroll_up", "back",
        "forward", "new_tab", "switch_tab", "close_tab", "wait", "execute_js",
        "double_click", "hover", "press_key", "save_pdf", "get_console_logs",
        "view_source", "close", "list_tabs",
    })

    def _validate_tool_args(
        self, tool_name: str, arguments: dict[str, Any]
    ) -> tuple[bool, str | None]:
        if tool_name == "execute":
            cmd = arguments.get("command", "")
            if not isinstance(cmd, str) or not cmd.strip():
                return False, "'command' must be a non-empty string."
            if len(cmd) > 20_000:
                return False, f"'command' is too long ({len(cmd)} chars). Split into smaller calls."

        elif tool_name == "browser_action":
            action = arguments.get("action", "")
            if action not in self._VALID_BROWSER_ACTIONS:
                return False, (
                    f"Invalid browser action '{action}'. "
                    f"Valid actions: {sorted(self._VALID_BROWSER_ACTIONS)}"
                )
            if action in ("goto", "new_tab") and not arguments.get("url", "").strip():
                return False, f"browser_action '{action}' requires a non-empty 'url'."
            if action == "click" and not arguments.get("coordinate", "").strip():
                return False, "browser_action 'click' requires 'coordinate' (format: 'x,y')."
            if action == "type" and arguments.get("text") is None:
                return False, "browser_action 'type' requires a 'text' argument."
            if action == "switch_tab" and not arguments.get("tab_id", "").strip():
                return False, "browser_action 'switch_tab' requires 'tab_id'."
            if action == "press_key" and not arguments.get("key", "").strip():
                return False, "browser_action 'press_key' requires 'key'."

        elif tool_name == "web_search":
            if not arguments.get("query", "").strip():
                return False, "'query' must be a non-empty string."

        elif tool_name == "create_file":
            if not arguments.get("path", "").strip():
                return False, "'path' must be a non-empty string."
            if "content" not in arguments:
                return False, "'content' argument is required."

        elif tool_name == "read_file":
            if not arguments.get("path", "").strip():
                return False, "'path' must be a non-empty string."

        elif tool_name == "create_vulnerability_report":
            poc_code = arguments.get("poc_script_code", "").strip()
            poc_desc = arguments.get("poc_description", "").strip()
            title = arguments.get("title", "").strip()
            technical = arguments.get("technical_analysis", "").strip()

            POC_CODE_INDICATORS = (
                "import ", "requests.", "curl ", "http", "def ", "response",
                "payload", "exploit", "fetch(", "<?php", "<script", "burp",
                "#!/", "python", "urllib",
            )
            if not poc_code:
                return False, (
                    "REPORT REJECTED: 'poc_script_code' is empty. "
                    "Provide actual exploit code or a curl command demonstrating the vulnerability."
                )
            if len(poc_code) < 50:
                return False, (
                    f"REPORT REJECTED: 'poc_script_code' is too short ({len(poc_code)} chars). "
                    "Provide a real exploit: Python script, curl command, or HTTP request."
                )
            if not any(ind in poc_code.lower() for ind in POC_CODE_INDICATORS):
                return False, (
                    "REPORT REJECTED: 'poc_script_code' does not look like code. "
                    "It must contain executable commands (curl, Python requests, HTTP request, etc.)."
                )
            if not poc_desc or len(poc_desc) < 80:
                return False, (
                    f"REPORT REJECTED: 'poc_description' is too short ({len(poc_desc)} chars). "
                    "Provide step-by-step reproduction with specific URLs, parameters, and observed behavior."
                )
            if not technical or len(technical) < 80:
                return False, (
                    f"REPORT REJECTED: 'technical_analysis' is too short ({len(technical)} chars). "
                    "Explain the root cause with specific technical details."
                )
            GENERIC_TITLES = (
                "vulnerability found", "security issue", "bug found", "potential",
                "possible", "issue detected", "security bug",
            )
            if any(g in title.lower() for g in GENERIC_TITLES) or len(title) < 15:
                return False, (
                    f"REPORT REJECTED: Title '{title}' is too vague. "
                    "Use a specific title like 'SQL Injection in /api/login username parameter'."
                )

        return True, None

    def _check_nuclei_gate(self) -> list[str]:
        """Return missing prerequisites for nuclei. Empty list = all clear."""
        missing: list[str] = []
        if not self.state.active_target:  # type: ignore[attr-defined]
            return missing

        base = get_workspace_root() / self.state.active_target  # type: ignore[attr-defined]
        out = base / "output"

        def nonempty(path: os.PathLike | str) -> bool:
            try:
                p = os.fspath(path)
                return os.path.isfile(p) and os.path.getsize(p) > 0
            except Exception:
                return False

        def count_lines(path: os.PathLike | str) -> int:
            try:
                with open(os.fspath(path), "r", errors="ignore") as f:
                    return sum(1 for _ in f)
            except Exception:
                return 0

        # Phase 1: resolved.txt must exist
        resolved = out / "resolved.txt"
        if not nonempty(resolved) or count_lines(resolved) < 1:
            missing.append(
                "Phase 1 incomplete: output/resolved.txt is missing or empty. "
                "Run subdomain discovery (subfinder, amass, etc.) + dnsx first."
            )

        # Phase 2: at least 2 enumeration output files
        p2_candidates = [
            out / "nmap_scan.gnmap",
            out / "nmap_scan.xml",
            out / "ports.txt",
            out / "urls_katana.txt",
            out / "wayback.txt",
            out / "whatweb.txt",
            out / "tls.txt",
            out / "gospider",
        ]
        p2_found = sum(
            1 for p in p2_candidates
            if (os.path.isdir(os.fspath(p)) and len(os.listdir(os.fspath(p))) > 0)
            or nonempty(p)
        )
        if p2_found < 2:
            missing.append(
                f"Phase 2 incomplete: only {p2_found}/2 enumeration output files found. "
                "Run port scanning (nmap/naabu) AND URL crawling (katana/gospider/waybackurls) first."
            )

        # Live probe: live_hosts.txt must exist
        live_hosts = out / "live_hosts.txt"
        if not nonempty(live_hosts) or count_lines(live_hosts) < 1:
            missing.append(
                "Live probe incomplete: output/live_hosts.txt is missing or empty. "
                "Run `httpx -l output/resolved.txt -status-code -o output/live_hosts.txt` first."
            )

        return missing

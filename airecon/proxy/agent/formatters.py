from __future__ import annotations

import asyncio
import json
import logging
import re
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .output_parser import parse_tool_output

if TYPE_CHECKING:
    from .models import AgentState

logger = logging.getLogger("airecon.agent")

# Cache for --help output per tool binary (avoids re-running)
_help_cache: dict[str, str] = {}
_help_lookup_inflight: set[str] = set()

# ---------------------------------------------------------------------------
# Inline security hints injected into tool output
# ---------------------------------------------------------------------------
# Loaded from port_correlations.json and tech_correlations.json at import time.
# No hardcoded data — single source of truth lives in the data/ directory.

_DATA_DIR = Path(__file__).parent.parent / "data"


def _load_port_hints() -> dict[int, str]:
    """Build {port: action_hint} from port_correlations.json."""
    try:
        raw = json.loads((_DATA_DIR / "port_correlations.json").read_text(encoding="utf-8"))
        hints: dict[int, str] = {}
        for port_str, info in raw.items():
            try:
                port = int(port_str)
            except ValueError:
                continue
            service = info.get("service", port_str)
            vulns: list[str] = info.get("vulns", [])
            tools: list[str] = info.get("tools", [])
            sev: str = info.get("severity", "")
            parts = [service]
            # Show first two vulns for breadth, highlight CVEs
            if vulns:
                parts.append("check: " + "; ".join(vulns[:2]))
            if tools:
                parts.append("tool: " + tools[0])
            if sev in ("HIGH", "CRITICAL"):
                parts.append(f"[{sev}]")
            hints[port] = " | ".join(parts)
        return hints
    except Exception as exc:
        logger.debug("Could not load port_correlations.json: %s", exc)
        return {}


def _load_tech_hints() -> dict[str, str]:
    """Build {tech_lower: action_hint} from tech_correlations.json."""
    try:
        raw = json.loads((_DATA_DIR / "tech_correlations.json").read_text(encoding="utf-8"))
        hints: dict[str, str] = {}
        for tech, info in raw.items():
            vulns: list[str] = info.get("vulns", [])
            paths: list[str] = info.get("paths", [])
            tools: list[str] = info.get("tools", [])
            parts = [tech.title()]
            if vulns:
                parts.append("check: " + "; ".join(vulns[:2]))
            if paths:
                parts.append("paths: " + ", ".join(paths[:3]))
            if tools:
                parts.append("tool: " + tools[0])
            hints[tech.lower()] = " | ".join(parts)
        return hints
    except Exception as exc:
        logger.debug("Could not load tech_correlations.json: %s", exc)
        return {}


_PORT_HINTS: dict[int, str] = _load_port_hints()
_TECH_HINTS: dict[str, str] = _load_tech_hints()

# Nmap/httpx open port pattern: "80/tcp  open" or "port 80 open" or "[80]"
_PORT_OPEN_RE = re.compile(
    r"\b(\d{2,5})/(?:tcp|udp)\s+open"      # nmap: 80/tcp  open
    r"|\bport\s+(\d{2,5})\s+open"           # generic: port 80 open
    r"|\[(\d{2,5})\]",                       # httpx: [80]
)

# All tech names use non-alphanumeric boundary matching to avoid false positives.
# e.g. "go" must not match "google", "flask" must not match "flasked",
# "django" must not match "djangorestframework".
_TECH_HINT_RE: dict[str, re.Pattern[str]] = {
    tech: re.compile(rf"(?<![a-z0-9]){re.escape(tech)}(?![a-z0-9])")
    for tech in _TECH_HINTS
}


def _extract_security_hints(output: str) -> list[str]:
    """Scan tool output for open ports and tech stack, return actionable hints."""
    hints: list[str] = []
    seen: set[int | str] = set()
    out_lower = output.lower()

    # Port-based hints
    for m in _PORT_OPEN_RE.finditer(output):
        port_str = m.group(1) or m.group(2) or m.group(3)
        if not port_str:
            continue
        port = int(port_str)
        if port in _PORT_HINTS and port not in seen:
            hints.append(f"  PORT {port}: {_PORT_HINTS[port]}")
            seen.add(port)

    # Technology-based hints — all use word-boundary regex to prevent false matches
    for tech, hint in _TECH_HINTS.items():
        if tech in seen:
            continue
        pattern = _TECH_HINT_RE[tech]
        if pattern.search(out_lower):
            hints.append(f"  TECH {tech.upper()}: {hint}")
            seen.add(tech)

    return hints


class _FormatterMixin:
    # Attributes provided by AgentLoop — declared here for type checkers only.
    if TYPE_CHECKING:
        state: AgentState
    def _smart_format_tool_result(
        self,
        tool_name: str,
        result: dict[str, Any],
        success: bool,
        command: str = "",
    ) -> str:
        # CTF mode: tight cap at 1000 chars per tool output — aligns with the
        # 1500-char per-message cap in _get_tool_result_cap() so the two passes
        # don't fight each other, and keeps the rolling window under budget.
        _ctf = getattr(self, "_ctf_mode", False)
        MAX_TOTAL = 1000 if _ctf else 12000

        if not success:
            error_msg = result.get("error", "") or ""
            stderr_msg = result.get("stderr", "") or ""
            stdout_msg = result.get("stdout", "") or ""
            exit_code = result.get("exit_code", "")

            parts = [f"COMMAND FAILED (exit code: {exit_code})"]
            if error_msg.strip():
                parts.append(f"ERROR: {error_msg.strip()}")
            if stderr_msg.strip() and stderr_msg.strip() != error_msg.strip():
                parts.append(f"STDERR: {stderr_msg.strip()[:2000]}")
            if stdout_msg.strip():
                parts.append(f"STDOUT: {stdout_msg.strip()[:2000]}")

            combined = (error_msg + stderr_msg + stdout_msg).lower()
            # Extract real tool binary from command (strip cd prefix, sudo,
            # etc.)
            cmd_clean = re.sub(
                r"^cd\s+/workspace/[^\s]+\s*&&\s*",
                "",
                command.strip())
            tokens = cmd_clean.split()
            tool_bin = tokens[0] if tokens else "tool"
            if tool_bin == "sudo" and len(tokens) > 1:
                tool_bin = tokens[1]

            if "command not found" in combined or (
                "no such file" in combined and "or directory" in combined and tool_bin
            ):
                parts.append(
                    f"TIP: Tool '{tool_bin}' is missing. You have full ROOT privileges to install it.\n"
                    f"SUGGESTED ACTION 1: Run `sudo apt update && sudo apt install -y {tool_bin}` or `pip install {tool_bin}`\n"
                    f"SUGGESTED ACTION 2: If not in APT/PIP, use `web_search` to find its Github repo, `git clone` it into `/home/pentester/tools/`, and compile it."
                )
            elif "permission denied" in combined and not command.strip().startswith(
                "sudo"
            ):
                parts.append(
                    f"TIP: Retry with elevated privileges: sudo {command.strip()[:80]}"
                )
            elif "connection refused" in combined or "connection timed out" in combined:
                parts.append(
                    "TIP: Target may be down or filtering. "
                    "Verify reachability: curl -I --max-time 5 <url>"
                )
            elif any(
                k in combined
                for k in (
                    "invalid option",
                    "unknown flag",
                    "unrecognized",
                    "syntax error",
                )
            ):
                # AUTO-CORRECT: Run --help and inject valid flags
                help_text = self._auto_help_lookup(tool_bin)
                if help_text:
                    parts.append(
                        f"AUTO-CORRECTION — valid flags for '{tool_bin}':\n{help_text}"
                    )
                else:
                    parts.append(
                        f"TIP: Flag/syntax error. Check: {tool_bin} --help | head -40"
                    )
            elif "no route to host" in combined:
                parts.append(
                    "TIP: Network unreachable from container. Check Docker network settings."
                )
            elif exit_code == 3 and "curl" in command:
                parts.append(
                    "TIP: curl exit code 3 = URL malformed. "
                    "Special characters in the payload must be percent-encoded:\n"
                    "  ' → %27   space → %20   ( → %28   ) → %29   & → %26\n"
                    "OPTION 1 — encode manually: ?lang=test%27%20AND%20SLEEP%283%29--\n"
                    "OPTION 2 — use --data-urlencode (GET): "
                    "curl -sk -G https://target.com/path --data-urlencode 'param=payload with spaces'"
                )
            else:
                parts.append(
                    "ACTION REQUIRED: Analyze the error. "
                    "Common causes: wrong flags (run `tool --help`), missing file, "
                    "permission denied, network timeout."
                )
            return "\n".join(parts)

        if tool_name == "execute":
            stdout = (
                result.get("stdout", "")
                or (
                    result.get("result", "")
                    if isinstance(result.get("result"), str)
                    else ""
                )
                or ""
            )
            if not stdout.strip():
                return (
                    "Command executed successfully with NO OUTPUT.\n"
                    "WARNING: Empty output does NOT necessarily mean 0 results.\n"
                    "Possible causes:\n"
                    "- The tool found 0 results\n"
                    "- Output was written directly to a file (check: ls output/)\n"
                    "- A permission error occurred silently\n"
                    "- The tool crashed without printing an error\n"
                    "ACTION: Verify the tool ran correctly before concluding no results. "
                    "If a file was written, read it with: cat output/<file>. "
                    "DO NOT invent results."
                )

            # Strip HTML before parsing — raw HTML floods context with tag soup.
            # Applied early so both structured parser and raw fallback get clean text.
            _stdout_head = stdout[:400].lower()
            _is_html = (
                "<!doctype html" in _stdout_head
                or ("<html" in _stdout_head and "<head" in _stdout_head)
                or ("<html" in _stdout_head and "<body" in _stdout_head)
            )
            if _is_html:
                # Remove script/style blocks (no useful pentest info)
                stdout = re.sub(
                    r"<(script|style)[^>]*>.*?</(script|style)>",
                    " ",
                    stdout,
                    flags=re.DOTALL | re.IGNORECASE,
                )
                # Strip all remaining HTML tags
                stdout = re.sub(r"<[^>]+>", " ", stdout)
                # Collapse whitespace and keep non-empty lines
                stdout = "\n".join(
                    ln.strip()
                    for ln in re.sub(r"[ \t]+", " ", stdout).splitlines()
                    if ln.strip()
                )

            # Try structured parsing first
            parsed = parse_tool_output(command, stdout)
            if parsed and parsed.total_count > 0:
                parts = [parsed.summary]
                if parsed.items:
                    parts.append("Key items:")
                    for item in parsed.items:
                        parts.append(f"  {item}")
                    if parsed.total_count > len(parsed.items):
                        parts.append(
                            f"  ... and {parsed.total_count - len(parsed.items)} more"
                        )
                parts.append(
                    f"\nTOTAL: {parsed.total_count} items. Full output saved to file."
                )
                body = "\n".join(parts)
                if len(body) > MAX_TOTAL:
                    body = body[:MAX_TOTAL] + "\n... (truncated)"
                # Append inline security hints
                hints = _extract_security_hints(stdout)
                if hints:
                    body += "\n\n[SECURITY CONTEXT — act on these]\n" + "\n".join(hints)
                return body

            # Fallback: raw truncation (HTML already stripped above if applicable)
            lines = stdout.strip().split("\n")
            total = len(lines)
            # Use tighter head/tail in CTF mode to minimise context usage.
            _head_n, _tail_n = (30, 5) if _ctf else (60, 15)
            if total > (_head_n + _tail_n):
                head = "\n".join(lines[:_head_n])
                tail = "\n".join(lines[-_tail_n:])
                body = (
                    f"{head}\n\n"
                    f"... [{total - _head_n - _tail_n} more lines] ...\n\n"
                    f"{tail}\n\n"
                    f"TOTAL OUTPUT: {total} lines. Full output saved to file."
                )
            else:
                body = stdout.strip()
            if len(body) > MAX_TOTAL:
                body = body[:MAX_TOTAL] + "\n... (truncated)"

            # Append inline security hints for ports/techs found in output
            hints = _extract_security_hints(stdout)
            if hints:
                body += "\n\n[SECURITY CONTEXT — act on these]\n" + "\n".join(hints)
            return body

        if tool_name == "browser_action" and isinstance(result, dict):
            res_copy = dict(result)
            if "screenshot" in res_copy:
                res_copy["screenshot"] = "<base64_image_hidden_from_context>"
            content = json.dumps(res_copy, default=str)
        elif (
            isinstance(result, dict)
            and "result" in result
            and isinstance(result["result"], str)
        ):
            content = result["result"]
        else:
            content = json.dumps(result, default=str)
        if len(content) > MAX_TOTAL:
            content = content[:MAX_TOTAL] + "\n... (truncated)"
        return content

    def _build_recent_history_context(self, last_n: int = 10) -> str:
        recent = self.state.tool_history[-last_n:
                                         ] if self.state.tool_history else []
        if not recent:
            return ""

        lines = [f"[SYSTEM: RECENT EXECUTIONS — last {len(recent)} calls]"]
        for i, rec in enumerate(recent, 1):
            status = "OK" if rec.status == "success" else "FAIL"
            detail = ""
            if rec.tool_name == "execute":
                cmd = rec.arguments.get("command", "")
                cmd = re.sub(
                    r"^cd\s+/workspace/[^\s]+\s*&&\s*",
                    "",
                    cmd).strip()
                detail = f": {cmd[:100]}"
            elif rec.tool_name == "browser_action":
                action = rec.arguments.get("action", "?")
                url = rec.arguments.get("url", "")
                detail = f" action={action} url={url}"
            elif rec.tool_name == "web_search":
                detail = f": {rec.arguments.get('query', '')[:60]}"
            lines.append(
                f"  {i}. [{status}] {rec.tool_name}{detail} ({rec.duration:.1f}s)"
            )

        return "\n".join(lines)

    def _truncate_result(
            self, result: dict[str, Any], max_len: int = 500) -> str:
        if not result.get("success", False):
            error = result.get("error", "") or ""
            stderr = result.get("stderr", "") or ""
            stdout = result.get("stdout", "") or ""
            exit_code = result.get("exit_code", "")
            detail = error.strip() or stderr.strip() or stdout.strip()
            if not detail:
                detail = f"Command failed (exit code: {exit_code})"
            if len(detail) > max_len:
                detail = detail[:max_len] + "... (truncated)"
            return f"ERROR: {detail}"

        res_data = result.get("result", "")
        if isinstance(res_data, dict) and "stdout" in res_data:
            stdout = res_data["stdout"].strip()
        elif isinstance(res_data, str):
            stdout = res_data.strip()
        else:
            stdout = ""

        if stdout:
            if len(stdout) > max_len * 2:
                summary = ""
                if "subdomains found" in stdout.lower():
                    summary = "(Subdomain Scan Results) "
                elif "vulnerabilities found" in stdout.lower():
                    summary = "(Scan Results) "
                return f"Success {summary}-- Output too large ({len(stdout)} chars). Check output file."

            lines = [line for line in stdout.split("\n") if line.strip()]
            count = len(lines)
            is_list = all(
                len(line) < 100 for line in lines[:5]) if lines else False
            if count > 10:
                if is_list:
                    preview = "\n".join(f"  {line}" for line in lines[:8])
                    return f"Success -- Found {count} items.\n{preview}\n  ... ({count - 8} more)"
                else:
                    preview = "\n".join(f"  {line}" for line in lines[:8])
                    return f"Success\n{preview}\n  ... ({count - 8} more lines)"
            else:
                return "Success\n" + "\n".join(f"  {line}" for line in lines)

        if not res_data:
            return "Command executed (no output)."
        try:
            text = json.dumps(result, default=str)
            if len(text) > max_len:
                return f"Result too large ({len(text)} chars). Check output file."
            return text
        except Exception:
            return "Result (unserializable). Check output file."

    def _auto_help_lookup(self, tool_binary: str) -> str | None:
        """Run <tool> --help inside Docker and extract valid flags.

        In async runtime, this method warms the cache in the background and
        returns cached results when available.

        Returns compact help text or None if lookup fails.
        Caches results to avoid re-running for the same tool.
        """
        if tool_binary in _help_cache:
            return _help_cache[tool_binary] if _help_cache[tool_binary] else None

        # Skip if engine not available
        engine = getattr(self, "engine", None)
        if not engine:
            return None

        def _blocking_lookup() -> str | None:
            # Use thread pool to avoid asyncio event loop issues
            import concurrent.futures

            try:
                def _run_help():
                    try:
                        loop = asyncio.new_event_loop()
                        asyncio.set_event_loop(loop)
                        try:
                            return loop.run_until_complete(
                                engine.execute_tool(
                                    "execute",
                                    {"command": f"{tool_binary} --help 2>&1 | head -60"},
                                )
                            )
                        finally:
                            loop.close()
                    except Exception:
                        return None

                with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                    future = pool.submit(_run_help)
                    result = future.result(timeout=15)
            except Exception:
                return None

            if result is None:
                return None
            stdout = result.get("stdout", "") or result.get("result", "") or ""
            if not stdout.strip() or len(stdout) < 20:
                return None

            # Extract flag lines (lines starting with -, or containing --)
            lines = stdout.strip().split("\n")
            flag_lines: list[str] = []
            usage_lines: list[str] = []
            for line in lines:
                stripped = line.strip()
                if stripped.startswith("-") or "  -" in line:
                    flag_lines.append(stripped)
                elif stripped.lower().startswith("usage:") or stripped.lower().startswith(
                    "synopsis"
                ):
                    usage_lines.append(stripped)

            if not flag_lines and not usage_lines:
                # No flags found — return first 30 lines as-is
                return "\n".join(lines[:30])

            parts: list[str] = []
            if usage_lines:
                parts.append("USAGE: " + usage_lines[0])
            if flag_lines:
                parts.append("VALID FLAGS:")
                for flag in flag_lines[:25]:  # Cap at 25 flags
                    parts.append(f"  {flag}")

            compact = "\n".join(parts)
            logger.info(
                "Auto-help lookup for '%s': %d flags found",
                tool_binary,
                len(flag_lines),
            )
            return compact

        try:
            running_loop = asyncio.get_running_loop()
        except RuntimeError:
            running_loop = None

        # Async runtime: warm cache in background without blocking the loop.
        if running_loop is not None:
            if tool_binary not in _help_lookup_inflight:
                _help_lookup_inflight.add(tool_binary)

                async def _populate_cache() -> None:
                    try:
                        compact = await asyncio.to_thread(_blocking_lookup)
                        _help_cache[tool_binary] = compact or ""
                    except Exception:
                        _help_cache[tool_binary] = ""
                    finally:
                        _help_lookup_inflight.discard(tool_binary)

                running_loop.create_task(_populate_cache())
            return None

        # Sync runtime: resolve immediately.
        compact = _blocking_lookup()
        _help_cache[tool_binary] = compact or ""
        return compact

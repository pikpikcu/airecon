from __future__ import annotations

import asyncio
import json
import logging
import re
from typing import Any

from .output_parser import parse_tool_output

logger = logging.getLogger("airecon.agent")

# Cache for --help output per tool binary (avoids re-running)
_help_cache: dict[str, str] = {}


class _FormatterMixin:

    def _smart_format_tool_result(
        self,
        tool_name: str,
        result: dict[str, Any],
        success: bool,
        command: str = "",
    ) -> str:
        MAX_TOTAL = 4000  # Reduced from 8000 — structured parsing extracts key data

        if not success:
            error_msg  = result.get("error",  "") or ""
            stderr_msg = result.get("stderr", "") or ""
            stdout_msg = result.get("stdout", "") or ""
            exit_code  = result.get("exit_code", "")

            parts = [f"COMMAND FAILED (exit code: {exit_code})"]
            if error_msg.strip():
                parts.append(f"ERROR: {error_msg.strip()}")
            if stderr_msg.strip() and stderr_msg.strip() != error_msg.strip():
                parts.append(f"STDERR: {stderr_msg.strip()[:2000]}")
            if stdout_msg.strip():
                parts.append(f"STDOUT: {stdout_msg.strip()[:2000]}")

            combined = (error_msg + stderr_msg + stdout_msg).lower()
            # Extract real tool binary from command (strip cd prefix, sudo, etc.)
            cmd_clean = re.sub(r"^cd\s+/workspace/[^\s]+\s*&&\s*", "", command.strip())
            tokens = cmd_clean.split()
            tool_bin = tokens[0] if tokens else "tool"
            if tool_bin == "sudo" and len(tokens) > 1:
                tool_bin = tokens[1]

            if "command not found" in combined or (
                "no such file" in combined and "or directory" in combined and tool_bin
            ):
                parts.append(
                    f"TIP: '{tool_bin}' may not be installed. "
                    f"Verify: which {tool_bin} | "
                    f"Install: sudo apt-get install -y {tool_bin} or pip3/go install equivalent."
                )
            elif "permission denied" in combined and not command.strip().startswith("sudo"):
                parts.append(f"TIP: Retry with elevated privileges: sudo {command.strip()[:80]}")
            elif "connection refused" in combined or "connection timed out" in combined:
                parts.append(
                    "TIP: Target may be down or filtering. "
                    "Verify reachability: curl -I --max-time 5 <url>"
                )
            elif any(k in combined for k in ("invalid option", "unknown flag", "unrecognized", "syntax error")):
                # AUTO-CORRECT: Run --help and inject valid flags
                help_text = self._auto_help_lookup(tool_bin)
                if help_text:
                    parts.append(f"AUTO-CORRECTION — valid flags for '{tool_bin}':\n{help_text}")
                else:
                    parts.append(f"TIP: Flag/syntax error. Check: {tool_bin} --help | head -40")
            elif "no route to host" in combined:
                parts.append("TIP: Network unreachable from container. Check Docker network settings.")
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
                or (result.get("result", "") if isinstance(result.get("result"), str) else "")
                or ""
            )
            if not stdout.strip():
                return (
                    "Command executed successfully with NO OUTPUT.\n"
                    "This means:\n"
                    "- The tool found 0 results (not an error)\n"
                    "- Output was written directly to a file (check: ls output/)\n"
                    "- Or the tool ran silently\n"
                    "DO NOT invent results. If a file was written, read it with: cat output/<file>"
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
                        parts.append(f"  ... and {parsed.total_count - len(parsed.items)} more")
                parts.append(f"\nTOTAL: {parsed.total_count} items. Full output saved to file.")
                body = "\n".join(parts)
                if len(body) > MAX_TOTAL:
                    body = body[:MAX_TOTAL] + "\n... (truncated)"
                return body

            # Fallback: raw truncation
            lines = stdout.strip().split("\n")
            total = len(lines)
            if total > 100:
                head = "\n".join(lines[:60])
                tail = "\n".join(lines[-15:])
                body = (
                    f"{head}\n\n"
                    f"... [{total - 75} more lines] ...\n\n"
                    f"{tail}\n\n"
                    f"TOTAL OUTPUT: {total} lines. Full output saved to file."
                )
            else:
                body = stdout.strip()
            if len(body) > MAX_TOTAL:
                body = body[:MAX_TOTAL] + "\n... (truncated)"
            return body

        if isinstance(result, dict) and "result" in result and isinstance(result["result"], str):
            content = result["result"]
        else:
            content = json.dumps(result, default=str)
        if len(content) > MAX_TOTAL:
            content = content[:MAX_TOTAL] + "\n... (truncated)"
        return content

    def _build_recent_history_context(self, last_n: int = 10) -> str:
        recent = self.state.tool_history[-last_n:] if self.state.tool_history else []  # type: ignore[attr-defined]
        if not recent:
            return ""

        lines = [f"[SYSTEM: RECENT EXECUTIONS — last {len(recent)} calls]"]
        for i, rec in enumerate(recent, 1):
            status = "OK" if rec.status == "success" else "FAIL"
            detail = ""
            if rec.tool_name == "execute":
                cmd = rec.arguments.get("command", "")
                cmd = re.sub(r"^cd\s+/workspace/[^\s]+\s*&&\s*", "", cmd).strip()
                detail = f": {cmd[:100]}"
            elif rec.tool_name == "browser_action":
                detail = f" action={rec.arguments.get('action','?')} url={rec.arguments.get('url','')}"
            elif rec.tool_name == "web_search":
                detail = f": {rec.arguments.get('query','')[:60]}"
            lines.append(f"  {i}. [{status}] {rec.tool_name}{detail} ({rec.duration:.1f}s)")

        return "\n".join(lines)

    def _truncate_result(self, result: dict[str, Any], max_len: int = 500) -> str:
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

            lines = [l for l in stdout.split("\n") if l.strip()]
            count = len(lines)
            is_list = all(len(l) < 100 for l in lines[:5]) if lines else False
            if count > 10:
                if is_list:
                    preview = "\n".join(f"  {line}" for line in lines[:8])
                    return f"Success -- Found {count} items.\n{preview}\n  ... ({count-8} more)"
                else:
                    preview = "\n".join(f"  {line}" for line in lines[:8])
                    return f"Success\n{preview}\n  ... ({count-8} more lines)"
            else:
                return f"Success\n" + "\n".join(f"  {line}" for line in lines)

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

        Returns compact help text or None if lookup fails.
        Caches results to avoid re-running for the same tool.
        """
        global _help_cache
        if tool_binary in _help_cache:
            return _help_cache[tool_binary]

        # Skip if engine not available
        engine = getattr(self, "engine", None)
        if not engine:
            return None

        try:
            # Run --help via Docker (sync wrapper for async engine)
            result = asyncio.get_event_loop().run_until_complete(
                engine.execute_tool("execute", {"command": f"{tool_binary} --help 2>&1 | head -60"})
            )
        except RuntimeError:
            # If we're already in an async loop, use a thread
            import concurrent.futures
            try:
                with concurrent.futures.ThreadPoolExecutor() as pool:
                    future = pool.submit(
                        asyncio.run,
                        engine.execute_tool("execute", {"command": f"{tool_binary} --help 2>&1 | head -60"})
                    )
                    result = future.result(timeout=10)
            except Exception:
                _help_cache[tool_binary] = ""
                return None
        except Exception:
            _help_cache[tool_binary] = ""
            return None

        stdout = result.get("stdout", "") or result.get("result", "") or ""
        if not stdout.strip() or len(stdout) < 20:
            _help_cache[tool_binary] = ""
            return None

        # Extract flag lines (lines starting with -, or containing --)
        lines = stdout.strip().split("\n")
        flag_lines = []
        usage_lines = []
        for line in lines:
            stripped = line.strip()
            if stripped.startswith("-") or "  -" in line:
                flag_lines.append(stripped)
            elif stripped.lower().startswith("usage:") or stripped.lower().startswith("synopsis"):
                usage_lines.append(stripped)

        if not flag_lines and not usage_lines:
            # No flags found — return first 30 lines as-is
            compact = "\n".join(lines[:30])
            _help_cache[tool_binary] = compact
            return compact

        parts = []
        if usage_lines:
            parts.append("USAGE: " + usage_lines[0])
        if flag_lines:
            parts.append("VALID FLAGS:")
            for f in flag_lines[:25]:  # Cap at 25 flags
                parts.append(f"  {f}")

        compact = "\n".join(parts)
        _help_cache[tool_binary] = compact
        logger.info(f"Auto-help lookup for '{tool_binary}': {len(flag_lines)} flags found")
        return compact


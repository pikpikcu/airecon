from __future__ import annotations

import asyncio
import logging
import re
import time
from typing import Any
from urllib.parse import urlparse


from ..browser import browser_action
from ..config import get_config, get_workspace_root
from ..data_loader import load_tools_meta
from ..scope import check_network_tool_scope
from .executors_catalog import (
    _RESULT_TRUNCATION_THRESHOLD,
)

logger = logging.getLogger("airecon.agent")

# ── Load browser config from tools_meta ────────────────────────────────
_BROWSER_CONFIG = load_tools_meta().get("browser_config", {})
_TRACKING_URL_PATTERNS = _BROWSER_CONFIG.get("tracking_url_patterns", [])
_TRACKING_QUERY_PARAMS = _BROWSER_CONFIG.get("tracking_query_params", [])
_GUIDANCE_MESSAGES = _BROWSER_CONFIG.get("guidance_messages", {})

_COMPILED_TRACKING_PATTERNS = [
    re.compile(p, re.IGNORECASE) for p in _TRACKING_URL_PATTERNS
]


def _is_tracking_or_asset_url(url: str) -> bool:
    for pattern in _COMPILED_TRACKING_PATTERNS:
        if pattern.search(url):
            return True
    # Check for random-looking query params (tracking IDs, timestamps)
    parsed = urlparse(url)
    query = parsed.query.lower()
    param_count = sum(1 for p in _TRACKING_QUERY_PARAMS if p in query)
    if param_count >= 2:
        return True
    # Check for very long random-looking path segments
    path = parsed.path
    if re.search(r"/[a-f0-9]{8,}-[a-f0-9]{4,}", path):
        return True
    return False


def _extract_domain_from_url(page_url: str) -> str:
    if not page_url:
        return "unknown"
    netloc = urlparse(page_url).netloc.replace(":", "_")
    return netloc or "unknown"


def _save_browser_artifact(
    host_output: Any,
    artifact_type: str,
    page_url: str,
    content: str,
    extra_data: dict[str, Any] | None = None,
) -> tuple[str, str]:
    domain = _extract_domain_from_url(page_url)
    file_map = {
        "source": "source_{}.txt",
        "console": "console_{}.txt",
        "network": "network_{}.txt",
    }
    filename = file_map.get(artifact_type, f"{artifact_type}_{{}}.txt").format(domain)
    filepath = host_output / filename

    with open(filepath, "w", encoding="utf-8") as f:
        f.write(f"URL: {page_url}\n{'=' * 60}\n")
        f.write(content)

    saved_path = f"output/{filename}"

    # Build the note message based on artifact type and extra data
    if artifact_type == "source":
        js_count = extra_data.get("js_count", 0) if extra_data else 0
        js_note = (
            f" {js_count} JS files extracted to output/js_files.txt."
            if js_count
            else ""
        )
        note = f"[Auto-saved full page source ({len(content)} chars) to {saved_path}.{js_note} Analyze JS files for API endpoints, secrets, and vulnerabilities.]"
    elif artifact_type == "console":
        log_count = extra_data.get("log_count", 0) if extra_data else 0
        note = f"[Auto-saved {log_count} console logs to {saved_path}. Check for errors, debug info, and leaked sensitive data.]"
    elif artifact_type == "network":
        req_count = extra_data.get("req_count", 0) if extra_data else 0
        api_count = extra_data.get("api_count", 0) if extra_data else 0
        note = f"[Auto-saved {req_count} network entries to {saved_path}. {api_count} XHR/Fetch API calls detected. Review for API endpoints, auth tokens, and sensitive data in responses.]"
    else:
        note = f"[Auto-saved {artifact_type} to {saved_path}.]"

    return saved_path, note


class _BrowserExecutorMixin:
    def _format_network_entry(self, entry: dict[str, Any]) -> str:
        lines = []
        etype = entry.get("type", "?")
        url = entry.get("url", "")

        if etype == "request":
            method = entry.get("method", "GET")
            resource_type = entry.get("resource_type", "")
            lines.append(f">> {method} [{resource_type}] {url}")
            if entry.get("post_data"):
                lines.append(f"   BODY: {entry['post_data']}")
        elif etype == "response":
            status = entry.get("status", "")
            content_type = entry.get("content_type", "")
            lines.append(f"<< {status} {url}  [{content_type}]")
            if entry.get("body"):
                lines.append(f"   RESPONSE: {entry['body']}")

        lines.append("")
        return "\n".join(lines)

    async def _execute_local_browser_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> tuple[bool, float, dict[str, Any], str | None]:
        self._last_output_file = None

        scope_error = check_network_tool_scope(tool_name, arguments)
        if scope_error:
            return False, 0.0, {"success": False, "error": scope_error}, None

        # ── Pre-filter: block tracking/analytics URLs before browser ──
        action = arguments.get("action", "")
        url = arguments.get("url", "")
        if action == "goto" and url:
            if _is_tracking_or_asset_url(url):
                return (
                    False,
                    0.0,
                    {
                        "success": False,
                        "blocked_by_filter": True,
                        "reason": _GUIDANCE_MESSAGES.get(
                            "tracking_url_blocked",
                            "URL blocked: tracking/analytics/static asset pattern.",
                        ),
                        "url": url[:200],
                        "next_action": _GUIDANCE_MESSAGES.get(
                            "tracking_url_suggestion",
                            "Do NOT use browser_action for this URL. Use curl or httpx instead.",
                        ),
                    },
                    None,
                )

        args_key = self._normalize_args_for_dedup(tool_name, arguments)

        _browser_timeout = float(get_config().browser_action_timeout)
        start_time = time.time()
        try:
            try:
                result = await asyncio.wait_for(
                    asyncio.to_thread(browser_action, **arguments),
                    timeout=_browser_timeout,
                )
            except asyncio.TimeoutError:
                asyncio.get_running_loop().run_in_executor(
                    None,
                    lambda: browser_action(action="close"),
                )
                return (
                    False,
                    _browser_timeout,
                    {
                        "success": False,
                        "error": f"Browser action timed out after {_browser_timeout:.0f}s. Browser close requested.",
                    },
                    None,
                )

            if arguments.get("action") == "launch" and hasattr(self, "_session"):
                cookies = getattr(self._session, "auth_cookies", [])
                if cookies:
                    try:
                        await asyncio.to_thread(
                            browser_action, action="inject_cookies", cookies=cookies
                        )
                        if "url" in arguments:
                            await asyncio.to_thread(
                                browser_action, action="goto", url=arguments["url"]
                            )
                    except Exception as e:
                        logger.warning("Failed to auto-inject session cookies: %s", e)

            success = not (isinstance(result, dict) and "error" in result)
            if not success and isinstance(result, dict):
                error_str = str(result.get("error", ""))
                # Redirect loop — detect, register dead URL, give guidance
                if "Too many redirects" in error_str or "redirect" in error_str.lower():
                    redirected_url = ""
                    _final_m = re.search(r"final URL:\s*(\S+)", error_str)
                    if _final_m:
                        redirected_url = _final_m.group(1)

                    # Register the redirect target as a dead/blocked URL
                    if redirected_url and hasattr(self, "state"):
                        self.state.add_dead_host(redirected_url)
                        logger.info(
                            "Dead URL registered from browser redirect loop: %s",
                            redirected_url[:200],
                        )

                    result = {
                        "success": False,
                        "redirect_loop": True,
                        "error": error_str,
                        "message": _GUIDANCE_MESSAGES.get(
                            "redirect_loop_detected",
                            "The page redirect chain exceeded 10 hops.",
                        ),
                        "final_url": redirected_url[:200],
                        "next_action": _GUIDANCE_MESSAGES.get(
                            "redirect_loop_suggestion",
                            "Do NOT retry the same URL. It has been registered as dead.",
                        ),
                    }
                elif "success" not in result:
                    result = {"success": False, "error": result.get("error", error_str)}
            elif "success" not in result:
                result = {"success": success, "result": result}

            if isinstance(result, dict) and result.get("domain_dead"):
                host = result.get("host", "")
                if host and hasattr(self, "state"):
                    added = self.state.add_dead_host(host)
                    if added:
                        logger.info(
                            "Dead host auto-registered from browser_action: %s", host
                        )

                if "next_action" not in result:
                    result["next_action"] = (
                        f"SKIP: {host} is unreachable. "
                        + _GUIDANCE_MESSAGES.get(
                            "domain_dead",
                            "Remove from target list and proceed to next subdomain.",
                        )
                    )

            if success and self.state.active_target:
                action = arguments.get("action")
                action_artifact_map = {
                    "view_source": ("source", "full_page_source"),
                    "get_console_logs": ("console", "console_logs"),
                    "get_network_logs": ("network", None),
                }
                if action in action_artifact_map and self.state.active_target:
                    try:
                        inner = result.get("result", {})
                        if not isinstance(inner, dict):
                            inner = {}
                        page_url = inner.get("url", "")
                        host_output = (
                            get_workspace_root() / self.state.active_target / "output"
                        )
                        host_output.mkdir(parents=True, exist_ok=True)

                        artifact_type, body_key = action_artifact_map[action]

                        if artifact_type == "source":
                            source_full = (
                                inner.get(body_key) or inner.get("page_source") or ""
                            )
                            js_urls = list(
                                dict.fromkeys(
                                    re.findall(
                                        r'src=["\']([^"\']*\.js[^"\']*)["\']',
                                        source_full,
                                    )
                                    + re.findall(
                                        r'https?://[^\s"\'<>]+\.js(?:\?[^\s"\'<>]*)?',
                                        source_full,
                                    )
                                )
                            )
                            if js_urls:
                                js_file = host_output / "js_files.txt"
                                with open(js_file, "a", encoding="utf-8") as f:
                                    f.write(
                                        f"\n{'=' * 60}\nSOURCE: {page_url}\n{'=' * 60}\n"
                                    )
                                    for j in js_urls:
                                        f.write(j + "\n")
                            content = source_full
                            extra = {"js_count": len(js_urls)}
                        elif artifact_type == "console":
                            logs = inner.get(body_key, [])
                            content = "\n".join(
                                f"[{log_entry.get('type', 'log')}] {log_entry.get('text', '')}"
                                for log_entry in logs
                            )
                            extra = {"log_count": len(logs)}
                        else:  # network
                            reqs = inner.get("network_requests", [])
                            content = (
                                f"Total entries: {len(reqs)}\n{'=' * 60}\n\n"
                                + "\n".join(self._format_network_entry(e) for e in reqs)
                            )
                            extra = {"req_count": len(reqs)}
                            inner.pop("network_requests", None)

                        saved_path, note = _save_browser_artifact(
                            host_output,
                            artifact_type,
                            page_url,
                            content,
                            extra_data=extra,
                        )
                        if body_key:
                            inner.pop(body_key, None)
                        inner["auto_saved"] = saved_path
                        inner["note"] = note
                        result = {"success": True, "result": inner}
                        self._last_output_file = saved_path

                    except Exception as _e:
                        logger.warning("Failed to auto-save browser result: %s", _e)

            try:
                self._save_tool_output(tool_name, arguments, result)
            except Exception as _e:
                logger.debug("Could not save tool output: %s", _e)
        except Exception as e:
            success = False
            result = {"success": False, "error": str(e)}
            logger.error("Browser tool exec error: %s", e)

        duration = time.time() - start_time

        history_result = result
        if (
            success
            and self._last_output_file
            and len(str(result)) > _RESULT_TRUNCATION_THRESHOLD
        ):
            history_result = {
                "success": True,
                "result": f"<Result truncated. Full output in {self._last_output_file}>",
                "truncated": True,
            }

        self._append_tool_history(
            tool_name=tool_name,
            arguments=arguments,
            result=history_result,
            duration=duration,
            status="success" if success else "error",
        )

        if success:
            self._executed_tool_counts[args_key] = (
                self._executed_tool_counts.get(args_key, 0) + 1
            )
        return success, duration, result, self._last_output_file

from __future__ import annotations

import json
import logging
import re
import shlex
import time
import uuid
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from .models import ToolExecution
from ..config import get_workspace_root

logger = logging.getLogger("airecon.agent")


def _profile_code_analysis_target(host_path: Path) -> dict[str, Any]:
    profile = {
        "languages": [],
        "rules": [],
        "signals": [],
    }
    if not host_path.exists():
        return profile

    if host_path.is_file():
        files = [host_path]
        base_dir = host_path.parent
    else:
        base_dir = host_path
        files = []
        for item in sorted(host_path.rglob("*")):
            if not item.is_file():
                continue
            files.append(item)
            if len(files) >= 250:
                break

    languages: set[str] = set()
    rules: set[str] = set()
    signals: list[str] = []

    for item in files:
        rel = str(item.relative_to(base_dir)) if item != host_path else item.name
        rel_lower = rel.lower()
        name_lower = item.name.lower()
        suffix = item.suffix.lower()

        if suffix == ".py" or name_lower in {"pyproject.toml", "requirements.txt", "setup.py"}:
            languages.add("python")
            rules.add("p/python")
        if suffix in {".js", ".jsx"} or name_lower == "package.json":
            languages.add("javascript")
            rules.add("p/javascript")
        if suffix in {".ts", ".tsx"} or name_lower == "tsconfig.json":
            languages.add("typescript")
            rules.add("p/typescript")
        if name_lower in {"dockerfile", "docker-compose.yml", "docker-compose.yaml"}:
            rules.add("p/docker")
        if ".github/workflows/" in rel_lower or name_lower == ".gitlab-ci.yml":
            rules.add("p/ci")
        if name_lower.startswith(".env") or suffix in {".pem", ".p12", ".kdbx"}:
            rules.add("p/secrets")

    profile["languages"] = sorted(languages)
    profile["rules"] = sorted(rules)
    profile["signals"] = signals[:8]
    return profile


_SET_COOKIE_RE = re.compile(r"(?mi)^set-cookie:\s*([^;\r\n]+)", re.MULTILINE)
_COOKIE_NAME_BLACKLIST = {"", "expires", "path", "domain", "max-age", "secure", "httponly", "samesite"}


def _registrable_host(url: str) -> str:
    try:
        host = urlparse(url).hostname or ""
    except Exception as _e:
        logger.debug("registrable_host parse error: %s", _e)
        return ""
    return host.strip().lower().rstrip(".")


def _parse_set_cookie_headers(raw_http: str) -> dict[str, str]:
    cookies: dict[str, str] = {}
    if not raw_http:
        return cookies
    for match in _SET_COOKIE_RE.finditer(raw_http):
        pair = match.group(1).strip()
        if "=" not in pair:
            continue
        name, value = pair.split("=", 1)
        name = name.strip()
        if name.lower() in _COOKIE_NAME_BLACKLIST:
            continue
        cookies[name] = value.strip()
    return cookies


# Common CSRF/authenticity token patterns found across frameworks. The LLM
# is responsible for deciding *whether* to use a captured token on its next
# request — Python only observes and surfaces the signal.
_CSRF_META_RE = re.compile(
    r"""<meta[^>]+name\s*=\s*['"](?P<name>csrf[_-]?token|csrf-param|authenticity[_-]?token)['"][^>]*content\s*=\s*['"](?P<val>[^'"\s]{8,200})['"]""",
    re.IGNORECASE,
)
_CSRF_INPUT_RE = re.compile(
    r"""<input[^>]+name\s*=\s*['"](?P<name>_?csrf[_-]?token|_csrf|csrfmiddlewaretoken|authenticity_token|__RequestVerificationToken)['"][^>]*value\s*=\s*['"](?P<val>[^'"\s]{8,400})['"]""",
    re.IGNORECASE,
)
_CSRF_COOKIE_NAMES = frozenset(
    n.lower()
    for n in (
        "xsrf-token",
        "csrftoken",
        "csrf-token",
        "_csrf",
        "x-csrf-token",
    )
)


def _extract_csrf_token(
    body_excerpt: str, harvested_cookies: dict[str, str]
) -> dict[str, str]:
    if harvested_cookies:
        for name, value in harvested_cookies.items():
            if not name:
                continue
            if name.lower() in _CSRF_COOKIE_NAMES and value:
                return {
                    "token": value.strip()[:400],
                    "field": name,
                    "source": "cookie",
                }
    if body_excerpt:
        m_meta = _CSRF_META_RE.search(body_excerpt)
        if m_meta:
            return {
                "token": m_meta.group("val").strip()[:400],
                "field": m_meta.group("name"),
                "source": "meta",
            }
        m_input = _CSRF_INPUT_RE.search(body_excerpt)
        if m_input:
            return {
                "token": m_input.group("val").strip()[:400],
                "field": m_input.group("name"),
                "source": "form",
            }
    return {}


def _detect_rate_limit(status_code: int, headers: dict[str, str] | None) -> dict[str, Any] | None:
    if headers is None:
        headers = {}
    lower = {k.lower(): str(v) for k, v in headers.items()}
    signal: dict[str, Any] = {}

    if status_code == 429:
        signal["kind"] = "rate_limited"
    elif status_code == 503 and ("retry-after" in lower or "rate" in lower.get("server", "").lower()):
        signal["kind"] = "service_unavailable_throttle"
    else:
        remaining = lower.get("x-ratelimit-remaining") or lower.get("ratelimit-remaining")
        if remaining and remaining.strip().isdigit() and int(remaining.strip()) == 0:
            signal["kind"] = "quota_exhausted"

    if not signal:
        return None

    retry_after = lower.get("retry-after", "").strip()
    if retry_after:
        signal["retry_after_raw"] = retry_after[:40]
        try:
            signal["retry_after_seconds"] = int(retry_after)
        except ValueError:
            # HTTP-date form — LLM can parse if needed
            pass
    reset = lower.get("x-ratelimit-reset") or lower.get("ratelimit-reset")
    if reset:
        signal["reset_at"] = reset[:40]
    return signal


class _ObserveExecutorMixin:
    async def _exec_record_hypothesis(
        self,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> tuple[bool, float, dict[str, Any], str | None]:
        start_time = time.time()

        claim = str(arguments.get("claim", "")).strip()
        status = str(arguments.get("status", "pending")).lower()
        hyp_id = str(arguments.get("hypothesis_id", "")).strip()
        evidence = str(arguments.get("evidence", "")).strip()
        test_plan = str(arguments.get("test_plan", "")).strip()
        phase = str(arguments.get("phase", "RECON")).upper()

        valid_statuses = {"pending", "testing", "confirmed", "refuted"}
        if status not in valid_statuses:
            return (
                False,
                time.time() - start_time,
                {
                    "success": False,
                    "error": f"Invalid status '{status}'. Must be one of: {sorted(valid_statuses)}",
                },
                None,
            )

        if not claim:
            return (
                False,
                time.time() - start_time,
                {
                    "success": False,
                    "error": "record_hypothesis requires a non-empty 'claim'.",
                },
                None,
            )

        if hyp_id:
            updated = self.state.update_hypothesis(hyp_id, status, evidence or None)
            duration = time.time() - start_time
            if updated:
                return (
                    True,
                    duration,
                    {
                        "success": True,
                        "action": "updated",
                        "hypothesis_id": hyp_id,
                        "status": status,
                        "message": f"Hypothesis {hyp_id} updated to '{status}'.",
                    },
                    None,
                )

            logger.debug("Hypothesis ID '%s' not found — creating new entry.", hyp_id)

        new_id = self.state.add_hypothesis(claim, test_plan, phase=phase)
        if new_id and status != "pending":
            self.state.update_hypothesis(new_id, status, evidence or None)

        duration = time.time() - start_time
        if not new_id:
            return (
                True,
                duration,
                {
                    "success": True,
                    "action": "deduplicated",
                    "message": "A semantically identical hypothesis already exists.",
                },
                None,
            )

        return (
            True,
            duration,
            {
                "success": True,
                "action": "created",
                "hypothesis_id": new_id,
                "status": status,
                "message": (
                    f"Hypothesis '{claim[:80]}' recorded as '{status}'. "
                    f"ID: {new_id}. Use this ID to update status after testing."
                ),
            },
            None,
        )

    async def _execute_http_observe_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> tuple[bool, float, dict[str, Any], str | None]:
        self._last_output_file = None
        start_time = time.time()

        url = self._str_arg(arguments, "url")
        if not url:
            return (
                False,
                0.0,
                {
                    "success": False,
                    "error": "http_observe requires a 'url' argument.",
                },
                None,
            )

        method = (self._str_arg(arguments, "method") or "GET").upper()
        headers: dict[str, str] = {}
        raw_headers = arguments.get("headers")
        if isinstance(raw_headers, dict):
            headers = {str(k): str(v) for k, v in raw_headers.items()}
        body = self._str_arg(arguments, "body")
        save_as = self._str_arg(arguments, "save_as")
        compare_to = self._str_arg(arguments, "compare_to")

        _follow_raw = arguments.get("follow_redirects", False)
        follow_redirects = (
            _follow_raw
            if isinstance(_follow_raw, bool)
            else str(_follow_raw).lower() == "true"
        )

        _timeout_raw = arguments.get("timeout")
        if _timeout_raw is None:
            from ..config import get_config

            _timeout_raw = get_config().observe_request_timeout
        try:
            req_timeout = max(5, min(120, int(_timeout_raw)))
        except (TypeError, ValueError):
            from ..config import get_config

            req_timeout = get_config().observe_request_timeout

        cmd_parts = [
            "curl",
            "-s",
            "-i",
            "-k",                 # pentest: skip TLS verify (self-signed / internal CA)
            "--globoff",          # treat URL literally — [ ] { } in query strings are not globs
            "--max-time",
            str(req_timeout),
            "-X",
            method,
        ]
        if not follow_redirects:
            cmd_parts.append("--no-location")

        # Auto-attach per-host session cookies when the LLM hasn't already
        # set a Cookie header. Realistic bug-bounty flows need authenticated
        # state to persist across tool calls.
        _existing_cookie_hdr = any(str(k).lower() == "cookie" for k in headers)
        _host_key = _registrable_host(url)
        _session_snapshot = self.state.http_sessions.get(_host_key, {}) if _host_key else {}
        _session_cookies: dict[str, str] = dict(_session_snapshot.get("cookies", {}))
        _injected_cookies = False
        if _session_cookies and not _existing_cookie_hdr:
            cookie_header = "; ".join(f"{n}={v}" for n, v in _session_cookies.items())
            headers = {**headers, "Cookie": cookie_header}
            _injected_cookies = True

        for h_name, h_val in headers.items():
            cmd_parts.extend(["-H", f"{h_name}: {h_val}"])
        if body:
            cmd_parts.extend(["--data-raw", body])
        cmd_parts.append(url)

        curl_cmd = " ".join(shlex.quote(p) for p in cmd_parts)

        try:
            exec_result = await self.engine.execute_tool(
                "execute",
                {"command": curl_cmd, "timeout": req_timeout + 5},
            )
            raw_output = (
                exec_result.get("stdout")
                or exec_result.get("result")
                or exec_result.get("output")
                or ""
            )
            raw_output_file: str | None = None
            if raw_output:
                try:
                    active_target = self.state.active_target or "unknown"
                    output_dir = get_workspace_root() / active_target / "output"
                    output_dir.mkdir(parents=True, exist_ok=True)
                    timestamp = time.strftime("%Y%m%d_%H%M%S")
                    filename = f"http_observe_raw_{timestamp}.txt"
                    raw_path = output_dir / filename
                    raw_path.write_text(raw_output, encoding="utf-8", errors="replace")
                    raw_output_file = f"output/{filename}"
                    self._last_output_file = raw_output_file
                except Exception as _e:
                    logger.debug("Failed to save http_observe raw output: %s", _e)
            exec_error = exec_result.get("error") or exec_result.get("stderr") or ""
            exec_success = bool(exec_result.get("success", True))
            exit_code = exec_result.get("exit_code")

            # If command failed but no error message, generate one from exit code / raw output
            if not exec_success and not exec_error:
                if exit_code is not None and exit_code != 0:
                    exec_error = f"curl exited with code {exit_code}"
                elif raw_output:
                    exec_error = raw_output.strip()[:200]
                else:
                    # Handle case where exit_code is None, 0, or empty
                    exit_code_str = (
                        str(exit_code) if exit_code is not None else "unknown"
                    )
                    exec_error = f"curl command returned exit code {exit_code_str} with no output"
        except Exception as _e:
            duration = time.time() - start_time
            return False, duration, {"success": False, "error": str(_e)}, None

        parsed = self._parse_http_response(raw_output)
        status_code = parsed["status_code"]
        headers_out = parsed["headers"]
        body_out = parsed["body"]
        body_size = len(body_out.encode("utf-8", errors="replace"))

        result: dict[str, Any] = {
            "success": exec_success,
            "url": url,
            "method": method,
            "status_code": status_code,
            "status_line": parsed["status_line"],
            "headers": headers_out,
            "body": body_out[:4000],
            "body_truncated": body_size > 4000,
            "body_size_bytes": body_size,
            "response_time_ms": int((time.time() - start_time) * 1000),
        }
        if raw_output_file:
            result["raw_output_file"] = raw_output_file
            result["raw_output_preview"] = raw_output[:2000]
        if exec_error and not exec_success:
            result["error"] = exec_error[:500]
        if _injected_cookies:
            result["session_cookies_used"] = sorted(_session_cookies.keys())[:8]

        # Harvest Set-Cookie headers from the response and merge into the
        # per-host session jar so subsequent calls stay authenticated.
        harvested: dict[str, str] = {}
        if _host_key and exec_success:
            harvested = _parse_set_cookie_headers(raw_output)
            if harvested:
                jar = self.state.http_sessions.setdefault(_host_key, {"cookies": {}})
                jar.setdefault("cookies", {}).update(harvested)
                jar["updated_at_iter"] = getattr(self.state, "iteration", 0)
                result["session_cookies_harvested"] = sorted(harvested.keys())[:8]

        # CSRF / authenticity token harvest. We only observe what we see
        # (meta tag, hidden form input, or common CSRF cookie) — the LLM
        # decides whether to re-inject on its next state-changing request.
        if _host_key and exec_success:
            csrf_info = _extract_csrf_token(body_out[:6000], harvested)
            if csrf_info:
                jar = self.state.http_sessions.setdefault(_host_key, {"cookies": {}})
                jar["csrf"] = {**csrf_info, "captured_at_iter": getattr(self.state, "iteration", 0)}
                result["csrf_token"] = {
                    "field": csrf_info.get("field", ""),
                    "source": csrf_info.get("source", ""),
                }

        # Rate-limit signal — Python flags, LLM decides backoff strategy.
        _rl_signal = _detect_rate_limit(status_code, headers_out)
        if _rl_signal:
            result["rate_limit"] = _rl_signal
            if _host_key:
                jar = self.state.http_sessions.setdefault(_host_key, {"cookies": {}})
                jar["rate_limited_at_iter"] = getattr(self.state, "iteration", 0)
                jar["rate_limit_signal"] = _rl_signal

        if save_as and save_as.strip():
            baseline_entry: dict[str, Any] = {
                "status_code": status_code,
                "status_line": parsed["status_line"],
                "headers": headers_out,
                "body": body_out[:4000],
                "body_size_bytes": body_size,
            }
            self.state.http_baselines[save_as.strip()] = baseline_entry
            result["saved_as"] = save_as.strip()

        if compare_to and compare_to.strip():
            baseline = self.state.http_baselines.get(compare_to.strip())
            if baseline is None:
                result["diff_error"] = (
                    f"No baseline named '{compare_to}' found. Use save_as first."
                )
            else:
                diff = self._diff_http_responses(baseline, result)
                result["diff"] = diff
                result["compared_to"] = compare_to.strip()

        if exec_success and self._session:
            _url_params = list(parse_qs(urlparse(url).query).keys())
            _body_params: list[str] = []
            if body:
                try:
                    _body_json = json.loads(body)
                    if isinstance(_body_json, dict):
                        _body_params = list(_body_json.keys())
                except (ValueError, TypeError):
                    _body_params = list(parse_qs(body).keys())
            param_names = _url_params + _body_params
            self._session.app_model.update_from_response(
                url=url,
                method=method,
                status_code=status_code,
                headers=headers_out,
                body_excerpt=body_out[:2000],
                param_names=param_names,
            )

        duration = time.time() - start_time
        self.state.tool_history.append(
            ToolExecution(
                tool_name=tool_name,
                arguments=arguments,
                result=result,
                duration=duration,
                status="success" if exec_success else "error",
            )
        )
        self.state.tool_counts["total"] += 1
        return exec_success, duration, result, None

    @staticmethod
    def _parse_http_response(raw: str) -> dict[str, Any]:
        if not raw:
            return {"status_code": 0, "status_line": "", "headers": {}, "body": ""}

        blocks = re.split(r"(?m)^HTTP/", raw)

        last_block = ("HTTP/" + blocks[-1]) if len(blocks) > 1 else raw

        lines = (
            last_block.split("\r\n") if "\r\n" in last_block else last_block.split("\n")
        )
        status_line = lines[0].strip() if lines else ""

        status_code = 0
        m = re.match(r"HTTP/[\d.]+\s+(\d{3})", status_line)
        if m:
            status_code = int(m.group(1))

        headers: dict[str, str] = {}
        body_lines: list[str] = []
        in_body = False
        for line in lines[1:]:
            if in_body:
                body_lines.append(line)
            elif line.strip() == "":
                in_body = True
            else:
                colon_idx = line.find(":")
                if colon_idx > 0:
                    h_name = line[:colon_idx].strip()
                    h_val = line[colon_idx + 1 :].strip()

                    if h_name.lower() in headers:
                        headers[h_name.lower()] = headers[h_name.lower()] + "; " + h_val
                    else:
                        headers[h_name.lower()] = h_val

        body = "\n".join(body_lines)
        return {
            "status_code": status_code,
            "status_line": status_line,
            "headers": headers,
            "body": body,
        }

    @staticmethod
    def _diff_http_responses(
        baseline: dict[str, Any],
        current: dict[str, Any],
    ) -> dict[str, Any]:
        diff: dict[str, Any] = {}

        b_code = baseline.get("status_code", 0)
        c_code = current.get("status_code", 0)
        if b_code != c_code:
            diff["status_code_changed"] = {"from": b_code, "to": c_code}

        b_headers = baseline.get("headers", {})
        c_headers = current.get("headers", {})
        all_keys = set(b_headers) | set(c_headers)
        header_changes: dict[str, Any] = {}
        for k in all_keys:
            bv = b_headers.get(k)
            cv = c_headers.get(k)
            if bv != cv:
                header_changes[k] = {"from": bv, "to": cv}
        if header_changes:
            diff["header_changes"] = header_changes

        b_size = baseline.get("body_size_bytes", 0)
        c_size = current.get("body_size_bytes", 0)
        size_delta = c_size - b_size
        if abs(size_delta) > 0:
            diff["body_size_delta_bytes"] = size_delta

        b_body = (baseline.get("body") or "")[:500]
        c_body = (current.get("body") or "")[:500]
        if b_body != c_body:
            diff["body_changed"] = True
            diff["body_baseline_excerpt"] = b_body[:200]
            diff["body_current_excerpt"] = c_body[:200]
        else:
            diff["body_changed"] = False

        security_headers = [
            "location",
            "set-cookie",
            "x-frame-options",
            "content-security-policy",
            "www-authenticate",
            "access-control-allow-origin",
            "x-powered-by",
            "server",
        ]
        notable: dict[str, str] = {}
        for sh in security_headers:
            if sh in c_headers:
                notable[sh] = c_headers[sh]
        if notable:
            diff["security_headers_present"] = notable

        diff["significant_change"] = bool(
            diff.get("status_code_changed")
            or diff.get("body_size_delta_bytes", 0) > 50
            or diff.get("header_changes")
        )
        return diff

    async def _execute_code_analysis_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> tuple[bool, float, dict[str, Any], str | None]:
        from ..semgrep import get_default_rules, run_code_analysis

        self._last_output_file = None
        start_time = time.time()

        target_path = self._str_arg(arguments, "target_path") or "."
        rules = arguments.get("rules") or None
        languages = arguments.get("languages") or None

        active_target = self.state.active_target or "unknown"
        from .validators import validate_target_path

        _base = (
            "/workspace"
            if target_path.startswith("/")
            else f"/workspace/{active_target}"
        )
        _ok, _resolved = validate_target_path(target_path, _base)
        if not _ok:
            return (
                False,
                0.0,
                {"success": False, "error": f"Invalid target_path: {_resolved}"},
                None,
            )
        target_path = str(_resolved)

        raw_target_path = self._str_arg(arguments, "target_path") or "."
        host_target_path = None
        try:
            workspace_root = get_workspace_root()
            raw_clean = raw_target_path.removeprefix("/workspace/").removeprefix("workspace/")
            if raw_target_path.startswith("/"):
                host_target_path = workspace_root / raw_clean
            else:
                host_target_path = workspace_root / active_target / raw_clean
        except Exception as e:
            logger.debug("Failed to resolve host target path: %s", e)
            host_target_path = None

        code_profile = _profile_code_analysis_target(host_target_path) if host_target_path else {
            "languages": [],
            "rules": [],
            "signals": [],
        }
        if not languages and code_profile["languages"]:
            languages = list(code_profile["languages"])
        if code_profile["rules"]:
            base_rules = list(rules or get_default_rules())
            rules = list(dict.fromkeys(base_rules + list(code_profile["rules"])))

        try:
            result = await run_code_analysis(
                engine=self.engine,
                target_path=target_path,
                rules=rules,
                languages=languages,
            )

            findings_capped = result.get("findings", [])[:50]

            _stdout_lines: list[str] = []
            for _f in findings_capped:
                _sev = str(_f.get("severity", "MEDIUM")).upper()
                _rule = _f.get("rule_id", "unknown")
                _msg = _f.get("message", "")
                _file = _f.get("file", "")
                _line = _f.get("start_line", "?")
                _code = _f.get("code_snippet", "")
                _stdout_lines.append(f"[{_sev}] {_rule}: {_msg}")
                if _file:
                    _stdout_lines.append(f"  File: {_file}:{_line}")
                if _code:
                    _stdout_lines.append(f"  Code: {_code}")
            res_dict = {
                "success": True,
                "summary": result.get("summary", ""),
                "total": result.get("total", 0),
                "findings": findings_capped,
                "errors": result.get("errors", []),
                "stdout": "\n".join(_stdout_lines),
                "target_profile": code_profile,
            }
            if code_profile["signals"]:
                profile_summary = ", ".join(code_profile["signals"][:5])
                res_dict["summary"] = (
                    f"{res_dict['summary']} | Code profile: {profile_summary}"
                    if res_dict["summary"]
                    else f"Code profile: {profile_summary}"
                )

            try:
                self._save_tool_output(tool_name, arguments, res_dict)
            except Exception as _e:
                logger.debug("Could not save tool output: %s", _e)
            success = True
        except Exception as e:
            logger.error("code_analysis error: %s", e)
            res_dict = {"success": False, "error": str(e)}
            success = False

        duration = time.time() - start_time
        self.state.tool_history.append(
            ToolExecution(
                tool_name=tool_name,
                arguments=arguments,
                result=res_dict,
                duration=duration,
                status="success" if success else "error",
            )
        )
        self.state.tool_counts["total"] += 1
        return success, duration, res_dict, None

    async def _execute_schemathesis_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> tuple[bool, float, dict[str, Any], str | None]:
        self._last_output_file = None
        start_time = time.time()

        schema_url = self._str_arg(arguments, "schema_url").strip()
        base_url = self._str_arg(arguments, "base_url").strip()
        auth_header = self._str_arg(arguments, "auth_header").strip()
        checks = arguments.get("checks") or []
        try:
            max_examples = int(arguments.get("max_examples") or 30)
        except (TypeError, ValueError):
            max_examples = 30

        if not schema_url:
            return (
                False,
                0.0,
                {"success": False, "error": "'schema_url' is required."},
                None,
            )

        import shlex

        cmd_parts = [
            "schemathesis run",
            shlex.quote(schema_url),
        ]
        if base_url:
            cmd_parts.extend(["--url", shlex.quote(base_url)])
        if auth_header:
            cmd_parts.extend(["--header", shlex.quote(f"Authorization: {auth_header}")])
        if checks:
            cmd_parts.extend(["--checks", shlex.quote(",".join(checks))])
        cmd_parts.append(f"--max-examples {int(max_examples)}")
        cmd_parts.append("--request-timeout 15")
        cmd_parts.append("--output-truncate false")
        active_target = self.state.active_target or "unknown"
        workspace_dir = shlex.quote(f"/workspace/{active_target}")
        run_id = uuid.uuid4().hex[:12]
        output_file = f"/workspace/{active_target}/output/schemathesis_{run_id}.txt"
        report_file = f"/workspace/{active_target}/output/schemathesis_{run_id}.json"
        cmd_parts.extend(["--report json", "--report-json-path", shlex.quote(report_file)])
        joined_cmd = " ".join(cmd_parts)
        # Preserve the scanner's status instead of tee/cat's status. Exit 1
        # may mean findings, so also inspect the structured report below.
        full_cmd = (
            f"cd {workspace_dir} && {{ {joined_cmd} > {shlex.quote(output_file)} 2>&1; "
            f"status=$?; cat {shlex.quote(output_file)}; exit \"$status\"; }}"
        )

        try:
            workspace_root = get_workspace_root().resolve()
            host_output = (workspace_root / active_target / "output").resolve()
            host_output.relative_to(workspace_root)
            host_output.mkdir(parents=True, exist_ok=True)
            host_report = host_output / f"schemathesis_{run_id}.json"
            exec_result = await self.engine.execute_tool(
                "execute",
                {"command": full_cmd, "timeout": 300},
            )
            stdout = (
                exec_result.get("stdout", "") or exec_result.get("result", "") or ""
            )

            res_dict = {
                "output_file": output_file,
                "report_file": report_file,
                "raw_output": stdout[:3000],
            }
            report = json.loads(host_report.read_text(encoding="utf-8"))
            if not isinstance(report, dict):
                raise ValueError("Schemathesis JSON report must be an object")
            counts = report.get("test_cases") or {}
            operations = report.get("operations") or {}
            if not isinstance(counts, dict) or not isinstance(operations, dict):
                raise ValueError("Invalid Schemathesis test counts")
            generated = int(counts.get("generated", 0))
            failed = int(counts.get("with_failures", 0))
            violations = int(counts.get("unique_failures", 0))
            passed = max(0, generated - failed - int(counts.get("without_checks", 0)))
            failures = report.get("failures", [])
            errors = report.get("errors", [])
            exit_code = exec_result.get("exit_code")
            success = (
                report.get("complete") is True
                and exit_code in (0, 1)
                and report.get("exit_code") == exit_code
                and (exit_code == 0 or bool(failures))
                and not errors
                and not operations.get("errored", 0)
                and int(operations.get("tested", 0)) > 0
                and generated > 0
            )
            res_dict.update({
                "success": success,
                "exit_code": exit_code,
                "complete": report.get("complete") is True,
                "passed": passed,
                "violations": violations,
                "test_cases": counts,
                "failures": failures,
                "errors": errors,
                "summary": (
                    f"Schemathesis completed: {passed} passed test cases, "
                    f"{failed} failed test cases, {violations} unique violations."
                    if success else "Schemathesis scan failed or was incomplete."
                ),
            })
            if not success:
                res_dict["error"] = str(errors or exec_result.get("error") or
                                        "Incomplete run, no tested operations, or scanner execution error")[:500]
            try:
                self._save_tool_output(tool_name, arguments, res_dict)
            except Exception as _e:
                logger.debug("Could not save tool output: %s", _e)
        except Exception as e:
            logger.error("schemathesis_fuzz error: %s", e)
            res_dict = {"success": False, "error": f"Schemathesis report unavailable or invalid: {e}",
                        "output_file": output_file, "report_file": report_file}
            success = False

        duration = time.time() - start_time
        self.state.tool_history.append(
            ToolExecution(
                tool_name=tool_name,
                arguments=arguments,
                result=res_dict,
                duration=duration,
                status="success" if success else "error",
            )
        )
        self.state.tool_counts["total"] += 1
        return success, duration, res_dict, self._last_output_file

from __future__ import annotations

import asyncio
import logging
import time
from pathlib import Path
from typing import Any

from ..config import get_config, get_workspace_root
from ..fuzzer import FUZZ_PAYLOADS as _FUZZ_PAYLOAD_KEYS
from .models import ToolExecution
from .utils import (
    NO_VULNS_FOUND,
    as_bool,
    as_str_list,
    is_host_in_scope,
    FINDING_FORMAT,
)

logger = logging.getLogger("airecon.agent")

NO_FUZZING_RESULT = NO_VULNS_FOUND


def _parse_auth(
    arguments: dict[str, Any],
) -> tuple[str | None, str | None, str | None, dict[str, str] | None]:
    raw = arguments.get("auth_login_url")
    login_url = raw.strip() if isinstance(raw, str) and raw.strip() else None
    username = arguments.get("auth_username")
    password = arguments.get("auth_password")
    raw_extra = arguments.get("auth_extra_fields")
    extra: dict[str, str] | None = None
    if isinstance(raw_extra, dict):
        extra = {str(k): str(v) for k, v in raw_extra.items() if str(k).strip()}
    return login_url, username, password, extra


def _record_tool_completion(
    self,
    tool_name: str,
    arguments: dict[str, Any],
    result: dict[str, Any],
    start_time: float,
    success: bool,
    output_file: str | None = None,
) -> None:
    duration = time.time() - start_time
    try:
        self._save_tool_output(tool_name, arguments, result)
    except Exception as _e:
        logger.debug("Could not save tool output")
    self.state.tool_history.append(
        ToolExecution(
            tool_name=tool_name,
            arguments=arguments,
            result=result,
            duration=duration,
            status="success" if success else "error",
        )
    )
    self.state.tool_counts["total"] += 1


def _format_findings(results: list[Any]) -> list[str]:
    return [
        FINDING_FORMAT.format(
            p=r.parameter,
            v=r.vuln_type,
            s=r.severity,
            c=r.confidence,
            e=r.evidence,
        )
        for r in results
    ]


def _scope_error(target: str, session_target: str, detail: str = "") -> str:
    domain = "subdomains of" if not detail else detail
    return (
        f"OUT-OF-SCOPE: {target!r} does not belong to the target scope "
        f"({session_target!r}). Do NOT fuzz third-party domains. "
        f"Only fuzz {domain} {session_target!r}."
    )


def _handle_oos(
    self, tool_name: str, arguments: dict[str, Any], target: str, start_time: float
) -> tuple[bool, float, dict[str, Any], str | None]:
    session_target = getattr(getattr(self, "_session", None), "target", "unknown")
    logger.warning(
        "Fuzzing scope violation — target %r is outside session scope %r. Skipping.",
        target,
        session_target,
    )
    result = {"success": False, "error": _scope_error(target, session_target)}
    _record_tool_completion(
        self, tool_name, arguments, result, start_time, success=False
    )
    return False, time.time() - start_time, result, None


def _record_fuzz_surface(
    self_ref: Any, arguments: dict[str, Any], findings: list[Any], success: bool
) -> None:
    try:
        tracker = getattr(self_ref, "_surface_tracker", None)
        if tracker is None:
            return
    except AttributeError:
        return

    target_url = str(arguments.get("target", ""))
    params = arguments.get("parameters", [])
    vuln_types = arguments.get("vuln_types", [])
    n_findings = len(findings) if findings else 0

    endpoints: list[str] = (
        [target_url]
        if target_url
        else ([str(p) for p in params if str(p)] if isinstance(params, list) else [])
        or ["<root>"]
    )
    vts = [str(v) for v in vuln_types if str(v)] if isinstance(vuln_types, list) else []
    if not vts:
        vts = ["generic_fuzz"]

    for ep in endpoints:
        for vt in vts:
            tracker.record_test(
                endpoint=ep,
                vuln_type=vt,
                tool_used="advanced_fuzz",
                findings=n_findings,
            )


class _FuzzingExecutorMixin:
    async def _execute_advanced_fuzz_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> tuple[bool, float, dict[str, Any], str | None]:
        from ..fuzzer import Fuzzer

        self._last_output_file = None
        start_time = time.time()

        target = arguments.get("target", "")
        params = arguments.get("parameters", [])
        method = arguments.get("method", "GET")
        valid_vuln_types = set(_FUZZ_PAYLOAD_KEYS.keys())
        raw_vuln_types = arguments.get("vuln_types")
        vuln_types = (
            [v for v in raw_vuln_types if isinstance(v, str) and v in valid_vuln_types]
            if raw_vuln_types and isinstance(raw_vuln_types, list)
            else []
        ) or list(valid_vuln_types)

        enable_phase2 = as_bool(arguments.get("phase2"), default=True)
        ssrf_params = as_str_list(arguments.get("ssrf_params"))
        graphql_endpoints = as_str_list(arguments.get("graphql_endpoints"))
        race_params = as_str_list(arguments.get("race_params"))
        auth_login_url, auth_username, auth_password, auth_extra_fields = _parse_auth(
            arguments
        )
        fuzzer = None

        try:
            async with Fuzzer(
                target=target,
                method=method,
                headers=self._build_fuzz_headers(),
                auth_login_url=auth_login_url,
            ) as fuzzer:
                self._fuzzer_instance = fuzzer
                if hasattr(self, "_restore_payload_memory_into"):
                    self._restore_payload_memory_into(fuzzer)
                if isinstance(auth_username, str) and isinstance(auth_password, str):
                    fuzzer.set_auth_credentials(
                        auth_username,
                        auth_password,
                        auth_extra_fields,
                        login_url=auth_login_url,
                    )
                await fuzzer.fuzz_parameters(params, vuln_types)
                phase2_findings: list[Any] = []
                if enable_phase2:
                    phase2_findings = await fuzzer.run_phase2_advanced_tests(
                        ssrf_params=ssrf_params,
                        graphql_endpoints=graphql_endpoints,
                        race_params=race_params,
                    )
                results = list(fuzzer.results)

            res_dict = {
                "success": True,
                "findings": _format_findings(results) if results else NO_FUZZING_RESULT,
                "phase2_enabled": enable_phase2,
                "phase2_findings": len(phase2_findings) if enable_phase2 else 0,
            }
            _record_tool_completion(
                self, tool_name, arguments, res_dict, start_time, success=True
            )
        except Exception as e:
            logger.error("Fuzzer error: %s", e)
            res_dict = {"success": False, "error": str(e)}
            _record_tool_completion(
                self, tool_name, arguments, res_dict, start_time, success=False
            )
            return False, time.time() - start_time, res_dict, None
        finally:
            if fuzzer is not None and hasattr(self, "_capture_payload_memory_from"):
                self._capture_payload_memory_from(fuzzer)

        _record_fuzz_surface(self, arguments, results, success=True)
        return True, time.time() - start_time, res_dict, None

    def _is_target_in_scope(self, target_url: str) -> bool:
        session_target = ""
        try:
            if self._session and self._session.target:
                session_target = self._session.target.strip()
        except Exception as e:
            logger.debug(
                "Expected failure reading session target for scope check: %s", e
            )
        return is_host_in_scope(target_url, session_target)

    async def _execute_quick_fuzz_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> tuple[bool, float, dict[str, Any], str | None]:
        from ..fuzzer import Fuzzer

        self._last_output_file = None
        start_time = time.time()
        target = arguments.get("target", "")
        params = arguments.get("params") or None
        cfg = get_config()
        fuzzer = None

        if not self._is_target_in_scope(target):
            return _handle_oos(self, tool_name, arguments, target, start_time)

        try:
            async with Fuzzer(
                target,
                threads=int(getattr(cfg, "fuzzer_threads", 10)),
                timeout=int(getattr(cfg, "fuzzer_timeout", 30)),
                headers=self._build_fuzz_headers(),
            ) as fuzzer:
                self._fuzzer_instance = fuzzer
                if hasattr(self, "_restore_payload_memory_into"):
                    self._restore_payload_memory_into(fuzzer)
                results = await asyncio.wait_for(
                    fuzzer.fuzz_parameters(
                        params=params or ["q", "search", "id", "page"],
                        vuln_types=[
                            "sql_injection",
                            "xss",
                            "path_traversal",
                            "ssti",
                        ],
                        max_payloads_per_type=int(
                            getattr(cfg, "fuzzer_quick_max_payloads_per_type", 0)
                            or 0
                        ),
                    ),
                    timeout=float(
                        getattr(cfg, "fuzzer_quick_timeout_seconds", 300.0)
                    ),
                )

            if not results:
                res_dict = {"success": True, "result": NO_FUZZING_RESULT}
            else:
                findings_list = _format_findings(results)
                stdout_lines = []
                for r in results:
                    sev = r.severity.upper()
                    stdout_lines.append(
                        f"[{sev}] {r.vuln_type.upper()} on param '{r.parameter}' at {r.target}"
                    )
                    stdout_lines.append(
                        f"Payload: {r.payload} | Conf: {r.confidence:.2f}"
                    )
                    stdout_lines.append(f"Evidence: {r.evidence}")
                res_dict = {
                    "success": True,
                    "stdout": "\n".join(stdout_lines),
                    "findings": findings_list,
                    "total": len(findings_list),
                }
            _record_tool_completion(
                self, tool_name, arguments, res_dict, start_time, success=True
            )
        except asyncio.TimeoutError:
            res_dict = {
                "success": False,
                "error": "quick_fuzz timed out",
                "timed_out": True,
            }
            _record_tool_completion(
                self, tool_name, arguments, res_dict, start_time, success=False
            )
            return False, time.time() - start_time, res_dict, None
        except asyncio.CancelledError:
            res_dict = {
                "success": False,
                "error": "quick_fuzz cancelled",
                "cancelled": True,
            }
            _record_tool_completion(
                self, tool_name, arguments, res_dict, start_time, success=False
            )
            return False, time.time() - start_time, res_dict, None
        except Exception as e:
            logger.error("quick_fuzz error: %r", e)
            res_dict = {"success": False, "error": str(e)}
            _record_tool_completion(
                self, tool_name, arguments, res_dict, start_time, success=False
            )
            return False, time.time() - start_time, res_dict, None
        finally:
            if fuzzer is not None and hasattr(self, "_capture_payload_memory_from"):
                self._capture_payload_memory_from(fuzzer)

        return True, time.time() - start_time, res_dict, None

    async def _execute_deep_fuzz_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> tuple[bool, float, dict[str, Any], str | None]:
        self._last_output_file = None
        start_time = time.time()

        target = arguments.get("target", "")
        params = arguments.get("params") or None
        vuln_types = arguments.get("vuln_types") or None

        if not self._is_target_in_scope(target):
            return _handle_oos(self, tool_name, arguments, target, start_time)

        enable_phase2 = as_bool(arguments.get("phase2"), default=True)
        enable_phase3 = as_bool(arguments.get("phase3"), default=True)
        ssrf_params = as_str_list(arguments.get("ssrf_params"))
        graphql_endpoints = as_str_list(arguments.get("graphql_endpoints"))
        race_params = as_str_list(arguments.get("race_params"))
        store_params = as_str_list(arguments.get("store_params"))
        trigger_paths = as_str_list(arguments.get("trigger_paths"))
        auth_login_url, auth_username, auth_password, auth_extra_fields = _parse_auth(
            arguments
        )

        tester = None
        try:
            from ..fuzzer import InteractiveRealTimeTester

            tester = InteractiveRealTimeTester(
                target,
                threads=10,
                timeout=20,
                headers=self._build_fuzz_headers(),
                auth_login_url=auth_login_url,
            )
            self._fuzzer_instance = tester.fuzzer
            if hasattr(self, "_restore_payload_memory_into"):
                self._restore_payload_memory_into(tester.fuzzer)
            if isinstance(auth_username, str) and isinstance(auth_password, str):
                tester.fuzzer.set_auth_credentials(
                    auth_username,
                    auth_password,
                    auth_extra_fields,
                    login_url=auth_login_url,
                )
            stream_errors: list[str] = []
            completed = False
            async for event in tester.stream_fuzz(
                params=params, vuln_types=vuln_types
            ):
                if event.event_type == "error":
                    stream_errors.append(str(event.data.get("message") or "Fuzzing failed"))
                elif event.event_type == "complete":
                    completed = True
            if not completed:
                stream_errors.append("Fuzzing stream ended before completion")

            phase2_findings: list[Any] = []
            phase3_findings: list[Any] = []
            if enable_phase2 and not stream_errors:
                phase2_findings = await tester.fuzzer.run_phase2_advanced_tests(
                    ssrf_params=ssrf_params,
                    graphql_endpoints=graphql_endpoints,
                    race_params=race_params,
                )
            if enable_phase3 and not stream_errors:
                phase3_findings = await tester.fuzzer.run_phase3_advanced_tests(
                    store_params=store_params or params,
                    trigger_paths=trigger_paths,
                )
            if phase2_findings or phase3_findings:
                tester._findings.extend(phase2_findings + phase3_findings)

            summary = tester.get_summary()
            summary["phase2_enabled"] = enable_phase2
            summary["phase3_enabled"] = enable_phase3
            summary["phase2_findings"] = len(phase2_findings)
            summary["phase3_findings"] = len(phase3_findings)

            success = not stream_errors
            res_dict = {
                "success": success,
                "summary": summary,
                "findings": _format_findings(getattr(tester, "_findings", [])),
            }
            if stream_errors:
                res_dict["error"] = "; ".join(stream_errors)
                res_dict["partial"] = True
            _record_tool_completion(
                self, tool_name, arguments, res_dict, start_time, success=success
            )
        except Exception as e:
            logger.error("deep_fuzz error: %s", e)
            res_dict = {"success": False, "error": str(e), "partial": tester is not None,
                        "findings": _format_findings(getattr(tester, "_findings", []))}
            _record_tool_completion(
                self, tool_name, arguments, res_dict, start_time, success=False
            )
            return False, time.time() - start_time, res_dict, None
        finally:
            if tester is not None:
                if hasattr(self, "_capture_payload_memory_from"):
                    self._capture_payload_memory_from(tester.fuzzer)
                try:
                    await tester.fuzzer.close()
                except Exception as _e:
                    logger.debug("Could not close deep_fuzz tester")

        return success, time.time() - start_time, res_dict, None

    async def _execute_generate_wordlist_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> tuple[bool, float, dict[str, Any], str | None]:
        from ..fuzzer import generate_fuzz_wordlist

        self._last_output_file = None
        start_time = time.time()

        raw_output_file = arguments.get("output_file", "wordlist.txt")
        output_file = Path(raw_output_file).name or "wordlist.txt"
        max_combinations = min(int(arguments.get("max_combinations", 300)), 1000)
        vuln_types = arguments.get("vuln_types") or None

        try:
            wordlist = generate_fuzz_wordlist(
                max_combinations=max_combinations, vuln_types=vuln_types
            )
            target = self.state.active_target or "unknown"
            host_output = get_workspace_root() / target / "output"
            host_output.mkdir(parents=True, exist_ok=True)
            out_path = host_output / output_file
            with open(out_path, "w", encoding="utf-8") as f:
                f.write("\n".join(wordlist))

            saved_path = f"output/{output_file}"
            fuzzer_instance = getattr(self, "_fuzzer_instance", None)
            model_used = getattr(fuzzer_instance, "model", None)
            res_dict = {
                "success": True,
                "result": f"Generated {len(wordlist)} entries saved to {saved_path}.",
                "saved_to": saved_path,
                "total_entries": len(wordlist),
                "model_used": model_used,
            }
            _record_tool_completion(
                self, tool_name, arguments, res_dict, start_time, success=True
            )
            return True, time.time() - start_time, res_dict, self._last_output_file
        except Exception as e:
            logger.error("generate_wordlist error: %s", e)
            res_dict = {"success": False, "error": str(e)}
            _record_tool_completion(
                self, tool_name, arguments, res_dict, start_time, success=False
            )
            return False, time.time() - start_time, res_dict, self._last_output_file

    def _build_fuzz_headers(self) -> dict[str, str] | None:
        headers: dict[str, str] = {}
        session = getattr(self, "_session", None)
        if session is None:
            return None
        auth_cookies: list[dict[str, Any]] = getattr(session, "auth_cookies", []) or []
        if auth_cookies:
            cookie_str = "; ".join(
                f"{c.get('name', '')}={c.get('value', '')}"
                for c in auth_cookies
                if c.get("name")
            )
            if cookie_str:
                headers["Cookie"] = cookie_str
        auth_hdrs: dict[str, str] = getattr(session, "auth_headers", {}) or {}
        headers.update(auth_hdrs)
        return headers or None

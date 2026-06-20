from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

from .constants import MINI_AGENT_BLOCKED_TOOLS
from .executors_catalog import (
    _SPECIALIST_PREFIXES,
    _safe_non_negative_int,
)
from .models import ToolExecution

logger = logging.getLogger("airecon.agent")


def _is_duplicate_vulnerability(
    vuln: dict[str, Any], existing: list[dict[str, Any]]
) -> bool:
    finding = str(vuln.get("finding") or vuln.get("title") or "").strip().lower()
    location = (
        str(vuln.get("location") or vuln.get("endpoint") or vuln.get("url") or "")
        .strip()
        .lower()
    )
    severity = str(vuln.get("severity") or "").strip().lower()

    for item in existing or []:
        i_finding = str(item.get("finding") or item.get("title") or "").strip().lower()
        i_location = (
            str(item.get("location") or item.get("endpoint") or item.get("url") or "")
            .strip()
            .lower()
        )
        i_severity = str(item.get("severity") or "").strip().lower()
        if (
            finding
            and finding == i_finding
            and location == i_location
            and severity == i_severity
        ):
            return True
    return False


class _InteractiveExecutorMixin:
    async def _execute_request_user_input(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        request_id: str | None = None,
        event: asyncio.Event | None = None,
    ) -> tuple[bool, float, dict[str, Any], str | None]:
        from .validators import VALID_USER_INPUT_TYPES

        self._last_output_file = None
        start_time = time.time()

        prompt = self._str_arg(arguments, "prompt").strip()
        raw_type = self._str_arg(arguments, "input_type").strip() or "text"
        input_type = raw_type if raw_type in VALID_USER_INPUT_TYPES else "text"
        if raw_type and raw_type not in VALID_USER_INPUT_TYPES:
            logger.warning(
                "request_user_input: unknown input_type %r, defaulting to 'text'",
                raw_type,
            )
        try:
            timeout_seconds = float(arguments.get("timeout_seconds") or 300)
            timeout_seconds = max(10.0, min(timeout_seconds, 3600.0))
        except (TypeError, ValueError):
            timeout_seconds = 300.0

        if not prompt:
            return (
                False,
                0.0,
                {
                    "success": False,
                    "error": "'prompt' argument is required.",
                },
                None,
            )

        if event is None:
            import uuid as _uuid_mod

            if not request_id:
                request_id = str(_uuid_mod.uuid4())
            event = asyncio.Event()
            self._user_input_event = event
            self._user_input_cancelled = False
            self._user_input_value = ""
            self._user_input_request_id = request_id
            self._user_input_prompt = prompt
            self._user_input_type = input_type
        else:
            if not request_id:
                request_id = getattr(self, "_user_input_request_id", "") or ""

        logger.info(
            "request_user_input: waiting for user (type=%s, timeout=%.0fs, id=%s)",
            input_type,
            timeout_seconds,
            request_id,
        )

        try:
            await asyncio.wait_for(event.wait(), timeout=timeout_seconds)
            cancelled = bool(getattr(self, "_user_input_cancelled", False))
            value = self._user_input_value
            if cancelled:
                success = False
                res: dict[str, Any] = {
                    "success": False,
                    "input_type": input_type,
                    "cancelled": True,
                    "error": "User cancelled the input dialog.",
                }
            else:
                success = bool(value)
                res = {
                    "success": success,
                    "input_type": input_type,
                    "value": value,
                }
                if not success:
                    res["error"] = "User submitted an empty value."
        except asyncio.TimeoutError:
            success = False
            res = {
                "success": False,
                "input_type": input_type,
                "error": (
                    f"Timed out waiting for user input after {timeout_seconds:.0f}s. "
                    "The user did not respond in time."
                ),
            }
        finally:
            self._user_input_event = None
            self._user_input_value = ""
            self._user_input_cancelled = False
            self._user_input_request_id = ""
            self._user_input_prompt = ""
            self._user_input_type = "text"

        duration = time.time() - start_time
        return success, duration, res, None

    async def _execute_spawn_agent_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> tuple[bool, float, dict[str, Any], str | None]:
        self._last_output_file = None
        start_time = time.time()

        task = arguments.get("task", "")
        target = arguments.get("target", self.state.active_target or "")

        _RAW_SPECIALIST = str(arguments.get("specialist", "exploit"))
        _VALID_SPECIALISTS = {
            "sqli",
            "xss",
            "ssrf",
            "lfi",
            "recon",
            "exploit",
            "analyzer",
            "reporter",
        }
        specialist = (
            _RAW_SPECIALIST.lower().strip()
            if _RAW_SPECIALIST.lower().strip() in _VALID_SPECIALISTS
            else "exploit"
        )

        prompt = (
            f"[SUBAGENT — Specialist: {specialist.upper()}]\n"
            f"[Target: {target}]\n\n"
            f"{_SPECIALIST_PREFIXES.get(specialist, '')}\n\n"
            f"Task assigned by parent agent:\n{task}\n\n"
            "Run focused tests. Use create_vulnerability_report for each confirmed finding. "
            "Output [TASK_COMPLETE] when done."
        )

        try:
            from .loop import AgentLoop

            parent_llm = getattr(self, "llm", None)
            if parent_llm is None:
                from ..llm import create_llm_client

                parent_llm = create_llm_client()
                await parent_llm._async_init()

            agent = AgentLoop(llm=parent_llm, engine=self.engine)

            agent._is_subagent = True

            agent._override_max_iterations = 100

            agent._blocked_tools = set(MINI_AGENT_BLOCKED_TOOLS)

            _sub_iters = 0
            async for _ in agent.process_message(prompt):
                _sub_iters += 1

            _raw_sub_usage = getattr(getattr(agent, "state", None), "token_usage", {})
            sub_token_usage = (
                dict(_raw_sub_usage) if isinstance(_raw_sub_usage, dict) else {}
            )
            sub_total = _safe_non_negative_int(
                sub_token_usage.get("cumulative", sub_token_usage.get("used", 0))
            )
            sub_prompt_total = _safe_non_negative_int(
                sub_token_usage.get(
                    "cumulative_prompt", sub_token_usage.get("last_prompt", 0)
                )
            )
            sub_completion_total = _safe_non_negative_int(
                sub_token_usage.get(
                    "cumulative_completion", sub_token_usage.get("last_completion", 0)
                )
            )
            if sub_total > 0:
                state_token_usage = getattr(self.state, "token_usage", None)
                if not isinstance(state_token_usage, dict):
                    state_token_usage = {}
                    try:
                        self.state.token_usage = state_token_usage
                    except Exception as e:
                        logger.debug("Expected failure updating token usage: %s", e)
                state_token_usage["cumulative"] = (
                    _safe_non_negative_int(state_token_usage.get("cumulative", 0))
                    + sub_total
                )
                state_token_usage["cumulative_prompt"] = (
                    _safe_non_negative_int(
                        state_token_usage.get("cumulative_prompt", 0)
                    )
                    + sub_prompt_total
                )
                state_token_usage["cumulative_completion"] = (
                    _safe_non_negative_int(
                        state_token_usage.get("cumulative_completion", 0)
                    )
                    + sub_completion_total
                )
                parent_session = getattr(self, "_session", None)
                if parent_session is not None:
                    parent_session.token_total = _safe_non_negative_int(
                        state_token_usage.get("cumulative", 0)
                    )
                    parent_session.token_prompt_total = _safe_non_negative_int(
                        state_token_usage.get("cumulative_prompt", 0)
                    )
                    parent_session.token_completion_total = _safe_non_negative_int(
                        state_token_usage.get("cumulative_completion", 0)
                    )
                    parent_session.token_last_used = _safe_non_negative_int(
                        state_token_usage.get("used", 0)
                    )

            findings: list[str] = []
            if agent._session:
                findings = [
                    v.get("finding", str(v))
                    for v in agent._session.vulnerabilities[:10]
                ]

                parent_session = getattr(self, "_session", None)
                if parent_session is not None:
                    for vuln in agent._session.vulnerabilities:
                        if not _is_duplicate_vulnerability(
                            vuln, parent_session.vulnerabilities
                        ):
                            parent_session.vulnerabilities.append(vuln)

            res_dict = {
                "success": True,
                "specialist": specialist,
                "target": target,
                "findings": findings,
                "total": len(findings),
                "iterations": _sub_iters,
                "token_usage": sub_token_usage,
            }
            success = True
        except Exception as e:
            logger.error("spawn_agent error: %s", e)
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
        self.state.tool_counts["subagents"] = (
            self.state.tool_counts.get("subagents", 0) + 1
        )
        return success, duration, res_dict, None

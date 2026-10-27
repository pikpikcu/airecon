from __future__ import annotations

import logging
from typing import Any
from urllib.parse import urlparse

from ..config import get_config
from ..config import get_workspace_root
from ..context_budget import ArtifactCompressor, ContextBudgetError, pack_history, request_chars
from ..data_loader import severity_to_int
from .models import _get_model_limits
from .session import get_untested_injection_points

logger = logging.getLogger("airecon.agent")


class _ContextMixin:
    @property
    def _MAX_TOOL_RESULT_CHARS(self) -> int:
        limits = _get_model_limits()
        return min(3_000, limits.get("max_tool_result_chars", 50000))

    def _inject_exploit_vuln_context(self) -> None:
        if not self._session:
            return

        vulns = self._session.vulnerabilities or []
        injection_pts = self._session.injection_points or []

        if not vulns and not injection_pts:
            return

        lines = [
            "[SYSTEM: EXPLOIT PHASE — CONFIRMED ATTACK SURFACE]",
            "Exploit each item below systematically. Do NOT re-discover — go straight to exploitation.\n",
        ]

        if vulns:
            lines.append("## Confirmed Vulnerabilities:")
            for i, v in enumerate(vulns[:25], 1):
                finding = str(
                    v.get("finding")
                    or v.get("title")
                    or v.get("name")
                    or "Unknown finding"
                )
                url = str(
                    v.get("url")
                    or v.get("endpoint")
                    or v.get("evidence")
                    or v.get("proof")
                    or ""
                )
                sev_raw = str(v.get("severity", "")).strip()
                if sev_raw in {"5", "4", "3", "2", "1"}:
                    sev = {
                        "5": "CRITICAL",
                        "4": "HIGH",
                        "3": "MEDIUM",
                        "2": "LOW",
                        "1": "INFO",
                    }[sev_raw]
                else:
                    sev = sev_raw
                if not sev:
                    f_up = finding.upper()
                    for lbl in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
                        if f"[{lbl}]" in f_up or f"{lbl}:" in f_up:
                            sev = lbl
                            break
                param = v.get("parameter", "")
                detail = f" (param: {param})" if param else ""
                lines.append(f"  {i}. [{sev}] {finding}{detail} — {url}")

        if injection_pts:
            lines.append("\n## Injection Points — test each by its type:")
            for j, ip in enumerate(injection_pts[:20], 1):
                url = ip.get("url", "")
                param = ip.get("parameter", "")
                method = ip.get("method", "GET")
                itype = ip.get("type_hint", "INJECT")
                lines.append(f"  {j}. [{itype}] {method} {url} param={param}")

        lines.append(
            "\nPriority order: CRITICAL > HIGH > MEDIUM. "
            "Confirm each exploit with proof-of-concept output showing actual impact."
        )

        vuln_ctx = "\n".join(lines)
        self.state.conversation.append(
            {
                "role": "system",
                "content": vuln_ctx,
                "_bucket": "protected_system",
            }
        )

    def _build_recent_execution_memory(self, last_n: int = 6) -> list[str]:
        recent = self.state.tool_history[-last_n:] if self.state.tool_history else []
        if not recent:
            return []

        lines: list[str] = []
        for rec in recent:
            status = "OK" if rec.status == "success" else "FAIL"
            detail = ""
            if rec.tool_name == "execute":
                command = str(rec.arguments.get("command", "") or "").strip()
                if command:
                    detail = command[:90]
            elif rec.tool_name == "browser_action":
                action = str(rec.arguments.get("action", "") or "").strip()
                url = str(rec.arguments.get("url", "") or "").strip()
                detail = f"{action} {url}".strip()[:90]
            elif rec.arguments:
                interesting_arg = next(
                    (
                        f"{k}={v}"
                        for k, v in rec.arguments.items()
                        if k in {"url", "endpoint", "path", "target", "query"}
                    ),
                    "",
                )
                detail = interesting_arg[:90]

            line = f"  - [{status}] {rec.tool_name}"
            if detail:
                line += f": {detail}"
            lines.append(line)
        return lines

    def _build_failure_memory(self, max_items: int = 4) -> list[str]:
        if not getattr(self.state, "failure_log", None):
            return []

        lines: list[str] = []
        for failure in self.state.failure_log[-max_items:]:
            lines.append(
                "  - "
                + f"{str(failure.get('name', 'tool'))} "
                + f"[{str(failure.get('error_type', 'other'))}] "
                + f"on {str(failure.get('target', '') or 'current target')}: "
                + f"{str(failure.get('suggested_action', 'review the last error'))[:120]}"
            )
        return lines

    def _build_anomaly_memory(self, max_items: int = 4) -> list[str]:
        interesting_tags = {
            "workflow",
            "business_logic",
            "tenant",
            "trust_boundary",
            "principal",
            "authorization",
            "state_machine",
            "commerce",
            "anomaly",
        }
        lines: list[str] = []
        seen: set[str] = set()
        for ev in reversed(getattr(self.state, "evidence_log", [])[-20:]):
            if not isinstance(ev, dict):
                continue
            tags = {
                str(tag).strip().lower()
                for tag in (ev.get("tags") or [])
                if str(tag).strip()
            }
            summary = str(ev.get("summary", "") or "").strip()
            if not summary:
                continue
            lower_summary = summary.lower()
            if not (
                tags & interesting_tags
                or any(token in lower_summary for token in ("unexpected", "odd", "workflow", "tenant", "approve", "refund", "coupon", "otp", "totp"))
            ):
                continue
            dedup_key = summary[:120].lower()
            if dedup_key in seen:
                continue
            seen.add(dedup_key)
            lines.append(f"  - {summary[:160]}")
            if len(lines) >= max_items:
                break
        return lines

    def _compact_phase_context(self, from_phase: str) -> None:
        msgs = self.state.conversation
        keep_recent = 15
        cutoff = max(0, len(msgs) - keep_recent)
        compacted_tools = 0
        compacted_thinking = 0
        chars_freed = 0

        for i, msg in enumerate(msgs[:cutoff]):
            role = msg.get("role")
            if msg.get("_protected"):
                continue
            content = str(msg.get("content", ""))

            if role == "tool" and len(content) > 400:
                if not self._compact_tool_message(msg, 750):
                    continue
                freed = len(content) - len(msg["content"])
                chars_freed += freed
                compacted_tools += 1

            elif role == "assistant" and msg.get("thinking"):
                thinking_len = len(str(msg["thinking"]))
                msg.pop("thinking", None)
                chars_freed += thinking_len
                compacted_thinking += 1

        if compacted_tools or compacted_thinking:
            logger.info(
                "Phase transition compaction (%s→next): %d tool msgs, "
                "%d thinking strips, ~%d chars freed",
                from_phase,
                compacted_tools,
                compacted_thinking,
                chars_freed,
            )

    def _messages_for_llm(self) -> list[dict[str, Any]]:
        msgs = self.state.conversation
        last_assistant_idx = -1
        for i, m in enumerate(msgs):
            if m.get("role") == "assistant":
                last_assistant_idx = i

        if last_assistant_idx == -1:
            return type(self.state)._repair_tool_pairs(list(msgs))

        result = []
        for i, msg in enumerate(msgs):
            if (
                msg.get("role") == "assistant"
                and i != last_assistant_idx
                and msg.get("thinking")
            ):
                msg = {k: v for k, v in msg.items() if k != "thinking"}
            result.append(msg)
        # Guarantee the tool_call/tool_result pairing invariant on every request,
        # not only after truncation. A stray tool result (its assistant turn was
        # compacted away) otherwise reaches the gateway as an orphaned function
        # call output and is rejected with HTTP 400.
        return type(self.state)._repair_tool_pairs(result)

    def _get_tool_result_cap(self) -> int:
        if self._ctf_mode:
            return 1500
        ctx = (
            self._adaptive_num_ctx
            if self._adaptive_num_ctx > 0
            else get_config().llm_context_window
        )

        base_cap = max(3_000, min(self._MAX_TOOL_RESULT_CHARS, int(ctx * 0.08 * 3)))

        used = self.state.token_usage.get("used", 0)
        ratio = used / max(ctx, 1)
        if ratio >= 0.90:
            return max(1_000, base_cap // 16)
        if ratio >= 0.75:
            return max(1_500, base_cap // 10)
        if ratio >= 0.60:
            return max(2_000, base_cap // 6)
        if ratio >= 0.45:
            return max(3_000, base_cap // 3)
        if ratio >= 0.30:
            return max(4_000, base_cap // 2)
        return base_cap

    def _cap_tool_result(self, content: str) -> str:
        cap = self._get_tool_result_cap()
        if len(content) <= cap:
            return content
        head = int(cap * 0.70)
        tail = int(cap * 0.10)
        omitted = len(content) - head - tail
        return content[:head] + f"\n...[{omitted} chars omitted]...\n" + content[-tail:]

    def _compact_tool_message(self, message: dict[str, Any], cap: int) -> bool:
        if message.get("_protected") or message.get("name") == "read_file":
            return False
        content = str(message.get("content", ""))
        if len(content.encode()) <= cap:
            return False
        try:
            preview, reference = self._get_artifact_compressor().preview(
                content, cap, reference=message.get("_context_ref"),
                external=not bool(message.get("_context_ref")),
            )
        except (OSError, ContextBudgetError) as exc:
            logger.warning("Keeping original tool output: %s", type(exc).__name__)
            return False
        message["content"] = preview
        message["_context_ref"] = reference
        return True

    def _drop_stale_tool_results(self) -> int:

        msgs = self.state.conversation
        if len(msgs) <= 8:
            return 0

        non_system = [(i, m) for i, m in enumerate(msgs) if m.get("role") != "system"]
        if len(non_system) <= 5:
            return 0

        keep_from_idx = non_system[-5][0] if len(non_system) > 5 else 0

        dropped = 0
        chars_freed = 0
        new_conversation = []
        for i, msg in enumerate(msgs):
            if i < keep_from_idx and msg.get("role") == "tool":
                before = len(str(msg.get("content", "")))
                if self._compact_tool_message(msg, 750):
                    dropped += 1
                    chars_freed += before - len(msg["content"])
                new_conversation.append(msg)
            else:
                new_conversation.append(msg)

        if dropped > 0:
            self.state.conversation = new_conversation
            logger.info(
                "Dropped %d stale tool results (%d chars freed) — "
                "prevents progressive slowdown",
                dropped,
                chars_freed,
            )
        return dropped

    async def _call_compression_llm(
        self,
        messages_to_compress: list[dict[str, Any]],
    ) -> str:
        if not messages_to_compress:
            return ""
        if not getattr(self, "llm", None):
            return ""

        if self._recovery_force_tool_calls > 0:
            return ""

        # Per-message cap is config-driven and scales with the context window:
        # large-context models can afford to feed the compressor more detail, so
        # less is lost in the handoff summary.
        _cfg = get_config()
        try:
            _PER_MSG_CAP = int(
                getattr(_cfg, "memory_compression_input_per_msg_chars", 350)
            )
        except (TypeError, ValueError):
            _PER_MSG_CAP = 350
        _eff_ctx = int(
            getattr(self, "_adaptive_num_ctx", 0) or getattr(_cfg, "llm_context_window", 0) or 0
        )
        if _eff_ctx >= 100_000:
            _PER_MSG_CAP *= 2
        chunks: list[str] = []
        for msg in messages_to_compress:
            role = msg.get("role", "?")
            content = str(msg.get("content", ""))[:_PER_MSG_CAP].strip()
            if not content:
                continue
            chunks.append(f"[{role.upper()}] {content}")

        if not chunks:
            return ""

        messages_text = "\n\n".join(chunks)
        prior = self._compression_summary

        if prior:
            system_content = (
                "You are a context compression assistant for a security assessment agent.\n"
                "Update the existing summary with new information from the messages below.\n"
                "PRESERVE everything still relevant from the previous summary.\n"
                "ADD new findings, progress, and decisions from the new messages.\n"
                "Always keep: flags, CVEs, credentials, confirmed vulnerabilities, endpoints."
            )
            user_content = (
                f"## Previous Summary (PRESERVE relevant parts):\n{prior}\n\n"
                f"## New Messages to Integrate:\n{messages_text}\n\n"
                "Output an updated structured summary:\n"
                "## Goal\n## Progress\n### Done\n### In Progress\n"
                "## Key Findings\n## Key Decisions\n## Next Steps"
            )
        else:
            system_content = (
                "You are a context compression assistant for a security assessment agent.\n"
                "Summarize the conversation messages below into a structured handoff.\n"
                "Keep ALL security findings: flags, CVEs, credentials, endpoints, vulnerabilities."
            )
            user_content = (
                f"## Messages to Summarize:\n{messages_text}\n\n"
                "Output a structured summary:\n"
                "## Goal\n## Progress\n### Done\n### In Progress\n"
                "## Key Findings\n## Key Decisions\n## Next Steps"
            )

        try:
            summary = await self.llm.complete(
                messages=[
                    {"role": "system", "content": system_content},
                    {"role": "user", "content": user_content},
                ],
                options={"num_predict": 2048, "temperature": 0.1},
            )
            return summary.strip()
        except Exception as exc:
            logger.warning(
                "Iterative compression LLM call failed: %s — falling back to truncation",
                exc,
            )
            return ""

    async def _enforce_char_budget(
        self, num_ctx: int, num_predict: int | None = None
    ) -> None:
        cfg = get_config()
        effective_predict = (
            self._fit_num_predict_to_ctx(num_predict, num_ctx)
            if num_predict is not None
            else self._fit_num_predict_to_ctx(
                getattr(cfg, "openai_max_tokens", 32768), num_ctx
            )
        )

        if not self.state.conversation:
            return
        budget = max(0, (num_ctx - effective_predict - 256) * 3) if num_ctx > 0 else 0
        learned = int(getattr(self, "_context_char_budget", 0) or 0)
        if learned:
            budget = min(budget, learned) if budget else learned
        if not budget and num_ctx == -1:
            return
        self.state.conversation = pack_history(
            self.state.conversation, self._tools_llm, budget,
            self._get_artifact_compressor(),
        )

    def _get_artifact_compressor(self) -> ArtifactCompressor:
        root = get_workspace_root().resolve()
        target_root = (root / (self.state.active_target or "unknown")).resolve()
        if not target_root.is_relative_to(root):
            raise OSError("Compression target outside workspace")
        session_id = str(getattr(getattr(self, "_session", None), "session_id", "session") or "session")
        return ArtifactCompressor(target_root, session_id)

    def _recover_context_budget(self, num_predict: int) -> bool:
        before = request_chars(self._messages_for_llm(), self._tools_llm)
        learned = int(getattr(self, "_context_char_budget", 0) or before)
        budget = min(before, learned) // 2
        try:
            packed = pack_history(
                self.state.conversation, self._tools_llm, budget,
                self._get_artifact_compressor(),
            )
        except (ContextBudgetError, OSError):
            return False
        if request_chars(packed, self._tools_llm) >= before:
            return False
        self.state.conversation = packed
        self._context_char_budget = budget
        cap = max(128, num_predict // 2)
        self._adaptive_num_predict_cap = min(
            int(getattr(self, "_adaptive_num_predict_cap", 0) or cap), cap,
        )
        if getattr(self, "_session", None):
            self._session.context_char_budget = budget
        return True

    def _append_tool_result(
        self,
        tool_name: str,
        content_str: str,
        success: bool,
        tool_call_id: str | None = None,
    ) -> None:
        cfg = get_config()
        reference = None
        if tool_name != "read_file":
            try:
                compressor = self._get_artifact_compressor()
                reference = compressor.save(content_str)
                if len(content_str.encode()) > self._get_tool_result_cap():
                    content_str, reference = compressor.preview(
                        content_str, self._get_tool_result_cap(), reference=reference,
                    )
            except (OSError, RuntimeError) as exc:
                # Keep the full result when storage/compression fails; the request
                # budget gate can stop safely, but must not invent recoverability.
                logger.warning("Output compaction unavailable: %s", type(exc).__name__)
        if cfg.tool_response_role.lower() == "tool":
            tool_msg: dict[str, Any] = {
                "role": "tool",
                "name": tool_name,
                "content": content_str,
            }
            if tool_call_id:
                tool_msg["tool_call_id"] = tool_call_id
            if reference:
                tool_msg["_context_ref"] = reference
            self.state.conversation.append(tool_msg)
        else:
            status = "successfully" if success else "with errors"
            self.state.conversation.append(
                {
                    "role": "user",
                    "content": f"[SYSTEM: Tool '{tool_name}' executed {status}]\nOutput:\n{content_str}",
                    "_tool_result": True,
                    **({"_context_ref": reference} if reference else {}),
                }
            )

    def _build_critical_findings_context(self) -> str:
        if not self._session:
            return ""

        s = self._session
        parts = ["[SYSTEM: CRITICAL FINDINGS — DO NOT LOSE]"]

        if s.validated_subdomains:
            parts.append(
                "VALIDATED SUBDOMAINS ({0}): {1}".format(
                    len(s.validated_subdomains),
                    ", ".join(s.validated_subdomains[:5]),
                )
            )
            if len(s.validated_subdomains) > 5:
                parts.append(f"... and {len(s.validated_subdomains) - 5} more")
            if s.subdomains:
                parts.append(f"RAW SUBDOMAINS: {len(s.subdomains)} total")
        elif s.subdomains:
            parts.append(
                f"SUBDOMAINS ({len(s.subdomains)}): {', '.join(s.subdomains[:5])}"
            )
            if len(s.subdomains) > 5:
                parts.append(f"... and {len(s.subdomains) - 5} more")

        if s.validated_live_hosts:
            parts.append(
                "VALIDATED LIVE HOSTS ({0}): {1}".format(
                    len(s.validated_live_hosts),
                    ", ".join(s.validated_live_hosts[:8]),
                )
            )
            if s.live_hosts:
                parts.append(f"RAW LIVE HOSTS: {len(s.live_hosts)} total")
        elif s.live_hosts:
            parts.append(
                f"LIVE HOSTS ({len(s.live_hosts)}): {', '.join(s.live_hosts[:8])}"
            )
        elif s.subdomains and not s.validated_subdomains:
            parts.append(
                "WARNING: subdomains enumerated but NOT YET validated. "
                "Run: httpx -l output/subdomains.txt -sc -o output/live_hosts.txt "
                "to filter live hosts BEFORE port scanning or directory brute-force."
            )

        if s.open_ports:
            port_summary = []
            for host, ports in list(s.open_ports.items())[:5]:
                port_summary.append(f"{host}:{','.join(map(str, ports[:5]))}")
            parts.append(f"OPEN PORTS: {'; '.join(port_summary)}")

        if s.validated_urls:
            parts.append(
                "VALIDATED URLS ({0}): {1}".format(
                    len(s.validated_urls),
                    ", ".join(s.validated_urls[:3]),
                )
            )
            if len(s.validated_urls) > 3:
                parts.append(f"... and {len(s.validated_urls) - 3} more URLs")
            if s.urls:
                parts.append(f"RAW URLS: {len(s.urls)} total")
        elif s.urls:
            parts.append(f"URLs ({len(s.urls)}): {', '.join(s.urls[:3])}")
            if len(s.urls) > 3:
                parts.append(f"... and {len(s.urls) - 3} more URLs")

            # URL intelligence — classify and warn about static assets
            try:
                from .url_intelligence import build_url_intelligence_context

                _url_ctx = build_url_intelligence_context(list(s.urls))
                if _url_ctx:
                    parts.append("")
                    parts.append(_url_ctx)
            except Exception as _url_err:
                logger.debug("URL intelligence build failed: %s", _url_err)

        if s.vulnerabilities:
            vuln_vals = []
            for v in s.vulnerabilities[:10]:
                vt = v.get("title", v.get("finding", "Unknown"))
                vf = v.get("flag")
                if vf:
                    vuln_vals.append(f"{vt} (FLAG: {vf})")
                else:
                    vuln_vals.append(vt)
            parts.append(f"VULNERABILITIES: {'; '.join(vuln_vals)}")

        if s.injection_points:
            untested = get_untested_injection_points(s)
            all_ips = s.injection_points
            tested_count = len(all_ips) - len(untested)

            show = untested[:8] if untested else all_ips[:8]
            ip_lines: list[str] = []
            for pt in show:
                path = urlparse(pt.get("url", "")).path or pt.get("url", "")
                ip_lines.append(
                    f"  [{pt.get('type_hint', '?')}] {pt.get('parameter', '?')} @ {path}"
                )
            untested_note = f"{len(untested)} UNTESTED" if untested else "all tested"
            parts.append(
                f"INJECTION POINTS ({len(all_ips)} total, {untested_note}, {tested_count} tested):\n"
                + "\n".join(ip_lines)
                + (
                    f"\n  ... +{len(untested) - 8} more untested"
                    if len(untested) > 8
                    else ""
                )
            )

        if s.technologies:
            tech_parts = [
                f"{name}/{ver}" if ver else name
                for name, ver in list(s.technologies.items())[:10]
            ]
            parts.append(f"TECHNOLOGIES: {', '.join(tech_parts)}")

        if s.completed_phases:
            parts.append(f"COMPLETED PHASES: {', '.join(s.completed_phases)}")

        result = "\n".join(parts)
        if len(result) > 2000:
            result = result[:1980] + "\n... [truncated, total exceeded 2000 chars]"
        return result

    def _build_compressed_findings_summary(self) -> str:
        active_target = str(self.state.active_target or "").strip()
        if (
            not self._session
            and not self.state.hypothesis_queue
            and not self.state.evidence_log
            and not active_target
        ):
            return ""

        parts: list[str] = [
            "[SYSTEM: PINNED CONTEXT — confirmed findings, hypotheses, gaps]"
        ]
        added_any = False

        scope_anchor = str(getattr(self, "_scope_anchor_target", "") or "").strip()
        if active_target:
            parts.append(f"SCOPE TARGET: {active_target}")
            if scope_anchor:
                parts.append(f"SCOPE ANCHOR: {scope_anchor}")
            parts.append(
                f"SCOPE LOCK: {'ACTIVE' if getattr(self, '_scope_lock_active', False) else 'INACTIVE'}"
            )
            added_any = True

        memory_health = getattr(self, "_memory_health_status", {})
        if isinstance(memory_health, dict) and memory_health:
            if memory_health.get("ok"):
                parts.append(
                    "MEMORY BRAIN: OK "
                    f"(target_sessions={int(memory_health.get('target_sessions', 0))}, "
                    f"target_findings={int(memory_health.get('target_findings', 0))}, "
                    f"patterns={int(memory_health.get('patterns_total', 0))}, "
                    f"high_quality_patterns={int(memory_health.get('high_quality_patterns', 0))})"
                )
            else:
                parts.append(
                    "MEMORY BRAIN: DEGRADED "
                    f"({str(memory_health.get('error', 'unknown'))[:120]})"
                )
            added_any = True

        compression_summary = str(getattr(self, "_compression_summary", "") or "").strip()
        if compression_summary:
            _cfg = get_config()
            try:
                _summary_cap = int(
                    getattr(_cfg, "memory_compression_summary_chars", 700)
                )
            except (TypeError, ValueError):
                _summary_cap = 700
            _eff_ctx = int(
                getattr(self, "_adaptive_num_ctx", 0)
                or getattr(_cfg, "llm_context_window", 0)
                or 0
            )
            if _eff_ctx >= 100_000:
                _summary_cap *= 2
            parts.append("ITERATIVE MEMORY HANDOFF:")
            parts.append(f"  {compression_summary[:_summary_cap]}")
            added_any = True

        recent_exec = self._build_recent_execution_memory(last_n=6)
        if recent_exec:
            parts.append("RECENT EXECUTION MEMORY:")
            parts.extend(recent_exec)
            added_any = True

        failure_memory = self._build_failure_memory(max_items=4)
        if failure_memory:
            parts.append("FAILURE MEMORY (DO NOT REPEAT):")
            parts.extend(failure_memory)
            added_any = True

        anomaly_memory = self._build_anomaly_memory(max_items=4)
        if anomaly_memory:
            parts.append("UNUSUAL SIGNALS / ANOMALIES:")
            parts.extend(anomaly_memory)
            added_any = True

        if self._session and self._session.vulnerabilities:
            vulns = self._session.vulnerabilities[:10]
            vlines = []
            for v in vulns:
                finding = v.get("finding", "")
                title = v.get("title", "")
                severity = v.get("severity", v.get("severity_level", "MEDIUM"))
                confidence = v.get("confidence", 0.0)
                proof = (
                    v.get("proof", v.get("evidence", ""))[:60]
                    if isinstance(v.get("evidence", ""), list)
                    else v.get("proof", "")[:60]
                )
                flag = v.get("flag", "")

                line_parts = [f"[{severity}]{'' if not flag else '[FLAG]'}"]
                if title:
                    line_parts.append(title[:40])
                else:
                    line_parts.append(finding[:40])
                if confidence > 0.7:
                    line_parts.append(f"(conf={int(confidence * 100)}%)")
                if proof:
                    line_parts.append(f"[{proof}...]")

                vlines.append("  - " + " ".join(line_parts))

            parts.append(f"CONFIRMED VULNS ({len(self._session.vulnerabilities)}):")
            parts.extend(vlines)
            added_any = True

        pending_hyps = self.state.get_pending_hypotheses(max_items=5)
        if pending_hyps:
            parts.append("ACTIVE HYPOTHESES TO TEST (DO NOT LOSE):")
            for i, h in enumerate(pending_hyps):
                claim = h.get("claim", "")[:80]
                test_plan = h.get("test_plan", "")[:60]
                confidence = h.get("confidence", 0.0)
                evidences = h.get("evidence_refs", [])[:2]
                evidence_str = f"[{len(evidences)}ev]" if evidences else ""

                parts.append(
                    f"  [{i + 1}] [{confidence * 100:.0f}%]{evidence_str} {claim}"
                )
                if test_plan:
                    parts.append(f"       → {test_plan}")
            added_any = True

        if self.state.evidence_log:
            high_ev = [
                e
                for e in self.state.evidence_log
                if severity_to_int(e.get("severity", 1)) >= 4
                and float(e.get("confidence", 0.0)) >= 0.75
            ][:5]
            if high_ev:
                parts.append("HIGH-VALUE EVIDENCE (CRITICAL - DO NOT COMPRESS):")
                for ev in high_ev:
                    summary = ev.get("summary", ev.get("finding", ""))[:90]
                    source = ev.get("source_tool", "tool")
                    severity = ev.get("severity", 1)
                    confidence = ev.get("confidence", 0.0)
                    parts.append(
                        f"  [{source}][SEV={severity}][{int(confidence * 100)}%] {summary}"
                    )
                added_any = True

        if self._session and self._session.injection_points:
            untested = get_untested_injection_points(self._session)
            if untested:
                parts.append(f"UNTESTED INJECTION POINTS ({len(untested)} remaining):")
                for pt in untested[:5]:
                    param = pt.get("parameter", "?")
                    url_path = pt.get("url", "")[:50]
                    inj_type = pt.get("type_hint", "??")
                    parts.append(f"  [{inj_type}] {param} @ {url_path}")
                added_any = True

        if not added_any:
            return ""

        return "\n".join(parts)

    def _build_handoff_summary(self) -> str:
        lines: list[str] = ["[SYSTEM: HANDOFF SUMMARY — task progress & orientation]"]

        original_task = ""
        for msg in self.state.conversation:
            if msg.get("role") == "user":
                original_task = str(msg.get("content", ""))[:300]
                break
        if original_task:
            lines.append(f"## Goal\n{original_task}")

        done_lines: list[str] = []
        if self._session and self._session.completed_phases:
            done_lines.append(
                f"Phases completed: {', '.join(self._session.completed_phases)}"
            )
        if self._session and self._session.subdomains:
            done_lines.append(f"Subdomains enumerated: {len(self._session.subdomains)}")
        if self._session and self._session.live_hosts:
            done_lines.append(f"Live hosts confirmed: {len(self._session.live_hosts)}")
        if self._session and self._session.vulnerabilities:
            done_lines.append(
                f"Vulnerabilities confirmed: {len(self._session.vulnerabilities)} "
                f"({', '.join(v.get('finding', '')[:50] for v in self._session.vulnerabilities[:3])})"
            )
        if self._session and self._session.tested_endpoints:
            done_lines.append(
                f"Endpoints tested: {len(self._session.tested_endpoints)}"
            )

        current_phase_str = "UNKNOWN"
        if self.pipeline:
            try:
                current_phase_str = self.pipeline.get_current_phase().value
            except Exception as e:
                logger.debug(
                    "Expected failure getting current phase for context: %s", e
                )

        in_progress_lines: list[str] = [f"Current phase: {current_phase_str}"]

        active_objs = [
            o
            for o in (self.state.objective_queue or [])
            if o.get("status") == "pending"
        ][:3]
        for obj in active_objs:
            obj_text = str(obj.get("title") or obj.get("description") or "").strip()
            if obj_text:
                in_progress_lines.append(f"  → {obj_text[:100]}")

        pending_hyps = self.state.get_pending_hypotheses(max_items=3)
        for h in pending_hyps:
            in_progress_lines.append(f"  [hypothesis] {h.get('claim', '')[:80]}")

        if done_lines or in_progress_lines:
            lines.append("## Progress")
            if done_lines:
                lines.append("### Done")
                lines.extend(f"  - {line}" for line in done_lines)
            if in_progress_lines:
                lines.append("### In Progress")
                lines.extend(f"  - {line}" for line in in_progress_lines)

        decision_lines: list[str] = []
        if self._session and self._session.technologies:
            tech = ", ".join(
                f"{k}/{v}" if v else k
                for k, v in list(self._session.technologies.items())[:6]
            )
            decision_lines.append(f"Technology stack: {tech}")
        if self._session and self._session.waf_profiles:
            for host, wp in list(self._session.waf_profiles.items())[:2]:
                decision_lines.append(
                    f"WAF detected on {host}: {wp.get('waf_name', '?')} "
                    f"(confidence={wp.get('confidence', 0):.0%})"
                )
        if decision_lines:
            lines.append("## Key Context")
            lines.extend(f"  - {line}" for line in decision_lines)

        if self._session and self._session.injection_points:
            untested = get_untested_injection_points(self._session)[:5]
            if untested:
                lines.append("## Next Steps")
                lines.append("  Untested injection points remaining:")
                for pt in untested:
                    path = urlparse(pt.get("url", "")).path or pt.get("url", "")
                    lines.append(
                        f"    [{pt.get('type_hint', '?')}] "
                        f"{pt.get('parameter', '?')} @ {path}"
                    )

        if len(lines) <= 1:
            return ""
        return "\n".join(lines)

    def _compress_old_tool_outputs(self, *, aggressive: bool = False) -> None:
        non_system = [m for m in self.state.conversation if m.get("role") != "system"]
        keep_window = 4 if aggressive else 8
        if len(non_system) <= keep_window:
            return

        stub_max = 750 if (aggressive or self.state.iteration > 30) else 1500

        compress_count = 0
        boundary_ids = set(id(m) for m in non_system[-keep_window:])

        for msg in self.state.conversation:
            if id(msg) in boundary_ids:
                continue
            if msg.get("_protected"):
                continue
            role = msg.get("role", "")
            content = str(msg.get("content", ""))
            if role == "tool" and len(content.encode()) > stub_max and self._compact_tool_message(msg, stub_max):
                compress_count += 1

        if compress_count:
            logger.debug(
                "Compressed %d tool outputs at iter %d (aggressive=%s, stub=%d chars)",
                compress_count,
                self.state.iteration,
                aggressive,
                stub_max,
            )

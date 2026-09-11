from __future__ import annotations

import logging
import re
from typing import Any, AsyncIterator
from urllib.parse import urlparse

from ..system import auto_load_skills_for_message, auto_load_skills_for_technologies
from .loop_exploration import _get_meaningful_evidence_threshold
from .loop_phase_mentor import maybe_inject_mentor_analysis
from .models import AgentEvent
from .output_parser import parse_tool_output
from .session import save_session, update_from_parsed_output
from .waf_detector import (
    build_waf_bypass_context,
    detect_waf_from_response,
    merge_waf_profiles,
    rank_bypass_strategies,
)

logger = logging.getLogger("airecon.agent")

# Static asset extensions that should NOT be fuzzed individually
# But their PARENT DIRECTORY might be worth fuzzing!
# Loaded from file_extensions.json (was hardcoded — now single source of truth)
def _load_pure_static_exts() -> frozenset[str]:
    """Load static asset extensions from file_extensions.json."""
    try:
        from airecon.proxy.data_loader import load_file_extensions
        data = load_file_extensions()
        exts = data.get("static", [])
        return frozenset(str(e).strip().lower() for e in exts if str(e).strip())
    except Exception as e:
        logging.getLogger("airecon.agent.loop_cycle_post").warning(
            "Failed to load static extensions from JSON: %s", e
        )
        return frozenset()


_PURE_STATIC_EXTS: frozenset[str] = _load_pure_static_exts()

# JS files are GOLD — do NOT block analysis
# PDFs can leak info — do NOT block entirely


def _detect_static_asset_abuse(tool_name: str, arguments: dict) -> str | None:

    cmd = ""
    target_url = ""

    if tool_name == "execute":
        cmd = arguments.get("command", "").lower()
        url_match = re.search(r"https?://[^\s\"'<>|;&]+", cmd)
        if url_match:
            target_url = url_match.group(0)

    elif tool_name in ("quick_fuzz", "advanced_fuzz", "deep_fuzz"):
        target_url = arguments.get("target", arguments.get("url", "")).lower()

    if not target_url:
        return None

    # Check if URL is a pure static asset
    try:
        parsed = urlparse(target_url)
        path = parsed.path.rstrip("/")
        last_segment = path.rsplit("/", 1)[-1] if "/" in path else path
        if "." in last_segment:
            ext = last_segment.rsplit(".", 1)[-1].lower()
            if ext in _PURE_STATIC_EXTS:
                # Extract parent directory for fuzzing suggestion
                parent_dir = target_url.rsplit("/", 1)[0] + "/"
                return (
                    f"[STATIC ASSET NOTICE] You are testing '{target_url}' which is a "
                    f"static asset file (.{ext}). The file itself has ZERO attack surface.\n\n"
                    f"BUT the directory is fuzzable! Try:\n"
                    f"  - Directory fuzzing: ffuf -u {parent_dir}FUZZ -w wordlist.txt\n"
                    f"  - File discovery: Look for .php, .asp, .jsp, .html, .json in that path\n"
                    f"  - Hidden files: .env, .git/, backup files, config files\n\n"
                    f"SKIP individual .{ext} files. Fuzz the directory instead:\n"
                    f"  {parent_dir}"
                )
            # JS files — explicitly encourage analysis
            if ext in ("js", "jsx", "ts", "tsx", "mjs"):
                return (
                    f"[JS FILE RECON] .js/.ts files are GOLD for recon! "
                    f"Instead of fuzzing the JS file itself, analyze it for:\n"
                    f"  - API routes: grep -E 'api|/v[0-9]+|/graphql' {last_segment}\n"
                    f"  - API keys/secrets: grep -iE 'key|secret|token|password|auth' {last_segment}\n"
                    f"  - Internal endpoints: grep -oE 'https?://[^ \"\\']+' {last_segment}\n"
                    f"  - Source map: Check for {last_segment}.map for full source reconstruction\n"
                    f"  - Use linkfinder/jsleak for automated JS analysis"
                )
    except Exception as exc:
        logger.debug("Static asset abuse detection parse error: %s", exc)

    return None


class _CyclePostMixin:
    def _check_static_asset_abuse(
        self, tool_name: str, arguments: dict, success: bool
    ) -> str | None:
        return _detect_static_asset_abuse(tool_name, arguments)

    # ── HTTP response structurer + behavioral diff ──────────────────────────
    # Reuses _parse_http_response and _diff_http_responses already defined in
    # executors_observe._ObserveExecutorMixin (available at runtime via MRO).

    def _auto_http_context(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        result: dict[str, Any],
        success: bool,
    ) -> str:
        """Parse HTTP output from a tool call and return a structured context card.

        On first call to an endpoint: saves the response as baseline.
        On subsequent calls: computes a behavioral diff and shows it.
        The LLM receives this and decides what changes mean — no verdict from Python.
        """
        if not success:
            return ""
        _HTTP_TOOLS = {"execute", "http_observe", "browser_action", "quick_fuzz", "advanced_fuzz"}
        if tool_name not in _HTTP_TOOLS:
            return ""

        stdout = ""
        if isinstance(result, dict):
            stdout = str(result.get("stdout", "") or result.get("body", "") or "")
        if not stdout or "HTTP/" not in stdout:
            return ""

        _parse = getattr(self, "_parse_http_response", None)
        _diff_fn = getattr(self, "_diff_http_responses", None)
        if not _parse:
            return ""

        parsed = _parse(stdout)
        status = parsed.get("status_code", 0)
        if not status:
            return ""

        # Extract the endpoint being tested
        endpoint = ""
        if tool_name == "execute":
            cmd = str(arguments.get("command", ""))
            m = re.search(r"https?://[^\s\"'<>]+", cmd)
            if m:
                endpoint = m.group(0).split("?")[0].rstrip("/")[:200]
        else:
            for k in ("url", "target", "endpoint"):
                v = str(arguments.get(k, "")).strip()
                if v:
                    endpoint = v.split("?")[0].rstrip("/")[:200]
                    break
        if not endpoint:
            return ""

        baseline_key = f"auto:{endpoint[:180]}"
        baseline = self.state.http_baselines.get(baseline_key)
        current_entry: dict[str, Any] = {
            "status_code": status,
            "headers": parsed.get("headers", {}),
            "body": (parsed.get("body", "") or "")[:4000],
            "body_size_bytes": len(parsed.get("body", "") or ""),
        }

        lines = ["[HTTP RESPONSE SNAPSHOT]", f"Endpoint : {endpoint}", f"Status   : {status}"]

        _interesting_hdrs = {
            "server", "x-powered-by", "content-type", "location", "set-cookie",
            "www-authenticate", "x-frame-options", "access-control-allow-origin",
            "x-generator", "x-aspnet-version", "x-runtime", "x-debug-token",
            "content-length", "transfer-encoding",
        }
        hdrs = parsed.get("headers", {})
        notable = {k: v for k, v in hdrs.items() if k.lower() in _interesting_hdrs}
        if notable:
            hdr_str = "; ".join(f"{k}: {str(v)[:55]}" for k, v in list(notable.items())[:6])
            lines.append(f"Headers  : {hdr_str}")

        body_excerpt = (parsed.get("body", "") or "")[:350].strip()
        if body_excerpt:
            lines.append(f"Body     :\n{body_excerpt}")

        has_diff_changes = False
        if baseline and _diff_fn:
            diff = _diff_fn(baseline, current_entry)
            changes: list[str] = []
            sc = diff.get("status_code_changed")
            if sc:
                changes.append(f"Status: {sc['from']} → {sc['to']}")
            delta = diff.get("body_size_delta_bytes", 0)
            if abs(delta) > 30:
                dir_ = "grew" if delta > 0 else "shrank"
                changes.append(
                    f"Body {dir_} by {abs(delta)} bytes "
                    f"({baseline['body_size_bytes']} → {current_entry['body_size_bytes']})"
                )
            elif diff.get("body_changed"):
                changes.append("Body content changed (similar size — different data)")
            for hk, hv in list(diff.get("header_changes", {}).items())[:3]:
                changes.append(
                    f"Header '{hk}': {str(hv.get('from', '–'))[:30]} → {str(hv.get('to', '–'))[:30]}"
                )
            if changes:
                has_diff_changes = True
                lines.append("\n[BEHAVIORAL DIFF vs BASELINE]")
                for ch in changes:
                    lines.append(f"  • {ch}")
                lines.append(
                    "\nAnalyze these changes. A status shift, body growth, or new headers "
                    "may be a behavioral signal. You decide what this means and whether to "
                    "escalate, test further, or continue."
                )
            self.state.http_baselines[baseline_key] = current_entry
        else:
            self.state.http_baselines[baseline_key] = current_entry

        # Only inject card when there is actionable information:
        # a behavioral diff, an error/redirect response, or first baseline visit
        is_first_visit = not baseline
        is_error_or_redirect = status >= 400
        if not (has_diff_changes or is_error_or_redirect or is_first_visit):
            return ""

        # On first visit without diff, keep output minimal to save context
        if is_first_visit and not is_error_or_redirect:
            return f"[HTTP BASELINE] {endpoint} → {status} ({current_entry['body_size_bytes']} bytes)"

        return "\n".join(lines)

    # ── Hypothesis feedback loop ─────────────────────────────────────────────

    def _hypothesis_feedback_context(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        result_text: str,
    ) -> str:
        """Link a tool result to pending hypotheses so the LLM can update its reasoning.

        Python finds the overlap between result and hypothesis (by endpoint or keywords).
        The LLM decides whether the hypothesis is confirmed — no verdict here.
        """
        pending = self.state.get_pending_hypotheses(max_items=6)
        if not pending:
            return ""
        # Rate-limit: hypothesis feedback at most every 4 iterations to avoid context flood
        _last_hyp_iter = getattr(self, "_last_hyp_feedback_iter", -10)
        if self.state.iteration - _last_hyp_iter < 4:
            return ""

        endpoint = ""
        cmd_text = ""
        if tool_name == "execute":
            cmd_text = str(arguments.get("command", "")).lower()
            m = re.search(r"https?://[^\s\"'<>]+", cmd_text)
            if m:
                endpoint = m.group(0).split("?")[0].rstrip("/")
        else:
            for k in ("url", "target", "endpoint"):
                v = str(arguments.get(k, "")).strip()
                if v:
                    endpoint = v.split("?")[0].rstrip("/")
                    break

        # Derive host+path and path-only views of the endpoint so that claims
        # written in shorthand (e.g. "auth bypass on /login") still match.
        endpoint_lower = endpoint.lower()
        host_path = ""
        path_only = ""
        if endpoint_lower:
            host_path = re.sub(r"^https?://", "", endpoint_lower)
            m_path = re.search(r"/[\w\-./]+$", host_path)
            if m_path:
                path_only = m_path.group(0)

        search_text = (cmd_text + " " + result_text[:500]).lower()
        matched: list[dict[str, Any]] = []

        for hyp in pending:
            claim_lower = str(hyp.get("claim", "")).lower()
            hyp_tags = {str(t).lower() for t in hyp.get("tags", [])}

            # Match by endpoint overlap — full URL, host+path, or path-only
            if endpoint_lower and len(endpoint_lower) > 5 and (
                endpoint_lower in claim_lower
                or (host_path and len(host_path) > 5 and host_path in claim_lower)
                or (path_only and len(path_only) > 3 and path_only in claim_lower)
            ):
                matched.append(hyp)
                continue

            # Match by keyword overlap (≥2 meaningful words shared)
            claim_words = {w for w in claim_lower.split() if len(w) >= 5}
            result_words = set(search_text.split())
            if len(claim_words & result_words) >= 2:
                matched.append(hyp)
                continue

            # Match by tag vs tool name
            if hyp_tags & {tool_name.lower()} and hyp not in matched:
                matched.append(hyp)

        if not matched:
            return ""

        lines: list[str] = []
        for hyp in matched[:2]:
            hyp_id = str(hyp.get("id", "?"))
            claim = str(hyp.get("claim", ""))
            excerpt = result_text[:300].strip()
            lines.append(f"[HYPOTHESIS CHECK — {hyp_id}]")
            lines.append(f"Pending : {claim}")
            if excerpt:
                lines.append(f"New data:\n{excerpt}")
            lines.append(
                "Does this confirm, refute, or is inconclusive for this hypothesis? "
                "Update your reasoning: escalate, pivot, or close."
            )
            lines.append("")
            self.state.update_hypothesis(hyp_id, "testing", result_text[:200])

        self._last_hyp_feedback_iter = self.state.iteration  # type: ignore[attr-defined]
        return "\n".join(lines).strip()

    # ── Context pruning ──────────────────────────────────────────────────────

    # Prefixes of system messages that are safe to prune when context grows.
    # WAF context, target intelligence, and skill blocks are kept.
    _PRUNABLE_PREFIXES = (
        "[HTTP BASELINE]",
        "[HTTP RESPONSE SNAPSHOT]",
        "[HYPOTHESIS CHECK —",
        "[NEW EVIDENCE —",
        "[BEHAVIORAL DIFF",
        "[SCOPE ADVISORY]",
        "[VERIFICATION —",
        "[SESSION —",
        "[RATE LIMIT —",
    )

    # These are re-injected fresh every iteration, so older copies are pure
    # waste — keep ONLY the latest one. Left unbounded they dominated the
    # context (HANDOFF SUMMARY appeared 15×, ~38k tokens of duplicated system
    # boilerplate crowding out the agent's actual recon data), which is the main
    # reason analysis/exploit underperformed regardless of model.
    _SINGLETON_SYSTEM_PREFIXES = (
        "[SYSTEM: HANDOFF SUMMARY",
        "[VISIONARY ANALYSIS",
        "[SYSTEM: ANALYSIS —",
        "[SYSTEM: LLM RECON VALIDATION",
        "[SYSTEM: OUTPUT FILE MANIFEST",
        "[SYSTEM: RESUMED SESSION",
        "[SYSTEM: CRITICAL FINDINGS",
        "[SYSTEM: HIGH-VALUE TARGETS",
        "META-REASONING",
        "<system_tool_intelligence",
        "<target_intelligence",
        "<system_learned_insights",
        "<system_adaptive_recommendations",
    )

    def _prune_stale_system_context(self) -> None:
        """Collapse re-injected ephemeral system messages to control context.

        Runs EVERY iteration because the heavy families (HANDOFF SUMMARY,
        VISIONARY ANALYSIS, EXPERT/ANALYSIS guidance, RECON VALIDATION,
        target/tool intelligence, ...) are re-added fresh each turn — left
        unchecked they accumulated into ~38k tokens of duplicated boilerplate
        that crowded out the agent's actual recon data. Policy:
          * singleton families  → keep only the latest 1 (older copies are stale)
          * `[SKILL LOADED: X]`  → keep latest 1 PER DISTINCT skill (different
            skills are not duplicates)
          * snapshot families    → keep the latest 2
        Core/registration system messages (no matched prefix) are never pruned.
        """
        before = len(self.state.conversation)
        singleton_seen: set[str] = set()
        skill_seen: set[str] = set()
        prunable_seen: dict[str, int] = {}
        keep: list[dict] = []

        # Walk in reverse so the kept copy is always the most recent.
        for msg in reversed(self.state.conversation):
            if msg.get("role") != "system":
                keep.append(msg)
                continue
            content = str(msg.get("content", ""))

            sp = next(
                (p for p in self._SINGLETON_SYSTEM_PREFIXES if content.startswith(p)),
                None,
            )
            if sp is not None:
                if sp not in singleton_seen:
                    singleton_seen.add(sp)
                    keep.append(msg)
                continue

            if content.startswith("[SKILL LOADED"):
                key = content.split("\n", 1)[0].strip()
                if key not in skill_seen:
                    skill_seen.add(key)
                    keep.append(msg)
                continue

            mp = next(
                (p for p in self._PRUNABLE_PREFIXES if content.startswith(p)),
                None,
            )
            if mp is None:
                keep.append(msg)
                continue
            count = prunable_seen.get(mp, 0)
            if count < 2:
                keep.append(msg)
                prunable_seen[mp] = count + 1

        if len(keep) != before:
            self.state.conversation = list(reversed(keep))
            logger.debug(
                "Context pruned at iter %d: %d → %d messages",
                self.state.iteration,
                before,
                len(self.state.conversation),
            )

    # ── Scope advisory drainer ───────────────────────────────────────────────

    def _drain_scope_advisories(self) -> str:
        """Consume pending soft scope advisories queued by the validator.

        The validator records out-of-declared-scope URLs it let through when
        scope_lock is not strict. This surfaces them to the LLM so it can
        justify or abandon the pivot on its own — Python never decides.
        """
        advisories = getattr(self, "_pending_scope_advisories", None) or []
        if not advisories:
            return ""
        # Move them out so they're not emitted twice.
        self._pending_scope_advisories = []  # type: ignore[attr-defined]

        lines = ["[SCOPE ADVISORY]"]
        declared = ""
        seen: set[str] = set()
        for adv in advisories[:4]:
            url = str(adv.get("url", "")).strip()
            if not url or url in seen:
                continue
            seen.add(url)
            declared = str(adv.get("declared_scope", "")).strip() or declared
            lines.append(f"  • {url}")
        if len(advisories) > 4:
            lines.append(f"  … and {len(advisories) - 4} more")
        lines.append(
            f"Declared scope: {declared or '(apex target)'}"
        )
        lines.append(
            "These URLs sit outside the declared apex. Before continuing, "
            "confirm each one is target-owned (bucket, CDN, SaaS tenant, "
            "subsidiary) or a legitimate 3rd-party used for read-only "
            "validation. If you cannot justify it as target-owned or "
            "validation-related, stop testing it and pivot back in-scope."
        )
        return "\n".join(lines)

    # ── Session & rate-limit advisories ──────────────────────────────────────

    def _build_session_rate_advisory(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        result: dict[str, Any],
    ) -> str:
        """Surface session state + rate-limit signals detected by the HTTP layer.

        Python reports observed facts (cookies attached, cookies harvested,
        rate-limit response received). The LLM decides backoff timing,
        re-auth, or pivot. No policy enforcement here.
        """
        if not isinstance(result, dict):
            return ""

        blocks: list[str] = []

        used = result.get("session_cookies_used") or []
        harvested = result.get("session_cookies_harvested") or []
        csrf_meta = result.get("csrf_token") or {}
        if used or harvested or csrf_meta:
            host_key = ""
            for k in ("url", "target", "endpoint"):
                v = str(arguments.get(k, "")).strip()
                if v:
                    try:
                        host_key = urlparse(v).hostname or ""
                    except Exception as _e:
                        logger.debug("session advisory url parse error: %s", _e)
                        host_key = ""
                    if host_key:
                        break
            header = f"[SESSION — {host_key or 'host'}]"
            lines = [header]
            if used:
                lines.append(
                    f"Cookies reused from jar: {', '.join(str(n) for n in used[:6])}"
                )
            if harvested:
                lines.append(
                    f"New cookies captured:    {', '.join(str(n) for n in harvested[:6])}"
                )
            if csrf_meta:
                _field = str(csrf_meta.get("field", ""))
                _source = str(csrf_meta.get("source", ""))
                lines.append(
                    f"CSRF token captured:     field='{_field}' source='{_source}' — "
                    "re-inject on your next state-changing POST/PUT/PATCH/DELETE. "
                    "For meta/form tokens add it as a header (e.g. 'X-CSRF-Token') "
                    "or body field; for cookie tokens mirror the value as header."
                )
            lines.append(
                "These cookies will auto-attach to future http_observe calls for "
                "this host. If auth broke (401/403), re-authenticate or clear the "
                "jar before retrying."
            )
            blocks.append("\n".join(lines))

        rl = result.get("rate_limit")
        if isinstance(rl, dict) and rl.get("kind"):
            host_hint = ""
            for k in ("url", "target", "endpoint"):
                v = str(arguments.get(k, "")).strip()
                if v:
                    try:
                        host_hint = urlparse(v).hostname or ""
                    except Exception as _e:
                        logger.debug("rate-limit advisory url parse error: %s", _e)
                        host_hint = ""
                    if host_hint:
                        break
            header = f"[RATE LIMIT — {host_hint or 'host'}]"
            lines = [header, f"Signal : {rl.get('kind')}"]
            if rl.get("retry_after_seconds") is not None:
                lines.append(f"Retry after : {rl.get('retry_after_seconds')}s")
            elif rl.get("retry_after_raw"):
                lines.append(f"Retry after : {rl.get('retry_after_raw')}")
            if rl.get("reset_at"):
                lines.append(f"Reset at : {rl.get('reset_at')}")
            lines.append(
                "Throttling detected. Do NOT hammer this host — slow down, "
                "pivot to a different host/endpoint, or wait before retrying."
            )
            blocks.append("\n".join(lines))

        return "\n\n".join(blocks)

    # ── Evidence action director ─────────────────────────────────────────────

    def _evidence_action_directive(
        self,
        phase: str,
        meaningful_delta: int,
        new_evidence: list[dict[str, Any]],
    ) -> str:
        """Inject a general escalation directive when new meaningful evidence appears.

        Deliberately does NOT name a specific vuln type — the LLM reasons about
        what the evidence means. This keeps the detection open to novel findings.
        """
        # Only fire when at least 2 meaningful findings arrive at once,
        # or every 5th meaningful find (to avoid injecting on every minor signal).
        if meaningful_delta <= 0 or not new_evidence:
            return ""
        total_meaningful = sum(
            1 for e in getattr(self.state, "evidence_log", [])
            if float(e.get("confidence", 0.0)) >= 0.65
        )
        if meaningful_delta < 2 and total_meaningful % 5 != 0:
            return ""

        summaries = [
            str(e.get("summary", ""))[:120]
            for e in new_evidence
            if str(e.get("summary", "")).strip()
        ][:3]
        if not summaries:
            return ""

        lines = [
            f"[NEW EVIDENCE — {meaningful_delta} meaningful finding(s) · phase: {phase}]"
        ]
        for s in summaries:
            lines.append(f"  • {s}")
        lines.append(
            "\nExamine this evidence critically. Ask yourself:\n"
            "  1. Is this a vulnerability signal, an attack surface, or noise?\n"
            "  2. Does it confirm a pending hypothesis or open a new one?\n"
            "  3. What is the most impactful next action — exploit, escalate, or pivot?\n"
            "Act on the most promising signal. Do not repeat what you already know."
        )
        return "\n".join(lines)

    async def _finalize_tool_results(
        self,
        current_phase: Any,
        all_results: dict[int, tuple[Any, ...]],
        has_task_complete: bool,
    ) -> AsyncIterator[AgentEvent]:
        self._iteration_terminated = False
        for idx in sorted(all_results.keys()):
            res = all_results[idx]
            (
                _,
                tc,
                tool_name,
                arguments,
                was_valid,
                duration,
                result,
                output_file,
                success,
            ) = res

            if not was_valid:
                arg_error = result.get("error", "Unknown validation error")
                yield AgentEvent(
                    type="tool_end",
                    data={
                        "tool_id": str(idx),
                        "tool": tool_name,
                        "success": False,
                        "duration": 0.0,
                        "result_preview": f"VALIDATION ERROR: {arg_error}",
                        "output_file": None,
                        "tool_counts": self.state.tool_counts,
                        "token_usage": dict(self.state.token_usage),
                        "skills_used": list(self.state.skills_used),
                        "caido": {
                            "active": bool(getattr(self, "_caido_available", False))
                            or (
                                self.state.tool_counts.get("caido_send_request", 0)
                                + self.state.tool_counts.get("caido_automate", 0)
                            )
                            > 0,
                            "findings_count": (
                                self.state.tool_counts.get("caido_send_request", 0)
                                + self.state.tool_counts.get("caido_automate", 0)
                            ),
                        },
                    },
                )
                self._consecutive_failures += 1
                self._append_tool_result(
                    tool_name,
                    f"ARGUMENT VALIDATION FAILED: {arg_error}\nFix the arguments and retry.",
                    False,
                    tc.get("id"),
                )
                continue

            yield AgentEvent(
                type="tool_end",
                data={
                    "tool_id": str(idx),
                    "tool": tool_name,
                    "success": success,
                    "duration": round(duration, 2),
                    "result_preview": self._truncate_result(result),
                    "output_file": output_file,
                    "tool_counts": self.state.tool_counts,
                    "token_usage": dict(self.state.token_usage),
                    "skills_used": list(self.state.skills_used),
                    "caido": {
                        "active": bool(getattr(self, "_caido_available", False))
                        or (
                            self.state.tool_counts.get("caido_send_request", 0)
                            + self.state.tool_counts.get("caido_automate", 0)
                        )
                        > 0,
                        "findings_count": (
                            self.state.tool_counts.get("caido_send_request", 0)
                            + self.state.tool_counts.get("caido_automate", 0)
                        ),
                    },
                },
            )
            self._track_tool_usage(tool_name, arguments)

            _duration = float(duration)
            _output_size = len(
                str(result.get("stdout", "") or result.get("result", ""))
                if isinstance(result, dict)
                else ""
            )
            self._record_tool_to_memory(
                tool_name=tool_name,
                success=bool(success),
                duration=_duration,
                output_size=_output_size,
            )

            if success:
                self._consecutive_failures = 0
                self.state.missing_tool_count = 0
            else:
                self._consecutive_failures += 1

            raw_command = (
                arguments.get("command", "")
                if tool_name == "execute"
                else tool_name
            )
            content_str = self._smart_format_tool_result(
                tool_name, result, success, raw_command
            )

            # Anti-hallucination guard: detect fuzzing/testing of static assets
            if tool_name in ("execute", "quick_fuzz", "advanced_fuzz", "deep_fuzz"):
                _static_guard_note = self._check_static_asset_abuse(
                    tool_name, arguments, success
                )
                if _static_guard_note:
                    content_str = _static_guard_note + "\n\n" + content_str

            if self.pipeline:
                phase_warn = self.pipeline.check_tool_phase_fit(tool_name)
                if phase_warn:
                    content_str = phase_warn + "\n\n" + content_str
            phase_gate_note = self._build_phase_gate_note(tool_name, success)
            if phase_gate_note:
                content_str = phase_gate_note + "\n\n" + content_str

            if success and tool_name in ("web_search", "browser_action"):
                content_str += (
                    "\n\n[SYSTEM: MANDATORY FILE SAVE]\n"
                    f"You just executed `{tool_name}` successfully. "
                    "You are STRICTLY FORBIDDEN from keeping these results only in memory. "
                    "You MUST immediately use the `create_file` tool to save these findings "
                    "(URLs, text content, view_source, or console_logs) into the `output/` directory "
                    "(e.g., `output/dork_results.txt` or `output/source.txt`). "
                    "Do NOT proceed until this data is saved to disk!"
                )

            _SESSION_UPDATE_TOOLS = (
                "execute",
                "browser_action",
                "quick_fuzz",
                "code_analysis",
            )
            if success and tool_name in _SESSION_UPDATE_TOOLS and self._session:
                stdout = result.get("stdout", "") or result.get("result", "") or ""
                if isinstance(stdout, str) and stdout.strip():
                    _techs_before = dict(self._session.technologies)
                    _phase_for_parse = self._get_current_phase().value
                    parsed_out = parse_tool_output(
                        raw_command, stdout, phase=_phase_for_parse
                    )
                    if parsed_out and parsed_out.total_count > 0:
                        update_from_parsed_output(
                            self._session, parsed_out, raw_command
                        )
                        save_session(self._session)

                    _new_techs = {
                        k: v
                        for k, v in self._session.technologies.items()
                        if k not in _techs_before
                    }
                    if _new_techs:
                        _tech_skill_ctx, _tech_names = auto_load_skills_for_technologies(
                            _new_techs,
                            already_loaded=self._loaded_tech_skill_paths,
                        )
                        if _tech_skill_ctx:
                            self.state.conversation.append(
                                {"role": "system", "content": _tech_skill_ctx}
                            )
                            self._loaded_tech_skill_paths.update(_tech_names)
                            for _sn in _tech_names:
                                if _sn not in self.state.skills_used:
                                    self.state.skills_used.append(_sn)
                            for skill_rel in _tech_names:
                                if skill_rel not in self._session.loaded_skills:
                                    self._session.loaded_skills.append(skill_rel)
                            logger.info(
                                "Tech-skill auto-injected for new techs: %s → skills: %s",
                                list(_new_techs.keys()),
                                _tech_names,
                            )

            phase_after_tool = self._get_current_phase()
            meaningful_before = sum(
                1
                for e in self.state.evidence_log
                if float(e.get("confidence", 0.0))
                >= _get_meaningful_evidence_threshold()
            )
            _total_ev_before = len(self.state.evidence_log)
            self._record_evidence_from_result(
                phase=phase_after_tool.value,
                tool_name=tool_name,
                arguments=arguments,
                result=result,
                success=success,
                output_file=output_file,
            )
            self._update_objectives_from_tool(
                phase_after_tool,
                tool_name,
                arguments,
                success,
                result,
                output_file,
            )
            self._update_objectives_from_session(phase_after_tool)
            if hasattr(self, "_save_new_findings_to_memory"):
                try:
                    self._save_new_findings_to_memory()
                except Exception as _finding_sync_err:
                    logger.debug(
                        "Failed to sync findings into memory DB: %s",
                        _finding_sync_err,
                    )
            meaningful_after = sum(
                1
                for e in self.state.evidence_log
                if float(e.get("confidence", 0.0))
                >= _get_meaningful_evidence_threshold()
            )
            self.state.record_tool_outcome(
                phase_after_tool.value,
                tool_name,
                success=bool(success),
                meaningful_evidence_delta=max(
                    0, meaningful_after - meaningful_before
                ),
            )

            # ── Evidence-driven skill injection ────────────────────────
            # When new meaningful evidence is added, derive relevant skills
            # from what was actually discovered (not from user keywords).
            if meaningful_after > meaningful_before:
                _threshold = _get_meaningful_evidence_threshold()
                _new_evidence = [
                    e
                    for e in self.state.evidence_log[-(meaningful_after - meaningful_before + 10):]
                    if float(e.get("confidence", 0.0)) >= _threshold
                ]
                if _new_evidence:
                    _ev_parts: list[str] = []
                    for _ev in _new_evidence:
                        _ev_parts.append(str(_ev.get("summary", "")))
                        for _tag in _ev.get("tags", []):
                            _ev_parts.append(str(_tag))
                    _ev_text = " ".join(_ev_parts).strip()
                    if _ev_text:
                        _already_loaded: set[str] = set(
                            getattr(self, "_loaded_tech_skill_paths", set())
                        )
                        if self._session:
                            _already_loaded.update(self._session.loaded_skills)
                        _ev_skill_ctx, _ev_skill_names = auto_load_skills_for_message(
                            _ev_text,
                            phase=phase_after_tool.value,
                            session_loaded_skills=_already_loaded,
                        )
                        if _ev_skill_ctx and _ev_skill_names:
                            _ev_skill_ctx = _ev_skill_ctx.replace(
                                "Based on your request,",
                                "Based on evidence discovered,",
                            ).replace(
                                "based on your request",
                                "based on evidence discovered",
                            )
                            self.state.conversation.append(
                                {"role": "system", "content": _ev_skill_ctx}
                            )
                            if hasattr(self, "_loaded_tech_skill_paths"):
                                self._loaded_tech_skill_paths.update(_ev_skill_names)
                            for _sn in _ev_skill_names:
                                if _sn not in self.state.skills_used:
                                    self.state.skills_used.append(_sn)
                            if self._session:
                                for _sn in _ev_skill_names:
                                    if _sn not in self._session.loaded_skills:
                                        self._session.loaded_skills.append(_sn)
                            logger.info(
                                "Evidence-driven skill injection: evidence=%d new → skills: %s",
                                meaningful_after - meaningful_before,
                                _ev_skill_names,
                            )

            # ── Intelligence: Adaptive Learning ────────────────────────
            if hasattr(self, "_record_adaptive_learning"):
                self._record_adaptive_learning(
                    tool_name=tool_name,
                    arguments=arguments,
                    result=result,
                    success=bool(success),
                    duration=duration,
                    phase=phase_after_tool.value,
                )

            if (
                success
                and phase_after_tool.value == "EXPLOIT"
                and self.state.exploit_chains
            ):
                try:
                    for _cd in self.state.exploit_chains:
                        if _cd.get("status") not in ("planning", "active"):
                            continue
                        _cs_idx = int(_cd.get("current_step_index", 0))
                        _steps = _cd.get("steps", [])
                        if _cs_idx >= len(_steps):
                            continue
                        _cur_step = _steps[_cs_idx]
                        _hint = str(_cur_step.get("tool_hint", "")).lower()

                        _match_token = tool_name.lower()
                        if _match_token == "execute" and isinstance(  # nosec B105
                            arguments, dict
                        ):
                            _raw_cmd = str(arguments.get("command", "")).strip()
                            _stripped = re.sub(
                                r"^cd\s+\S+\s*&&\s*", "", _raw_cmd
                            ).strip()
                            _binary = (
                                _stripped.split()[0].lower() if _stripped else ""
                            )
                            _shell_builtins = {
                                "cd",
                                "echo",
                                "export",
                                "source",
                                ".",
                                "for",
                                "while",
                                "if",
                            }
                            if _binary and _binary not in _shell_builtins:
                                _match_token = _binary
                        if _hint and (
                            _match_token in _hint or tool_name.lower() in _hint
                        ):
                            _cur_step["status"] = "done"
                            _next_idx = _cs_idx + 1
                            _chain_name = _cd.get("name", "?")
                            _vuln_basis = (
                                str(_cd.get("vuln_basis", "")).lower().strip()
                            )
                            if _next_idx >= len(_steps):
                                _cd["status"] = "completed"
                                _cd["current_step_index"] = _next_idx
                                logger.info(
                                    "Exploit chain '%s' COMPLETED after %d steps",
                                    _chain_name,
                                    len(_steps),
                                )

                                if _vuln_basis and self.state.hypothesis_queue:
                                    _vb_words = {
                                        w
                                        for w in _vuln_basis.split()
                                        if len(w) >= 4
                                    }
                                    for _hyp in self.state.hypothesis_queue:
                                        if _hyp.get("status") not in (
                                            "pending",
                                            "testing",
                                        ):
                                            continue
                                        _hwords = set(
                                            str(_hyp.get("claim", ""))
                                            .lower()
                                            .split()
                                        )
                                        if _vb_words & _hwords:
                                            self.state.update_hypothesis(
                                                str(_hyp.get("id", "")),
                                                "confirmed",
                                                f"Exploit chain '{_chain_name}' completed all steps",
                                            )
                                            break
                            else:
                                _cd["current_step_index"] = _next_idx
                                _cd["status"] = "active"
                                _steps[_next_idx]["status"] = "in_progress"
                                logger.info(
                                    "Exploit chain '%s' advanced to step %d/%d: %s",
                                    _chain_name,
                                    _next_idx + 1,
                                    len(_steps),
                                    _steps[_next_idx].get("description", "")[:60],
                                )

                                if _vuln_basis and self.state.hypothesis_queue:
                                    _vb_words = {
                                        w
                                        for w in _vuln_basis.split()
                                        if len(w) >= 4
                                    }
                                    for _hyp in self.state.hypothesis_queue:
                                        if _hyp.get("status") != "pending":
                                            continue
                                        _hwords = set(
                                            str(_hyp.get("claim", ""))
                                            .lower()
                                            .split()
                                        )
                                        if _vb_words & _hwords:
                                            self.state.update_hypothesis(
                                                str(_hyp.get("id", "")),
                                                "testing",
                                                f"Exploit chain '{_chain_name}' in progress (step {_next_idx + 1}/{len(_steps)})",
                                            )
                                            break
                            break
                except Exception as _chain_adv_e:
                    logger.debug("Chain advancement error: %s", _chain_adv_e)

                if (
                    success
                    and phase_after_tool.value == "EXPLOIT"
                    and self.state.exploit_chains
                ):
                    try:
                        _chain_found_match = False
                        _chain_hint_for_correction = ""
                        for _cd in self.state.exploit_chains:
                            if _cd.get("status") not in ("planning", "active"):
                                continue
                            _cs_idx = int(_cd.get("current_step_index", 0))
                            _steps = _cd.get("steps", [])
                            if _cs_idx >= len(_steps):
                                continue
                            _cur_step = _steps[_cs_idx]
                            _hint = str(_cur_step.get("tool_hint", "")).lower()
                            _chain_hint_for_correction = _hint

                            if _hint:
                                _match_token = tool_name.lower()
                                if _match_token == "execute" and isinstance(  # nosec B105
                                    arguments, dict
                                ):
                                    _raw_cmd = str(
                                        arguments.get("command", "")
                                    ).strip()
                                    _stripped = re.sub(
                                        r"^cd\s+\S+\s*&&\s*", "", _raw_cmd
                                    ).strip()
                                    _binary = (
                                        _stripped.split()[0].lower()
                                        if _stripped
                                        else ""
                                    )
                                    _shell_builtins = {
                                        "cd",
                                        "echo",
                                        "export",
                                        "source",
                                        ".",
                                        "for",
                                        "while",
                                        "if",
                                    }
                                    if _binary and _binary not in _shell_builtins:
                                        _match_token = _binary
                                if (
                                    _match_token in _hint
                                    or tool_name.lower() in _hint
                                ):
                                    _chain_found_match = True
                                    break

                        if not _chain_found_match and _chain_hint_for_correction:
                            logger.info(
                                "Chain correction: LLM used '%s' but chain requires '%s'",
                                tool_name,
                                _chain_hint_for_correction,
                            )
                            content_str += (
                                f"\n\n[EXPLOIT CHAIN CORRECTION] You used '{tool_name}' but your active "
                                f"exploit chain step requires '{_chain_hint_for_correction}'.\n"
                                f"USE '{_chain_hint_for_correction}' NOW to advance the chain. "
                                f"This tool hint is a strong recommendation — ignoring it will waste iterations."
                            )
                    except Exception as _chain_corr_e:
                        logger.debug(
                            "Chain correction injection error: %s", _chain_corr_e
                        )

            self.state.record_tool_use(phase_after_tool.value, tool_name)

            if success:
                _skip_learning_tools = {
                    "create_file",
                    "read_file",
                    "list_files",
                    "request_user_input",
                }
                if tool_name not in _skip_learning_tools:
                    _phase_name = str(phase_after_tool.value).upper()
                    _pattern_type = (
                        "exploit"
                        if _phase_name in {"EXPLOIT", "REPORT"}
                        else "recon"
                    )
                    _technique_name = tool_name
                    _cmd_snapshot = tool_name
                    if tool_name == "execute" and isinstance(arguments, dict):
                        _raw_cmd = str(arguments.get("command", "")).strip()
                        _stripped = re.sub(
                            r"^cd\s+\S+\s*&&\s*", "", _raw_cmd
                        ).strip()
                        if _stripped:
                            _cmd_snapshot = _stripped[:300]
                            _first = (
                                _stripped.split(maxsplit=1)[0]
                                .rsplit("/", 1)[-1]
                                .strip()
                                .lower()
                            )
                            if _first:
                                _technique_name = _first
                    self._save_recon_exploit_pattern(
                        technique_name=_technique_name,
                        pattern_type=_pattern_type,
                        commands=[_cmd_snapshot],
                        success=True,
                        description=f"{_phase_name} step using {_technique_name}",
                    )

            budget_note = self._check_tool_budget(tool_name, phase_after_tool.value)
            if budget_note:
                content_str = budget_note + "\n\n" + content_str

            if (
                success
                and tool_name in ("http_observe", "execute")
                and self._session
            ):
                _waf_headers: dict[str, str] = result.get("headers", {}) or {}
                _waf_body: str = str(
                    result.get("body_excerpt") or result.get("stdout") or ""
                )[:3000]
                _waf_status: int = int(result.get("status_code") or 0)
                if _waf_headers or _waf_body:
                    try:
                        _waf_url = arguments.get("url") or arguments.get(
                            "command", ""
                        )
                        try:
                            _waf_host = urlparse(str(_waf_url)).netloc or str(
                                _waf_url
                            )
                        except Exception as exc:
                            logger.debug("WAF host URL parse error: %s", exc)
                            _waf_host = str(_waf_url)[:50]
                        if not _waf_host or " " in _waf_host:
                            _url_match = re.search(
                                r"https?://[^\s\"']+", str(_waf_url)
                            )
                            if _url_match:
                                _waf_host = urlparse(_url_match.group(0)).netloc
                        _waf_host = str(_waf_host).strip()[:120]
                        _waf_profile = detect_waf_from_response(
                            host=_waf_host,
                            status_code=_waf_status,
                            headers=_waf_headers,
                            body_excerpt=_waf_body,
                            iteration=self.state.iteration,
                        )
                        _existing = self._session.waf_profiles.get(_waf_host)
                        _merged = merge_waf_profiles(
                            _existing,
                            _waf_profile,
                            host=_waf_host,
                            status_code=_waf_status,
                            iteration=self.state.iteration,
                        )
                        if _merged:
                            _old_stats = {}
                            if isinstance(_existing, dict):
                                _old_stats = (
                                    _existing.get("strategy_stats", {}) or {}
                                )

                            if tool_name == "execute" and isinstance(
                                arguments, dict
                            ):
                                _cmd_lower = str(
                                    arguments.get("command", "")
                                ).lower()
                                _prior_strategies = []
                                if isinstance(_existing, dict):
                                    _prior_strategies = list(
                                        _existing.get("bypass_strategies", [])
                                    )
                                _matched_strategy = ""
                                for _st in _prior_strategies:
                                    _st_l = str(_st).lower()
                                    if "header" in _st_l and any(
                                        h in _cmd_lower
                                        for h in (
                                            "x-forwarded-for",
                                            "user-agent",
                                            "-h ",
                                        )
                                    ):
                                        _matched_strategy = str(_st)
                                        break
                                    if "encoding" in _st_l and (
                                        "%25" in _cmd_lower
                                        or "%2f" in _cmd_lower
                                        or "%27" in _cmd_lower
                                    ):
                                        _matched_strategy = str(_st)
                                        break
                                    if "case variation" in _st_l and any(
                                        k in _cmd_lower
                                        for k in ("union", "select", "script")
                                    ):
                                        _matched_strategy = str(_st)
                                        break
                                    if "verb" in _st_l and any(
                                        m in _cmd_lower
                                        for m in (
                                            "-x post",
                                            "-x put",
                                            "-x patch",
                                            "-x delete",
                                        )
                                    ):
                                        _matched_strategy = str(_st)
                                        break
                                if _matched_strategy:
                                    _stat = _old_stats.setdefault(
                                        _matched_strategy,
                                        {"attempts": 0, "successes": 0},
                                    )
                                    _stat["attempts"] = (
                                        int(_stat.get("attempts", 0)) + 1
                                    )
                                    if _waf_status and _waf_status not in (
                                        403,
                                        406,
                                        412,
                                        429,
                                        501,
                                        999,
                                    ):
                                        _stat["successes"] = (
                                            int(_stat.get("successes", 0)) + 1
                                        )
                            _ranked = rank_bypass_strategies(_merged, _old_stats)[
                                :8
                            ]
                            _merged.bypass_strategies = _ranked
                            _history: list[dict[str, Any]] = []
                            if isinstance(_existing, dict) and isinstance(
                                _existing.get("history"), list
                            ):
                                _history = list(_existing["history"])
                            _history.append(
                                {
                                    "iteration": self.state.iteration,
                                    "status_code": _waf_status,
                                    "tool": tool_name,
                                    "confidence": round(_merged.confidence, 3),
                                    "waf_name": _merged.waf_name,
                                }
                            )
                            self._session.waf_profiles[_waf_host] = {
                                "host": _waf_host,
                                "waf_name": _merged.waf_name,
                                "confidence": _merged.confidence,
                                "evidence": _merged.evidence,
                                "detected_at": self.state.iteration,
                                "bypass_strategies": _ranked,
                                "strategy_stats": _old_stats,
                                "history": _history[-15:],
                            }
                            _waf_ctx = build_waf_bypass_context(_merged)
                            if _waf_ctx:
                                self.state.conversation = [
                                    m
                                    for m in self.state.conversation
                                    if not m.get("content", "").startswith(
                                        f'<waf_bypass host="{_waf_host}"'
                                    )
                                ]
                                self.state.conversation.append(
                                    {
                                        "role": "system",
                                        "content": _waf_ctx,
                                    }
                                )
                                logger.info(
                                    "WAF detected on %s: %s (conf=%.0f%%)",
                                    _waf_host,
                                    _merged.waf_name,
                                    _merged.confidence * 100,
                                )
                    except Exception as _waf_e:
                        logger.debug("WAF detection error: %s", _waf_e)

            if not success and self._consecutive_failures >= 3:
                alt_suggestion = self._suggest_alternative_tool(
                    tool_name, raw_command
                )
                content_str += (
                    f"\n\n[SYSTEM: {self._consecutive_failures} CONSECUTIVE FAILURES DETECTED] "
                    "MANDATORY: Stop using the current approach. "
                    "Switch to a completely different tool or strategy. "
                    + (
                        f"SUGGESTED ALTERNATIVES: {alt_suggestion}\n"
                        if alt_suggestion
                        else ""
                    )
                    + "If all options are exhausted, document what was tried and emit [TASK_COMPLETE]."
                )

            if success and self.state.tool_counts["total"] >= 1:
                if self.state.planned_tools:
                    executed_tools = set()
                    for hist in self.state.tool_history:
                        executed_tools.add(hist.tool_name)

                    unexecuted = [
                        t
                        for t in self.state.planned_tools
                        if t not in executed_tools and t != "execute"
                    ]

                    if unexecuted:
                        content_str += (
                            f"\n\n[SYSTEM: PLANNED TOOLS NOT EXECUTED!]\n"
                            "You PLANNED to use these tools but haven't executed them: "
                            f"{', '.join(unexecuted)}\n"
                            "You MUST call these tools now before moving to the next phase!"
                        )

                content_str += (
                    "\n\n[SYSTEM: SELF-CHECK] MANDATORY — Answer these BEFORE continuing:\n"
                    "1. Does this tool generate NEW output not already in output/ directory? (Check first!)\n"
                    "2. If output file exists: is the existing data sufficient, or do you need fresh data?\n"
                    "3. Does this advance toward exploitation, or are you just repeating recon?\n"
                    "4. Have you already run this exact command in this session? (Check tool_history)\n"
                    "If answer to Q1=NO or Q2=sufficient or Q3=recon or Q4=YES: "
                    "SKIP redundant execution, move to next phase or emit [TASK_COMPLETE]."
                )

            # ── Auto HTTP structure + behavioral diff ──────────────
            _http_ctx = self._auto_http_context(tool_name, arguments, result, success)
            if _http_ctx:
                content_str += "\n\n" + _http_ctx

            # ── Session state + rate-limit advisories ───────────────
            _session_ctx = self._build_session_rate_advisory(
                tool_name, arguments, result
            )
            if _session_ctx:
                content_str += "\n\n" + _session_ctx

            # ── Hypothesis feedback loop ────────────────────────────
            _result_blob = (
                self._extract_result_text(result)
                if hasattr(self, "_extract_result_text")
                else str(result)
            )
            _hyp_ctx = self._hypothesis_feedback_context(tool_name, arguments, _result_blob)
            if _hyp_ctx:
                content_str += "\n\n" + _hyp_ctx

            # ── Evidence action director ────────────────────────────
            _ev_dir = self._evidence_action_directive(
                phase=phase_after_tool.value,
                meaningful_delta=max(0, meaningful_after - meaningful_before),
                new_evidence=self.state.evidence_log[_total_ev_before:],
            )
            if _ev_dir:
                content_str += "\n\n" + _ev_dir

            # ── Soft scope advisories (LLM reasons about pivot) ────
            _scope_adv = self._drain_scope_advisories()
            if _scope_adv:
                content_str += "\n\n" + _scope_adv

            # ── Hypothesis verification via independent evidence ───
            try:
                _verify = getattr(self, "_verify_confirmed_hypotheses", None)
                _build = getattr(self, "_build_verification_note", None)
                if callable(_verify) and callable(_build):
                    _new_ids = _verify()
                    if _new_ids:
                        _note = _build(_new_ids)
                        if isinstance(_note, str) and _note:
                            content_str += "\n\n" + _note
            except Exception as _ve:
                logger.debug("Hypothesis verification check failed: %s", _ve)

            self._prune_stale_system_context()
            self._record_tested_endpoint(tool_name, arguments)
            self._append_tool_result(tool_name, content_str, success, tc.get("id"))

            self._mentor_tool_call_count += 1

            self._refresh_exploration_state()

            maybe_inject_mentor_analysis(
                self,
                current_phase=current_phase,
                all_results=all_results,
            )

            if self._session:
                save_session(self._session)

            if has_task_complete:
                logger.info("Agent emitted [TASK_COMPLETE] after tools — stopping.")
                self._iteration_terminated = True
                yield AgentEvent(type="done", data={})
                return

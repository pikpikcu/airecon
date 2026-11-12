from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Any
import json
import logging
import shlex
from urllib.parse import urlparse

from .constants import VALID_BROWSER_ACTIONS
from .tuning import get_tuning
from .utils import is_host_in_scope

logger = logging.getLogger("airecon.validation")

def _poc_type_min_length(poc_code: str) -> int:
    lower = poc_code.lstrip().lower()
    if lower.startswith("curl "):
        return 20
    if lower.startswith("#!/bin/bash") or lower.startswith("#!/bin/sh"):
        return 22
    if lower.startswith("<?php"):
        return 28
    if any(sig in lower[:80] for sig in (
        "import ", "def ", "requests.", "urllib",
        "#!/usr/bin/env python", "#!/usr/bin/python",
    )):
        return 40
    if any(sig in lower[:80] for sig in ("fetch(", "xmlhttprequest", "require(", "const ", "let ", "var ")):
        return 28
    if lower.startswith(("get ", "post ", "put ", "delete ", "patch ")):
        return 28
    return 22


_POC_DESC_MIN: int = 30
_TECHNICAL_MIN: int = 30


_VALID_INPUT_TYPES_JSON = [
    entry.get("function", {})
    .get("parameters", {})
    .get("properties", {})
    .get("input_type", {})
    .get("enum", [])
    for entry in (
        json.loads(
            (Path(__file__).parent.parent / "data" / "tools.json").read_text(
                encoding="utf-8"
            )
        )
        if (Path(__file__).parent.parent / "data" / "tools.json").exists()
        else []
    )
    if entry.get("function", {}).get("name") == "request_user_input"
]
VALID_USER_INPUT_TYPES: frozenset[str] = frozenset(
    _VALID_INPUT_TYPES_JSON[0]
    if _VALID_INPUT_TYPES_JSON
    else {"text", "captcha", "totp", "password", "otp"}
)


def _load_known_tools() -> frozenset[str]:
    try:
        data_file = Path(__file__).parent.parent / "data" / "tools_meta.json"
        meta = json.loads(data_file.read_text(encoding="utf-8"))
        tools: set[str] = set()
        for category in meta.get("categories", {}).values():
            if isinstance(category, dict):
                for tool_list in category.values():
                    if isinstance(tool_list, list):
                        tools.update(t.lower() for t in tool_list if t)
            elif isinstance(category, list):
                tools.update(t.lower() for t in category if t)
        return frozenset(tools)
    except Exception as e:
        logger.warning("Operation failed: %s", e)
        return frozenset()


_KNOWN_TOOLS: frozenset[str] = _load_known_tools()
_REPLAY_GAP_MESSAGES = {
    "request_logged": str(
        get_tuning(
            "validator.replay.gap_messages.request_logged",
            "describe the exact replay request that was executed",
        )
    ),
    "response_logged": str(
        get_tuning(
            "validator.replay.gap_messages.response_logged",
            "describe the exploit response that was observed",
        )
    ),
    "payload_observed": str(
        get_tuning(
            "validator.replay.gap_messages.payload_observed",
            "link the payload to the observed output",
        )
    ),
    "target_bound": str(
        get_tuning(
            "validator.replay.gap_messages.target_bound",
            "bind the PoC to the same target/endpoint as the finding",
        )
    ),
    "runtime_command_logged": str(
        get_tuning(
            "validator.replay.gap_messages.runtime_command_logged",
            "include the exact replay command that was executed",
        )
    ),
    "runtime_response_logged": str(
        get_tuning(
            "validator.replay.gap_messages.runtime_response_logged",
            "include runtime response details (status/body) for that replay",
        )
    ),
    "runtime_http": str(
        get_tuning(
            "validator.replay.gap_messages.runtime_http",
            "include HTTP status evidence from runtime replay",
        )
    ),
    "runtime_signal": str(
        get_tuning(
            "validator.replay.gap_messages.runtime_signal",
            "include impact evidence from runtime replay",
        )
    ),
    "runtime_impact": str(
        get_tuning(
            "validator.replay.gap_messages.runtime_impact",
            "show runtime impact (data/error/access change), not only heartbeat output",
        )
    ),
    "runtime_host_bound": str(
        get_tuning(
            "validator.replay.gap_messages.runtime_host_bound",
            "use the same PoC host in runtime replay evidence",
        )
    ),
    "runtime_payload_bound": str(
        get_tuning(
            "validator.replay.gap_messages.runtime_payload_bound",
            "use the same PoC payload in runtime replay evidence",
        )
    ),
}

_URL_REGEX = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
_HOST_HEADER_REGEX = re.compile(r"(?im)^host:\s*([^\s/:]+)")
_IP_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

_EXTS_PATH = Path(__file__).parent.parent / "data" / "file_extensions.json"
try:
    _ext_data = json.loads(_EXTS_PATH.read_text(encoding="utf-8"))
    _KNOWN_FILE_EXTS = {
        str(ext).lower()
        for bucket in _ext_data.values()
        if isinstance(bucket, list)
        for ext in bucket
        if isinstance(ext, str)
    }
except Exception as _ext_err:
    logger.debug("Failed to load file_extensions.json for scope guard: %s", _ext_err)
    _KNOWN_FILE_EXTS = set()

_HOSTLIKE_TOKEN_REGEX = re.compile(
    r"^(?:[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+|\d{1,3}(?:\.\d{1,3}){3})(?::\d+)?(?:[/?#].*)?$"
)


def _looks_like_path(text: str) -> bool:
    stripped = text.strip()
    if not stripped:
        return True
    if stripped.startswith(("/", "./", "../", "~")):
        return True
    if re.match(r"^[a-zA-Z]:[\\/]", stripped):
        return True
    if "/" in stripped or "\\" in stripped:
        return True
    return False


def _looks_like_file_name(text: str) -> bool:
    stripped = text.strip().lower()
    if "." not in stripped or "/" in stripped or "\\" in stripped:
        return False
    ext = stripped.rsplit(".", 1)[-1]
    return ext in _KNOWN_FILE_EXTS


def _looks_like_token(text: str) -> bool:
    parts = text.split(".")
    if len(parts) == 3 and all(len(p) >= 8 for p in parts):
        if all(re.fullmatch(r"[A-Za-z0-9_-]+", p or "") for p in parts):
            return True
    if len(parts) >= 3 and all(len(p) >= 10 for p in parts):
        if all(re.fullmatch(r"[A-Za-z0-9-]+", p or "") for p in parts):
            return True
    return False


def _iter_text_values(data: Any) -> list[str]:
    values: list[str] = []
    if isinstance(data, dict):
        for v in data.values():
            values.extend(_iter_text_values(v))
    elif isinstance(data, list):
        for item in data:
            values.extend(_iter_text_values(item))
    elif isinstance(data, str):
        values.append(data)
    return values


def _extract_scope_candidates_from_text(text: str) -> set[str]:
    candidates: set[str] = set()
    if not text:
        return candidates
    stripped = text.strip()
    if not stripped:
        return candidates

    def _normalize_candidate(raw: str) -> str | None:
        token = raw.strip().strip("()[]{}<>,;\"'")
        if not token:
            return None
        if _looks_like_file_name(token) or _looks_like_token(token):
            return None
        try:
            parsed = urlparse(token if "://" in token else f"http://{token}")
            host = (parsed.hostname or "").strip().lower().rstrip(".")
        except ValueError:
            return None
        if not host:
            return None
        if _looks_like_file_name(host) or _looks_like_token(host):
            return None
        return f"http://{host}"

    sanitized = stripped
    for url in _URL_REGEX.findall(stripped):
        normalized = _normalize_candidate(url)
        if normalized:
            candidates.add(normalized)
        sanitized = sanitized.replace(url, " ")

    for ip in _IP_REGEX.findall(sanitized):
        normalized = _normalize_candidate(ip)
        if normalized:
            candidates.add(normalized)

    host_match = _HOST_HEADER_REGEX.search(stripped)
    if host_match:
        normalized = _normalize_candidate(host_match.group(1))
        if normalized:
            candidates.add(normalized)

    if "://" not in stripped and not _looks_like_path(stripped) and not _looks_like_file_name(stripped):
        if re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", stripped):
            normalized = _normalize_candidate(stripped)
            if normalized:
                candidates.add(normalized)

    for raw_token in re.split(r"\s+", sanitized):
        token = raw_token.strip().strip("()[]{}<>,;\"'")
        if not token:
            continue
        if token.startswith(("/", "./", "../", "~")):
            continue
        is_hostlike = bool(_HOSTLIKE_TOKEN_REGEX.match(token))
        if "=" in token and not token.startswith(("http://", "https://")) and not is_hostlike:
            continue
        if not is_hostlike:
            continue
        normalized = _normalize_candidate(token)
        if normalized:
            candidates.add(normalized)

    return candidates


def _collect_scope_candidates(tool_name: str, arguments: dict[str, Any]) -> set[str]:
    _ = tool_name
    candidates: set[str] = set()
    for text in _iter_text_values(arguments):
        candidates |= _extract_scope_candidates_from_text(text)
    return candidates
_REPLAY_SCORE_WEIGHTS = {
    "request_logged": float(
        get_tuning("validator.replay.score_weights.request_logged", 0.16)
    ),
    "response_logged": float(
        get_tuning("validator.replay.score_weights.response_logged", 0.16)
    ),
    "target_bound": float(
        get_tuning("validator.replay.score_weights.target_bound", 0.18)
    ),
    "payload_observed": float(
        get_tuning("validator.replay.score_weights.payload_observed", 0.14)
    ),
    "matching_finding": float(
        get_tuning("validator.replay.score_weights.matching_finding", 0.12)
    ),
    "artifact_bound": float(
        get_tuning("validator.replay.score_weights.artifact_bound", 0.09)
    ),
    "runtime_http": float(
        get_tuning("validator.replay.score_weights.runtime_http", 0.09)
    ),
    "runtime_signal": float(
        get_tuning("validator.replay.score_weights.runtime_signal", 0.06)
    ),
    "runtime_impact": float(
        get_tuning("validator.replay.score_weights.runtime_impact", 0.05)
    ),
    "runtime_host_bound": float(
        get_tuning("validator.replay.score_weights.runtime_host_bound", 0.05)
    ),
    "runtime_payload_bound": float(
        get_tuning("validator.replay.score_weights.runtime_payload_bound", 0.05)
    ),
    "no_runtime_text_bonus": float(
        get_tuning("validator.replay.score_weights.no_runtime_text_bonus", 0.08)
    ),
}
_REPLAY_THRESHOLDS = {
    "strict_with_runtime": float(
        get_tuning("validator.replay.thresholds.strict_with_runtime", 0.58)
    ),
    "strict_no_runtime": float(
        get_tuning("validator.replay.thresholds.strict_no_runtime", 0.48)
    ),
    "non_strict": float(get_tuning("validator.replay.thresholds.non_strict", 0.38)),
}
_REPLAY_SEVERITY_OFFSETS = {
    "CRITICAL": float(
        get_tuning("validator.replay.thresholds.severity_offset.critical", 0.10)
    ),
    "HIGH": float(get_tuning("validator.replay.thresholds.severity_offset.high", 0.06)),
    "MEDIUM": float(
        get_tuning("validator.replay.thresholds.severity_offset.medium", 0.02)
    ),
    "LOW": float(get_tuning("validator.replay.thresholds.severity_offset.low", -0.02)),
    "INFO": float(
        get_tuning("validator.replay.thresholds.severity_offset.info", -0.04)
    ),
}


def validate_target_path(
    target: str, base_dir: str | Path = "/workspace"
) -> tuple[bool, str]:
    try:
        base_path = Path(base_dir).resolve()
        target_path = (base_path / target).resolve()

        try:
            target_path.relative_to(base_path)
        except ValueError:
            return False, f"Path traversal detected: {target} escapes {base_dir}"

        current = base_path
        for part in Path(target).parts:
            next_path = current / part
            if next_path.is_symlink():
                resolved_link = next_path.resolve()
                try:
                    resolved_link.relative_to(base_path)
                except ValueError:
                    return False, (
                        f"Symlink traversal detected: '{next_path}' is a symlink "
                        f"pointing outside workspace to '{resolved_link}'"
                    )
            current = next_path

        dangerous_chars = [";", "|", "$", "`", "(", ")", "&", "<", ">", "\n", "\r"]
        if any(char in target for char in dangerous_chars):
            return False, f"Invalid characters in path: {target}"

        return True, str(target_path)

    except Exception as e:
        return False, f"Path validation error: {str(e)}"


def extract_paths_from_command(command: str) -> list[str]:
    _Q = r'(?:"([^"]+)"|\'([^\']+)\'|(\S+))'
    patterns = [
        rf"-o\s+{_Q}",
        rf"-output\s+{_Q}",
        rf">>\s*{_Q}",
        rf"(?<!>)>(?!>)\s*{_Q}",
        rf"-t\s+{_Q}",
        rf"--targets\s+{_Q}",
    ]
    paths: list[str] = []
    for pattern in patterns:
        for groups in re.findall(pattern, command):
            path = next((g for g in groups if g), None)
            if path:
                paths.append(path)
    return paths


def validate_command_paths(
    command: str, base_dir: str | Path = "/workspace"
) -> tuple[bool, str]:
    for path in extract_paths_from_command(command):
        is_valid, error = validate_target_path(path, base_dir)
        if not is_valid:
            return False, str(error)
    return True, ""


def validate_paths_in_semgrep_args(
    target_path: str, base_dir: str | Path = "/workspace"
) -> tuple[bool, str]:
    return validate_target_path(target_path, base_dir)


def validate_paths_in_filesystem_args(
    file_path: str, base_dir: str | Path = "/workspace"
) -> tuple[bool, str]:
    return validate_target_path(file_path, base_dir)


DANGEROUS_PATTERNS: list[tuple[str, str]] = [
    (r"rm\s+-rf\s+/", "Dangerous: rm -rf / detected"),
    (r"dd\s+if=.*of=/dev", "Dangerous: writing to /dev"),
    (r":\s*\(\s*\)\s*\{.*:\s*\|.*:\s*&", "Dangerous: fork bomb detected"),
    (r"pkill\s+-9", "Dangerous: killing critical processes"),
    (r">\s*/dev/sd[a-z]", "Dangerous: writing to disk device"),
]


def _has_dangerous_chmod_mode(command: str) -> bool:
    if "chmod" not in command.lower():
        return False

    try:
        tokens = shlex.split(command, posix=True)
    except ValueError:
        tokens = command.split()

    for i, token in enumerate(tokens):
        if token.lower() != "chmod":
            continue

        mode_idx = i + 1
        while mode_idx < len(tokens) and tokens[mode_idx].startswith("-"):
            mode_idx += 1
        if mode_idx >= len(tokens):
            continue
        mode_token = tokens[mode_idx]

        for clause in mode_token.split(","):
            clause = clause.strip().lower()
            if "+s" in clause or "=s" in clause:
                return True

        if re.fullmatch(r"[0-7]{4,}", mode_token):
            special_digit = int(mode_token[-4])
            if special_digit in {2, 4, 6, 7}:
                return True

    return False


def has_dangerous_patterns(command: str) -> tuple[bool, str]:
    for pattern, description in DANGEROUS_PATTERNS:
        if re.search(pattern, command, re.IGNORECASE):
            return True, description
    if _has_dangerous_chmod_mode(command):
        return True, "Dangerous: SUID/SGID bit change detected"
    return False, ""


def validate_for_execution(
    command: str, base_dir: str | Path = "/workspace"
) -> tuple[bool, str]:
    has_danger, danger_msg = has_dangerous_patterns(command)
    if has_danger:
        return False, danger_msg

    try:
        shlex.split(command)
    except ValueError as e:
        return False, (
            f"Shell syntax error (unbalanced quotes): {e}. "
            "Rewrite the command using double-quotes for the outer string "
            "or avoid embedding single-quotes inside single-quoted arguments."
        )
    return validate_command_paths(command, base_dir)


_HTTP_EVIDENCE_RE = re.compile(
    r"(http\s+[2345]\d{2}|status[:\s]+[2345]\d{2}|code\s+[2345]\d{2}|"
    r"\b[2345]\d{2}\s+(ok|found|forbidden|redirect|not found|created|"
    r"accepted|no content|moved|unauthorized|bad request|internal server error|"
    r"forbidden|unauthorized|forbidden)\b|"
    r"response[:\s]+[2345]\d{2}|→\s*[2345]\d{2}|"
    r"\[[2345]\d{2}\]|\([2345]\d{2}\)|\{[2345]\d{2}\}|"
    r"returned\s+[2345]\d{2}|returns\s+[2345]\d{2}|got\s+[2345]\d{2}|"
    r"observed[:\s]+[2345]\d{2}|status\s*[2345]\d{2}|"
    r"\"status(?:Code)?\"\s*:\s*[2345]\d{2}|"
    r"\"code\"\s*:\s*[2345]\d{2}|"
    r"\"http_status\"\s*:\s*[2345]\d{2})",
    re.IGNORECASE,
)

_HTTP_EVIDENCE_PATTERNS = {
    "status_change": re.compile(
        r"(200|201|204|301|302|304|400|401|403|404|500|503)\s*→\s*(200|201|204|301|302|304|400|401|403|404|500|503)",
        re.IGNORECASE,
    ),
    "response_content": re.compile(
        r"(response|returned|got|contain(?:s|ing)|found|showing|displays?|has|includes)\s+.*?"
        r"(admin|user|password|token|secret|key|cookie|session|data|record|list|table|error|exception|query|select|insert|update|delete|flag|id|username|email|api|credential)",
        re.IGNORECASE,
    ),
    "error_indicator": re.compile(
        r"(error|exception|sql|syntax|warning|failed|denied|forbidden|timeout|connection|refused|unreachable|stack trace|traceback)",
        re.IGNORECASE,
    ),
    "data_extraction": re.compile(
        r"(extracted|captured|dumped|found|leaked|exposed|retrieved|obtained|recovered|decrypted)\s+.*?"
        r"(password|token|api|key|secret|credential|session|cookie|hash|id|username|email|data)",
        re.IGNORECASE,
    ),
}


class _ValidatorMixin:
    @staticmethod
    def _str_arg(arguments: dict[str, Any], key: str) -> str:
        val = arguments.get(key)
        return val if isinstance(val, str) else ""

    def _resolve_scope_target(self) -> str:
        anchor = str(getattr(self, "_scope_anchor_target", "") or "").strip()
        if anchor:
            return anchor
        state_obj = getattr(self, "state", None)
        active = (
            str(getattr(state_obj, "active_target", "") or "").strip()
            if state_obj is not None
            else ""
        )
        if active:
            return active
        session_target = str(
            getattr(getattr(self, "_session", None), "target", "") or ""
        ).strip()
        return session_target

    def _scope_guard_active(self) -> bool:
        try:
            phase = str(self._get_current_phase().value).upper()
        except Exception as e:
            logger.debug("Scope guard phase lookup failed: %s", e)
            phase = ""
        if phase == "RECON":
            return False
        if bool(getattr(self, "_scope_lock_active", False)):
            return True
        return bool(self._resolve_scope_target())

    def _check_scope_url(self, url: str) -> tuple[bool, str | None]:
        scope_target = self._resolve_scope_target()
        if not scope_target or not url:
            return True, None
        if is_host_in_scope(url, scope_target):
            return True, None
        return (
            False,
            f"OUT-OF-SCOPE: {url!r} is outside the current scope {scope_target!r}.",
        )

    @staticmethod
    def _normalize_severity_label(value: str) -> str:
        raw = (value or "").strip().upper()
        if raw in ("CRIT",):
            return "CRITICAL"
        if raw in ("MODERATE",):
            return "MEDIUM"
        if raw in ("INFORMATIONAL",):
            return "INFO"
        return raw if raw in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"} else ""

    @staticmethod
    def _severity_from_cvss_score(score: float) -> str:
        if score >= 9.0:
            return "CRITICAL"
        if score >= 7.0:
            return "HIGH"
        if score >= 4.0:
            return "MEDIUM"
        if score > 0.0:
            return "LOW"
        return "INFO"

    def _derive_report_severity(
        self,
        arguments: dict[str, Any],
        matched_finding_severity: str = "",
    ) -> str:
        explicit = self._normalize_severity_label(self._str_arg(arguments, "severity"))
        if explicit:
            return explicit

        matched = self._normalize_severity_label(matched_finding_severity)
        if matched:
            return matched

        raw_cvss = arguments.get("cvss_score")
        if raw_cvss is not None:
            try:
                return self._severity_from_cvss_score(float(raw_cvss))
            except (TypeError, ValueError):
                pass
        return "MEDIUM"

    @staticmethod
    def _resolve_replay_threshold(
        *,
        is_strict_phase: bool,
        has_runtime_context: bool,
        severity: str,
    ) -> float:
        if is_strict_phase:
            base = (
                _REPLAY_THRESHOLDS["strict_with_runtime"]
                if has_runtime_context
                else _REPLAY_THRESHOLDS["strict_no_runtime"]
            )
            offset = _REPLAY_SEVERITY_OFFSETS.get(
                severity,
                _REPLAY_SEVERITY_OFFSETS["MEDIUM"],
            )
            return min(0.95, max(0.25, base + offset))
        return _REPLAY_THRESHOLDS["non_strict"]

    _VALID_BROWSER_ACTIONS = VALID_BROWSER_ACTIONS

    def _collect_runtime_verification_texts(self, max_entries: int = 24) -> list[str]:
        chunks: list[str] = []
        state = getattr(self, "state", None)
        if state is None:
            return chunks

        tool_history = list(getattr(state, "tool_history", []) or [])[-max_entries:]
        for entry in tool_history:
            try:
                tool_name = str(getattr(entry, "tool_name", "") or "")
                arguments = getattr(entry, "arguments", {}) or {}
                result = getattr(entry, "result", {}) or {}
                arg_blob = " ".join(f"{k}={v}" for k, v in list(arguments.items())[:6])
                out_blob = " ".join(
                    str(result.get(k, ""))[:500]
                    for k in ("stdout", "stderr", "output", "content", "summary")
                    if isinstance(result.get(k), str)
                )
                merged = f"{tool_name} {arg_blob} {out_blob}".strip()
                if merged:
                    chunks.append(merged)
            except Exception as e:
                logger.warning("Operation failed: %s", e)
                continue

        evidence_log = list(getattr(state, "evidence_log", []) or [])[-max_entries:]
        for ev in evidence_log:
            try:
                if not isinstance(ev, dict):
                    continue
                summary = str(ev.get("summary", "")).strip()
                artifact = str(ev.get("artifact", "")).strip()
                if summary:
                    chunks.append(f"{summary} {artifact}".strip())
            except Exception as e:
                logger.warning("Operation failed: %s", e)
                continue
        return chunks

    @staticmethod
    def _extract_payload_markers(text: str) -> list[str]:
        markers: list[str] = []
        for m in re.findall(r"(['\"`])(.*?)\1", text):
            token = str(m[1]).strip()
            if len(token) < 4:
                continue
            if re.search(
                r"(or\s+1=1|union\s+select|<script|../|169\.254|cmd=|token=|jwt)",
                token,
                re.IGNORECASE,
            ):
                markers.append(token.lower()[:120])
        for m in re.findall(
            r"(?:payload|param|query|id|user|url)\s*[:=]\s*([^\s,&]+)",
            text,
            re.IGNORECASE,
        ):
            tok = str(m).strip().strip("'\"")
            if tok and len(tok) >= 3:
                markers.append(tok.lower()[:80])

        seen: set[str] = set()
        return [x for x in markers if not (x in seen or seen.add(x))]

    @staticmethod
    def _hosts_related(left: str, right: str) -> bool:
        left = left.strip().lower()
        right = right.strip().lower()
        if not left or not right:
            return False
        return left == right or left.endswith("." + right) or right.endswith("." + left)

    def _has_detected_waf_profile(self, hosts: list[str]) -> bool:
        session = getattr(self, "_session", None)
        waf_profiles = getattr(session, "waf_profiles", None)
        if not isinstance(waf_profiles, dict) or not waf_profiles:
            return False

        active_target = ""
        try:
            state = getattr(self, "state", None)
            active_target = (
                str(getattr(state, "active_target", "") or "").strip().lower()
            )
        except Exception as e:
            logger.warning("Operation failed: %s", e)
            active_target = ""

        host_candidates = {
            str(h).split(":")[0].strip().lower()
            for h in hosts
            if isinstance(h, str) and h.strip()
        }
        if active_target:
            host_candidates.add(active_target.split(":")[0])
        if not host_candidates:
            return False

        for raw_host, profile in waf_profiles.items():
            host_key = str(raw_host).split(":")[0].strip().lower()
            if not host_key:
                continue

            if host_candidates and not any(
                self._hosts_related(host_key, candidate)
                for candidate in host_candidates
            ):
                continue

            if isinstance(profile, dict):
                if profile.get("detected") is False:
                    continue
                marker_fields = (
                    "name",
                    "waf_name",
                    "vendor",
                    "signature",
                    "fingerprint",
                )
                if any(str(profile.get(k, "")).strip() for k in marker_fields):
                    return True
                try:
                    if float(profile.get("confidence", 0.0) or 0.0) > 0:
                        return True
                except (TypeError, ValueError):
                    pass
                if profile.get("signals"):
                    return True
                if profile:
                    return True
            elif profile:
                return True
        return False

    def _replay_verification_score(
        self,
        *,
        poc_code: str,
        poc_desc: str,
        report_finding: str,
        matching_finding: bool,
    ) -> tuple[float, list[str], bool, bool]:
        gaps: list[str] = []
        runtime_chunks = self._collect_runtime_verification_texts()
        has_runtime = bool(runtime_chunks)

        runtime_text = " ".join(runtime_chunks).lower()
        desc_lower = poc_desc.lower()
        code_lower = poc_code.lower()
        report_lower = report_finding.lower()
        host_matches = re.findall(r"https?://([^\s/\"']+)", poc_code, re.IGNORECASE)
        hosts = [h.split(":")[0].lower() for h in host_matches if h]

        waf_block_indicators = [
            r"\b403\b.*\b(forbidden|blocked|waf|firewall|access denied)\b",
            r"\b401\b.*\b(unauthorized|authentication required)\b",
            r"\b(blocked|blocked by|mod_security|cloudflare|akamai|sucuri)\b",
            r"\b(access denied|not allowed|forbidden|prohibited)\b",
        ]

        has_waf_block = any(
            re.search(pattern, runtime_text) or re.search(pattern, desc_lower)
            for pattern in waf_block_indicators
        )

        has_waf_detected = self._has_detected_waf_profile(hosts)
        if not has_waf_detected:
            has_waf_detected = bool(
                re.search(
                    r"\b(waf|web.?application.?firewall|cloudflare|mod.?security|akamai|imperva|sucuri)\b",
                    runtime_text,
                )
            )

        waf_false_positive = has_waf_block and not has_waf_detected

        request_logged = bool(
            re.search(r"\b(get|post|put|delete|patch|curl|request)\b", desc_lower)
            or re.search(r"\b(curl|requests\.|httpx\.|urllib|fetch\()", code_lower)
        )
        response_logged = bool(
            _HTTP_EVIDENCE_RE.search(poc_desc)
            or re.search(r"\b(response|returned|body|status|code)\b", desc_lower)
        )
        if not request_logged:
            gaps.append(_REPLAY_GAP_MESSAGES["request_logged"])
        if not response_logged:
            gaps.append(_REPLAY_GAP_MESSAGES["response_logged"])

        payload_markers = self._extract_payload_markers(poc_code + " " + poc_desc)
        payload_observed = bool(payload_markers) and any(
            marker in desc_lower or (has_runtime and marker in runtime_text)
            for marker in payload_markers[:8]
        )
        if payload_markers and not payload_observed and not has_runtime:
            payload_observed = bool(
                re.search(
                    r"\b(sql|sqli|xss|ssrf|idor|csrf|rce|lfi|token|admin|password|credential|bypass)\b",
                    desc_lower,
                )
            )
        if payload_markers and not payload_observed:
            gaps.append(_REPLAY_GAP_MESSAGES["payload_observed"])

        target_bound = False
        runtime_host_bound = False
        if hosts:
            if has_runtime:
                runtime_host_bound = any(h in runtime_text for h in hosts)
                target_bound = runtime_host_bound or any(h in desc_lower for h in hosts)
            else:
                target_bound = True
        elif report_lower:
            key_terms = [w for w in report_lower.split() if len(w) >= 5][:10]
            target_bound = bool(key_terms) and any(
                any(term in blob for term in key_terms)
                for blob in ([desc_lower] + ([runtime_text] if has_runtime else []))
            )
        if not target_bound:
            gaps.append(_REPLAY_GAP_MESSAGES["target_bound"])

        runtime_http = has_runtime and bool(
            re.search(
                r"\b(http/?\d\.\d|status|code)\s*[=:]?\s*[2345]\d{2}", runtime_text
            )
        )
        runtime_command_logged = has_runtime and bool(
            re.search(
                r"\b(curl|requests\.|httpx\.|urllib|fetch\(|\bget\b|\bpost\b|\bput\b|\bdelete\b|\bpatch\b)\b",
                runtime_text,
            )
        )
        runtime_response_logged = has_runtime and bool(
            re.search(r"\b(response|returned|body|status|code)\b", runtime_text)
        )
        runtime_signal = has_runtime and bool(
            re.search(
                r"\b(sql|xss|ssrf|idor|csrf|rce|lfi|auth|forbidden|unauthorized|credential|token)\b",
                runtime_text,
            )
        )
        runtime_impact = has_runtime and bool(
            re.search(
                r"\b(admin|credential|password|token|dump|leak|record|rows?|session opened|meterpreter|shell|forbidden|unauthorized|error)\b",
                runtime_text,
            )
        )
        runtime_payload_bound = has_runtime and (
            not payload_markers
            or any(marker in runtime_text for marker in payload_markers[:8])
        )
        if has_runtime and not runtime_command_logged:
            gaps.append(_REPLAY_GAP_MESSAGES["runtime_command_logged"])
        if has_runtime and not runtime_response_logged:
            gaps.append(_REPLAY_GAP_MESSAGES["runtime_response_logged"])
        if has_runtime and not runtime_http:
            gaps.append(_REPLAY_GAP_MESSAGES["runtime_http"])
        if has_runtime and not runtime_signal:
            gaps.append(_REPLAY_GAP_MESSAGES["runtime_signal"])
        if has_runtime and not runtime_impact:
            gaps.append(_REPLAY_GAP_MESSAGES["runtime_impact"])
        if has_runtime and hosts and not runtime_host_bound:
            gaps.append(_REPLAY_GAP_MESSAGES["runtime_host_bound"])
        if has_runtime and payload_markers and not runtime_payload_bound:
            gaps.append(_REPLAY_GAP_MESSAGES["runtime_payload_bound"])

        artifact_bound = bool(
            re.search(r"\b(output/|artifact|log|trace|capture|pcap|json)\b", desc_lower)
            or (
                has_runtime
                and re.search(r"\b(output/|artifact|log|trace|capture)\b", runtime_text)
            )
        )

        score = 0.0
        if request_logged:
            score += _REPLAY_SCORE_WEIGHTS["request_logged"]
        if response_logged:
            score += _REPLAY_SCORE_WEIGHTS["response_logged"]
        if target_bound:
            score += _REPLAY_SCORE_WEIGHTS["target_bound"]
        if payload_observed or not payload_markers:
            score += _REPLAY_SCORE_WEIGHTS["payload_observed"]
        if matching_finding:
            score += _REPLAY_SCORE_WEIGHTS["matching_finding"]
        if artifact_bound:
            score += _REPLAY_SCORE_WEIGHTS["artifact_bound"]

        if has_runtime:
            if runtime_http:
                score += _REPLAY_SCORE_WEIGHTS["runtime_http"]
            if runtime_signal:
                score += _REPLAY_SCORE_WEIGHTS["runtime_signal"]
            if runtime_impact:
                score += _REPLAY_SCORE_WEIGHTS["runtime_impact"]
            if runtime_host_bound or not hosts:
                score += _REPLAY_SCORE_WEIGHTS["runtime_host_bound"]
            if runtime_payload_bound:
                score += _REPLAY_SCORE_WEIGHTS["runtime_payload_bound"]

            if waf_false_positive:
                score -= 0.4
                gaps.append(
                    "WAF block detected without bypass evidence - may be false positive"
                )
        else:
            if request_logged and response_logged and target_bound:
                score += _REPLAY_SCORE_WEIGHTS["no_runtime_text_bonus"]

        runtime_bound = (
            (
                runtime_command_logged
                and runtime_response_logged
                and runtime_http
                and runtime_signal
                and runtime_impact
                and (runtime_host_bound or not hosts)
                and runtime_payload_bound
            )
            if has_runtime
            else False
        )
        return min(1.0, max(0.0, score)), gaps, has_runtime, runtime_bound

    def _validate_tool_args(
        self, tool_name: str, arguments: dict[str, Any]
    ) -> tuple[bool, str | None]:
        if self._scope_guard_active():
            scope_target = self._resolve_scope_target()
            if scope_target:
                lock_strict = bool(getattr(self, "_scope_lock_active", False))
                for candidate in _collect_scope_candidates(tool_name, arguments):
                    ok, err = self._check_scope_url(candidate)
                    if ok:
                        continue
                    if lock_strict:
                        return False, err
                    advisories = getattr(self, "_pending_scope_advisories", None)
                    if advisories is None:
                        advisories = []
                        self._pending_scope_advisories = advisories  # type: ignore[attr-defined]
                    advisories.append(
                        {
                            "url": candidate,
                            "declared_scope": scope_target,
                            "tool": tool_name,
                        }
                    )
                    logger.debug(
                        "Scope advisory (soft): %s outside %s — allowed, LLM reasons",
                        candidate,
                        scope_target,
                    )

        if tool_name == "execute":
            cmd = self._str_arg(arguments, "command")
            if not cmd.strip():
                return False, "'command' must be a non-empty string."
            if len(cmd) > 20_000:
                return (
                    False,
                    f"'command' is too long ({len(cmd)} chars). Split into smaller calls.",
                )
            has_danger, danger_msg = has_dangerous_patterns(cmd)
            if has_danger:
                return False, f"Command rejected: {danger_msg}"

        elif tool_name == "browser_action":
            action = self._str_arg(arguments, "action")
            if action not in self._VALID_BROWSER_ACTIONS:
                return False, (
                    f"Invalid browser action '{action}'. "
                    f"Valid actions: {sorted(self._VALID_BROWSER_ACTIONS)}"
                )
            if (
                action in ("goto", "new_tab")
                and not self._str_arg(arguments, "url").strip()
            ):
                return False, f"browser_action '{action}' requires a non-empty 'url'."
            if action == "click" and not self._str_arg(arguments, "coordinate").strip():
                return (
                    False,
                    "browser_action 'click' requires 'coordinate' (format: 'x,y').",
                )
            if action == "type" and not isinstance(arguments.get("text"), str):
                return False, "browser_action 'type' requires a 'text' string argument."
            if (
                action == "switch_tab"
                and not self._str_arg(arguments, "tab_id").strip()
            ):
                return False, "browser_action 'switch_tab' requires 'tab_id'."
            if action == "press_key" and not self._str_arg(arguments, "key").strip():
                return False, "browser_action 'press_key' requires 'key'."
            if action == "execute_js":
                if not self._str_arg(arguments, "js_code").strip():
                    return (
                        False,
                        "browser_action 'execute_js' requires non-empty 'js_code'.",
                    )
                parallel = arguments.get("parallel", False)
                if not isinstance(parallel, bool):
                    return (
                        False,
                        "browser_action 'execute_js' optional 'parallel' must be boolean.",
                    )
                if parallel and self._str_arg(arguments, "tab_id").strip():
                    return False, (
                        "browser_action 'execute_js' with parallel=true must not set 'tab_id'."
                    )

        elif tool_name == "web_search":
            if not self._str_arg(arguments, "query").strip():
                return False, "'query' must be a non-empty string."

        elif tool_name == "create_file":
            path_str = self._str_arg(arguments, "path")
            if not path_str.strip():
                return False, "'path' must be a non-empty string."
            if "content" not in arguments:
                return False, "'content' argument is required."

        elif tool_name == "read_file":
            if not self._str_arg(arguments, "path").strip():
                return False, "'path' must be a non-empty string."
            if "offset" in arguments:
                try:
                    if int(arguments["offset"]) < 0:
                        return False, "'offset' must be >= 0."
                except (TypeError, ValueError):
                    return False, "'offset' must be an integer."
            if "limit" in arguments:
                try:
                    lim = int(arguments["limit"])
                    if lim < 1 or lim > 5000:
                        return False, "'limit' must be between 1 and 5000."
                except (TypeError, ValueError):
                    return False, "'limit' must be an integer."

        elif tool_name == "list_files":
            pass

        elif tool_name in ("caido_send_request", "caido_automate"):
            host_raw = (
                self._str_arg(arguments, "host")
                .removeprefix("https://")
                .removeprefix("http://")
                .rstrip("/")
            )
            if not host_raw.strip():
                return False, (
                    f"'{tool_name}' requires a non-empty 'host' (e.g. 'target.com', not a full URL)."
                )
            if tool_name == "caido_automate":
                if not self._str_arg(arguments, "raw_http").strip():
                    return (
                        False,
                        "'caido_automate' requires 'raw_http' with §FUZZ§ marker.",
                    )
                if not arguments.get("payloads"):
                    return (
                        False,
                        "'caido_automate' requires a non-empty 'payloads' list.",
                    )

        elif tool_name == "schemathesis_fuzz":
            if not self._str_arg(arguments, "schema_url").strip():
                return False, "'schema_url' is required for schemathesis_fuzz."
            raw_examples = arguments.get("max_examples")
            if raw_examples is not None:
                try:
                    int(raw_examples)
                except (TypeError, ValueError):
                    return False, (
                        f"'max_examples' must be an integer, got {type(raw_examples).__name__}."
                    )

        elif tool_name == "create_vulnerability_report":
            _phase_obj = (
                self._get_current_phase()
                if hasattr(self, "_get_current_phase")
                else None
            )
            _phase_str = _phase_obj.value if _phase_obj is not None else None
            if _phase_str is None:
                _phase_str = "RECON"
            _phase_str = _phase_str.upper()
            is_strict_phase = _phase_str in ("EXPLOIT", "REPORT")
            poc_code = self._str_arg(arguments, "poc_script_code").strip()
            poc_desc = self._str_arg(arguments, "poc_description").strip()
            title = self._str_arg(arguments, "title").strip()
            technical = self._str_arg(arguments, "technical_analysis").strip()
            is_ctf = bool(self._str_arg(arguments, "flag").strip())
            report_finding = (
                self._str_arg(arguments, "description").strip().lower()
                or poc_desc.lower()
                or title.lower()
            )

            matching_finding = False
            matched_finding_severity = ""
            if (
                hasattr(self, "_session")
                and self._session
                and self._session.vulnerabilities
            ):
                for v in self._session.vulnerabilities:
                    vuln_finding = str(v.get("finding", "")).lower()
                    if report_finding and any(
                        w in vuln_finding for w in report_finding.split() if len(w) > 4
                    ):
                        matching_finding = True
                        raw_severity = v.get("severity")
                        if isinstance(raw_severity, str):
                            matched_finding_severity = raw_severity
                        break
            report_severity = self._derive_report_severity(
                arguments, matched_finding_severity
            )

            if not poc_code:
                return False, (
                    "REPORT REJECTED: 'poc_script_code' is empty. "
                    "Provide actual exploit code or a curl command demonstrating the vulnerability."
                )
            _poc_min = _poc_type_min_length(poc_code)
            if len(poc_code) < _poc_min:
                return False, (
                    f"REPORT REJECTED: 'poc_script_code' is too short ({len(poc_code)} chars, "
                    f"minimum {_poc_min} for this PoC type). "
                    "Provide a real exploit: Python script, curl command, or HTTP request."
                )

            poc_lower = poc_code.lower()
            _is_python = any(
                sig in poc_lower
                for sig in (
                    "import ",
                    "def ",
                    "#!/usr/bin/env python",
                    "#!/usr/bin/python",
                    "requests.",
                    "urllib",
                    "http.client",
                )
            )
            _is_curl = poc_lower.lstrip().startswith("curl ")
            _is_php = "<?php" in poc_lower
            _is_js = any(
                sig in poc_lower for sig in ("fetch(", "xmlhttprequest", "require(")
            )
            _is_bash = "#!/bin/bash" in poc_lower or "#!/bin/sh" in poc_lower

            if _is_python:
                try:
                    ast.parse(poc_code)
                except SyntaxError as syn_err:
                    return False, (
                        "REPORT REJECTED: 'poc_script_code' is not valid Python — "
                        f"SyntaxError at line {syn_err.lineno}: {syn_err.msg}. "
                        "Fix the syntax or provide a curl command instead."
                    )
            elif not (_is_curl or _is_php or _is_js or _is_bash):
                NON_PYTHON_INDICATORS = (
                    "curl ",
                    "http",
                    "payload",
                    "exploit",
                    "fetch(",
                    "<?php",
                    "<script",
                    "burp",
                    "#!/",
                    "request",
                )
                if not any(ind in poc_lower for ind in NON_PYTHON_INDICATORS):
                    return False, (
                        "REPORT REJECTED: 'poc_script_code' does not look like code. "
                        "It must be a Python script (with valid syntax), a curl command, "
                        "PHP/JS snippet, or an HTTP request."
                    )
            if not poc_desc or len(poc_desc) < _POC_DESC_MIN:
                return False, (
                    f"REPORT REJECTED: 'poc_description' is too short ({len(poc_desc)} chars, "
                    f"minimum {_POC_DESC_MIN}). "
                    "Provide step-by-step reproduction with specific URLs, parameters, and observed behavior."
                )

            if not is_ctf and (not technical or len(technical) < _TECHNICAL_MIN):
                return False, (
                    f"REPORT REJECTED: 'technical_analysis' is too short ({len(technical)} chars, "
                    f"minimum {_TECHNICAL_MIN}). "
                    "Explain the root cause with specific technical details."
                )
            GENERIC_TITLES = (
                "vulnerability found",
                "security issue",
                "bug found",
                "potential",
                "possible",
                "issue detected",
                "security bug",
            )
            UNVERIFIED_PHRASES = (
                "further verification needed",
                "needs verification",
                "needs to be verified",
                "may be vulnerable",
                "could be vulnerable",
                "appears to be vulnerable",
                "potentially vulnerable",
                "might be vulnerable",
                "possible vulnerability",
                "note:",
                "unconfirmed",
                "not confirmed",
                "could not confirm",
                "needs more testing",
                "requires further",
                "needs further",
            )
            combined_text = (poc_desc + " " + technical).lower()
            for phrase in UNVERIFIED_PHRASES:
                if phrase in combined_text:
                    return False, (
                        f"REPORT REJECTED: Report contains unverified language: '{phrase}'. "
                        "Only submit findings you have CONFIRMED by observing actual exploitation impact. "
                        "Do not submit speculative or unverified findings."
                    )
            if "http" not in poc_code.lower() and "curl" not in poc_code.lower():
                return False, (
                    "REPORT REJECTED: 'poc_script_code' must include the actual target URL. "
                    "Show the real HTTP request that demonstrates the vulnerability."
                )

            scope_valid = True
            if hasattr(self, "_session") and self._session:
                def _is_ip_address(host: str) -> bool:
                    parts = host.split(".")
                    return len(parts) == 4 and all(
                        p.isdigit() and 0 <= int(p) <= 255 for p in parts
                    )

                def _get_base_domain(host: str) -> str:
                    host = host.lower().split(":")[0]
                    if _is_ip_address(host):
                        return host
                    parts = host.split(".")
                    return ".".join(parts[-2:]) if len(parts) >= 2 else host

                poc_url_match = re.search(r"https?://([^\s/\"']+)", poc_code.lower())
                if poc_url_match:
                    poc_host = poc_url_match.group(1).split(":")[0]
                    session_hosts = [self._session.target] + list(
                        self._session.live_hosts
                    )

                    if _is_ip_address(poc_host):
                        direct_match = poc_host in session_hosts
                        if not direct_match:
                            scope_valid = False
                            return False, (
                                f"REPORT REJECTED: PoC targets '{poc_host}' which is not in session scan scope. "
                                f"Session target: {self._session.target}. Live hosts: {', '.join(self._session.live_hosts[:5])}. "
                                "PoC must target the actual session target IP."
                            )
                    else:
                        poc_base = _get_base_domain(poc_host)
                        session_bases = [_get_base_domain(h) for h in session_hosts]

                        direct_match = any(
                            poc_host == h.split(":")[0] for h in session_hosts
                        )
                        base_match = any(poc_base == s_base for s_base in session_bases)

                        if not (direct_match or base_match):
                            scope_valid = False
                            return False, (
                                f"REPORT REJECTED: PoC targets '{poc_host}' which is not in session scan scope. "
                                f"Session target: {self._session.target}. Live hosts: {', '.join(self._session.live_hosts[:5])}. "
                                "PoC must target the actual session target or its subdomains."
                            )

            if not is_ctf:
                if not _HTTP_EVIDENCE_RE.search(poc_desc):
                    return False, (
                        "REPORT REJECTED: 'poc_description' must include actual HTTP response evidence. "
                        "Show the real status code and response data you observed, e.g.: "
                        "'GET /api/data → HTTP 200, response contained {user records}'. "
                        "A 301 redirect alone, or 'endpoint exists', is not sufficient — show what data/access was obtained."
                    )

                _desc_lower = poc_desc.lower()
                has_tool_reference = (
                    "output/" in _desc_lower
                    or "session" in _desc_lower
                    or "response" in _desc_lower
                    or "→" in poc_desc
                    or "http " in _desc_lower
                    or "observed" in _desc_lower
                    or "received" in _desc_lower
                    or "got" in _desc_lower
                    or "server returned" in _desc_lower
                    or "response body" in _desc_lower
                    or "response contained" in _desc_lower
                    or any(tool in _desc_lower for tool in _KNOWN_TOOLS)
                )
                if not has_tool_reference:
                    return False, (
                        "REPORT REJECTED: 'poc_description' must reference actual tool output or observed response data. "
                        "Reference the tool output file (e.g., 'output/nmap_scan.txt') or describe the actual response observed."
                    )

                has_status_change = bool(
                    _HTTP_EVIDENCE_PATTERNS["status_change"].search(poc_desc)
                )
                has_content_proof = bool(
                    _HTTP_EVIDENCE_PATTERNS["response_content"].search(poc_desc)
                )
                has_error_or_data = bool(
                    _HTTP_EVIDENCE_PATTERNS["error_indicator"].search(poc_desc)
                    or _HTTP_EVIDENCE_PATTERNS["data_extraction"].search(poc_desc)
                )
                impact_proven = (
                    has_status_change or has_content_proof or has_error_or_data
                )
                if not impact_proven:
                    return False, (
                        "REPORT REJECTED: HTTP status shown but exploitation impact not documented. "
                        "You must describe what the response contained or what changed. Examples: "
                        "'HTTP 200 containing admin panel buttons', "
                        "'HTTP 200 with SQL error message', "
                        "'Status changed from 403 (forbidden) to 200 (allowed)', "
                        "'Response leaked 50 user records'. "
                        "Do not submit 'HTTP 200' alone without explaining the impact."
                    )

            replay_score, replay_gaps, has_runtime_context, runtime_bound = (
                self._replay_verification_score(
                    poc_code=poc_code,
                    poc_desc=poc_desc,
                    report_finding=report_finding,
                    matching_finding=matching_finding,
                )
            )
            if not is_ctf:
                if is_strict_phase and not has_runtime_context:
                    return False, (
                        "REPORT REJECTED: Runtime replay evidence is mandatory in EXPLOIT/REPORT phase. "
                        "Do a real runtime replay (same target + payload) and include command/output evidence "
                        "before submitting create_vulnerability_report."
                    )
                if is_strict_phase and not runtime_bound:
                    gap_hint = (
                        "; ".join(dict.fromkeys(replay_gaps[:3]))
                        if replay_gaps
                        else (
                            "ensure PoC host/payload/status are present in runtime replay evidence"
                        )
                    )
                    return False, (
                        "REPORT REJECTED: Replay verification confidence too low. "
                        "Runtime replay evidence is not bound to this PoC. "
                        "In strict phases, reports must be proven on the same runtime trace "
                        "(host + payload + status/impact). "
                        f"Fix: {gap_hint}."
                    )
                replay_threshold = self._resolve_replay_threshold(
                    is_strict_phase=is_strict_phase,
                    has_runtime_context=has_runtime_context,
                    severity=report_severity,
                )
                if replay_score < replay_threshold:
                    gap_hint = (
                        "; ".join(dict.fromkeys(replay_gaps[:3]))
                        if replay_gaps
                        else "add clearer replay evidence"
                    )
                    return False, (
                        "REPORT REJECTED: Replay verification confidence too low "
                        f"({replay_score:.2f}/{replay_threshold:.2f}, severity={report_severity}). "
                        "The report must prove an end-to-end exploit flow (request → payload → response → impact). "
                        f"Fix: {gap_hint}."
                    )

            score = 0
            improvements: list[str] = []

            if len(poc_code) >= 120:
                score += 20
            elif len(poc_code) >= 80:
                score += 14
            else:
                improvements.append(
                    "expand PoC code with full request and payload details"
                )

            if _is_python or _is_curl or _is_php or _is_js or _is_bash:
                score += 15
            else:
                improvements.append("use a concrete script/HTTP snippet format")

            if len(poc_desc) >= 120:
                score += 20
            elif len(poc_desc) >= 80:
                score += 14
            else:
                improvements.append("make reproduction steps more explicit")

            if is_ctf:
                score += 10
            elif len(technical) >= 120:
                score += 15
            elif len(technical) >= 80:
                score += 10
            else:
                improvements.append("expand root-cause analysis")

            if (
                title
                and len(title) >= 15
                and not any(g in title.lower() for g in GENERIC_TITLES)
            ):
                score += 10
            else:
                improvements.append(
                    "use a specific vulnerability title with endpoint/parameter"
                )

            if scope_valid:
                score += 5

            if matching_finding:
                score += 10
            elif not is_strict_phase:
                score += 5
                improvements.append("link finding to session evidence when available")

            if not is_ctf and _HTTP_EVIDENCE_RE.search(poc_desc):
                score += 10
            if not is_ctf and impact_proven:
                score += 10
            if not is_ctf:
                score += int(replay_score * 20)
                if replay_score < 0.65:
                    improvements.append(
                        "replay verification (request/payload/response/impact)"
                    )

            if not is_ctf:
                try:
                    from ..config import get_config

                    _v_cfg = get_config()
                    if _v_cfg.verification_enabled:
                        from .verification import ConfidenceEscalator

                        _escalator = ConfidenceEscalator()

                        _v_replay = replay_score >= 0.5
                        _v_cross = matching_finding
                        _v_neg = True
                        _v_fp = False
                        _v_dyn = False

                        _v_tier, _v_conf, _v_status = _escalator.escalate(
                            original_confidence=replay_score,
                            replay_verified=_v_replay,
                            cross_tool_validated=_v_cross,
                            negative_test_passed=_v_neg,
                            fp_detected=_v_fp,
                            dynamic_content=_v_dyn,
                        )

                        if _v_tier >= 2:
                            score += 15
                        elif _v_tier >= 1:
                            score += 8

                        if _v_conf < _v_cfg.verification_min_report_confidence:
                            improvements.append(
                                f"verification confidence too low ({_v_conf:.2f} < {_v_cfg.verification_min_report_confidence:.2f})"
                            )
                except Exception as e:
                    logger.warning("Operation failed: %s", e)

            if (
                is_strict_phase
                and hasattr(self, "_session")
                and self._session
                and self._session.vulnerabilities
            ):
                if not matching_finding and len(poc_code) < 200:
                    return False, (
                        "REPORT REJECTED: Vulnerability not found in session discoveries and PoC is too short. "
                        "Report tool-discovered findings, or provide a stronger manual PoC (>200 chars) with explicit evidence."
                    )

            threshold = 45 if is_ctf else (70 if is_strict_phase else 55)
            if score < threshold:
                hint = "; ".join(dict.fromkeys(improvements[:3]))
                return False, (
                    f"REPORT REJECTED: Report quality score too low ({score}/{threshold}) for {_phase_str} phase. "
                    + (
                        f"Improve: {hint}."
                        if hint
                        else "Add stronger evidence and technical detail."
                    )
                )

        return True, None

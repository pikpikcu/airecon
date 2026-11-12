from __future__ import annotations

import json
import logging
import re
from enum import Enum
from pathlib import Path
from typing import Any

logger = logging.getLogger("airecon.agent.constants")

EPHEMERAL_PREFIXES: tuple[str, ...] = (
    "[SYSTEM: WORKSPACE",
    "[SYSTEM: ACTIVE_TARGET",
    "[SYSTEM: ADDITIONAL_TARGETS",
    "[SYSTEM: RECENT EXECUTIONS",
    "[SYSTEM: EVALUATION CHECKPOINT",
    "[SYSTEM: MANDATORY PLANNING",
    "[SYSTEM: PREVIOUS SESSION DATA",
    "[SYSTEM: CRITICAL FINDINGS",
    "[SYSTEM: OBJECTIVE FOCUS",
    "<objective_focus",
    "[SYSTEM: PHASE GATE",
    "[SYSTEM: AGGRESSIVE EXPLORATION",
    "[SYSTEM: QUALITY SCOREBOARD",
    "[SYSTEM: RECOVERY STATE",
    "[SYSTEM: CAIDO REMINDER",
    "[SYSTEM: UNVERIFIED CLAIM",
    "<reflector ",
    "<mentor_analysis>",
    "<hypothesis_queue",
    "<exploit_chain_plan>",
    "<waf_bypass ",
)

def _load_tool_classifications(
    field: str, fallback: frozenset[str] | None = None
) -> frozenset[str]:
    try:
        path = Path(__file__).parent.parent / "data" / "tools_meta.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        tools = data.get("tool_classifications", {}).get(field, [])
        loaded = frozenset(str(t).strip().lower() for t in tools if str(t).strip())
        if loaded:
            return loaded
    except Exception as e:
        logger.warning("Failed to load tool classifications (%s) from JSON: %s", field, e)
    return fallback or frozenset()


def _load_tool_schema_enum(tool_name: str, property_name: str) -> frozenset[str]:
    try:
        path = Path(__file__).parent.parent / "data" / "tools.json"
        raw = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(raw, list):
            return frozenset()
        for entry in raw:
            if not isinstance(entry, dict):
                continue
            function = entry.get("function", {})
            if not isinstance(function, dict) or function.get("name") != tool_name:
                continue
            parameters = function.get("parameters", {})
            if not isinstance(parameters, dict):
                break
            properties = parameters.get("properties", {})
            if not isinstance(properties, dict):
                break
            prop_data = properties.get(property_name, {})
            if not isinstance(prop_data, dict):
                break
            enum_values = prop_data.get("enum", [])
            if not isinstance(enum_values, list):
                break
            return frozenset(str(value).strip() for value in enum_values if str(value).strip())
    except Exception as e:
        logger.warning(
            "Failed to load %s.%s enum from tools.json: %s",
            tool_name,
            property_name,
            e,
        )
    return frozenset()


SHALLOW_TOOLS: frozenset[str] = _load_tool_classifications("shallow_tools")
DEEP_TOOLS: frozenset[str] = _load_tool_classifications("deep_tools")
CAIDO_BLOCKED_TOOLS: frozenset[str] = _load_tool_classifications(
    "caido_blocked_tools",
    frozenset(
        {
            "spawn_agent",
            "quick_fuzz",
            "advanced_fuzz",
            "deep_fuzz",
            "schemathesis_fuzz",
            "caido_automate",
            "caido_send_request",
        }
    ),
)
MINI_AGENT_BLOCKED_TOOLS: frozenset[str] = _load_tool_classifications(
    "mini_agent_blocked_tools",
    frozenset(
        {
            "spawn_agent",
            "run_parallel_agents",
        }
    ),
)

SEVERITY_ORDER: dict[str, int] = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "INFO": 4,
}
SEVERITY_LABELS: dict[int, str] = {
    5: "CRITICAL",
    4: "HIGH",
    3: "MEDIUM",
    2: "LOW",
    1: "INFO",
}
SEVERITY_VALUES: frozenset[str] = frozenset(SEVERITY_ORDER.keys())
CVSS_THRESHOLDS: list[tuple[float, str]] = [
    (9.0, "CRITICAL"),
    (7.0, "HIGH"),
    (4.0, "MEDIUM"),
]

WRAPPER_TOKENS: frozenset[str] = frozenset(
    {
        "sudo",
        "timeout",
        "stdbuf",
        "env",
        "command",
        "nice",
        "nohup",
        "flock",
        "setsid",
    }
)
SHELL_WRAPPERS: frozenset[str] = frozenset(
    {
        "bash",
        "sh",
        "zsh",
        "fish",
        "dash",
        "ksh",
        "csh",
        "tcsh",
        "ash",
    }
)

MAX_EMPTY_RETRIES: int = 4

VALID_BROWSER_ACTIONS: frozenset[str] = _load_tool_schema_enum("browser_action", "action")

DEFAULT_USER_AGENT: str = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)

def _load_waf_block_status_codes() -> frozenset[int]:
    try:
        path = Path(__file__).parent.parent / "data" / "waf_signatures.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        codes = data.get("block_status_codes", [])
        return frozenset(int(c) for c in codes if c)
    except Exception as e:
        logger.warning("Failed to load WAF block status codes from JSON: %s", e)
        return frozenset({403, 406, 412, 429, 501, 999})


WAF_BLOCK_STATUS_CODES: frozenset[int] = _load_waf_block_status_codes()

BODY_TRUNCATION_LIMIT: int = 5000

ALPHA_EWMA: float = 0.3

DEAD_HOST_MARKERS: tuple[str, ...] = (
    "NXDOMAIN",
    "SERVFAIL",
    "REFUSED",
    "dead host",
    "no route to host",
    "connection refused",
    "Name or service not known",
    "cannot assign requested address",
    "is not reachable",
    "Temporary failure in name resolution",
    "host not found",
)

RESTARTABLE_ERRORS: tuple[str, ...] = (
    "No frame with given id",
    "No frame with given element id",
    "No node with given id found",
    "Session with given id not found",
    "context was already started",
    "connection closed",
    "connection reset",
    "end of file",
    "socket disconnected",
)

SECURITY_HEADERS: dict[str, str] = {
    "content-security-policy": "Controls resource loading to prevent XSS and data injection",
    "x-frame-options": "Prevents clickjacking by controlling iframe embedding",
    "x-content-type-options": "Prevents MIME-type sniffing",
    "strict-transport-security": "Enforces HTTPS connections",
    "x-xss-protection": "Enables built-in browser XSS filtering",
    "referrer-policy": "Controls referrer information sent with requests",
    "permissions-policy": "Restricts browser features available to the page",
    "cross-origin-opener-policy": "Isolates browsing context cross-origin",
    "cross-origin-resource-policy": "Protects against cross-origin reads",
    "cross-origin-embedder-policy": "Prevents loading cross-origin resources",
}

CSRF_FIELD_NAMES: tuple[str, ...] = (
    "csrf_token",
    "csrf",
    "_token",
    "authenticity_token",
)
SESSION_COOKIE_NAMES: tuple[str, ...] = (
    "session",
    "sessionid",
    "sess",
    "auth",
    "token",
    "jwt",
    "remember",
    "phpsessid",
    "jsessionid",
    "asp.net_sessionid",
)
LOGIN_SUCCESS_INDICATORS: tuple[str, ...] = (
    "welcome",
    "logged in",
    "dashboard",
    "logout",
)
LOGIN_FAILURE_INDICATORS: tuple[str, ...] = (
    "invalid credentials",
    "incorrect password",
    "authentication failed",
    "wrong password",
    "wrong username",
    "login failed",
    "account not found",
    "user not found",
    "invalid login",
    "access denied",
)
AUTH_FAILURE_PATTERNS: tuple[tuple[str, str], ...] = (
    ("invalid_token", "Invalid or expired authentication token"),
    ("unauthorized", "Missing or invalid authorization"),
    ("forbidden", "Access denied by server"),
    ("session_expired", "User session has expired"),
    ("csrf_mismatch", "CSRF token validation failed"),
    ("rate_limit", "Authentication rate limit exceeded"),
    ("account_locked", "Account has been temporarily locked"),
)

CAPTCHA_PROVIDERS: tuple[str, ...] = (
    "recaptcha",
    "hCaptcha",
    "Turnstile",
    "FunCaptcha",
    "KeyCAPTCHA",
    "GeeTest",
    "Cloudflare Turnstile",
    "AWS WAF Captcha",
)
CAPTCHA_IFRAME_SELECTORS: tuple[str, ...] = (
    'iframe[src*="captcha"]',
    'iframe[src*="challenge"]',
    'iframe[src*="verify"]',
    'iframe[src*="bot"]',
)
CAPTCHA_INPUT_NAMES: tuple[str, ...] = (
    "g-recaptcha-response",
    "h-captcha-response",
    "cf-turnstile-response",
    "turnstile-response",
)


class AgentRole(str, Enum):
    RECON = "recon"
    ANALYZER = "analyzer"
    EXPLOITER = "exploiter"
    REPORTER = "reporter"
    SPECIALIST = "specialist"
    SCOUT = "scout"
    EXPLOIT = "exploit"


SUBAGENT_EVENT_TYPE_MAP: dict[str, str] = {
    "subdomain": "SUBDOMAIN",
    "vulnerability": "VULNERABILITY",
    "credential": "CREDENTIAL",
    "technology": "TECHNOLOGY",
    "port": "PORT",
    "tool_output": "TOOL_OUTPUT",
    "url": "URL",
    "injection_point": "INJECTION_POINT",
}

CD_WORKSPACE_PREFIX_RE = re.compile(r"^cd\s+/workspace/[^\s]+\s*&&\s*")
CD_DIR_PREFIX_RE = re.compile(r"^cd\s+\S+\s*&&\s*")

def _load_waf_bypass_strategies() -> dict[str, list[dict[str, Any]]]:
    try:
        path = Path(__file__).parent.parent / "data" / "waff_bypass.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        return data.get("BYPASS_STRATEGIES", {})
    except Exception as e:
        logger.warning("Failed to load WAF bypass strategies from JSON: %s", e)
        return {
            "generic": [
                {
                    "name": "sql_comment",
                    "description": "Append SQL comment to bypass keyword filtering",
                    "comments": ["--", "#", "/*", "-- -", "#-", "/*-"],
                },
            ],
        }


WAF_BYPASS_STRATEGIES: dict[str, list[dict[str, Any]]] = _load_waf_bypass_strategies()

SEVERITY_MULTIPLIER: dict[int, float] = {5: 2.0, 4: 1.5, 3: 1.0, 2: 0.7, 1: 0.5}

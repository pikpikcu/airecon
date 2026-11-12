from __future__ import annotations

import logging
import re
from typing import Any
from urllib.parse import parse_qs, urlparse

from ..data_loader import load_endpoint_patterns, load_file_extensions

logger = logging.getLogger("airecon.agent.url_intelligence")

_EXT_DATA = load_file_extensions()

_PURE_STATIC_EXTS: frozenset[str] = frozenset(_EXT_DATA.get("static", []))

_HIGH_VALUE_EXTS: frozenset[str] = frozenset(_EXT_DATA.get("high_value", []))

_DOCUMENT_EXTS: frozenset[str] = frozenset(_EXT_DATA.get("document", []))

_BACKEND_EXTS: frozenset[str] = frozenset(_EXT_DATA.get("backend", []))

_DYNAMIC_EXTS: frozenset[str] = _BACKEND_EXTS

_ENDPOINT_DATA = load_endpoint_patterns()
_TESTABLE_URL_PATTERNS: list[tuple[str, str]] = [
    (entry["pattern"], entry["description"])
    for entry in _ENDPOINT_DATA.get("url_patterns", [])
]

_STATIC_DIR_PATTERNS: list[str] = _ENDPOINT_DATA.get("static_dir_patterns", [])

_JS_ANALYSIS_HINTS: str = (
    "JS FILE ANALYSIS GUIDANCE — When you find .js files, DO NOT skip them! "
    "JavaScript files are GOLD for recon because they often contain:\n"
    "  1. API routes and internal endpoints (search for '/api/', '/v1/', '/graphql')\n"
    "  2. Hardcoded API keys, tokens, secrets (search for 'apiKey', 'secret', 'token', 'key=')\n"
    "  3. Internal hostnames and infrastructure (search for '.internal', '.corp', 'localhost')\n"
    "  4. Parameter names and expected formats (search for 'params', 'query', 'body')\n"
    "  5. Authentication flows and OAuth configs (search for 'oauth', 'auth', 'login')\n"
    "  6. File upload endpoints (search for 'upload', 'multipart', 'FormData')\n"
    "  7. Debug/dev endpoints that shouldn't be in production (search for 'debug', 'test', 'dev')\n"
    "  8. CSP headers and security configurations (search for 'Content-Security-Policy')\n"
    "  9. Third-party integrations and webhooks (search for 'webhook', 'callback')\n"
    "  10. Source maps (.map files) that reveal full source code structure\n\n"
    "TOOLS TO USE: Use LinkFinder, jsleak, or manual grep on JS files:\n"
    "  - grep -rn 'api\\|key\\|secret\\|token\\|password' file.js\n"
    "  - linkfinder -i file.js -o cli\n"
    "  - jsleak -i file.js\n"
    "  - Or download and read the file: curl file.js | grep -E 'http|api|key'"
)


def _get_url_extension(url: str) -> str:
    try:
        parsed = urlparse(url)
        path = parsed.path.rstrip("/")
        last_segment = path.rsplit("/", 1)[-1] if "/" in path else path
        if "." in last_segment:
            ext = last_segment.rsplit(".", 1)[-1].lower()
            return ext
    except Exception as exc:
        logger.warning("Operation failed: %s", exc)
    return ""


def extract_parent_directory(url: str) -> str | None:
    try:
        parsed = urlparse(url)
        path = parsed.path.rstrip("/")
        if "/" not in path or path == "/":
            return None
        parent_path = path.rsplit("/", 1)[0] + "/"
        from urllib.parse import urlunparse

        return urlunparse(
            (
                parsed.scheme,
                parsed.netloc,
                parent_path,
                "",
                "",
                "",
            )
        )
    except Exception as exc:
        logger.debug("URL intelligence error: %s", exc)
        return None


def has_path_parameters(url: str) -> bool:
    try:
        parsed = urlparse(url)
        path = parsed.path
        if re.search(r"\{[^}]+\}", path):
            return True
        if re.search(r":[a-zA-Z_][a-zA-Z0-9_]*", path):
            return True
        if re.search(r"/\d{3,}(?:/|$)", path):
            return True
        if re.search(
            r"/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", path, re.I
        ):
            return True
    except Exception as exc:
        logger.warning("Operation failed: %s", exc)
    return False


def has_query_parameters(url: str) -> bool:
    try:
        parsed = urlparse(url)
        return bool(parsed.query) and "=" in parsed.query
    except Exception as exc:
        logger.debug("URL intelligence error: %s", exc)
        return False


def get_query_param_names(url: str) -> list[str]:
    try:
        parsed = urlparse(url)
        return list(parse_qs(parsed.query).keys())
    except Exception as exc:
        logger.debug("URL intelligence error: %s", exc)
        return []


def classify_url(url: str) -> dict[str, Any]:
    ext = _get_url_extension(url)
    has_path = has_path_parameters(url)
    has_query = has_query_parameters(url)
    params = get_query_param_names(url) if has_query else []

    directory_url = None
    matched_pattern = None
    priority = 0
    category = "unknown"
    is_pure_static = False
    is_testable = False
    is_informational = False
    guidance = None

    if ext in _DYNAMIC_EXTS:
        category = "testable_endpoint"
        is_testable = True
        is_pure_static = False
        if has_query or has_path:
            priority = 90
            matched_pattern = f"Server-side .{ext} with parameters"
        elif ext in ("php", "asp", "aspx", "jsp"):
            priority = 85
            matched_pattern = f"Server-side language: .{ext}"
        else:
            priority = 60
            matched_pattern = f"Dynamic page: .{ext}"

    elif ext in _HIGH_VALUE_EXTS:
        category = (
            "js_file"
            if ext in ("js", "jsx", "ts", "tsx", "mjs", "cjs")
            else "informational"
        )
        is_pure_static = False
        is_testable = False
        is_informational = True
        priority = 70
        matched_pattern = f"JavaScript/TypeScript file: .{ext} (recon gold!)"
        guidance = _JS_ANALYSIS_HINTS
        directory_url = extract_parent_directory(url)
        if directory_url:
            priority = 75

    elif ext in _PURE_STATIC_EXTS:
        category = "static_asset"
        is_pure_static = True
        is_testable = False
        is_informational = False
        priority = 5
        matched_pattern = f"Static asset: .{ext} (no attack surface)"
        directory_url = extract_parent_directory(url)
        if directory_url:
            priority = 40
            matched_pattern = f"Static .{ext} → fuzz directory: {directory_url}"

    elif ext in _DOCUMENT_EXTS:
        category = "informational"
        is_pure_static = False
        is_testable = False
        is_informational = True
        directory_url = extract_parent_directory(url)

        if ext in ("pdf", "doc", "docx", "xls", "xlsx"):
            priority = 35
            matched_pattern = f"Document file: .{ext} (might contain sensitive info)"
            guidance = (
                f"PDF/Document files can leak sensitive information: internal hostnames, "
                f"author names, software versions, internal processes, or confidential data. "
                f"Download and review: curl -O '{url}' && exiftool file.pdf"
            )
        elif ext == "map":
            priority = 55
            matched_pattern = f"Source map: .{ext} (reveals source code)"
            guidance = (
                f"Source maps (.map) can be used to reconstruct full source code. "
                f"Download and use 'sourcemap' tools to extract original source: "
                f"curl '{url}' > file.map"
            )
        elif ext in ("json", "xml", "yml", "yaml"):
            priority = 45
            matched_pattern = f"Config/data file: .{ext}"
            guidance = (
                f"Check if .{ext} file is publicly accessible and leaks config/secrets."
            )
        elif ext in ("css", "scss", "less"):
            priority = 15
            matched_pattern = (
                f"Stylesheet: .{ext} (low value but check for internal paths)"
            )
        elif ext in ("txt", "md", "log"):
            priority = 25
            matched_pattern = f"Text/log file: .{ext}"
        else:
            priority = 20
            matched_pattern = f"Informational: .{ext}"

    else:
        url_lower = url.lower()
        for pattern, description in _TESTABLE_URL_PATTERNS:
            if re.search(pattern, url_lower):
                category = "testable_endpoint"
                is_testable = True
                priority = 85 if "api" in pattern or "graphql" in pattern else 60
                matched_pattern = description
                break

        if category == "unknown":
            for pat in _STATIC_DIR_PATTERNS:
                if re.search(pat, url_lower):
                    category = "static_asset"
                    is_pure_static = True
                    priority = 5
                    matched_pattern = f"Static directory path: {pat}"
                    directory_url = extract_parent_directory(url)
                    if directory_url:
                        priority = 35
                    break

        if category == "unknown" and (has_query or has_path):
            category = "testable_endpoint"
            is_testable = True
            priority = 75
            matched_pattern = "Has parameters (path or query)"
        elif category == "unknown":
            category = "informational"
            priority = 30
            matched_pattern = "No specific pattern matched"
            directory_url = extract_parent_directory(url)

    if has_path and is_testable:
        priority = min(100, priority + 10)
    if has_query and is_testable:
        priority = min(100, priority + 5)

    return {
        "category": category,
        "extension": ext,
        "is_pure_static": is_pure_static,
        "is_testable": is_testable,
        "is_informational": is_informational,
        "directory_url": directory_url,
        "has_path_params": has_path,
        "has_query_params": has_query,
        "param_names": params,
        "matched_pattern": matched_pattern,
        "priority": priority,
        "guidance": guidance,
    }


def filter_static_assets(urls: list[str]) -> tuple[list[str], list[str], list[str]]:
    testable: list[str] = []
    informational: list[str] = []
    static: list[str] = []

    for url in urls:
        classification = classify_url(url)
        if classification["is_testable"]:
            testable.append(url)
        elif classification["is_informational"]:
            informational.append(url)
        elif classification["is_pure_static"]:
            static.append(url)
        else:
            testable.append(url)

    return testable, informational, static


def sort_urls_by_priority(urls: list[str]) -> list[str]:
    scored = []
    for url in urls:
        classification = classify_url(url)
        scored.append((classification["priority"], url))

    scored.sort(key=lambda x: (-x[0], x[1]))
    return [url for _, url in scored]


def build_url_intelligence_context(urls: list[str]) -> str:
    if not urls:
        return ""

    classifications = [(url, classify_url(url)) for url in urls]

    testable = [u for u, c in classifications if c["is_testable"]]
    js_files = [u for u, c in classifications if c["category"] == "js_file"]
    informational = [
        u
        for u, c in classifications
        if c["is_informational"] and c["category"] != "js_file"
    ]
    pure_static = [u for u, c in classifications if c["is_pure_static"]]
    static_dirs: list[str] = []
    for u, c in classifications:
        if c["directory_url"] and c["directory_url"] not in static_dirs:
            static_dirs.append(c["directory_url"])

    parts: list[str] = [
        "<url_intelligence>",
        f"  Total URLs: {len(urls)}",
        f"  Testable endpoints: {len(testable)}",
        f"  JavaScript files (analyze for secrets/routes): {len(js_files)}",
        f"  Informational files (might leak info): {len(informational)}",
        f"  Pure static assets (images/fonts/media): {len(pure_static)}",
    ]

    if js_files:
        parts.append(f"  JS FILE ANALYSIS — {len(js_files)} JavaScript files found:")
        for url in js_files[:10]:
            parts.append(f"    {url[:120]}")
        if len(js_files) > 10:
            parts.append(f"    ... and {len(js_files) - 10} more JS files")
        parts.append(
            "  Use linkfinder, jsleak, or grep on JS files for API keys, routes, secrets."
        )

    if static_dirs:
        parts.append("  Directories for fuzzing (extracted from static URLs):")
        for d in sorted(set(static_dirs))[:15]:
            parts.append(f"    {d}")
        if len(static_dirs) > 15:
            parts.append(f"    ... and {len(static_dirs) - 15} more directories")

    if testable:
        sorted_testable = sort_urls_by_priority(testable)
        parts.append("  Top testable endpoints (sorted by priority):")
        for url in sorted_testable[:15]:
            c = classify_url(url)
            param_info = ""
            if c["has_path_params"]:
                param_info += " [path params]"
            if c["has_query_params"]:
                param_info += f" [query: {', '.join(c['param_names'][:5])}]"
            parts.append(f"    [{c['priority']:3d}]{param_info} {url[:120]}")
        if len(testable) > 15:
            parts.append(f"    ... and {len(testable) - 15} more testable endpoints")

    parts.append(
        "  <recon_guidance>"
        "  RULES: (1) Analyze JS files for routes/keys/secrets — DO NOT skip them. "
        "(2) Extract directories from static URLs for directory fuzzing. "
        "(3) Check PDFs/docs for leaked sensitive info. "
        "(4) Skip fuzzing individual image/font/media files entirely. "
        "(5) Focus fuzzing on API endpoints, forms, parameterized URLs, and directories."
        "  </recon_guidance>"
    )

    parts.append("</url_intelligence>")
    return "\n".join(parts)


def is_endpoint_worth_testing(url: str) -> bool:
    c = classify_url(url)
    return c["is_testable"] or c["is_informational"]

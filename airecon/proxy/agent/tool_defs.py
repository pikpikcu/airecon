from __future__ import annotations


def get_tool_definitions() -> list[dict]:
    return [
        _browser_action_def(),
        _create_file_def(),
        _read_file_def(),
        _web_search_def(),
        _create_vulnerability_report_def(),
    ]


def _browser_action_def() -> dict:
    return {
        "type": "function",
        "function": {
            "name": "browser_action",
            "description": "Control a headless browser to navigate, interact, or extract data from websites.",
            "parameters": {
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "enum": [
                            "launch", "goto", "click", "type", "scroll_down", "scroll_up",
                            "back", "forward", "new_tab", "switch_tab", "close_tab", "wait",
                            "execute_js", "double_click", "hover", "press_key", "save_pdf",
                            "get_console_logs", "view_source", "close", "list_tabs",
                        ],
                        "description": "The action to perform.",
                    },
                    "url": {"type": "string", "description": "URL for launch/goto/new_tab."},
                    "coordinate": {"type": "string", "description": "x,y coordinates for click/hover."},
                    "text": {"type": "string", "description": "Text to type."},
                    "tab_id": {"type": "string", "description": "Tab ID to target."},
                    "js_code": {"type": "string", "description": "JavaScript code to execute."},
                    "duration": {"type": "number", "description": "Duration to wait in seconds."},
                    "key": {"type": "string", "description": "Key to press."},
                    "file_path": {"type": "string", "description": "Path to save PDF."},
                    "clear": {"type": "boolean", "description": "Clear logs after fetching."},
                },
                "required": ["action"],
            },
        },
    }


def _create_file_def() -> dict:
    return {
        "type": "function",
        "function": {
            "name": "create_file",
            "description": "Create a new file in the workspace. Overwrites if exists.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "File path (relative to workspace/ or absolute within workspace/)"},
                    "content": {"type": "string", "description": "Content to write to the file."},
                },
                "required": ["path", "content"],
            },
        },
    }


def _read_file_def() -> dict:
    return {
        "type": "function",
        "function": {
            "name": "read_file",
            "description": "Read content of a file from the workspace.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "File path to read."},
                },
                "required": ["path"],
            },
        },
    }


def _web_search_def() -> dict:
    return {
        "type": "function",
        "function": {
            "name": "web_search",
            "description": (
                "Search the web using DuckDuckGo. Use this to research payloads, "
                "CVEs, exploit techniques, WAF bypasses, tool flags, or any "
                "information needed during security testing."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Search query string.",
                    },
                    "max_results": {
                        "type": "integer",
                        "description": "Maximum results to return (default: 5, max: 10).",
                    },
                },
                "required": ["query"],
            },
        },
    }


def _create_vulnerability_report_def() -> dict:
    return {
        "type": "function",
        "function": {
            "name": "create_vulnerability_report",
            "description": """Create a vulnerability report for a discovered security issue.

IMPORTANT: This tool checks for duplicate reports by title — a report with the same title as an existing one will be rejected. Do NOT attempt to re-submit a rejected report; move on to testing other areas.

Use this tool to document a specific fully verified security vulnerability.

DO NOT USE:
- For general security observations without specific vulnerabilities
- When you don't have concrete vulnerability details
- When you don't have a proof of concept, or still not 100% sure if it's a vulnerability
- For tracking multiple vulnerabilities (create separate reports)
- For reporting multiple vulnerabilities at once. Use a separate create_vulnerability_report for each vulnerability.
- To re-report a vulnerability that was already reported

DEDUPLICATION: If this tool returns with success=false and mentions a duplicate or existing title, DO NOT attempt to re-submit. Move on to testing other areas.

Professional, customer-facing report rules (PDF-ready):
- Do NOT include internal or system details: never mention local or absolute paths (e.g., "/workspace"), internal tools, agents, orchestrators, sandboxes, models, system prompts/instructions, connection issues, internal errors/logs/stack traces, or tester machine environment details.
- Tone and style: formal, objective, third-person, vendor-neutral, concise. No runbooks, checklists, or engineering notes. Avoid headings like "QUICK", "Approach", or "Techniques" that read like internal guidance.
- Use a standard penetration testing report structure per finding:
  1) Overview
  2) Severity and CVSS (vector only)
  3) Affected asset(s)
  4) Technical details
  5) Proof of concept (repro steps plus code)
  6) Impact
  7) Remediation
  8) Evidence (optional request/response excerpts, etc.) in the technical analysis field.
- Numbered steps are allowed ONLY within the proof of concept. Elsewhere, use clear, concise paragraphs suitable for customer-facing reports.
- Language must be precise and non-vague; avoid hedging.""",
            "parameters": {
                "type": "object",
                "properties": {
                    "title": {
                        "type": "string",
                        "description": "Clear, specific title (e.g., \"SQL Injection in /api/users Login Parameter\"). But not too long. Don't mention CVE number in the title.",
                    },
                    "description": {
                        "type": "string",
                        "description": "Comprehensive description of the vulnerability and how it was discovered",
                    },
                    "impact": {
                        "type": "string",
                        "description": "Impact assessment: what attacker can do, business risk, data at risk",
                    },
                    "target": {
                        "type": "string",
                        "description": "Affected target: URL, domain, or Git repository",
                    },
                    "technical_analysis": {
                        "type": "string",
                        "description": "Technical explanation of the vulnerability mechanism and root cause",
                    },
                    "poc_description": {
                        "type": "string",
                        "description": "Step-by-step instructions to reproduce the vulnerability",
                    },
                    "poc_script_code": {
                        "type": "string",
                        "description": "Actual proof of concept code, exploit, payload, or script that demonstrates the vulnerability. Python code.",
                    },
                    "remediation_steps": {
                        "type": "string",
                        "description": "Specific, actionable steps to fix the vulnerability",
                    },
                    "attack_vector": {
                        "type": "string",
                        "enum": ["N", "A", "L", "P"],
                        "description": "CVSS Attack Vector:\nN=Network, A=Adjacent, L=Local, P=Physical",
                    },
                    "attack_complexity": {
                        "type": "string",
                        "enum": ["L", "H"],
                        "description": "CVSS Attack Complexity:\nL=Low, H=High",
                    },
                    "privileges_required": {
                        "type": "string",
                        "enum": ["N", "L", "H"],
                        "description": "CVSS Privileges Required:\nN=None, L=Low, H=High",
                    },
                    "user_interaction": {
                        "type": "string",
                        "enum": ["N", "R"],
                        "description": "CVSS User Interaction:\nN=None, R=Required",
                    },
                    "scope": {
                        "type": "string",
                        "enum": ["U", "C"],
                        "description": "CVSS Scope:\nU=Unchanged, C=Changed",
                    },
                    "confidentiality": {
                        "type": "string",
                        "enum": ["N", "L", "H"],
                        "description": "CVSS Confidentiality Impact:\nN=None, L=Low, H=High",
                    },
                    "integrity": {
                        "type": "string",
                        "enum": ["N", "L", "H"],
                        "description": "CVSS Integrity Impact:\nN=None, L=Low, H=High",
                    },
                    "availability": {
                        "type": "string",
                        "enum": ["N", "L", "H"],
                        "description": "CVSS Availability Impact:\nN=None, L=Low, H=High",
                    },
                    "endpoint": {
                        "type": "string",
                        "description": "API endpoint(s) or URL path(s) — for web vulns, or repo path — for code vulns",
                    },
                    "method": {
                        "type": "string",
                        "description": "HTTP method(s) (GET, POST, etc.) — for web vulnerabilities.",
                    },
                    "cve": {
                        "type": "string",
                        "description": "CVE identifier (e.g., \"CVE-2024-1234\"). Verify it's valid via web_search before using.",
                    },
                },
                "required": [
                    "title", "description", "impact", "target", "technical_analysis",
                    "poc_description", "poc_script_code", "remediation_steps",
                    "attack_vector", "attack_complexity", "privileges_required",
                    "user_interaction", "scope", "confidentiality", "integrity", "availability",
                ],
            },
        },
    }

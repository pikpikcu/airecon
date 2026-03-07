"""Source Code Analysis via Semgrep.

Runs Semgrep static analysis inside the Docker sandbox against
cloned repositories or downloaded source code. Results are parsed
into structured findings with severity, CWE, and file location.
"""

from __future__ import annotations

import json
import logging
from typing import Any

logger = logging.getLogger("airecon.semgrep")

# Curated rule sets targeting security vulnerabilities
DEFAULT_RULE_SETS: list[str] = [
    "p/security-audit",
    "p/owasp-top-ten",
    "p/cwe-top-25",
]


def get_default_rules() -> list[str]:
    """Return the default Semgrep security rule sets."""
    return list(DEFAULT_RULE_SETS)


def build_semgrep_command(
    target_path: str,
    rules: list[str] | None = None,
    languages: list[str] | None = None,
    max_findings: int = 100,
) -> str:
    """Build a Semgrep CLI command string for Docker execution.

    Args:
        target_path: Path to scan inside the container (relative to /workspace).
        rules: Semgrep rule set identifiers (e.g. p/security-audit).
        languages: Filter to specific languages (e.g. python, javascript).
        max_findings: Cap the number of findings returned.

    Returns:
        Full command string to run inside the Docker sandbox.
    """
    rule_sets = rules or get_default_rules()
    rule_args = " ".join(f"--config {r}" for r in rule_sets)

    lang_arg = ""
    if languages:
        lang_arg = f"--lang {','.join(languages)}"

    return (
        f"semgrep {rule_args} {lang_arg} "
        f"--json --no-git-ignore --max-target-bytes 1000000 "
        f"--timeout 120 --max-memory 2048 "
        f"--metrics off "
        f"{target_path} 2>/dev/null | head -c {int(max_findings) * 5000}"
    )


def parse_semgrep_results(raw_json: str) -> dict[str, Any]:
    """Parse Semgrep JSON output into structured findings.

    Args:
        raw_json: Raw JSON string from `semgrep --json`.

    Returns:
        Dict with 'findings' (list), 'errors' (list), and 'summary'.
    """
    try:
        data = json.loads(raw_json)
    except json.JSONDecodeError as e:
        return {
            "findings": [],
            "errors": [f"Failed to parse Semgrep output: {e}"],
            "summary": "Parse error",
        }

    results: list[dict[str, Any]] = []
    for result in data.get("results", []):
        check_id = result.get("check_id", "unknown")
        message = result.get("extra", {}).get("message", "")
        severity = result.get("extra", {}).get("severity", "WARNING").upper()
        metadata = result.get("extra", {}).get("metadata", {})

        finding = {
            "rule_id": check_id,
            "message": message,
            "severity": severity,
            "file": result.get("path", ""),
            "start_line": result.get("start", {}).get("line", 0),
            "end_line": result.get("end", {}).get("line", 0),
            "code_snippet": result.get("extra", {}).get("lines", ""),
            "cwe": metadata.get("cwe", []),
            "owasp": metadata.get("owasp", []),
            "confidence": metadata.get("confidence", "MEDIUM"),
            "references": metadata.get("references", []),
        }
        results.append(finding)

    errors = [
        {"type": e.get("type", ""), "message": e.get("message", "")}
        for e in data.get("errors", [])
    ]

    # Build summary
    by_severity: dict[str, int] = {}
    for f in results:
        sev = f["severity"]
        by_severity[sev] = by_severity.get(sev, 0) + 1

    severity_str = ", ".join(
        f"{k}: {v}" for k, v in sorted(
            by_severity.items()))
    summary = f"Found {len(results)} issues ({severity_str})" if results else "No issues found"

    return {
        "findings": results,
        "errors": errors,
        "summary": summary,
        "total": len(results),
    }


async def run_code_analysis(
    engine: Any,
    target_path: str,
    rules: list[str] | None = None,
    languages: list[str] | None = None,
) -> dict[str, Any]:
    """Run Semgrep analysis on a target path inside the Docker sandbox.

    This is the main entry point called by the executor. It:
    1. Checks if semgrep is installed (installs if needed)
    2. Builds and runs the semgrep command
    3. Parses and returns structured results

    Args:
        engine: DockerEngine instance for command execution.
        target_path: Path to scan (relative to workspace root).
        rules: Optional list of Semgrep rule sets.
        languages: Optional list of languages to filter.

    Returns:
        Dict with parsed findings, errors, and summary.
    """
    # Ensure semgrep is available
    install_check = await engine.execute_tool(
        "execute",
        {"command": "which semgrep || pip install semgrep 2>&1 | tail -1"},
    )
    if not install_check.get("success", False):
        logger.warning(
            "Semgrep installation may have failed, attempting scan anyway")

    # Build and run the scan command
    scan_cmd = build_semgrep_command(
        target_path, rules=rules, languages=languages)
    result = await engine.execute_tool("execute", {"command": scan_cmd})

    if not result.get("success", False):
        error_msg = result.get("error", result.get("stderr", "Unknown error"))
        return {
            "findings": [],
            "errors": [f"Semgrep execution failed: {error_msg}"],
            "summary": "Scan failed",
            "total": 0,
        }

    stdout = result.get("result", result.get("stdout", ""))
    if isinstance(stdout, dict):
        stdout = json.dumps(stdout)

    if not stdout or not stdout.strip():
        return {
            "findings": [],
            "errors": [],
            "summary": "No output from Semgrep (target may have no scannable files)",
            "total": 0,
        }

    return parse_semgrep_results(stdout)

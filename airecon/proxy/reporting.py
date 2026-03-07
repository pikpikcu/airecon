"""
Vulnerability reporting tool for AIRecon.
"""
import os
import re
import logging
from typing import Any
from datetime import datetime
from .config import get_workspace_root

_CVE_RE = re.compile(r'^CVE-\d{4}-\d{4,}$', re.IGNORECASE)

logger = logging.getLogger("airecon.proxy.reporting")

try:
    from cvss import CVSS3
except ImportError:
    CVSS3 = None


def calculate_cvss_and_severity(
    attack_vector: str,
    attack_complexity: str,
    privileges_required: str,
    user_interaction: str,
    scope: str,
    confidentiality: str,
    integrity: str,
    availability: str,
) -> tuple[float, str, str]:
    if CVSS3 is None:
        return 0.0, "unknown", "CVSS library not installed"

    try:
        vector = (
            f"CVSS:3.1/AV:{attack_vector}/AC:{attack_complexity}/"
            f"PR:{privileges_required}/UI:{user_interaction}/S:{scope}/"
            f"C:{confidentiality}/I:{integrity}/A:{availability}"
        )

        c = CVSS3(vector)
        scores = c.scores()
        severities = c.severities()

        base_score = scores[0]
        base_severity = severities[0]

        severity = base_severity.lower()
        return base_score, severity, vector

    except Exception:
        logger.exception("Failed to calculate CVSS")
        return 0.0, "unknown", ""


def _validate_required_fields(**kwargs: str | None) -> list[str]:
    validation_errors: list[str] = []

    # Only truly required fields — title, description, target, and PoC
    required_fields = {
        "title": "Title cannot be empty",
        "description": "Description cannot be empty",
        "target": "Target cannot be empty",
        "poc_description": "PoC description cannot be empty",
        "poc_script_code": "PoC script/code is REQUIRED - provide the actual exploit/payload",
    }

    for field_name, error_msg in required_fields.items():
        value = kwargs.get(field_name)
        if not value or not str(value).strip():
            validation_errors.append(error_msg)

    return validation_errors


def _validate_cvss_parameters(**kwargs: str) -> list[str]:
    validation_errors: list[str] = []

    cvss_validations = {
        "attack_vector": ["N", "A", "L", "P"],
        "attack_complexity": ["L", "H"],
        "privileges_required": ["N", "L", "H"],
        "user_interaction": ["N", "R"],
        "scope": ["U", "C"],
        "confidentiality": ["N", "L", "H"],
        "integrity": ["N", "L", "H"],
        "availability": ["N", "L", "H"],
    }

    for param_name, valid_values in cvss_validations.items():
        value = kwargs.get(param_name)
        if value not in valid_values:
            validation_errors.append(
                f"Invalid {param_name}: {value}. Must be one of: {valid_values}"
            )

    return validation_errors


def create_vulnerability_report(
    title: str,
    description: str,
    target: str,
    poc_description: str,
    poc_script_code: str,
    # Optional text fields (required for full reports, optional for CTF)
    impact: str = "",
    technical_analysis: str = "",
    remediation_steps: str = "",
    # CVSS Breakdown Components (optional — skip for CTF)
    attack_vector: str | None = None,
    attack_complexity: str | None = None,
    privileges_required: str | None = None,
    user_interaction: str | None = None,
    scope: str | None = None,
    confidentiality: str | None = None,
    integrity: str | None = None,
    availability: str | None = None,
    # Optional fields
    endpoint: str | None = None,
    method: str | None = None,
    cve: str | None = None,
    suggested_fix: str | None = None,
    flag: str | None = None,
    # Internal injection
    _workspace_root: str | None = None,
    _active_target: str | None = None,
) -> dict[str, Any]:

    validation_errors = _validate_required_fields(
        title=title,
        description=description,
        target=target,
        poc_description=poc_description,
        poc_script_code=poc_script_code,
    )

    # Determine if CVSS was provided (all 8 params must be present)
    cvss_params = {
        "attack_vector": attack_vector,
        "attack_complexity": attack_complexity,
        "privileges_required": privileges_required,
        "user_interaction": user_interaction,
        "scope": scope,
        "confidentiality": confidentiality,
        "integrity": integrity,
        "availability": availability,
    }
    has_cvss = all(v is not None for v in cvss_params.values())

    if has_cvss:
        validation_errors.extend(
            _validate_cvss_parameters(
                **cvss_params))  # type: ignore[arg-type]

    if validation_errors:
        return {"success": False, "message": "Validation failed",
                "errors": validation_errors}

    # Validate CVE format if provided
    if cve and cve.strip():
        if not _CVE_RE.match(cve.strip()):
            return {
                "success": False,
                "message": f"Invalid CVE format: '{cve}'. Must match CVE-YYYY-NNNN+ (e.g., CVE-2024-1234). Use web_search to verify CVE IDs.",
            }

    # Calculate CVSS only if all params were provided
    if has_cvss:
        cvss_score, severity, cvss_vector = calculate_cvss_and_severity(
            **cvss_params)  # type: ignore[arg-type]
    else:
        cvss_score, severity, cvss_vector = 0.0, "n/a", ""

    # Clean target for folder name
    target_clean = str(target).replace(
        "https://",
        "").replace(
        "http://",
        "").split("/")[0]
    target_clean = re.sub(r'[^a-zA-Z0-9\.\-_]', '_', target_clean)

    # Normalize subdomain to root target: if the LLM passed sub.target.com but the
    # active target is target.com, save the report under
    # target.com/vulnerabilities/
    if _active_target:
        active_clean = str(_active_target).replace(
            "https://",
            "").replace(
            "http://",
            "").split("/")[0]
        active_clean = re.sub(r'[^a-zA-Z0-9\.\-_]', '_', active_clean)
        if target_clean != active_clean and (
            target_clean.endswith(
                "." +
                active_clean) or active_clean.endswith(
                "." +
                target_clean)
        ):
            target_clean = active_clean

    if not _workspace_root:
        _workspace_root = str(get_workspace_root())

    vuln_dir = os.path.join(_workspace_root, target_clean, "vulnerabilities")
    try:
        os.makedirs(vuln_dir, exist_ok=True)
    except Exception as e:
        return {"success": False, "message": f"Failed to create directory: {e}"}

    # Generate filename
    slug = re.sub(r'[^a-zA-Z0-9]', '_', title).lower()
    # Truncate slug if too long
    slug = slug[:50]
    filename = f"{slug}.md"
    filepath = os.path.join(vuln_dir, filename)
    report_id = slug

    # Check for duplicate file (simple check)
    if os.path.exists(filepath):
        return {
            "success": False,
            "message": f"Report '{filename}' already exists. Title collision detected.",
            "duplicate_of": report_id,
            "duplicate_title": title,
            "confidence": 1.0,
            "reason": "Exact title match with existing report.",
        }

    # Generate Markdown Content — adapt format based on whether CVSS/full
    # fields provided
    md_content = f"# {title}\n\n"
    md_content += f"**ID**: {report_id}\n"

    if has_cvss:
        md_content += f"**Severity**: {severity.upper()} (CVSS: {cvss_score})\n"
        md_content += f"**Vector**: `{cvss_vector}`\n"

    md_content += f"**Target**: {target}\n"
    md_content += f"**Date**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"

    if endpoint:
        md_content += f"**Endpoint**: {endpoint}\n"
    if method:
        md_content += f"**Method**: {method}\n"
    if flag:
        md_content += f"**Flag**: `{flag}`\n"

    md_content += f"\n## Overview\n{description}\n"

    if has_cvss:
        md_content += "\n## Severity and CVSS\n"
        md_content += f"- **Base Score**: {cvss_score} ({severity.upper()})\n"
        md_content += f"- **Vector**: `{cvss_vector}`\n"

    if technical_analysis and technical_analysis.strip():
        md_content += f"\n## Technical Details\n{technical_analysis}\n"

    md_content += f"\n## Proof of Concept\n{poc_description}\n"
    md_content += f"\n```\n{poc_script_code}\n```\n"

    if impact and impact.strip():
        md_content += f"\n## Impact\n{impact}\n"

    if remediation_steps and remediation_steps.strip():
        md_content += f"\n## Remediation\n{remediation_steps}\n"

    if suggested_fix and suggested_fix.strip():
        md_content += f"\n## Suggested Fix\n```\n{suggested_fix.strip()}\n```\n"

    if cve:
        md_content += f"\n## Reference\n**CVE**: {cve}\n"

    try:
        with open(filepath, "w") as f:
            f.write(md_content)

        result: dict[str, Any] = {
            "success": True,
            "message": f"Vulnerability report saved to {filepath}",
            "report_id": report_id,
            "report_path": filepath,
        }
        if has_cvss:
            result["severity"] = severity
            result["cvss_score"] = cvss_score
        if flag:
            result["flag"] = flag
        return result
    except Exception as e:
        return {"success": False, "message": f"Failed to write report file: {e}"}

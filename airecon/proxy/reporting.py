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

    required_fields = {
        "title": "Title cannot be empty",
        "description": "Description cannot be empty",
        "impact": "Impact cannot be empty",
        "target": "Target cannot be empty",
        "technical_analysis": "Technical analysis cannot be empty",
        "poc_description": "PoC description cannot be empty",
        "poc_script_code": "PoC script/code is REQUIRED - provide the actual exploit/payload",
        "remediation_steps": "Remediation steps cannot be empty",
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
    impact: str,
    target: str,
    technical_analysis: str,
    poc_description: str,
    poc_script_code: str,
    remediation_steps: str,
    # CVSS Breakdown Components
    attack_vector: str,
    attack_complexity: str,
    privileges_required: str,
    user_interaction: str,
    scope: str,
    confidentiality: str,
    integrity: str,
    availability: str,
    # Optional fields
    endpoint: str | None = None,
    method: str | None = None,
    cve: str | None = None,
    # Internal injection
    _workspace_root: str | None = None, 
) -> dict[str, Any]:
    
    validation_errors = _validate_required_fields(
        title=title,
        description=description,
        impact=impact,
        target=target,
        technical_analysis=technical_analysis,
        poc_description=poc_description,
        poc_script_code=poc_script_code,
        remediation_steps=remediation_steps,
    )

    validation_errors.extend(
        _validate_cvss_parameters(
            attack_vector=attack_vector,
            attack_complexity=attack_complexity,
            privileges_required=privileges_required,
            user_interaction=user_interaction,
            scope=scope,
            confidentiality=confidentiality,
            integrity=integrity,
            availability=availability,
        )
    )

    if validation_errors:
        return {"success": False, "message": "Validation failed", "errors": validation_errors}

    # Validate CVE format if provided
    if cve and cve.strip():
        if not _CVE_RE.match(cve.strip()):
            return {
                "success": False,
                "message": f"Invalid CVE format: '{cve}'. Must match CVE-YYYY-NNNN+ (e.g., CVE-2024-1234). Use web_search to verify CVE IDs.",
            }

    cvss_score, severity, cvss_vector = calculate_cvss_and_severity(
        attack_vector,
        attack_complexity,
        privileges_required,
        user_interaction,
        scope,
        confidentiality,
        integrity,
        availability,
    )

    # Clean target for folder name
    target_clean = str(target).replace("https://", "").replace("http://", "").split("/")[0]
    target_clean = re.sub(r'[^a-zA-Z0-9\.\-_]', '_', target_clean)
    
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
            "reason": "Exact title match with existing report."
        }

    # Generate Markdown Content
    md_content = f"""# {title}

**ID**: {report_id}
**Severity**: {severity.upper()} (CVSS: {cvss_score})
**Vector**: `{cvss_vector}`
**Target**: {target}
**Date**: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
**Endpoint**: {endpoint or "N/A"}
**Method**: {method or "N/A"}

## 1. Overview
{description}

## 2. Severity and CVSS
- **Base Score**: {cvss_score} ({severity.upper()})
- **Vector**: `{cvss_vector}`

## 3. Affected Asset(s)
- **Target**: {target}
- **Endpoint**: {endpoint or "N/A"}

## 4. Technical Details
{technical_analysis}

## 5. Proof of Concept
{poc_description}

```python
{poc_script_code}
```

## 6. Impact
{impact}

## 7. Remediation
{remediation_steps}

"""
    if cve:
        md_content += f"## Reference\n**CVE**: {cve}\n"

    try:
        with open(filepath, "w") as f:
            f.write(md_content)
            
        return {
            "success": True, 
            "message": f"Vulnerability report saved to {filepath}",
            "report_id": report_id,
            "report_path": filepath,
            "severity": severity,
            "cvss_score": cvss_score
        }
    except Exception as e:
        return {"success": False, "message": f"Failed to write report file: {e}"}

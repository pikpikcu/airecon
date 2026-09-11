"""Tests for per-finding evidence persistence (raw request/response artifacts)."""

from __future__ import annotations

import json
import tempfile

from airecon.proxy.reporting import create_vulnerability_report


def _report(tmp, **extra):
    base = dict(
        title="Reflected XSS in q",
        description="desc",
        target="https://t.example",
        poc_description="poc",
        poc_script_code="<script>alert(1)</script>",
        endpoint="https://t.example/s?q=1",
        method="GET",
        _workspace_root=tmp,
        _active_target="https://t.example",
    )
    base.update(extra)
    return create_vulnerability_report(**base)


def test_evidence_artifact_written_and_linked():
    tmp = tempfile.mkdtemp()
    r = _report(
        tmp,
        _verification_status="CONFIRMED",
        _verification_confidence=0.9,
        _evidence_artifacts=[
            {"payload": "<script>alert(1)</script>", "status": 200, "length": 1234, "confirmed": True},
            {"payload": "clean", "status": 200, "length": 1000, "confirmed": False},
        ],
    )
    assert r["success"] is True
    assert r["evidence_count"] == 2
    # Artifact file persisted with the actual records.
    data = json.load(open(r["evidence_path"]))
    assert len(data["records"]) == 2
    assert data["verification_status"] == "CONFIRMED"
    assert data["records"][0]["confirmed"] is True
    # Markdown references the artifact + renders an evidence table.
    md = open(r["report_path"]).read()
    assert "## Evidence (captured request/response)" in md
    assert ".evidence.json" in md
    assert "| # | Payload | Status | Len | Confirmed |" in md


def test_no_evidence_section_when_none():
    tmp = tempfile.mkdtemp()
    r = _report(tmp, _verification_status="EVIDENCE-GROUNDED")
    assert r["success"] is True
    assert "evidence_path" not in r
    md = open(r["report_path"]).read()
    assert "## Evidence (captured request/response)" not in md


def test_finding_lifecycle_labels():
    tmp = tempfile.mkdtemp()
    cases = {
        "CONFIRMED": "VALIDATED",
        "CERTIFIED": "VALIDATED",
        "VALIDATED": "VALIDATED",
        "RUNTIME-INCONCLUSIVE": "SUSPECTED",
        "EVIDENCE-GROUNDED": "SUSPECTED",
        "": "INFORMATIONAL",
    }
    for i, (status, expected) in enumerate(cases.items()):
        r = _report(tmp, title=f"Finding {i}", _verification_status=status)
        assert r["finding_status"] == expected
        assert f"**Finding status**: {expected}" in open(r["report_path"]).read()


def test_classification_section_cwe_owasp():
    tmp = tempfile.mkdtemp()
    r = _report(tmp, title="SQLi", cwe="CWE-89", owasp="A03:2021-Injection")
    md = open(r["report_path"]).read()
    assert "## Classification" in md
    assert "CWE-89" in md
    assert "A03:2021-Injection" in md
    # Absent when not provided.
    r2 = _report(tmp, title="NoClass")
    assert "## Classification" not in open(r2["report_path"]).read()


def test_evidence_table_escapes_pipes():
    tmp = tempfile.mkdtemp()
    r = _report(
        tmp,
        _verification_status="CONFIRMED",
        _evidence_artifacts=[{"payload": "a|b|c", "status": 200, "length": 5, "confirmed": True}],
    )
    md = open(r["report_path"]).read()
    # Pipe in payload must be escaped so the markdown table isn't broken.
    assert "a\\|b\\|c" in md

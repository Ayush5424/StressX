import os
import json
import pytest
from app.models.target import Target
from app.models.session import AuditSession
from app.models.finding import Finding, Severity, Confidence, FindingCategory
from app.models.evidence import Evidence
from app.evidence.store import EvidenceStore


def test_evidence_store_export(tmp_path):
    store = EvidenceStore(export_dir=str(tmp_path))
    target = Target(base_url="http://127.0.0.1:8088")
    session = AuditSession(target=target)

    # Add evidence and finding
    ev = Evidence.from_http_exchange(
        description="SQL injection verification probe",
        method="GET",
        url="http://127.0.0.1:8088/api/v1/search?q='",
        status_code=500,
        req_headers={"Accept": "application/json"},
        req_body=None,
        res_headers={"content-type": "application/json"},
        res_body='{"detail": "syntax error"}',
        latency_ms=12.4
    )
    session.add_evidence(ev)

    finding = Finding(
        title="SQL Injection in Search",
        category=FindingCategory.UNSAFE_INPUT_HANDLING,
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        description="Dynamic query vulnerable to SQL injection",
        impact="Data leakage",
        remediation="Use ORM",
        affected_endpoint="/api/v1/search"
    )
    finding.add_evidence(ev)
    session.add_finding(finding)

    # Export
    dossier_path = store.save_session_dossier(session)
    report_path = store.generate_markdown_report(session)

    assert os.path.exists(dossier_path)
    assert os.path.exists(report_path)

    with open(dossier_path, "r", encoding="utf-8") as f:
        data = json.load(f)
        assert data["session_id"] == session.id
        assert data["summary"]["total_findings"] == 1
        assert len(data["findings"]) == 1

    with open(report_path, "r", encoding="utf-8") as f:
        md_content = f.read()
        assert "StressX Autonomous Security Assessment Report" in md_content
        assert "SQL Injection in Search" in md_content

import json
from datetime import datetime, timezone, timedelta
import pytest
from pathlib import Path

from app.models.target import Target
from app.models.session import AuditSession, SessionStatus
from app.models.finding import Finding, FindingCategory, Severity, Confidence, FindingStatus
from app.models.hypothesis import Hypothesis, HypothesisStatus
from app.models.attempt import AttackAttempt
from app.models.evidence import Evidence
from app.models.observation import Observation
from app.models.metrics import ActionRecord, AuditMetrics, AggregateMetrics
from app.evidence.redact import redact_sensitive_text, redact_dict
from app.evidence.store import EvidenceStore
from app.tools.finish_audit import FinishAuditTool


def test_secret_redaction():
    raw_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    raw_bearer = f"Bearer {raw_jwt}"
    raw_db = "postgresql://audit_admin:superSecretP@ssword123@db.internal:5432/audit_db"
    raw_aws = "AKIAIOSFODNN7EXAMPLE"
    raw_privkey = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA04m...\n-----END RSA PRIVATE KEY-----"

    text = f"User authenticated with {raw_bearer}, connected to {raw_db} and key {raw_aws}. Key block:\n{raw_privkey}"
    redacted = redact_sensitive_text(text)

    assert raw_jwt not in redacted
    assert "superSecretP@ssword123" not in redacted
    assert raw_aws not in redacted
    assert "MIIEowIBAAKCAQEA04m" not in redacted
    assert "[REDACTED" in redacted

    # Test dictionary redaction
    sensitive_dict = {
        "user": "auditor",
        "password": "Password123!",
        "token": "token-xyz-12345",
        "nested": {
            "api_key": "secret-api-key",
            "url": "http://127.0.0.1:8080/query?secret=token123"
        }
    }
    redacted_dict = redact_dict(sensitive_dict)
    assert redacted_dict["password"] == "[REDACTED]"
    assert redacted_dict["token"] == "[REDACTED]"
    assert redacted_dict["nested"]["api_key"] == "[REDACTED]"
    assert "token123" not in redacted_dict["nested"]["url"]


def test_action_logging(tmp_path):
    store = EvidenceStore(export_dir=str(tmp_path))
    audit_id = "test_audit_001"

    action1 = ActionRecord(
        audit_id=audit_id,
        step=1,
        tool="discover_http_surface",
        intent="Map endpoints",
        target="http://127.0.0.1:8088",
        method="GET",
        status_code=200,
        latency_ms=12.5,
        hypothesis_id=None,
        outcome="SUCCESS",
        success=True,
        summary="Discovered 5 endpoints with password=secret123"
    )

    action2 = ActionRecord(
        audit_id=audit_id,
        step=2,
        tool="send_http_request",
        intent="Test SQL injection",
        target="http://127.0.0.1:8088/api/search?q=' OR '1'='1",
        method="GET",
        status_code=500,
        latency_ms=25.0,
        hypothesis_id="hypo_01",
        outcome="SUCCESS",
        success=True,
        summary="SQL syntax error returned"
    )

    store.log_action(action1)
    store.log_action(action2)

    audit_dir = store.get_audit_dir(audit_id)
    actions_file = audit_dir / "actions.jsonl"
    assert actions_file.exists()

    lines = actions_file.read_text(encoding="utf-8").strip().split("\n")
    assert len(lines) == 2

    rec1 = json.loads(lines[0])
    assert rec1["audit_id"] == audit_id
    assert rec1["step"] == 1
    assert rec1["tool"] == "discover_http_surface"
    assert "secret123" not in rec1["summary"]
    assert "[REDACTED]" in rec1["summary"]

    rec2 = json.loads(lines[1])
    assert rec2["step"] == 2
    assert rec2["hypothesis_id"] == "hypo_01"
    assert rec2["status_code"] == 500


def test_metric_calculation_and_counters():
    t0 = datetime(2026, 9, 29, 10, 0, 0, tzinfo=timezone.utc)
    t1 = t0 + timedelta(seconds=42.8)

    target = Target(base_url="http://127.0.0.1:8088")
    session = AuditSession(
        target=target,
        max_steps=20,
        start_time=t0.isoformat()
    )
    session.end_time = t1.isoformat()
    session.step_count = 18
    session.context_data["discovered_endpoints"] = ["/health", "/api/users/1", "/api/search", "/api/debug"]

    # Add 3 attack attempts
    session.add_attempt(AttackAttempt(
        step=2,
        tool="send_http_request",
        target="http://127.0.0.1:8088/api/users/1",
        action_summary="Probing user endpoint for IDOR",
        response_summary="Status: 200 OK",
        result="ANOMALY_DETECTED",
        request_data={"latency_ms": 15.0}
    ))
    session.add_attempt(AttackAttempt(
        step=3,
        tool="send_http_request",
        target="http://127.0.0.1:8088/api/search?q='",
        action_summary="Testing SQL injection",
        response_summary="Status: 500 Internal Server Error",
        result="CONFIRMED",
        request_data={"latency_ms": 25.0}
    ))
    session.add_attempt(AttackAttempt(
        step=4,
        tool="send_http_request",
        target="http://127.0.0.1:8088/api/auth/login",
        action_summary="Testing authentication credentials",
        response_summary="Status: 401 Unauthorized",
        result="PROBE_RECORDED",
        request_data={"latency_ms": 20.0}
    ))

    # Add hypotheses: 2 supported, 1 rejected, 1 testing
    session.add_hypothesis(Hypothesis(
        category=FindingCategory.AUTHORIZATION,
        description="IDOR in /api/users/{id}",
        target_endpoint="/api/users/1",
        status=HypothesisStatus.SUPPORTED,
        rationale="Unauthenticated access granted"
    ))
    session.add_hypothesis(Hypothesis(
        category=FindingCategory.UNSAFE_INPUT_HANDLING,
        description="SQL injection in /api/search",
        target_endpoint="/api/search",
        status=HypothesisStatus.SUPPORTED,
        rationale="SQL error in response"
    ))
    session.add_hypothesis(Hypothesis(
        category=FindingCategory.INFORMATION_DISCLOSURE,
        description="Exposed env vars",
        target_endpoint="/health",
        status=HypothesisStatus.REJECTED,
        rationale="Clean JSON status returned"
    ))
    session.add_hypothesis(Hypothesis(
        category=FindingCategory.RESOURCE_EXHAUSTION,
        description="Denial of service via batch payload",
        target_endpoint="/api/search",
        status=HypothesisStatus.TESTING,
        rationale="Testing payload limit"
    ))

    # Add findings: 1 CONFIRMED CRITICAL, 1 LIKELY HIGH
    ev1 = Evidence(
        evidence_type="HTTP_TRANSACTION",
        description="User data leaked without auth",
        request_summary="GET /api/users/2",
        response_summary="HTTP 200 with admin profile"
    )
    session.add_evidence(ev1)
    finding1 = Finding(
        title="BAPI / IDOR Access",
        category=FindingCategory.AUTHORIZATION,
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        status=FindingStatus.CONFIRMED,
        description="Arbitrary user profiles readable",
        impact="Full account compromise",
        affected_endpoint="/api/users/1",
        evidence=[ev1]
    )
    session.add_finding(finding1)

    ev2 = Evidence(
        evidence_type="HTTP_TRANSACTION",
        description="SQL Error detected",
        request_summary="GET /api/search?q='",
        response_summary="HTTP 500 SQLite syntax error"
    )
    session.add_evidence(ev2)
    finding2 = Finding(
        title="SQL Injection Vulnerability",
        category=FindingCategory.UNSAFE_INPUT_HANDLING,
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        status=FindingStatus.LIKELY,
        description="Unsanitized query parameter",
        impact="Database read/write",
        affected_endpoint="/api/search",
        evidence=[ev2]
    )
    session.add_finding(finding2)

    # Add observations: 4 success, 1 failure
    session.add_observation(Observation(step=1, tool="discover_http_surface", target="/", summary="Discovered routes", raw_data={"endpoints": ["/health"]}))
    session.add_observation(Observation(step=2, tool="send_http_request", target="/api/users/1", summary="Got user 1", raw_data={"status_code": 200}))
    session.add_observation(Observation(step=3, tool="send_http_request", target="/api/search", summary="Got 500 error", raw_data={"status_code": 500}))
    session.add_observation(Observation(step=4, tool="send_http_request", target="/api/auth/login", summary="Execution Error: timed out", raw_data={"error": "timeout"}))

    metrics = AuditMetrics.calculate_from_session(session, project_type="PYTHON")

    # Verifications
    assert metrics.duration_seconds == 42.8
    assert metrics.total_steps == 18
    assert metrics.total_http_requests == 3
    assert metrics.total_endpoints_discovered == 4
    assert metrics.total_hypotheses == 4
    assert metrics.hypotheses_supported == 2
    assert metrics.hypotheses_rejected == 1
    assert metrics.hypotheses_inconclusive == 1

    assert metrics.total_findings == 2
    assert metrics.confirmed_findings == 1
    assert metrics.likely_findings == 1
    assert metrics.critical_findings == 1
    assert metrics.high_findings == 1
    assert metrics.medium_findings == 0

    assert metrics.evidence_records == 2
    assert metrics.tool_calls == 4
    assert metrics.successful_tool_calls == 3
    assert metrics.failed_tool_calls == 1

    assert metrics.authorization_tests >= 1
    assert metrics.injection_tests >= 1
    assert metrics.authentication_tests >= 1
    assert metrics.total_http_latency_ms == 60.0
    assert metrics.average_http_latency_ms == 20.0


def test_persistent_report_creation(tmp_path):
    store = EvidenceStore(export_dir=str(tmp_path))
    target = Target(base_url="http://127.0.0.1:8088")
    session = AuditSession(target=target)
    session.complete(SessionStatus.COMPLETED)

    audit_dir, metrics = store.save_audit_dossier(session, project_type="SPRING_BOOT_MAVEN")

    assert audit_dir.exists()
    assert (audit_dir / "metrics.json").exists()
    assert (audit_dir / "findings.json").exists()
    assert (audit_dir / "evidence.json").exists()
    assert (audit_dir / "report.json").exists()
    assert (audit_dir / "report.md").exists()

    # Verify metrics.json
    metrics_data = json.loads((audit_dir / "metrics.json").read_text(encoding="utf-8"))
    assert metrics_data["audit_id"] == session.id
    assert metrics_data["project_type"] == "SPRING_BOOT_MAVEN"
    assert "duration_seconds" in metrics_data

    # Verify report.json
    report_data = json.loads((audit_dir / "report.json").read_text(encoding="utf-8"))
    assert report_data["audit_id"] == session.id
    assert "metrics" in report_data


def test_aggregate_metrics_and_idempotence(tmp_path):
    store = EvidenceStore(export_dir=str(tmp_path))

    target = Target(base_url="http://127.0.0.1:8088")
    session1 = AuditSession(target=target)
    session1.step_count = 5
    session1.complete(SessionStatus.COMPLETED)

    # Save session 1
    _, m1 = store.save_audit_dossier(session1)
    agg1 = store.get_aggregate_metrics()
    assert agg1.total_audits == 1
    assert agg1.total_steps == 5

    # Re-save session 1 (simulate rerun/idempotency test)
    _, m1_repeat = store.save_audit_dossier(session1)
    agg1_dup = store.get_aggregate_metrics()
    assert agg1_dup.total_audits == 1  # Must not double-count
    assert agg1_dup.total_steps == 5

    # Save distinct session 2
    session2 = AuditSession(target=Target(base_url="http://127.0.0.1:8089"))
    session2.step_count = 10
    session2.complete(SessionStatus.COMPLETED)

    _, m2 = store.save_audit_dossier(session2)
    agg2 = store.get_aggregate_metrics()
    assert agg2.total_audits == 2
    assert agg2.total_steps == 15
    assert agg2.total_targets == 2


@pytest.mark.asyncio
async def test_finish_audit_tool_metrics_summary():
    tool = FinishAuditTool()
    target = Target(base_url="http://127.0.0.1:8088")
    session = AuditSession(target=target)
    session.step_count = 12
    session.context_data["discovered_endpoints"] = ["/health", "/api/test"]

    obs = await tool.execute(session, summary="Evaluation concluded successfully")
    assert obs.tool == "finish_audit"
    assert "Audit completed against http://127.0.0.1:8088" in obs.summary

    # Ensure key insights contain formatted concise summary fields
    insight_text = "\n".join(obs.key_insights)
    assert "Duration:" in insight_text
    assert "Steps: 12" in insight_text
    assert "Endpoints discovered: 2" in insight_text
    assert "Confirmed findings: 0" in insight_text
    assert f"Report location: audit_reports/{session.id}/" in insight_text

    # Raw data must contain full metrics dict
    assert obs.raw_data["audit_id"] == session.id
    assert obs.raw_data["total_steps"] == 12

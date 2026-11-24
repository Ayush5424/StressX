import pytest
import json
import tempfile
from pathlib import Path
from fastapi.testclient import TestClient

from app.api.server import api_app
from app.api.manager import AuditManager, AUDIT_MANAGER
from app.models.config import AuditConfig, TargetComplexity, ComplexityLevel, AuditStatus


@pytest.fixture
def client():
    return TestClient(api_app)


def test_audit_manager_user_isolation():
    """Verify AuditManager enforces strict multi-tenant boundary checks."""
    with tempfile.TemporaryDirectory() as tmpdir:
        manager = AuditManager(reports_dir=tmpdir)

        # Alice creates an audit
        alice_cfg = manager.create_audit(
            target_url="http://example.com/api",
            audit_name="Alice Pentest",
            user_id="user_alice"
        )
        assert alice_cfg.user_id == "user_alice"

        # Bob creates an audit
        bob_cfg = manager.create_audit(
            target_url="http://example.com/service",
            audit_name="Bob Pentest",
            user_id="user_bob"
        )
        assert bob_cfg.user_id == "user_bob"

        # Alice can access her own audit
        cfg = manager.get_audit(alice_cfg.audit_id, user_id="user_alice")
        assert cfg is not None
        assert cfg.audit_id == alice_cfg.audit_id

        # Bob cannot access Alice's audit (raises PermissionError)
        with pytest.raises(PermissionError):
            manager.get_audit(alice_cfg.audit_id, user_id="user_bob")

        # Alice cannot access Bob's audit
        with pytest.raises(PermissionError):
            manager.get_audit(bob_cfg.audit_id, user_id="user_alice")

        # Bob cannot access Alice's surface or activity
        with pytest.raises(PermissionError):
            manager.get_surface(alice_cfg.audit_id, user_id="user_bob")

        with pytest.raises(PermissionError):
            manager.get_activity(alice_cfg.audit_id, user_id="user_bob")

        with pytest.raises(PermissionError):
            manager.get_findings(alice_cfg.audit_id, user_id="user_bob")

        # list_reports filters by user
        alice_reports = manager.list_reports(user_id="user_alice")
        assert len(alice_reports) == 1
        assert alice_reports[0]["audit_id"] == alice_cfg.audit_id

        bob_reports = manager.list_reports(user_id="user_bob")
        assert len(bob_reports) == 1
        assert bob_reports[0]["audit_id"] == bob_cfg.audit_id

        # Stats are scoped per user
        alice_stats = manager.get_global_stats(user_id="user_alice")
        assert alice_stats["total_audits"] == 1

        charlie_stats = manager.get_global_stats(user_id="user_charlie")
        assert charlie_stats["total_audits"] == 0


def test_persisted_report_tenant_isolation():
    """Verify that persisted report files on disk cannot be read by another user."""
    with tempfile.TemporaryDirectory() as tmpdir:
        manager = AuditManager(reports_dir=tmpdir)
        audit_dir = Path(tmpdir) / "audit_secret_123"
        audit_dir.mkdir(parents=True)

        # Write report.json belonging to Alice
        report_data = {
            "audit_id": "audit_secret_123",
            "user_id": "user_alice",
            "audit_name": "Classified Assessment",
            "target_name": "Core Banking API",
            "status": "COMPLETED",
            "findings_count": 3
        }
        (audit_dir / "report.json").write_text(json.dumps(report_data))
        (audit_dir / "findings.json").write_text(json.dumps([{"title": "SQL Injection", "severity": "HIGH"}]))

        # Alice can fetch report details
        details = manager.get_report_details("audit_secret_123", user_id="user_alice")
        assert details["audit_id"] == "audit_secret_123"
        assert details["user_id"] == "user_alice"

        # Bob cannot fetch Alice's report details (403 PermissionError)
        with pytest.raises(PermissionError):
            manager.get_report_details("audit_secret_123", user_id="user_bob")

        # Findings isolation check
        alice_findings = manager.get_findings("audit_secret_123", user_id="user_alice")
        assert len(alice_findings) == 1

        with pytest.raises(PermissionError):
            manager.get_findings("audit_secret_123", user_id="user_bob")


def test_api_endpoints_tenant_isolation(client):
    """Verify HTTP API enforces multi-tenant boundaries via X-User-ID header and query params."""
    # Alice creates an audit
    res_alice = client.post(
        "/api/audits",
        headers={"X-User-ID": "user_alice_http"},
        json={
            "target_url": "https://service.internal/api",
            "audit_name": "Alice Private Audit"
        }
    )
    assert res_alice.status_code == 200
    alice_audit_id = res_alice.json()["audit_id"]
    assert res_alice.json()["user_id"] == "user_alice_http"

    # Alice can read her audit
    res_get_alice = client.get(
        f"/api/audits/{alice_audit_id}",
        headers={"X-User-ID": "user_alice_http"}
    )
    assert res_get_alice.status_code == 200
    assert res_get_alice.json()["audit_id"] == alice_audit_id

    # Bob attempts to read Alice's audit -> 403 Forbidden
    res_get_bob = client.get(
        f"/api/audits/{alice_audit_id}",
        headers={"X-User-ID": "user_bob_http"}
    )
    assert res_get_bob.status_code == 403

    # Bob attempts to access Alice's surface -> 403 Forbidden
    res_surface_bob = client.get(
        f"/api/audits/{alice_audit_id}/surface",
        headers={"X-User-ID": "user_bob_http"}
    )
    assert res_surface_bob.status_code == 403

    # Bob attempts to access Alice's activity -> 403 Forbidden
    res_activity_bob = client.get(
        f"/api/audits/{alice_audit_id}/activity",
        headers={"X-User-ID": "user_bob_http"}
    )
    assert res_activity_bob.status_code == 403

    # Bob attempts to access Alice's findings -> 403 Forbidden
    res_findings_bob = client.get(
        f"/api/audits/{alice_audit_id}/findings",
        headers={"X-User-ID": "user_bob_http"}
    )
    assert res_findings_bob.status_code == 403

    # Bob attempts to stop Alice's audit -> 403 Forbidden
    res_stop_bob = client.post(
        f"/api/audits/{alice_audit_id}/stop",
        headers={"X-User-ID": "user_bob_http"}
    )
    assert res_stop_bob.status_code == 403

    # Reports listing is isolated
    res_reports_bob = client.get(
        "/api/reports",
        headers={"X-User-ID": "user_bob_http"}
    )
    assert res_reports_bob.status_code == 200
    bob_reports = res_reports_bob.json()
    assert all(r["audit_id"] != alice_audit_id for r in bob_reports)

    # Bob's stats show 0 audits
    res_stats_bob = client.get(
        "/api/stats",
        headers={"X-User-ID": "user_bob_http"}
    )
    assert res_stats_bob.status_code == 200
    assert res_stats_bob.json()["total_audits"] == 0

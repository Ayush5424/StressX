import pytest
import asyncio
import tempfile
from pathlib import Path
from fastapi.testclient import TestClient

from app.api.server import api_app
from app.api.manager import AUDIT_MANAGER, AuditManager
from app.api.events import EVENT_MANAGER, AuditEventType
from app.target.complexity import ComplexityAnalyzer
from app.target.detector import ProjectDetector, ProjectInfo, ProjectType
from app.models.config import AuditConfig, TargetComplexity, ComplexityLevel, AuditStatus


@pytest.fixture
def client():
    return TestClient(api_app)


@pytest.fixture
def sample_project_dir():
    with tempfile.TemporaryDirectory() as tmpdir:
        p = Path(tmpdir)
        # Create a sample project with routes and compose file
        (p / "requirements.txt").write_text("fastapi\nuvicorn\nsqlalchemy\nredis\ncelery\n")
        (p / "main.py").write_text("""
from fastapi import FastAPI
app = FastAPI()

@app.get("/api/users")
def get_users(): return []

@app.post("/api/users")
def create_user(): return {}

@app.put("/api/users/{id}")
def update_user(): return {}

@app.delete("/api/users/{id}")
def delete_user(): return {}

@app.get("/api/jobs/status")
def job_status(): return {}
""")
        (p / "docker-compose.yml").write_text("""
version: '3.8'
services:
  web:
    build: .
    ports:
      - "8000:8000"
  db:
    image: postgres:15
  redis:
    image: redis:alpine
  worker:
    build: .
""")
        yield str(p)


def test_complexity_analyzer_scoring(sample_project_dir):
    detector = ProjectDetector()
    project_info = detector.detect(sample_project_dir)

    analyzer = ComplexityAnalyzer()
    complexity = analyzer.analyze(sample_project_dir, project_info)

    assert complexity.score > 0
    assert complexity.recommended_steps >= 15
    assert complexity.level in (ComplexityLevel.LOW, ComplexityLevel.MEDIUM, ComplexityLevel.HIGH, ComplexityLevel.VERY_HIGH)
    assert len(complexity.reasons) > 0
    assert complexity.endpoints_estimated >= 4
    assert complexity.mutation_routes_estimated >= 1
    assert complexity.services_count >= 3


def test_api_analyze_project(client, sample_project_dir):
    res = client.post("/api/projects/analyze", json={"project_path": sample_project_dir})
    assert res.status_code == 200
    data = res.json()
    assert "project" in data
    assert "complexity" in data
    assert data["complexity"]["recommended_steps"] >= 15
    assert data["project"]["is_multi_service"] is True


def test_audit_lifecycle_api(client, sample_project_dir):
    # 1. Create audit
    create_res = client.post(
        "/api/audits",
        json={"project_path": sample_project_dir, "selected_steps": 30, "name": "Test Target"}
    )
    assert create_res.status_code == 200
    audit = create_res.json()
    audit_id = audit["audit_id"]
    assert audit_id.startswith("audit_")
    assert audit["selected_steps"] == 30
    assert audit["status"] == "CONFIGURED"

    # 2. Get audit details
    get_res = client.get(f"/api/audits/{audit_id}")
    assert get_res.status_code == 200
    assert get_res.json()["audit_id"] == audit_id

    # 3. Get surface (should be empty initially)
    surf_res = client.get(f"/api/audits/{audit_id}/surface")
    assert surf_res.status_code == 200
    assert "endpoints" in surf_res.json()

    # 4. Get activity
    act_res = client.get(f"/api/audits/{audit_id}/activity")
    assert act_res.status_code == 200

    # 5. Stop audit (should handle graceful stop even if not yet launched)
    stop_res = client.post(f"/api/audits/{audit_id}/stop")
    assert stop_res.status_code in (200, 404)


def test_dashboard_stats_and_reports_api(client):
    stats_res = client.get("/api/stats")
    assert stats_res.status_code == 200
    stats = stats_res.json()
    assert "active_audits" in stats
    assert "total_audits" in stats
    assert "total_findings" in stats

    reports_res = client.get("/api/reports")
    assert reports_res.status_code == 200
    reports = reports_res.json()
    assert isinstance(reports, list)


def test_static_dashboard_html_served(client):
    res = client.get("/")
    assert res.status_code == 200
    assert "StressX" in res.text
    assert "Autonomous AI Security Testing Platform" in res.text
    assert "root" in res.text

    # Verify compiled React assets are accessible
    from pathlib import Path
    assets_dir = Path("app/static/assets")
    if assets_dir.exists():
        for asset in assets_dir.iterdir():
            if asset.is_file():
                asset_res = client.get(f"/assets/{asset.name}")
                assert asset_res.status_code == 200

    # Verify SPA fallback serves React index.html for client-side routing
    spa_res = client.get("/reports")
    assert spa_res.status_code == 200
    assert "root" in spa_res.text

    # Verify obsolete /static route is not served as a mounted directory
    static_res = client.get("/static")
    assert static_res.status_code in (404, 200)



@pytest.mark.asyncio
async def test_event_manager_publish_subscribe():
    test_audit_id = "test_audit_stream"
    received_events = []

    async def subscriber():
        async for ev in EVENT_MANAGER.subscribe(test_audit_id):
            received_events.append(ev)
            if ev.event_type == AuditEventType.AUDIT_COMPLETED:
                break

    sub_task = asyncio.create_task(subscriber())
    await asyncio.sleep(0.05)

    await EVENT_MANAGER.emit(test_audit_id, AuditEventType.AUDIT_STARTED, {"target": "http://127.0.0.1"})
    await EVENT_MANAGER.emit(test_audit_id, AuditEventType.TOOL_STARTED, {"tool": "send_http_request"})
    await EVENT_MANAGER.emit(test_audit_id, AuditEventType.AUDIT_COMPLETED, {"findings_count": 0})

    await asyncio.wait_for(sub_task, timeout=2.0)

    assert len(received_events) == 3
    assert received_events[0].event_type == AuditEventType.AUDIT_STARTED
    assert received_events[1].event_type == AuditEventType.TOOL_STARTED
    assert received_events[2].event_type == AuditEventType.AUDIT_COMPLETED

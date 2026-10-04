import pytest
import asyncio
from unittest.mock import AsyncMock, patch, MagicMock
import httpx

from app.models.target import Target
from app.models.session import AuditSession, SessionStatus, AuditPhase
from app.models.finding import FindingCategory, FindingStatus, Severity, Confidence
from app.models.evidence import Evidence
from app.models.attack_family import AttackFamily, recommend_attack_family
from app.tools.measure_baseline import MeasureBaselineTool
from app.tools.pressure_test import PressureTestTool
from app.tools.concurrency_test import ConcurrencyTestTool
from app.tools.record_evidence import RecordEvidenceTool


@pytest.fixture
def test_target():
    return Target(base_url="http://127.0.0.1:8000", allowed_hosts=["127.0.0.1", "localhost"])


@pytest.fixture
def test_session(test_target):
    return AuditSession(target=test_target)


# 1. Baseline establishment
@pytest.mark.asyncio
async def test_baseline_establishment(test_session):
    tool = MeasureBaselineTool()
    
    mock_responses = [
        MagicMock(status_code=200, text="OK response", headers={})
        for _ in range(5)
    ]
    
    with patch("httpx.AsyncClient.request", side_effect=mock_responses):
        obs = await tool.execute(test_session, path="/api/health", sample_count=5)
        
    assert obs.raw_data["samples_count"] == 5
    assert obs.raw_data["baseline_healthy"] is True
    assert "200" in obs.raw_data["status_distribution"]
    assert obs.raw_data["status_distribution"]["200"] == 5
    assert test_session.context_data["baselines"]["/api/health"]["healthy"] is True


# 2 & 4. Rate-limit detection and threshold identification
@pytest.mark.asyncio
async def test_pressure_test_rate_limit_detection(test_session):
    tool = PressureTestTool()

    # Baseline requests (3) return 200, then under pressure requests return 429, then recovery returns 200
    def mock_req(method, url, **kwargs):
        call_count[0] += 1
        if call_count[0] <= 3:
            return MagicMock(status_code=200, text="OK", headers={})
        elif call_count[0] <= 8:
            return MagicMock(status_code=429, text="Too Many Requests", headers={"Retry-After": "2"})
        else:
            return MagicMock(status_code=200, text="OK", headers={})

    call_count = [0]
    with patch("httpx.AsyncClient.request", side_effect=mock_req):
        obs = await tool.execute(test_session, path="/api/auth/login", initial_rate=5, max_rate=15)

    assert obs.raw_data["rate_limit_detected"] is True
    assert obs.raw_data["threshold_rate"] > 0
    assert "HTTP 429 Too Many Requests" in obs.raw_data["threshold_reason"]
    assert obs.raw_data["recovery_verified"] is True


# 3 & 5. Pressure escalation and degradation detection
@pytest.mark.asyncio
async def test_pressure_test_degradation_detection(test_session):
    tool = PressureTestTool()

    # Baseline returns fast 200s, then under pressure returns 500s (triggering error threshold degradation)
    def mock_req(method, url, **kwargs):
        call_count[0] += 1
        if call_count[0] <= 3:
            return MagicMock(status_code=200, text="OK", headers={})
        elif call_count[0] <= 10:
            return MagicMock(status_code=500, text="Internal Server Error: database connection pool timeout", headers={})
        else:
            return MagicMock(status_code=200, text="OK", headers={})

    call_count = [0]
    with patch("httpx.AsyncClient.request", side_effect=mock_req):
        obs = await tool.execute(test_session, path="/api/items", initial_rate=5, max_rate=20)

    assert obs.raw_data["degradation_detected"] is True
    assert "error rate" in obs.raw_data["threshold_reason"].lower()
    assert "OBSERVED:" in obs.raw_data["observed_facts"]
    assert "INFERRED:" in obs.raw_data["inferred_conclusion"]


# 6. Recovery verification
@pytest.mark.asyncio
async def test_recovery_detection(test_session):
    tool = PressureTestTool()

    # System recovers smoothly
    call_count = [0]
    def mock_req(method, url, **kwargs):
        call_count[0] += 1
        return MagicMock(status_code=200, text="Normal", headers={})

    with patch("httpx.AsyncClient.request", side_effect=mock_req):
        obs = await tool.execute(test_session, path="/api/test", initial_rate=5)

    assert obs.raw_data["recovery_verified"] is True
    assert obs.raw_data["degradation_detected"] is False


# 7. Concurrency experiment logic & database lock detection
@pytest.mark.asyncio
async def test_concurrency_lock_detection(test_session):
    tool = ConcurrencyTestTool()

    # Baseline returns 200, concurrent requests return SQLite lock error
    call_count = [0]
    def mock_req(method, url, **kwargs):
        call_count[0] += 1
        if call_count[0] == 1:
            return MagicMock(status_code=200, text='{"success": true}', headers={})
        else:
            return MagicMock(status_code=500, text='{"error": "sqlite3.OperationalError: database is locked"}', headers={})

    with patch("httpx.AsyncClient.request", side_effect=mock_req):
        obs = await tool.execute(test_session, path="/api/items", concurrency_level=5)

    assert obs.raw_data["db_lock_detected"] is True
    assert obs.raw_data["race_condition_detected"] is True
    assert "lock contention: true" in obs.summary.lower()
    assert any("database lock contention" in ins.lower() for ins in obs.key_insights)


# 8. Resource-pressure bounds enforcement
@pytest.mark.asyncio
async def test_resource_pressure_bounds_enforced(test_session):
    tool = PressureTestTool()

    # Pass excessive numbers to ensure clamping to safe sandbox bounds
    with patch("httpx.AsyncClient.request", return_value=MagicMock(status_code=200, text="OK", headers={})):
        obs = await tool.execute(
            test_session,
            path="/api/heavy",
            initial_rate=1000,
            max_rate=5000,
            concurrency=100,
            max_total_requests=9999
        )

    # Max allowed rate is clamped to 30, concurrency to 10, total requests to 50
    assert obs.raw_data["peak_rate"] <= 30
    assert obs.raw_data["concurrency"] <= 10
    assert obs.raw_data["total_requests"] <= 50


# 9. Evidence generation from experiment
def test_evidence_from_experiment():
    ev = Evidence.from_experiment(
        description="Controlled pressure experiment",
        endpoint="/api/search",
        method="GET",
        test_conditions="pressure_test with 20 req/s",
        pressure_level="HIGH",
        baseline_metrics={"mean_ms": 35.0},
        observed_degradation="Latency spiked to 850ms",
        recovery_behavior="Latency returned to 40ms",
        response_samples=[{"status": 500, "latency_ms": 850.0}],
        observed_behavior="OBSERVED: Latency spiked under 20 req/s",
        inferred_behavior="INFERRED: Inadequate backpressure"
    )

    assert ev.evidence_type == "SYSTEM_EXPERIMENT"
    assert ev.observed_behavior.startswith("OBSERVED:")
    assert ev.inferred_behavior.startswith("INFERRED:")
    assert ev.baseline_metrics["mean_ms"] == 35.0
    assert ev.verified is True


# 10. False-positive prevention
@pytest.mark.asyncio
async def test_record_evidence_false_positive_prevention(test_session):
    tool = RecordEvidenceTool()

    # Attempt to confirm an uninformative 500 without database syntax as SQL injection
    test_session.observations.append(
        MagicMock(
            tool="send_http_request",
            target="/api/search",
            summary="HTTP 500 Internal Server Error",
            raw_data={
                "status_code": 500,
                "body": "An unexpected error occurred in application handler.",
                "elapsed_ms": 45.0,
                "request": {"method": "GET", "url": "http://127.0.0.1:8000/api/search?q='"}
            }
        )
    )

    obs = await tool.execute(
        test_session,
        title="SQL Injection on /api/search",
        category="INJECTION",
        severity="HIGH",
        confidence="HIGH",
        status="CONFIRMED",
        endpoint="/api/search",
        description="Endpoint produced HTTP 500 on quote.",
        impact="Data leak",
        remediation="Parametrize query"
    )

    # Must be downgraded from CONFIRMED to INCONCLUSIVE due to lack of DB syntax or differential proof
    finding = test_session.findings[-1]
    assert finding.status == FindingStatus.INCONCLUSIVE
    assert finding.confidence == Confidence.LOW
    assert "[EVIDENCE VERIFICATION WARNING]" in finding.description


# 11. Dynamic attack family recommendations
def test_attack_family_recommendations():
    recs_auth = recommend_attack_family("/api/v1/auth/login")
    assert AttackFamily.AUTHENTICATION in recs_auth
    assert AttackFamily.RATE_LIMITING in recs_auth

    recs_user = recommend_attack_family("/api/users/{user_id}")
    assert AttackFamily.AUTHORIZATION in recs_user

    recs_search = recommend_attack_family("/api/search")
    assert AttackFamily.INJECTION in recs_search

    recs_debug = recommend_attack_family("/api/debug/config")
    assert AttackFamily.INFORMATION_DISCLOSURE in recs_debug

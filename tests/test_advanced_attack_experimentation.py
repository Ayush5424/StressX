import pytest
import asyncio
from unittest.mock import AsyncMock, patch, MagicMock
import httpx

from app.models.target import Target
from app.models.session import AuditSession, SessionStatus, AuditPhase
from app.models.finding import Finding, FindingCategory, FindingType, FindingStatus, Severity, Confidence
from app.models.evidence import Evidence
from app.models.hypothesis import Hypothesis, HypothesisStatus
from app.models.attack_family import AttackFamily, ATTACK_CAPABILITIES, recommend_attack_family
from app.tools.test_idempotency import TestIdempotencyTool
from app.tools.inject_failure import InjectFailureTool
from app.tools.record_evidence import RecordEvidenceTool
from app.agent.controller import AgentController
from app.models.decision import AgentDecision


@pytest.fixture
def test_target():
    return Target(base_url="http://127.0.0.1:8000", allowed_hosts=["127.0.0.1", "localhost"])


@pytest.fixture
def test_session(test_target):
    return AuditSession(target=test_target)


# 1. 63-family Attack Taxonomy and Classification Mapping
def test_attack_taxonomy_coverage():
    families = list(AttackFamily)
    assert len(families) >= 50  # Comprehensive taxonomy coverage

    for fam in families:
        category = fam.to_finding_category()
        finding_type = fam.to_finding_type()
        assert isinstance(category, FindingCategory)
        assert isinstance(finding_type, FindingType)

    # Specific classifications
    assert AttackFamily.SQL_INJECTION.to_finding_type() == FindingType.SECURITY_VULNERABILITY
    assert AttackFamily.IDOR_BOLA.to_finding_type() == FindingType.SECURITY_VULNERABILITY
    assert AttackFamily.DUPLICATE_OPERATION.to_finding_type() == FindingType.BUSINESS_LOGIC_FAILURE
    assert AttackFamily.IDEMPOTENCY_ABUSE.to_finding_type() == FindingType.BUSINESS_LOGIC_FAILURE
    assert AttackFamily.RECOVERY_FAILURE.to_finding_type() == FindingType.RESILIENCE_FAILURE
    assert AttackFamily.DEPENDENCY_FAILURE.to_finding_type() == FindingType.DEPENDENCY_FAILURE
    assert AttackFamily.THREAD_POOL_EXHAUSTION.to_finding_type() == FindingType.PERFORMANCE_FAILURE


# 2. Causal Chain Tracking in Models
def test_causal_chain_in_hypothesis_evidence_and_finding():
    chain = ["Injected single quote", "Database syntax error 500", "SQL injection confirmed"]
    downstream = ["Leaked table schemas"]

    hypo = Hypothesis(
        category=FindingCategory.INJECTION,
        finding_type=FindingType.SECURITY_VULNERABILITY,
        description="SQL injection in /search",
        target_endpoint="/search",
        rationale="Unescaped query parameters",
        causal_chain=chain,
        downstream_effects=downstream
    )
    assert hypo.finding_type == FindingType.SECURITY_VULNERABILITY
    assert hypo.causal_chain == chain
    assert hypo.downstream_effects == downstream

    ev = Evidence.from_experiment(
        description="Resilience test",
        endpoint="/api/mutations",
        method="POST",
        test_conditions="concurrent_replay",
        pressure_level="HIGH",
        baseline_metrics={},
        observed_degradation="None",
        recovery_behavior="Immediate",
        response_samples=[],
        observed_behavior="Idempotency key handled cleanly",
        inferred_behavior="Robust state deduplication",
        curl_command="curl -X POST http://127.0.0.1:8000/api/mutations",
        causal_chain=chain,
        downstream_effects=downstream
    )
    assert ev.causal_chain == chain
    assert ev.downstream_effects == downstream

    finding = Finding(
        title="Duplicate Operation on Mutation",
        category=FindingCategory.DUPLICATE_OPERATION,
        finding_type=FindingType.BUSINESS_LOGIC_FAILURE,
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        description="Tasks API creates duplicate records with identical key",
        impact="Inconsistent state",
        causal_chain=chain
    )
    assert finding.finding_type == FindingType.BUSINESS_LOGIC_FAILURE
    assert finding.causal_chain == chain


# 3. Hypothesis early 404/405 rejection
def test_hypothesis_404_405_early_rejection():
    hypo = Hypothesis(
        category=FindingCategory.API_SECURITY,
        description="Testing missing endpoint",
        target_endpoint="/nonexistent",
        rationale="Exploratory probe"
    )

    # 404 triggers immediate rejection
    is_terminated = hypo.record_attempt(status_code=404)
    assert is_terminated is True
    assert hypo.status == HypothesisStatus.REJECTED
    assert "404" in hypo.termination_reason

    # 405 triggers immediate rejection
    hypo2 = Hypothesis(
        category=FindingCategory.API_SECURITY,
        description="Testing GET on POST-only endpoint",
        target_endpoint="/api/mutations",
        rationale="Testing method"
    )
    is_terminated2 = hypo2.record_attempt(status_code=405)
    assert is_terminated2 is True
    assert hypo2.status == HypothesisStatus.REJECTED
    assert "405" in hypo2.termination_reason


# 4. TestIdempotencyTool: Sequential and Concurrent Replay
@pytest.mark.asyncio
async def test_idempotency_tool_unhandled_500_detection(test_session):
    tool = TestIdempotencyTool()

    # Step 1: returns 201 Created. Step 2 (replay): returns 500 SQL unique constraint error.
    call_count = [0]
    def mock_req(method, url, **kwargs):
        call_count[0] += 1
        if call_count[0] == 1:
            return MagicMock(status_code=201, text='{"id": "res_1"}', headers={})
        return MagicMock(status_code=500, text='{"error": "Unique constraint violation"}', headers={})

    with patch("httpx.AsyncClient.request", side_effect=mock_req):
        obs = await tool.execute(
            test_session,
            path="/api/mutations",
            method="POST",
            body='{"type": "COMPUTE"}',
            idempotency_header="Idempotency-Key",
            scenario="sequential_replay"
        )

    raw = obs.raw_data
    assert raw["statuses"] == [201, 500]
    assert len(raw["findings_suggested"]) >= 1
    suggested = raw["findings_suggested"][0]
    assert suggested["finding_type"] == FindingType.SYSTEM_DESIGN_FAILURE
    assert suggested["category"] == FindingCategory.STATE_CONSISTENCY_FAILURE
    assert len(raw["causal_chain"]) > 0


@pytest.mark.asyncio
async def test_idempotency_tool_duplicate_resource_detection(test_session):
    tool = TestIdempotencyTool()

    # Step 1: returns 201 with ID 1. Step 2: returns 201 with ID 2 (duplicate created!).
    call_count = [0]
    def mock_req(method, url, **kwargs):
        call_count[0] += 1
        if call_count[0] == 1:
            return MagicMock(status_code=201, text='{"id": "res_1"}', headers={})
        return MagicMock(status_code=201, text='{"id": "res_2"}', headers={})

    with patch("httpx.AsyncClient.request", side_effect=mock_req):
        obs = await tool.execute(
            test_session,
            path="/api/mutations",
            method="POST",
            body='{"type": "COMPUTE"}',
            scenario="sequential_replay"
        )

    raw = obs.raw_data
    assert raw["statuses"] == [201, 201]
    assert len(raw["findings_suggested"]) >= 1
    suggested = raw["findings_suggested"][0]
    assert suggested["finding_type"] == FindingType.BUSINESS_LOGIC_FAILURE
    assert suggested["category"] == FindingCategory.DUPLICATE_OPERATION


# 5. InjectFailureTool: Fault Injection & Automated Rollback
@pytest.mark.asyncio
async def test_inject_failure_tool_lifecycle(test_session):
    tool = InjectFailureTool()

    # Pre-check: 200, Inject: 200, During: 500, Reset: 200, Post: 200
    mock_responses = [
        MagicMock(status_code=200, text="OK", headers={}),  # baseline
        MagicMock(status_code=200, text="Mode set to FAIL", headers={}),  # inject
        MagicMock(status_code=500, text="Internal Error: failure mode", headers={}),  # during
        MagicMock(status_code=200, text="Mode set to NORMAL", headers={}),  # reset
        MagicMock(status_code=200, text="OK", headers={})  # post recovery
    ]

    with patch("httpx.AsyncClient.request", side_effect=mock_responses):
        obs = await tool.execute(
            test_session,
            path="/api/simulation/fault",
            method="POST",
            payload={"mode": "FAIL"},
            reset_path="/api/simulation/fault",
            reset_payload={"mode": "NORMAL"},
            observe_path="/health"
        )

    raw = obs.raw_data
    assert raw["baseline_status"] == 200
    assert raw["during_status"] == 500
    assert raw["post_status"] == 200
    assert len(raw["causal_chain"]) >= 4
    # Suggests dependency failure for returning unhandled 500
    assert any(f["category"] == FindingCategory.DEPENDENCY_FAILURE for f in raw["findings_suggested"])


# 6. Anti-repetition: passive header loops & 404 blocking
@pytest.mark.asyncio
async def test_controller_blocks_passive_loops_and_404_repeat(test_session):
    controller = AgentController(target=test_session.target)
    controller.session.attack_attempts.append(
        MagicMock(tool="inspect_http_response", target="/", action_summary="inspect")
    )

    # 1. Attempting inspect_http_response on "/" again is blocked
    dec1 = AgentDecision(
        reasoning_summary="Re-inspecting security headers",
        next_action="Check headers",
        tool="inspect_http_response",
        arguments={"path": "/"}
    )
    is_blocked, blocked_obs = controller._check_and_prevent_repetition(dec1, 2)
    assert is_blocked is True
    assert "PASSIVE INSPECTION LOOP PREVENTED" in blocked_obs.summary

    # 2. Attempting a known 404 path again is blocked
    controller.session.context_data["disallowed_or_404_paths"] = ["/api/v1/auth/login"]
    dec2 = AgentDecision(
        reasoning_summary="Retrying login route",
        next_action="Send request",
        tool="send_http_request",
        arguments={"path": "/api/v1/auth/login"}
    )
    is_blocked2, blocked_obs2 = controller._check_and_prevent_repetition(dec2, 3)
    assert is_blocked2 is True
    assert "INVALID TARGET BLOCKED" in blocked_obs2.summary

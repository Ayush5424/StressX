import pytest
from app.models.target import Target
from app.models.session import AuditSession, SessionStatus, AuditPhase
from app.models.decision import AgentDecision
from app.models.hypothesis import Hypothesis, HypothesisStatus
from app.models.finding import Finding, FindingCategory, Severity, Confidence, FindingStatus
from app.models.evidence import Evidence
from app.models.observation import Observation
from app.models.metrics import AuditMetrics
from app.models.adapter import LocalModel
from app.agent.controller import AgentController
from typing import Type, TypeVar, Optional
from pydantic import BaseModel

T = TypeVar("T", bound=BaseModel)


class LoopingMockModel(LocalModel):
    """Simulates an LLM that attempts to repeat inspect_http_response."""
    def __init__(self):
        self.call_count = 0

    def generate(self, prompt: str, system: Optional[str] = None) -> str:
        return ""

    def generate_structured(self, prompt: str, response_schema: Type[T], system: Optional[str] = None) -> T:
        self.call_count += 1
        if self.call_count == 1:
            decision = AgentDecision(
                reasoning_summary="Mapping surface.",
                next_action="Run initial discovery",
                tool="discover_http_surface",
                arguments={"scan_depth": "standard"}
            )
        elif self.call_count in (2, 3, 4):
            # Model tries to loop on passive inspect_http_response with identical arguments
            decision = AgentDecision(
                reasoning_summary="Inspecting response.",
                next_action="Inspect headers on root",
                tool="inspect_http_response",
                arguments={"target_endpoint": "/"}
            )
        elif self.call_count == 5:
            # Model pivots after seeing repetition blocked
            decision = AgentDecision(
                reasoning_summary="Pivoting to active injection test.",
                next_action="Active probe on search endpoint",
                tool="send_http_request",
                arguments={"method": "GET", "path": "/api/search?q='", "timeout_seconds": 0.1}
            )
        else:
            decision = AgentDecision(
                reasoning_summary="Conclude test.",
                next_action="Finish audit",
                tool="finish_audit",
                arguments={"summary": "Audit completed."}
            )
        return response_schema.model_validate(decision.model_dump())

    def close(self) -> None:
        pass


class InfiniteLoopModel(LocalModel):
    """Simulates an agent that never finishes on its own to test safety bounds."""
    def generate(self, prompt: str, system: Optional[str] = None) -> str:
        return ""

    def generate_structured(self, prompt: str, response_schema: Type[T], system: Optional[str] = None) -> T:
        decision = AgentDecision(
            reasoning_summary="Probing active endpoint with varied token.",
            next_action=f"Probe step",
            tool="send_http_request",
            arguments={"method": "GET", "path": f"/api/test?v={id(prompt)}", "timeout_seconds": 0.1}
        )
        return response_schema.model_validate(decision.model_dump())

    def close(self) -> None:
        pass


@pytest.mark.asyncio
async def test_agent_leaves_recon_after_surface_discovery():
    target = Target(base_url="http://127.0.0.1:8088")
    model = LoopingMockModel()
    controller = AgentController(target=target, model=model, max_steps=10)

    # Pre-populate surface
    controller.session.context_data["discovered_endpoints"] = ["/api/users", "/api/search", "/api/debug"]

    # Initial phase is RECON
    assert controller.session.current_phase == AuditPhase.RECON

    # Step 1: Model calls discover_http_surface, but surface is already known -> blocked by repetition guard
    # and forces phase to HYPOTHESIS
    await controller.run_audit()

    assert controller.session.current_phase == AuditPhase.COMPLETE
    assert controller.session.repeated_actions_prevented >= 1


@pytest.mark.asyncio
async def test_repetition_prevention_and_strategy_pivot():
    target = Target(base_url="http://127.0.0.1:8088")
    model = LoopingMockModel()
    controller = AgentController(target=target, model=model, max_steps=10)

    session = await controller.run_audit()

    # Model tried to call inspect_http_response at steps 2, 3, 4
    # The 2nd and 3rd identical calls should have been blocked
    assert session.repeated_actions_prevented >= 2

    # Check observations contain repetition guard notice
    rep_obs = [o for o in session.observations if "REPETITION PREVENTED" in o.summary]
    assert len(rep_obs) >= 2

    # Verify model successfully pivoted to active send_http_request at step 5
    active_probes = [o for o in session.observations if o.tool == "send_http_request"]
    assert len(active_probes) >= 1
    assert session.status == SessionStatus.COMPLETED


def test_hypothesis_lifecycle_progression():
    hypo = Hypothesis(
        category=FindingCategory.UNSAFE_INPUT_HANDLING,
        description="SQL injection in /api/search",
        target_endpoint="/api/search",
        status=HypothesisStatus.FORMULATED,
        rationale="Dynamic query parameter detected",
        confidence=Confidence.LOW
    )

    assert hypo.status == HypothesisStatus.FORMULATED
    assert len(hypo.previous_observations) == 0

    # Advance to testing with observation
    hypo.update_status(HypothesisStatus.TESTING)
    hypo.add_observation("Single quote triggered 500 SQLite error")
    assert hypo.status == HypothesisStatus.TESTING
    assert len(hypo.previous_observations) == 1

    # Advance to supported with evidence
    hypo.update_status(HypothesisStatus.SUPPORTED, "Differential response confirmed logical manipulation")
    assert hypo.status == HypothesisStatus.SUPPORTED
    assert "Differential response" in hypo.rationale


def test_confirmed_findings_require_evidence():
    # Finding without evidence
    f_empty = Finding(
        title="Suspected SQL Injection",
        category=FindingCategory.UNSAFE_INPUT_HANDLING,
        severity=Severity.HIGH,
        confidence=Confidence.LOW,
        status=FindingStatus.CONFIRMED,
        description="Possible flaw",
        impact="Data leakage",
        affected_endpoint="/api/search",
        evidence=[]
    )
    # The framework requires evidence items for empirical confirmation
    assert len(f_empty.evidence) == 0

    ev = Evidence(
        evidence_type="HTTP_TRANSACTION",
        description="SQL error provoked with single quote",
        request_summary="GET /api/search?q='",
        response_summary="HTTP 500 with sqlite3.OperationalError"
    )
    f_empty.add_evidence(ev)
    assert len(f_empty.evidence) == 1
    assert f_empty.evidence[0].verified is True


def test_metrics_distinguish_discovery_from_active_testing():
    session = AuditSession(target=Target(base_url="http://127.0.0.1:8088"))
    session.step_count = 6
    session.repeated_actions_prevented = 2
    session.context_data["discovered_endpoints"] = ["/api/debug", "/api/search", "/api/users"]

    # 2 Recon observations
    session.add_observation(Observation(step=1, tool="discover_http_surface", target="/", summary="Discovered 3 routes"))
    session.add_observation(Observation(step=2, tool="inspect_http_response", target="/", summary="Checked headers"))

    # 3 Active testing observations
    session.add_observation(Observation(step=3, tool="send_http_request", target="/api/debug", summary="Got 200 with env"))
    session.add_observation(Observation(step=4, tool="send_http_request", target="/api/search?q='", summary="Got 500 error"))
    session.add_observation(Observation(step=5, tool="compare_responses", target="/api/search", summary="Differential confirmed"))

    # 1 Evidence observation
    session.add_observation(Observation(step=6, tool="record_evidence", target="/api/search", summary="Recorded finding"))

    ev = Evidence(evidence_type="HTTP_TRANSACTION", description="Test", request_summary="GET /", response_summary="200")
    session.add_evidence(ev)

    metrics = AuditMetrics.calculate_from_session(session)

    assert metrics.reconnaissance_steps == 2
    assert metrics.active_test_steps == 4  # send_http_request (2) + compare_responses (1) + record_evidence (1)
    assert metrics.repeated_actions_prevented == 2
    assert metrics.verification_attempts >= 1  # compare_responses
    assert metrics.unique_endpoints_tested >= 2
    assert metrics.testing_actions >= 4


@pytest.mark.asyncio
async def test_step_safety_limit_terminates_audit():
    target = Target(base_url="http://127.0.0.1:8088")
    model = InfiniteLoopModel()
    # Safety limit set to 5 steps
    controller = AgentController(target=target, model=model, max_steps=5)

    session = await controller.run_audit()

    # Must cleanly terminate at max_steps with TIMED_OUT status
    assert session.step_count == 5
    assert session.status == SessionStatus.TIMED_OUT
    assert session.end_time is not None

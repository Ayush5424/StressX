import pytest
from typing import Type, TypeVar, Optional
from pydantic import BaseModel

from app.models.target import Target
from app.models.session import AuditSession, SessionStatus, AuditPhase
from app.models.decision import AgentDecision
from app.models.hypothesis import Hypothesis, HypothesisStatus
from app.models.finding import FindingCategory, FindingStatus, Severity, Confidence
from app.models.observation import Observation
from app.models.adapter import LocalModel
from app.agent.controller import AgentController
from app.tools.discover_http_surface import DiscoverHttpSurfaceTool
from app.tools.record_evidence import RecordEvidenceTool

T = TypeVar("T", bound=BaseModel)


class Stagnating500Model(LocalModel):
    """Simulates an LLM that keeps trying repeated 500 requests against the same endpoint.
    
    Tests that the controller terminates the hypothesis after max_stagnation (3)
    and forces the agent to pivot to an untested endpoint.
    """
    def __init__(self):
        self.step = 0

    def generate(self, prompt: str, system: Optional[str] = None) -> str:
        return ""

    def generate_structured(self, prompt: str, response_schema: Type[T], system: Optional[str] = None) -> T:
        self.step += 1
        if self.step == 1:
            decision = AgentDecision(
                reasoning_summary="Recon already done. Formulating hypothesis on error endpoint.",
                next_action="Probe /api/error_prone endpoint with variant 1",
                tool="send_http_request",
                arguments={"method": "GET", "path": "/api/error_prone?x=1"}
            )
        elif self.step == 2:
            decision = AgentDecision(
                reasoning_summary="Got 500 error. Trying variant 2 on same endpoint.",
                next_action="Probe /api/error_prone endpoint with variant 2",
                tool="send_http_request",
                arguments={"method": "GET", "path": "/api/error_prone?x=2"}
            )
        elif self.step == 3:
            decision = AgentDecision(
                reasoning_summary="Got 500 again. Trying variant 3 on same endpoint.",
                next_action="Probe /api/error_prone endpoint with variant 3",
                tool="send_http_request",
                arguments={"method": "GET", "path": "/api/error_prone?x=3"}
            )
        elif self.step == 4:
            # Model observes stagnation pivot prompt and switches to untested endpoint
            decision = AgentDecision(
                reasoning_summary="Hypothesis stagnated. Pivoting to untested candidate endpoint.",
                next_action="Probe /api/other_endpoint",
                tool="send_http_request",
                arguments={"method": "GET", "path": "/api/other_endpoint"}
            )
        else:
            decision = AgentDecision(
                reasoning_summary="Audit finished after surface evaluation.",
                next_action="Complete audit",
                tool="finish_audit",
                arguments={"summary": "Finished."}
            )
        return response_schema.model_validate(decision.model_dump())

    def close(self) -> None:
        pass


@pytest.mark.asyncio
async def test_repeated_500s_cause_stagnation_termination_and_pivot():
    """Verifies that repeated HTTP 500s without security proof terminate as INCONCLUSIVE and trigger a pivot."""
    target = Target(base_url="http://127.0.0.1:8088")
    model = Stagnating500Model()
    controller = AgentController(target=target, model=model, max_steps=8)

    # Discovered endpoints with a primary and alternative
    controller.session.context_data["discovered_endpoints"] = ["/api/error_prone", "/api/other_endpoint"]
    controller.session.set_phase(AuditPhase.HYPOTHESIS)

    # Intercept tool executor to return HTTP 500 with uninformative generic text
    async def mock_execute(tool_name, session, arguments):
        path = arguments.get("path", "/")
        if "error_prone" in path:
            return Observation(
                step=session.step_count,
                tool=tool_name,
                target=path,
                summary=f"HTTP GET {path} -> Status 500 in 12ms",
                key_insights=["Internal server error"],
                raw_data={"status_code": 500, "body": "Internal Server Error", "elapsed_ms": 12.0}
            )
        else:
            return Observation(
                step=session.step_count,
                tool=tool_name,
                target=path,
                summary=f"HTTP GET {path} -> Status 200 in 10ms",
                key_insights=["Endpoint accessible"],
                raw_data={"status_code": 200, "body": '{"status": "ok"}', "elapsed_ms": 10.0}
            )

    controller.tools.execute_tool = mock_execute

    session = await controller.run_audit()

    # Find the hypothesis for /api/error_prone
    error_hypos = [h for h in session.hypotheses if "/api/error_prone" in h.target_endpoint]
    assert len(error_hypos) == 1
    hypo = error_hypos[0]

    # Stagnation must have marked this hypothesis INCONCLUSIVE
    assert hypo.status == HypothesisStatus.INCONCLUSIVE
    assert hypo.is_stagnant() is True
    assert hypo.stagnation_count >= 3
    assert "Stagnation detected" in (hypo.termination_reason or "")

    # Check pivot to untested endpoint occurred
    other_hypos = [h for h in session.hypotheses if "/api/other_endpoint" in h.target_endpoint]
    assert len(other_hypos) == 1

    # Check session completed successfully
    assert session.status == SessionStatus.COMPLETED


@pytest.mark.asyncio
async def test_bare_500_or_200_cannot_confirm_finding():
    """Verifies that RecordEvidenceTool rejects confirming findings based solely on bare 500 or 200 responses."""
    session = AuditSession(target=Target(base_url="http://127.0.0.1:8088"))
    tool = RecordEvidenceTool()

    # 1. Observation has HTTP 500 with no database syntax error or secret
    session.add_observation(Observation(
        step=1,
        tool="send_http_request",
        target="/api/failing",
        summary="HTTP GET /api/failing -> 500 Internal Server Error",
        raw_data={
            "status_code": 500,
            "body": "Something went wrong",
            "request": {"method": "GET", "url": "http://127.0.0.1:8088/api/failing"}
        }
    ))

    # Agent attempts to record confirmed SQL injection finding without actual SQL syntax error in body
    obs = await tool.execute(
        session=session,
        title="Unverified SQL Injection",
        category="UNSAFE_INPUT_HANDLING",
        severity="HIGH",
        confidence="HIGH",
        status="CONFIRMED",
        endpoint="/api/failing",
        description="Endpoint threw 500 when probed",
        impact="Suspected injection",
        remediation="Parameterized queries"
    )

    # Must be downgraded to INCONCLUSIVE because bare 500 alone does not prove SQL injection
    assert len(session.findings) == 1
    finding = session.findings[0]
    assert finding.status == FindingStatus.INCONCLUSIVE
    assert finding.confidence == Confidence.LOW
    assert "EVIDENCE VERIFICATION WARNING" in finding.description
    assert "Recorded finding as INCONCLUSIVE" in obs.summary


def test_openapi_dynamic_spec_parsing():
    """Verifies dynamic extraction of routes, methods, and parameters from OpenAPI JSON."""
    raw_spec = {
        "openapi": "3.0.0",
        "info": {"title": "Test App API", "version": "1.0"},
        "paths": {
            "/api/v2/users/{id}": {
                "get": {
                    "summary": "Get User Details",
                    "parameters": [{"name": "id", "in": "path", "required": True}]
                },
                "put": {
                    "summary": "Update User",
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "properties": {"email": {"type": "string"}, "role": {"type": "string"}}
                                }
                            }
                        }
                    }
                }
            },
            "/api/v2/auth/token": {
                "post": {
                    "summary": "Generate Token",
                    "parameters": [{"name": "grant_type", "in": "query"}]
                }
            }
        }
    }

    routes, params = DiscoverHttpSurfaceTool.parse_openapi_spec(raw_spec)

    assert len(routes) == 3
    route_paths = [r["path"] for r in routes]
    assert "/api/v2/users/{id}" in route_paths
    assert "/api/v2/auth/token" in route_paths

    route_methods = [r["method"] for r in routes]
    assert "GET" in route_methods
    assert "PUT" in route_methods
    assert "POST" in route_methods

    # Verify extracted parameters
    assert "id" in params
    assert "grant_type" in params
    assert "email" in params
    assert "role" in params


def test_untested_endpoints_priority_sorting():
    """Verifies candidate endpoints are identified and prioritized logically."""
    session = AuditSession(target=Target(base_url="http://127.0.0.1:8088"))
    session.context_data["discovered_endpoints"] = [
        "/api/search",
        "/api/debug/env",
        "/api/auth/login",
        "/api/users/profile",
        "/health"
    ]
    controller = AgentController(target=session.target, model=Stagnating500Model())
    controller.session = session

    untested = controller.get_untested_endpoints()
    assert len(untested) == 5
    # Debug/env should have highest priority score (5)
    assert untested[0] == "/api/debug/env"
    # Auth/login should be next (4)
    assert untested[1] == "/api/auth/login"


def test_404_405_rejects_hypothesis_and_prompts_pivot():
    """Verifies that encountering a 404 or 405 immediately rejects the hypothesis."""
    session = AuditSession(target=Target(base_url="http://127.0.0.1:8088"))
    controller = AgentController(target=session.target, model=Stagnating500Model())
    controller.session = session
    controller.session.set_phase(AuditPhase.TEST)
    
    hypo = Hypothesis(
        category=FindingCategory.API_SECURITY,
        description="Test endpoint validity",
        target_endpoint="/api/nonexistent",
        status=HypothesisStatus.TESTING,
        rationale="Probe route"
    )
    session.add_hypothesis(hypo)

    decision = AgentDecision(
        reasoning_summary="Probe route",
        next_action="GET /api/nonexistent",
        tool="send_http_request",
        arguments={"path": "/api/nonexistent"}
    )
    obs = Observation(
        step=1,
        tool="send_http_request",
        target="/api/nonexistent",
        summary="HTTP GET /api/nonexistent -> 404 Not Found",
        raw_data={"status_code": 404, "body": "Not Found"}
    )

    controller._advance_phase_and_hypothesis(decision, obs)

    assert hypo.status == HypothesisStatus.REJECTED
    assert "404" in (hypo.termination_reason or "")
    assert session.current_phase == AuditPhase.HYPOTHESIS
    assert controller._repetition_warning is not None
    assert "PIVOTING" in controller._repetition_warning


@pytest.mark.asyncio
async def test_confirmed_finding_with_genuine_sql_syntax_error():
    """Verifies that RecordEvidenceTool confirms findings when real SQL dialect syntax errors are observed."""
    session = AuditSession(target=Target(base_url="http://127.0.0.1:8088"))
    tool = RecordEvidenceTool()

    session.add_observation(Observation(
        step=1,
        tool="send_http_request",
        target="/api/search?q='",
        summary="HTTP GET /api/search?q=' -> 500 SQLite Syntax Error",
        raw_data={
            "status_code": 500,
            "body": "sqlite3.OperationalError: near '': syntax error",
            "request": {"method": "GET", "url": "http://127.0.0.1:8088/api/search?q='"}
        }
    ))

    obs = await tool.execute(
        session=session,
        title="SQL Injection in Search",
        category="UNSAFE_INPUT_HANDLING",
        severity="HIGH",
        confidence="HIGH",
        status="CONFIRMED",
        endpoint="/api/search",
        description="Sqlite syntax error triggered",
        impact="Database compromise",
        remediation="Parameterized queries"
    )

    assert len(session.findings) == 1
    finding = session.findings[0]
    assert finding.status == FindingStatus.CONFIRMED
    assert finding.confidence == Confidence.HIGH
    assert "Confirmed and recorded finding" in obs.summary


@pytest.mark.asyncio
async def test_access_denied_401_403_cannot_confirm_auth_bypass():
    """Verifies that HTTP 401/403 responses cannot be recorded as confirmed authentication/authorization bypass."""
    session = AuditSession(target=Target(base_url="http://127.0.0.1:8088"))
    tool = RecordEvidenceTool()

    session.add_observation(Observation(
        step=1,
        tool="send_http_request",
        target="/api/admin/secrets",
        summary="HTTP GET /api/admin/secrets -> 403 Forbidden",
        raw_data={
            "status_code": 403,
            "body": '{"detail": "Forbidden: Admin role required"}',
            "request": {"method": "GET", "url": "http://127.0.0.1:8088/api/admin/secrets"}
        }
    ))

    obs = await tool.execute(
        session=session,
        title="Admin Access Bypass",
        category="AUTHORIZATION",
        severity="CRITICAL",
        confidence="HIGH",
        status="CONFIRMED",
        endpoint="/api/admin/secrets",
        description="Tested admin endpoint",
        impact="Privilege escalation",
        remediation="Check roles"
    )

    finding = session.findings[0]
    # Denied access is not authorization bypass -> must be downgraded to INCONCLUSIVE
    assert finding.status == FindingStatus.INCONCLUSIVE
    assert finding.confidence == Confidence.LOW
    assert "Access Denied" in finding.description


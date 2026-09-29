import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional
from pydantic import BaseModel, Field

from app.models.target import Target
from app.models.observation import Observation
from app.models.hypothesis import Hypothesis
from app.models.attempt import AttackAttempt
from app.models.finding import Finding
from app.models.evidence import Evidence


class SessionStatus(str, Enum):
    INITIALIZING = "INITIALIZING"
    RECON = "RECON"
    ATTACKING = "ATTACKING"
    VERIFYING = "VERIFYING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    TIMED_OUT = "TIMED_OUT"


class AuditPhase(str, Enum):
    RECON = "RECON"
    HYPOTHESIS = "HYPOTHESIS"
    TEST = "TEST"
    OBSERVE = "OBSERVE"
    VERIFY = "VERIFY"
    EVIDENCE = "EVIDENCE"
    COMPLETE = "COMPLETE"


def generate_session_id() -> str:
    return f"sess_{uuid.uuid4().hex[:8]}"


class AuditSession(BaseModel):
    """Encapsulates the state, history, hypotheses, and evidence of an autonomous security audit."""
    id: str = Field(default_factory=generate_session_id)
    target: Target = Field(..., description="Target definition and boundary config")
    status: SessionStatus = Field(default=SessionStatus.INITIALIZING)
    current_phase: AuditPhase = Field(default=AuditPhase.RECON, description="Active audit execution phase")
    current_hypothesis_id: Optional[str] = Field(default=None, description="ID of currently active hypothesis")
    repeated_actions_prevented: int = Field(default=0, description="Count of duplicate actions blocked by anti-repetition guard")
    sandbox_deployments: int = Field(default=0, description="Count of verified successful sandbox deployments")
    sandbox_cleanup_success: int = Field(default=0, description="Count of verified successful sandbox cleanups")
    step_count: int = Field(default=0)
    max_steps: int = Field(default=30)
    start_time: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    end_time: Optional[str] = None
    
    # State tracking
    observations: list[Observation] = Field(default_factory=list)
    hypotheses: list[Hypothesis] = Field(default_factory=list)
    attack_attempts: list[AttackAttempt] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    evidence_store: dict[str, Evidence] = Field(default_factory=dict)
    
    # Session context (discovered endpoints, tokens, cookies, state variables)
    context_data: dict[str, Any] = Field(
        default_factory=lambda: {
            "discovered_endpoints": [],
            "tokens": {},
            "cookies": {},
            "interesting_parameters": [],
            "active_user_roles": {}
        }
    )

    def model_post_init(self, __context) -> None:
        if self.target:
            if getattr(self.target, "sandbox_deployment_success", False):
                self.sandbox_deployments = 1
                self.context_data["sandbox_deployments"] = 1
            if getattr(self.target, "sandbox_cleanup_success", False):
                self.sandbox_cleanup_success = 1
                self.context_data["sandbox_cleanup_success"] = 1

    def record_sandbox_deployment(self, success: bool = True) -> None:
        self.sandbox_deployments = 1 if success else 0
        if self.target:
            self.target.sandbox_deployment_success = success
        self.context_data["sandbox_deployments"] = self.sandbox_deployments

    def record_sandbox_cleanup(self, success: bool = True) -> None:
        self.sandbox_cleanup_success = 1 if success else 0
        if self.target:
            self.target.sandbox_cleanup_success = success
        self.context_data["sandbox_cleanup_success"] = self.sandbox_cleanup_success

    def set_phase(self, phase: AuditPhase) -> None:
        self.current_phase = phase

    def get_current_hypothesis(self) -> Optional[Hypothesis]:
        if self.current_hypothesis_id:
            for h in self.hypotheses:
                if h.id == self.current_hypothesis_id:
                    return h
        for h in self.hypotheses:
            if h.status in (HypothesisStatus.FORMULATED, HypothesisStatus.TESTING):
                return h
        return None

    def add_observation(self, obs: Observation) -> None:
        self.observations.append(obs)

    def add_hypothesis(self, hypo: Hypothesis) -> None:
        self.hypotheses.append(hypo)
        self.current_hypothesis_id = hypo.id

    def add_attempt(self, attempt: AttackAttempt) -> None:
        self.attack_attempts.append(attempt)

    def add_finding(self, finding: Finding) -> None:
        # Avoid duplicate findings by title and endpoint
        for existing in self.findings:
            if existing.title == finding.title and existing.affected_endpoint == finding.affected_endpoint:
                for ev in finding.evidence:
                    existing.add_evidence(ev)
                return
        self.findings.append(finding)

    def add_evidence(self, ev: Evidence) -> None:
        self.evidence_store[ev.id] = ev

    def complete(self, status: SessionStatus = SessionStatus.COMPLETED) -> None:
        self.status = status
        self.current_phase = AuditPhase.COMPLETE
        self.end_time = datetime.now(timezone.utc).isoformat()

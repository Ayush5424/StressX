import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field
from app.models.finding import FindingCategory, FindingType, Confidence


class HypothesisStatus(str, Enum):
    FORMULATED = "FORMULATED"
    TESTING = "TESTING"
    SUPPORTED = "SUPPORTED"
    REJECTED = "REJECTED"
    INCONCLUSIVE = "INCONCLUSIVE"


def generate_hypo_id() -> str:
    return f"hypo_{uuid.uuid4().hex[:8]}"


class Hypothesis(BaseModel):
    """A reasoning hypothesis formulated by the agent based on observations.
    
    The agent forms hypotheses and tests them with tailored attacks before confirming.
    """
    id: str = Field(default_factory=generate_hypo_id)
    category: FindingCategory = Field(..., description="Vulnerability category being investigated")
    finding_type: Optional[FindingType] = Field(default=None, description="Distinguished finding classification type")
    description: str = Field(..., description="Hypothesis statement (e.g. 'IDOR in /users/{id}')")
    target_endpoint: str = Field(..., description="Endpoint under suspicion")
    status: HypothesisStatus = Field(default=HypothesisStatus.FORMULATED)
    rationale: str = Field(..., description="Reasoning that led to this hypothesis")
    attack_attempt_ids: list[str] = Field(default_factory=list, description="Associated attack attempts")
    evidence_ids: list[str] = Field(default_factory=list, description="IDs of collected evidence")
    causal_chain: list[str] = Field(default_factory=list, description="Causal sequence (e.g. ['send payload', 'duplicate state created', 'integrity breach'])")
    downstream_effects: list[str] = Field(default_factory=list, description="Observed or expected downstream system effects")
    confidence: Confidence = Field(default=Confidence.MEDIUM)
    previous_observations: list[str] = Field(default_factory=list, description="Observations gathered during testing")
    attempts_count: int = Field(default=0, description="Total attack attempts made against this hypothesis")
    stagnation_count: int = Field(default=0, description="Consecutive attempts that failed to produce new security evidence")
    max_stagnant_attempts: int = Field(default=3, description="Maximum stagnant attempts allowed before termination")
    security_question: Optional[str] = Field(default=None, description="Specific security question being tested")
    expected_signal: Optional[str] = Field(default=None, description="Observable signal that would support or refute the hypothesis")
    termination_reason: Optional[str] = Field(default=None, description="Reason hypothesis was terminated (stagnation, 404, resolved, etc.)")
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def update_status(self, new_status: HypothesisStatus, rationale_update: Optional[str] = None) -> None:
        self.status = new_status
        self.updated_at = datetime.now(timezone.utc).isoformat()
        if rationale_update:
            self.rationale += f" | Update: {rationale_update}"

    def terminate(self, new_status: HypothesisStatus, reason: str) -> None:
        """Terminates hypothesis with a specific conclusive or inconclusive reason."""
        self.status = new_status
        self.termination_reason = reason
        self.updated_at = datetime.now(timezone.utc).isoformat()
        self.rationale += f" | Terminated ({new_status.value}): {reason}"

    def record_attempt(
        self,
        attempt_id: Optional[str] = None,
        produced_evidence: bool = False,
        summary: Optional[str] = None,
        status_code: Optional[int] = None
    ) -> bool:
        """Records an attempt against this hypothesis.
        
        Returns True if the hypothesis has stagnated or hit 404/405 and should be terminated.
        """
        self.attempts_count += 1
        if self.status == HypothesisStatus.FORMULATED:
            self.status = HypothesisStatus.TESTING
        if attempt_id and attempt_id not in self.attack_attempt_ids:
            self.attack_attempt_ids.append(attempt_id)
        if summary:
            self.add_observation(summary)

        # Quick rejection of non-existent endpoints or unsupported methods
        if status_code in (404, 405):
            self.terminate(
                HypothesisStatus.REJECTED,
                f"Endpoint returned HTTP {status_code} - route not found or method not allowed"
            )
            return True
            
        if produced_evidence:
            self.stagnation_count = 0
        else:
            self.stagnation_count += 1

        self.updated_at = datetime.now(timezone.utc).isoformat()
        return self.is_stagnant()

    def is_stagnant(self) -> bool:
        """Returns True if consecutive non-productive attempts meet or exceed threshold."""
        return self.stagnation_count >= self.max_stagnant_attempts

    def add_observation(self, obs_summary: str) -> None:
        if obs_summary not in self.previous_observations:
            self.previous_observations.append(obs_summary)
            self.updated_at = datetime.now(timezone.utc).isoformat()

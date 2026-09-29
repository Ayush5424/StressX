import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field
from app.models.finding import FindingCategory, Confidence


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
    description: str = Field(..., description="Hypothesis statement (e.g. 'IDOR in /users/{id}')")
    target_endpoint: str = Field(..., description="Endpoint under suspicion")
    status: HypothesisStatus = Field(default=HypothesisStatus.FORMULATED)
    rationale: str = Field(..., description="Reasoning that led to this hypothesis")
    attack_attempt_ids: list[str] = Field(default_factory=list, description="Associated attack attempts")
    evidence_ids: list[str] = Field(default_factory=list, description="IDs of collected evidence")
    confidence: Confidence = Field(default=Confidence.MEDIUM)
    previous_observations: list[str] = Field(default_factory=list, description="Observations gathered during testing")
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def update_status(self, new_status: HypothesisStatus, rationale_update: Optional[str] = None) -> None:
        self.status = new_status
        self.updated_at = datetime.now(timezone.utc).isoformat()
        if rationale_update:
            self.rationale += f" | Update: {rationale_update}"

    def add_observation(self, obs_summary: str) -> None:
        if obs_summary not in self.previous_observations:
            self.previous_observations.append(obs_summary)
            self.updated_at = datetime.now(timezone.utc).isoformat()

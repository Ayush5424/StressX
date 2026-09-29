import uuid
from datetime import datetime, timezone
from typing import Any, Optional
from pydantic import BaseModel, Field


def generate_attempt_id() -> str:
    return f"att_{uuid.uuid4().hex[:8]}"


class AttackAttempt(BaseModel):
    """Log of a specific security probing or attack action performed against the target."""
    id: str = Field(default_factory=generate_attempt_id)
    step: int = Field(..., description="Audit loop step index")
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    tool: str = Field(..., description="Tool name used")
    target: str = Field(..., description="Specific URL/endpoint attacked")
    hypothesis_id: Optional[str] = Field(default=None, description="Hypothesis being evaluated")
    action_summary: str = Field(..., description="Description of attack payload and intent")
    request_data: dict[str, Any] = Field(default_factory=dict, description="Request parameters, headers, and body")
    response_summary: str = Field(..., description="Response status, timing, and anomalies")
    result: str = Field(..., description="Attack outcome: e.g. PROBE_RECORDED, ANOMALY_DETECTED, CONFIRMED")
    evidence_id: Optional[str] = Field(default=None, description="Linked Evidence ID if created")

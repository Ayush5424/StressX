import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field
from app.models.evidence import Evidence


class FindingStatus(str, Enum):
    CONFIRMED = "CONFIRMED"
    LIKELY = "LIKELY"
    INCONCLUSIVE = "INCONCLUSIVE"
    NOT_CONFIRMED = "NOT_CONFIRMED"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Confidence(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class FindingCategory(str, Enum):
    AUTHENTICATION = "AUTHENTICATION"
    AUTHORIZATION = "AUTHORIZATION"
    INFORMATION_DISCLOSURE = "INFORMATION_DISCLOSURE"
    UNSAFE_INPUT_HANDLING = "UNSAFE_INPUT_HANDLING"
    RESOURCE_EXHAUSTION = "RESOURCE_EXHAUSTION"
    API_SECURITY = "API_SECURITY"
    CONFIGURATION = "CONFIGURATION"


def generate_finding_id() -> str:
    return f"find_{uuid.uuid4().hex[:8]}"


class Finding(BaseModel):
    """An autonomous security finding backed by verified empirical evidence."""
    id: str = Field(default_factory=generate_finding_id)
    title: str = Field(..., description="Short descriptive title of the finding")
    category: FindingCategory = Field(..., description="Vulnerability category")
    severity: Severity = Field(..., description="Assessed impact severity")
    confidence: Confidence = Field(..., description="Confidence level based on runtime validation")
    description: str = Field(..., description="Technical explanation of the security issue")
    impact: str = Field(..., description="Consequences of potential exploitation")
    evidence: list[Evidence] = Field(default_factory=list, description="Verified runtime evidence artifacts")
    reproduction_steps: list[str] = Field(default_factory=list, description="Step-by-step reproduction instructions")
    remediation: Optional[str] = Field(default=None, description="Actionable fix recommendations")
    status: FindingStatus = Field(default=FindingStatus.CONFIRMED, description="Validation status")
    affected_endpoint: Optional[str] = Field(default=None, description="Target endpoint or URI affected")
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def add_evidence(self, item: Evidence) -> None:
        item.finding_id = self.id
        self.evidence.append(item)

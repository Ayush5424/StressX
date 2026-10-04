import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional
from pydantic import BaseModel, Field


class ComplexityLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    VERY_HIGH = "VERY_HIGH"


class AuditStatus(str, Enum):
    CONFIGURED = "CONFIGURED"
    INITIALIZING = "INITIALIZING"
    SANDBOXING = "SANDBOXING"
    RUNNING = "RUNNING"
    PAUSED = "PAUSED"
    STOPPING = "STOPPING"
    STOPPED = "STOPPED"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


def generate_audit_id() -> str:
    return f"audit_{uuid.uuid4().hex[:8]}"


class TargetComplexity(BaseModel):
    """Deterministic and explainable architectural complexity analysis profile."""
    level: ComplexityLevel = ComplexityLevel.LOW
    score: int = 0
    recommended_steps: int = 15
    min_steps: int = 5
    max_steps_allowed: int = 50
    endpoints_estimated: int = 0
    mutation_routes_estimated: int = 0
    controllers_count: int = 0
    services_count: int = 0
    workers_count: int = 0
    databases_detected: list[str] = Field(default_factory=list)
    caches_detected: list[str] = Field(default_factory=list)
    queues_detected: list[str] = Field(default_factory=list)
    has_compose: bool = False
    has_auth_surface: bool = False
    has_operator_surface: bool = False
    reasons: list[str] = Field(default_factory=list)


class AuditConfig(BaseModel):
    """Complete audit configuration establishing boundaries, step budgets, and target metadata."""
    audit_id: str = Field(default_factory=generate_audit_id)
    audit_name: str = "Security Audit"
    target_name: str = "Target Application"
    target_path: Optional[str] = None
    target_url: Optional[str] = None
    target_type: str = "UNKNOWN"
    project_name: str = "Unknown Target"
    framework: Optional[str] = None
    language: Optional[str] = None
    complexity: TargetComplexity = Field(default_factory=TargetComplexity)
    recommended_steps: int = 15
    max_steps: int = 18
    selected_steps: int = 18
    step_budget: int = 18
    steps_completed: int = 0
    status: AuditStatus = AuditStatus.CONFIGURED
    phase: Optional[str] = "RECON"
    model_name: Optional[str] = None
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    started_at: Optional[str] = None
    ended_at: Optional[str] = None
    completed_at: Optional[str] = None
    duration: Optional[str] = None
    duration_seconds: float = 0.0
    findings_count: int = 0
    highest_severity: Optional[str] = None
    severity_breakdown: dict[str, int] = Field(default_factory=dict)


from typing import Any
from pydantic import BaseModel, Field


class AgentDecision(BaseModel):
    """Structured decision produced by the autonomous security model."""
    reasoning_summary: str = Field(
        default="Autonomous security assessment reasoning.",
        description="Concise summary of reasoning based on current observations, without internal hidden CoT"
    )
    next_action: str = Field(
        default="Execute security test probe",
        description="Description of what this action intends to discover, test, or confirm"
    )
    tool: str = Field(
        default="discover_http_surface",
        description="Tool name to execute (e.g. discover_http_surface, send_http_request, compare_responses, record_evidence, finish_audit)"
    )
    arguments: dict[str, Any] = Field(
        default_factory=dict,
        description="Arguments passed to the selected tool"
    )

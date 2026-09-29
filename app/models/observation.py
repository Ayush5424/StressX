import uuid
from datetime import datetime, timezone
from typing import Any
from pydantic import BaseModel, Field


def generate_obs_id() -> str:
    return f"obs_{uuid.uuid4().hex[:8]}"


class Observation(BaseModel):
    """Structured perception of tool execution results returned to the agent reasoning loop."""
    id: str = Field(default_factory=generate_obs_id)
    step: int = Field(..., description="Audit loop step sequence number")
    tool: str = Field(..., description="Tool name that produced this observation")
    target: str = Field(..., description="Target URL or endpoint tested")
    summary: str = Field(..., description="Concise textual summary of observation")
    key_insights: list[str] = Field(default_factory=list, description="Extracted security-relevant signals")
    raw_data: dict[str, Any] = Field(default_factory=dict, description="Raw structured results from tool")
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

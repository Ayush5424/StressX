from abc import ABC, abstractmethod
from typing import Any, Optional
from app.models.session import AuditSession
from app.models.observation import Observation
from app.models.target import TargetBoundaryViolation


class BaseTool(ABC):
    """Abstract base class for all controlled security audit tools."""

    name: str
    description: str
    parameters_schema: dict[str, Any]

    def validate_target(self, session: AuditSession, url_or_path: str) -> str:
        """Validates that a URL or path is strictly permitted by the session target."""
        resolved = session.target.resolve_url(url_or_path)
        return resolved

    @abstractmethod
    async def execute(self, session: AuditSession, **kwargs: Any) -> Observation:
        """Executes the tool against the controlled target and returns a structured Observation."""
        pass

from urllib.parse import urlparse
from pydantic import BaseModel, Field


class TargetBoundaryViolation(Exception):
    """Raised when an operation attempts to target an unauthorized host or resource."""
    pass


class Target(BaseModel):
    """Represents a bounded security assessment target.
    
    Every attack attempt and tool operation must strictly validate against this target.
    """
    base_url: str = Field(..., description="Root URL of the target application (e.g. http://127.0.0.1:8088)")
    allowed_hosts: list[str] = Field(default_factory=list, description="Explicit list of permitted hosts/IPs")
    allowed_ports: list[int] = Field(default_factory=list, description="Permitted TCP ports")
    name: str = Field(default="Controlled Target", description="Friendly identifier for target")
    isolated_network: str = Field(default="stressx-sandbox-net", description="Docker network name if sandboxed")
    is_sandboxed: bool = Field(default=False, description="Whether target is running inside an isolated Docker container")
    sandbox_deployment_success: bool = Field(default=False, description="Whether Docker sandbox container was successfully deployed")
    sandbox_cleanup_success: bool = Field(default=False, description="Whether Docker sandbox container was cleanly removed")

    def model_post_init(self, __context) -> None:
        parsed = urlparse(self.base_url)
        host = parsed.hostname or "localhost"
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        
        if host not in self.allowed_hosts:
            self.allowed_hosts.append(host)
        # Always allow loopback aliases if host is loopback
        if host in ("127.0.0.1", "localhost", "0.0.0.0"):
            for alias in ("127.0.0.1", "localhost", "0.0.0.0"):
                if alias not in self.allowed_hosts:
                    self.allowed_hosts.append(alias)
                    
        if port not in self.allowed_ports:
            self.allowed_ports.append(port)

    def is_url_allowed(self, url: str) -> bool:
        """Verify that a given target URL strictly falls within allowed hosts and ports."""
        parsed = urlparse(url)
        # Relative URLs are always allowed relative to base_url
        if not parsed.netloc:
            return True
        host = parsed.hostname
        if not host:
            return False
        if host not in self.allowed_hosts:
            return False
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        if self.allowed_ports and port not in self.allowed_ports:
            return False
        return True

    def validate_or_raise(self, url: str) -> None:
        """Enforces boundary checking. Raises TargetBoundaryViolation if outside scope."""
        if not self.is_url_allowed(url):
            raise TargetBoundaryViolation(
                f"Target URL '{url}' violates assessment boundaries! Allowed hosts: {self.allowed_hosts}"
            )

    def resolve_url(self, path_or_url: str) -> str:
        """Resolves a relative path or verifies an absolute URL."""
        if path_or_url.startswith("http://") or path_or_url.startswith("https://"):
            self.validate_or_raise(path_or_url)
            return path_or_url
        clean_path = path_or_url if path_or_url.startswith("/") else f"/{path_or_url}"
        resolved = f"{self.base_url.rstrip('/')}{clean_path}"
        self.validate_or_raise(resolved)
        return resolved

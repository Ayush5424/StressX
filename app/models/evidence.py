import uuid
from datetime import datetime, timezone
from typing import Any, Optional
from pydantic import BaseModel, Field


def generate_id(prefix: str = "evi") -> str:
    return f"{prefix}_{uuid.uuid4().hex[:8]}"


class Evidence(BaseModel):
    """Runtime empirical evidence supporting a hypothesis or confirmed finding.
    
    Every finding must be backed by verifiable evidence objects containing actual HTTP exchanges.
    """
    id: str = Field(default_factory=generate_id)
    finding_id: Optional[str] = None
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    evidence_type: str = Field(..., description="e.g. HTTP_TRANSACTION, RESPONSE_DIFF, TIMING, INFORMATION_LEAK")
    description: str = Field(..., description="Explanation of what this evidence demonstrates")
    request_summary: str = Field(..., description="Summary of request method, path, headers and payload")
    response_summary: str = Field(..., description="Status code, latency, and key response characteristics")
    curl_command: Optional[str] = Field(default=None, description="Exact curl command to reproduce this evidence")
    raw_data: dict[str, Any] = Field(default_factory=dict, description="Structured request/response data payload")
    verified: bool = Field(default=True, description="Whether this evidence was verified against the running target")

    @classmethod
    def from_http_exchange(
        cls,
        description: str,
        method: str,
        url: str,
        status_code: int,
        req_headers: dict,
        req_body: Any,
        res_headers: dict,
        res_body: str,
        latency_ms: float,
        evidence_type: str = "HTTP_TRANSACTION"
    ) -> "Evidence":
        # Build reproducible curl
        header_flags = " ".join([f"-H '{k}: {v}'" for k, v in req_headers.items() if k.lower() != "content-length"])
        body_flag = f"-d '{req_body}'" if req_body else ""
        curl = f"curl -X {method} '{url}' {header_flags} {body_flag}".strip()

        # Truncate response preview to safe length
        body_preview = res_body[:500] + ("..." if len(res_body) > 500 else "") if res_body else "[empty]"

        return cls(
            evidence_type=evidence_type,
            description=description,
            request_summary=f"{method} {url} | Body: {str(req_body)[:100]}",
            response_summary=f"HTTP {status_code} ({latency_ms:.1f}ms) | Content: {body_preview}",
            curl_command=curl,
            raw_data={
                "request": {
                    "method": method,
                    "url": url,
                    "headers": req_headers,
                    "body": req_body
                },
                "response": {
                    "status_code": status_code,
                    "headers": dict(res_headers),
                    "body_snippet": body_preview,
                    "latency_ms": latency_ms
                }
            },
            verified=True
        )

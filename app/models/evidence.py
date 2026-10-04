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
    baseline_metrics: Optional[dict[str, Any]] = Field(default=None, description="Measured baseline performance metrics")
    experiment_metrics: Optional[dict[str, Any]] = Field(default=None, description="Metrics observed under experimental pressure")
    observed_behavior: Optional[str] = Field(default=None, description="Directly observed empirical facts and metrics")
    inferred_behavior: Optional[str] = Field(default=None, description="Inferred architectural or system-design conclusion")
    causal_chain: list[str] = Field(default_factory=list, description="Sequence of linked causal events leading to system weakness")
    downstream_effects: list[str] = Field(default_factory=list, description="Downstream system impacts observed or verified")
    upstream_trigger: Optional[str] = Field(default=None, description="Root failure trigger initiating this chain")

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

    @classmethod
    def from_experiment(
        cls,
        description: str,
        endpoint: str,
        method: str,
        test_conditions: str,
        pressure_level: str,
        baseline_metrics: dict[str, Any],
        observed_degradation: str,
        recovery_behavior: str,
        response_samples: list[dict[str, Any]],
        observed_behavior: str,
        inferred_behavior: str,
        curl_command: Optional[str] = None,
        evidence_type: str = "SYSTEM_EXPERIMENT",
        causal_chain: Optional[list[str]] = None,
        downstream_effects: Optional[list[str]] = None,
        upstream_trigger: Optional[str] = None
    ) -> "Evidence":
        summary_req = f"{method} {endpoint} under {pressure_level} ({test_conditions})"
        summary_res = f"Observed: {observed_degradation} | Recovery: {recovery_behavior}"
        return cls(
            evidence_type=evidence_type,
            description=description,
            request_summary=summary_req,
            response_summary=summary_res,
            curl_command=curl_command or f"curl -X {method} '{endpoint}'",
            baseline_metrics=baseline_metrics,
            experiment_metrics={
                "pressure_level": pressure_level,
                "test_conditions": test_conditions,
                "observed_degradation": observed_degradation,
                "recovery_behavior": recovery_behavior,
                "samples": response_samples[:5]
            },
            observed_behavior=observed_behavior,
            inferred_behavior=inferred_behavior,
            causal_chain=causal_chain or [],
            downstream_effects=downstream_effects or [],
            upstream_trigger=upstream_trigger,
            raw_data={
                "endpoint": endpoint,
                "method": method,
                "baseline_metrics": baseline_metrics,
                "observed_degradation": observed_degradation,
                "recovery_behavior": recovery_behavior,
                "response_samples": response_samples[:5]
            },
            verified=True
        )

import json
from typing import Any
from app.tools.base import BaseTool
from app.models.session import AuditSession
from app.models.observation import Observation


class InspectHttpResponseTool(BaseTool):
    """Tool for passive inspection of response headers, status codes, and body structures."""

    name = "inspect_http_response"
    description = (
        "Passive inspection tool for response headers and body disclosures. "
        "NOTE: Missing security headers are passive signals and do NOT constitute confirmed vulnerabilities. "
        "Do not repeatedly inspect the same endpoint; advance to active testing using send_http_request."
    )
    parameters_schema = {
        "type": "object",
        "properties": {
            "target_endpoint": {"type": "string", "description": "Endpoint to inspect"},
            "headers": {"type": "object", "description": "Response headers to evaluate"},
            "body": {"type": "string", "description": "Response body content"}
        }
    }

    SECURITY_HEADERS = [
        "content-security-policy",
        "x-frame-options",
        "x-content-type-options",
        "strict-transport-security",
        "referrer-policy"
    ]

    async def execute(self, session: AuditSession, **kwargs: Any) -> Observation:
        endpoint = kwargs.get("target_endpoint", "/")
        headers = {k.lower(): v for k, v in (kwargs.get("headers", {}) or {}).items()}
        body = kwargs.get("body", "")

        # If headers/body not provided, inspect latest observation raw_data
        if not headers and not body and session.observations:
            last_raw = session.observations[-1].raw_data
            headers = {k.lower(): v for k, v in last_raw.get("headers", {}).items()}
            body = last_raw.get("body", "")
            endpoint = last_raw.get("request", {}).get("url", endpoint)

        insights: list[str] = []
        missing_sec_headers: list[str] = []

        # Check missing security headers
        for sh in self.SECURITY_HEADERS:
            if sh not in headers:
                missing_sec_headers.append(sh)

        if missing_sec_headers:
            insights.append(f"Missing defensive HTTP headers: {', '.join(missing_sec_headers)}")

        # Check server disclosures
        if "server" in headers:
            insights.append(f"Server software disclosed: {headers['server']}")
        if "x-powered-by" in headers:
            insights.append(f"Application framework disclosed: {headers['x-powered-by']}")

        # Body analysis
        body_lower = body.lower()
        if "traceback" in body_lower or "syntaxerror" in body_lower or "operationalerror" in body_lower:
            insights.append("Response leaks internal programming traceback or database exception details.")
        if "secret" in body_lower or "password" in body_lower or "jwt_secret" in body_lower:
            insights.append("Response body matches sensitive token or secret variable name patterns.")

        summary = (
            f"Inspection of {endpoint}: {len(missing_sec_headers)} security headers missing. "
            f"{len(insights)} potential security insights flagged."
        )

        return Observation(
            step=session.step_count,
            tool=self.name,
            target=endpoint,
            summary=summary,
            key_insights=insights,
            raw_data={
                "missing_headers": missing_sec_headers,
                "server_disclosures": {k: headers.get(k) for k in ["server", "x-powered-by"] if k in headers},
                "insights": insights
            }
        )

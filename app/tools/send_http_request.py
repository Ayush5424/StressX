import time
from typing import Any, Optional
import httpx
from app.tools.base import BaseTool
from app.models.session import AuditSession
from app.models.observation import Observation
from app.models.attempt import AttackAttempt


class SendHttpRequestTool(BaseTool):
    """Tool for sending controlled HTTP requests (probes/payloads) to target endpoints."""

    name = "send_http_request"
    description = (
        "Dispatches an HTTP request (GET, POST, PUT, DELETE, etc.) with specified headers, "
        "query parameters, and payload body. Enforces target boundaries."
    )
    parameters_schema = {
        "type": "object",
        "required": ["method", "path"],
        "properties": {
            "method": {"type": "string", "enum": ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]},
            "path": {"type": "string", "description": "Relative path or permitted target URL"},
            "headers": {"type": "object", "description": "HTTP request headers"},
            "params": {"type": "object", "description": "URL query parameters"},
            "body": {"type": "string", "description": "Request body string (JSON/text/raw)"},
            "timeout_seconds": {"type": "number", "default": 8.0}
        }
    }

    async def execute(self, session: AuditSession, **kwargs: Any) -> Observation:
        method = kwargs.get("method", "GET").upper()
        path = kwargs.get("path", "/")
        headers = kwargs.get("headers", {}) or {}
        params = kwargs.get("params", {}) or {}
        body = kwargs.get("body")
        timeout_seconds = float(kwargs.get("timeout_seconds", 8.0))

        # Enforce target boundary
        resolved_url = self.validate_target(session, path)

        # Inject session token/cookies if available and not explicitly provided
        if "Authorization" not in headers and "active_token" in session.context_data:
            headers["Authorization"] = f"Bearer {session.context_data['active_token']}"

        start_time = time.perf_counter()
        insights: list[str] = []

        try:
            async with httpx.AsyncClient(timeout=timeout_seconds, follow_redirects=False) as client:
                res = await client.request(
                    method=method,
                    url=resolved_url,
                    headers=headers,
                    params=params,
                    content=body.encode("utf-8") if isinstance(body, str) else None
                )
                elapsed_ms = (time.perf_counter() - start_time) * 1000.0

                res_text = res.text
                status_code = res.status_code
                res_headers = dict(res.headers)

                # Security signal extraction
                if status_code == 500:
                    insights.append(f"HTTP 500 Internal Server Error triggered on {path}.")
                    if any(term in res_text.lower() for term in ["traceback", "exception", "sqlite", "syntax error"]):
                        insights.append("Application error reveals unhandled stack trace or database dialect error.")
                elif status_code == 200:
                    insights.append(f"Request succeeded with HTTP 200 ({elapsed_ms:.1f}ms).")
                    if any(term in res_text.lower() for term in ["password", "secret_key", "token", "private_key"]):
                        insights.append("Response content contains potential credential or secret tokens.")

                if elapsed_ms > 2000:
                    insights.append(f"Noticeable latency anomaly detected: {elapsed_ms:.1f}ms response time.")

                attempt = AttackAttempt(
                    step=session.step_count,
                    tool=self.name,
                    target=resolved_url,
                    action_summary=f"{method} {path} probe (status: {status_code})",
                    request_data={"method": method, "url": resolved_url, "headers": headers, "params": params, "body": body},
                    response_summary=f"HTTP {status_code} ({elapsed_ms:.1f}ms)",
                    result="SUCCESSFUL_PROBE" if status_code < 400 else "ANOMALY_OR_ERROR"
                )
                session.add_attempt(attempt)

                summary = (
                    f"HTTP {method} {path} -> Status {status_code} in {elapsed_ms:.1f}ms. "
                    f"Body length: {len(res_text)} bytes."
                )

                return Observation(
                    step=session.step_count,
                    tool=self.name,
                    target=resolved_url,
                    summary=summary,
                    key_insights=insights,
                    raw_data={
                        "status_code": status_code,
                        "elapsed_ms": elapsed_ms,
                        "headers": res_headers,
                        "body": res_text[:2000],
                        "request": {
                            "method": method,
                            "url": resolved_url,
                            "headers": headers,
                            "body": body
                        }
                    }
                )

        except httpx.TimeoutException:
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            insights.append(f"Request timed out after {timeout_seconds}s. Possible resource starvation or blocking loop.")
            return Observation(
                step=session.step_count,
                tool=self.name,
                target=resolved_url,
                summary=f"HTTP {method} {path} -> TIMEOUT after {timeout_seconds}s",
                key_insights=insights,
                raw_data={"error": "timeout", "elapsed_ms": elapsed_ms}
            )
        except Exception as e:
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            return Observation(
                step=session.step_count,
                tool=self.name,
                target=resolved_url,
                summary=f"HTTP {method} {path} failed: {type(e).__name__} ({str(e)})",
                key_insights=[f"Network/Connection error: {str(e)}"],
                raw_data={"error": str(e), "elapsed_ms": elapsed_ms}
            )

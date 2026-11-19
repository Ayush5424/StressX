import time
import json
from typing import Any, Optional
import httpx
from app.tools.base import BaseTool
from app.models.session import AuditSession
from app.models.observation import Observation
from app.models.attempt import AttackAttempt
from app.models.finding import FindingCategory, FindingType, Severity, Confidence


class TestInputBoundariesTool(BaseTool):
    """Tool for auditing controller input validation, parameter boundaries, and type confusion resilience."""

    name = "test_input_boundaries"
    description = (
        "Empirically tests endpoint resilience against extreme boundary conditions, negative quantities, "
        "type confusion, and oversized inputs. Detects unhandled 500 server crashes and database error disclosures."
    )
    parameters_schema = {
        "type": "object",
        "required": ["endpoint"],
        "properties": {
            "endpoint": {
                "type": "string",
                "description": "Target endpoint to audit (e.g. '/api/orders', '/api/procurements', '/api/search')"
            },
            "method": {
                "type": "string",
                "enum": ["GET", "POST", "PUT", "DELETE", "PATCH"],
                "default": "POST"
            },
            "parameter_name": {
                "type": "string",
                "description": "Optional specific parameter to fuzz (e.g. 'amount', 'quantity', 'id', 'search')"
            },
            "baseline_body": {
                "type": "string",
                "description": "Optional baseline JSON request body"
            }
        }
    }

    async def execute(self, session: AuditSession, **kwargs: Any) -> Observation:
        endpoint = kwargs.get("endpoint", "/")
        method = kwargs.get("method", "POST").upper()
        parameter_name = kwargs.get("parameter_name") or "quantity"
        baseline_body_str = kwargs.get("baseline_body") or "{}"
        active_token = session.context_data.get("active_token")

        resolved_url = self.validate_target(session, endpoint)
        headers = {"Content-Type": "application/json"}
        if active_token:
            headers["Authorization"] = f"Bearer {active_token}"

        insights: list[str] = []
        findings_suggested: list[dict[str, Any]] = []
        probe_results: list[dict[str, Any]] = []

        # Parse baseline body or initialize template
        try:
            base_payload = json.loads(baseline_body_str) if baseline_body_str else {}
        except Exception:
            base_payload = {}

        if not isinstance(base_payload, dict):
            base_payload = {}

        # Define boundary test cases
        test_cases = [
            {
                "name": "negative_numeric_boundary",
                "desc": "Negative value to test business logic bounds",
                "value": -1,
                "is_numeric": True
            },
            {
                "name": "zero_boundary",
                "desc": "Zero value boundary test",
                "value": 0,
                "is_numeric": True
            },
            {
                "name": "large_integer_overflow",
                "desc": "Very large integer to test overflow handling",
                "value": 999999999999999999,
                "is_numeric": True
            },
            {
                "name": "type_confusion_array",
                "desc": "Array type confusion where scalar is expected",
                "value": [1, 2, 3],
                "is_numeric": False
            },
            {
                "name": "oversized_string_buffer",
                "desc": "Oversized string (5,000 characters) to test input buffer limits",
                "value": "A" * 5000,
                "is_numeric": False
            },
            {
                "name": "empty_string_boundary",
                "desc": "Empty string boundary condition",
                "value": "",
                "is_numeric": False
            }
        ]

        async with httpx.AsyncClient(timeout=8.0, follow_redirects=False) as client:
            for tc in test_cases:
                # Construct mutated payload
                mutated = dict(base_payload)
                mutated[parameter_name] = tc["value"]

                start = time.perf_counter()
                try:
                    if method == "GET":
                        # For GET, send as query parameter
                        res = await client.get(resolved_url, headers=headers, params={parameter_name: str(tc["value"])[:200]})
                    else:
                        res = await client.request(
                            method=method,
                            url=resolved_url,
                            headers=headers,
                            content=json.dumps(mutated).encode("utf-8")
                        )
                    elapsed_ms = (time.perf_counter() - start) * 1000.0

                    status = res.status_code
                    body_text = res.text
                    probe_results.append({
                        "test_case": tc["name"],
                        "status_code": status,
                        "elapsed_ms": elapsed_ms,
                        "body_preview": body_text[:300]
                    })

                    # Critical evaluation:
                    # 1. Server crashed with HTTP 500 Internal Server Error
                    if status == 500:
                        has_stack_trace = any(t in body_text.lower() for t in [
                            "stacktrace", "nullpointerexception", "org.springframework",
                            "indexoutofboundsexception", "illegalargumentexception",
                            "badsqlgrammarexception", "hibernateexception", "syntax error"
                        ])
                        err_type = "Database Dialect / Syntax Disclosure" if "sql" in body_text.lower() else "Unhandled Exception Crash"
                        insights.append(
                            f"UNHANDLED SERVER 500 on {endpoint} with test '{tc['name']}': {err_type}"
                        )
                        findings_suggested.append({
                            "title": f"Unhandled Server Exception (500) on {endpoint} via {tc['name']}",
                            "category": FindingCategory.INPUT_VALIDATION,
                            "finding_type": FindingType.SECURITY_VULNERABILITY,
                            "severity": Severity.HIGH if has_stack_trace else Severity.MEDIUM,
                            "confidence": Confidence.HIGH,
                            "description": (
                                f"Endpoint '{endpoint}' crashed with HTTP 500 Internal Server Error when receiving boundary input "
                                f"for parameter '{parameter_name}' ({tc['desc']}). "
                                f"{'Detailed internal stack traces or database errors were exposed.' if has_stack_trace else 'Input validation failed to reject invalid formats gracefully with 400 Bad Request.'}"
                            ),
                            "impact": "Denial of service, unhandled application crashes, or information disclosure revealing backend implementation details.",
                            "remediation": f"Implement strict input validation annotations (e.g. @Valid, @NotNull, @Min, @Size) on '{endpoint}' controllers."
                        })
                        break  # Found confirmed crash

                    # 2. Acceptance of negative quantity/price on mutation endpoint (200/201)
                    if tc["name"] == "negative_numeric_boundary" and status in (200, 201) and parameter_name in ("quantity", "amount", "price", "count"):
                        insights.append(
                            f"BUSINESS LOGIC FLAW: Endpoint {endpoint} accepted negative value for '{parameter_name}' (HTTP {status})."
                        )
                        findings_suggested.append({
                            "title": f"Missing Input Validation: Negative Value Accepted on {endpoint}",
                            "category": FindingCategory.INPUT_VALIDATION,
                            "finding_type": FindingType.BUSINESS_LOGIC_FAILURE,
                            "severity": Severity.HIGH,
                            "confidence": Confidence.HIGH,
                            "description": (
                                f"The mutation endpoint '{endpoint}' accepts negative values for numeric parameter '{parameter_name}'. "
                                f"Server returned HTTP {status} OK instead of rejecting with 400 Bad Request."
                            ),
                            "impact": "Business logic flaw enabling negative order values, inventory corruption, or financial calculation tampering.",
                            "remediation": f"Add non-negative validation constraints (e.g. @Positive or @Min(1)) to '{parameter_name}' in backend DTOs."
                        })

                except Exception as e:
                    probe_results.append({
                        "test_case": tc["name"],
                        "error": str(e)
                    })

        # Record attempt
        attempt = AttackAttempt(
            step=session.step_count,
            tool=self.name,
            target=resolved_url,
            action_summary=f"Input Boundary & Robustness Fuzzing on {method} {endpoint} (param: {parameter_name})",
            request_data={"endpoint": endpoint, "method": method, "parameter": parameter_name, "probes": len(probe_results)},
            response_summary=f"Probes executed: {len(probe_results)}, Anomalies: {len(findings_suggested)}",
            result="VULNERABILITY_CONFIRMED" if findings_suggested else "INPUT_HANDLING_STABLE"
        )
        session.add_attempt(attempt)

        summary = (
            f"Input boundary testing on {method} {endpoint} for '{parameter_name}': "
            f"{len(probe_results)} test cases evaluated, {len(findings_suggested)} validation vulnerabilities identified."
        )

        return Observation(
            step=session.step_count,
            tool=self.name,
            target=endpoint,
            summary=summary,
            key_insights=insights or ["Input parameters are safely validated; server cleanly handles boundary conditions."],
            raw_data={
                "endpoint": endpoint,
                "method": method,
                "parameter_name": parameter_name,
                "probe_results": probe_results,
                "findings_suggested": findings_suggested
            }
        )

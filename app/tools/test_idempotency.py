import asyncio
import json
import time
import uuid
from typing import Any, Optional
import httpx

from app.tools.base import BaseTool
from app.models.session import AuditSession
from app.models.observation import Observation
from app.models.attempt import AttackAttempt
from app.models.finding import FindingCategory, FindingType, Severity, Confidence
from app.models.attack_family import AttackFamily


class TestIdempotencyTool(BaseTool):
    """Controlled tool for testing duplicate request handling, idempotency mechanisms, and replay behavior."""

    name = "test_idempotency"
    description = (
        "Tests duplicate request handling and idempotency keys (sequential and concurrent replay). "
        "Observes whether identical requests produce duplicate state, unhandled 500 database constraint exceptions, "
        "deadlocks, or proper idempotent responses."
    )
    parameters_schema = {
        "type": "object",
        "required": ["path"],
        "properties": {
            "path": {"type": "string", "description": "Target endpoint path (typically a mutation like POST/PUT)"},
            "method": {"type": "string", "enum": ["POST", "PUT", "PATCH", "DELETE"], "default": "POST"},
            "headers": {"type": "object", "description": "HTTP headers"},
            "body": {"type": "string", "description": "Request body JSON string"},
            "idempotency_header": {
                "type": "string",
                "default": "Idempotency-Key",
                "description": "Header name used for idempotency (e.g. 'Idempotency-Key', 'X-Idempotency-Key')"
            },
            "idempotency_key": {
                "type": "string",
                "description": "Optional specific idempotency key value to use; auto-generated if omitted"
            },
            "scenario": {
                "type": "string",
                "enum": ["sequential_replay", "concurrent_replay", "missing_key"],
                "default": "sequential_replay",
                "description": "Testing scenario: sequential replay, concurrent replay with identical key, or missing key"
            },
            "replay_count": {
                "type": "integer",
                "default": 2,
                "description": "Number of replay attempts (2 to 5)"
            }
        }
    }

    async def execute(self, session: AuditSession, **kwargs: Any) -> Observation:
        path = kwargs.get("path", "/")
        method = kwargs.get("method", "POST").upper()
        headers = dict(kwargs.get("headers", {}) or {})
        raw_body = kwargs.get("body")
        idempotency_header = kwargs.get("idempotency_header", "Idempotency-Key")
        scenario = kwargs.get("scenario", "sequential_replay")
        replay_count = max(2, min(int(kwargs.get("replay_count", 2)), 5))

        resolved_url = self.validate_target(session, path)

        if "Authorization" not in headers and "active_token" in session.context_data:
            headers["Authorization"] = f"Bearer {session.context_data['active_token']}"

        key_value = kwargs.get("idempotency_key") or f"idemp-{uuid.uuid4().hex[:12]}"
        if scenario != "missing_key":
            headers[idempotency_header] = key_value

        if "Content-Type" not in headers and raw_body:
            headers["Content-Type"] = "application/json"

        # Prepare payload
        payload_data = None
        if raw_body:
            try:
                payload_data = json.loads(raw_body)
            except Exception:
                payload_data = raw_body

        insights: list[str] = []
        statuses: list[int] = []
        latencies: list[float] = []
        bodies: list[str] = []
        causal_chain: list[str] = []
        downstream_effects: list[str] = []
        findings_suggested: list[dict[str, Any]] = []

        timeout = httpx.Timeout(10.0, connect=3.0)

        async def _send_one(client: httpx.AsyncClient) -> tuple[int, float, str, dict[str, str]]:
            t0 = time.perf_counter()
            try:
                resp = await client.request(
                    method=method,
                    url=resolved_url,
                    headers=headers,
                    json=payload_data if isinstance(payload_data, (dict, list)) else None,
                    content=raw_body if not isinstance(payload_data, (dict, list)) else None,
                    timeout=timeout
                )
                lat = round(time.perf_counter() - t0, 4)
                return resp.status_code, lat, resp.text, dict(resp.headers)
            except Exception as e:
                lat = round(time.perf_counter() - t0, 4)
                return 0, lat, f"ERROR: {str(e)}", {}

        async with httpx.AsyncClient(verify=False) as client:
            if scenario == "sequential_replay":
                causal_chain.append(f"Step 1: Dispatch initial {method} request with {idempotency_header}='{key_value}'")
                status1, lat1, body1, hdrs1 = await _send_one(client)
                statuses.append(status1)
                latencies.append(lat1)
                bodies.append(body1[:500])

                for i in range(1, replay_count):
                    causal_chain.append(f"Step {i+1}: Sequential replay #{i} with identical {idempotency_header}='{key_value}'")
                    st, lt, bd, hd = await _send_one(client)
                    statuses.append(st)
                    latencies.append(lt)
                    bodies.append(bd[:500])

            elif scenario == "concurrent_replay":
                causal_chain.append(f"Dispatch {replay_count} concurrent requests with identical {idempotency_header}='{key_value}'")
                tasks = [_send_one(client) for _ in range(replay_count)]
                results = await asyncio.gather(*tasks)
                for st, lt, bd, hd in results:
                    statuses.append(st)
                    latencies.append(lt)
                    bodies.append(bd[:500])

            else:  # missing_key
                causal_chain.append(f"Dispatch {method} request intentionally omitting {idempotency_header}")
                headers.pop(idempotency_header, None)
                st, lt, bd, hd = await _send_one(client)
                statuses.append(st)
                latencies.append(lt)
                bodies.append(bd[:500])

        # Analyze outcomes
        initial_status = statuses[0] if statuses else 0
        replay_statuses = statuses[1:] if len(statuses) > 1 else []

        insights.append(f"Initial status: {initial_status}, Replay statuses: {replay_statuses}")

        # Check for unhandled server error (500) on replay
        if any(s == 500 for s in replay_statuses):
            insights.append("CRITICAL: Replay triggered HTTP 500 Internal Server Error (likely unhandled database constraint or state conflict)")
            downstream_effects.append("Database unique constraint violation unhandled by application layer, returning HTTP 500 to caller")
            causal_chain.append("Replay triggered unhandled internal server error / SQL constraint failure")
            findings_suggested.append({
                "category": FindingCategory.STATE_CONSISTENCY_FAILURE,
                "finding_type": FindingType.SYSTEM_DESIGN_FAILURE,
                "attack_family": AttackFamily.IDEMPOTENCY_ABUSE.value,
                "title": f"Unhandled Server Error on Idempotent Replay at {path}",
                "severity": Severity.MEDIUM,
                "confidence": Confidence.HIGH,
                "causal_chain": list(causal_chain),
                "downstream_effects": list(downstream_effects)
            })

        # Check if identical keys create different resource IDs (duplicate state creation)
        if len(bodies) > 1 and initial_status in (200, 201) and all(s in (200, 201) for s in replay_statuses):
            # Check if IDs differ
            first_body = bodies[0]
            differing = [b for b in bodies[1:] if b != first_body]
            if differing:
                insights.append("WARNING: Replay returned 200/201 but response body differed (likely duplicate resource created despite idempotency key)")
                downstream_effects.append("Duplicate business object created in storage; idempotency key ignored or not enforced")
                causal_chain.append("Idempotency key ignored; duplicate operations executed in persistence layer")
                findings_suggested.append({
                    "category": FindingCategory.DUPLICATE_OPERATION,
                    "finding_type": FindingType.BUSINESS_LOGIC_FAILURE,
                    "attack_family": AttackFamily.DUPLICATE_OPERATION.value,
                    "title": f"Duplicate Resource Creation with Identical Idempotency Key at {path}",
                    "severity": Severity.HIGH,
                    "confidence": Confidence.HIGH,
                    "causal_chain": list(causal_chain),
                    "downstream_effects": list(downstream_effects)
                })
            else:
                insights.append("SUCCESS: Idempotency properly enforced (subsequent requests returned identical cached response)")

        # Check if missing key on required endpoint returns 400 vs 500
        if scenario == "missing_key":
            if initial_status == 500:
                insights.append("CRITICAL: Omitting idempotency key produced HTTP 500 instead of a controlled 400 Bad Request")
                downstream_effects.append("Missing idempotency header causes unhandled exception in controller/middleware")
                findings_suggested.append({
                    "category": FindingCategory.INPUT_VALIDATION,
                    "finding_type": FindingType.SYSTEM_DESIGN_FAILURE,
                    "attack_family": AttackFamily.INPUT_VALIDATION.value,
                    "title": f"Unhandled Exception on Missing Idempotency Key at {path}",
                    "severity": Severity.LOW,
                    "confidence": Confidence.HIGH,
                    "causal_chain": list(causal_chain),
                    "downstream_effects": list(downstream_effects)
                })

        summary = f"Idempotency test [{scenario}] against {method} {path}: statuses={statuses}, insights={len(insights)}"

        attempt = AttackAttempt(
            step=session.step_count,
            tool=self.name,
            target=resolved_url,
            action_summary=f"Idempotency test [{scenario}] against {method} {path}",
            request_data={
                "method": method,
                "scenario": scenario,
                "idempotency_header": idempotency_header,
                "idempotency_key": key_value,
                "replay_count": replay_count
            },
            response_summary=f"Statuses: {statuses}",
            result="FINDINGS_SUGGESTED" if findings_suggested else "IDEMPOTENT_STABLE"
        )
        session.add_attempt(attempt)

        return Observation(
            step=session.step_count,
            tool=self.name,
            target=resolved_url,
            summary=summary,
            raw_data={
                "path": path,
                "method": method,
                "scenario": scenario,
                "idempotency_header": idempotency_header,
                "idempotency_key": key_value,
                "statuses": statuses,
                "latencies": latencies,
                "insights": insights,
                "causal_chain": causal_chain,
                "downstream_effects": downstream_effects,
                "findings_suggested": findings_suggested
            }
        )

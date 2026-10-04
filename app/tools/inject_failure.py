import asyncio
import json
import time
from typing import Any, Optional
import httpx

from app.tools.base import BaseTool
from app.models.session import AuditSession
from app.models.observation import Observation
from app.models.attempt import AttackAttempt
from app.models.finding import FindingCategory, FindingType, Severity, Confidence
from app.models.attack_family import AttackFamily


class InjectFailureTool(BaseTool):
    """Tool for injecting controlled faults, testing graceful degradation, and evaluating recovery."""

    name = "inject_failure"
    description = (
        "Injects controlled faults or failure modes into designated test endpoints (e.g. simulation or worker controls), "
        "observes downstream application behavior, and verifies that the system recovers cleanly when restored. "
        "Always attempts automatic rollback to prevent persistent target corruption."
    )
    parameters_schema = {
        "type": "object",
        "required": ["path"],
        "properties": {
            "path": {"type": "string", "description": "Failure injection or simulation endpoint (e.g. '/api/simulation/fault' or '/admin/chaos')"},
            "method": {"type": "string", "enum": ["POST", "PUT", "GET"], "default": "POST"},
            "payload": {"type": "object", "description": "Payload defining the failure mode (e.g. {'mode': 'FAIL'} or {'mode': 'SLOW'})"},
            "reset_path": {"type": "string", "description": "Endpoint to reset failure state (defaults to path)"},
            "reset_payload": {"type": "object", "description": "Payload to reset failure state (e.g. {'mode': 'NORMAL'})"},
            "observe_path": {"type": "string", "default": "/health", "description": "Downstream endpoint to observe during failure"},
            "observe_method": {"type": "string", "default": "GET", "description": "Method to probe observe_path"}
        }
    }

    async def execute(self, session: AuditSession, **kwargs: Any) -> Observation:
        path = kwargs.get("path", "/")
        method = kwargs.get("method", "POST").upper()
        payload = kwargs.get("payload") or {}
        reset_path = kwargs.get("reset_path") or path
        reset_payload = kwargs.get("reset_payload") or {"mode": "NORMAL"}
        observe_path = kwargs.get("observe_path", "/health")
        observe_method = kwargs.get("observe_method", "GET").upper()

        inject_url = self.validate_target(session, path)
        reset_url = self.validate_target(session, reset_path)
        observe_url = self.validate_target(session, observe_path)

        insights: list[str] = []
        causal_chain: list[str] = []
        downstream_effects: list[str] = []
        findings_suggested: list[dict[str, Any]] = []

        timeout = httpx.Timeout(8.0, connect=3.0)

        async with httpx.AsyncClient(verify=False) as client:
            # 1. Pre-failure baseline on observe_path
            t0 = time.perf_counter()
            baseline_status = 0
            try:
                base_resp = await client.request(observe_method, observe_url, timeout=timeout)
                baseline_status = base_resp.status_code
                baseline_lat = round(time.perf_counter() - t0, 3)
            except Exception:
                baseline_lat = round(time.perf_counter() - t0, 3)

            causal_chain.append(f"Pre-check baseline {observe_method} {observe_path}: HTTP {baseline_status} ({baseline_lat}s)")

            # 2. Inject failure
            causal_chain.append(f"Inject failure via {method} {path} with payload={payload}")
            inject_status = 0
            try:
                inj_resp = await client.request(method, inject_url, json=payload, timeout=timeout)
                inject_status = inj_resp.status_code
                insights.append(f"Failure injection response: HTTP {inject_status}")
            except Exception as e:
                insights.append(f"Failure injection request error: {str(e)}")

            # 3. Observe during failure
            during_status = 0
            during_lat = 0.0
            during_body = ""
            try:
                t1 = time.perf_counter()
                dur_resp = await client.request(observe_method, observe_url, timeout=timeout)
                during_status = dur_resp.status_code
                during_lat = round(time.perf_counter() - t1, 3)
                during_body = dur_resp.text[:400]
                causal_chain.append(f"Downstream probe during failure {observe_method} {observe_path}: HTTP {during_status} ({during_lat}s)")
            except httpx.TimeoutException:
                during_lat = 8.0
                causal_chain.append(f"Downstream probe timed out during failure ({during_lat}s)")
                downstream_effects.append("Downstream service completely stalled or timed out")
            except Exception as e:
                causal_chain.append(f"Downstream probe errored: {str(e)}")

            # 4. Mandatory cleanup / reset
            causal_chain.append(f"Revert failure via POST {reset_path} with payload={reset_payload}")
            try:
                await client.request("POST", reset_url, json=reset_payload, timeout=timeout)
            except Exception as e:
                insights.append(f"Warning: Reset request failed: {str(e)}")

            # Wait briefly for recovery
            await asyncio.sleep(0.5)

            # 5. Observe post-recovery
            post_status = 0
            post_lat = 0.0
            try:
                t2 = time.perf_counter()
                post_resp = await client.request(observe_method, observe_url, timeout=timeout)
                post_status = post_resp.status_code
                post_lat = round(time.perf_counter() - t2, 3)
                causal_chain.append(f"Post-reset probe {observe_method} {observe_path}: HTTP {post_status} ({post_lat}s)")
            except Exception as e:
                causal_chain.append(f"Post-reset probe failed: {str(e)}")
                downstream_effects.append("System failed to recover after failure was disabled")

        # Evaluate resilience findings
        if baseline_status == 200 and post_status not in (200, 204):
            insights.append("CRITICAL: Application failed to recover to healthy state after fault was cleared")
            downstream_effects.append("Persistent outage after temporary fault injection")
            findings_suggested.append({
                "category": FindingCategory.RECOVERY_FAILURE,
                "finding_type": FindingType.RESILIENCE_FAILURE,
                "attack_family": AttackFamily.RECOVERY_FAILURE.value,
                "title": f"System Failed to Recover After Fault at {observe_path}",
                "severity": Severity.HIGH,
                "confidence": Confidence.HIGH,
                "causal_chain": list(causal_chain),
                "downstream_effects": list(downstream_effects)
            })

        if during_status == 500:
            insights.append("Downstream service returned HTTP 500 during fault mode (unhandled dependency or internal failure)")
            downstream_effects.append("Unhandled exception returned to caller instead of graceful degradation or circuit breaker response")
            findings_suggested.append({
                "category": FindingCategory.DEPENDENCY_FAILURE,
                "finding_type": FindingType.DEPENDENCY_FAILURE,
                "attack_family": AttackFamily.DEPENDENCY_FAILURE.value,
                "title": f"Unhandled 500 Under Fault Condition at {observe_path}",
                "severity": Severity.MEDIUM,
                "confidence": Confidence.MEDIUM,
                "causal_chain": list(causal_chain),
                "downstream_effects": list(downstream_effects)
            })

        summary = f"Failure injection test against {path}: baseline={baseline_status}, during={during_status}, post={post_status}"

        attempt = AttackAttempt(
            step=session.step_count,
            tool=self.name,
            target=inject_url,
            action_summary=f"Controlled failure injection via {method} {path} with payload={payload}",
            request_data={
                "payload": payload,
                "observe_path": observe_path,
                "baseline_status": baseline_status,
                "during_status": during_status,
                "post_status": post_status
            },
            response_summary=f"Baseline: {baseline_status}, During: {during_status}, Post: {post_status}",
            result="RESILIENCE_DEFECT" if findings_suggested else "RESILIENT_RECOVERED"
        )
        session.add_attempt(attempt)

        return Observation(
            step=session.step_count,
            tool=self.name,
            target=inject_url,
            summary=summary,
            raw_data={
                "path": path,
                "payload": payload,
                "baseline_status": baseline_status,
                "during_status": during_status,
                "post_status": post_status,
                "causal_chain": causal_chain,
                "downstream_effects": downstream_effects,
                "findings_suggested": findings_suggested,
                "insights": insights
            }
        )

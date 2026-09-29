import difflib
import time
from typing import Any
import httpx
from app.tools.base import BaseTool
from app.models.session import AuditSession
from app.models.observation import Observation
from app.models.attempt import AttackAttempt


class CompareResponsesTool(BaseTool):
    """Tool for sending comparative requests (e.g. baseline vs attack payload) to observe behavioral differentials."""

    name = "compare_responses"
    description = (
        "Sends two controlled HTTP requests (a baseline request and a modified attack request) "
        "and performs differential analysis on status codes, timing, content length, and body diffs."
    )
    parameters_schema = {
        "type": "object",
        "required": ["baseline_path", "attack_path"],
        "properties": {
            "method": {"type": "string", "default": "GET"},
            "baseline_path": {"type": "string", "description": "Baseline/normal request path"},
            "attack_path": {"type": "string", "description": "Mutated/attack payload request path"},
            "baseline_headers": {"type": "object"},
            "attack_headers": {"type": "object"},
            "baseline_body": {"type": "string"},
            "attack_body": {"type": "string"}
        }
    }

    async def execute(self, session: AuditSession, **kwargs: Any) -> Observation:
        method = kwargs.get("method", "GET").upper()
        base_path = kwargs.get("baseline_path", "/")
        att_path = kwargs.get("attack_path", "/")

        base_url = self.validate_target(session, base_path)
        att_url = self.validate_target(session, att_path)

        base_headers = kwargs.get("baseline_headers", {}) or {}
        att_headers = kwargs.get("attack_headers", {}) or {}

        # Default auth if active
        if "Authorization" not in base_headers and "active_token" in session.context_data:
            base_headers["Authorization"] = f"Bearer {session.context_data['active_token']}"
        if "Authorization" not in att_headers and "active_token" in session.context_data:
            att_headers["Authorization"] = f"Bearer {session.context_data['active_token']}"

        base_body = kwargs.get("baseline_body")
        att_body = kwargs.get("attack_body")

        async with httpx.AsyncClient(timeout=10.0) as client:
            # Baseline request
            t0 = time.perf_counter()
            res_base = await client.request(
                method, base_url, headers=base_headers, content=base_body.encode("utf-8") if base_body else None
            )
            base_ms = (time.perf_counter() - t0) * 1000.0

            # Attack request
            t1 = time.perf_counter()
            res_att = await client.request(
                method, att_url, headers=att_headers, content=att_body.encode("utf-8") if att_body else None
            )
            att_ms = (time.perf_counter() - t1) * 1000.0

        insights: list[str] = []
        status_diff = res_base.status_code != res_att.status_code
        timing_diff = abs(att_ms - base_ms)
        len_diff = abs(len(res_base.text) - len(res_att.text))

        if status_diff:
            insights.append(
                f"Status code shifted from {res_base.status_code} to {res_att.status_code} with attack payload."
            )
        else:
            insights.append(f"Both requests returned HTTP {res_base.status_code}.")

        if len_diff > 50:
            insights.append(f"Significant payload content length difference: {len_diff} bytes.")

        if timing_diff > 1500:
            insights.append(f"Significant latency divergence observed ({att_ms:.1f}ms vs {base_ms:.1f}ms baseline).")

        # Check for query/logic reflection
        if any(err in res_att.text.lower() for err in ["syntax error", "operationalerror", "sqlite"]):
            insights.append("Attack response specifically leaked SQL syntax errors not present in baseline.")

        # Record attempt
        attempt = AttackAttempt(
            step=session.step_count,
            tool=self.name,
            target=att_url,
            action_summary=f"Compared {base_path} vs {att_path}",
            request_data={"baseline": base_path, "attack": att_path},
            response_summary=f"Baseline: HTTP {res_base.status_code} ({base_ms:.1f}ms) vs Attack: HTTP {res_att.status_code} ({att_ms:.1f}ms)",
            result="BEHAVIORAL_DIFFERENTIAL_OBSERVED" if (status_diff or len_diff > 20 or timing_diff > 1000) else "NO_DIVERGENCE"
        )
        session.add_attempt(attempt)

        summary = (
            f"Differential analysis complete: Baseline HTTP {res_base.status_code} ({base_ms:.1f}ms) "
            f"vs Attack HTTP {res_att.status_code} ({att_ms:.1f}ms). Delta: {len_diff} bytes."
        )

        return Observation(
            step=session.step_count,
            tool=self.name,
            target=att_url,
            summary=summary,
            key_insights=insights,
            raw_data={
                "baseline": {
                    "status": res_base.status_code,
                    "elapsed_ms": base_ms,
                    "body_snippet": res_base.text[:300]
                },
                "attack": {
                    "status": res_att.status_code,
                    "elapsed_ms": att_ms,
                    "body_snippet": res_att.text[:300]
                },
                "status_divergence": status_diff,
                "length_delta": len_diff,
                "timing_delta_ms": timing_diff
            }
        )

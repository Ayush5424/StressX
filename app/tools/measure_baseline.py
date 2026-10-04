import asyncio
import time
from typing import Any
import httpx

from app.tools.base import BaseTool
from app.models.session import AuditSession
from app.models.observation import Observation
from app.models.attempt import AttackAttempt


class MeasureBaselineTool(BaseTool):
    """Tool for establishing empirical healthy baselines for endpoints before testing."""

    name = "measure_baseline"
    description = (
        "Measures healthy baseline performance and behavior for an endpoint. Dispatches a small sample "
        "of sequential requests (3-10) to record latency distribution, status codes, and payload characteristics."
    )
    parameters_schema = {
        "type": "object",
        "required": ["path"],
        "properties": {
            "path": {"type": "string", "description": "Target endpoint path to measure baseline on"},
            "method": {"type": "string", "enum": ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"], "default": "GET"},
            "headers": {"type": "object", "description": "HTTP request headers"},
            "params": {"type": "object", "description": "Query parameters"},
            "body": {"type": "string", "description": "Request body string"},
            "sample_count": {"type": "integer", "default": 5, "description": "Number of baseline samples (max 10)"},
            "delay_ms": {"type": "number", "default": 50.0, "description": "Inter-request delay in milliseconds"}
        }
    }

    async def execute(self, session: AuditSession, **kwargs: Any) -> Observation:
        path = kwargs.get("path", "/")
        method = kwargs.get("method", "GET").upper()
        headers = kwargs.get("headers", {}) or {}
        params = kwargs.get("params") or None
        body = kwargs.get("body")
        sample_count = max(2, min(int(kwargs.get("sample_count", 5)), 10))
        delay_ms = max(10.0, float(kwargs.get("delay_ms", 50.0)))

        resolved_url = self.validate_target(session, path)

        if "Authorization" not in headers and "active_token" in session.context_data:
            headers["Authorization"] = f"Bearer {session.context_data['active_token']}"

        latencies: list[float] = []
        statuses: list[int] = []
        status_dist: dict[str, int] = {}
        body_lengths: list[int] = []
        body_snippet = ""

        insights: list[str] = []

        async with httpx.AsyncClient(timeout=8.0, follow_redirects=False) as client:
            for idx in range(sample_count):
                if idx > 0 and delay_ms > 0:
                    await asyncio.sleep(delay_ms / 1000.0)

                t0 = time.perf_counter()
                try:
                    res = await client.request(
                        method=method,
                        url=resolved_url,
                        headers=headers,
                        params=params,
                        content=body.encode("utf-8") if isinstance(body, str) else None
                    )
                    elapsed_ms = (time.perf_counter() - t0) * 1000.0
                    latencies.append(round(elapsed_ms, 2))
                    statuses.append(res.status_code)
                    s_str = str(res.status_code)
                    status_dist[s_str] = status_dist.get(s_str, 0) + 1
                    body_lengths.append(len(res.text))
                    if not body_snippet:
                        body_snippet = res.text[:300]
                except Exception as ex:
                    elapsed_ms = (time.perf_counter() - t0) * 1000.0
                    latencies.append(round(elapsed_ms, 2))
                    statuses.append(0)
                    status_dist["0"] = status_dist.get("0", 0) + 1
                    insights.append(f"Baseline sample {idx+1} failed: {type(ex).__name__}")

        if not latencies:
            return Observation(
                step=session.step_count,
                tool=self.name,
                target=resolved_url,
                summary=f"Failed to record baseline samples for {path}",
                key_insights=["Baseline collection failed completely."],
                raw_data={"error": "no_samples", "target": resolved_url}
            )

        latencies.sort()
        mean_lat = round(sum(latencies) / len(latencies), 2)
        min_lat = latencies[0]
        max_lat = latencies[-1]
        p95_idx = int(0.95 * len(latencies))
        p95_lat = latencies[min(p95_idx, len(latencies) - 1)]

        healthy = all(200 <= s < 400 for s in statuses)
        avg_len = round(sum(body_lengths) / len(body_lengths), 1) if body_lengths else 0

        baseline_profile = {
            "path": path,
            "method": method,
            "sample_count": len(latencies),
            "status_distribution": status_dist,
            "mean_latency_ms": mean_lat,
            "min_latency_ms": min_lat,
            "p95_latency_ms": p95_lat,
            "max_latency_ms": max_lat,
            "healthy": healthy,
            "avg_body_length": avg_len,
            "body_snippet": body_snippet
        }

        # Store in session context for subsequent differential tests
        baselines = session.context_data.setdefault("baselines", {})
        baselines[path] = baseline_profile

        insights.append(
            f"Baseline established for {path}: Mean latency {mean_lat}ms (p95: {p95_lat}ms), Statuses: {status_dist}."
        )
        if not healthy:
            insights.append("Baseline reflects errors or non-2xx statuses under normal conditions.")

        summary = (
            f"Baseline established on {method} {path} across {len(latencies)} samples: "
            f"Mean {mean_lat}ms, p95 {p95_lat}ms, Status {status_dist}. Healthy: {healthy}."
        )

        attempt = AttackAttempt(
            step=session.step_count,
            tool=self.name,
            target=resolved_url,
            action_summary=f"Established healthy baseline for {method} {path}",
            request_data={"method": method, "path": path, "sample_count": len(latencies)},
            response_summary=summary,
            result="BASELINE_ESTABLISHED" if healthy else "BASELINE_UNHEALTHY"
        )
        session.add_attempt(attempt)

        return Observation(
            step=session.step_count,
            tool=self.name,
            target=resolved_url,
            summary=summary,
            key_insights=insights,
            raw_data={
                "total_requests": len(latencies),
                "samples_count": len(latencies),
                "status_distribution": status_dist,
                "mean_latency_ms": mean_lat,
                "min_latency_ms": min_lat,
                "p95_latency_ms": p95_lat,
                "max_latency_ms": max_lat,
                "baseline_healthy": healthy,
                "body_snippet": body_snippet,
                "profile": baseline_profile
            }
        )

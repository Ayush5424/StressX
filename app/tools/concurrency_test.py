import asyncio
import time
from typing import Any, Optional
import httpx

from app.tools.base import BaseTool
from app.models.session import AuditSession
from app.models.observation import Observation
from app.models.attempt import AttackAttempt


class ConcurrencyTestTool(BaseTool):
    """Tool for executing controlled concurrency experiments to detect race conditions and lock exhaustion."""

    name = "concurrency_test"
    description = (
        "Dispatches simultaneous concurrent requests (2-10 workers) to the same endpoint or resource. "
        "Observes status distributions, latency jitter, database lock contention, duplicate operations, "
        "and connection pool exhaustion. Never assumes race conditions from timing alone."
    )
    parameters_schema = {
        "type": "object",
        "required": ["path"],
        "properties": {
            "path": {"type": "string", "description": "Target endpoint path for concurrent execution"},
            "method": {"type": "string", "enum": ["GET", "POST", "PUT", "DELETE", "PATCH"], "default": "GET"},
            "headers": {"type": "object", "description": "HTTP request headers"},
            "params": {"type": "object", "description": "Query parameters"},
            "body": {"type": "string", "description": "Request body string"},
            "concurrency_level": {"type": "integer", "default": 5, "description": "Simultaneous workers (2-10)"},
            "test_type": {
                "type": "string",
                "enum": ["identical_requests", "resource_mutation", "identity_concurrency"],
                "default": "identical_requests",
                "description": "Concurrency scenario"
            }
        }
    }

    async def execute(self, session: AuditSession, **kwargs: Any) -> Observation:
        path = kwargs.get("path", "/")
        method = kwargs.get("method", "GET").upper()
        headers = kwargs.get("headers", {}) or {}
        params = kwargs.get("params") or None
        body = kwargs.get("body")
        concurrency_level = max(2, min(int(kwargs.get("concurrency_level", 5)), 10))
        test_type = kwargs.get("test_type", "identical_requests")

        resolved_url = self.validate_target(session, path)

        if "Authorization" not in headers and "active_token" in session.context_data:
            headers["Authorization"] = f"Bearer {session.context_data['active_token']}"

        insights: list[str] = []
        statuses: list[int] = []
        latencies: list[float] = []
        bodies: list[str] = []
        status_dist: dict[str, int] = {}

        # 1. Measure single baseline request first
        baseline_ms = 0.0
        baseline_status = 0
        async with httpx.AsyncClient(timeout=8.0, follow_redirects=False) as client:
            t_base_0 = time.perf_counter()
            try:
                res_base = await client.request(
                    method=method,
                    url=resolved_url,
                    headers=headers,
                    params=params,
                    content=body.encode("utf-8") if isinstance(body, str) else None
                )
                baseline_ms = round((time.perf_counter() - t_base_0) * 1000.0, 2)
                baseline_status = res_base.status_code
            except Exception as e:
                insights.append(f"Baseline request before concurrency failed: {e}")

            # 2. Dispatch simultaneous requests concurrently via asyncio.gather
            async def _worker(worker_id: int) -> tuple[int, float, str]:
                worker_body = body
                worker_headers = dict(headers)
                t0 = time.perf_counter()
                try:
                    res = await client.request(
                        method=method,
                        url=resolved_url,
                        headers=worker_headers,
                        params=params,
                        content=worker_body.encode("utf-8") if isinstance(worker_body, str) else None
                    )
                    el = round((time.perf_counter() - t0) * 1000.0, 2)
                    return res.status_code, el, res.text
                except Exception as ex:
                    el = round((time.perf_counter() - t0) * 1000.0, 2)
                    return 0, el, f"Worker Error: {type(ex).__name__}"

            tasks = [_worker(i) for i in range(concurrency_level)]
            results = await asyncio.gather(*tasks)

        for sc, el, txt in results:
            statuses.append(sc)
            latencies.append(el)
            bodies.append(txt)
            s_str = str(sc)
            status_dist[s_str] = status_dist.get(s_str, 0) + 1

        # 3. Analyze concurrency indicators
        latencies.sort()
        mean_lat = round(sum(latencies) / len(latencies), 2)
        min_lat = latencies[0]
        max_lat = latencies[-1]
        jitter_ms = round(max_lat - min_lat, 2)

        # Look for lock contention / DB deadlock signatures
        lock_keywords = ["database is locked", "deadlock", "lock timeout", "connection pool exhausted", "too many connections"]
        db_lock_detected = any(any(kw in b.lower() for kw in lock_keywords) for b in bodies)

        # Check for 5xx errors under concurrency when baseline was 200
        concurrency_5xx = (baseline_status == 200 and any(s >= 500 for s in statuses))
        
        # Check for duplicate creation in state-changing operations
        duplicate_success = (method in ("POST", "PUT") and statuses.count(200) + statuses.count(201) > 1 and test_type == "resource_mutation")

        race_condition_detected = db_lock_detected or duplicate_success
        errors_detected = concurrency_5xx or (0 in statuses)

        if db_lock_detected:
            insights.append("Database lock contention or pool exhaustion detected in response bodies.")
        if concurrency_5xx:
            insights.append(f"HTTP 5xx errors surfaced under {concurrency_level} simultaneous requests (baseline was HTTP {baseline_status}).")
        if duplicate_success:
            insights.append("State mutation permitted duplicate successful actions under concurrency.")
        if not race_condition_detected and not concurrency_5xx:
            insights.append(f"No race conditions or lock contention observed across {concurrency_level} simultaneous requests.")

        observed_facts = (
            f"OBSERVED: {concurrency_level} simultaneous workers on {method} {path}; "
            f"Baseline latency: {baseline_ms}ms (HTTP {baseline_status}); Concurrent latencies: min {min_lat}ms, mean {mean_lat}ms, max {max_lat}ms; "
            f"Status distribution: {status_dist}; Lock errors observed: {db_lock_detected}; 5xx under concurrency: {concurrency_5xx}."
        )

        if race_condition_detected:
            inferred_conclusion = (
                f"INFERRED: Concurrency defect verified. Application exposes database lock contention or lack of transaction isolation."
            )
        elif concurrency_5xx:
            inferred_conclusion = (
                f"INFERRED: Thread/worker saturation or connection pool starvation under simultaneous requests."
            )
        else:
            inferred_conclusion = (
                f"INFERRED: Application handled {concurrency_level} simultaneous requests with consistent state handling."
            )

        summary = (
            f"Concurrency test ({concurrency_level} workers) on {method} {path} complete. "
            f"Statuses: {status_dist}. Mean latency: {mean_lat}ms (jitter: {jitter_ms}ms). "
            f"Lock contention: {db_lock_detected}, 5xx errors: {concurrency_5xx}."
        )

        attempt = AttackAttempt(
            step=session.step_count,
            tool=self.name,
            target=resolved_url,
            action_summary=f"Simultaneous concurrency test on {method} {path} ({concurrency_level} workers)",
            request_data={
                "method": method,
                "path": path,
                "concurrency_level": concurrency_level,
                "test_type": test_type
            },
            response_summary=summary,
            result="RACE_OR_LOCK_DEFECT" if race_condition_detected else (
                "CONCURRENCY_ERROR" if concurrency_5xx else "CONCURRENCY_STABLE"
            )
        )
        session.add_attempt(attempt)

        return Observation(
            step=session.step_count,
            tool=self.name,
            target=resolved_url,
            summary=summary,
            key_insights=insights + [observed_facts, inferred_conclusion],
            raw_data={
                "total_requests": concurrency_level + 1,
                "concurrency_level": concurrency_level,
                "baseline_latency_ms": baseline_ms,
                "mean_latency_ms": mean_lat,
                "min_latency_ms": min_lat,
                "max_latency_ms": max_lat,
                "jitter_ms": jitter_ms,
                "status_distribution": status_dist,
                "db_lock_detected": db_lock_detected,
                "concurrency_5xx": concurrency_5xx,
                "race_condition_detected": race_condition_detected,
                "errors_detected": errors_detected,
                "observed_facts": observed_facts,
                "inferred_conclusion": inferred_conclusion,
                "sample_bodies": [b[:200] for b in bodies[:3]]
            }
        )
